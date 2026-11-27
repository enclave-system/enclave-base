package selftest

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	out map[string]string // key: "name arg arg"
	err map[string]error
	fn  func(name string, args []string) ([]byte, bool) // fallback (tpm2 trial sessions)
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	k := strings.Join(append([]string{name}, args...), " ")
	if e, ok := f.err[k]; ok {
		return nil, e
	}
	if e, ok := f.err[name]; ok {
		return nil, e
	}
	if o, ok := f.out[k]; ok {
		return []byte(o), nil
	}
	if f.fn != nil {
		if o, ok := f.fn(name, args); ok {
			return o, nil
		}
	}
	return nil, errors.New("unexpected command: " + k)
}

func put(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	sbPath = "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	smPath = "sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
)

// The enklave kernels are built without IPv6, so the base ruleset is an
// "ip" table (an "inet" table needs CONFIG_NF_TABLES_INET, which needs IPV6).
const goodNft = `{"nftables":[{"metainfo":{}},{"table":{"family":"ip","name":"enklave"}},
{"chain":{"family":"ip","table":"enklave","name":"input","policy":"drop"}},
{"chain":{"family":"ip","table":"enklave","name":"forward","policy":"drop"}},
{"chain":{"family":"ip","table":"enklave","name":"output","policy":"drop"}}]}`

const unitsCmd = "systemctl list-units --all --plain --no-legend --state=active"

func find(t *testing.T, rs []Result, name string) Result {
	t.Helper()
	for _, r := range rs {
		if r.Check == name {
			return r
		}
	}
	t.Fatalf("check %q not emitted", name)
	return Result{}
}

func TestAllGood(t *testing.T) {
	root, r := goodRoot(t)
	rs := RunChecks(root, r)
	wantOrder := []string{"secureboot", "setupmode_off", "lockdown", "module_sig_enforce", "usr_verity", "usr_readonly",
		"var_luks", "var_tpm_bound", "var_authenticated", "var_integrity", "var_rollback", "state_readonly", "efi_updates", "tpm_locked", "pcr11_sealed",
		"no_pkg_manager", "apparmor", "nft_default_drop", "no_getty", "ipv6_absent", "no_credentials", "role", "version", "dev_keys"}
	if len(rs) != len(wantOrder) {
		t.Fatalf("got %d results: %+v", len(rs), rs)
	}
	for i, n := range wantOrder {
		if rs[i].Check != n {
			t.Errorf("pos %d: got %s want %s", i, rs[i].Check, n)
		}
		if !rs[i].OK {
			t.Errorf("%s not ok: %s", rs[i].Check, rs[i].Detail)
		}
	}
	if d := find(t, rs, "version").Detail; d != "1.2.3" {
		t.Errorf("version detail %q", d)
	}
	if d := find(t, rs, "role").Detail; d != "ref" {
		t.Errorf("role detail %q", d)
	}
}

func TestChecksNotOk(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, root string, r *fakeRunner)
	}{
		{"secureboot", func(t *testing.T, root string, r *fakeRunner) { put(t, root, sbPath, "\x06\x00\x00\x00\x00") }},
		{"setupmode_off", func(t *testing.T, root string, r *fakeRunner) { put(t, root, smPath, "\x06\x00\x00\x00\x01") }},
		{"lockdown", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "sys/kernel/security/lockdown", "none [integrity] confidentiality\n")
		}},
		{"module_sig_enforce", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "sys/module/module/parameters/sig_enforce", "N\n")
		}},
		{"usr_verity", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "sys/dev/block/253:0/dm/uuid", "CRYPT-LUKS2-x\n")
		}},
		{"usr_readonly", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "proc/self/mountinfo",
				"20 1 253:0 / /usr rw,relatime - erofs /dev/mapper/usr rw\n21 1 253:1 / /var rw - ext4 /dev/x rw\n")
		}},
		{"var_luks", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "sys/dev/block/253:1/dm/uuid", "CRYPT-VERITY-x\n")
		}},
		{"var_tpm_bound", func(t *testing.T, root string, r *fakeRunner) {
			r.out[luksDumpCmd] = strings.Replace(goodLuksDump, "enklave-tpm2-nv", "systemd-tpm2", 1)
		}},
		{"var_authenticated", func(t *testing.T, root string, r *fakeRunner) {
			r.out[recordReadCmd] = strings.Repeat("\xAA", 32) // swapped volume
		}},
		{"var_integrity", func(t *testing.T, root string, r *fakeRunner) {
			r.out[luksDumpCmd] = strings.Replace(goodLuksDump, "integrity: hmac(sha256)", "integrity: (no)", 1)
		}},
		{"var_rollback", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "var/lib/enklave/.manifest", `{"version":41,"entries":[],"mac":"00"}`)
		}},
		{"tpm_locked", func(t *testing.T, root string, r *fakeRunner) {
			r.out[hierCmd] = strings.Replace(lockedHier, "disableClear:              1", "disableClear:              0", 1)
		}},
		{"pcr11_sealed", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "run/enklave/policy.json", `{"pcr11_policy":"`+strings.Repeat("cc", 32)+`"}`)
		}},
		{"no_pkg_manager", func(t *testing.T, root string, r *fakeRunner) { put(t, root, "usr/bin/dpkg", "x") }},
		{"apparmor", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "sys/module/apparmor/parameters/enabled", "N\n")
		}},
		{"nft_default_drop", func(t *testing.T, root string, r *fakeRunner) {
			r.out["nft -j list ruleset"] = strings.Replace(goodNft, `"name":"forward","policy":"drop"`, `"name":"forward","policy":"accept"`, 1)
		}},
		{"no_getty", func(t *testing.T, root string, r *fakeRunner) {
			r.out[unitsCmd] = "getty@tty1.service loaded active running Getty\n"
		}},
		{"ipv6_absent", func(t *testing.T, root string, r *fakeRunner) { put(t, root, "proc/net/if_inet6", "") }},
		{"no_credentials", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "proc/cmdline", "usrhash=ab lockdown=confidentiality root=tmpfs\n")
		}},
		{"role", func(t *testing.T, root string, r *fakeRunner) { put(t, root, "usr/lib/enklave/role", "bogus\n") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, r := goodRoot(t)
			c.mutate(t, root, r)
			res := find(t, RunChecks(root, r), c.name)
			if res.OK {
				t.Errorf("expected not ok")
			}
			if res.Detail == "" {
				t.Errorf("expected detail")
			}
		})
	}
}

func TestMissingEverythingNoPanic(t *testing.T) {
	rs := RunChecks(t.TempDir(), &fakeRunner{})
	for _, r := range rs {
		if r.Check == "version" {
			if !r.OK || r.Detail != "unknown" {
				t.Errorf("version: %+v", r)
			}
			continue
		}
		if r.Check == "ipv6_absent" || r.Check == "no_pkg_manager" {
			if !r.OK { // definitive ENOENT: absence is ok
				t.Errorf("%s not ok on empty root: %s", r.Check, r.Detail)
			}
			continue
		}
		if r.OK {
			t.Errorf("%s ok on empty root", r.Check)
		}
	}
}

func TestRunnerErrorIsNotOk(t *testing.T) {
	root, r := goodRoot(t)
	r.err = map[string]error{"nft -j list ruleset": errors.New("boom"), unitsCmd: errors.New("bang")}
	rs := RunChecks(root, r)
	if x := find(t, rs, "nft_default_drop"); x.OK || !strings.Contains(x.Detail, "boom") {
		t.Errorf("%+v", x)
	}
	if x := find(t, rs, "no_getty"); x.OK || !strings.Contains(x.Detail, "bang") {
		t.Errorf("%+v", x)
	}
}

func TestNftChainMissingAndWrongTable(t *testing.T) {
	root, r := goodRoot(t)
	r.out["nft -j list ruleset"] = strings.ReplaceAll(goodNft, `"table":"enklave"`, `"table":"other"`)
	if find(t, RunChecks(root, r), "nft_default_drop").OK {
		t.Error("wrong table accepted")
	}
	r.out["nft -j list ruleset"] = "not json"
	if find(t, RunChecks(root, r), "nft_default_drop").OK {
		t.Error("bad json accepted")
	}
}

func TestNftRequiresIPFamily(t *testing.T) {
	root, r := goodRoot(t)
	r.out["nft -j list ruleset"] = strings.ReplaceAll(goodNft, `"family":"ip"`, `"family":"inet"`)
	if x := find(t, RunChecks(root, r), "nft_default_drop"); x.OK {
		t.Errorf("inet enklave table accepted: %+v", x)
	}
	// An unrelated inet chain next to the ip table does not change the result.
	r.out["nft -j list ruleset"] = strings.Replace(goodNft, `]}`,
		`,{"chain":{"family":"inet","table":"enklave","name":"input","policy":"accept"}}]}`, 1)
	if x := find(t, RunChecks(root, r), "nft_default_drop"); !x.OK {
		t.Errorf("ip table with extra inet chain rejected: %+v", x)
	}
}

func TestRoleValid(t *testing.T) {
	for _, role := range []string{"ref", "client", "gateway", "terminal", "console", "sluice", "backup", "fileserver"} {
		root, r := goodRoot(t)
		put(t, root, "usr/lib/enklave/role", "\n "+role+" \n")
		if x := find(t, RunChecks(root, r), "role"); !x.OK || x.Detail != role {
			t.Errorf("%s: %+v", role, x)
		}
	}
}

func TestMarker(t *testing.T) {
	root, r := goodRoot(t)
	for _, x := range RunChecks(root, r) {
		if x.Check == "marker" {
			t.Fatal("marker emitted without test-profile")
		}
	}
	put(t, root, "usr/lib/enklave/test-profile", "")
	rs := RunChecks(root, r)
	if find(t, rs, "marker").OK {
		t.Error("marker ok without file")
	}
	if rs[len(rs)-1].Check != "marker" {
		t.Error("marker should be last")
	}
	put(t, root, "var/lib/enklave/data/marker", "x")
	if !find(t, RunChecks(root, r), "marker").OK {
		t.Error("marker not ok with file")
	}
}

func TestWriteResultsDone(t *testing.T) {
	var b bytes.Buffer
	all := WriteResults(&b, []Result{{"a", true, "x"}, {"b", false, "bad"}})
	if all {
		t.Error("all should be false")
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("%q", b.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &m); err != nil {
		t.Fatal(err)
	}
	if m["check"] != "done" || m["ok"] != false {
		t.Errorf("%v", m)
	}
	b.Reset()
	if !WriteResults(&b, []Result{{"a", true, ""}}) || !strings.Contains(b.String(), `{"check":"done","ok":true}`) {
		t.Errorf("%q", b.String())
	}
	if !strings.Contains(b.String(), `"detail":""`) {
		t.Errorf("detail must be present: %q", b.String())
	}
}

// --- require-secureboot ---

func TestRequireSecureBoot(t *testing.T) {
	type tc struct {
		name     string
		setup    func(root string)
		logOnly  bool
		wantCode int
		wantOff  bool
	}
	cases := []tc{
		{"on", func(root string) { put(t, root, sbPath, "\x06\x00\x00\x00\x01") }, false, 0, false},
		{"off", func(root string) { put(t, root, sbPath, "\x06\x00\x00\x00\x00") }, false, 1, true},
		{"missing", func(root string) {}, false, 1, true},
		{"short", func(root string) { put(t, root, sbPath, "\x06\x00") }, false, 1, true},
		{"off-logonly", func(root string) { put(t, root, sbPath, "\x06\x00\x00\x00\x00") }, true, 1, false},
		{"missing-logonly", func(root string) {}, true, 1, false},
		{"on-logonly", func(root string) { put(t, root, sbPath, "\x06\x00\x00\x00\x01") }, true, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			c.setup(root)
			off := 0
			var errb bytes.Buffer
			args := []string{"--root", root}
			if c.logOnly {
				args = append(args, "--log-only")
			}
			code := Main("enklave-selftest", append([]string{"require-secureboot"}, args...), &fakeRunner{}, func(Runner) { off++ }, &errb)
			if code != c.wantCode {
				t.Errorf("code %d want %d", code, c.wantCode)
			}
			if (off == 1) != c.wantOff || off > 1 {
				t.Errorf("poweroff calls %d, want %v", off, c.wantOff)
			}
			if c.wantCode != 0 && !strings.Contains(errb.String(), "Secure Boot") {
				t.Errorf("no log line: %q", errb.String())
			}
		})
	}
}

func TestArgv0Dispatch(t *testing.T) {
	root := t.TempDir()
	off := 0
	var errb bytes.Buffer
	code := Main("/usr/lib/enklave/require-secureboot", []string{"--root", root}, &fakeRunner{}, func(Runner) { off++ }, &errb)
	if code != 1 || off != 1 {
		t.Errorf("code=%d off=%d", code, off)
	}
}

func TestPowerOffFallbackRetriesAndLogs(t *testing.T) {
	r := &fakeRunner{err: map[string]error{"systemctl poweroff --force --force": errors.New("no")}}
	called, slept := 0, 0
	var log bytes.Buffer
	powerOff(r, func() error { called++; return errors.New("eperm") },
		func(time.Duration) { slept++ }, &log, time.Second, time.Second, 3)
	if called != 3 || slept != 3 {
		t.Errorf("called=%d slept=%d, want 3", called, slept)
	}
	if !strings.Contains(log.String(), "systemctl poweroff failed") || !strings.Contains(log.String(), "eperm") {
		t.Errorf("log: %q", log.String())
	}
	r = &fakeRunner{out: map[string]string{"systemctl poweroff --force --force": ""}}
	powerOff(r, func() error { called++; return nil }, func(time.Duration) {}, &log, time.Second, time.Second, 3)
	if called != 3 {
		t.Errorf("fallback used despite systemctl success")
	}
}

type hangRunner struct{ block chan struct{} }

func (h *hangRunner) Run(string, ...string) ([]byte, error) { <-h.block; return nil, nil }

func TestPowerOffSystemctlHangFallsBack(t *testing.T) {
	h := &hangRunner{block: make(chan struct{})}
	defer close(h.block)
	called := 0
	var log bytes.Buffer
	powerOff(h, func() error { called++; return nil }, func(time.Duration) {}, &log,
		20*time.Millisecond, time.Millisecond, 2)
	if called != 2 || !strings.Contains(log.String(), "timed out") {
		t.Errorf("called=%d log=%q", called, log.String())
	}
}

func TestRequireSecureBootUsageErrorsStillGuard(t *testing.T) {
	cases := []struct {
		name    string
		argv0   string
		args    func(root string) []string
		wantOff bool
		want    int
	}{
		{"unknown-flag", "require-secureboot", func(r string) []string { return []string{"--root", r, "--bogus"} }, true, 2},
		{"stray-positional", "require-secureboot", func(r string) []string { return []string{"--root", r, "stray"} }, true, 2},
		{"doubled-name", "require-secureboot", func(r string) []string { return []string{"--root", r, "require-secureboot"} }, true, 2},
		{"subcmd-unknown-flag", "enklave-selftest", func(r string) []string { return []string{"require-secureboot", "--root", r, "--bogus"} }, true, 2},
		{"log-only-usage", "require-secureboot", func(r string) []string { return []string{"--root", r, "--log-only", "x"} }, false, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			off := 0
			var errb bytes.Buffer
			code := Main(c.argv0, c.args(root), &fakeRunner{}, func(Runner) { off++ }, &errb)
			if code != c.want || (off == 1) != c.wantOff {
				t.Errorf("code=%d off=%d", code, off)
			}
		})
	}
	// Secure Boot on + usage error: no poweroff, usage code.
	root := t.TempDir()
	put(t, root, sbPath, "\x06\x00\x00\x00\x01")
	off := 0
	if code := Main("require-secureboot", []string{"--root", root, "--bogus"}, &fakeRunner{}, func(Runner) { off++ }, &bytes.Buffer{}); code != 2 || off != 0 {
		t.Errorf("code=%d off=%d", code, off)
	}
}

func TestNoCredentials(t *testing.T) {
	check := func(t *testing.T, root string, r *fakeRunner, wantOK bool) {
		t.Helper()
		if x := find(t, RunChecks(root, r), "no_credentials"); x.OK != wantOK {
			t.Errorf("no_credentials ok=%v, want %v: %+v", x.OK, wantOK, x)
		}
	}
	t.Run("empty credentials dir is ok", func(t *testing.T) {
		root, r := goodRoot(t)
		if err := os.MkdirAll(filepath.Join(root, "run/credentials/@system"), 0o700); err != nil {
			t.Fatal(err)
		}
		check(t, root, r, true)
	})
	t.Run("imported credential is not ok", func(t *testing.T) {
		root, r := goodRoot(t)
		put(t, root, "run/credentials/@system/udev.rules.99-evil-enc", "x")
		check(t, root, r, false)
	})
	t.Run("credentials path not a directory is not ok", func(t *testing.T) {
		root, r := goodRoot(t)
		put(t, root, "run/credentials", "i am a file") // ENOTDIR
		check(t, root, r, false)
	})
	for _, cl := range []string{
		"systemd.import_credentials=yes",
		"systemd.import_credentials=no systemd.import_credentials=yes", // last one wins
		"systemd.import_credentials=no systemd.import_credentials",
		"systemd.import_credentials=no2",
		"xsystemd.import_credentials=no",
		"systemd.import_credentials=0",
	} {
		t.Run("cmdline "+cl, func(t *testing.T) {
			root, r := goodRoot(t)
			put(t, root, "proc/cmdline", "root=tmpfs "+cl+"\n")
			check(t, root, r, false)
		})
	}
	t.Run("missing proc/cmdline is not ok", func(t *testing.T) {
		root, r := goodRoot(t)
		if err := os.Remove(filepath.Join(root, "proc/cmdline")); err != nil {
			t.Fatal(err)
		}
		check(t, root, r, false)
	})
}

func TestStatErrorsAreNotOk(t *testing.T) {
	root, r := goodRoot(t)
	put(t, root, "proc/net", "i am a file") // ENOTDIR for proc/net/if_inet6
	if x := find(t, RunChecks(root, r), "ipv6_absent"); x.OK || x.Detail == "" {
		t.Errorf("ipv6_absent: %+v", x)
	}
	root, r = goodRoot(t)
	put(t, root, "usr/bin", "i am a file") // ENOTDIR for usr/bin/apt
	if x := find(t, RunChecks(root, r), "no_pkg_manager"); x.OK || x.Detail == "" {
		t.Errorf("no_pkg_manager: %+v", x)
	}
}

func TestMainUsageAndOut(t *testing.T) {
	var errb bytes.Buffer
	if c := Main("enklave-selftest", []string{"bogus"}, &fakeRunner{}, func(Runner) {}, &errb); c != 2 {
		t.Errorf("code %d", c)
	}
	if c := Main("enklave-selftest", []string{}, &fakeRunner{}, func(Runner) {}, &errb); c != 2 {
		t.Errorf("no --out: code %d", c)
	}
	root, r := goodRoot(t)
	out := filepath.Join(t.TempDir(), "out.jsonl")
	if c := Main("enklave-selftest", []string{"--out", out, "--root", root}, r, func(Runner) {}, &errb); c != 0 {
		t.Errorf("code %d: %s", c, errb.String())
	}
	b, _ := os.ReadFile(out)
	if !strings.HasSuffix(string(b), `{"check":"done","ok":true}`+"\n") {
		t.Errorf("%s", b)
	}
	// failing root -> exit 1
	if c := Main("enklave-selftest", []string{"--out", out, "--root", t.TempDir()}, &fakeRunner{}, func(Runner) {}, &errb); c != 1 {
		t.Errorf("code %d", c)
	}
}
