package selftest

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	out map[string]string // key: "name arg arg"
	err map[string]error
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	k := strings.Join(append([]string{name}, args...), " ")
	if e, ok := f.err[k]; ok {
		return nil, e
	}
	if o, ok := f.out[k]; ok {
		return []byte(o), nil
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

const goodNft = `{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"enklave"}},
{"chain":{"family":"inet","table":"enklave","name":"input","policy":"drop"}},
{"chain":{"family":"inet","table":"enklave","name":"forward","policy":"drop"}},
{"chain":{"family":"inet","table":"enklave","name":"output","policy":"drop"}}]}`

const unitsCmd = "systemctl list-units --all --plain --no-legend --state=active"

// goodRoot builds a fully passing fake root and runner.
func goodRoot(t *testing.T) (string, *fakeRunner) {
	root := t.TempDir()
	put(t, root, sbPath, "\x06\x00\x00\x00\x01")
	put(t, root, smPath, "\x06\x00\x00\x00\x00")
	put(t, root, "sys/kernel/security/lockdown", "none integrity [confidentiality]\n")
	put(t, root, "sys/module/module/parameters/sig_enforce", "Y\n")
	put(t, root, "proc/self/mountinfo",
		"20 1 253:0 / /usr ro,relatime shared:1 - erofs /dev/mapper/usr ro\n"+
			"21 1 253:1 / /var rw,relatime shared:2 - ext4 /dev/mapper/var rw\n")
	put(t, root, "sys/dev/block/253:0/dm/uuid", "CRYPT-VERITY-abc-usr\n")
	put(t, root, "sys/dev/block/253:1/dm/uuid", "CRYPT-LUKS2-abc-var\n")
	if err := os.MkdirAll(filepath.Join(root, "sys/dev/block/253:1/slaves/vda4"), 0o755); err != nil {
		t.Fatal(err)
	}
	put(t, root, "sys/module/apparmor/parameters/enabled", "Y\n")
	put(t, root, "usr/lib/enklave/role", " ref\n")
	put(t, root, "usr/lib/os-release", "NAME=Enklave\nIMAGE_VERSION=1.2.3\n")
	r := &fakeRunner{out: map[string]string{
		"cryptsetup luksDump /dev/vda4": "Tokens:\n  0: systemd-tpm2\n",
		"nft -j list ruleset":           goodNft,
		unitsCmd:                        "sshd-not.service loaded active running x\nfoo.service loaded active running y\n",
	}}
	return root, r
}

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
		"var_luks", "var_tpm_bound", "no_pkg_manager", "apparmor", "nft_default_drop", "no_getty", "ipv6_absent", "role", "version"}
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
			r.out["cryptsetup luksDump /dev/vda4"] = "Tokens:\n"
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
	put(t, root, "var/lib/enklave/marker", "x")
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

func TestPowerOffFallback(t *testing.T) {
	r := &fakeRunner{err: map[string]error{"systemctl poweroff --force --force": errors.New("no")}}
	called := 0
	powerOff(r, func() error { called++; return nil })
	if called != 1 {
		t.Errorf("fallback calls %d", called)
	}
	r = &fakeRunner{out: map[string]string{"systemctl poweroff --force --force": ""}}
	powerOff(r, func() error { called++; return nil })
	if called != 1 {
		t.Errorf("fallback used despite systemctl success")
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
