package varauth

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTPM is a stateful stand-in for tpm2-tools and systemd-repart.
type fakeTPM struct {
	pcr15, pcr7pol, pcr11pol []byte
	defined, written, locked bool
	attrs                    uint32
	policy, content          []byte
	repartJSON               string
	calls                    []string
	fail                     map[string]error
}

func newFake() *fakeTPM {
	return &fakeTPM{
		pcr15:      bytes.Repeat([]byte{0x15}, 32),
		pcr7pol:    bytes.Repeat([]byte{0x07}, 32),
		pcr11pol:   bytes.Repeat([]byte{0x11}, 32),
		repartJSON: `[{"type":"var","activity":"create"}]`,
	}
}

func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (f *fakeTPM) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	switch name {
	case "systemd-repart":
		return []byte(f.repartJSON), nil
	case "tpm2_pcrread":
		return []byte(fmt.Sprintf("  sha256:\n    15: 0x%X\n", f.pcr15)), nil
	case "tpm2_getcap":
		if f.defined {
			return []byte("- 0x1800E01\n- 0x1500016\n"), nil
		}
		return []byte("- 0x1500016\n"), nil
	case "tpm2_policypcr":
		if argAfter(args, "-l") == "sha256:11" {
			return []byte(hex.EncodeToString(f.pcr11pol) + "\n"), nil
		}
		return []byte(hex.EncodeToString(f.pcr7pol) + "\n"), nil
	case "tpm2_nvdefine":
		if f.defined {
			return nil, errors.New("NV_DefineSpace: index exists")
		}
		var a uint32
		fmt.Sscanf(argAfter(args, "-a"), "0x%x", &a)
		p, err := os.ReadFile(argAfter(args, "-L"))
		if err != nil {
			return nil, err
		}
		f.defined, f.attrs, f.policy = true, a, p
	case "tpm2_nvwrite":
		if f.locked || !f.defined {
			return nil, errors.New("NV_Write refused")
		}
		b, err := os.ReadFile(argAfter(args, "-i"))
		if err != nil {
			return nil, err
		}
		f.content, f.written = b, true
		f.attrs |= 0x20000000
	case "tpm2_nvwritelock":
		f.locked = true
		f.attrs |= 0x00000800
	case "tpm2_nvreadpublic":
		if !f.defined {
			return nil, errors.New("handle not correct")
		}
		return []byte(fmt.Sprintf("0x1800e01:\n  name: 000b00\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n"+
			"  attributes:\n    friendly: x\n    value: 0x%X\n  size: 32\n  authorization policy: %X\n\n", f.attrs, f.policy)), nil
	case "tpm2_nvread":
		if !f.written {
			return nil, errors.New("NV not written")
		}
		return f.content, nil
	}
	return nil, nil
}

func (f *fakeTPM) called(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func setup(t *testing.T, f *fakeTPM) Config {
	t.Helper()
	d := t.TempDir()
	c := Config{
		RunDir:  filepath.Join(d, "run"),
		WorkDir: filepath.Join(d, "run/varauth"),
		PubKey:  filepath.Join(d, "pub.pem"),
		PCRSig:  filepath.Join(d, "pcrsig.json"),
	}
	sig := base64.StdEncoding.EncodeToString([]byte("signature"))
	js := fmt.Sprintf(`{"sha256":[{"pcrs":[11],"pkfp":"aa","pol":"%x","sig":"%s"}]}`, f.pcr11pol, sig)
	if err := os.WriteFile(c.PCRSig, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

func firstBoot(t *testing.T, f *fakeTPM, c Config) {
	t.Helper()
	if err := Repart(c, f, []string{"--dry-run=no"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(c, f); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	if err := os.Remove(c.CreatedFlag()); err != nil { // /run is volatile
		t.Fatal(err)
	}
}

func TestFirstBootProvisionsAndLocks(t *testing.T) {
	f := newFake()
	c := setup(t, f)
	if err := Repart(c, f, []string{"--dry-run=no"}); err != nil {
		t.Fatal(err)
	}
	msg, err := Verify(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "provisioned") {
		t.Errorf("msg %q", msg)
	}
	if !f.locked || !bytes.Equal(f.content, f.pcr15) || f.attrs != AttrsLocked || !bytes.Equal(f.policy, f.pcr7pol) {
		t.Errorf("state locked=%v attrs=%x content=%x policy=%x", f.locked, f.attrs, f.content, f.policy)
	}
	if !f.called("tpm2_nvdefine 0x01800E01 -C o -s 32 -a 0x02042008") {
		t.Errorf("nvdefine call missing/wrong: %v", f.calls)
	}
	if !f.called("tpm2_verifysignature") || !f.called("tpm2_policyauthorize") {
		t.Errorf("policy authorization not used: %v", f.calls)
	}
	if b, _ := os.ReadFile(c.ResultFile()); strings.TrimSpace(string(b)) != hex.EncodeToString(f.pcr15) {
		t.Errorf("result file %q", b)
	}
	if !f.called("systemd-repart --dry-run=no --json=short") {
		t.Errorf("repart call: %v", f.calls)
	}
	if _, err := os.Stat(c.WorkDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("work dir not removed: %v", err)
	}
}

func TestLaterBootVerifies(t *testing.T) {
	f := newFake()
	c := setup(t, f)
	firstBoot(t, f, c)
	f.calls = nil
	f.repartJSON = `[{"type":"var","activity":"unchanged"}]`
	if err := Repart(c, f, nil); err != nil {
		t.Fatal(err)
	}
	msg, err := Verify(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg, "provisioned") || f.called("tpm2_nvdefine") || f.called("tpm2_nvwrite") {
		t.Errorf("later boot must not provision: %q %v", msg, f.calls)
	}
}

func TestFailClosed(t *testing.T) {
	cases := []struct {
		name string
		prep func(f *fakeTPM, c Config) // after a successful first boot
		want string
	}{
		{"swapped volume", func(f *fakeTPM, c Config) { f.pcr15 = bytes.Repeat([]byte{0xAA}, 32) }, "does not match"},
		{"index removed", func(f *fakeTPM, c Config) { f.defined, f.written, f.locked = false, false, false }, "missing"},
		{"index redefined unwritten", func(f *fakeTPM, c Config) {
			f.written, f.locked, f.attrs = false, false, AttrsDefine
		}, "attributes"},
		{"index not write-locked", func(f *fakeTPM, c Config) { f.locked, f.attrs = false, AttrsDefine|0x20000000 }, "attributes"},
		{"weak attributes", func(f *fakeTPM, c Config) { f.attrs = AttrsLocked | 0x2 /* OWNERWRITE */ }, "attributes"},
		{"wrong policy", func(f *fakeTPM, c Config) { f.policy = bytes.Repeat([]byte{1}, 32) }, "authPolicy"},
		{"pcr7 changed", func(f *fakeTPM, c Config) { f.pcr7pol = bytes.Repeat([]byte{2}, 32) }, "authPolicy"},
		{"pcr15 zero", func(f *fakeTPM, c Config) { f.pcr15 = make([]byte, 32) }, "not measured"},
		{"tpm error", func(f *fakeTPM, c Config) { f.fail = map[string]error{"tpm2_nvread": errors.New("boom")} }, "boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			c := setup(t, f)
			firstBoot(t, f, c)
			tc.prep(f, c)
			_, err := Verify(c, f)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(c.ResultFile()); err == nil {
				// result file from the first boot is fine, but must not be refreshed
				b, _ := os.ReadFile(c.ResultFile())
				if tc.name == "swapped volume" && strings.Contains(string(b), "aaaa") {
					t.Error("result file updated for swapped volume")
				}
			}
		})
	}
}

func TestFirstBootRejectsPredefinedIndex(t *testing.T) {
	for _, attrs := range []uint32{AttrsLocked, AttrsDefine, 0x00040004 /* AUTHWRITE|AUTHREAD */} {
		f := newFake()
		c := setup(t, f)
		f.defined, f.written, f.locked, f.attrs, f.policy, f.content = true, true, true, attrs, f.pcr7pol, f.pcr15
		if err := Repart(c, f, nil); err != nil {
			t.Fatal(err)
		}
		_, err := Verify(c, f)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("attrs %x: err = %v", attrs, err)
		}
		if f.called("tpm2_nvwrite") {
			t.Error("wrote to a pre-defined index")
		}
	}
}

func TestFirstBootWithoutMatchingSignatureFails(t *testing.T) {
	f := newFake()
	c := setup(t, f)
	f.pcr11pol = bytes.Repeat([]byte{0x99}, 32) // phase not covered by .pcrsig
	if err := Repart(c, f, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(c, f); err == nil || !strings.Contains(err.Error(), "no signed PCR 11 policy") {
		t.Fatalf("err = %v", err)
	}
	if f.called("tpm2_nvdefine") {
		t.Error("index defined without a valid signed policy")
	}
}

func TestRepart(t *testing.T) {
	for _, tc := range []struct {
		json    string
		created bool
		err     bool
	}{
		{`[{"type":"esp","activity":"unchanged"},{"type":"var","activity":"create"}]`, true, false},
		{`[{"type":"var","activity":"unchanged"}]`, false, false},
		{`[{"type":"var","activity":"resize"}]`, false, false},
		{`[]`, false, true},
		{`[{"type":"var","activity":"create"},{"type":"var","activity":"create"}]`, false, true},
		{`not json`, false, true},
	} {
		f := newFake()
		c := setup(t, f)
		f.repartJSON = tc.json
		err := Repart(c, f, []string{"--definitions=/x"})
		if (err != nil) != tc.err {
			t.Errorf("%s: err = %v", tc.json, err)
		}
		_, serr := os.Stat(c.CreatedFlag())
		if (serr == nil) != tc.created {
			t.Errorf("%s: created flag = %v", tc.json, serr == nil)
		}
		if !f.called("systemd-repart --definitions=/x --json=short") {
			t.Errorf("repart call %v", f.calls)
		}
	}
	// a stale flag is never silently reused
	f := newFake()
	c := setup(t, f)
	if err := Repart(c, f, nil); err != nil {
		t.Fatal(err)
	}
	if err := Repart(c, f, nil); err == nil {
		t.Error("second create flag accepted")
	}
}

func TestRepartErrorPropagates(t *testing.T) {
	f := newFake()
	c := setup(t, f)
	f.fail = map[string]error{"systemd-repart": errors.New("no tpm")}
	if err := Repart(c, f, nil); err == nil {
		t.Fatal("repart error swallowed")
	}
}

// Output captured from tpm2-tools 5.7 on swtpm.
const realPublic = `0x1800e01:
  name: 000b07faf7a954ae3470233469a156a097f0f8ce25d985477420176931486d2394e4
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: policywrite|writelocked|writedefine|authread|no_da|written
    value: 0x22042808
  size: 32
  authorization policy: EB05C41A8B59DE8F4426211037729B203124BC759E30950A87CFCE5B00FF5B84

`

func TestParseNVPublicReal(t *testing.T) {
	p, err := ParseNVPublic([]byte(realPublic))
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := hex.DecodeString("EB05C41A8B59DE8F4426211037729B203124BC759E30950A87CFCE5B00FF5B84")
	if p.NameAlg != 0xB || p.Attributes != 0x22042808 || p.Size != 32 || !bytes.Equal(p.AuthPolicy, pol) {
		t.Errorf("%+v", p)
	}
	if err := CheckPublic(p, pol); err != nil {
		t.Error(err)
	}
	if AttrsLocked != 0x22042808 || AttrsDefine != 0x02042008 {
		t.Errorf("attribute constants %x %x", AttrsDefine, AttrsLocked)
	}
	if _, err := ParseNVPublic([]byte("0x1800e01:\n  size: 32\n")); err == nil {
		t.Error("incomplete output accepted")
	}
}
