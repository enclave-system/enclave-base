package varauth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enklave.local/base/internal/tpmpolicy"
)

func b64(s string) string      { return base64.StdEncoding.EncodeToString([]byte(s)) }
func mustJSON(v any) []byte    { b, _ := json.Marshal(v); return b }
func readFile(p string) string { b, _ := os.ReadFile(p); return string(b) }
func manifestVersion(e *env) int {
	var m struct{ Version int }
	json.Unmarshal([]byte(readFile(filepath.Join(e.c.stateMount(), ".manifest"))), &m)
	return m.Version
}

type crash struct{ step string }

func TestFirstAndLaterBoots(t *testing.T) {
	e := newEnv(t, "prod")
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	f := e.f
	for _, ix := range allIndices {
		got := f.nv[handleNum(ix.Handle)]
		want := ix.Final
		if ix == Secret {
			want = Secret.Final
		}
		if got == nil || got.attrs != want {
			t.Fatalf("%s: %+v", ix.Name, got)
		}
	}
	for _, hi := range []string{"o", "e", "l"} {
		if f.h[hi].auth == "" || len(f.h[hi].policy) == 0 {
			t.Errorf("hierarchy %s not locked: %+v", hi, f.h[hi])
		}
	}
	if !f.disClear || f.pers[handleNum(SaltHandle)] == nil {
		t.Error("clear not disabled or salt key missing")
	}
	if readFile(e.c.PlatformFile()) != "firmware-auth\n" {
		t.Errorf("platform %q", readFile(e.c.PlatformFile()))
	}
	if manifestVersion(e) != int(e.counter()) {
		t.Errorf("manifest %d counter %d", manifestVersion(e), e.counter())
	}
	joined := strings.Join(f.calls, "\n")
	for _, want := range []string{"--integrity hmac-sha256", "--pbkdf argon2id", "--cipher aes-xts-plain64",
		"headless=true,keyfile-erase,tpm2-measure-pcr=yes", "tpm2_clearcontrol -C l s", "tpm2_setprimarypolicy -C o"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q", want)
		}
	}
	// lock-down happens before the secret index is defined (N1)
	if strings.Index(joined, "tpm2_changeauth -c l") > strings.Index(joined, "tpm2_nvdefine "+Secret.Handle) {
		t.Error("secret defined before the hierarchy lock-down")
	}

	e.later()
	c := e.counter()
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	e.commit(t, "config", "v1")
	if e.counter() != c+1 || manifestVersion(e) != int(c+1) {
		t.Errorf("commit: counter %d manifest %d", e.counter(), manifestVersion(e))
	}
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if f.nv[handleNum(Secret.Handle)].attrs&attrReadLocked == 0 {
		t.Error("secret not read-locked after unlock")
	}
	if err := Probe(e.c, f); err == nil {
		t.Error("key readable after unlock")
	}
}

func TestInterruptedProvisioningFailsClosed(t *testing.T) {
	for _, step := range []string{"salt-created", "epoch-defined", "locked", "secret-written", "formatted", "state-initialized"} {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t, "test")
			os.MkdirAll(filepath.Join(e.c.espMount(), "EFI/enklave"), 0o700)
			os.WriteFile(filepath.Join(e.c.espMount(), "EFI/enklave/test-pause"), []byte(step), 0o600)
			old := pauseHook
			pauseHook = func(s string) { panic(crash{s}) }
			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Fatal("pause point not reached")
					}
				}()
				e.boot(t) //nolint:errcheck
			}()
			pauseHook = old
			os.Remove(filepath.Join(e.c.espMount(), "EFI/enklave/test-pause"))
			e.later()
			if err := e.boot(t); err == nil {
				t.Fatal("partial provisioning accepted")
			}
			// an attacker who completes the lock-down himself gains nothing
			for _, hi := range []string{"o", "e", "l"} {
				if e.f.h[hi].auth == "" {
					e.f.h[hi].auth = "attacker"
				}
			}
			e.f.disClear = true
			if err := e.boot(t); err == nil {
				t.Fatal("partial provisioning accepted after attacker lock-down")
			}
		})
	}
}

func TestAttacksAfterProvisioning(t *testing.T) {
	cases := []struct {
		name string
		prep func(t *testing.T, e *env)
		want string
	}{
		{"swapped volume", func(t *testing.T, e *env) { e.f.luks[e.dev] = bytes.Repeat([]byte{0xAA}, 64) }, "wrong key"},
		{"tainted PCR 12", func(t *testing.T, e *env) { e.f.pcr[12] = bytes.Repeat([]byte{1}, 32) }, "PCR 12"},
		{"PCR 7 changed", func(t *testing.T, e *env) { e.f.pcr[7] = bytes.Repeat([]byte{9}, 32) }, "authPolicy"},
		{"unknown UKI", func(t *testing.T, e *env) { e.f.pcr[11] = bytes.Repeat([]byte{0x5a}, 32) }, "no signed approved policy"},
		{"forged signature", func(t *testing.T, e *env) {
			p := signed(t, e.f.pcr[11], 0, "ref", "prod")
			p.Signature = b64("SIG:00")
			os.RemoveAll(filepath.Join(e.c.espMount(), e.c.PolicyDir))
			e.install(t, p)
		}, "signature rejected"},
		{"test-profile UKI on prod state", func(t *testing.T, e *env) { e.setImage(t, "ref", "test", 0, 0) }, "authPolicy"},
		{"other role UKI", func(t *testing.T, e *env) { e.setImage(t, "client", "prod", 0, 0) }, "authPolicy"},
		{"epoch revoked", func(t *testing.T, e *env) {
			binary.BigEndian.PutUint64(e.f.nv[handleNum(Epoch.Handle)].data, 1)
		}, "revoked"},
		{"release/policy epoch mismatch", func(t *testing.T, e *env) {
			os.WriteFile(e.c.ReleaseFile, []byte(`{"epoch":1,"heal_below":0}`), 0o644)
		}, "release epoch"},
		{"salt key substituted", func(t *testing.T, e *env) { e.f.pers[handleNum(SaltHandle)] = []byte{0, 0x0b, 1, 2} }, "salt key"},
		{"hierarchy unlocked", func(t *testing.T, e *env) { e.f.h["o"].auth = "" }, "not locked"},
		{"secret undefined", func(t *testing.T, e *env) { delete(e.f.nv, handleNum(Secret.Handle)) }, "partial"},
		{"record altered", func(t *testing.T, e *env) {
			e.f.nv[handleNum(Record.Handle)].data[0] ^= 1
		}, "does not match NV record"},
		{"counter policy replaced", func(t *testing.T, e *env) {
			e.f.nv[handleNum(Counter.Handle)].policy = bytes.Repeat([]byte{5}, 32)
		}, "authPolicy"},
		{"state file tampered", func(t *testing.T, e *env) {
			os.WriteFile(filepath.Join(e.c.stateMount(), "data/config"), []byte("evil"), 0o644)
		}, "manifest"},
		{"state rolled back", func(t *testing.T, e *env) {
			ix := e.f.nv[handleNum(Counter.Handle)]
			binary.BigEndian.PutUint64(ix.data, binary.BigEndian.Uint64(ix.data)+1)
		}, "ROLLBACK"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, "prod")
			if err := e.boot(t); err != nil {
				t.Fatal(err)
			}
			e.later()
			if err := e.boot(t); err != nil {
				t.Fatal(err)
			}
			e.commit(t, "config", "v1")
			tc.prep(t, e)
			wantErr(t, e.boot(t), tc.want)
		})
	}
}

func TestFirstBootRefusals(t *testing.T) {
	cases := []struct {
		name string
		prep func(e *env)
		want string
	}{
		{"pre-defined index", func(e *env) { e.f.nv[handleNum(Secret.Handle)] = &nvIdx{attrs: 0x00060006, size: 64} }, "not fresh"},
		{"owner auth set", func(e *env) { e.f.h["o"].auth = "x" }, "not fresh"},
		{"tainted PCR 12", func(e *env) { e.f.pcr[12] = bytes.Repeat([]byte{1}, 32) }, "PCR 12"},
		{"existing LUKS header", func(e *env) { e.f.luks[e.dev] = []byte("x") }, "LUKS header"},
		{"platform hierarchy error", func(e *env) {
			e.f.fail = map[string]error{"tpm2_hierarchycontrol": errors.New("TPM_RC_FAILURE")}
		}, "platform hierarchy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, "prod")
			tc.prep(e)
			wantErr(t, e.boot(t), tc.want)
			if len(e.f.luks[e.dev]) == 64 {
				t.Error("volume formatted despite refusal")
			}
		})
	}
}

func TestPlatformHierarchy(t *testing.T) {
	e := newEnv(t, "prod")
	e.f.h["p"].auth = ""
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if e.f.phEnable || readFile(e.c.PlatformFile()) != "disabled-by-enklave\n" {
		t.Errorf("platform not disabled: %v %q", e.f.phEnable, readFile(e.c.PlatformFile()))
	}
}

func TestHealing(t *testing.T) {
	e := newEnv(t, "prod")
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	e.later()
	e.commit(t, "config", "secret data of epoch 0")
	oldKey := append([]byte{}, e.f.luks[e.dev]...)
	oldAuth := map[string]string{}
	for k, v := range e.f.h {
		oldAuth[k] = v.auth
	}
	oldSalt := e.f.pers[handleNum(SaltHandle)]

	// release epoch 1 declares everything provisioned before epoch 1 compromised
	e.setImage(t, "ref", "prod", 1, 1)
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(e.f.luks[e.dev], oldKey) {
		t.Error("volume key not replaced")
	}
	for _, k := range []string{"o", "e", "l"} {
		if e.f.h[k].auth == oldAuth[k] {
			t.Errorf("hierarchy %s auth not rotated", k)
		}
	}
	rec, _ := ParseRecord(e.f.nv[handleNum(Record.Handle)].data)
	if rec.Epoch != 1 {
		t.Errorf("record epoch %d", rec.Epoch)
	}
	if _, err := os.Stat(filepath.Join(e.c.stateMount(), "data/config")); !errors.Is(err, os.ErrNotExist) {
		t.Error("state of the compromised epoch survived healing")
	}
	if bytes.Equal(oldSalt, e.f.pers[handleNum(SaltHandle)]) == false {
		// same owner seed: the deterministic salt key is re-created identically
		t.Error("salt key not re-created deterministically")
	}
	if binary.BigEndian.Uint64(e.f.nv[handleNum(Epoch.Handle)].data)&1 == 0 {
		t.Error("epoch 0 not revoked")
	}
	// the old key no longer opens anything and an epoch-0 UKI is refused
	if bytes.Equal(e.f.luks[e.dev], oldKey) {
		t.Error("old key still valid")
	}
	e.setImage(t, "ref", "prod", 0, 0)
	wantErr(t, e.boot(t), "revoked")
	// healing is not repeated by the same release
	e.setImage(t, "ref", "prod", 1, 1)
	key := append([]byte{}, e.f.luks[e.dev]...)
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, e.f.luks[e.dev]) {
		t.Error("healed again although record epoch >= heal_below")
	}
}

func TestInterruptedHealRecovers(t *testing.T) {
	e := newEnv(t, "test")
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	e.later()
	e.setImage(t, "ref", "test", 1, 1)
	os.MkdirAll(filepath.Join(e.c.espMount(), "EFI/enklave"), 0o700)
	os.WriteFile(filepath.Join(e.c.espMount(), "EFI/enklave/test-pause"), []byte("healed-tpm"), 0o600)
	old := pauseHook
	pauseHook = func(s string) { panic(crash{s}) }
	func() {
		defer func() { recover() }() //nolint:errcheck
		e.boot(t)                    //nolint:errcheck
	}()
	pauseHook = old
	os.Remove(filepath.Join(e.c.espMount(), "EFI/enklave/test-pause"))
	if err := e.boot(t); err != nil {
		t.Fatalf("interrupted heal not recoverable by the healing release: %v", err)
	}
}

func TestRevocationOfOlderEpochs(t *testing.T) {
	e := newEnv(t, "prod")
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	e.later()
	e.setImage(t, "ref", "prod", 2, 0)
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if v := binary.BigEndian.Uint64(e.f.nv[handleNum(Epoch.Handle)].data); v != 3 {
		t.Fatalf("E = %x", v)
	}
	e.setImage(t, "ref", "prod", 0, 0)
	wantErr(t, e.boot(t), "revoked")
}

func TestSealed(t *testing.T) {
	e := newEnv(t, "prod")
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	sig := filepath.Join(e.c.RunDir, "pcrsig.json")
	os.WriteFile(sig, []byte(`{"sha256":[{"pcrs":[11],"pol":"`+strings.Repeat("ab", 32)+`"}]}`), 0o600)
	// still in the signed phase
	if _, err := Sealed(e.c, e.f, sig); err == nil {
		t.Fatal("signed phase reported sealed")
	}
	e.f.pcr[11] = h(e.f.pcr[11], []byte("sysinit"))
	if _, err := Sealed(e.c, e.f, sig); err != nil {
		t.Fatal(err)
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
		{`[]`, false, true},
		{`[{"type":"var","activity":"create"},{"type":"var","activity":"create"}]`, false, true},
		{`not json`, false, true},
	} {
		e := newEnv(t, "prod")
		e.f.repart = tc.json
		err := Repart(e.c, e.f, []string{"--definitions=/x"})
		if (err != nil) != tc.err {
			t.Errorf("%s: err = %v", tc.json, err)
		}
		if _, serr := os.Stat(e.c.CreatedFlag()); (serr == nil) != tc.created {
			t.Errorf("%s: created flag = %v", tc.json, serr == nil)
		}
	}
	e := newEnv(t, "prod")
	e.f.pcr[12] = bytes.Repeat([]byte{1}, 32)
	wantErr(t, Repart(e.c, e.f, nil), "PCR 12")
}

const realPublic = `0x1800e01:
  name: 000b07faf7a954ae3470233469a156a097f0f8ce25d985477420176931486d2394e4
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: policywrite|writelocked|writedefine|authread|no_da|written
    value: 0x22042808
  size: 74
  authorization policy: EB05C41A8B59DE8F4426211037729B203124BC759E30950A87CFCE5B00FF5B84

`

func TestParseHelpers(t *testing.T) {
	p, err := ParseNVPublic([]byte(realPublic))
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := hex.DecodeString("EB05C41A8B59DE8F4426211037729B203124BC759E30950A87CFCE5B00FF5B84")
	if err := CheckPublic(Record, p, Record.Final, pol); err != nil {
		t.Error(err)
	}
	if err := CheckPublic(Record, p, Record.Final, nil); err == nil {
		t.Error("empty expected policy accepted")
	}
	want := map[string]uint32{"record": 0x22042808, "secret": 0xB2082808, "counter": 0x22080018, "epoch": 0x22040028}
	for _, ix := range allIndices {
		if ix.Final != want[ix.Name] {
			t.Errorf("%s final 0x%08x", ix.Name, ix.Final)
		}
	}
	rd := RecordData{PCR15: bytes.Repeat([]byte{1}, 32), Epoch: 7, SaltName: bytes.Repeat([]byte{2}, 34)}
	if back, err := ParseRecord(rd.bytes()); err != nil || back.Epoch != 7 || !bytes.Equal(back.SaltName, rd.SaltName) {
		t.Errorf("%+v %v", back, err)
	}
	if _, err := ParseRecord([]byte{1}); err == nil {
		t.Error("short record accepted")
	}
	_ = tpmpolicy.RefPrefix
}
