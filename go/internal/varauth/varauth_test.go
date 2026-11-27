package varauth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enklave.local/base/internal/ekcert"
	"enklave.local/base/internal/sbstate"
	"enklave.local/base/internal/sbstate/sbtest"
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
		{"PCR 7 changed", func(t *testing.T, e *env) { e.pcr7 = bytes.Repeat([]byte{9}, 32) }, "Secure Boot configuration"},
		{"Secure Boot disabled", func(t *testing.T, e *env) { e.fw.SecureBoot = 0 }, "Secure Boot configuration"},
		{"dbx changed without a release update", func(t *testing.T, e *env) {
			e.fw.Vars["dbx-"+sbstate.GUIDSecurity] = sbtest.ESL(bytes.Repeat([]byte{1}, 32))
		}, "Secure Boot configuration"},
		{"PCR policy index rewritten", func(t *testing.T, e *env) {
			e.f.nv[handleNum(PCRPolicy.Handle)].data = tpmpolicy.DigestNV(bytes.Repeat([]byte{3}, 32))
		}, "Secure Boot configuration"},
		{"PCR policy index replaced", func(t *testing.T, e *env) {
			e.f.nv[handleNum(PCRPolicy.Handle)].policy = nil
		}, "authPolicy"},
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
		{"salt key replaced by another EK", func(t *testing.T, e *env) {
			k, _ := ekcert.FromPublicKey(&newEKKey().PublicKey)
			e.f.pers[handleNum(SaltHandle)] = k.TPM2B()
		}, "not the key of this TPM's EK certificate"},
		{"EK certificate removed", func(t *testing.T, e *env) { e.f.setEKCert(nil) }, "no valid EK certificate"},
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
		if e.f.h[k].auth == oldAuth[k] || e.f.h[k].auth == "garbage" || len(e.f.h[k].auth) != 64 {
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
	want := map[string]uint32{"record": 0x22042808, "secret": 0xB2082808, "counter": 0x22080018, "epoch": 0x22040028, "pcrpolicy": 0x22040002}
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

// ---------------------------------------------------------------- F1: salt key substitution

// An active bus interposer rewrites TPM2_ReadPublic responses. No session
// may ever be salted to a key it chose, wherever in the boot it starts.
func TestSaltSubstitutionMITM(t *testing.T) {
	attacker, _ := ekcert.FromPublicKey(&newEKKey().PublicKey)
	for _, from := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("later boot substituted from response %d", from), func(t *testing.T) {
			e := newEnv(t, "prod")
			if err := e.boot(t); err != nil {
				t.Fatal(err)
			}
			e.later()
			e.f.mitm = func(n int, real []byte) []byte {
				if n < from {
					return real
				}
				return attacker.TPM2B()
			}
			err := e.boot(t)
			if len(e.f.violations) > 0 {
				t.Fatalf("interposer obtained a session key: %v", e.f.violations)
			}
			if e.f.readPubs >= from && err == nil {
				t.Fatal("boot succeeded although the salt key was substituted")
			}
			if err != nil {
				wantErr(t, err, "EK certificate")
			}
		})
	}
	t.Run("first boot", func(t *testing.T) {
		e := newEnv(t, "prod")
		e.f.mitm = func(int, []byte) []byte { return attacker.TPM2B() }
		wantErr(t, e.boot(t), "not the key of this TPM's EK certificate")
		if len(e.f.violations) > 0 || len(e.f.luks[e.dev]) == 64 || e.f.h["o"].auth != "" {
			t.Fatalf("provisioned through a substituted key: %v", e.f.violations)
		}
	})
	t.Run("sessions never use a raw handle", func(t *testing.T) {
		e := newEnv(t, "prod")
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		e.later()
		e.commit(t, "config", "v1")
		e.setImage(t, "ref", "prod", 1, 1) // healing boot as well
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		for _, c := range e.f.calls {
			if strings.HasPrefix(c, "tpm2_startauthsession") && strings.Contains(c, " -c 0x") {
				t.Fatalf("session started from a raw handle (ESYS would read the public area itself): %s", c)
			}
		}
	})
}

// ---------------------------------------------------------------- F2: EK certificate

func TestEKCertificate(t *testing.T) {
	foreign := newTestCA("foreign CA")
	cases := []struct {
		name, profile string
		prep          func(e *env)
		want          string // "" = accepted
	}{
		{"valid certificate", "prod", func(e *env) {}, ""},
		{"missing certificate", "prod", func(e *env) { e.f.setEKCert(nil) }, "holds no EK certificate"},
		{"foreign CA", "prod", func(e *env) { e.f.setEKCert(foreign.ekCertificate(&e.f.ek.PublicKey)) }, "does not chain to a trusted TPM vendor CA"},
		{"mismatched EK", "prod", func(e *env) { e.f.setEKCert(vendorCA().ekCertificate(&newEKKey().PublicKey)) }, "not the key of this TPM's EK certificate"},
		{"expired certificate", "prod", func(e *env) { e.c.Now = func() time.Time { return testNow.Add(48 * time.Hour) } }, "does not chain"},
		{"corrupt certificate", "prod", func(e *env) { e.f.nv[handleNum(ekcert.ECC.CertHandle())].data[40] ^= 0xff }, "EK certificate"},
		{"clock before the build time", "prod", func(e *env) {
			// dead RTC battery: the build time of the release is used instead
			e.c.Now = func() time.Time { return time.Unix(0, 0) }
			os.WriteFile(e.c.ReleaseFile, []byte(fmt.Sprintf(`{"epoch":0,"heal_below":0,"built":%d}`, testNow.Unix())), 0o644)
		}, ""},
		{"test CA in a production image", "prod", func(e *env) {
			// emulated TPM certified by the test CA only
			os.MkdirAll(filepath.Join(e.c.EKTestCADir, "RootCA"), 0o755)
			os.WriteFile(filepath.Join(e.c.EKTestCADir, "RootCA/test.cer"), foreign.cert.Raw, 0o644)
			e.f.setEKCert(foreign.ekCertificate(&e.f.ek.PublicKey))
		}, "does not chain to a trusted TPM vendor CA"},
		{"test CA in a test image", "test", func(e *env) {
			os.MkdirAll(filepath.Join(e.c.EKTestCADir, "RootCA"), 0o755)
			os.WriteFile(filepath.Join(e.c.EKTestCADir, "RootCA/test.cer"), foreign.cert.Raw, 0o644)
			e.f.setEKCert(foreign.ekCertificate(&e.f.ek.PublicKey))
		}, ""},
		{"no certificate but EK in the signed allowlist", "prod", func(e *env) {
			e.f.setEKCert(nil)
			k, _ := ekcert.FromPublicKey(&e.f.ek.PublicKey)
			os.WriteFile(e.c.EKAllowlist, []byte("# dev VM\n"+hex.EncodeToString(k.Name())+"\n"), 0o644)
		}, ""},
		{"no certificate and another EK in the allowlist", "prod", func(e *env) {
			e.f.setEKCert(nil)
			k, _ := ekcert.FromPublicKey(&newEKKey().PublicKey)
			os.WriteFile(e.c.EKAllowlist, []byte(hex.EncodeToString(k.Name())+"\n"), 0o644)
		}, "not in the signed EK allowlist"},
		{"malformed allowlist", "prod", func(e *env) { os.WriteFile(e.c.EKAllowlist, []byte("junk\n"), 0o644) }, "allowlist"},
		{"empty vendor bundle", "prod", func(e *env) { os.RemoveAll(filepath.Join(e.c.EKCADir, "Vendor")) }, "bundle is empty"},
		{"TPM without PolicyAuthorizeNV", "prod", func(e *env) { e.f.noAuthorizeNV = true }, "revision 1.38"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.profile)
			tc.prep(e)
			err := e.boot(t)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				e.later()
				if err := e.boot(t); err != nil { // validated again on every boot
					t.Fatal(err)
				}
				return
			}
			wantErr(t, err, tc.want)
			if len(e.f.luks[e.dev]) == 64 || e.f.h["o"].auth != "" || e.f.pers[handleNum(SaltHandle)] != nil {
				t.Error("TPM or volume provisioned although the EK is not authentic")
			}
		})
	}
	t.Run("validated on every later boot", func(t *testing.T) {
		e := newEnv(t, "prod")
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		e.later()
		e.f.setEKCert(foreign.ekCertificate(&e.f.ek.PublicKey))
		wantErr(t, e.boot(t), "does not chain")
	})
	t.Run("source is recorded", func(t *testing.T) {
		e := newEnv(t, "prod")
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(readFile(e.c.SaltSourceFile()), "fake TPM vendor EK CA") {
			t.Errorf("source %q", readFile(e.c.SaltSourceFile()))
		}
	})
}

// ---------------------------------------------------------------- F4: heal checks the salt key

func TestHealChecksSaltKey(t *testing.T) {
	provisioned := func(t *testing.T) *env {
		e := newEnv(t, "prod")
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		e.later()
		e.setImage(t, "ref", "prod", 1, 1)
		return e
	}
	t.Run("another genuine TPM of the same vendor", func(t *testing.T) {
		// the endorsement key differs from the recorded one although its
		// certificate is valid: EK validation alone would accept it
		e := provisioned(t)
		key := append([]byte{}, e.f.luks[e.dev]...)
		e.f.ek = newEKKey()
		e.f.setEKCert(vendorCA().ekCertificate(&e.f.ek.PublicKey))
		wantErr(t, e.boot(t), "differs from the recorded")
		if !bytes.Equal(key, e.f.luks[e.dev]) || e.f.nv[handleNum(Secret.Handle)] == nil {
			t.Error("state destroyed although the heal was refused")
		}
	})
	t.Run("endorsement key without a valid certificate", func(t *testing.T) {
		e := provisioned(t)
		e.f.ek = newEKKey()
		wantErr(t, e.boot(t), "not the key of this TPM's EK certificate")
	})
	t.Run("EK certificate from a foreign CA", func(t *testing.T) {
		e := provisioned(t)
		e.f.setEKCert(newTestCA("foreign").ekCertificate(&e.f.ek.PublicKey))
		wantErr(t, e.boot(t), "does not chain")
	})
	t.Run("genuine", func(t *testing.T) {
		e := provisioned(t)
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
	})
}

// ---------------------------------------------------------------- F3: signed Secure Boot updates

const dbxVar = "dbx-" + sbstate.GUIDSecurity

func (e *env) shipDbx(t *testing.T, name string, hashes ...[]byte) {
	t.Helper()
	os.MkdirAll(e.c.UpdatesDir, 0o755)
	if err := os.WriteFile(filepath.Join(e.c.UpdatesDir, name), sbtest.Auth(sbtest.ESL(hashes...)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *env) vDigest() []byte { return e.f.nv[handleNum(PCRPolicy.Handle)].data }

func (e *env) updates() string { return strings.TrimSpace(readFile(e.c.EFIUpdatesFile())) }

func (e *env) mustBoot(t *testing.T, wantStatus string) {
	t.Helper()
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(e.updates(), wantStatus) {
		t.Fatalf("Secure Boot updates: %q, want %q...", e.updates(), wantStatus)
	}
}

func TestDbxUpdate(t *testing.T) {
	revoked := bytes.Repeat([]byte{0xd0}, 32)
	// device provisioned by release 0, then release 1 (epoch 1, heal as given)
	// arrives carrying a dbx append that revokes the old UKI
	start := func(t *testing.T, heal int) *env {
		e := newEnv(t, "prod")
		e.mustBoot(t, "current (0 update")
		e.later()
		e.commit(t, "config", "kept across the dbx update")
		e.setImage(t, "ref", "prod", 1, heal)
		e.shipDbx(t, "dbx-epoch0.auth", revoked)
		return e
	}
	t.Run("update then unlock then re-record", func(t *testing.T) {
		e := start(t, 0)
		old7 := append([]byte{}, e.f.pcr[7]...)
		steady := append([]byte{}, e.vDigest()...)
		e.mustBoot(t, "pending")
		if !bytes.Contains(e.fw.Vars[dbxVar], revoked) {
			t.Fatal("dbx not handed to the firmware")
		}
		if bytes.Equal(e.vDigest(), steady) {
			t.Fatal("old PCR 7 still accepted after the update was handed to the firmware")
		}
		e.mustBoot(t, "current (1 update") // PCR 7 changed: bridge, check, re-record
		if bytes.Equal(e.f.pcr[7], old7) {
			t.Fatal("test firmware did not change PCR 7")
		}
		if readFile(filepath.Join(e.c.stateMount(), "data/config")) != "kept across the dbx update" {
			t.Error("state lost")
		}
		if _, err := os.Stat(filepath.Join(e.c.stateMount(), ".pcr7")); !errors.Is(err, os.ErrNotExist) {
			t.Error("transition record left behind")
		}
		final := append([]byte{}, e.vDigest()...)
		e.mustBoot(t, "current (1 update")
		if !bytes.Equal(final, e.vDigest()) || bytes.Equal(final, steady) {
			t.Error("V not stable on the new PCR 7")
		}
		e.commit(t, "config", "v2")
		// the old Secure Boot state (dbx rolled back) is no longer accepted
		e.fw.Vars[dbxVar] = nil
		wantErr(t, e.boot(t), "Secure Boot configuration")
	})
	t.Run("with healing", func(t *testing.T) {
		e := start(t, 1)
		key := append([]byte{}, e.f.luks[e.dev]...)
		e.mustBoot(t, "pending")
		if bytes.Equal(key, e.f.luks[e.dev]) {
			t.Fatal("not healed")
		}
		key = append([]byte{}, e.f.luks[e.dev]...)
		e.mustBoot(t, "current (1 update")
		if !bytes.Equal(key, e.f.luks[e.dev]) {
			t.Fatal("healed twice")
		}
		// the revoked epoch-0 UKI is refused by the TPM as well
		e.setImage(t, "ref", "prod", 0, 0)
		wantErr(t, e.boot(t), "revoked")
	})
	t.Run("power loss before the firmware took the update", func(t *testing.T) {
		e := start(t, 0)
		cv := &crashVars{Firmware: e.fw, crash: true}
		e.c.EFI = cv
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("crash point not reached")
				}
			}()
			e.boot(t) //nolint:errcheck
		}()
		cv.crash = false
		e.mustBoot(t, "pending") // PCR 7 unchanged, boot chain binding holds, update handed over again
		e.mustBoot(t, "current (1 update")
	})
	t.Run("power loss after the firmware took the update", func(t *testing.T) {
		e := start(t, 0)
		cv := &crashVars{Firmware: e.fw, crashAfter: true}
		e.c.EFI = cv
		func() {
			defer func() { recover() }() //nolint:errcheck
			e.boot(t)                    //nolint:errcheck
		}()
		cv.crashAfter = false
		e.mustBoot(t, "current (1 update")
	})
	t.Run("firmware rejects the update", func(t *testing.T) {
		e := start(t, 0)
		steady := append([]byte{}, e.vDigest()...)
		e.fw.Reject = errors.New("EACCES")
		e.mustBoot(t, "failed: NOT APPLIED: dbx-epoch0.auth")
		if !bytes.Equal(steady, e.vDigest()) {
			t.Error("binding changed although nothing was applied")
		}
		e.mustBoot(t, "failed") // still boots, still reports
		e.fw.Reject = nil
		e.mustBoot(t, "pending")
		e.mustBoot(t, "current (1 update")
	})
	t.Run("event log does not explain PCR 7 so blocked and no brick", func(t *testing.T) {
		e := newEnv(t, "prod")
		e.pcr7 = bytes.Repeat([]byte{0x42}, 32)
		e.mustBoot(t, "current")
		e.later()
		e.shipDbx(t, "dbx-epoch0.auth", revoked)
		e.mustBoot(t, "blocked")
		if e.fw.Vars[dbxVar] != nil {
			t.Error("update applied although the transition cannot be carried")
		}
		e.mustBoot(t, "blocked")
	})
	// attacks while the transition is open: nothing but the same boot chain
	// with an unchanged Secure Boot configuration (plus the signed update)
	// may complete it
	for name, tc := range map[string]struct {
		mut  func(e *env)
		want string
	}{
		"secure boot disabled":      {func(e *env) { e.fw.SecureBoot = 0 }, "changed beyond the signed updates"},
		"db key enrolled":           {func(e *env) { e.fw.Vars["db-"+sbstate.GUIDSecurity] = []byte("attacker") }, "changed beyond the signed updates"},
		"other signing authority":   {func(e *env) { e.fw.Authority = []byte("attacker cert") }, "changed beyond the signed updates"},
		"additional authority":      {func(e *env) { e.fw.Extra = []sbtest.Ev{{PCR: 7, Type: 0x800000E0, Data: []byte("x")}} }, "changed beyond the signed updates"},
		"other boot loader (PCR 4)": {func(e *env) { e.f.pcr[4] = bytes.Repeat([]byte{0x44}, 32) }, "Secure Boot configuration, firmware or boot chain changed"},
		"other firmware (PCR 0)":    {func(e *env) { e.f.pcr[0] = bytes.Repeat([]byte{0x40}, 32) }, "Secure Boot configuration, firmware or boot chain changed"},
		"option ROM/driver (PCR 2)": {func(e *env) { e.f.pcr[2] = bytes.Repeat([]byte{0x41}, 32) }, "Secure Boot configuration, firmware or boot chain changed"},
		"ESP credential (PCR 12)":   {func(e *env) { e.f.pcr[12] = bytes.Repeat([]byte{1}, 32) }, "PCR 12"},
		"transition record removed": {func(e *env) { os.Remove(filepath.Join(e.c.stateMount(), ".pcr7")) }, "record is missing"},
		"transition record forged": {func(e *env) {
			os.WriteFile(filepath.Join(e.c.stateMount(), ".pcr7"), []byte(`{"events":[],"vars":[],"mac":"00"}`), 0o600)
		}, "not authentic"},
		"event log tampered":         {func(e *env) { e.pcr7 = bytes.Repeat([]byte{0x43}, 32) }, "replays PCR 7"},
		"another UKI (other PCR 11)": {func(e *env) { e.f.pcr[11] = bytes.Repeat([]byte{0x5a}, 32) }, "no signed approved policy"},
	} {
		t.Run("pending transition: "+name, func(t *testing.T) {
			e := start(t, 0)
			e.mustBoot(t, "pending")
			tc.mut(e)
			wantErr(t, e.boot(t), tc.want)
		})
	}
}

type crashVars struct {
	*sbtest.Firmware
	crash, crashAfter bool
}

func (c *crashVars) Append(name, guid string, auth []byte) error {
	if c.crash {
		panic("power loss before the variable write")
	}
	err := c.Firmware.Append(name, guid, auth)
	if c.crashAfter {
		panic("power loss after the variable write")
	}
	return err
}

// ---------------------------------------------------------------- M1: recovery of an interrupted provisioning

// A healing release recovers a provisioning that was interrupted after the
// lock-down; cuts before the lock-down need a factory reset.
func TestInterruptedProvisioningRecovery(t *testing.T) {
	for step, recoverable := range map[string]bool{"salt-created": false, "epoch-defined": false,
		"locked": true, "secret-written": true, "formatted": true, "state-initialized": true} {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t, "test")
			os.MkdirAll(filepath.Join(e.c.espMount(), "EFI/enklave"), 0o700)
			os.WriteFile(filepath.Join(e.c.espMount(), "EFI/enklave/test-pause"), []byte(step), 0o600)
			old := pauseHook
			pauseHook = func(s string) { panic(crash{s}) }
			func() {
				defer func() { recover() }() //nolint:errcheck
				e.boot(t)                    //nolint:errcheck
			}()
			pauseHook = old
			os.Remove(filepath.Join(e.c.espMount(), "EFI/enklave/test-pause"))
			e.later()
			e.setImage(t, "ref", "test", 1, 1)
			err := e.boot(t)
			if recoverable && err != nil {
				t.Fatalf("healing release did not recover: %v", err)
			}
			if !recoverable {
				wantErr(t, err, "not locked")
			}
		})
	}
}

// The endorsement key is DA protected: once it was used as a salt key, a
// power cut counts as a failed authorization and after TPM2_PT_MAX_AUTH_FAIL
// of them salted sessions are refused (observed on swtpm: 3 power cuts,
// TPM_RC_LOCKOUT 0x921). Neither power cuts nor deliberately failed
// authorizations may lock a device out.
func TestPowerCutsDoNotLockOut(t *testing.T) {
	e := newEnv(t, "prod")
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	e.later()
	for i := 0; i < 6; i++ {
		e.f.powerCut()
		if err := e.boot(t); err != nil {
			t.Fatalf("boot after power cut %d: %v", i+1, err)
		}
		e.commit(t, "config", fmt.Sprint(i))
	}
	if e.f.daInterval != 0 || e.f.daCounter != 0 {
		t.Errorf("DA lockout not disabled: interval %d, counter %d", e.f.daInterval, e.f.daCounter)
	}
	// an attacker drove the TPM into lockout (failed authorizations on the
	// owner hierarchy): the next boot recovers by itself
	e.f.daInterval, e.f.daCounter = 1000, 99
	if err := e.boot(t); err != nil {
		t.Fatalf("boot with the TPM in lockout: %v", err)
	}
	// also when the healing release is the one that finds it
	e.f.daInterval, e.f.daCounter = 1000, 99
	e.setImage(t, "ref", "prod", 1, 1)
	if err := e.boot(t); err != nil {
		t.Fatalf("healing boot with the TPM in lockout: %v", err)
	}
}

// Power loss inside the PCR 7 transition at the test pause points (the VM
// proofs cut the power at the same points).
func TestDbxUpdatePowerLossAtPausePoints(t *testing.T) {
	for _, step := range []string{"pcr7-bridge", "pcr7-applied"} {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t, "test")
			e.mustBoot(t, "current")
			e.later()
			e.setImage(t, "ref", "test", 1, 0)
			e.shipDbx(t, "dbx-epoch0.auth", bytes.Repeat([]byte{0xd0}, 32))
			os.MkdirAll(filepath.Join(e.c.espMount(), "EFI/enklave"), 0o700)
			os.WriteFile(filepath.Join(e.c.espMount(), "EFI/enklave/test-pause"), []byte(step), 0o600)
			old := pauseHook
			pauseHook = func(s string) { panic(crash{s}) }
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("pause point not reached")
					}
				}()
				e.boot(t) //nolint:errcheck
			}()
			pauseHook = old
			os.Remove(filepath.Join(e.c.espMount(), "EFI/enklave/test-pause"))
			e.f.powerCut()
			if step == "pcr7-bridge" {
				e.mustBoot(t, "pending") // nothing reached the firmware yet
			}
			e.mustBoot(t, "current (1 update")
			e.mustBoot(t, "current (1 update")
		})
	}
}

func TestHealRecordsSaltCheck(t *testing.T) {
	e := newEnv(t, "prod")
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	e.later()
	e.setImage(t, "ref", "prod", 1, 1)
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(e.c.SaltSourceFile()), "re-created salt key has the Name recorded at provisioning") {
		t.Errorf("source %q", readFile(e.c.SaltSourceFile()))
	}
}
