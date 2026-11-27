package varauth

import (
	"bytes"
	"crypto/x509"
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
		}, "is not the authenticated key of this TPM"},
		{"EK certificate removed", func(t *testing.T, e *env) { e.f.setEKCert(nil) }, "no signed per-device admission"},
		{"transition index rewritten", func(t *testing.T, e *env) {
			e.f.nv[handleNum(Transition.Handle)].policy = nil
		}, "authPolicy"},
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
	want := map[string]uint32{"record": 0x22042808, "secret": 0xB2082808, "counter": 0x22080018, "epoch": 0x22040028, "pcrpolicy": 0x22040002, "transition": 0x22040002}
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
		wantErr(t, e.boot(t), "is not the authenticated key of this TPM")
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
	var t0 *testing.T
	foreign := newTestCA("foreign CA")
	cases := []struct {
		name, profile string
		prep          func(e *env)
		want          string // "" = accepted
	}{
		{"valid certificate", "prod", func(e *env) {}, ""},
		{"missing certificate", "prod", func(e *env) { e.f.setEKCert(nil) }, "holds no EK certificate"},
		{"foreign CA", "prod", func(e *env) { e.f.setEKCert(foreign.ekCertificate(&e.f.ek.PublicKey)) }, "does not chain to a trusted TPM vendor CA"},
		{"mismatched EK", "prod", func(e *env) { e.f.setEKCert(vendorCA().ekCertificate(&newEKKey().PublicKey)) }, "is not the authenticated key of this TPM"},
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
		{"certificate without the EK extended key usage", "prod", func(e *env) {
			e.f.setEKCert(vendorCA().certificate(&e.f.ek.PublicKey, func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil }))
		}, "not issued for endorsement keys"},
		{"certificate without TPM attributes", "prod", func(e *env) {
			e.f.setEKCert(vendorCA().certificate(&e.f.ek.PublicKey, func(c *x509.Certificate) { c.ExtraExtensions = nil }))
		}, "manufacturer, model and version"},
		{"require_ftpm and a discrete-TPM vendor", "prod", func(e *env) {
			e.requireFTPM = true
			e.setImage(t0, "ref", "prod", 0, 0)
		}, "requires a firmware TPM"},
		{"require_ftpm and a firmware-TPM vendor", "prod", func(e *env) {
			e.requireFTPM = true
			e.setImage(t0, "ref", "prod", 0, 0)
			os.Rename(filepath.Join(e.c.EKCADir, "Vendor"), filepath.Join(e.c.EKCADir, "Intel"))
		}, ""},
		{"empty vendor bundle", "prod", func(e *env) { os.RemoveAll(filepath.Join(e.c.EKCADir, "Vendor")) }, "bundle is empty"},
		{"TPM without PolicyAuthorizeNV", "prod", func(e *env) { e.f.noAuthorizeNV = true }, "revision 1.38"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.profile)
			t0 = t
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
		wantErr(t, e.boot(t), "is not the authenticated key of this TPM")
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
	older := bytes.Repeat([]byte{0x0d}, 32) // a revocation the device already has
	start := func(t *testing.T, heal int) *env {
		e := newEnv(t, "prod")
		e.fw.Vars[dbxVar] = sbtest.ESL(older)
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
		if ts := e.f.nv[handleNum(Transition.Handle)].data; ts[64] != 0 {
			t.Errorf("transition index not idle after completion: state %d", ts[64])
		}
		final := append([]byte{}, e.vDigest()...)
		e.mustBoot(t, "current (1 update")
		if !bytes.Equal(final, e.vDigest()) || bytes.Equal(final, steady) {
			t.Error("V not stable on the new PCR 7")
		}
		e.commit(t, "config", "v2")
		// the old Secure Boot state (dbx rolled back) is no longer accepted
		e.fw.Vars[dbxVar] = sbtest.ESL(older)
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
	t.Run("event log unusable after enrolment so blocked and no brick", func(t *testing.T) {
		e := newEnv(t, "prod")
		e.mustBoot(t, "current")
		e.later()
		e.badLog = true // cannot happen without a firmware change: provisioning checks the log (B7)
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
		"secure boot disabled":       {func(e *env) { e.fw.SecureBoot = 0 }, "neither the state before the update"},
		"db key enrolled":            {func(e *env) { e.fw.Vars["db-"+sbstate.GUIDSecurity] = []byte("attacker") }, "neither the state before the update"},
		"other signing authority":    {func(e *env) { e.fw.Authority = []byte("attacker cert") }, "neither the state before the update"},
		"additional authority":       {func(e *env) { e.fw.Extra = []sbtest.Ev{{PCR: 7, Type: 0x800000E0, Data: []byte("x")}} }, "neither the state before the update"},
		"other boot loader (PCR 4)":  {func(e *env) { e.f.pcr[4] = bytes.Repeat([]byte{0x44}, 32) }, "Secure Boot configuration, firmware or boot chain changed"},
		"other firmware (PCR 0)":     {func(e *env) { e.f.pcr[0] = bytes.Repeat([]byte{0x40}, 32) }, "Secure Boot configuration, firmware or boot chain changed"},
		"option ROM/driver (PCR 2)":  {func(e *env) { e.f.pcr[2] = bytes.Repeat([]byte{0x41}, 32) }, "Secure Boot configuration, firmware or boot chain changed"},
		"ESP credential (PCR 12)":    {func(e *env) { e.f.pcr[12] = bytes.Repeat([]byte{1}, 32) }, "PCR 12"},
		"transition index cleared":   {func(e *env) { e.f.nv[handleNum(Transition.Handle)].data = make([]byte, Transition.Size) }, "no Secure Boot update is in transit"},
		"transition index replaced":  {func(e *env) { e.f.nv[handleNum(Transition.Handle)].attrs |= attrPolicyWrite }, "attributes"},
		"older dbx entry dropped":    {func(e *env) { e.fw.Vars[dbxVar] = sbtest.ESL(revoked) }, "neither the state before the update"},
		"foreign dbx entry added":    {func(e *env) { e.fw.Vars[dbxVar] = sbtest.ESL(older, revoked, bytes.Repeat([]byte{9}, 32)) }, "neither the state before the update"},
		"KEK replaced":               {func(e *env) { e.fw.Vars["KEK-"+sbstate.GUIDGlobal] = []byte("attacker") }, "neither the state before the update"},
		"event log tampered":         {func(e *env) { e.pcr7 = bytes.Repeat([]byte{0x43}, 32) }, "replays PCR 7"},
		"another UKI (other PCR 11)": {func(e *env) { e.f.pcr[11] = bytes.Repeat([]byte{0x5a}, 32) }, "no signed approved policy"},
	} {
		t.Run("pending transition: "+name, func(t *testing.T) {
			e := start(t, 0)
			e.mustBoot(t, "pending")
			tc.mut(e)
			n := len(e.f.calls)
			wantErr(t, e.boot(t), tc.want)
			// B2: refused before the volume key leaves the TPM
			for _, c := range e.f.calls[n:] {
				if strings.HasPrefix(c, "tpm2_nvread "+Secret.Handle) {
					t.Fatal("volume key read from the TPM although the Secure Boot state is not an expected one")
				}
			}
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

// ---------------------------------------------------------------- round 5

// B1: admission of a TPM without EK certificate is a signature for exactly
// one endorsement key, under its own policyRef.
func TestEKAdmission(t *testing.T) {
	noCert := func(t *testing.T, profile string) *env {
		e := newEnv(t, profile)
		e.f.setEKCert(nil)
		return e
	}
	t.Run("admitted device", func(t *testing.T) {
		e := noCert(t, "dev")
		e.admit(t, e.ekName())
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(readFile(e.c.SaltSourceFile()), "signed per-device admission") {
			t.Errorf("source %q", readFile(e.c.SaltSourceFile()))
		}
		e.later()
		e.commit(t, "config", "v1")
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		// its objects are bound to the per-device ref, not to the base ref
		base := newEnv(t, "dev")
		if err := base.boot(t); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(e.f.nv[handleNum(Secret.Handle)].policy, base.f.nv[handleNum(Secret.Handle)].policy) {
			t.Error("admitted and certified devices share policy P")
		}
		// healing keeps working, also after the salt key was already evicted
		e.setImage(t, "ref", "dev", 1, 1)
		delete(e.f.pers, handleNum(SaltHandle))
		delete(e.f.nv, handleNum(Record.Handle))
		if err := e.boot(t); err != nil {
			t.Fatalf("heal of an admitted device: %v", err)
		}
	})
	t.Run("admission of another device", func(t *testing.T) {
		e := noCert(t, "dev")
		e.admit(t, append([]byte{0, 0x0b}, bytes.Repeat([]byte{7}, 32)...))
		wantErr(t, e.boot(t), "no signed per-device admission")
		if e.f.h["o"].auth != "" || e.f.pers[handleNum(SaltHandle)] != nil || len(e.f.luks[e.dev]) == 64 {
			t.Error("provisioned without an admission")
		}
	})
	t.Run("admission signed for another profile", func(t *testing.T) {
		e := noCert(t, "prod")
		e.install(t, signedRef(t, e.f.pcr[11], 0, "ref", "dev", tpmpolicy.RefEK(refOf("ref", "dev"), e.ekName())))
		wantErr(t, e.boot(t), "no signed per-device admission")
	})
	t.Run("forged admission", func(t *testing.T) {
		e := noCert(t, "dev")
		p := signedRef(t, e.f.pcr[11], 0, "ref", "dev", tpmpolicy.RefEK(refOf("ref", "dev"), e.ekName()))
		p.Signature = b64("SIG:00")
		e.install(t, p)
		wantErr(t, e.boot(t), "signature rejected")
		if e.f.h["o"].auth != "" || e.f.pers[handleNum(SaltHandle)] != nil || len(e.f.nv) != 0 {
			t.Error("TPM changed although the admission is forged")
		}
	})
	t.Run("a certified TPM is never matched against admissions", func(t *testing.T) {
		e := newEnv(t, "dev")
		e.admit(t, e.ekName()) // even an admission of its own key is ignored
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(readFile(e.c.SaltSourceFile()), "EK certificate") {
			t.Errorf("source %q", readFile(e.c.SaltSourceFile()))
		}
	})
	// The round-4 bypass: an EK admitted "elsewhere" (here even for this very
	// release) is presented by an interposer on a certificate-provisioned
	// device; it hides the certificate and rewrites the unauthenticated
	// record. The device must refuse and no session may reach that key.
	t.Run("admitted foreign EK presented on a certified device", func(t *testing.T) {
		e := newEnv(t, "dev")
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		e.later()
		other, _ := ekcert.FromPublicKey(&newEKKey().PublicKey)
		e.admit(t, other.Name())
		e.f.setEKCert(nil)
		e.f.mitm = func(int, []byte) []byte { return other.TPM2B() }
		copy(e.f.nv[handleNum(Record.Handle)].data[40:], other.Name())
		err := e.boot(t)
		if len(e.f.violations) > 0 {
			t.Fatalf("session salted to the foreign admitted key: %v", e.f.violations)
		}
		wantErr(t, err, "authPolicy") // the admitted ref opens none of this device's objects
	})
	t.Run("admitted foreign EK presented on a fresh device", func(t *testing.T) {
		e := noCert(t, "dev")
		other, _ := ekcert.FromPublicKey(&newEKKey().PublicKey)
		e.admit(t, other.Name())
		e.f.mitm = func(int, []byte) []byte { return other.TPM2B() }
		// An admission is a statement about ONE key. If that key is not in
		// this TPM, the TPM cannot decrypt a salt encrypted to it: the first
		// salted session fails, before any authValue or key is set.
		if err := e.boot(t); err == nil {
			t.Fatal("provisioned with an endorsement key the TPM does not hold")
		}
		if e.f.h["o"].auth != "" || e.f.h["l"].auth != "" || e.f.nv[handleNum(Secret.Handle)] != nil || len(e.f.luks[e.dev]) == 64 {
			t.Error("hierarchy authValues or the volume key were set through a session salted to a foreign key")
		}
	})
}

// B2: one-shot bridge. A variable store rolled back after the update was
// applied must not re-open the transition, however often it is repeated.
func TestDbxRollbackDoesNotReopenBridge(t *testing.T) {
	older, revoked := bytes.Repeat([]byte{0x0d}, 32), bytes.Repeat([]byte{0xd0}, 32)
	e := newEnv(t, "prod")
	e.fw.Vars[dbxVar] = sbtest.ESL(older)
	e.mustBoot(t, "current")
	e.later()
	steady := append([]byte{}, e.vDigest()...)
	e.setImage(t, "ref", "prod", 1, 0)
	e.shipDbx(t, "dbx-epoch0.auth", revoked)
	e.mustBoot(t, "pending")
	for i := 0; i < 3; i++ {
		e.fw.Vars[dbxVar] = sbtest.ESL(older) // SPI flash rolled back
		e.mustBoot(t, "failed: NOT APPLIED: the firmware lost")
		if !bytes.Equal(e.vDigest(), steady) {
			t.Fatalf("round %d: the boot-chain binding is open after a rollback", i)
		}
		if bytes.Contains(e.fw.Vars[dbxVar], revoked) {
			t.Fatalf("round %d: update handed to the firmware again", i)
		}
	}
	// with Secure Boot off the steady binding refuses as always
	e.fw.SecureBoot = 0
	wantErr(t, e.boot(t), "Secure Boot configuration")
}

// B7: firmware whose event log cannot carry a Secure Boot update is not enrolled.
func TestNonConformingEventLog(t *testing.T) {
	for name, tc := range map[string]struct {
		mut  func(e *env)
		want string
	}{
		"log does not replay to PCR 7": {func(e *env) { e.pcr7 = bytes.Repeat([]byte{0x42}, 32) }, "replays PCR 7"},
		"log truncated":                {func(e *env) { e.badLog = true }, "event log"},
		"dbx not measured":             {func(e *env) { e.fw.Skip = "dbx" }, "dbx-"},
		"KEK measured twice": {func(e *env) {
			e.fw.Extra = []sbtest.Ev{{PCR: 7, Type: 0x80000001, Data: sbtest.VarEvent(sbstate.GUIDGlobal, "KEK", []byte("kek"))}}
		}, "KEK-"},
		"db is not a signature list": {func(e *env) { e.fw.Vars["db-"+sbstate.GUIDSecurity] = []byte("not a list at all, just bytes") }, "db-"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, "prod")
			tc.mut(e)
			err := e.boot(t)
			wantErr(t, err, "cannot carry signed Secure Boot variable updates")
			wantErr(t, err, tc.want)
			if e.f.h["o"].auth != "" || len(e.f.nv) != 1 || len(e.f.luks[e.dev]) == 64 { // only the EK certificate index
				t.Error("device enrolled on non-conforming firmware")
			}
		})
	}
	t.Run("checked again when healing", func(t *testing.T) {
		e := newEnv(t, "prod")
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		e.later()
		e.setImage(t, "ref", "prod", 1, 1)
		e.badLog = true
		wantErr(t, e.boot(t), "cannot carry signed Secure Boot variable updates")
		if e.f.nv[handleNum(Secret.Handle)] == nil {
			t.Error("state destroyed although the heal was refused")
		}
	})
}

// B8: the state service authorizes callers, runs only writers defined by
// the image, keeps the keys to itself and authenticates every read.
func TestStateService(t *testing.T) {
	e := newEnv(t, "prod")
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	e.later()
	s := e.state(t)
	if _, err := os.Stat(e.c.StateKeyFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state keys left in /run after the service started")
	}
	if _, err := NewStateServer(e.c, e.f); err == nil {
		t.Fatal("a second process obtained the state keys")
	}
	v0 := e.counter()
	for name, tc := range map[string]struct {
		req  StateRequest
		unit string
		want string
	}{
		"caller in another unit":      {StateRequest{Op: "exec", Writer: "config"}, "evil.service", "not authorized"},
		"caller outside any unit":     {StateRequest{Op: "exec", Writer: "config"}, "", "not authorized"},
		"transient unit of root":      {StateRequest{Op: "exec", Writer: "config"}, "run-u42.service", "not authorized"},
		"writer not in the image":     {StateRequest{Op: "exec", Writer: "sh"}, "enklave-config.service", "unknown state writer"},
		"unknown operation":           {StateRequest{Op: "key"}, "enklave-config.service", "unknown operation"},
		"read of a file not in state": {StateRequest{Op: "read", Path: "../.manifest"}, "x.service", "not exist"},
	} {
		if rep := s.Handle(tc.req, tc.unit, nil); rep.OK || !strings.Contains(rep.Error, tc.want) {
			t.Errorf("%s: %+v, want %q", name, rep, tc.want)
		}
	}
	if e.counter() != v0 {
		t.Fatal("a refused request changed the state")
	}
	e.commit(t, "config", "hello")
	rep := s.Handle(StateRequest{Op: "read", Path: "config"}, "any-reader.service", nil)
	if !rep.OK || string(rep.Data) != "hello" || rep.Version != v0+1 || rep.Counter != v0+1 {
		t.Fatalf("verified read: %+v", rep)
	}
	// a write that bypassed the service (root remounted the volume) is
	// detected by the next read, not only at the next boot
	os.WriteFile(filepath.Join(e.c.stateMount(), "data/config"), []byte("forged"), 0o644)
	if rep := s.Handle(StateRequest{Op: "read", Path: "config"}, "any-reader.service", nil); rep.OK || !strings.Contains(rep.Error, "manifest") {
		t.Errorf("forged content served: %+v", rep)
	}
	if rep := s.Handle(StateRequest{Op: "exec", Writer: "config"}, "enklave-config.service", nil); rep.OK {
		t.Error("commit on top of forged content")
	}
	// writer definitions: only .service units and absolute commands
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, "x.json"), []byte(`{"unit":"../x","exec":["sh"]}`), 0o644)
	if _, err := LoadWriters(bad); err == nil {
		t.Error("malformed writer accepted")
	}
	if w, err := LoadWriters(filepath.Join(bad, "none")); err != nil || len(w) != 0 {
		t.Errorf("image without writers: %v %v", w, err)
	}
}
