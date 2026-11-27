package varauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enclave.local/base/internal/sbstate"
	"enclave.local/base/internal/sbstate/sbtest"
)

func (e *env) secretReads(from int) int {
	n := 0
	for _, c := range e.f.calls[from:] {
		if strings.HasPrefix(c, "tpm2_nvread "+Secret.Handle) {
			n++
		}
	}
	return n
}

// G1: the record of a rolled-back update is monotonic. A release without
// the update does not clear it, and a release with more updates does not
// overwrite it.
func TestRollbackRecordIsMonotonic(t *testing.T) {
	older, revoked, second := bytes.Repeat([]byte{0x0d}, 32), bytes.Repeat([]byte{0xd0}, 32), bytes.Repeat([]byte{0xd1}, 32)
	start := func(t *testing.T) (*env, []byte) {
		e := newEnv(t, "prod")
		e.fw.Vars[dbxVar] = sbtest.ESL(older)
		e.mustBoot(t, "current")
		e.later()
		steady := append([]byte{}, e.vDigest()...)
		e.setImage(t, "ref", "prod", 1, 0)
		e.shipDbx(t, "dbx-epoch0.auth", revoked)
		e.mustBoot(t, "pending")
		e.fw.Vars[dbxVar] = sbtest.ESL(older) // SPI rollback
		e.mustBoot(t, "failed: NOT APPLIED: the firmware lost")
		return e, steady
	}
	t.Run("release without the update in between", func(t *testing.T) {
		e, steady := start(t)
		os.Rename(e.c.UpdatesDir, e.c.UpdatesDir+".off") // same-ref release without the update
		e.mustBoot(t, "current (0 update")
		e.mustBoot(t, "current (0 update")
		os.Rename(e.c.UpdatesDir+".off", e.c.UpdatesDir) // the update release again
		for i := 0; i < 2; i++ {
			e.mustBoot(t, "failed: NOT APPLIED: dbx-epoch0.auth: the firmware lost this update before")
			if !bytes.Equal(e.vDigest(), steady) || bytes.Contains(e.fw.Vars[dbxVar], revoked) {
				t.Fatal("the transition was opened again after a rollback")
			}
		}
	})
	t.Run("release with one more update", func(t *testing.T) {
		e, _ := start(t)
		e.shipDbx(t, "dbx-second.auth", second)
		e.mustBoot(t, "pending: 1 of 2")
		if !strings.Contains(e.updates(), "dbx-epoch0.auth: the firmware lost this update before") {
			t.Fatalf("status %q", e.updates())
		}
		if bytes.Contains(e.fw.Vars[dbxVar], revoked) || !bytes.Contains(e.fw.Vars[dbxVar], second) {
			t.Fatal("wrong updates handed to the firmware")
		}
		e.mustBoot(t, "failed: NOT APPLIED: dbx-epoch0.auth: the firmware lost this update before")
		// the record of the first update is still there
		ts, err := parseTransition(e.f.nv[handleNum(Transition.Handle)].data)
		if err != nil || len(ts.seen) != 1 || ts.seen[0].n != seenInFW || ts.state != trIdle {
			t.Fatalf("record: %+v %v", ts, err)
		}
	})
	t.Run("update never taken is armed three times at most", func(t *testing.T) {
		e := newEnv(t, "prod")
		e.mustBoot(t, "current")
		e.later()
		steady := append([]byte{}, e.vDigest()...)
		e.shipDbx(t, "dbx-epoch0.auth", revoked)
		cv := &crashVars{Firmware: e.fw, crash: true}
		e.c.EFI = cv
		for i := 0; i < maxArmCount; i++ {
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("crash point not reached")
					}
				}()
				e.boot(t) //nolint:errcheck
			}()
			if bytes.Equal(e.vDigest(), steady) {
				t.Fatal("not armed")
			}
		}
		e.mustBoot(t, "failed: NOT APPLIED: dbx-epoch0.auth: armed 3 times")
		if !bytes.Equal(e.vDigest(), steady) {
			t.Fatal("armed a fourth time")
		}
	})
	t.Run("refusal by the firmware does not use up the attempts", func(t *testing.T) {
		e := newEnv(t, "prod")
		e.mustBoot(t, "current")
		e.later()
		e.shipDbx(t, "dbx-epoch0.auth", revoked)
		e.fw.Reject = errors.New("EACCES")
		for i := 0; i < 5; i++ {
			e.mustBoot(t, "failed: NOT APPLIED: dbx-epoch0.auth: EACCES")
			// a refused update leaves no entry behind (the record has 8 slots)
			if ts := e.f.nv[handleNum(Transition.Handle)].data; !bytes.Equal(ts, make([]byte, Transition.Size)) {
				t.Fatalf("record not empty after a refusal: %x", ts)
			}
		}
		e.fw.Reject = nil
		e.mustBoot(t, "pending")
		e.mustBoot(t, "current (1 update")
		if ts := e.f.nv[handleNum(Transition.Handle)].data; !bytes.Equal(ts, make([]byte, Transition.Size)) {
			t.Errorf("record not empty once the firmware holds the update: %x", ts)
		}
	})
}

type partVars struct {
	*sbtest.Firmware
	reject [][]byte
}

func (p *partVars) Append(name, guid string, auth []byte) error {
	for _, r := range p.reject {
		if bytes.Contains(auth, r) {
			return errors.New("EFI_OUT_OF_RESOURCES")
		}
	}
	return p.Firmware.Append(name, guid, auth)
}

// G2: the firmware takes only some of the release's updates. What index T
// and V record is what was read back, so the next boot is one of the bound
// states.
func TestPartialUpdateAcceptance(t *testing.T) {
	a, b, c := bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb2}, 32), bytes.Repeat([]byte{0xc3}, 32)
	for name, reject := range map[string][][]byte{"second of three": {b}, "first of three": {a}, "last of three": {c}, "two of three": {a, c}} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, "prod")
			e.mustBoot(t, "current")
			e.later()
			e.commit(t, "config", "kept")
			e.shipDbx(t, "dbx-a.auth", a)
			e.shipDbx(t, "dbx-b.auth", b)
			e.shipDbx(t, "dbx-c.auth", c)
			pv := &partVars{e.fw, reject}
			e.c.EFI = pv
			e.mustBoot(t, "pending: ")
			if !strings.Contains(e.updates(), "EFI_OUT_OF_RESOURCES") {
				t.Fatalf("status %q", e.updates())
			}
			// no brick: the next boot completes what the firmware took and
			// reports the rest
			e.mustBoot(t, "failed: NOT APPLIED: ")
			e.mustBoot(t, "failed: NOT APPLIED: ")
			// refused updates occupy no record entry, taken ones are dropped once in the firmware
			if ts := e.f.nv[handleNum(Transition.Handle)].data; !bytes.Equal(ts, make([]byte, Transition.Size)) {
				t.Fatalf("record not empty: %x", ts)
			}
			if readFile(filepath.Join(e.c.stateMount(), "data/config")) != "kept" {
				t.Error("state lost")
			}
			pv.reject = nil // the firmware has room again
			e.mustBoot(t, "pending: ")
			e.mustBoot(t, "current (3 update")
		})
	}
}

// G3: the TPM enforces the transition. With the software checks switched
// off (test hook; models an attacker who patched them out by DMA), a boot
// with any other Secure Boot state gets no policy session, so no key.
func TestTransitionEnforcedByTPM(t *testing.T) {
	older, revoked := bytes.Repeat([]byte{0x0d}, 32), bytes.Repeat([]byte{0xd0}, 32)
	for name, mut := range map[string]func(e *env){
		"secure boot disabled":    func(e *env) { e.fw.SecureBoot = 0 },
		"db key enrolled":         func(e *env) { e.fw.Vars["db-"+sbstate.GUIDSecurity] = sbtest.ESL(bytes.Repeat([]byte{0x66}, 32)) },
		"older dbx entry dropped": func(e *env) { e.fw.Vars[dbxVar] = sbtest.ESL(revoked) },
		"other signing authority": func(e *env) { e.fw.Authority = []byte("attacker cert") },
		"PCR 7 not from the log":  func(e *env) { e.pcr7 = bytes.Repeat([]byte{0x43}, 32) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, "test")
			e.fw.Vars[dbxVar] = sbtest.ESL(older)
			e.mustBoot(t, "current")
			e.later()
			e.shipDbx(t, "dbx-epoch0.auth", revoked)
			e.mustBoot(t, "pending")
			os.MkdirAll(filepath.Join(e.c.espMount(), "EFI/enclave"), 0o700)
			os.WriteFile(filepath.Join(e.c.espMount(), "EFI/enclave/test-skip-bridge-check"), nil, 0o600)
			mut(e)
			n := len(e.f.calls)
			wantErr(t, e.boot(t), "tpm2_policyor: TPM_RC_VALUE")
			if e.secretReads(n) != 0 {
				t.Fatal("the TPM released the volume key")
			}
			// the two bound states still work with the checks off
			e.fw.Vars[dbxVar] = append(sbtest.ESL(older), sbtest.ESL(revoked)...)
			e.fw.SecureBoot, e.fw.Authority, e.pcr7 = 1, []byte("enclave db certificate"), nil
			e.fw.Vars["db-"+sbstate.GUIDSecurity] = sbtest.NewFirmware().Vars["db-"+sbstate.GUIDSecurity]
			e.mustBoot(t, "current (1 update")
		})
	}
	// the hook exists in the test profile only
	e := newEnv(t, "prod")
	e.mustBoot(t, "current")
	e.later()
	e.shipDbx(t, "dbx-epoch0.auth", revoked)
	e.mustBoot(t, "pending")
	os.WriteFile(filepath.Join(e.c.espMount(), "EFI/enclave/test-skip-bridge-check"), nil, 0o600)
	e.fw.SecureBoot = 0
	wantErr(t, e.boot(t), "is none of them")
	// V lists exactly two states while the update is pending
	e.fw.SecureBoot = 1
	ts, err := parseTransition(e.f.nv[handleNum(Transition.Handle)].data)
	if err != nil || ts.state != trArmed || !ts.applied || len(ts.next) != 2 {
		t.Fatalf("transition record: %+v %v", ts, err)
	}
}

// G3: firmware that does not measure a variable verbatim cannot be bound in
// advance and is not enrolled.
func TestUnpredictableFirmwareNotEnrolled(t *testing.T) {
	e := newEnv(t, "prod")
	e.c.EFI = &shiftVars{e.fw}
	wantErr(t, e.boot(t), "refusing to enrol the device")
	if e.f.h["o"].auth != "" || len(e.f.luks[e.dev]) != 0 {
		t.Error("TPM or volume touched")
	}
}

// shiftVars returns dbx in another form than the firmware measured.
type shiftVars struct{ *sbtest.Firmware }

func (s *shiftVars) Read(name, guid string) ([]byte, error) {
	b, err := s.Firmware.Read(name, guid)
	if name == "dbx" {
		b = append(append([]byte{}, b...), sbtest.ESL(bytes.Repeat([]byte{1}, 32))...)
	}
	return b, err
}

// G5: production accepts vendor-certified endorsement keys only. The
// certificate may come from the TPM or, fetched from the vendor, from the ESP.
func TestProdNeedsVendorCertificate(t *testing.T) {
	espCert := func(e *env, name string, der []byte) {
		d := filepath.Join(e.c.espMount(), EKCertDir)
		os.MkdirAll(d, 0o700)
		os.WriteFile(filepath.Join(d, name), der, 0o600)
	}
	t.Run("prod refuses an uncertified admission", func(t *testing.T) {
		e := newEnv(t, "prod")
		e.f.setEKCert(nil)
		e.admit(t, e.ekName())
		wantErr(t, e.boot(t), "production release accepts only endorsement keys certified by a TPM vendor")
		if e.f.h["o"].auth != "" || e.f.pers[handleNum(SaltHandle)] != nil || len(e.f.luks[e.dev]) != 0 {
			t.Error("TPM or volume touched")
		}
	})
	t.Run("certificate from the ESP", func(t *testing.T) {
		e := newEnv(t, "prod")
		e.f.setEKCert(nil)
		espCert(e, "other-device.cer", vendorCA().ekCertificate(&newEKKey().PublicKey))
		espCert(e, "this-device.cer", vendorCA().ekCertificate(&e.f.ek.PublicKey))
		espCert(e, "junk.cer", []byte("not a certificate"))
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(readFile(e.c.SaltSourceFile()), "this-device.cer from the ESP") {
			t.Errorf("source %q", readFile(e.c.SaltSourceFile()))
		}
		e.later()
		e.commit(t, "config", "v1")
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
		// same policy as a device with the certificate in NV: the base ref
		base := newEnv(t, "prod")
		if err := base.boot(t); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(e.f.nv[handleNum(PCRPolicy.Handle)].policy, base.f.nv[handleNum(PCRPolicy.Handle)].policy) {
			t.Error("ESP-certified device is not under the base ref")
		}
		// healing works; without the certificate the device stays shut
		e.setImage(t, "ref", "prod", 1, 1)
		if err := e.boot(t); err != nil {
			t.Fatalf("heal: %v", err)
		}
		os.Remove(filepath.Join(e.c.espMount(), EKCertDir, "this-device.cer"))
		wantErr(t, e.boot(t), "is not the authenticated key of this TPM")
	})
	t.Run("ESP certificate of another TPM only", func(t *testing.T) {
		e := newEnv(t, "prod")
		e.f.setEKCert(nil)
		espCert(e, "other-device.cer", vendorCA().ekCertificate(&newEKKey().PublicKey))
		wantErr(t, e.boot(t), "is not the authenticated key of this TPM")
	})
	t.Run("ESP certificate from an unknown CA", func(t *testing.T) {
		e := newEnv(t, "prod")
		e.f.setEKCert(nil)
		espCert(e, "forged.cer", newTestCA("attacker CA").ekCertificate(&e.f.ek.PublicKey))
		wantErr(t, e.boot(t), "does not chain to a trusted TPM vendor CA")
	})
	t.Run("dev build still admits per device", func(t *testing.T) {
		e := newEnv(t, "dev")
		e.f.setEKCert(nil)
		e.admit(t, e.ekName())
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
	})
	// G8: an admission does not get around require_ftpm
	t.Run("require_ftpm refuses admissions", func(t *testing.T) {
		e := newEnv(t, "dev")
		e.requireFTPM = true
		e.setImage(t, "ref", "dev", 0, 0)
		e.f.setEKCert(nil)
		e.admit(t, e.ekName())
		wantErr(t, e.boot(t), "requires a firmware TPM (require_ftpm), which only a vendor certificate proves")
	})
	t.Run("client role needs require_ftpm", func(t *testing.T) {
		e := newEnv(t, "prod")
		e.setImage(t, "client", "prod", 0, 0)
		wantErr(t, e.boot(t), "role client must be built with require_ftpm")
		e = newEnv(t, "dev")
		e.setImage(t, "client", "dev", 0, 0)
		wantErr(t, e.boot(t), "role client must be built with require_ftpm")
		e = newEnv(t, "test") // emulated TPMs of the VM tests
		e.setImage(t, "client", "test", 0, 0)
		if err := e.boot(t); err != nil {
			t.Fatal(err)
		}
	})
}

// G6: no volume key without an active IOMMU.
func TestRequireIOMMU(t *testing.T) {
	for name, tc := range map[string]struct {
		mut  func(sys string)
		want string
	}{
		"no ACPI table":       {func(sys string) { os.Remove(filepath.Join(sys, "firmware/acpi/tables/DMAR")) }, "no ACPI DMAR or IVRS table"},
		"kernel runs no unit": {func(sys string) { os.Remove(filepath.Join(sys, "class/iommu/dmar0")) }, "/sys/class/iommu is empty"},
		"no groups":           {func(sys string) { os.RemoveAll(filepath.Join(sys, "kernel/iommu_groups")) }, "no IOMMU groups"},
		"passthrough domain": {func(sys string) {
			os.WriteFile(filepath.Join(sys, "kernel/iommu_groups/1/type"), []byte("identity\n"), 0o644)
		}, `type "identity"`},
	} {
		t.Run(name, func(t *testing.T) {
			// first boot: nothing is created
			e := newEnv(t, "prod")
			tc.mut(e.c.Sys)
			wantErr(t, e.boot(t), tc.want)
			if e.f.h["o"].auth != "" || len(e.f.luks[e.dev]) != 0 {
				t.Error("provisioned without DMA protection")
			}
			// enrolled device: refused before the volume key is read
			e = newEnv(t, "prod")
			if err := e.boot(t); err != nil {
				t.Fatal(err)
			}
			e.later()
			tc.mut(e.c.Sys)
			n := len(e.f.calls)
			wantErr(t, e.boot(t), "refusing to release the volume key")
			if e.secretReads(n) != 0 {
				t.Fatal("volume key read without DMA protection")
			}
		})
	}
	// AMD: IVRS instead of DMAR
	e := newEnv(t, "prod")
	os.Rename(filepath.Join(e.c.Sys, "firmware/acpi/tables/DMAR"), filepath.Join(e.c.Sys, "firmware/acpi/tables/IVRS"))
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
}

// G7: the lockout is not switched off on a TPM that holds foreign objects.
func TestForeignObjectsFailClosed(t *testing.T) {
	foreignNV := func(e *env) { e.f.nv[0x01500010] = &nvIdx{attrs: attrWritten, data: []byte{1}, size: 1, auth: "1234"} }
	foreignKey := func(e *env) { e.f.pers[0x81000042] = []byte("key with a PIN") }
	for name, mut := range map[string]func(e *env){"NV index": foreignNV, "persistent key": foreignKey} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, "prod")
			if err := e.boot(t); err != nil {
				t.Fatal(err)
			}
			e.later()
			mut(e)
			e.f.daInterval, e.f.daCounter = 1000, 2 // someone re-enabled the lockout parameters
			n := len(e.f.calls)
			wantErr(t, e.boot(t), "objects that are not enclave's")
			for _, c := range e.f.calls[n:] {
				if strings.HasPrefix(c, "tpm2_dictionarylockout") {
					t.Fatal("lockout touched although a foreign object exists")
				}
			}
			if e.secretReads(n) != 0 {
				t.Fatal("volume key read")
			}
		})
	}
	// first boot on a TPM that holds a foreign persistent key: not enrolled
	e := newEnv(t, "prod")
	foreignKey(e)
	wantErr(t, e.boot(t), "objects that are not enclave's")
	if e.f.h["o"].auth != "" || len(e.f.luks[e.dev]) != 0 {
		t.Error("TPM locked or volume created")
	}
}

// G9: the status of the release's Secure Boot updates is published for
// every local user, in every profile.
func TestUpdateStatusIsPublic(t *testing.T) {
	status := func(e *env) UpdateStatus {
		var s UpdateStatus
		p := filepath.Join(e.c.StatusDir, "secure-boot-updates.json")
		b, err := os.ReadFile(p)
		if err != nil || json.Unmarshal(b, &s) != nil {
			t.Fatalf("%s: %v %q", p, err, b)
		}
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o644 {
			t.Errorf("mode %v", fi.Mode())
		}
		return s
	}
	e := newEnv(t, "prod")
	e.mustBoot(t, "current")
	if s := status(e); s.Status != "current" || !s.OK {
		t.Errorf("%+v", s)
	}
	e.later()
	e.shipDbx(t, "dbx-epoch0.auth", bytes.Repeat([]byte{0xd0}, 32))
	e.fw.Reject = errors.New("EACCES")
	e.mustBoot(t, "failed")
	if s := status(e); s.Status != "failed" || s.OK || !strings.Contains(s.Detail, "EACCES") {
		t.Errorf("%+v", s)
	}
	e.fw.Reject = nil
	e.mustBoot(t, "pending")
	if s := status(e); s.Status != "pending" || !s.OK {
		t.Errorf("%+v", s)
	}
	e.fw.Vars[dbxVar] = nil // rolled back
	e.mustBoot(t, "failed")
	if s := status(e); s.Status != "failed" || s.OK || !strings.Contains(s.Detail, "rolled back") {
		t.Errorf("%+v", s)
	}
	e.badLog = true
	os.Remove(filepath.Join(e.c.UpdatesDir, "dbx-epoch0.auth"))
	e.shipDbx(t, "dbx-other.auth", bytes.Repeat([]byte{0xd7}, 32))
	e.mustBoot(t, "blocked")
	if s := status(e); s.Status != "blocked" || s.OK {
		t.Errorf("%+v", s)
	}
}

// edk2Vars models edk2's authenticated append: entries the variable already
// holds are dropped from the update before it is appended.
type edk2Vars struct{ *sbtest.Firmware }

func (v *edk2Vars) Append(name, guid string, auth []byte) error {
	payload, err := sbstate.AuthPayload(auth)
	if err != nil {
		return err
	}
	c, err := sbstate.AppendCandidates(v.Vars[name+"-"+guid], payload)
	if err != nil {
		return err
	}
	v.Vars[name+"-"+guid] = c[0]
	return nil
}

// G3: the binding is computed in advance for both ways firmware stores an
// append (edk2 drops entries it already has, others append as is); either
// way the next boot is a bound state, and V is narrowed to what was read back.
func TestTransitionWithDedupingFirmware(t *testing.T) {
	older, revoked := bytes.Repeat([]byte{0x0d}, 32), bytes.Repeat([]byte{0xd0}, 32)
	for name, edk2 := range map[string]bool{"edk2 append": true, "plain append": false} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, "prod")
			e.fw.Vars[dbxVar] = sbtest.ESL(older)
			e.mustBoot(t, "current")
			e.later()
			e.shipDbx(t, "dbx-epoch0.auth", older, revoked) // repeats an entry the device has
			if edk2 {
				e.c.EFI = &edk2Vars{e.fw}
			}
			e.mustBoot(t, "pending")
			ts, err := parseTransition(e.f.nv[handleNum(Transition.Handle)].data)
			if err != nil || len(ts.next) != 2 {
				t.Fatalf("V not narrowed to two states: %+v %v", ts, err)
			}
			e.mustBoot(t, "current (1 update")
		})
	}
}

// oddVars stores an append in a third form (entries in reverse order).
type oddVars struct{ *sbtest.Firmware }

func (v *oddVars) Append(name, guid string, auth []byte) error {
	payload, _ := sbstate.AuthPayload(auth)
	v.Vars[name+"-"+guid] = append(append([]byte{}, payload...), v.Vars[name+"-"+guid]...)
	return nil
}

// G3: firmware that stores an append in a form nobody computed in advance
// is still carried: V is narrowed to the value read back, and the status
// says so (bring-up check). Only a power cut in that same instant is not
// covered (README).
func TestUnpredictedAppendFormIsReadBack(t *testing.T) {
	e := newEnv(t, "prod")
	e.fw.Vars[dbxVar] = sbtest.ESL(bytes.Repeat([]byte{0x0d}, 32))
	e.mustBoot(t, "current")
	e.later()
	e.shipDbx(t, "dbx-epoch0.auth", bytes.Repeat([]byte{0xd0}, 32))
	e.c.EFI = &oddVars{e.fw}
	e.mustBoot(t, "pending")
	if !strings.Contains(e.updates(), "not predicted") {
		t.Errorf("status %q", e.updates())
	}
	e.mustBoot(t, "current (1 update")
}

// A healing release that arrives while a Secure Boot update is pending
// heals and completes the transition in the same boot (PCR 7 is bound
// exactly in both modes, so healing needs no steady state).
func TestHealingWhileUpdatePending(t *testing.T) {
	older, revoked := bytes.Repeat([]byte{0x0d}, 32), bytes.Repeat([]byte{0xd0}, 32)
	for name, rolledBack := range map[string]bool{"update in the firmware": false, "update rolled back": true} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, "prod")
			e.fw.Vars[dbxVar] = sbtest.ESL(older)
			e.mustBoot(t, "current")
			e.later()
			e.setImage(t, "ref", "prod", 1, 0)
			e.shipDbx(t, "dbx-epoch0.auth", revoked)
			e.mustBoot(t, "pending")
			key := append([]byte{}, e.f.luks[e.dev]...)
			e.setImage(t, "ref", "prod", 2, 2) // healing release, same update
			if rolledBack {
				e.fw.Vars[dbxVar] = sbtest.ESL(older)
				e.mustBoot(t, "failed: NOT APPLIED: the firmware lost")
			} else {
				e.mustBoot(t, "current (1 update")
			}
			if bytes.Equal(key, e.f.luks[e.dev]) {
				t.Fatal("not healed")
			}
			if ts, err := parseTransition(e.f.nv[handleNum(Transition.Handle)].data); err != nil || ts.state != trIdle {
				t.Fatalf("transition not closed: %+v %v", ts, err)
			}
			key = append([]byte{}, e.f.luks[e.dev]...)
			if err := e.boot(t); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(key, e.f.luks[e.dev]) {
				t.Fatal("healed twice")
			}
			// a foreign Secure Boot state is refused by a healing release as well
			e.fw.SecureBoot = 0
			wantErr(t, e.boot(t), "Secure Boot configuration changed")
		})
	}
	// ... and a healing release does not heal under a foreign Secure Boot state
	e := newEnv(t, "prod")
	e.mustBoot(t, "current")
	e.later()
	e.shipDbx(t, "dbx-epoch0.auth", revoked)
	e.mustBoot(t, "pending")
	key := append([]byte{}, e.f.luks[e.dev]...)
	e.setImage(t, "ref", "prod", 1, 1)
	e.fw.SecureBoot = 0
	wantErr(t, e.boot(t), "is none of them")
	if !bytes.Equal(key, e.f.luks[e.dev]) {
		t.Fatal("healed under a foreign Secure Boot state")
	}
}
