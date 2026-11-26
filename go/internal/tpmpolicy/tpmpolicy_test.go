package tpmpolicy

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Vector captured from swtpm (tpm2-tools 5.7): a trial session with
// PolicyPCR(sha256:11) on a fresh TPM followed by
// tpm2_policynv -i <0x0000000000000001> 0x01800E04 bc.
func TestApprovedMatchesTPM(t *testing.T) {
	pol := mustHex(t, vecPCR11Policy)
	name := mustHex(t, vecEpochName)
	got, err := Approved(pol, 0, name)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, vecApproved); !bytes.Equal(got, want) {
		t.Fatalf("approved %x, want %x", got, want)
	}
	other, _ := Approved(pol, 1, name)
	if bytes.Equal(other, got) {
		t.Error("epoch does not change the approved digest")
	}
}

func TestEpochOperandAndMask(t *testing.T) {
	op, err := EpochOperand(0)
	if err != nil || !bytes.Equal(op, []byte{0, 0, 0, 0, 0, 0, 0, 1}) {
		t.Errorf("epoch 0: %x %v", op, err)
	}
	op, _ = EpochOperand(9)
	if !bytes.Equal(op, []byte{0, 0, 0, 0, 0, 0, 2, 0}) {
		t.Errorf("epoch 9: %x", op)
	}
	for _, e := range []int{-1, 64} {
		if _, err := EpochOperand(e); err == nil {
			t.Errorf("epoch %d accepted", e)
		}
	}
	if RevokeMask(0) != 0 || RevokeMask(1) != 1 || RevokeMask(3) != 7 {
		t.Error("revoke mask")
	}
	if _, err := Approved([]byte{1}, 0, nil); err == nil {
		t.Error("short pcr11 policy accepted")
	}
}

// swtpm vector (PolicyNV on a written bits index 0x01800E05).
const (
	vecPCR11Policy = "fd32fa22c52cfc8e1a0c29eb38519f87084cab0b04b0d8f020a4d38b2f4e223e"
	vecEpochName   = "000b5f08a0dbf9b0227bf779fc40887bc6fa5691cfa6f1c86f047a49b027ec689969"
	vecApproved    = "bc21ecdbe442dc1c68c05af8dafc80c3c37a18e3a9dde917e564e9e9629479c7"
)

func TestRefAndFileDecode(t *testing.T) {
	ref, err := Ref("ref", "prod")
	if err != nil || ref != "enklave-var-v1:ref:prod" {
		t.Fatalf("%q %v", ref, err)
	}
	for _, bad := range [][2]string{{"evil", "prod"}, {"ref", "dev"}, {"ref:x", "prod"}, {"", ""}} {
		if _, err := Ref(bad[0], bad[1]); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	good := File{Version: 2, Role: "ref", Profile: "prod", PCR11Policy: vecPCR11Policy, Approved: vecApproved, Ref: ref}
	if _, _, err := good.Decode("ref", "prod"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := good.Decode("ref", "test"); err == nil {
		t.Error("prod policy accepted by a test profile")
	}
	if _, _, err := good.Decode("client", "prod"); err == nil {
		t.Error("ref policy accepted by another role")
	}
	mut := func(f func(*File)) File { c := good; f(&c); return c }
	for _, bad := range []File{
		mut(func(f *File) { f.Version = 1 }),
		mut(func(f *File) { f.Ref = "enklave-var-v1:ref:test" }),
		mut(func(f *File) { f.Profile = "test" }),
		mut(func(f *File) { f.PCR11Policy = "zz" }),
		mut(func(f *File) { f.Approved = "00" }),
	} {
		if _, _, err := bad.Decode("ref", "prod"); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if m := SignedMessage([]byte{1, 2}, ref); !bytes.Equal(m, append([]byte{1, 2}, ref...)) {
		t.Errorf("signed message %x", m)
	}
}

func TestRelease(t *testing.T) {
	for _, r := range []Release{{0, 0}, {3, 3}, {3, 1}} {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	for _, r := range []Release{{-1, 0}, {64, 0}, {2, 3}, {2, -1}} {
		if err := r.Validate(); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
}
