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
	for _, bad := range [][2]string{{"evil", "prod"}, {"ref", "debug"}, {"ref:x", "prod"}, {"", ""}} {
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
	for _, r := range []Release{{Epoch: 0}, {Epoch: 3, HealBelow: 3}, {Epoch: 3, HealBelow: 1}} {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	for _, r := range []Release{{Epoch: -1}, {Epoch: 64}, {Epoch: 2, HealBelow: 3}, {Epoch: 2, HealBelow: -1}} {
		if err := r.Validate(); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
}

// Vectors captured from swtpm 0.7.1 / tpm2-tools 5.7 (fix round 4):
//
//	tpm2_nvdefine 0x01800E05 -C o -s 34 -a "ownerwrite|authread|no_da"; tpm2_nvwrite ...
//	tpm2_nvreadpublic 0x01800E05                      -> name, attributes 0x22040002
//	tpm2_policyauthorizenv -S trial -C 0x01800E05 0x01800E05 -L pstar
//	tpm2_policycommandcode -S trial TPM2_CC_NV_ChangeAuth -L pca
func TestLocalPolicyArithmeticMatchesTPM(t *testing.T) {
	name := NVName(0x01800E05, 0x22040002, nil, 34)
	if want := mustHex(t, "000b1f8f84c29e1d730ce5290644ec503e750714f551f84518f7e1213f67de5cfd06"); !bytes.Equal(name, want) {
		t.Fatalf("NV name %x, want %x", name, want)
	}
	pstar := PolicyAuthorizeNV(name)
	if want := mustHex(t, "2558a6fe60bfa7232a8f816bd014b29873fd48a09f3b8a7eff4d7b171c83b980"); !bytes.Equal(pstar, want) {
		t.Fatalf("PolicyAuthorizeNV %x, want %x", pstar, want)
	}
	pca := PolicyCommandCode(pstar, CCNVChangeAuth)
	if want := mustHex(t, "2e035f844b930fed7af178db46324e9ce58f07d56cddb992750bdea83d416e76"); !bytes.Equal(pca, want) {
		t.Fatalf("PolicyCommandCode %x, want %x", pca, want)
	}
	if d := DigestNV(pstar); len(d) != 34 || d[0] != 0 || d[1] != 0x0b {
		t.Errorf("DigestNV %x", d)
	}
	if bytes.Equal(NVName(0x01800E05, 0x22040002, []byte{1}, 34), name) {
		t.Error("authPolicy does not change the NV name")
	}
}

// B1: a per-device admission is signed for a ref that names the device's EK.
func TestRefEK(t *testing.T) {
	base, _ := Ref("ref", "dev")
	name := append([]byte{0, 0x0b}, bytes.Repeat([]byte{0xab}, 32)...)
	ref := RefEK(base, name)
	if ref != "enklave-var-v1:ref:dev:ek:000b"+hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatalf("%q", ref)
	}
	f := File{Version: 2, Role: "ref", Profile: "dev", PCR11Policy: vecPCR11Policy, Approved: vecApproved, Ref: ref}
	if _, _, err := f.DecodeRef("ref", "dev", ref); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.Decode("ref", "dev"); err == nil {
		t.Error("per-device policy accepted for the base ref")
	}
	other := RefEK(base, append([]byte{0, 0x0b}, bytes.Repeat([]byte{0xcd}, 32)...))
	if _, _, err := f.DecodeRef("ref", "dev", other); err == nil {
		t.Error("admission of one EK accepted for another")
	}
	if _, _, err := f.DecodeRef("ref", "prod", ref); err == nil {
		t.Error("dev admission accepted by a prod image")
	}
	if _, _, err := f.DecodeRef("ref", "dev", "enklave-var-v1:ref:devil"); err == nil {
		t.Error("foreign ref accepted")
	}
}
