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

func TestFileDecode(t *testing.T) {
	f := File{Version: 1, Epoch: 0, PCR11Policy: vecPCR11Policy, Approved: vecApproved, Ref: Ref, Signature: "x"}
	if _, _, err := f.Decode(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []File{
		{Version: 2, Ref: Ref, PCR11Policy: vecPCR11Policy, Approved: vecApproved},
		{Version: 1, Ref: "", PCR11Policy: vecPCR11Policy, Approved: vecApproved},
		{Version: 1, Ref: Ref, PCR11Policy: "zz", Approved: vecApproved},
		{Version: 1, Ref: Ref, PCR11Policy: vecPCR11Policy, Approved: "00"},
	} {
		if _, _, err := bad.Decode(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if m := SignedMessage([]byte{1, 2}); !bytes.Equal(m, append([]byte{1, 2}, Ref...)) {
		t.Errorf("signed message %x", m)
	}
}

// swtpm vector (PolicyNV on a written bits index 0x01800E05).
const (
	vecPCR11Policy = "fd32fa22c52cfc8e1a0c29eb38519f87084cab0b04b0d8f020a4d38b2f4e223e"
	vecEpochName   = "000b5f08a0dbf9b0227bf779fc40887bc6fa5691cfa6f1c86f047a49b027ec689969"
	vecApproved    = "bc21ecdbe442dc1c68c05af8dafc80c3c37a18e3a9dde917e564e9e9629479c7"
)
