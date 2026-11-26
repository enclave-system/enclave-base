// Package tpmpolicy holds the TPM 2.0 policy arithmetic and the signed
// "approved policy" file shared by the build-time signer
// (cmd/enklave-sign-policy) and the runtime (internal/varauth).
//
// An enklave UKI of role R, profile P (prod|test) and security epoch N comes
// with one signed approved policy:
//
//	approved = PolicyNV(E, operandB = bit N, offset 0, TPM_EO_BITCLEAR)
//	           applied on top of PolicyPCR(sha256:11 = the UKI's value in the
//	           phase enter-initrd:leave-initrd)
//
// signed (RSASSA-PKCS1-v1_5, SHA-256) with the PCR signing key over
// approved || Ref(R, P). The NV indices and TPM hierarchies that guard /var
// use PolicyAuthorize(PCR signing key, Ref(R, P)), so only a signature for
// the same role and profile satisfies them: a test-profile UKI can never open
// a production /var, a client UKI never a gateway /var. E is a TPM_NT_BITS
// index; setting bit k revokes every UKI of epoch k irreversibly. systemd's
// own .pcrsig signatures use an empty policyRef and never satisfy these
// policies.
package tpmpolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

const (
	// RefPrefix is the versioned prefix of every enklave policyRef.
	RefPrefix = "enklave-var-v1"
	// MaxEpoch is the highest epoch representable in the 64-bit E index.
	MaxEpoch = 63

	ccPolicyNV = 0x00000149 // TPM_CC_PolicyNV
	eoBitClear = 0x000B     // TPM_EO_BITCLEAR
)

var (
	roleRe   = regexp.MustCompile(`^(ref|client|gateway|terminal|console|sluice|backup|fileserver)$`)
	profiles = map[string]bool{"prod": true, "test": true}
)

// Ref returns the policyRef for a role and profile.
func Ref(role, profile string) (string, error) {
	if !roleRe.MatchString(role) {
		return "", fmt.Errorf("invalid role %q", role)
	}
	if !profiles[profile] {
		return "", fmt.Errorf("invalid profile %q (prod|test)", profile)
	}
	return RefPrefix + ":" + role + ":" + profile, nil
}

// EpochOperand is operandB for PolicyNV: an 8-byte big-endian mask with only
// bit epoch set.
func EpochOperand(epoch int) ([]byte, error) {
	if epoch < 0 || epoch > MaxEpoch {
		return nil, fmt.Errorf("epoch %d out of range 0..%d", epoch, MaxEpoch)
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(1)<<uint(epoch))
	return b, nil
}

// RevokeMask returns the bits of all epochs older than epoch.
func RevokeMask(epoch int) uint64 {
	if epoch <= 0 {
		return 0
	}
	return (uint64(1) << uint(epoch)) - 1
}

// PolicyNV extends a policy digest with TPM2_PolicyNV (TPM 2.0 Part 3, 23.9):
// H(old || TPM_CC_PolicyNV || H(operandB || offset || operation) || nvName).
func PolicyNV(old, operandB []byte, offset, operation uint16, nvName []byte) []byte {
	a := sha256.New()
	a.Write(operandB)
	var u [2]byte
	binary.BigEndian.PutUint16(u[:], offset)
	a.Write(u[:])
	binary.BigEndian.PutUint16(u[:], operation)
	a.Write(u[:])
	args := a.Sum(nil)

	h := sha256.New()
	h.Write(old)
	var cc [4]byte
	binary.BigEndian.PutUint32(cc[:], ccPolicyNV)
	h.Write(cc[:])
	h.Write(args)
	h.Write(nvName)
	return h.Sum(nil)
}

// Approved computes the approved policy digest for a UKI of the given epoch.
// pcr11Policy is the PolicyPCR(sha256:11) digest of that UKI (from .pcrsig),
// epochName the TPM Name of the epoch index E.
func Approved(pcr11Policy []byte, epoch int, epochName []byte) ([]byte, error) {
	if len(pcr11Policy) != sha256.Size {
		return nil, errors.New("PCR 11 policy digest must be 32 bytes")
	}
	op, err := EpochOperand(epoch)
	if err != nil {
		return nil, err
	}
	return PolicyNV(pcr11Policy, op, 0, eoBitClear, epochName), nil
}

// File is the signed approved policy shipped next to the UKI on the ESP
// (/EFI/enklave/policy/<uki>.json). Only approved||ref is covered by the
// TPM-verified signature; role, profile and epoch are bound because the
// runtime recomputes approved and ref from its own, verity-protected values.
type File struct {
	Version     int    `json:"version"`
	Role        string `json:"role"`
	Profile     string `json:"profile"`
	Epoch       int    `json:"epoch"`
	PCR11Policy string `json:"pcr11_policy"` // hex
	Approved    string `json:"approved"`     // hex
	Ref         string `json:"ref"`
	Signature   string `json:"signature"` // base64 RSASSA-PKCS1-v1_5/SHA-256 over approved||ref
}

// Decode checks f against the expected role/profile and returns the binary
// PCR 11 policy and approved digest.
func (f File) Decode(role, profile string) (pcr11, approved []byte, err error) {
	ref, err := Ref(role, profile)
	if err != nil {
		return nil, nil, err
	}
	if f.Version != 2 || f.Ref != ref || f.Role != role || f.Profile != profile {
		return nil, nil, fmt.Errorf("policy file is for %s/%s (ref %q, version %d), want %s", f.Role, f.Profile, f.Ref, f.Version, ref)
	}
	if pcr11, err = hex.DecodeString(f.PCR11Policy); err != nil || len(pcr11) != sha256.Size {
		return nil, nil, fmt.Errorf("bad pcr11_policy %q", f.PCR11Policy)
	}
	if approved, err = hex.DecodeString(f.Approved); err != nil || len(approved) != sha256.Size {
		return nil, nil, fmt.Errorf("bad approved %q", f.Approved)
	}
	return pcr11, approved, nil
}

// SignedMessage is the byte string covered by the signature.
func SignedMessage(approved []byte, ref string) []byte {
	return append(append([]byte{}, approved...), ref...)
}

// Release is the verity-protected release metadata in
// /usr/lib/enklave/release.json.
type Release struct {
	Epoch     int `json:"epoch"`
	HealBelow int `json:"heal_below"` // /var provisioned under an epoch < HealBelow is rekeyed
}

// Validate checks the release values.
func (r Release) Validate() error {
	if r.Epoch < 0 || r.Epoch > MaxEpoch {
		return fmt.Errorf("release epoch %d out of range", r.Epoch)
	}
	if r.HealBelow < 0 || r.HealBelow > r.Epoch {
		return fmt.Errorf("heal_below %d must be within 0..epoch (%d)", r.HealBelow, r.Epoch)
	}
	return nil
}
