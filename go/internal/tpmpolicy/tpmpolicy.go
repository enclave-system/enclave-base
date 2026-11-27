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
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
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
	roleRe = regexp.MustCompile(`^(ref|client|gateway|terminal|console|sluice|backup|fileserver)$`)
	// prod: production keys, production configuration. dev: production
	// configuration signed with a development PKI. test: test profile.
	profiles = map[string]bool{"prod": true, "dev": true, "test": true}
)

// Ref returns the policyRef for a role and profile.
func Ref(role, profile string) (string, error) {
	if !roleRe.MatchString(role) {
		return "", fmt.Errorf("invalid role %q", role)
	}
	if !profiles[profile] {
		return "", fmt.Errorf("invalid profile %q (prod|dev|test)", profile)
	}
	return RefPrefix + ":" + role + ":" + profile, nil
}

// RefEKPrefix marks a per-device policyRef.
const RefEKPrefix = "ek1:"

// RefEK is the policyRef of ONE device whose TPM has no EK certificate and
// was admitted by a signature: a digest over the base ref and the Name of
// that device's endorsement key (a policyRef is at most 64 bytes, so the
// Name itself does not fit). Policies signed for it authorize nothing on any
// other device, and nothing on a device provisioned through an EK
// certificate (whose objects are bound to the base ref).
func RefEK(base string, ekName []byte) string {
	h := sha256.Sum256([]byte(base + ":ek:" + hex.EncodeToString(ekName)))
	return RefEKPrefix + base64.RawURLEncoding.EncodeToString(h[:])
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
	// EK is the Name (hex) of the endorsement key a per-device admission is
	// for. Informational: what counts is that Ref equals RefEK(base, Name).
	EK string `json:"ek,omitempty"`
	// DevKeys is informational release metadata: signed with a development
	// PKI. The authoritative marker is release.json in the verity /usr.
	DevKeys bool `json:"dev_keys,omitempty"`
}

// Decode checks f against the expected role/profile and returns the binary
// PCR 11 policy and approved digest.
func (f File) Decode(role, profile string) (pcr11, approved []byte, err error) {
	ref, err := Ref(role, profile)
	if err != nil {
		return nil, nil, err
	}
	return f.DecodeRef(role, profile, ref)
}

// DecodeRef is Decode for an explicit policyRef (the base ref of role and
// profile, or the per-device ref of an admitted endorsement key).
func (f File) DecodeRef(role, profile, ref string) (pcr11, approved []byte, err error) {
	base, err := Ref(role, profile)
	if err != nil {
		return nil, nil, err
	}
	if ref != base && (!strings.HasPrefix(ref, RefEKPrefix) || len(ref) > 64) {
		return nil, nil, fmt.Errorf("policyRef %q does not belong to %s", ref, base)
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
	// DevKeys marks a build signed with a development PKI (DEV-KEYS); such a
	// build must never ship. Built is the build time (Unix seconds), the lower
	// bound of the clock used to validate EK certificates.
	DevKeys bool  `json:"dev_keys"`
	Built   int64 `json:"built"`
	// RequireFTPM makes provisioning refuse TPMs whose EK certificate was
	// issued by a discrete-TPM vendor (README "Accepted limits").
	RequireFTPM bool `json:"require_ftpm"`
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

// CheckRoleRelease enforces release rules that depend on the role (G8):
// a client must require a firmware TPM, because a client is the device an
// attacker gets into his hands, and the bus of a discrete TPM can be
// tapped and driven. Only test-profile builds (emulated TPMs in VMs) are
// exempt.
func CheckRoleRelease(role, profile string, r Release) error {
	if role == "client" && profile != "test" && !r.RequireFTPM {
		return fmt.Errorf("role client must be built with require_ftpm (REQUIRE_FTPM=1); only test-profile builds are exempt")
	}
	return nil
}

// ---------------------------------------------------------------- local policy arithmetic
//
// Everything below is computed locally instead of being asked from the TPM
// with a trial session: the results must not depend on what a TPM-bus
// interposer answers.

const (
	ccPolicyOR          = 0x00000171
	ccPolicyCommandCode = 0x0000016C
	ccPolicyAuthorizeNV = 0x00000192
	algSHA256           = 0x000B

	// CCNVChangeAuth and CCNVSetBits are the command codes used in policies.
	CCNVChangeAuth = 0x0000013B
	CCNVSetBits    = 0x00000135
)

func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

func sum(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// NVName is the TPM Name of an NV index with nameAlg SHA-256:
// TPM_ALG_SHA256 || H(TPMS_NV_PUBLIC).
func NVName(handle, attributes uint32, authPolicy []byte, dataSize int) []byte {
	pub := append(be32(handle), be16(algSHA256)...)
	pub = append(pub, be32(attributes)...)
	pub = append(pub, be16(uint16(len(authPolicy)))...)
	pub = append(pub, authPolicy...)
	pub = append(pub, be16(uint16(dataSize))...)
	return append(be16(algSHA256), sum(pub)...)
}

// PolicyAuthorizeNV is the policy digest after TPM2_PolicyAuthorizeNV with the
// named index: the digest is reset and extended with the command code and
// the index Name (TPM 2.0 Part 3, 23.22).
func PolicyAuthorizeNV(nvName []byte) []byte {
	return sum(make([]byte, sha256.Size), be32(ccPolicyAuthorizeNV), nvName)
}

// PolicyCommandCode extends a policy digest with TPM2_PolicyCommandCode.
func PolicyCommandCode(old []byte, code uint32) []byte {
	return sum(old, be32(ccPolicyCommandCode), be32(code))
}

// PolicyOR is the policy digest after TPM2_PolicyOR over the given branches.
func PolicyOR(branches ...[]byte) []byte {
	parts := [][]byte{make([]byte, sha256.Size), be32(ccPolicyOR)}
	return sum(append(parts, branches...)...)
}

// DigestNV is the content of a PolicyAuthorizeNV index: a TPMT_HA.
func DigestNV(policy []byte) []byte { return append(be16(algSHA256), policy...) }
