// Package varauth creates, unlocks, authenticates and heals the encrypted
// persistent state volume (mounted at /var/lib/enclave).
//
// The volume is LUKS2 (aes-xts-plain64 512-bit, hmac-sha256 integrity,
// argon2id) with a 64-byte random key S held in TPM NV index S. All enclave
// NV indices and the owner, endorsement and lockout hierarchies are governed
// by policy P:
//
//	P = PolicyAuthorizeNV(V)
//	V = PolicyAuthorize(PCR signing key, Ref(role, profile)) || PolicyPCR(7 = recorded, 12 = 0)
//
// V is an NV index that only the owner hierarchy (that is, P itself) can
// write. The expected Secure Boot state (PCR 7) can therefore be moved by an
// authorized boot across a signed dbx/db/KEK update without redefining any
// object. During such a transition V binds PCR 0, 2 and 4 (firmware and boot
// chain) instead of PCR 7; the first boot afterwards checks that only the
// signed variable changed and records the new PCR 7 (see secureBootUpdates).
//
// PolicyAuthorize needs the release's signed approved policy (package
// tpmpolicy): PCR 11 in enter-initrd:leave-initrd of that very UKI and its
// security epoch not revoked in the bits index E. So only an unrevoked
// enclave UKI of the same role and profile, under the recorded Secure Boot
// state, without ESP credentials, before sysinit, can read S or administer
// the TPM. No administrative secret exists: hierarchy authValues are random
// and discarded, the platform hierarchy is disabled from the OS, Clear is
// disabled.
//
// Every command that carries a secret uses a salted session with parameter
// encryption. The salt key is the TPM's endorsement key (default template).
// Its public area is authenticated on every boot against the EK certificate
// (TPM vendor CAs in /usr) or the signed EK allowlist, and sessions are
// started from a locally built key reference, so a bus interposer cannot
// substitute the key (package ekcert).
package varauth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"enclave.local/base/internal/sbstate"
	"enclave.local/base/internal/tpmpolicy"
)

// Runner runs external commands and returns stdout.
type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

// TPMA_NV bits and NV types.
const (
	attrOwnerWrite  = 0x00000002
	attrPolicyWrite = 0x00000008
	ntCounter       = 0x00000010
	ntBits          = 0x00000020
	attrWriteLocked = 0x00000800
	attrWriteDefine = 0x00002000
	attrAuthRead    = 0x00040000
	attrPolicyRead  = 0x00080000
	attrNoDA        = 0x02000000
	attrReadLocked  = 0x10000000
	attrWritten     = 0x20000000
	attrReadSTClear = 0x80000000

	// NameAlgSHA256 is TPM_ALG_SHA256.
	NameAlgSHA256 = 0x000B
	// SaltHandle is the persistent salt key: the TPM's endorsement key
	// (default template, RSA 2048 or ECC P-256).
	SaltHandle = "0x81000E01"

	recordSize = 32 + 8 + 34 // PCR 15 || provisioning epoch || salt key (EK) Name
)

// Index describes one NV index.
type Index struct {
	Name   string
	Handle string
	Size   int
	Define uint32
	Final  uint32
}

// The NV indices (owner range; "E" for enclave).
var (
	// Record: PCR 15 of the authentic volume, provisioning epoch, salt key Name.
	Record = Index{"record", "0x01800E01", recordSize,
		attrPolicyWrite | attrWriteDefine | attrAuthRead | attrNoDA,
		attrPolicyWrite | attrWriteDefine | attrAuthRead | attrNoDA | attrWritten | attrWriteLocked}
	// Secret: the volume key; write-locked, read-locked after use each boot.
	Secret = Index{"secret", "0x01800E02", 64,
		attrPolicyRead | attrPolicyWrite | attrWriteDefine | attrReadSTClear | attrNoDA,
		attrPolicyRead | attrPolicyWrite | attrWriteDefine | attrReadSTClear | attrNoDA | attrWritten | attrWriteLocked | attrReadLocked}
	// Counter: state version (anti-rollback); policy OR(P, PolicyAuthValue).
	Counter = Index{"counter", "0x01800E03", 8,
		ntCounter | attrPolicyWrite | attrPolicyRead | attrNoDA,
		ntCounter | attrPolicyWrite | attrPolicyRead | attrNoDA | attrWritten}
	// Epoch: revocation bits; bit k set = UKIs of security epoch k revoked.
	Epoch = Index{"epoch", "0x01800E04", 8,
		ntBits | attrPolicyWrite | attrAuthRead | attrNoDA,
		ntBits | attrPolicyWrite | attrAuthRead | attrNoDA | attrWritten}

	// PCRPolicy (V): the PolicyAuthorizeNV index holding the PCR-bound part
	// of policy P as a TPMT_HA. It is written through the owner hierarchy
	// only (that is, under P). Its authPolicy is never used for
	// authorization: it binds the index Name, and with it P, to the PCR
	// signing key, role and profile.
	PCRPolicy = Index{"pcrpolicy", "0x01800E05", 34,
		attrOwnerWrite | attrAuthRead | attrNoDA,
		attrOwnerWrite | attrAuthRead | attrNoDA | attrWritten}

	// Transition (T): record of signed Secure Boot variable updates, written
	// through the owner hierarchy only (under P): the exact Secure Boot
	// states index V admits while an update is in transit, and the monotonic
	// per-update record (layout: verify.go). It is read before the volume key
	// is released.
	Transition = Index{"transition", "0x01800E06", 496,
		attrOwnerWrite | attrAuthRead | attrNoDA,
		attrOwnerWrite | attrAuthRead | attrNoDA | attrWritten}

	allIndices = []Index{Record, Secret, Counter, Epoch, PCRPolicy, Transition}
)

// Config holds the paths used at runtime.
type Config struct {
	RunDir      string // private state on tmpfs
	PubKey      string // PCR signing public key from the UKI (.pcrpkey)
	PolicyDir   string // signed approved policies, relative to the ESP root
	RoleFile    string
	TestMarker  string
	ReleaseFile string
	StateRoot   string // mounted state volume at runtime
	Work        string // per-process scratch dir (default RunDir/work)

	EKCADir     string // TPM vendor EK CAs (verity /usr)
	EKTestCADir string // test CA for emulated TPMs; honoured in the test profile only
	WritersDir  string // state writers allowed by the image (verity /usr)
	UpdatesDir  string // signed Secure Boot variable updates shipped by the release
	EventLog    string // TCG event log of this boot
	EFI         sbstate.Vars
	Now         func() time.Time
	Sys         string // sysfs (IOMMU check)
	StatusDir   string // world-readable status files for the console
	ConfigPub   string // config-signing public key (signed writer input)
}

// DefaultConfig returns the paths used on the image.
func DefaultConfig() Config {
	return Config{
		RunDir:      "/run/enclave",
		PubKey:      "/run/systemd/tpm2-pcr-public-key.pem",
		PolicyDir:   "EFI/enclave/policy",
		RoleFile:    "/usr/lib/enclave/role",
		TestMarker:  "/usr/lib/enclave/test-profile",
		ReleaseFile: "/usr/lib/enclave/release.json",
		StateRoot:   "/var/lib/enclave",
		EKCADir:     "/usr/share/enclave/tpm-ek-ca",
		EKTestCADir: "/usr/share/enclave/tpm-ek-ca-test",
		WritersDir:  "/usr/lib/enclave/state-writers.d",
		UpdatesDir:  "/usr/lib/enclave/efi-updates",
		EventLog:    "/sys/kernel/security/tpm0/binary_bios_measurements",
		EFI:         sbstate.EFIVarFS{Dir: "/sys/firmware/efi/efivars"},
		Now:         time.Now,
		Sys:         "/sys",
		StatusDir:   "/run/enclave-status",
		ConfigPub:   "/usr/share/enclave/keys/config-signing.pub",
	}
}

// EFIUpdatesFile records the state of the release's Secure Boot variable
// updates: "current", "pending ...", "failed ..." or "blocked ...".
func (c Config) EFIUpdatesFile() string { return filepath.Join(c.RunDir, "efi-updates") }

// SaltSourceFile records how the salt key (EK) was authenticated in this boot.
func (c Config) SaltSourceFile() string { return filepath.Join(c.RunDir, "ek-trust") }

func (c Config) work() string {
	if c.Work != "" {
		return c.Work
	}
	return filepath.Join(c.RunDir, "work")
}
func (c Config) espMount() string    { return filepath.Join(c.RunDir, "esp") }
func (c Config) stateMount() string  { return filepath.Join(c.RunDir, "statecheck") }
func (c Config) keyFile() string     { return filepath.Join(c.RunDir, "var.key") }
func (c Config) policyCache() string { return filepath.Join(c.RunDir, "policy.json") }
func (c Config) ekCertDir() string   { return filepath.Join(c.RunDir, "ekcert") }

// CreatedFlag is written by Repart when systemd-repart created the partition.
func (c Config) CreatedFlag() string { return filepath.Join(c.RunDir, "var-created") }

// ProvisionedFlag is written by Unlock after (re-)provisioning in this boot.
func (c Config) ProvisionedFlag() string { return filepath.Join(c.RunDir, "var-provisioned") }

// StateSocket is where the state service listens (authorized commits,
// verified reads).
func (c Config) StateSocket() string { return filepath.Join(c.RunDir, "state.sock") }

// StateKeyFile hands the derived state MAC key and counter auth from the
// unlock to the verify step and to the state service, which deletes it
// before anything else in the system starts.
func (c Config) StateKeyFile() string { return filepath.Join(c.RunDir, "state.key") }

// ResultFile records the authenticated PCR 15 value (hex).
func (c Config) ResultFile() string { return filepath.Join(c.RunDir, "var-authenticated") }

// CounterFile records the verified state version.
func (c Config) CounterFile() string { return filepath.Join(c.RunDir, "var-counter") }

// PlatformFile records how the platform hierarchy was found/handled.
func (c Config) PlatformFile() string { return filepath.Join(c.RunDir, "platform") }

// ---------------------------------------------------------------- identity

// Identity is the role/profile/release of the running image (all from the
// verity-protected /usr).
type Identity struct {
	Role, Profile, Ref string
	Release            tpmpolicy.Release
}

// LoadIdentity reads role, profile and release metadata.
func LoadIdentity(c Config) (Identity, error) {
	var id Identity
	b, err := os.ReadFile(c.RoleFile)
	if err != nil {
		return id, err
	}
	id.Role = strings.TrimSpace(string(b))
	b, err = os.ReadFile(c.ReleaseFile)
	if err != nil {
		return id, err
	}
	if err := json.Unmarshal(b, &id.Release); err != nil {
		return id, fmt.Errorf("release.json: %w", err)
	}
	// prod: production keys. dev: the same configuration signed with a
	// development PKI (its own policyRef: it can never open production
	// state, and only dev and test refs may admit emulated TPMs).
	id.Profile = "prod"
	if id.Release.DevKeys {
		id.Profile = "dev"
	}
	if _, err := os.Stat(c.TestMarker); err == nil {
		id.Profile = "test"
	} else if !errors.Is(err, os.ErrNotExist) {
		return id, err
	}
	if id.Ref, err = tpmpolicy.Ref(id.Role, id.Profile); err != nil {
		return id, err
	}
	if err := tpmpolicy.CheckRoleRelease(id.Role, id.Profile, id.Release); err != nil {
		return id, err
	}
	return id, id.Release.Validate()
}

// ---------------------------------------------------------------- helpers

func hexBytes(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"))
}

func handleNum(h string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(h), "0x"), 16, 32)
	return n
}

func lastDigest(out []byte) ([]byte, error) {
	f := strings.Fields(string(out))
	for i := len(f) - 1; i >= 0; i-- {
		s := strings.TrimPrefix(strings.ToLower(f[i]), "0x")
		if len(s) == 64 {
			if b, err := hex.DecodeString(s); err == nil {
				return b, nil
			}
		}
	}
	return nil, fmt.Errorf("no sha256 digest in output %q", strings.TrimSpace(string(out)))
}

// ReadPCR returns a sha256 PCR value.
func ReadPCR(r Runner, n int) ([]byte, error) {
	out, err := r.Run("tpm2_pcrread", fmt.Sprintf("sha256:%d", n))
	if err != nil {
		return nil, fmt.Errorf("tpm2_pcrread: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.TrimSpace(k) == strconv.Itoa(n) {
			b, err := hexBytes(v)
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("bad PCR %d value %q", n, v)
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("PCR %d missing from tpm2_pcrread output", n)
}

var zero32 = make([]byte, 32)

// RequireCleanPCR12 fails unless PCR 12 is all zero (no ESP credentials,
// addons or command line overrides).
func RequireCleanPCR12(r Runner) error {
	v, err := ReadPCR(r, 12)
	if err != nil {
		return err
	}
	if !bytes.Equal(v, zero32) {
		return fmt.Errorf("PCR 12 is %x, not clean (credential/addon/cmdline override on the ESP?)", v)
	}
	return nil
}

// NVPublic is the checked part of tpm2_nvreadpublic output.
type NVPublic struct {
	Name       []byte
	NameAlg    uint32
	Attributes uint32
	Size       int
	AuthPolicy []byte
}

// ParseNVPublic parses tpm2_nvreadpublic output for a single index.
func ParseNVPublic(out []byte) (NVPublic, error) {
	var p NVPublic
	section := ""
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "hash algorithm", "attributes":
			section = k
		case "name":
			b, err := hexBytes(v)
			if err != nil {
				return p, fmt.Errorf("bad name %q", v)
			}
			p.Name, seen["name"] = b, true
		case "value":
			n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(v), "0x"), 16, 32)
			if err != nil {
				return p, fmt.Errorf("bad %s value %q", section, v)
			}
			switch section {
			case "hash algorithm":
				p.NameAlg, seen["alg"] = uint32(n), true
			case "attributes":
				p.Attributes, seen["attr"] = uint32(n), true
			}
		case "size":
			n, err := strconv.Atoi(v)
			if err != nil {
				return p, fmt.Errorf("bad size %q", v)
			}
			p.Size, seen["size"] = n, true
		case "authorization policy":
			b, err := hexBytes(v)
			if err != nil {
				return p, fmt.Errorf("bad authorization policy %q", v)
			}
			p.AuthPolicy, seen["policy"] = b, true
		}
	}
	for _, k := range []string{"name", "alg", "attr", "size", "policy"} {
		if !seen[k] {
			return p, fmt.Errorf("tpm2_nvreadpublic output lacks %s", k)
		}
	}
	return p, nil
}

// CheckPublic compares an index public area with the expectation.
func CheckPublic(ix Index, p NVPublic, attrs uint32, policy []byte) error {
	switch {
	case p.NameAlg != NameAlgSHA256:
		return fmt.Errorf("NV %s %s nameAlg 0x%x, want sha256", ix.Name, ix.Handle, p.NameAlg)
	case p.Size != ix.Size:
		return fmt.Errorf("NV %s %s size %d, want %d", ix.Name, ix.Handle, p.Size, ix.Size)
	case p.Attributes != attrs:
		return fmt.Errorf("NV %s %s attributes 0x%08x, want 0x%08x", ix.Name, ix.Handle, p.Attributes, attrs)
	case len(policy) == 0 || !bytes.Equal(p.AuthPolicy, policy):
		return fmt.Errorf("NV %s %s authPolicy %x, want %x", ix.Name, ix.Handle, p.AuthPolicy, policy)
	}
	return nil
}

func handles(r Runner, what string) (map[uint64]bool, error) {
	out, err := r.Run("tpm2_getcap", what)
	if err != nil {
		return nil, fmt.Errorf("tpm2_getcap %s: %w", what, err)
	}
	m := map[uint64]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		h := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
		if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(h), "0x"), 16, 32); err == nil && h != "" {
			m[n] = true
		}
	}
	return m, nil
}

// DefinedIndices returns the defined NV handles.
func DefinedIndices(r Runner) (map[uint64]bool, error) { return handles(r, "handles-nv-index") }

// ReadPublic returns the parsed public area of an index.
func ReadPublic(r Runner, ix Index) (NVPublic, error) {
	out, err := r.Run("tpm2_nvreadpublic", ix.Handle)
	if err != nil {
		return NVPublic{}, fmt.Errorf("tpm2_nvreadpublic %s: %w", ix.Handle, err)
	}
	return ParseNVPublic(out)
}

// ReadNV reads an AUTHREAD index with empty auth.
func ReadNV(r Runner, ix Index) ([]byte, error) {
	out, err := r.Run("tpm2_nvread", ix.Handle, "-C", ix.Handle, "-s", strconv.Itoa(ix.Size))
	if err != nil {
		return nil, fmt.Errorf("tpm2_nvread %s: %w", ix.Handle, err)
	}
	if len(out) != ix.Size {
		return nil, fmt.Errorf("tpm2_nvread %s returned %d bytes, want %d", ix.Handle, len(out), ix.Size)
	}
	return out, nil
}

// RecordData is the content of record A.
type RecordData struct {
	PCR15    []byte
	Epoch    uint64
	SaltName []byte
}

// ParseRecord splits record A.
func ParseRecord(b []byte) (RecordData, error) {
	if len(b) != recordSize {
		return RecordData{}, fmt.Errorf("record has %d bytes, want %d", len(b), recordSize)
	}
	return RecordData{PCR15: b[:32], Epoch: binary.BigEndian.Uint64(b[32:40]), SaltName: b[40:]}, nil
}

func (d RecordData) bytes() []byte {
	b := append([]byte{}, d.PCR15...)
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], d.Epoch)
	b = append(b, e[:]...)
	return append(b, d.SaltName...)
}

// Hierarchy is the relevant TPM state (TPM2_PT_PERMANENT, TPM2_PT_STARTUP_CLEAR).
type Hierarchy struct {
	OwnerAuthSet, EndorsementAuthSet, LockoutAuthSet, DisableClear, PhEnable bool
}

// Locked reports whether all hierarchies are protected and Clear is disabled.
func (h Hierarchy) Locked() bool {
	return h.OwnerAuthSet && h.EndorsementAuthSet && h.LockoutAuthSet && h.DisableClear
}

// Fresh reports an unprovisioned TPM (no authorization set, Clear allowed).
func (h Hierarchy) Fresh() bool {
	return !h.OwnerAuthSet && !h.EndorsementAuthSet && !h.LockoutAuthSet && !h.DisableClear
}

// ReadHierarchy parses "tpm2_getcap properties-variable".
func ReadHierarchy(r Runner) (Hierarchy, error) {
	out, err := r.Run("tpm2_getcap", "properties-variable")
	if err != nil {
		return Hierarchy{}, fmt.Errorf("tpm2_getcap: %w", err)
	}
	var h Hierarchy
	sec, seen := "", 0
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasSuffix(t, ":") && !strings.HasPrefix(line, " ") {
			sec = t
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		set := strings.TrimSpace(v) == "1"
		switch sec + k {
		case "TPM2_PT_PERMANENT:ownerAuthSet":
			h.OwnerAuthSet = set
		case "TPM2_PT_PERMANENT:endorsementAuthSet":
			h.EndorsementAuthSet = set
		case "TPM2_PT_PERMANENT:lockoutAuthSet":
			h.LockoutAuthSet = set
		case "TPM2_PT_PERMANENT:disableClear":
			h.DisableClear = set
		case "TPM2_PT_STARTUP_CLEAR:phEnable":
			h.PhEnable = set
		default:
			continue
		}
		seen++
	}
	if seen != 5 {
		return h, errors.New("TPM2_PT_PERMANENT/STARTUP_CLEAR flags missing from tpm2_getcap output")
	}
	return h, nil
}

// LockPlatform disables the platform hierarchy if the OS can use it (empty
// platform auth). A platform hierarchy protected by firmware-held auth is
// accepted; any other failure fails closed. Runs first on every boot.
func LockPlatform(c Config, r Runner) (string, error) {
	h, err := ReadHierarchy(r)
	if err != nil {
		return "", err
	}
	state := "disabled"
	if h.PhEnable {
		_, err := r.Run("tpm2_hierarchycontrol", "-C", "p", "phEnable", "clear")
		switch {
		case err == nil:
			state = "disabled-by-enclave"
		case isAuthFailure(err):
			state = "firmware-auth" // platform auth set by firmware, unusable from the OS
		default:
			return "", fmt.Errorf("disabling the platform hierarchy: %w", err)
		}
	}
	if err := os.MkdirAll(c.RunDir, 0o700); err != nil {
		return "", err
	}
	return state, os.WriteFile(c.PlatformFile(), []byte(state+"\n"), 0o600)
}

func isAuthFailure(err error) bool {
	s := strings.ToLower(err.Error())
	for _, m := range []string{"0x9a2", "0x98e", "authorization failure", "bad_auth", "auth_fail"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}
