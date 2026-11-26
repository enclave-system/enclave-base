// Package varauth creates, unlocks, authenticates and heals the encrypted
// persistent state volume (mounted at /var/lib/enklave).
//
// The volume is LUKS2 (aes-xts-plain64 512-bit, hmac-sha256 integrity,
// argon2id) with a 64-byte random key S held in TPM NV index S. All enklave
// NV indices and the owner, endorsement and lockout hierarchies are governed
// by policy P:
//
//	P = PolicyAuthorize(PCR signing key, Ref(role, profile)) || PolicyPCR(7 = current, 12 = 0)
//
// PolicyAuthorize needs the release's signed approved policy (package
// tpmpolicy): PCR 11 in enter-initrd:leave-initrd of that very UKI and its
// security epoch not revoked in the bits index E. So only an unrevoked
// enklave UKI of the same role and profile, under Secure Boot, without ESP
// credentials, before sysinit, can read S or administer the TPM. No
// administrative secret exists: hierarchy authValues are random and
// discarded, the platform hierarchy is disabled from the OS, Clear is
// disabled. Every command that carries a secret uses a salted session with
// parameter encryption; the salt key's Name is pinned in record A.
package varauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"enklave.local/base/internal/statefs"
	"enklave.local/base/internal/tpmpolicy"
)

// Runner runs external commands and returns stdout.
type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

// TPMA_NV bits and NV types.
const (
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
	// SaltHandle is the persistent salt key (ECC P-256 primary, SRK template).
	SaltHandle = "0x81000E01"

	saltTemplateAttrs = "restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda"
	recordSize        = 32 + 8 + 34 // PCR 15 || provisioning epoch || salt key Name
)

// Index describes one NV index.
type Index struct {
	Name   string
	Handle string
	Size   int
	Define uint32
	Final  uint32
}

// The NV indices (owner range; "E" for enklave).
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

	allIndices = []Index{Record, Secret, Counter, Epoch}
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
}

// DefaultConfig returns the paths used on the image.
func DefaultConfig() Config {
	return Config{
		RunDir:      "/run/enklave",
		PubKey:      "/run/systemd/tpm2-pcr-public-key.pem",
		PolicyDir:   "EFI/enklave/policy",
		RoleFile:    "/usr/lib/enklave/role",
		TestMarker:  "/usr/lib/enklave/test-profile",
		ReleaseFile: "/usr/lib/enklave/release.json",
		StateRoot:   "/var/lib/enklave",
	}
}

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

// CreatedFlag is written by Repart when systemd-repart created the partition.
func (c Config) CreatedFlag() string { return filepath.Join(c.RunDir, "var-created") }

// ProvisionedFlag is written by Unlock after (re-)provisioning in this boot.
func (c Config) ProvisionedFlag() string { return filepath.Join(c.RunDir, "var-provisioned") }

// StateKeyFile holds the derived state MAC key and counter auth for runtime writers.
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
	id.Profile = "prod"
	if _, err := os.Stat(c.TestMarker); err == nil {
		id.Profile = "test"
	} else if !errors.Is(err, os.ErrNotExist) {
		return id, err
	}
	if id.Ref, err = tpmpolicy.Ref(id.Role, id.Profile); err != nil {
		return id, err
	}
	b, err = os.ReadFile(c.ReleaseFile)
	if err != nil {
		return id, err
	}
	if err := json.Unmarshal(b, &id.Release); err != nil {
		return id, fmt.Errorf("release.json: %w", err)
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
			state = "disabled-by-enklave"
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

// ---------------------------------------------------------------- sessions

type tpm struct {
	c  Config
	r  Runner
	id Identity

	pcr11, policy, pe, pc []byte
	epoch                 int
	ready, salted         bool
	pauseAt               string
}

func newTPM(c Config, r Runner) (*tpm, error) {
	id, err := LoadIdentity(c)
	if err != nil {
		return nil, err
	}
	return &tpm{c: c, r: r, id: id}, nil
}

func (t *tpm) w(name string) string { return filepath.Join(t.c.work(), name) }

func (t *tpm) run(name string, args ...string) ([]byte, error) {
	out, err := t.r.Run(name, args...)
	if err != nil {
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

func (t *tpm) put(name string, data []byte) error { return os.WriteFile(t.w(name), data, 0o600) }

// pause stops at a named provisioning step (test profile only).
func (t *tpm) pause(step string) {
	if t.id.Profile != "test" || t.pauseAt != step {
		return
	}
	msg := "enklave-varauth: TEST PAUSE at " + step + "\n"
	os.Stderr.WriteString(msg)
	if f, err := os.OpenFile("/dev/ttyS0", os.O_WRONLY, 0); err == nil {
		f.WriteString(msg)
		f.Close()
	}
	pauseHook(step)
}

func (t *tpm) trial(steps ...[]string) ([]byte, error) {
	if _, err := t.run("tpm2_startauthsession", "-S", t.w("trial.ctx")); err != nil {
		return nil, err
	}
	defer t.r.Run("tpm2_flushcontext", t.w("trial.ctx")) //nolint:errcheck
	var out []byte
	for _, st := range steps {
		o, err := t.run(st[0], append([]string{"-S", t.w("trial.ctx")}, st[1:]...)...)
		if err != nil {
			return nil, err
		}
		out = o
	}
	return lastDigest(out)
}

// prepare loads the PCR key and computes the expected policies.
func (t *tpm) prepare() error {
	if err := os.MkdirAll(t.c.work(), 0o700); err != nil {
		return err
	}
	if err := t.put("ref.bin", []byte(t.id.Ref)); err != nil {
		return err
	}
	if _, err := t.run("tpm2_loadexternal", "-C", "o", "-G", "rsa", "-u", t.c.PubKey,
		"-c", t.w("key.ctx"), "-n", t.w("key.name")); err != nil {
		return err
	}
	pcr7, err := ReadPCR(t.r, 7)
	if err != nil {
		return err
	}
	if err := t.put("pcrvals.bin", append(append([]byte{}, pcr7...), zero32...)); err != nil {
		return err
	}
	auth := []string{"tpm2_policyauthorize", "-n", t.w("key.name"), "-q", t.w("ref.bin")}
	if t.policy, err = t.trial(auth, []string{"tpm2_policypcr", "-l", "sha256:7,12", "-f", t.w("pcrvals.bin")}); err != nil {
		return err
	}
	b1, err := t.trial(auth)
	if err != nil {
		return err
	}
	b2, err := t.trial([]string{"tpm2_policycommandcode", "TPM2_CC_NV_SetBits"}, []string{"tpm2_policynvwritten", "c"})
	if err != nil {
		return err
	}
	av, err := t.trial([]string{"tpm2_policyauthvalue"})
	if err != nil {
		return err
	}
	// Counter admin branch: NV_ChangeAuth needs the ADMIN role, which requires
	// PolicyCommandCode in the session.
	pca, err := t.trial(auth, []string{"tpm2_policypcr", "-l", "sha256:7,12", "-f", t.w("pcrvals.bin")},
		[]string{"tpm2_policycommandcode", "TPM2_CC_NV_ChangeAuth"})
	if err != nil {
		return err
	}
	for n, d := range map[string][]byte{"p.bin": t.policy, "b1.bin": b1, "b2.bin": b2, "av.bin": av, "pca.bin": pca} {
		if err := t.put(n, d); err != nil {
			return err
		}
	}
	if t.pe, err = t.trial([]string{"tpm2_policyor", "-l", "sha256:" + t.w("b1.bin") + "," + t.w("b2.bin")}); err != nil {
		return err
	}
	if t.pc, err = t.trial([]string{"tpm2_policyor", "-l", "sha256:" + t.w("pca.bin") + "," + t.w("av.bin")}); err != nil {
		return err
	}
	if err := t.put("pe.bin", t.pe); err != nil {
		return err
	}
	if err := t.put("pc.bin", t.pc); err != nil {
		return err
	}
	t.pcr11, err = t.trial([]string{"tpm2_policypcr", "-l", "sha256:11"})
	return err
}

// Policies are the expected policy digests for this boot.
type Policies struct{ P, PE, PC []byte }

// ExpectedPolicies returns the policies (P for A/S and the hierarchies, PE
// for E, PC for the counter).
func ExpectedPolicies(c Config, r Runner) (Policies, error) {
	t, err := newTPM(c, r)
	if err != nil {
		return Policies{}, err
	}
	defer os.RemoveAll(c.work())
	if err := t.prepare(); err != nil {
		return Policies{}, err
	}
	return Policies{t.policy, t.pe, t.pc}, nil
}

func (t *tpm) selectPolicy(espDev string) (tpmpolicy.File, error) {
	var f tpmpolicy.File
	if err := os.MkdirAll(t.c.espMount(), 0o700); err != nil {
		return f, err
	}
	// Not "ro": systemd-boot-random-seed may already have mounted the ESP
	// read-write via the /efi automount, and a read-only second mount of the
	// same superblock fails with EBUSY. Nothing is written.
	if _, err := t.run("mount", "-t", "vfat", "-o", "nosuid,nodev,noexec,umask=077", espDev, t.c.espMount()); err != nil {
		return f, err
	}
	defer t.r.Run("umount", t.c.espMount()) //nolint:errcheck
	if t.id.Profile == "test" {
		if b, err := os.ReadFile(filepath.Join(t.c.espMount(), "EFI/enklave/test-pause")); err == nil {
			t.pauseAt = strings.TrimSpace(string(b))
		}
	}
	files, _ := filepath.Glob(filepath.Join(t.c.espMount(), t.c.PolicyDir, "*.json"))
	sort.Strings(files)
	want := hex.EncodeToString(t.pcr11)
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cand tpmpolicy.File
		if json.Unmarshal(b, &cand) == nil && strings.EqualFold(cand.PCR11Policy, want) {
			if err := os.WriteFile(t.c.policyCache(), b, 0o600); err != nil {
				return f, err
			}
			return cand, nil
		}
	}
	return f, fmt.Errorf("no signed approved policy for the running UKI (PCR 11 policy %s) in ESP:/%s", want, t.c.PolicyDir)
}

func (t *tpm) cachedPolicy() (tpmpolicy.File, error) {
	var f tpmpolicy.File
	b, err := os.ReadFile(t.c.policyCache())
	if err != nil {
		return f, err
	}
	return f, json.Unmarshal(b, &f)
}

// authorize checks E, recomputes the approved digest and obtains the ticket.
func (t *tpm) authorize(f tpmpolicy.File) error {
	pcr11, approved, err := f.Decode(t.id.Role, t.id.Profile)
	if err != nil {
		return err
	}
	if f.Epoch != t.id.Release.Epoch {
		return fmt.Errorf("approved policy epoch %d != release epoch %d", f.Epoch, t.id.Release.Epoch)
	}
	if !bytes.Equal(pcr11, t.pcr11) {
		return errors.New("approved policy is for another PCR 11 state")
	}
	pub, err := ReadPublic(t.r, Epoch)
	if err != nil {
		return err
	}
	if err := CheckPublic(Epoch, pub, Epoch.Final, t.pe); err != nil {
		return err
	}
	want, err := tpmpolicy.Approved(t.pcr11, f.Epoch, pub.Name)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, approved) {
		return fmt.Errorf("approved policy %x does not match epoch %d / index E (%x)", approved, f.Epoch, want)
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	op, _ := tpmpolicy.EpochOperand(f.Epoch)
	for name, data := range map[string][]byte{
		"approved.bin": approved, "msg.bin": tpmpolicy.SignedMessage(approved, t.id.Ref), "sig.bin": sig, "epochop.bin": op,
	} {
		if err := t.put(name, data); err != nil {
			return err
		}
	}
	if _, err := t.run("tpm2_verifysignature", "-c", t.w("key.ctx"), "-g", "sha256", "-m", t.w("msg.bin"),
		"-s", t.w("sig.bin"), "-f", "rsassa", "-t", t.w("ticket.bin")); err != nil {
		return fmt.Errorf("approved policy signature rejected: %w", err)
	}
	if _, err := t.run("tpm2_flushcontext", "-t"); err != nil {
		return err
	}
	t.epoch, t.ready = f.Epoch, true
	return nil
}

// session kinds
const (
	sessP  = "P"  // policy P (A, S, hierarchies)
	sessPE = "PE" // branch 1 of E's policy
	sessPC = "PC" // admin branch of the counter policy (NV_ChangeAuth only)
)

// session runs cmd with a policy session of the given kind. enc is "" (no
// parameter encryption: the command carries no secret), "encrypt" (response)
// or "decrypt" (command); encryption requires the verified salt key and is
// only used where the authorized entity has an empty authValue (the TPM mixes
// that authValue into the encryption key; see auxEncrypt for the others).
// tpm2_startauthsession -c enables both directions, so the unwanted one is
// switched off explicitly.
func (t *tpm) session(kind, enc string, cmd ...string) ([]byte, error) {
	if !t.ready {
		return nil, errors.New("policy not authorized")
	}
	s := t.w("s.ctx")
	start := []string{"tpm2_startauthsession", "--policy-session", "-S", s}
	steps := [][]string{start}
	switch enc {
	case "":
	case "decrypt", "encrypt":
		if !t.salted {
			return nil, errors.New("parameter encryption requested without a verified salt key")
		}
		steps[0] = append(start, "-c", SaltHandle)
		off := map[string]string{"decrypt": "--disable-encrypt", "encrypt": "--disable-decrypt"}[enc]
		steps = append(steps, []string{"tpm2_sessionconfig", s, off})
	default:
		return nil, fmt.Errorf("unknown parameter encryption %q", enc)
	}
	steps = append(steps,
		[]string{"tpm2_policypcr", "-S", s, "-l", "sha256:11"},
		[]string{"tpm2_policynv", "-S", s, "-i", t.w("epochop.bin"), Epoch.Handle, "bc"},
		[]string{"tpm2_policyauthorize", "-S", s, "-i", t.w("approved.bin"), "-q", t.w("ref.bin"), "-n", t.w("key.name"), "-t", t.w("ticket.bin")},
	)
	switch kind {
	case sessP:
		steps = append(steps, []string{"tpm2_policypcr", "-S", s, "-l", "sha256:7,12", "-f", t.w("pcrvals.bin")})
	case sessPC:
		steps = append(steps, []string{"tpm2_policypcr", "-S", s, "-l", "sha256:7,12", "-f", t.w("pcrvals.bin")},
			[]string{"tpm2_policycommandcode", "-S", s, "TPM2_CC_NV_ChangeAuth"},
			[]string{"tpm2_policyor", "-S", s, "-l", "sha256:" + t.w("pca.bin") + "," + t.w("av.bin")})
	case sessPE:
		steps = append(steps, []string{"tpm2_policyor", "-S", s, "-l", "sha256:" + t.w("b1.bin") + "," + t.w("b2.bin")})
	}
	defer t.r.Run("tpm2_flushcontext", s) //nolint:errcheck
	for _, st := range steps {
		if _, err := t.run(st[0], st[1:]...); err != nil {
			return nil, err
		}
	}
	return t.run(cmd[0], append(cmd[1:], "session:"+s)...)
}

// owner runs an owner-authorized command with policy P ("-C o -P session").
func (t *tpm) owner(enc string, name string, args ...string) error {
	_, err := t.session(sessP, enc, append(append([]string{name}, args...), "-C", "o", "-P")...)
	return err
}

func (t *tpm) defineWithPolicy(ix Index, policyFile string, authHex string) error {
	args := []string{ix.Handle, "-s", strconv.Itoa(ix.Size), "-a", fmt.Sprintf("0x%08x", ix.Define), "-L", t.w(policyFile), "-g", "sha256"}
	enc := ""
	if authHex != "" {
		args = append(args, "-p", "hex:"+authHex)
		enc = "decrypt"
	}
	return t.owner(enc, "tpm2_nvdefine", args...)
}

func (t *tpm) initEpoch() error {
	s := t.w("s.ctx")
	defer t.r.Run("tpm2_flushcontext", s) //nolint:errcheck
	for _, st := range [][]string{
		{"tpm2_startauthsession", "--policy-session", "-S", s},
		{"tpm2_policycommandcode", "-S", s, "TPM2_CC_NV_SetBits"},
		{"tpm2_policynvwritten", "-S", s, "c"},
		{"tpm2_policyor", "-S", s, "-l", "sha256:" + t.w("b1.bin") + "," + t.w("b2.bin")},
		{"tpm2_nvsetbits", Epoch.Handle, "-C", Epoch.Handle, "-i", "0", "-P", "session:" + s},
	} {
		if _, err := t.run(st[0], st[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (t *tpm) revoke() error {
	b, err := ReadNV(t.r, Epoch)
	if err != nil {
		return err
	}
	v := binary.BigEndian.Uint64(b)
	if v&(uint64(1)<<uint(t.epoch)) != 0 {
		return fmt.Errorf("security epoch %d of this UKI is revoked (E = 0x%x)", t.epoch, v)
	}
	mask := tpmpolicy.RevokeMask(t.epoch)
	if v&mask == mask {
		return nil
	}
	_, err = t.session(sessPE, "", "tpm2_nvsetbits", Epoch.Handle, "-C", Epoch.Handle, "-i", fmt.Sprintf("0x%x", mask), "-P")
	return err
}

func (t *tpm) checkIndex(ix Index, attrs uint32, policy []byte) error {
	pub, err := ReadPublic(t.r, ix)
	if err != nil {
		return err
	}
	return CheckPublic(ix, pub, attrs, policy)
}

// createSalt creates the deterministic salt primary and persists it.
// ownerPolicy selects owner authorization by policy P (locked TPM) instead of
// the empty owner auth of a fresh TPM.
func (t *tpm) createSalt(ownerPolicy bool) ([]byte, error) {
	if _, err := t.run("tpm2_flushcontext", "-t"); err != nil {
		return nil, err
	}
	create := []string{"-G", "ecc256:aes128cfb", "-a", saltTemplateAttrs, "-c", t.w("salt.ctx")}
	persist := []string{"-c", t.w("salt.ctx"), SaltHandle}
	if ownerPolicy {
		if err := t.owner("", "tpm2_createprimary", create...); err != nil {
			return nil, err
		}
		if err := t.owner("", "tpm2_evictcontrol", persist...); err != nil {
			return nil, err
		}
	} else {
		if _, err := t.run("tpm2_createprimary", append([]string{"-C", "o"}, create...)...); err != nil {
			return nil, err
		}
		if _, err := t.run("tpm2_evictcontrol", append([]string{"-C", "o"}, persist...)...); err != nil {
			return nil, err
		}
	}
	if _, err := t.run("tpm2_flushcontext", "-t"); err != nil {
		return nil, err
	}
	return t.saltName()
}

func (t *tpm) saltName() ([]byte, error) {
	if _, err := t.run("tpm2_readpublic", "-c", SaltHandle, "-n", t.w("salt.name")); err != nil {
		return nil, err
	}
	return os.ReadFile(t.w("salt.name"))
}

// useSalt enables salted sessions after checking the salt key's Name.
func (t *tpm) useSalt(want []byte) error {
	got, err := t.saltName()
	if err != nil {
		return err
	}
	if len(want) == 0 || !bytes.Equal(got, want) {
		return fmt.Errorf("salt key %s Name %x does not match the recorded %x (substituted key?)", SaltHandle, got, want)
	}
	t.salted = true
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// lockFresh locks a fresh TPM: hierarchy policies P, Clear disabled, random
// discarded authValues sent with parameter encryption.
func (t *tpm) lockFresh() error {
	for _, h := range []string{"o", "e", "l"} {
		if _, err := t.run("tpm2_setprimarypolicy", "-C", h, "-L", t.w("p.bin"), "-g", "sha256"); err != nil {
			return err
		}
	}
	if _, err := t.run("tpm2_clearcontrol", "-C", "l", "s"); err != nil {
		return err
	}
	for _, h := range []string{"o", "e", "l"} {
		v, err := randomHex(32)
		if err != nil {
			return err
		}
		hs := t.w("h.ctx")
		steps := [][]string{
			{"tpm2_startauthsession", "--hmac-session", "-S", hs, "-c", SaltHandle},
			{"tpm2_sessionconfig", hs, "--enable-decrypt"},
			{"tpm2_changeauth", "-c", h, "-p", "session:" + hs, "hex:" + v},
		}
		for _, st := range steps {
			if _, err := t.run(st[0], st[1:]...); err != nil {
				t.r.Run("tpm2_flushcontext", hs) //nolint:errcheck
				return err
			}
		}
		t.r.Run("tpm2_flushcontext", hs) //nolint:errcheck
	}
	return nil
}

// rotate re-applies the hierarchy policies and fresh random authValues on a
// locked TPM (healing). The current authValues are unknown (discarded), so
// the authorizing policy session cannot encrypt parameters; the new
// authValue is encrypted by an auxiliary salted HMAC session instead.
func (t *tpm) rotate() error {
	if !t.salted {
		return errors.New("rotation requires the verified salt key")
	}
	for _, h := range []string{"o", "e", "l"} {
		if _, err := t.session(sessP, "", "tpm2_setprimarypolicy", "-C", h, "-L", t.w("p.bin"), "-g", "sha256", "-P"); err != nil {
			return err
		}
	}
	for _, h := range []string{"o", "e", "l"} {
		v, err := randomHex(32)
		if err != nil {
			return err
		}
		aux := t.w("aux.ctx")
		if _, err := t.run("tpm2_startauthsession", "--hmac-session", "-S", aux, "-c", SaltHandle); err != nil {
			return err
		}
		_, err = t.run("tpm2_sessionconfig", aux, "--disable-encrypt")
		if err == nil {
			_, err = t.session(sessP, "", "tpm2_changeauth", "-c", h, "-S", aux, "hex:"+v, "-p")
		}
		t.r.Run("tpm2_flushcontext", aux) //nolint:errcheck
		if err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- repart

// Repart locks the platform hierarchy, requires a clean PCR 12, runs
// systemd-repart and records whether it created the partition.
func Repart(c Config, r Runner, args []string) error {
	if _, err := LockPlatform(c, r); err != nil {
		return err
	}
	if err := RequireCleanPCR12(r); err != nil {
		return err
	}
	out, err := r.Run("systemd-repart", append(append([]string{}, args...), "--json=short")...)
	if err != nil {
		return fmt.Errorf("systemd-repart: %w", err)
	}
	var parts []struct {
		Type     string `json:"type"`
		Activity string `json:"activity"`
	}
	if err := json.Unmarshal(out, &parts); err != nil {
		return fmt.Errorf("parse systemd-repart json: %w", err)
	}
	n, created := 0, false
	for _, p := range parts {
		if p.Type == "var" {
			n++
			created = p.Activity == "create"
		}
	}
	if n != 1 {
		return fmt.Errorf("systemd-repart reported %d var partitions, want 1", n)
	}
	if !created {
		return nil
	}
	fh, err := os.OpenFile(c.CreatedFlag(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return fh.Close()
}

func exists(p string) (bool, error) {
	_, err := os.Stat(p)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// ---------------------------------------------------------------- keys

func derive(key []byte, label string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	return h.Sum(nil)
}

// StateKeys are derived from the volume key S.
type StateKeys struct{ MAC, CounterAuth []byte }

func deriveKeys(s []byte) StateKeys {
	return StateKeys{derive(s, "enklave-state-mac-v1"), derive(s, "enklave-counter-auth-v1")}
}

// LoadStateKeys reads the runtime copy written by Unlock.
func LoadStateKeys(c Config) (StateKeys, error) {
	b, err := os.ReadFile(c.StateKeyFile())
	if err != nil {
		return StateKeys{}, err
	}
	if len(b) != 64 {
		return StateKeys{}, errors.New("bad state key file")
	}
	return StateKeys{b[:32], b[32:]}, nil
}

// counterRT authorizes the counter with PolicyAuthValue (runtime + boot).
type counterRT struct {
	r    Runner
	work string
	auth []byte
}

func (k counterRT) session(cmd ...string) ([]byte, error) {
	if err := os.MkdirAll(k.work, 0o700); err != nil {
		return nil, err
	}
	s := filepath.Join(k.work, "c.ctx")
	defer k.r.Run("tpm2_flushcontext", s) //nolint:errcheck
	for _, st := range [][]string{
		{"tpm2_startauthsession", "--policy-session", "-S", s, "-c", SaltHandle},
		{"tpm2_policyauthvalue", "-S", s},
		{"tpm2_policyor", "-S", s, "-l", "sha256:" + filepath.Join(k.work, "pca.bin") + "," + filepath.Join(k.work, "av.bin")},
	} {
		if _, err := k.r.Run(st[0], st[1:]...); err != nil {
			return nil, fmt.Errorf("%s: %w", st[0], err)
		}
	}
	out, err := k.r.Run(cmd[0], append(cmd[1:], "-P", "session:"+s+"+hex:"+hex.EncodeToString(k.auth))...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cmd[0], err)
	}
	return out, nil
}

func (k counterRT) Read() (uint64, error) {
	b, err := k.session("tpm2_nvread", Counter.Handle, "-C", Counter.Handle, "-s", "8")
	if err != nil {
		return 0, err
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("counter read returned %d bytes", len(b))
	}
	return binary.BigEndian.Uint64(b), nil
}

func (k counterRT) Increment() error {
	_, err := k.session("tpm2_nvincrement", Counter.Handle, "-C", Counter.Handle)
	return err
}

// OpenStore opens the mounted state store for runtime writers: it re-checks
// the salt key against record A and the counter's policy, then uses the
// derived keys from /run.
func OpenStore(c Config, r Runner, pause func(string)) (*statefs.Store, error) {
	keys, err := LoadStateKeys(c)
	if err != nil {
		return nil, err
	}
	t, err := newTPM(c, r)
	if err != nil {
		return nil, err
	}
	if err := t.prepare(); err != nil {
		return nil, err
	}
	rec, err := ReadNV(r, Record)
	if err != nil {
		return nil, err
	}
	rd, err := ParseRecord(rec)
	if err != nil {
		return nil, err
	}
	if err := t.useSalt(rd.SaltName); err != nil {
		return nil, err
	}
	if err := t.checkIndex(Counter, Counter.Final, t.pc); err != nil {
		return nil, err
	}
	return &statefs.Store{Root: c.StateRoot, Key: keys.MAC, Counter: counterRT{r, t.c.work(), keys.CounterAuth}, Pause: pause}, nil
}

// ---------------------------------------------------------------- unlock

// state of the enklave objects in the TPM
type tpmState struct {
	h        Hierarchy
	nv, pers map[uint64]bool
}

func (s tpmState) count() int {
	n := 0
	for _, ix := range allIndices {
		if s.nv[handleNum(ix.Handle)] {
			n++
		}
	}
	if s.pers[handleNum(SaltHandle)] {
		n++
	}
	return n
}

func readState(r Runner) (tpmState, error) {
	var s tpmState
	var err error
	if s.h, err = ReadHierarchy(r); err != nil {
		return s, err
	}
	if s.nv, err = DefinedIndices(r); err != nil {
		return s, err
	}
	s.pers, err = handles(r, "handles-persistent")
	return s, err
}

// Unlock opens the volume as /dev/mapper/var: provisions on the genuine
// first boot, heals if the release demands it, otherwise reads the key.
func Unlock(c Config, r Runner, varDev, espDev string) (string, error) {
	if err := os.MkdirAll(c.RunDir, 0o700); err != nil {
		return "", err
	}
	defer os.Remove(c.keyFile())
	defer os.RemoveAll(c.work())
	if _, err := os.Stat(c.PlatformFile()); err != nil {
		return "", errors.New("platform hierarchy not handled in this boot")
	}
	if err := RequireCleanPCR12(r); err != nil {
		return "", err
	}
	first, err := exists(c.CreatedFlag())
	if err != nil {
		return "", err
	}
	t, err := newTPM(c, r)
	if err != nil {
		return "", err
	}
	if err := t.prepare(); err != nil {
		return "", err
	}
	f, err := t.selectPolicy(espDev)
	if err != nil {
		return "", err
	}
	st, err := readState(r)
	if err != nil {
		return "", err
	}

	var key []byte
	verb := "opened"
	switch {
	case first:
		if st.count() != 0 || !st.h.Fresh() {
			return "", fmt.Errorf("first boot of /var on a TPM that is not fresh (%d enklave objects, %+v)", st.count(), st.h)
		}
		if _, err := r.Run("cryptsetup", "isLuks", varDev); err == nil {
			return "", fmt.Errorf("%s already carries a LUKS header on the first boot", varDev)
		}
		if key, err = t.provision(f, varDev); err != nil {
			return "", err
		}
		verb = "provisioned"
	default:
		if !st.h.Locked() {
			return "", fmt.Errorf("TPM hierarchies not locked on an enrolled machine: %+v (interrupted provisioning?)", st.h)
		}
		if !st.nv[handleNum(Epoch.Handle)] {
			return "", errors.New("epoch index missing on an enrolled machine")
		}
		if err := t.authorize(f); err != nil {
			return "", err
		}
		if err := t.revoke(); err != nil {
			return "", err
		}
		complete := st.count() == len(allIndices)+1
		var rd RecordData
		if st.nv[handleNum(Record.Handle)] {
			b, err := ReadNV(r, Record)
			if err != nil {
				return "", err
			}
			if rd, err = ParseRecord(b); err != nil {
				return "", err
			}
		}
		heal := t.id.Release.HealBelow > 0 && (!st.nv[handleNum(Record.Handle)] || rd.Epoch < uint64(t.id.Release.HealBelow))
		switch {
		case heal:
			if key, err = t.heal(st, varDev); err != nil {
				return "", fmt.Errorf("healing: %w", err)
			}
			verb = "healed"
		case !complete:
			return "", fmt.Errorf("partial enklave TPM state (%d of %d objects): interrupted provisioning, refusing", st.count(), len(allIndices)+1)
		default:
			if err := t.useSalt(rd.SaltName); err != nil {
				return "", err
			}
			for _, ck := range []struct {
				ix     Index
				attrs  uint32
				policy []byte
			}{{Record, Record.Final, t.policy}, {Secret, Secret.Final &^ attrReadLocked, t.policy}, {Counter, Counter.Final, t.pc}} {
				if err := t.checkIndex(ck.ix, ck.attrs, ck.policy); err != nil {
					return "", err
				}
			}
			key, err = t.session(sessP, "encrypt", "tpm2_nvread", Secret.Handle, "-C", Secret.Handle, "-s", strconv.Itoa(Secret.Size), "-P")
			if err != nil {
				return "", fmt.Errorf("reading the volume key from the TPM: %w", err)
			}
			if len(key) != Secret.Size {
				return "", fmt.Errorf("TPM returned %d key bytes", len(key))
			}
			if err := os.WriteFile(c.keyFile(), key, 0o600); err != nil {
				return "", err
			}
			if err := t.attach(varDev); err != nil {
				return "", err
			}
		}
	}
	keys := deriveKeys(key)
	for i := range key {
		key[i] = 0
	}
	if err := os.WriteFile(c.StateKeyFile(), append(append([]byte{}, keys.MAC...), keys.CounterAuth...), 0o400); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s the state volume on %s (role %s, profile %s, epoch %d)", verb, varDev, t.id.Role, t.id.Profile, t.epoch), nil
}

// attach opens the volume with the key file (erased after use), measures the
// volume key into PCR 15 and read-locks the secret.
func (t *tpm) attach(varDev string) error {
	_, attachErr := t.run("/usr/lib/systemd/systemd-cryptsetup", "attach", "var", varDev, t.c.keyFile(),
		"headless=true,keyfile-erase,tpm2-measure-pcr=yes")
	if _, err := t.session(sessP, "", "tpm2_nvreadlock", Secret.Handle, "-C", Secret.Handle, "-P"); err != nil {
		return fmt.Errorf("read-locking the volume key: %w", err)
	}
	return attachErr
}

// provision runs the genuine first boot on a fresh TPM. Order (N1): the
// hierarchies are locked before any index that protects data is defined;
// every later boot that finds a partial state fails closed.
func (t *tpm) provision(f tpmpolicy.File, varDev string) ([]byte, error) {
	if _, err := t.createSalt(false); err != nil {
		return nil, err
	}
	t.pause("salt-created")
	if err := t.defineFresh(Epoch, "pe.bin"); err != nil {
		return nil, err
	}
	if err := t.initEpoch(); err != nil {
		return nil, err
	}
	t.pause("epoch-defined")
	if err := t.authorize(f); err != nil {
		return nil, err
	}
	if err := t.revoke(); err != nil {
		return nil, err
	}
	name, err := t.saltName()
	if err != nil {
		return nil, err
	}
	if err := t.useSalt(name); err != nil {
		return nil, err
	}
	if err := t.lockFresh(); err != nil {
		return nil, err
	}
	t.pause("locked")
	return t.provisionVolume(varDev)
}

func (t *tpm) defineFresh(ix Index, policyFile string) error {
	_, err := t.run("tpm2_nvdefine", ix.Handle, "-C", "o", "-s", strconv.Itoa(ix.Size),
		"-a", fmt.Sprintf("0x%08x", ix.Define), "-L", t.w(policyFile), "-g", "sha256")
	return err
}

// provisionVolume creates S, the LUKS2 volume, the counter and the empty
// state store. The record A is written by Verify (it needs PCR 15).
func (t *tpm) provisionVolume(varDev string) ([]byte, error) {
	if err := t.defineWithPolicy(Secret, "p.bin", ""); err != nil {
		return nil, err
	}
	key := make([]byte, Secret.Size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := t.put("secret.bin", key); err != nil {
		return nil, err
	}
	_, err := t.session(sessP, "decrypt", "tpm2_nvwrite", Secret.Handle, "-C", Secret.Handle, "-i", t.w("secret.bin"), "-P")
	os.Remove(t.w("secret.bin"))
	if err != nil {
		return nil, err
	}
	if _, err := t.session(sessP, "", "tpm2_nvwritelock", Secret.Handle, "-C", Secret.Handle, "-P"); err != nil {
		return nil, err
	}
	t.pause("secret-written")
	if err := os.WriteFile(t.c.keyFile(), key, 0o600); err != nil {
		return nil, err
	}
	if _, err := t.run("cryptsetup", "luksFormat", "--batch-mode", "--type", "luks2",
		"--cipher", "aes-xts-plain64", "--key-size", "512", "--hash", "sha256",
		"--pbkdf", "argon2id", "--integrity", "hmac-sha256", "--label", "enklave-var",
		"--key-file", t.c.keyFile(), varDev); err != nil {
		return nil, err
	}
	tok := fmt.Sprintf(`{"type":"enklave-tpm2-nv","keyslots":["0"],"nv-secret":"%s","nv-record":"%s","nv-counter":"%s","nv-epoch":"%s","salt":"%s","ref":"%s"}`,
		Secret.Handle, Record.Handle, Counter.Handle, Epoch.Handle, SaltHandle, t.id.Ref)
	if err := t.put("token.json", []byte(tok)); err != nil {
		return nil, err
	}
	if _, err := t.run("cryptsetup", "token", "import", "--json-file", t.w("token.json"), "--token-id", "0", varDev); err != nil {
		return nil, err
	}
	t.pause("formatted")
	if err := t.attach(varDev); err != nil {
		return nil, err
	}
	if _, err := t.run("mkfs.ext4", "-q", "-L", "enklave-state", "/dev/mapper/var"); err != nil {
		return nil, err
	}
	keys := deriveKeys(key)
	// The counter's authValue is set with TPM2_NV_ChangeAuth (ADMIN role via
	// the P branch, parameter-encrypted): an authValue passed to
	// NV_DefineSpace under an owner *policy* session does not take effect
	// with tpm2-tools 5.7 (TPM_RC_AUTH_FAIL on first use, reproduced on swtpm).
	if err := t.defineWithPolicy(Counter, "pc.bin", ""); err != nil {
		return nil, err
	}
	if _, err := t.session(sessPC, "decrypt", "tpm2_changeauth", "-c", Counter.Handle, "hex:"+hex.EncodeToString(keys.CounterAuth), "-p"); err != nil {
		return nil, err
	}
	ctr := counterRT{t.r, t.c.work(), keys.CounterAuth}
	if err := ctr.Increment(); err != nil {
		return nil, err
	}
	if err := t.withState(func(root string) error {
		return (&statefs.Store{Root: root, Key: keys.MAC, Counter: ctr}).Init()
	}); err != nil {
		return nil, err
	}
	t.pause("state-initialized")
	if err := os.WriteFile(t.c.ProvisionedFlag(), []byte(strconv.Itoa(t.epoch)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (t *tpm) withState(fn func(root string) error) error {
	mnt := t.c.stateMount()
	if err := os.MkdirAll(mnt, 0o700); err != nil {
		return err
	}
	if _, err := t.run("mount", "-t", "ext4", "-o", "nosuid,nodev,noexec", "/dev/mapper/var", mnt); err != nil {
		return err
	}
	err := fn(mnt)
	if _, uerr := t.run("umount", mnt); err == nil {
		err = uerr
	}
	return err
}

// heal (N4) rotates the hierarchy authorization, replaces the salt key,
// destroys every index that a compromised epoch could have learned (S, A, C)
// and re-provisions an empty state volume with a new key.
func (t *tpm) heal(st tpmState, varDev string) ([]byte, error) {
	if st.pers[handleNum(SaltHandle)] {
		if err := t.owner("", "tpm2_evictcontrol", "-c", SaltHandle); err != nil {
			return nil, err
		}
	}
	name, err := t.createSalt(true)
	if err != nil {
		return nil, err
	}
	if err := t.useSalt(name); err != nil {
		return nil, err
	}
	if err := t.rotate(); err != nil {
		return nil, err
	}
	for _, ix := range []Index{Record, Secret, Counter} {
		if st.nv[handleNum(ix.Handle)] {
			if err := t.owner("", "tpm2_nvundefine", ix.Handle); err != nil {
				return nil, err
			}
		}
	}
	t.pause("healed-tpm")
	if _, err := t.run("cryptsetup", "erase", "--batch-mode", varDev); err != nil {
		// not a LUKS volume any more (interrupted heal): nothing to erase
		if _, lerr := t.r.Run("cryptsetup", "isLuks", varDev); lerr == nil {
			return nil, err
		}
	}
	return t.provisionVolume(varDev)
}

// ---------------------------------------------------------------- verify

// Verify authenticates the opened volume (PCR 15 against record A), checks
// every public area and the hierarchy lock, and verifies the state store
// against its manifest and the TPM counter (anti-rollback, anti-splice).
func Verify(c Config, r Runner) (string, error) {
	defer os.RemoveAll(c.work())
	pcr15, err := ReadPCR(r, 15)
	if err != nil {
		return "", err
	}
	if bytes.Equal(pcr15, zero32) {
		return "", errors.New("PCR 15 is zero: the volume key was not measured")
	}
	if err := RequireCleanPCR12(r); err != nil {
		return "", err
	}
	t, err := newTPM(c, r)
	if err != nil {
		return "", err
	}
	if err := t.prepare(); err != nil {
		return "", err
	}
	f, err := t.cachedPolicy()
	if err != nil {
		return "", err
	}
	if err := t.authorize(f); err != nil {
		return "", err
	}
	h, err := ReadHierarchy(r)
	if err != nil {
		return "", err
	}
	if !h.Locked() {
		return "", fmt.Errorf("TPM hierarchies not locked: %+v", h)
	}
	provisioned, err := exists(c.ProvisionedFlag())
	if err != nil {
		return "", err
	}
	name, err := t.saltName()
	if err != nil {
		return "", err
	}
	if provisioned {
		t.salted = true // salt key created in this boot by Unlock
		if err := t.defineWithPolicy(Record, "p.bin", ""); err != nil {
			return "", err
		}
		rd := RecordData{PCR15: pcr15, Epoch: uint64(t.epoch), SaltName: name}
		if err := t.put("record.bin", rd.bytes()); err != nil {
			return "", err
		}
		if _, err := t.session(sessP, "", "tpm2_nvwrite", Record.Handle, "-C", Record.Handle, "-i", t.w("record.bin"), "-P"); err != nil {
			return "", err
		}
		if _, err := t.session(sessP, "", "tpm2_nvwritelock", Record.Handle, "-C", Record.Handle, "-P"); err != nil {
			return "", err
		}
	}
	b, err := ReadNV(r, Record)
	if err != nil {
		return "", err
	}
	rd, err := ParseRecord(b)
	if err != nil {
		return "", err
	}
	if err := t.useSalt(rd.SaltName); err != nil {
		return "", err
	}
	for _, ck := range []struct {
		ix     Index
		attrs  uint32
		policy []byte
	}{{Record, Record.Final, t.policy}, {Secret, Secret.Final, t.policy}, {Counter, Counter.Final, t.pc}} {
		if err := t.checkIndex(ck.ix, ck.attrs, ck.policy); err != nil {
			return "", err
		}
	}
	if subtle.ConstantTimeCompare(rd.PCR15, pcr15) != 1 {
		return "", fmt.Errorf("volume does not match NV record %s (PCR 15 %x, recorded %x)", Record.Handle, pcr15, rd.PCR15)
	}
	keys, err := LoadStateKeys(c)
	if err != nil {
		return "", err
	}
	var version uint64
	if err := t.withState(func(root string) error {
		var verr error
		version, verr = (&statefs.Store{Root: root, Key: keys.MAC, Counter: counterRT{r, t.c.work(), keys.CounterAuth}}).Verify()
		return verr
	}); err != nil {
		return "", err
	}
	if err := os.WriteFile(c.ResultFile(), []byte(hex.EncodeToString(pcr15)+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(c.CounterFile(), []byte(strconv.FormatUint(version, 10)+"\n"), 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf("state volume verified: record %s (PCR 15 %x, provisioned at epoch %d), state version %d, %s/%s epoch %d, TPM locked",
		Record.Handle, pcr15, rd.Epoch, version, t.id.Role, t.id.Profile, t.epoch), nil
}

// ---------------------------------------------------------------- checks

// CurrentPCR11Policy returns PolicyPCR(sha256:11) for the current PCR 11.
func CurrentPCR11Policy(c Config, r Runner) ([]byte, error) {
	t := &tpm{c: c, r: r}
	if err := os.MkdirAll(c.work(), 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(c.work())
	return t.trial([]string{"tpm2_policypcr", "-l", "sha256:11"})
}

// SignedPCR11Policies returns every signed PCR 11 policy known to this boot
// (systemd's .pcrsig and the enklave approved policy).
func SignedPCR11Policies(pcrsig, cache string) ([]string, error) {
	var out []string
	b, err := os.ReadFile(pcrsig)
	if err != nil {
		return nil, err
	}
	var doc map[string][]struct {
		Pol string `json:"pol"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	for _, e := range doc["sha256"] {
		out = append(out, e.Pol)
	}
	b, err = os.ReadFile(cache)
	if err != nil {
		return nil, err
	}
	var f tpmpolicy.File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	out = append(out, f.PCR11Policy)
	return out, nil
}

// Sealed fails unless PCR 11 has left every signed phase (N7: runs after
// systemd-pcrphase-sysinit, independent of its conditions).
func Sealed(c Config, r Runner, pcrsig string) (string, error) {
	cur, err := CurrentPCR11Policy(c, r)
	if err != nil {
		return "", err
	}
	signed, err := SignedPCR11Policies(pcrsig, c.policyCache())
	if err != nil {
		return "", err
	}
	for _, s := range signed {
		if strings.EqualFold(s, hex.EncodeToString(cur)) {
			return "", fmt.Errorf("PCR 11 still satisfies a signed policy (%s): the sysinit phase was not measured", s)
		}
	}
	return fmt.Sprintf("PCR 11 policy %x matches none of %d signed policies", cur, len(signed)), nil
}

// Probe tries to read the volume key like root in the running system would.
// It returns nil only if the key could be read.
func Probe(c Config, r Runner) error {
	defer os.RemoveAll(c.work())
	t, err := newTPM(c, r)
	if err != nil {
		return err
	}
	if err := t.prepare(); err != nil {
		return err
	}
	f, err := t.cachedPolicy()
	if err != nil {
		return err
	}
	if pcr11, _, err := f.Decode(t.id.Role, t.id.Profile); err == nil {
		t.pcr11 = pcr11 // try the signed state even though PCR 11 moved on
	}
	if err := t.authorize(f); err != nil {
		return err
	}
	_, err = t.session(sessP, "", "tpm2_nvread", Secret.Handle, "-C", Secret.Handle, "-s", strconv.Itoa(Secret.Size), "-P")
	return err
}

// pauseHook is called at a test pause point (overridden in unit tests).
var pauseHook = func(string) { time.Sleep(time.Hour) }

// ReadCounter returns the TPM state counter (selftest).
func ReadCounter(c Config, r Runner) (uint64, error) {
	keys, err := LoadStateKeys(c)
	if err != nil {
		return 0, err
	}
	t, err := newTPM(c, r)
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(c.work())
	if err := t.prepare(); err != nil {
		return 0, err
	}
	return counterRT{r, c.work(), keys.CounterAuth}.Read()
}

// MeasureEvent is one record of systemd's userspace TPM measurement log
// (/run/log/systemd/tpm2-measure.log, JSON-SEQ).
type MeasureEvent struct {
	PCR     int `json:"pcr"`
	Digests []struct {
		HashAlg string `json:"hashAlg"`
		Digest  string `json:"digest"`
	} `json:"digests"`
	Content struct {
		String    string `json:"string"`
		EventType string `json:"eventType"`
	} `json:"content"`
}

// ReplayPCR replays all sha256 events for pcr in a JSON-SEQ measurement log.
func ReplayPCR(log []byte, pcr int) ([]byte, []MeasureEvent, error) {
	v := make([]byte, 32)
	var evs []MeasureEvent
	for _, rec := range bytes.Split(log, []byte{0x1e}) {
		rec = bytes.TrimSpace(rec)
		if len(rec) == 0 {
			continue
		}
		var e MeasureEvent
		if err := json.Unmarshal(rec, &e); err != nil {
			return nil, nil, fmt.Errorf("bad measurement log record: %w", err)
		}
		if e.PCR != pcr {
			continue
		}
		found := false
		for _, d := range e.Digests {
			if d.HashAlg != "sha256" {
				continue
			}
			b, err := hexBytes(d.Digest)
			if err != nil || len(b) != 32 {
				return nil, nil, fmt.Errorf("bad sha256 digest %q", d.Digest)
			}
			s := sha256.Sum256(append(append([]byte{}, v...), b...))
			v, found = s[:], true
		}
		if !found {
			return nil, nil, fmt.Errorf("PCR %d event %q without sha256 digest", pcr, e.Content.String)
		}
		evs = append(evs, e)
	}
	return v, evs, nil
}

// SaltName returns the Name of the persistent salt key (selftest).
func SaltName(c Config, r Runner) ([]byte, error) {
	if err := os.MkdirAll(c.work(), 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(c.work())
	return (&tpm{c: c, r: r}).saltName()
}
