// Package varauth creates, unlocks and authenticates the encrypted /var.
//
// /var is LUKS2 (aes-xts-plain64, 512-bit, argon2id keyslot, hmac-sha256
// integrity). Its 64-byte key S lives in a TPM NV index that can only be read
// with policy P:
//
//	P   = PolicyAuthorize(PCR signing key, tpmpolicy.Ref) || PolicyPCR(7 = current, 12 = clean/zero)
//
// PolicyAuthorize needs a signed approved policy (see package tpmpolicy) that
// binds PCR 11 to the signed UKI's value in the phase enter-initrd:leave-initrd
// and requires the UKI's security epoch to be unrevoked in the epoch index E.
// Hence S is readable only by an unrevoked enklave UKI, under Secure Boot,
// without ESP credentials/addons, before sysinit; it is read-locked right
// after use. All NV indices (record A, secret S, counter C, epoch E) are
// created only on the genuine first boot (systemd-repart created the
// partition during this boot, see Repart); afterwards the owner, lockout and
// endorsement hierarchies get random, discarded authorization values and
// TPM2_Clear is disabled, so the indices cannot be deleted or re-created.
//
// Every boot also checks that PCR 15 (systemd-cryptsetup's volume key
// measurement) equals the write-locked record A, and that the anti-rollback
// file in /var equals the NV counter C (accepting C+1 after a crash between
// the two updates), then advances both.
package varauth

import (
	"bytes"
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

	"enklave.local/base/internal/tpmpolicy"
)

// Runner runs external commands (systemd-repart, cryptsetup, tpm2-tools,
// mount) and returns stdout.
type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

// TPMA_NV bits and NV types used below.
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
)

// Index describes one NV index: handle, size, attributes at definition and
// in the expected steady state.
type Index struct {
	Name   string
	Handle string
	Size   int
	Define uint32
	Final  uint32
}

// The NV indices (owner range 0x01800000-0x01BFFFFF; "E" for enklave).
var (
	// Record: PCR 15 value of the authentic /var, written once and locked.
	Record = Index{"record", "0x01800E01", 32,
		attrPolicyWrite | attrWriteDefine | attrAuthRead | attrNoDA,
		attrPolicyWrite | attrWriteDefine | attrAuthRead | attrNoDA | attrWritten | attrWriteLocked}
	// Secret: the /var LUKS key; write-locked, read-locked after use each boot.
	Secret = Index{"secret", "0x01800E02", 64,
		attrPolicyRead | attrPolicyWrite | attrWriteDefine | attrReadSTClear | attrNoDA,
		attrPolicyRead | attrPolicyWrite | attrWriteDefine | attrReadSTClear | attrNoDA | attrWritten | attrWriteLocked | attrReadLocked}
	// Counter: monotonic anti-rollback counter for /var.
	Counter = Index{"counter", "0x01800E03", 8,
		ntCounter | attrPolicyWrite | attrAuthRead | attrNoDA,
		ntCounter | attrPolicyWrite | attrAuthRead | attrNoDA | attrWritten}
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
	PolicyDir   string // directory with signed approved policies, relative to the ESP root
	RollbackRel string // anti-rollback file, relative to the /var file system
}

// DefaultConfig returns the paths used on the image.
func DefaultConfig() Config {
	return Config{
		RunDir:      "/run/enklave",
		PubKey:      "/run/systemd/tpm2-pcr-public-key.pem",
		PolicyDir:   "EFI/enklave/policy",
		RollbackRel: "lib/enklave/rollback-counter",
	}
}

func (c Config) work() string        { return filepath.Join(c.RunDir, "work") }
func (c Config) espMount() string    { return filepath.Join(c.RunDir, "esp") }
func (c Config) varMount() string    { return filepath.Join(c.RunDir, "varcheck") }
func (c Config) keyFile() string     { return filepath.Join(c.RunDir, "var.key") }
func (c Config) policyCache() string { return filepath.Join(c.RunDir, "policy.json") }
func (c Config) CreatedFlag() string { return filepath.Join(c.RunDir, "var-created") }
func (c Config) ResultFile() string  { return filepath.Join(c.RunDir, "var-authenticated") }
func (c Config) CounterFile() string { return filepath.Join(c.RunDir, "var-counter") }
func (c Config) EpochFile() string   { return filepath.Join(c.RunDir, "epoch") }

// ---------------------------------------------------------------- helpers

func hexBytes(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"))
}

func handleNum(h string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(h), "0x"), 16, 32)
	return n
}

// lastDigest extracts the last 64-hex-digit token of a tpm2-tools output.
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

// ReadPCR returns a sha256 PCR value ("tpm2_pcrread sha256:N").
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

// RequireCleanPCR12 fails unless PCR 12 is all zero: systemd-stub extends it
// only for credentials, addons and command line overrides, none of which a
// genuine enklave boot has.
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

// DefinedIndices returns the defined NV handles (tpm2_getcap handles-nv-index).
func DefinedIndices(r Runner) (map[uint64]bool, error) {
	out, err := r.Run("tpm2_getcap", "handles-nv-index")
	if err != nil {
		return nil, fmt.Errorf("tpm2_getcap: %w", err)
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

// ReadPublic returns the parsed public area of an index.
func ReadPublic(r Runner, ix Index) (NVPublic, error) {
	out, err := r.Run("tpm2_nvreadpublic", ix.Handle)
	if err != nil {
		return NVPublic{}, fmt.Errorf("tpm2_nvreadpublic %s: %w", ix.Handle, err)
	}
	return ParseNVPublic(out)
}

// ReadNV reads an index with AUTHREAD and empty auth.
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

// ReadUint64 reads an 8-byte counter or bits index.
func ReadUint64(r Runner, ix Index) (uint64, error) {
	b, err := ReadNV(r, ix)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// Hierarchy is the TPM_PT_PERMANENT state relevant for the lock-down.
type Hierarchy struct {
	OwnerAuthSet, EndorsementAuthSet, LockoutAuthSet, DisableClear bool
}

// Locked reports whether all hierarchies are protected and Clear is disabled.
func (h Hierarchy) Locked() bool {
	return h.OwnerAuthSet && h.EndorsementAuthSet && h.LockoutAuthSet && h.DisableClear
}

// ReadHierarchy parses "tpm2_getcap properties-variable" (TPM2_PT_PERMANENT).
func ReadHierarchy(r Runner) (Hierarchy, error) {
	out, err := r.Run("tpm2_getcap", "properties-variable")
	if err != nil {
		return Hierarchy{}, fmt.Errorf("tpm2_getcap: %w", err)
	}
	var h Hierarchy
	in, seen := false, 0
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasSuffix(t, ":") && !strings.HasPrefix(line, " ") {
			in = t == "TPM2_PT_PERMANENT:"
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !in || !ok {
			continue
		}
		set := strings.TrimSpace(v) == "1"
		switch k {
		case "ownerAuthSet":
			h.OwnerAuthSet = set
		case "endorsementAuthSet":
			h.EndorsementAuthSet = set
		case "lockoutAuthSet":
			h.LockoutAuthSet = set
		case "disableClear":
			h.DisableClear = set
		default:
			continue
		}
		seen++
	}
	if seen != 4 {
		return h, errors.New("TPM2_PT_PERMANENT flags missing from tpm2_getcap output")
	}
	return h, nil
}

// ---------------------------------------------------------------- sessions

type tpm struct {
	c Config
	r Runner

	pcr11  []byte // current PolicyPCR(sha256:11)
	epoch  int
	ready  bool // key loaded, policies, ticket
	policy []byte
	pe     []byte
}

func (t *tpm) w(name string) string { return filepath.Join(t.c.work(), name) }

func (t *tpm) run(name string, args ...string) ([]byte, error) {
	out, err := t.r.Run(name, args...)
	if err != nil {
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

func (t *tpm) put(name string, data []byte) error {
	return os.WriteFile(t.w(name), data, 0o600)
}

// trial runs steps in a trial session and returns the final digest.
func (t *tpm) trial(steps ...[]string) ([]byte, error) {
	if _, err := t.run("tpm2_startauthsession", "-S", t.w("trial.ctx")); err != nil {
		return nil, err
	}
	defer t.r.Run("tpm2_flushcontext", t.w("trial.ctx")) //nolint:errcheck
	var out []byte
	for _, st := range steps {
		args := append([]string{"-S", t.w("trial.ctx")}, st[1:]...)
		o, err := t.run(st[0], args...)
		if err != nil {
			return nil, err
		}
		out = o
	}
	return lastDigest(out)
}

// prepare loads the PCR key, computes the expected policies and the current
// PCR 11 policy. Signature/ticket handling is done by authorize.
func (t *tpm) prepare() error {
	if err := os.MkdirAll(t.c.work(), 0o700); err != nil {
		return err
	}
	if err := t.put("ref.bin", []byte(tpmpolicy.Ref)); err != nil {
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
	if t.policy, err = t.trial(
		[]string{"tpm2_policyauthorize", "-n", t.w("key.name"), "-q", t.w("ref.bin")},
		[]string{"tpm2_policypcr", "-l", "sha256:7,12", "-f", t.w("pcrvals.bin")},
	); err != nil {
		return err
	}
	b1, err := t.trial([]string{"tpm2_policyauthorize", "-n", t.w("key.name"), "-q", t.w("ref.bin")})
	if err != nil {
		return err
	}
	b2, err := t.trial(
		[]string{"tpm2_policycommandcode", "TPM2_CC_NV_SetBits"},
		[]string{"tpm2_policynvwritten", "c"},
	)
	if err != nil {
		return err
	}
	if err := t.put("b1.bin", b1); err != nil {
		return err
	}
	if err := t.put("b2.bin", b2); err != nil {
		return err
	}
	if t.pe, err = t.trial([]string{"tpm2_policyor", "-l", "sha256:" + t.w("b1.bin") + "," + t.w("b2.bin")}); err != nil {
		return err
	}
	if t.pcr11, err = t.trial([]string{"tpm2_policypcr", "-l", "sha256:11"}); err != nil {
		return err
	}
	return nil
}

// ExpectedPolicies returns P (for A, S, C) and P_E (for E) for this boot.
func ExpectedPolicies(c Config, r Runner) (p, pe []byte, err error) {
	t := &tpm{c: c, r: r}
	defer os.RemoveAll(c.work())
	if err := t.prepare(); err != nil {
		return nil, nil, err
	}
	return t.policy, t.pe, nil
}

// selectPolicy reads the signed approved policies from the ESP and returns
// the one for the running UKI (matching the current PCR 11 policy).
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
	if err := json.Unmarshal(b, &f); err != nil {
		return f, err
	}
	if !strings.EqualFold(f.PCR11Policy, hex.EncodeToString(t.pcr11)) {
		return f, errors.New("cached approved policy does not belong to the running UKI")
	}
	return f, nil
}

// authorize checks E, recomputes the approved digest for the policy file and
// obtains the TPM ticket for its signature.
func (t *tpm) authorize(f tpmpolicy.File) error {
	pcr11, approved, err := f.Decode()
	if err != nil {
		return err
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
		"approved.bin": approved, "msg.bin": tpmpolicy.SignedMessage(approved), "sig.bin": sig, "epochop.bin": op,
	} {
		if err := t.put(name, data); err != nil {
			return err
		}
	}
	if _, err := t.run("tpm2_verifysignature", "-c", t.w("key.ctx"), "-g", "sha256", "-m", t.w("msg.bin"),
		"-s", t.w("sig.bin"), "-f", "rsassa", "-t", t.w("ticket.bin")); err != nil {
		return fmt.Errorf("approved policy signature rejected: %w", err)
	}
	t.epoch, t.ready = f.Epoch, true
	return nil
}

// session starts a policy session satisfying P (final = "pcr") or P_E
// (final = "or"), runs cmd with it and flushes it.
func (t *tpm) session(final string, cmd ...string) ([]byte, error) {
	if !t.ready {
		return nil, errors.New("policy not authorized")
	}
	s := t.w("s.ctx")
	steps := [][]string{
		{"tpm2_startauthsession", "--policy-session", "-S", s},
		{"tpm2_policypcr", "-S", s, "-l", "sha256:11"},
		{"tpm2_policynv", "-S", s, "-i", t.w("epochop.bin"), Epoch.Handle, "bc"},
		{"tpm2_policyauthorize", "-S", s, "-i", t.w("approved.bin"), "-q", t.w("ref.bin"), "-n", t.w("key.name"), "-t", t.w("ticket.bin")},
	}
	switch final {
	case "pcr":
		steps = append(steps, []string{"tpm2_policypcr", "-S", s, "-l", "sha256:7,12", "-f", t.w("pcrvals.bin")})
	case "or":
		steps = append(steps, []string{"tpm2_policyor", "-S", s, "-l", "sha256:" + t.w("b1.bin") + "," + t.w("b2.bin")})
	}
	defer t.r.Run("tpm2_flushcontext", s) //nolint:errcheck
	for _, st := range steps {
		if _, err := t.run(st[0], st[1:]...); err != nil {
			return nil, err
		}
	}
	return t.run(cmd[0], append(cmd[1:], "-P", "session:"+s)...)
}

func (t *tpm) define(ix Index, policy string) error {
	_, err := t.run("tpm2_nvdefine", ix.Handle, "-C", "o", "-s", strconv.Itoa(ix.Size),
		"-a", fmt.Sprintf("0x%08x", ix.Define), "-L", t.w(policy), "-g", "sha256")
	return err
}

// initEpoch writes E for the first time through the PolicyNvWritten(NO) branch.
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

// revoke sets the bits of all older epochs and refuses a revoked epoch.
func (t *tpm) revoke() error {
	v, err := ReadUint64(t.r, Epoch)
	if err != nil {
		return err
	}
	if v&(uint64(1)<<uint(t.epoch)) != 0 {
		return fmt.Errorf("security epoch %d of this UKI is revoked (E = 0x%x)", t.epoch, v)
	}
	mask := tpmpolicy.RevokeMask(t.epoch)
	if v&mask == mask {
		return nil
	}
	_, err = t.session("or", "tpm2_nvsetbits", Epoch.Handle, "-C", Epoch.Handle, "-i", fmt.Sprintf("0x%x", mask))
	return err
}

func (t *tpm) checkIndex(ix Index, attrs uint32, policy []byte) error {
	pub, err := ReadPublic(t.r, ix)
	if err != nil {
		return err
	}
	return CheckPublic(ix, pub, attrs, policy)
}

// ---------------------------------------------------------------- repart

// Repart runs systemd-repart with args plus --json=short after checking that
// PCR 12 is clean, and records whether it created the var partition.
func Repart(c Config, r Runner, args []string) error {
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
	if err := os.MkdirAll(c.RunDir, 0o700); err != nil {
		return err
	}
	fh, err := os.OpenFile(c.CreatedFlag(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return fh.Close()
}

func created(c Config) (bool, error) {
	_, err := os.Stat(c.CreatedFlag())
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// ---------------------------------------------------------------- unlock

// Unlock opens /var (varDev) as /dev/mapper/var. On the genuine first boot it
// creates the LUKS2 volume and the NV indices; otherwise it reads the key
// from the TPM. The key is read-locked in the TPM afterwards.
func Unlock(c Config, r Runner, varDev, espDev string) (string, error) {
	if err := os.MkdirAll(c.RunDir, 0o700); err != nil {
		return "", err
	}
	defer os.Remove(c.keyFile())
	defer os.RemoveAll(c.work())
	if err := RequireCleanPCR12(r); err != nil {
		return "", err
	}
	first, err := created(c)
	if err != nil {
		return "", err
	}
	t := &tpm{c: c, r: r}
	if err := t.prepare(); err != nil {
		return "", err
	}
	f, err := t.selectPolicy(espDev)
	if err != nil {
		return "", err
	}
	defined, err := DefinedIndices(r)
	if err != nil {
		return "", err
	}

	var key []byte
	if first {
		for _, ix := range allIndices {
			if defined[handleNum(ix.Handle)] {
				return "", fmt.Errorf("NV %s %s already exists on the first boot of this /var (pre-defined by someone else?)", ix.Name, ix.Handle)
			}
		}
		if _, err := r.Run("cryptsetup", "isLuks", varDev); err == nil {
			return "", fmt.Errorf("%s already carries a LUKS header on the first boot", varDev)
		}
		h, err := ReadHierarchy(r)
		if err != nil {
			return "", err
		}
		if h.OwnerAuthSet || h.LockoutAuthSet {
			return "", errors.New("TPM owner/lockout authorization already set on the first boot (not a fresh TPM)")
		}
		if err := t.put("pe.bin", t.pe); err != nil {
			return "", err
		}
		if err := t.put("p.bin", t.policy); err != nil {
			return "", err
		}
		if err := t.define(Epoch, "pe.bin"); err != nil {
			return "", err
		}
		if err := t.initEpoch(); err != nil {
			return "", err
		}
	} else if !defined[handleNum(Secret.Handle)] || !defined[handleNum(Epoch.Handle)] {
		return "", errors.New("NV secret/epoch index missing but /var already existed before this boot")
	}

	if err := t.authorize(f); err != nil {
		return "", err
	}
	if err := t.revoke(); err != nil {
		return "", err
	}

	if first {
		key = make([]byte, Secret.Size)
		if _, err := rand.Read(key); err != nil {
			return "", err
		}
		if err := os.WriteFile(c.keyFile(), key, 0o600); err != nil {
			return "", err
		}
		if _, err := t.run("cryptsetup", "luksFormat", "--batch-mode", "--type", "luks2",
			"--cipher", "aes-xts-plain64", "--key-size", "512", "--hash", "sha256",
			"--pbkdf", "argon2id", "--integrity", "hmac-sha256", "--label", "enklave-var",
			"--key-file", c.keyFile(), varDev); err != nil {
			return "", err
		}
		tok := fmt.Sprintf(`{"type":"enklave-tpm2-nv","keyslots":["0"],"nv-secret":"%s","nv-record":"%s","nv-counter":"%s","nv-epoch":"%s"}`,
			Secret.Handle, Record.Handle, Counter.Handle, Epoch.Handle)
		if err := t.put("token.json", []byte(tok)); err != nil {
			return "", err
		}
		if _, err := t.run("cryptsetup", "token", "import", "--json-file", t.w("token.json"), "--token-id", "0", varDev); err != nil {
			return "", err
		}
		if err := t.define(Secret, "p.bin"); err != nil {
			return "", err
		}
		if err := t.put("secret.bin", key); err != nil {
			return "", err
		}
		if _, err := t.session("pcr", "tpm2_nvwrite", Secret.Handle, "-C", Secret.Handle, "-i", t.w("secret.bin")); err != nil {
			return "", err
		}
		os.Remove(t.w("secret.bin"))
		if _, err := t.session("pcr", "tpm2_nvwritelock", Secret.Handle, "-C", Secret.Handle); err != nil {
			return "", err
		}
	} else {
		if err := t.checkIndex(Secret, Secret.Final&^attrReadLocked, t.policy); err != nil {
			return "", err
		}
		key, err = t.session("pcr", "tpm2_nvread", Secret.Handle, "-C", Secret.Handle, "-s", strconv.Itoa(Secret.Size))
		if err != nil {
			return "", fmt.Errorf("reading the /var key from the TPM: %w", err)
		}
		if len(key) != Secret.Size {
			return "", fmt.Errorf("TPM returned %d key bytes", len(key))
		}
		if err := os.WriteFile(c.keyFile(), key, 0o600); err != nil {
			return "", err
		}
	}

	// keyfile-erase removes the key file after use; volume key measured into PCR 15.
	_, attachErr := t.run("/usr/lib/systemd/systemd-cryptsetup", "attach", "var", varDev, c.keyFile(),
		"headless=true,keyfile-erase,tpm2-measure-pcr=yes")
	for i := range key {
		key[i] = 0
	}
	if _, err := t.session("pcr", "tpm2_nvreadlock", Secret.Handle, "-C", Secret.Handle); err != nil {
		return "", fmt.Errorf("read-locking the /var key: %w", err)
	}
	if attachErr != nil {
		return "", attachErr
	}
	if first {
		if _, err := t.run("mkfs.ext4", "-q", "-L", "var", "/dev/mapper/var"); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(c.EpochFile(), []byte(strconv.Itoa(t.epoch)+"\n"), 0o600); err != nil {
		return "", err
	}
	if first {
		return fmt.Sprintf("created and opened /var on %s (epoch %d)", varDev, t.epoch), nil
	}
	return fmt.Sprintf("opened /var on %s with the TPM-held key (epoch %d)", varDev, t.epoch), nil
}

// ---------------------------------------------------------------- verify

// Verify authenticates the opened /var (PCR 15 record), enforces the
// anti-rollback counter, checks every NV index and locks the TPM hierarchies.
func Verify(c Config, r Runner) (string, error) {
	defer os.RemoveAll(c.work())
	pcr15, err := ReadPCR(r, 15)
	if err != nil {
		return "", err
	}
	if bytes.Equal(pcr15, zero32) {
		return "", errors.New("PCR 15 is zero: the /var volume key was not measured")
	}
	if err := RequireCleanPCR12(r); err != nil {
		return "", err
	}
	first, err := created(c)
	if err != nil {
		return "", err
	}
	t := &tpm{c: c, r: r}
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
	defined, err := DefinedIndices(r)
	if err != nil {
		return "", err
	}

	if first {
		if defined[handleNum(Record.Handle)] || defined[handleNum(Counter.Handle)] {
			return "", errors.New("NV record/counter index already exists on the first boot")
		}
		if err := t.put("p.bin", t.policy); err != nil {
			return "", err
		}
		if err := t.define(Record, "p.bin"); err != nil {
			return "", err
		}
		if err := t.put("pcr15.bin", pcr15); err != nil {
			return "", err
		}
		if _, err := t.session("pcr", "tpm2_nvwrite", Record.Handle, "-C", Record.Handle, "-i", t.w("pcr15.bin")); err != nil {
			return "", err
		}
		if _, err := t.session("pcr", "tpm2_nvwritelock", Record.Handle, "-C", Record.Handle); err != nil {
			return "", err
		}
		if err := t.define(Counter, "p.bin"); err != nil {
			return "", err
		}
		if _, err := t.session("pcr", "tpm2_nvincrement", Counter.Handle, "-C", Counter.Handle); err != nil {
			return "", err
		}
	} else if !defined[handleNum(Record.Handle)] || !defined[handleNum(Counter.Handle)] {
		return "", errors.New("NV record/counter index missing but /var already existed before this boot")
	}

	for _, ix := range []Index{Record, Secret, Counter} {
		if err := t.checkIndex(ix, ix.Final, t.policy); err != nil {
			return "", err
		}
	}
	nv, err := ReadNV(r, Record)
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare(nv, pcr15) != 1 {
		return "", fmt.Errorf("/var volume does not match NV record %s (PCR 15 %x, recorded %x)", Record.Handle, pcr15, nv)
	}

	ctr, err := t.rollback(first)
	if err != nil {
		return "", err
	}

	h, err := ReadHierarchy(r)
	if err != nil {
		return "", err
	}
	if !h.Locked() {
		// First boot, or a first boot interrupted after provisioning: every
		// index has just been verified, so finish the lock-down now.
		if err := lockHierarchies(r, h); err != nil {
			return "", err
		}
		if h, err = ReadHierarchy(r); err != nil {
			return "", err
		}
		if !h.Locked() {
			return "", fmt.Errorf("TPM hierarchies not locked: %+v", h)
		}
	}

	if err := os.WriteFile(c.ResultFile(), []byte(hex.EncodeToString(pcr15)+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(c.CounterFile(), []byte(strconv.FormatUint(ctr, 10)+"\n"), 0o600); err != nil {
		return "", err
	}
	verb := "verified"
	if first {
		verb = "provisioned and verified"
	}
	return fmt.Sprintf("/var %s: NV record %s (PCR 15 %x), rollback counter %d, epoch %d, TPM hierarchies locked",
		verb, Record.Handle, pcr15, ctr, t.epoch), nil
}

// rollback enforces file value F == counter C (or C+1 after an interrupted
// update), then advances F and C by one. It returns the final counter.
func (t *tpm) rollback(first bool) (uint64, error) {
	mnt := t.c.varMount()
	if err := os.MkdirAll(mnt, 0o700); err != nil {
		return 0, err
	}
	if _, err := t.run("mount", "-t", "ext4", "-o", "nosuid,nodev,noexec", "/dev/mapper/var", mnt); err != nil {
		return 0, err
	}
	umounted := false
	defer func() {
		if !umounted {
			t.r.Run("umount", mnt) //nolint:errcheck
		}
	}()
	path := filepath.Join(mnt, t.c.RollbackRel)
	cval, err := ReadUint64(t.r, Counter)
	if err != nil {
		return 0, err
	}
	var fval uint64
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if fval, err = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err != nil {
			return 0, fmt.Errorf("bad rollback file: %w", err)
		}
	case errors.Is(err, os.ErrNotExist) && first:
		fval = cval
	case errors.Is(err, os.ErrNotExist):
		return 0, errors.New("anti-rollback file missing in an existing /var")
	default:
		return 0, err
	}
	switch {
	case fval == cval:
	case fval == cval+1: // crash between writing F and incrementing C
		if _, err := t.session("pcr", "tpm2_nvincrement", Counter.Handle, "-C", Counter.Handle); err != nil {
			return 0, err
		}
		cval++
	case fval < cval:
		return 0, fmt.Errorf("/var ROLLBACK detected: /var counter %d < TPM counter %d (old snapshot?)", fval, cval)
	default:
		return 0, fmt.Errorf("/var counter %d ahead of TPM counter %d", fval, cval)
	}
	if err := writeDurable(path, []byte(strconv.FormatUint(cval+1, 10)+"\n")); err != nil {
		return 0, err
	}
	if _, err := t.session("pcr", "tpm2_nvincrement", Counter.Handle, "-C", Counter.Handle); err != nil {
		return 0, err
	}
	if after, err := ReadUint64(t.r, Counter); err != nil || after != cval+1 {
		return 0, fmt.Errorf("TPM counter did not advance to %d (%d, %v)", cval+1, after, err)
	}
	if _, err := t.run("umount", mnt); err != nil {
		return 0, err
	}
	umounted = true
	return cval + 1, nil
}

func writeDurable(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// lockHierarchies disables TPM2_Clear and sets random, discarded
// authorization values for lockout, owner and endorsement.
func lockHierarchies(r Runner, h Hierarchy) error {
	if !h.DisableClear {
		if _, err := r.Run("tpm2_clearcontrol", "-C", "l", "s"); err != nil {
			return fmt.Errorf("tpm2_clearcontrol: %w", err)
		}
	}
	for _, hi := range []struct {
		set  bool
		name string
	}{{h.LockoutAuthSet, "l"}, {h.OwnerAuthSet, "o"}, {h.EndorsementAuthSet, "e"}} {
		if hi.set {
			continue
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		if _, err := r.Run("tpm2_changeauth", "-c", hi.name, "hex:"+hex.EncodeToString(b)); err != nil {
			return fmt.Errorf("tpm2_changeauth -c %s: %w", hi.name, err)
		}
		for i := range b {
			b[i] = 0
		}
	}
	return nil
}

// CurrentPCR11Policy returns PolicyPCR(sha256:11) for the current PCR 11.
func CurrentPCR11Policy(c Config, r Runner) ([]byte, error) {
	t := &tpm{c: c, r: r}
	if err := os.MkdirAll(c.work(), 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(c.work())
	return t.trial([]string{"tpm2_policypcr", "-l", "sha256:11"})
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

// ReplayPCR replays all sha256 events for pcr in a JSON-SEQ measurement log
// and returns the resulting value plus the events in order.
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

// Probe tries to read the /var key the way an attacker with root in the
// running system would (authorized policy session with the UKI's signed
// approved policy). It returns nil only if the key could be read, which must
// never happen after unlock (PCR 11 has left the signed phase and the index
// is read-locked).
func Probe(c Config, r Runner) error {
	defer os.RemoveAll(c.work())
	t := &tpm{c: c, r: r}
	if err := t.prepare(); err != nil {
		return err
	}
	b, err := os.ReadFile(c.policyCache())
	if err != nil {
		return err
	}
	var f tpmpolicy.File
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	// Use the signed policy even though PCR 11 no longer matches it.
	if pcr11, _, err := f.Decode(); err == nil {
		t.pcr11 = pcr11
	}
	if err := t.authorize(f); err != nil {
		return err
	}
	_, err = t.session("pcr", "tpm2_nvread", Secret.Handle, "-C", Secret.Handle, "-s", strconv.Itoa(Secret.Size))
	return err
}
