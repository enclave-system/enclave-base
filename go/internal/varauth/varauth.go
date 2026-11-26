// Package varauth authenticates the encrypted /var volume against a
// write-once TPM NV index, so that a LUKS volume made by an attacker (and
// unsealable by this TPM) is never mounted.
//
// Scheme:
//   - systemd-cryptsetup unlocks /var with tpm2-measure-pcr=yes, which extends
//     PCR 15 with a measurement of the volume key. Nothing else extends PCR 15
//     before enklave-varauth runs, so PCR 15 identifies the volume.
//   - On the genuine first boot (systemd-repart created the partition during
//     this boot, see Repart) the NV index must not exist yet. It is defined with
//     a write policy that only this enklave UKI can satisfy in the phase
//     "enter-initrd:leave-initrd": PolicyAuthorize(PCR 11, signed with the PCR
//     signing key embedded in the UKI) followed by PolicyPCR(7). PCR 15 is
//     written and the index is write-locked; TPMA_NV_WRITEDEFINE makes the
//     lock permanent.
//   - On every boot the index public area (attributes, size, nameAlg,
//     authPolicy) and its content are compared with the expectation and the
//     current PCR 15. Any mismatch fails closed.
package varauth

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Runner runs external commands (systemd-repart, tpm2-tools) and returns stdout.
type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

const (
	// Index is the NV index in the owner range (0x01800000-0x01BFFFFF).
	// 0x01800E01: "E" for enklave, 01 for the /var authentication record.
	Index = "0x01800E01"

	// Attributes at definition time:
	// POLICYWRITE | WRITEDEFINE | AUTHREAD | NO_DA.
	// TPMA_NV_POLICY_DELETE is not used: TPM2_NV_DefineSpace only accepts it
	// from the platform hierarchy, which firmware disables before the OS runs.
	AttrsDefine uint32 = 0x00000008 | 0x00002000 | 0x00040000 | 0x02000000
	// AttrsLocked are the attributes once written and write-locked
	// (+ WRITTEN | WRITELOCKED).
	AttrsLocked uint32 = AttrsDefine | 0x20000000 | 0x00000800
	// NVSize is the size of the index: one SHA-256 PCR value.
	NVSize = 32
	// NameAlgSHA256 is TPM_ALG_SHA256.
	NameAlgSHA256 = 0x000B
)

// Config holds the paths used by Repart and Verify.
type Config struct {
	RunDir  string // private state, e.g. /run/enklave (flag + result files)
	WorkDir string // scratch files for tpm2-tools (context, ticket, policy)
	PubKey  string // PCR signing public key from the UKI (.pcrpkey)
	PCRSig  string // signed PCR 11 policies from the UKI (.pcrsig)
}

// DefaultConfig returns the paths used on the image.
func DefaultConfig() Config {
	return Config{
		RunDir:  "/run/enklave",
		WorkDir: "/run/enklave/varauth",
		PubKey:  "/run/systemd/tpm2-pcr-public-key.pem",
		PCRSig:  "/run/systemd/tpm2-pcr-signature.json",
	}
}

// CreatedFlag is written by Repart when systemd-repart created /var in this boot.
func (c Config) CreatedFlag() string { return filepath.Join(c.RunDir, "var-created") }

// ResultFile records the authenticated PCR 15 value (hex) for the selftest.
func (c Config) ResultFile() string { return filepath.Join(c.RunDir, "var-authenticated") }

// Repart runs systemd-repart with args plus --json=short and records whether
// it created the var partition in this boot. Exactly one var partition must
// be reported.
func Repart(c Config, r Runner, args []string) error {
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
	f, err := os.OpenFile(c.CreatedFlag(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// NVPublic is the part of tpm2_nvreadpublic output that is checked.
type NVPublic struct {
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
		t := strings.TrimSpace(line)
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "hash algorithm", "attributes":
			section = k
			continue
		case "value":
			n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(v), "0x"), 16, 32)
			if err != nil {
				return p, fmt.Errorf("bad %s value %q", section, v)
			}
			switch section {
			case "hash algorithm":
				p.NameAlg = uint32(n)
				seen["alg"] = true
			case "attributes":
				p.Attributes = uint32(n)
				seen["attr"] = true
			}
		case "size":
			n, err := strconv.Atoi(v)
			if err != nil {
				return p, fmt.Errorf("bad size %q", v)
			}
			p.Size = n
			seen["size"] = true
		case "authorization policy":
			b, err := hex.DecodeString(v)
			if err != nil {
				return p, fmt.Errorf("bad authorization policy %q", v)
			}
			p.AuthPolicy = b
			seen["policy"] = true
		}
	}
	for _, k := range []string{"alg", "attr", "size", "policy"} {
		if !seen[k] {
			return p, fmt.Errorf("tpm2_nvreadpublic output lacks %s", k)
		}
	}
	return p, nil
}

// CheckPublic compares an index public area with the locked expectation.
// expectPolicy may be nil to skip the authPolicy comparison.
func CheckPublic(p NVPublic, expectPolicy []byte) error {
	switch {
	case p.NameAlg != NameAlgSHA256:
		return fmt.Errorf("NV index nameAlg 0x%x, want sha256", p.NameAlg)
	case p.Size != NVSize:
		return fmt.Errorf("NV index size %d, want %d", p.Size, NVSize)
	case p.Attributes != AttrsLocked:
		return fmt.Errorf("NV index attributes 0x%08x, want 0x%08x (written, write-locked)", p.Attributes, AttrsLocked)
	case expectPolicy != nil && !bytes.Equal(p.AuthPolicy, expectPolicy):
		return fmt.Errorf("NV index authPolicy %x, want %x", p.AuthPolicy, expectPolicy)
	}
	return nil
}

// IndexExists reports whether Index is defined (tpm2_getcap handles-nv-index).
func IndexExists(r Runner) (bool, error) {
	out, err := r.Run("tpm2_getcap", "handles-nv-index")
	if err != nil {
		return false, fmt.Errorf("tpm2_getcap: %w", err)
	}
	want, _ := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(Index), "0x"), 16, 32)
	for _, line := range strings.Split(string(out), "\n") {
		h := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
		if h == "" {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(h), "0x"), 16, 32)
		if err == nil && n == want {
			return true, nil
		}
	}
	return false, nil
}

// ReadNV returns the content of Index (AUTHREAD with empty auth).
func ReadNV(r Runner) ([]byte, error) {
	out, err := r.Run("tpm2_nvread", Index, "-C", Index, "-s", strconv.Itoa(NVSize))
	if err != nil {
		return nil, fmt.Errorf("tpm2_nvread: %w", err)
	}
	if len(out) != NVSize {
		return nil, fmt.Errorf("tpm2_nvread returned %d bytes, want %d", len(out), NVSize)
	}
	return out, nil
}

// ReadPublic returns the parsed public area of Index.
func ReadPublic(r Runner) (NVPublic, error) {
	out, err := r.Run("tpm2_nvreadpublic", Index)
	if err != nil {
		return NVPublic{}, fmt.Errorf("tpm2_nvreadpublic: %w", err)
	}
	return ParseNVPublic(out)
}

// lastDigest extracts the last 64-hex-digit line of a tpm2-tools output.
func lastDigest(out []byte) ([]byte, error) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		s := strings.TrimSpace(lines[i])
		s = strings.TrimPrefix(strings.ToLower(s), "0x")
		if len(s) == 64 {
			if b, err := hex.DecodeString(s); err == nil {
				return b, nil
			}
		}
	}
	return nil, fmt.Errorf("no sha256 digest in output %q", strings.TrimSpace(string(out)))
}

// readPCR15 parses "tpm2_pcrread sha256:15".
func readPCR15(r Runner) ([]byte, error) {
	out, err := r.Run("tpm2_pcrread", "sha256:15")
	if err != nil {
		return nil, fmt.Errorf("tpm2_pcrread: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.TrimSpace(k) == "15" {
			s := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "0x")
			b, err := hex.DecodeString(s)
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("bad PCR 15 value %q", v)
			}
			return b, nil
		}
	}
	return nil, errors.New("PCR 15 missing from tpm2_pcrread output")
}

type session struct {
	c Config
	r Runner
}

func (s session) w(name string) string { return filepath.Join(s.c.WorkDir, name) }

func (s session) run(name string, args ...string) ([]byte, error) {
	out, err := s.r.Run(name, args...)
	if err != nil {
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// loadKey loads the PCR signing public key (owner hierarchy, so that
// TPM2_VerifySignature yields a ticket usable by TPM2_PolicyAuthorize).
func (s session) loadKey() error {
	_, err := s.run("tpm2_loadexternal", "-C", "o", "-G", "rsa", "-u", s.c.PubKey,
		"-c", s.w("key.ctx"), "-n", s.w("key.name"))
	return err
}

// expectedPolicy computes PolicyAuthorize(key) || PolicyPCR(sha256:7) in a
// trial session. The key must be loaded.
func (s session) expectedPolicy() ([]byte, error) {
	if _, err := s.run("tpm2_startauthsession", "-S", s.w("trial.ctx")); err != nil {
		return nil, err
	}
	defer s.r.Run("tpm2_flushcontext", s.w("trial.ctx")) //nolint:errcheck
	if _, err := s.run("tpm2_policyauthorize", "-S", s.w("trial.ctx"), "-n", s.w("key.name")); err != nil {
		return nil, err
	}
	out, err := s.run("tpm2_policypcr", "-S", s.w("trial.ctx"), "-l", "sha256:7")
	if err != nil {
		return nil, err
	}
	return lastDigest(out)
}

// currentPCR11Policy computes PolicyPCR(sha256:11) for the current PCR 11.
func (s session) currentPCR11Policy() ([]byte, error) {
	if _, err := s.run("tpm2_startauthsession", "-S", s.w("trial11.ctx")); err != nil {
		return nil, err
	}
	defer s.r.Run("tpm2_flushcontext", s.w("trial11.ctx")) //nolint:errcheck
	out, err := s.run("tpm2_policypcr", "-S", s.w("trial11.ctx"), "-l", "sha256:11")
	if err != nil {
		return nil, err
	}
	return lastDigest(out)
}

// signatureFor returns the signature over pol from the UKI's .pcrsig.
func signatureFor(path string, pol []byte) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string][]struct {
		PCRs []int  `json:"pcrs"`
		Pol  string `json:"pol"`
		Sig  string `json:"sig"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	want := hex.EncodeToString(pol)
	for _, e := range doc["sha256"] {
		if len(e.PCRs) == 1 && e.PCRs[0] == 11 && strings.EqualFold(e.Pol, want) {
			return base64.StdEncoding.DecodeString(e.Sig)
		}
	}
	return nil, fmt.Errorf("no signed PCR 11 policy for the current phase (%s) in %s", want, path)
}

// policySession starts a policy session satisfying the index write policy.
func (s session) policySession() error {
	steps := [][]string{
		{"tpm2_startauthsession", "--policy-session", "-S", s.w("s.ctx")},
		{"tpm2_policypcr", "-S", s.w("s.ctx"), "-l", "sha256:11"},
		{"tpm2_policyauthorize", "-S", s.w("s.ctx"), "-i", s.w("pol11.bin"), "-n", s.w("key.name"), "-t", s.w("ticket.bin")},
		{"tpm2_policypcr", "-S", s.w("s.ctx"), "-l", "sha256:7"},
	}
	for _, st := range steps {
		if _, err := s.run(st[0], st[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (s session) provision(pcr15, policy []byte) error {
	pol11, err := s.currentPCR11Policy()
	if err != nil {
		return err
	}
	sig, err := signatureFor(s.c.PCRSig, pol11)
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{"pol11.bin": pol11, "sig.bin": sig, "policy.bin": policy, "pcr15.bin": pcr15} {
		if err := os.WriteFile(s.w(name), data, 0o600); err != nil {
			return err
		}
	}
	if _, err := s.run("tpm2_verifysignature", "-c", s.w("key.ctx"), "-g", "sha256", "-m", s.w("pol11.bin"),
		"-s", s.w("sig.bin"), "-f", "rsassa", "-t", s.w("ticket.bin")); err != nil {
		return err
	}
	if _, err := s.run("tpm2_nvdefine", Index, "-C", "o", "-s", strconv.Itoa(NVSize),
		"-a", fmt.Sprintf("0x%08x", AttrsDefine), "-L", s.w("policy.bin"), "-g", "sha256"); err != nil {
		return err
	}
	for _, op := range [][]string{
		{"tpm2_nvwrite", Index, "-i", s.w("pcr15.bin"), "-P", "session:" + s.w("s.ctx")},
		{"tpm2_nvwritelock", Index, "-C", Index, "-P", "session:" + s.w("s.ctx")},
	} {
		if err := s.policySession(); err != nil {
			return err
		}
		_, err := s.run(op[0], op[1:]...)
		s.r.Run("tpm2_flushcontext", s.w("s.ctx")) //nolint:errcheck
		if err != nil {
			return err
		}
	}
	return nil
}

// Verify provisions the NV index on the genuine first boot and then
// authenticates the unlocked /var against it. It returns the decision log
// line on success and a descriptive error on any failure.
func Verify(c Config, r Runner) (string, error) {
	if err := os.MkdirAll(c.WorkDir, 0o700); err != nil {
		return "", err
	}
	defer os.RemoveAll(c.WorkDir)
	s := session{c: c, r: r}

	pcr15, err := readPCR15(r)
	if err != nil {
		return "", err
	}
	if bytes.Equal(pcr15, make([]byte, 32)) {
		return "", errors.New("PCR 15 is zero: the /var volume key was not measured")
	}
	_, ferr := os.Stat(c.CreatedFlag())
	created := ferr == nil
	if ferr != nil && !errors.Is(ferr, os.ErrNotExist) {
		return "", ferr
	}
	exists, err := IndexExists(r)
	if err != nil {
		return "", err
	}
	if err := s.loadKey(); err != nil {
		return "", err
	}
	policy, err := s.expectedPolicy()
	if err != nil {
		return "", err
	}

	action := "verified"
	switch {
	case created && exists:
		return "", fmt.Errorf("NV index %s already exists on the first boot of this /var (pre-defined by someone else?)", Index)
	case !created && !exists:
		return "", fmt.Errorf("NV index %s is missing but /var already existed before this boot", Index)
	case created:
		if err := s.provision(pcr15, policy); err != nil {
			return "", fmt.Errorf("provisioning NV index %s: %w", Index, err)
		}
		action = "provisioned and verified"
	}

	pub, err := ReadPublic(r)
	if err != nil {
		return "", err
	}
	if err := CheckPublic(pub, policy); err != nil {
		return "", err
	}
	nv, err := ReadNV(r)
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare(nv, pcr15) != 1 {
		return "", fmt.Errorf("/var volume does not match NV index %s (PCR 15 %x, recorded %x)", Index, pcr15, nv)
	}
	if err := os.WriteFile(c.ResultFile(), []byte(hex.EncodeToString(pcr15)+"\n"), 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf("/var %s against NV index %s (PCR 15 %x)", action, Index, pcr15), nil
}
