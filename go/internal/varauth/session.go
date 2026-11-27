package varauth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"enclave.local/base/internal/ekcert"
	"enclave.local/base/internal/tpmpolicy"
)

// PCR selections of the PCR-bound part of policy P.
const (
	selSteady = "sha256:7,12" // exact Secure Boot state, no ESP credentials

	modeSteady = "steady"
	modeBridge = "transition"
)

var pcrsSteady = []int{7, 12}

type tpm struct {
	c  Config
	r  Runner
	id Identity

	// policy is P; plit is the PCR-bound digest of this boot (PolicyAuthorize
	// + PolicyPCR(7,12)): V holds it, or, while a signed Secure Boot update is
	// in transit, a PolicyOR over a list of such digests that includes it
	// (branches). b1 is V's authPolicy.
	pcr11, policy, pe, pc, b1, plit []byte
	branches                        [][]byte
	// test profile only: skip the software checks of a pending transition,
	// to show that the TPM refuses on its own (G3 proof)
	skipBridgeCheck bool
	epoch           int
	ready           bool
	mode            string      // which digest V holds (pcrMode)
	salt            *ekcert.Key // authenticated salt key
	saltSource      string
	pauseAt         string

	ref      string                    // policyRef of this device (setRef)
	av       []byte                    // PolicyAuthValue digest
	files    map[string]tpmpolicy.File // signed policies of the running UKI by ref (ESP)
	raw      map[string][]byte
	accepted []certifiedEK // vendor-certified endorsement keys this boot accepts
	ekName   []byte        // Name of the authenticated endorsement key
	ekAlgs   []ekcert.Alg  // its algorithm (both when only the Name is known)
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
	msg := "enclave-varauth: TEST PAUSE at " + step + "\n"
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

// pcrValues reads the given PCRs and writes their concatenation.
func (t *tpm) pcrValues(file string, pcrs []int) error {
	var vals []byte
	for _, n := range pcrs {
		v, err := ReadPCR(t.r, n)
		if err != nil {
			return err
		}
		vals = append(vals, v...)
	}
	return t.put(file, vals)
}

// prepare loads the PCR key and computes what does not depend on the
// policyRef. setRef completes it once the device's ref is known.
func (t *tpm) prepare() error {
	if err := os.MkdirAll(t.c.work(), 0o700); err != nil {
		return err
	}
	if _, err := t.run("tpm2_loadexternal", "-C", "o", "-G", "rsa", "-u", t.c.PubKey,
		"-c", t.w("key.ctx"), "-n", t.w("key.name")); err != nil {
		return err
	}
	if err := t.pcrValues("pcrs-steady.bin", pcrsSteady); err != nil {
		return err
	}
	b2, err := t.trial([]string{"tpm2_policycommandcode", "TPM2_CC_NV_SetBits"}, []string{"tpm2_policynvwritten", "c"})
	if err != nil {
		return err
	}
	if t.av, err = t.trial([]string{"tpm2_policyauthvalue"}); err != nil {
		return err
	}
	if err := t.put("b2.bin", b2); err != nil {
		return err
	}
	if err := t.put("av.bin", t.av); err != nil {
		return err
	}
	t.pcr11, err = t.trial([]string{"tpm2_policypcr", "-l", "sha256:11"})
	return err
}

// setRef computes the policies for a policyRef: the base ref of role and
// profile, or the per-device ref of an admitted endorsement key. Everything
// that depends on the Name of index V is computed locally.
func (t *tpm) setRef(ref string) error {
	t.ref = ref
	if err := t.put("ref.bin", []byte(ref)); err != nil {
		return err
	}
	auth := []string{"tpm2_policyauthorize", "-n", t.w("key.name"), "-q", t.w("ref.bin")}
	var err error
	if t.plit, err = t.trial(auth, []string{"tpm2_policypcr", "-l", selSteady, "-f", t.w("pcrs-steady.bin")}); err != nil {
		return err
	}
	if t.b1, err = t.trial(auth); err != nil {
		return err
	}
	vName := tpmpolicy.NVName(uint32(handleNum(PCRPolicy.Handle)), PCRPolicy.Final, t.b1, PCRPolicy.Size)
	t.policy = tpmpolicy.PolicyAuthorizeNV(vName)
	// Counter admin branch: NV_ChangeAuth needs the ADMIN role, which requires
	// PolicyCommandCode in the session.
	pca := tpmpolicy.PolicyCommandCode(t.policy, tpmpolicy.CCNVChangeAuth)
	t.pc = tpmpolicy.PolicyOR(pca, t.av)
	for n, d := range map[string][]byte{
		"p.bin": t.policy, "b1.bin": t.b1, "pca.bin": pca, "pc.bin": t.pc,
		"v-steady.bin": tpmpolicy.DigestNV(t.plit),
	} {
		if err := t.put(n, d); err != nil {
			return err
		}
	}
	if t.pe, err = t.trial([]string{"tpm2_policyor", "-l", "sha256:" + t.w("b1.bin") + "," + t.w("b2.bin")}); err != nil {
		return err
	}
	return t.put("pe.bin", t.pe)
}

// Policies are the expected policy digests for this boot.
type Policies struct {
	P, PE, PC []byte // hierarchies/A/S, epoch index, counter
	VAuth     []byte // authPolicy of index V (binds its Name)
	Steady    []byte // content of V for the Secure Boot state of this boot
}

// ExpectedPolicies returns the policies of this boot for this device (its
// policyRef follows from how its endorsement key is authenticated).
func ExpectedPolicies(c Config, r Runner) (Policies, error) {
	t, err := newTPM(c, r)
	if err != nil {
		return Policies{}, err
	}
	defer os.RemoveAll(c.work())
	if err := t.prepare(); err != nil {
		return Policies{}, err
	}
	if err := t.runtimeEK(); err != nil {
		return Policies{}, err
	}
	return Policies{t.policy, t.pe, t.pc, t.b1, tpmpolicy.DigestNV(t.plit)}, nil
}

// PCRBinding checks index V and describes what it binds (selftest).
func PCRBinding(c Config, r Runner) (string, error) {
	t, err := newTPM(c, r)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(c.work())
	if err := t.prepare(); err != nil {
		return "", err
	}
	if err := t.runtimeEK(); err != nil {
		return "", err
	}
	if err := t.pcrMode(); err != nil {
		return "", err
	}
	if t.mode == modeBridge {
		return fmt.Sprintf("PCR 7+12, one of %d exact Secure Boot states (signed variable update pending)", len(t.branches)), nil
	}
	return "PCR 7+12", nil
}

// loadPolicies reads every signed approved policy for the running UKI from
// the ESP (the base policy and per-device admissions), keyed by policyRef,
// and the test hooks (test profile only). The ESP is unauthenticated; each
// policy is verified by the TPM when it is used.
func (t *tpm) loadPolicies(espDev string) error {
	if err := os.MkdirAll(t.c.espMount(), 0o700); err != nil {
		return err
	}
	// Not "ro": systemd-boot-random-seed may already have mounted the ESP
	// read-write via the /efi automount, and a read-only second mount of the
	// same superblock fails with EBUSY. Nothing is written.
	if _, err := t.run("mount", "-t", "vfat", "-o", "nosuid,nodev,noexec,umask=077", espDev, t.c.espMount()); err != nil {
		return err
	}
	defer t.r.Run("umount", t.c.espMount()) //nolint:errcheck
	if t.id.Profile == "test" {
		if b, err := os.ReadFile(filepath.Join(t.c.espMount(), "EFI/enclave/test-pause")); err == nil {
			t.pauseAt = strings.TrimSpace(string(b))
			// Verify runs as a separate process (test profile only)
			if err := os.WriteFile(filepath.Join(t.c.RunDir, "test-pause"), b, 0o600); err != nil {
				return err
			}
		}
		if _, err := os.Stat(filepath.Join(t.c.espMount(), "EFI/enclave/test-skip-bridge-check")); err == nil {
			t.skipBridgeCheck = true
		}
		// models firmware whose event log is unusable (B7 proof)
		if _, err := os.Stat(filepath.Join(t.c.espMount(), "EFI/enclave/test-no-eventlog")); err == nil {
			t.c.EventLog = filepath.Join(t.c.RunDir, "test-no-eventlog")
		}
	}
	if err := t.copyEKCerts(); err != nil {
		return err
	}
	files, _ := filepath.Glob(filepath.Join(t.c.espMount(), t.c.PolicyDir, "*.json"))
	sort.Strings(files)
	want := hex.EncodeToString(t.pcr11)
	t.files = map[string]tpmpolicy.File{}
	t.raw = map[string][]byte{}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cand tpmpolicy.File
		if json.Unmarshal(b, &cand) == nil && strings.EqualFold(cand.PCR11Policy, want) {
			if _, dup := t.files[cand.Ref]; !dup {
				t.files[cand.Ref], t.raw[cand.Ref] = cand, b
			}
		}
	}
	if len(t.files) == 0 {
		return fmt.Errorf("no signed approved policy for the running UKI (PCR 11 policy %s) in ESP:/%s", want, t.c.PolicyDir)
	}
	return nil
}

// EKCertDir is where EK certificates fetched from the TPM vendor are placed
// on the ESP (G5), for TPMs that do not carry their certificate in NV
// (Intel PTT and AMD fTPM publish it through a web service keyed by the EK).
const EKCertDir = "EFI/enclave/ekcert"

// copyEKCerts copies those certificates to /run for the later steps of this
// boot. They are untrusted input: only the vendor signature counts.
func (t *tpm) copyEKCerts() error {
	dst := t.c.ekCertDir()
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	files, _ := filepath.Glob(filepath.Join(t.c.espMount(), EKCertDir, "*"))
	sort.Strings(files)
	for i, p := range files {
		if i >= 256 {
			break
		}
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() || fi.Size() > 16<<10 {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dst, fmt.Sprintf("%03d-%s", i, filepath.Base(p))), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// policy returns the signed policy for the device's policyRef and caches it
// for the later steps of this boot.
func (t *tpm) selectedPolicy() (tpmpolicy.File, error) {
	f, ok := t.files[t.ref]
	if !ok {
		return f, fmt.Errorf("no signed approved policy for policyRef %q of the running UKI in ESP:/%s", t.ref, t.c.PolicyDir)
	}
	return f, os.WriteFile(t.c.policyCache(), t.raw[t.ref], 0o600)
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
	if t.ref == "" {
		return errors.New("policyRef of this device not determined")
	}
	pcr11, approved, err := f.DecodeRef(t.id.Role, t.id.Profile, t.ref)
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
		"approved.bin": approved, "msg.bin": tpmpolicy.SignedMessage(approved, t.ref), "sig.bin": sig, "epochop.bin": op,
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

// pcrMode checks index V and finds out what it holds: the Secure Boot state
// of this boot (steady), or the branch list of a signed Secure Boot update
// in transit that includes the state of this boot. Anything else is a
// foreign Secure Boot configuration and fails closed. The TPM enforces the
// same on its own: no session of another PCR 7 value satisfies V.
func (t *tpm) pcrMode() error {
	if err := t.checkIndex(PCRPolicy, PCRPolicy.Final, t.b1); err != nil {
		return err
	}
	v, err := ReadNV(t.r, PCRPolicy)
	if err != nil {
		return err
	}
	if bytes.Equal(v, tpmpolicy.DigestNV(t.plit)) {
		t.mode, t.branches = modeSteady, nil
		return nil
	}
	ts, err := t.readTransition()
	if err != nil {
		return err
	}
	for _, l := range [][][]byte{ts.next, ts.cur} {
		if len(l) < 2 || !bytes.Equal(v, tpmpolicy.DigestNV(tpmpolicy.PolicyOR(l...))) {
			continue
		}
		in := false
		for _, b := range l {
			in = in || bytes.Equal(b, t.plit)
		}
		if !in && !t.skipBridgeCheck {
			return fmt.Errorf("PCR policy index %s holds the %d Secure Boot states of a signed variable update in transit, and the state of this boot (PCR 7+12: %x) is none of them; "+
				"the Secure Boot configuration changed without a signed update", PCRPolicy.Handle, len(l), t.plit)
		}
		return t.setBranches(l)
	}
	return fmt.Errorf("PCR policy index %s holds %x: neither the Secure Boot state of this boot (PCR 7+12: %x) "+
		"nor a signed variable update in transit; "+
		"the Secure Boot configuration changed without a signed update",
		PCRPolicy.Handle, v[2:], t.plit)
}

func (t *tpm) setBranches(l [][]byte) error {
	for i, b := range l {
		if err := t.put(fmt.Sprintf("or-%d.bin", i), b); err != nil {
			return err
		}
	}
	t.mode, t.branches = modeBridge, l
	return nil
}

// orList is the -l argument of tpm2_policyor for the branch list.
func (t *tpm) orList() string {
	var f []string
	for i := range t.branches {
		f = append(f, t.w(fmt.Sprintf("or-%d.bin", i)))
	}
	return "sha256:" + strings.Join(f, ",")
}

// writeSteady binds index V to the Secure Boot state of this boot alone
// (through the owner hierarchy, policy P).
func (t *tpm) writeSteady() error {
	if err := t.writeIndex(PCRPolicy, "v-steady.bin"); err != nil {
		return err
	}
	t.mode, t.branches = modeSteady, nil
	return nil
}

// writeBridge binds index V to a list of exact Secure Boot states, the
// first of which is the state of this boot.
func (t *tpm) writeBridge(l [][]byte) error {
	if len(l) < 2 || len(l) > maxBranches {
		return fmt.Errorf("a transition needs 2 to %d Secure Boot states, got %d", maxBranches, len(l))
	}
	if err := t.put("v-or.bin", tpmpolicy.DigestNV(tpmpolicy.PolicyOR(l...))); err != nil {
		return err
	}
	if err := t.writeIndex(PCRPolicy, "v-or.bin"); err != nil {
		return err
	}
	return t.setBranches(l)
}

// writeIndex rewrites an owner-written index (V or T) under policy P.
func (t *tpm) writeIndex(ix Index, file string) error {
	if _, err := t.session(sessP, "", "tpm2_nvwrite", ix.Handle, "-C", "o", "-i", t.w(file), "-P"); err != nil {
		return fmt.Errorf("writing NV %s %s: %w", ix.Name, ix.Handle, err)
	}
	return nil
}

// session kinds
const (
	sessP  = "P"  // policy P (A, S, V, hierarchies)
	sessPE = "PE" // branch 1 of E's policy
	sessPC = "PC" // admin branch of the counter policy (NV_ChangeAuth only)
)

// session runs cmd with a policy session of the given kind. enc is "" (no
// parameter encryption: the command carries no secret), "encrypt" (response)
// or "decrypt" (command); encryption requires the authenticated salt key and
// is only used where the authorized entity has an empty authValue (the TPM
// mixes that authValue into the encryption key; see rotate for the others).
// tpm2_startauthsession -c enables both directions, so the unwanted one is
// switched off explicitly.
func (t *tpm) session(kind, enc string, cmd ...string) ([]byte, error) {
	if !t.ready {
		return nil, errors.New("policy not authorized")
	}
	if kind != sessPE && t.mode == "" {
		return nil, errors.New("PCR policy index not checked")
	}
	s := t.w("s.ctx")
	start := []string{"tpm2_startauthsession", "--policy-session", "-S", s}
	steps := [][]string{start}
	switch enc {
	case "":
	case "decrypt", "encrypt":
		if t.salt == nil {
			return nil, errors.New("parameter encryption requested without an authenticated salt key")
		}
		steps[0] = append(start, "-c", t.w("salt.tr"))
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
	// PCR-bound part: the exact PCR 7+12 of this boot; during a transition
	// the TPM additionally checks that it is one of the listed branches.
	pstar := [][]string{{"tpm2_policypcr", "-S", s, "-l", selSteady, "-f", t.w("pcrs-steady.bin")}}
	if t.mode == modeBridge {
		pstar = append(pstar, []string{"tpm2_policyor", "-S", s, "-l", t.orList()})
	}
	pstar = append(pstar, []string{"tpm2_policyauthorizenv", "-S", s, "-C", PCRPolicy.Handle, PCRPolicy.Handle})
	switch kind {
	case sessP:
		steps = append(steps, pstar...)
	case sessPC:
		steps = append(append(steps, pstar...),
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

func (t *tpm) defineWithPolicy(ix Index, policyFile string) error {
	return t.owner("", "tpm2_nvdefine", ix.Handle, "-s", fmt.Sprint(ix.Size), "-a", fmt.Sprintf("0x%08x", ix.Define),
		"-L", t.w(policyFile), "-g", "sha256")
}

func (t *tpm) defineFresh(ix Index, policyFile string) error {
	_, err := t.run("tpm2_nvdefine", ix.Handle, "-C", "o", "-s", fmt.Sprint(ix.Size),
		"-a", fmt.Sprintf("0x%08x", ix.Define), "-L", t.w(policyFile), "-g", "sha256")
	return err
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

// requireCommand fails unless the TPM implements a command (TPM 2.0 library
// revision 1.38 or later is needed for PolicyAuthorizeNV).
func (t *tpm) requireCommand(name string) error {
	out, err := t.run("tpm2_getcap", "commands")
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), "TPM2_CC_"+name+":") {
		return fmt.Errorf("this TPM does not implement TPM2_%s (TPM 2.0 library revision 1.38 or later required)", name)
	}
	return nil
}

// ---------------------------------------------------------------- salt key (EK)

type certifiedEK struct {
	key  ekcert.Key
	desc string
}

// ekTrust is what this boot accepts as the TPM's endorsement key.
type ekTrust struct {
	certified []certifiedEK
	problems  []string
	discrete  bool // refused because the release requires a firmware TPM
}

// now is the clock used for certificate validity. A clock behind the build
// time of the release (dead RTC battery) is replaced by the build time.
func (t *tpm) now() time.Time {
	now := time.Now()
	if t.c.Now != nil {
		now = t.c.Now()
	}
	if built := time.Unix(t.id.Release.Built, 0); now.Before(built) {
		return built
	}
	return now
}

// loadEKTrust validates the EK certificates found in the TPM against the
// vendor CAs of the image. The certificates travel over the unauthenticated
// bus; their signatures are what counts.
func (t *tpm) loadEKTrust(nv map[uint64]bool) (ekTrust, error) {
	var tr ekTrust
	store := ekcert.NewStore()
	if err := store.AddDir(t.c.EKCADir); err != nil {
		return tr, fmt.Errorf("TPM vendor CA bundle: %w", err)
	}
	if t.id.Profile == "test" {
		// CA of the emulated test TPMs; the directory exists in test images only
		if err := store.AddDir(t.c.EKTestCADir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return tr, err
		}
	}
	if store.NRoots == 0 {
		return tr, errors.New("TPM vendor CA bundle is empty")
	}
	var chain []uint64
	for h := range nv {
		if h >= ekcert.ChainFirst && h <= ekcert.ChainLast {
			chain = append(chain, h)
		}
	}
	sort.Slice(chain, func(i, j int) bool { return chain[i] < chain[j] })
	for _, h := range chain {
		hs := fmt.Sprintf("0x%08X", h)
		if b, err := t.r.Run("tpm2_nvread", hs, "-C", hs); err == nil {
			store.AddIntermediates(b)
		}
	}
	at := t.now()
	for _, alg := range ekcert.Algs {
		h := alg.CertHandle()
		if !nv[handleNum(h)] {
			continue
		}
		der, err := t.r.Run("tpm2_nvread", h, "-C", h)
		if err != nil {
			tr.problems = append(tr.problems, fmt.Sprintf("%s: %v", h, err))
			continue
		}
		k, info, err := store.Verify(der, at)
		if err != nil {
			tr.problems = append(tr.problems, fmt.Sprintf("%s: %v", h, err))
			continue
		}
		if k.Alg != alg {
			tr.problems = append(tr.problems, fmt.Sprintf("%s holds a certificate for an %s key", h, k.Alg))
			continue
		}
		if t.id.Release.RequireFTPM && !info.Firmware() {
			tr.problems = append(tr.problems, fmt.Sprintf("%s: this release requires a firmware TPM (require_ftpm) and the EK certificate is from the discrete-TPM vendor directory %q (issuer %q)", h, info.Vendor, info.Issuer))
			tr.discrete = true
			continue
		}
		tr.certified = append(tr.certified, certifiedEK{k, fmt.Sprintf("EK certificate %s issued by %q", h, info.Issuer)})
	}
	// certificates fetched from the vendor and shipped on the ESP (G5)
	oob, _ := filepath.Glob(filepath.Join(t.c.ekCertDir(), "*"))
	sort.Strings(oob)
	var oobProblems []string
	for _, p := range oob {
		der, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if blk, _ := pem.Decode(der); blk != nil {
			der = blk.Bytes
		}
		name := filepath.Base(p)
		k, info, err := store.Verify(der, at)
		if err != nil {
			oobProblems = append(oobProblems, fmt.Sprintf("ESP certificate %s: %v", name, err))
			continue
		}
		if t.id.Release.RequireFTPM && !info.Firmware() {
			oobProblems = append(oobProblems, fmt.Sprintf("ESP certificate %s: this release requires a firmware TPM (require_ftpm) and the certificate is from the discrete-TPM vendor directory %q", name, info.Vendor))
			continue
		}
		tr.certified = append(tr.certified, certifiedEK{k, fmt.Sprintf("EK certificate %s from the ESP, issued by %q", name, info.Issuer)})
	}
	if len(tr.certified) == 0 {
		if len(tr.problems) == 0 {
			tr.problems = []string{"the TPM holds no EK certificate (NV 0x01C0000A / 0x01C00002)"}
		}
		if len(oob) == 0 {
			tr.problems = append(tr.problems, "no EK certificate in ESP:/"+EKCertDir)
		}
		tr.problems = append(tr.problems, oobProblems...)
	}
	return tr, nil
}

// chooseEK decides how this device's endorsement key is authenticated and,
// with it, the device's policyRef (B1):
//
//   - A TPM with a valid EK certificate uses the base ref of role and
//     profile, and its EK must be the certified key. Admissions are not
//     consulted at all.
//   - A TPM without a valid certificate needs a per-device admission: a
//     policy signed for RefEK(base, Name of this EK), shipped next to the
//     release's policy on the ESP. All its TPM objects are then bound to that
//     ref. An admission is useless on any other device, and an interposer
//     that hides the certificate of a certified device ends up under another
//     ref, whose policy opens none of that device's objects.
func (t *tpm) chooseEK(st tpmState, first bool) error {
	trust, err := t.loadEKTrust(st.nv)
	if err != nil {
		return err
	}
	if len(trust.certified) > 0 {
		t.acceptCertified(trust.certified)
		return t.setRef(t.id.Ref)
	}
	why := strings.Join(trust.problems, "; ")
	if trust.discrete {
		return errors.New("the TPM's endorsement key is refused: " + why)
	}
	if err := t.uncertifiedAllowed(); err != nil {
		return fmt.Errorf("the TPM's endorsement key cannot be authenticated: %s; %w", why, err)
	}
	admit := func(k ekcert.Key) (bool, error) {
		ref := tpmpolicy.RefEK(t.id.Ref, k.Name())
		if _, ok := t.files[ref]; !ok {
			return false, nil
		}
		t.ekName, t.ekAlgs = k.Name(), []ekcert.Alg{k.Alg}
		t.saltSource = fmt.Sprintf("signed per-device admission of EK %x", k.Name())
		return true, t.setRef(ref)
	}
	var names []string
	switch {
	case st.pers[handleNum(SaltHandle)]:
		k, err := t.readEK(SaltHandle)
		if err != nil {
			return fmt.Errorf("salt key %s: %w", SaltHandle, err)
		}
		if ok, err := admit(k); ok || err != nil {
			return err
		}
		names = append(names, hex.EncodeToString(k.Name()))
	case first:
		// fresh TPM: its endorsement keys, as the TPM reports them; only a
		// signature for exactly one of these Names admits the device
		for _, alg := range ekcert.Algs {
			if _, err := t.run("tpm2_createek", "-G", alg.Tool(), "-c", t.w("ek.ctx"), "-u", t.w("ek-created.pub")); err != nil {
				return err
			}
			k, err := t.readEK(t.w("ek.ctx"))
			t.r.Run("tpm2_flushcontext", "-t") //nolint:errcheck
			if err != nil {
				continue
			}
			if ok, err := admit(k); ok || err != nil {
				return err
			}
			names = append(names, hex.EncodeToString(k.Name()))
		}
	default:
		// locked TPM without its salt key (interrupted healing): the admission
		// under which index V was created
		pub, err := ReadPublic(t.r, PCRPolicy)
		if err != nil {
			return err
		}
		for ref, f := range t.files {
			name, err := hex.DecodeString(f.EK)
			if err != nil || len(name) == 0 || tpmpolicy.RefEK(t.id.Ref, name) != ref {
				continue
			}
			if err := t.setRef(ref); err != nil {
				return err
			}
			if bytes.Equal(t.b1, pub.AuthPolicy) {
				t.ekName, t.ekAlgs = name, ekcert.Algs
				t.saltSource = fmt.Sprintf("signed per-device admission of EK %x", name)
				return nil
			}
		}
	}
	return fmt.Errorf("the TPM's endorsement key cannot be authenticated: %s; and no signed per-device admission for this TPM's endorsement key (%s) accompanies the release",
		why, strings.Join(names, ", "))
}

// runtimeEK is chooseEK for the steps after the unlock (verify, state
// service, selftest): the persistent salt key exists, and the policy chosen
// at unlock is checked against the ref computed here.
func (t *tpm) runtimeEK() error {
	nv, err := DefinedIndices(t.r)
	if err != nil {
		return err
	}
	trust, err := t.loadEKTrust(nv)
	if err != nil {
		return err
	}
	if len(trust.certified) > 0 {
		t.acceptCertified(trust.certified)
		return t.setRef(t.id.Ref)
	}
	if trust.discrete {
		return errors.New("the TPM's endorsement key is refused: " + strings.Join(trust.problems, "; "))
	}
	if err := t.uncertifiedAllowed(); err != nil {
		return fmt.Errorf("the TPM's endorsement key cannot be authenticated: %s; %w", strings.Join(trust.problems, "; "), err)
	}
	k, err := t.readEK(SaltHandle)
	if err != nil {
		return fmt.Errorf("salt key %s: %w", SaltHandle, err)
	}
	t.ekName, t.ekAlgs = k.Name(), []ekcert.Alg{k.Alg}
	t.saltSource = fmt.Sprintf("signed per-device admission of EK %x", k.Name())
	return t.setRef(tpmpolicy.RefEK(t.id.Ref, k.Name()))
}

// uncertifiedAllowed says whether this release may accept an endorsement
// key without a vendor certificate through a signed per-device admission
// (G5, G8). Production never does: the signer cannot tell the Name of an
// emulated TPM from a real one, a vendor certificate can. A release that
// requires a firmware TPM never does either: without a certificate the kind
// of TPM is unknown.
func (t *tpm) uncertifiedAllowed() error {
	if t.id.Profile == "prod" {
		return errors.New("a production release accepts only endorsement keys certified by a TPM vendor (certificate in the TPM, or fetched from the vendor and placed in ESP:/" + EKCertDir + "); per-device admissions exist in dev and test builds only")
	}
	if t.id.Release.RequireFTPM {
		return errors.New("this release requires a firmware TPM (require_ftpm), which only a vendor certificate proves; a per-device admission is not accepted")
	}
	return nil
}

// acceptCertified makes the vendor-certified keys the only endorsement keys
// this boot accepts. The TPM's key must be one of them (acceptEK).
func (t *tpm) acceptCertified(cs []certifiedEK) {
	t.accepted, t.ekName, t.ekAlgs = cs, nil, nil
	for _, alg := range ekcert.Algs {
		for _, c := range cs {
			if c.key.Alg == alg {
				t.ekAlgs = append(t.ekAlgs, alg)
				break
			}
		}
	}
	t.saltSource = cs[0].desc
}

// acceptEK decides whether k is this device's authenticated endorsement key.
func (t *tpm) acceptEK(k ekcert.Key) error {
	if len(t.accepted) > 0 {
		var names []string
		for _, c := range t.accepted {
			if bytes.Equal(k.Name(), c.key.Name()) {
				t.ekName, t.saltSource = c.key.Name(), c.desc
				return nil
			}
			names = append(names, fmt.Sprintf("%x, %s", c.key.Name(), c.desc))
		}
		return fmt.Errorf("endorsement key %x (%s) is not the authenticated key of this TPM (%s): substituted key or foreign certificate",
			k.Name(), k.Alg, strings.Join(names, "; "))
	}
	if len(t.ekName) == 0 {
		return errors.New("endorsement key not authenticated yet")
	}
	if !bytes.Equal(k.Name(), t.ekName) {
		return fmt.Errorf("endorsement key %x (%s) is not the authenticated key of this TPM (%x, %s): substituted key or foreign certificate",
			k.Name(), k.Alg, t.ekName, t.saltSource)
	}
	return nil
}

// readEK reads a public area (persistent handle or context file) and
// requires a default-template endorsement key. The result is untrusted
// until accepted by an ekTrust.
func (t *tpm) readEK(ref string) (ekcert.Key, error) {
	if _, err := t.run("tpm2_readpublic", "-c", ref, "-o", t.w("ek.pub")); err != nil {
		return ekcert.Key{}, err
	}
	b, err := os.ReadFile(t.w("ek.pub"))
	if err != nil {
		return ekcert.Key{}, err
	}
	return ekcert.FromTPM2B(b)
}

// useSalt authenticates the persistent salt key and enables salted sessions.
// The key reference handed to tpm2_startauthsession is built locally from
// the authenticated public area: ESYS then issues no TPM2_ReadPublic, so
// nothing an interposer answers later can change the key the salt is
// encrypted to. recorded, if not nil, is the Name pinned in record A.
func (t *tpm) useSalt(recorded []byte) error {
	k, err := t.readEK(SaltHandle)
	if err != nil {
		return fmt.Errorf("salt key %s: %w", SaltHandle, err)
	}
	if err := t.acceptEK(k); err != nil {
		return fmt.Errorf("salt key %s: %w", SaltHandle, err)
	}
	if recorded != nil && !bytes.Equal(k.Name(), recorded) {
		return fmt.Errorf("salt key %s Name %x does not match the recorded %x (substituted key?)", SaltHandle, k.Name(), recorded)
	}
	if err := t.put("salt.tr", k.SerializedTR(uint32(handleNum(SaltHandle)))); err != nil {
		return err
	}
	t.salt = &k
	return nil
}

// recordedSalt authenticates the salt key against the trust anchors and
// record A (runtime users: state service, selftest).
func (t *tpm) recordedSalt() error {
	if err := t.runtimeEK(); err != nil {
		return err
	}
	rec, err := ReadNV(t.r, Record)
	if err != nil {
		return err
	}
	rd, err := ParseRecord(rec)
	if err != nil {
		return err
	}
	return t.useSalt(rd.SaltName)
}

// installSalt creates the authenticated endorsement key and persists it at
// SaltHandle. policy selects authorization by policy P (locked TPM) instead
// of the empty hierarchy auth of a fresh TPM.
func (t *tpm) installSalt(policy bool) error {
	var problems []string
	for _, alg := range t.ekAlgs {
		if _, err := t.run("tpm2_flushcontext", "-t"); err != nil {
			return err
		}
		// tpm2_createek applies the TCG default EK template of the algorithm
		create := []string{"tpm2_createek", "-G", alg.Tool(), "-c", t.w("ek.ctx"), "-u", t.w("ek-created.pub")}
		var err error
		if policy {
			_, err = t.session(sessP, "", append(create, "-P")...)
		} else {
			_, err = t.run(create[0], create[1:]...)
		}
		if err != nil {
			return err
		}
		k, err := t.readEK(t.w("ek.ctx"))
		if err == nil {
			err = t.acceptEK(k)
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", alg, err))
			continue
		}
		persist := []string{"-c", t.w("ek.ctx"), SaltHandle}
		if policy {
			err = t.owner("", "tpm2_evictcontrol", persist...)
		} else {
			_, err = t.run("tpm2_evictcontrol", append([]string{"-C", "o"}, persist...)...)
		}
		if err != nil {
			return err
		}
		if _, err := t.run("tpm2_flushcontext", "-t"); err != nil {
			return err
		}
		return t.useSalt(nil)
	}
	t.r.Run("tpm2_flushcontext", "-t") //nolint:errcheck
	return errors.New(strings.Join(problems, "; "))
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
	if t.salt == nil {
		return errors.New("lock-down requires the authenticated salt key")
	}
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
			{"tpm2_startauthsession", "--hmac-session", "-S", hs, "-c", t.w("salt.tr")},
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
	if t.salt == nil {
		return errors.New("rotation requires the authenticated salt key")
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
		if _, err := t.run("tpm2_startauthsession", "--hmac-session", "-S", aux, "-c", t.w("salt.tr")); err != nil {
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

// EKNames creates this TPM's default-template endorsement keys (transient)
// and returns their Names as allowlist lines. It is a provisioning aid for
// TPMs without an EK certificate in NV (run it on the device, or on the host
// against a virtual TPM); it needs an empty endorsement auth.
func EKNames(c Config, r Runner) ([]string, error) {
	work, err := os.MkdirTemp("", "enclave-ek-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	c.Work = work
	t := &tpm{c: c, r: r}
	var out []string
	for _, alg := range ekcert.Algs {
		if _, err := t.run("tpm2_createek", "-G", alg.Tool(), "-c", t.w("ek.ctx"), "-u", t.w("ek-created.pub")); err != nil {
			return nil, err
		}
		k, err := t.readEK(t.w("ek.ctx"))
		t.r.Run("tpm2_flushcontext", "-t") //nolint:errcheck
		if err != nil {
			return nil, fmt.Errorf("%s: %w", alg, err)
		}
		out = append(out, fmt.Sprintf("%x  # %s", k.Name(), alg))
	}
	return out, nil
}

// ---------------------------------------------------------------- dictionary-attack lockout

// DAState is the TPM's dictionary-attack state (tpm2_getcap properties-variable).
type DAState struct {
	Counter, MaxTries, Interval, Recovery uint64
	InLockout                             bool
}

// ReadDA parses the dictionary-attack properties.
func ReadDA(r Runner) (DAState, error) {
	out, err := r.Run("tpm2_getcap", "properties-variable")
	if err != nil {
		return DAState{}, fmt.Errorf("tpm2_getcap: %w", err)
	}
	var d DAState
	seen := 0
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		var dst *uint64
		switch k {
		case "inLockout":
			d.InLockout = v == "1"
			seen++
			continue
		case "TPM2_PT_LOCKOUT_COUNTER":
			dst = &d.Counter
		case "TPM2_PT_MAX_AUTH_FAIL":
			dst = &d.MaxTries
		case "TPM2_PT_LOCKOUT_INTERVAL":
			dst = &d.Interval
		case "TPM2_PT_LOCKOUT_RECOVERY":
			dst = &d.Recovery
		default:
			continue
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(v), "0x"), 16, 64)
		if err != nil {
			return d, fmt.Errorf("bad %s value %q", k, v)
		}
		*dst = n
		seen++
	}
	if seen != 5 {
		return d, errors.New("dictionary-attack properties missing from tpm2_getcap output")
	}
	return d, nil
}

// disableDA takes the TPM out of dictionary-attack lockout and disables the
// lockout (recovery time 0), authorized through the lockout hierarchy
// (policy P on a locked TPM, the empty auth on a fresh one).
//
// Why: the endorsement key is a DA-protected object. Using it as the salt
// key makes the TPM count every power loss without TPM2_Shutdown as a failed
// authorization, and anyone can add failures by sending wrong authValues.
// In lockout the TPM refuses salted sessions, so a few power cuts would make
// the device fail closed. No enclave secret depends on the lockout: every
// authValue is 256 bits of entropy and every index is NO_DA. It runs before
// the first salted session of every boot; a policy session on the lockout
// hierarchy works while the TPM is in lockout.
func (t *tpm) disableDA(policy bool) error {
	d, err := ReadDA(t.r)
	if err != nil {
		return err
	}
	lockout := func(args ...string) error {
		if policy {
			_, err := t.session(sessP, "", append(append([]string{"tpm2_dictionarylockout"}, args...), "-p")...)
			return err
		}
		_, err := t.run("tpm2_dictionarylockout", args...)
		return err
	}
	if d.Interval != 0 {
		// keep the other parameters; some TPMs restrict their range
		if err := lockout("-s", "-n", strconv.FormatUint(d.MaxTries, 10), "-t", "0", "-l", strconv.FormatUint(d.Recovery, 10)); err != nil {
			fmt.Fprintf(os.Stderr, "enclave-varauth: warning: this TPM does not allow disabling its dictionary-attack lockout: %v\n", err)
		}
	}
	if d.Counter != 0 || d.InLockout {
		if err := lockout("-c"); err != nil {
			return fmt.Errorf("resetting the TPM dictionary-attack lockout: %w", err)
		}
	}
	if d, err = ReadDA(t.r); err != nil {
		return err
	}
	if d.InLockout {
		return errors.New("the TPM stays in dictionary-attack lockout")
	}
	return nil
}

// checkSignature has the TPM verify the signature of a policy for the
// device's policyRef. The first boot calls it before it creates anything,
// so that a forged policy or admission leaves the TPM untouched.
func (t *tpm) checkSignature(f tpmpolicy.File) error {
	_, approved, err := f.DecodeRef(t.id.Role, t.id.Profile, t.ref)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	if err := t.put("pre-msg.bin", tpmpolicy.SignedMessage(approved, t.ref)); err != nil {
		return err
	}
	if err := t.put("pre-sig.bin", sig); err != nil {
		return err
	}
	if _, err := t.run("tpm2_verifysignature", "-c", t.w("key.ctx"), "-g", "sha256", "-m", t.w("pre-msg.bin"),
		"-s", t.w("pre-sig.bin"), "-f", "rsassa", "-t", t.w("pre-ticket.bin")); err != nil {
		return fmt.Errorf("approved policy signature rejected: %w", err)
	}
	_, err = t.run("tpm2_flushcontext", "-t")
	return err
}

// ForeignObjects lists TPM objects that enclave does not account for. The
// dictionary-attack lockout is disabled, which is sound only while nothing
// in the TPM is protected by a guessable authValue: every enclave object is
// NO_DA with a 256-bit or empty-and-policy-only authorization, the
// hierarchies have random 256-bit authValues, and the only other objects
// allowed are the vendor's EK certificates and keys (TCG-reserved ranges,
// no secret authValue) and the storage root key systemd creates at
// 0x81000001 (empty authValue by design, protects nothing of enclave's).
func ForeignObjects(r Runner) ([]string, error) {
	nv, err := DefinedIndices(r)
	if err != nil {
		return nil, err
	}
	pers, err := handles(r, "handles-persistent")
	if err != nil {
		return nil, err
	}
	var out []string
	for h := range nv {
		known := h >= 0x01C00000 && h <= 0x01C0FFFF
		for _, ix := range allIndices {
			known = known || h == handleNum(ix.Handle)
		}
		if !known {
			out = append(out, fmt.Sprintf("NV 0x%08X", h))
		}
	}
	for h := range pers {
		if h != handleNum(SaltHandle) && h != 0x81000001 && !(h >= 0x81010000 && h <= 0x8101FFFF) {
			out = append(out, fmt.Sprintf("persistent 0x%08X", h))
		}
	}
	sort.Strings(out)
	return out, nil
}
