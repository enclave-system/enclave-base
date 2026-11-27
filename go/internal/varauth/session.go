package varauth

import (
	"bytes"
	"crypto/rand"
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

	"enklave.local/base/internal/ekcert"
	"enklave.local/base/internal/tpmpolicy"
)

// PCR selections of the PCR-bound part of policy P.
const (
	selSteady = "sha256:7,12"     // recorded Secure Boot state, no ESP credentials
	selBridge = "sha256:0,2,4,12" // firmware and boot chain, during a PCR 7 transition

	modeSteady = "steady"
	modeBridge = "transition"
)

var (
	pcrsSteady = []int{7, 12}
	pcrsBridge = []int{0, 2, 4, 12}
)

type tpm struct {
	c  Config
	r  Runner
	id Identity

	// policy is P; plit and pbridge are the PCR-bound digests V may hold for
	// the PCR values of this boot; b1 is V's authPolicy.
	pcr11, policy, pe, pc, b1, plit, pbridge []byte
	epoch                                    int
	ready                                    bool
	mode                                     string      // which digest V holds (pcrMode)
	salt                                     *ekcert.Key // authenticated salt key
	saltSource                               string
	pauseAt                                  string
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

// prepare loads the PCR key and computes the expected policies. Everything
// that depends on the Name of index V is computed locally.
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
	if err := t.pcrValues("pcrs-steady.bin", pcrsSteady); err != nil {
		return err
	}
	if err := t.pcrValues("pcrs-bridge.bin", pcrsBridge); err != nil {
		return err
	}
	auth := []string{"tpm2_policyauthorize", "-n", t.w("key.name"), "-q", t.w("ref.bin")}
	var err error
	if t.plit, err = t.trial(auth, []string{"tpm2_policypcr", "-l", selSteady, "-f", t.w("pcrs-steady.bin")}); err != nil {
		return err
	}
	if t.pbridge, err = t.trial(auth, []string{"tpm2_policypcr", "-l", selBridge, "-f", t.w("pcrs-bridge.bin")}); err != nil {
		return err
	}
	if t.b1, err = t.trial(auth); err != nil {
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
	vName := tpmpolicy.NVName(uint32(handleNum(PCRPolicy.Handle)), PCRPolicy.Final, t.b1, PCRPolicy.Size)
	t.policy = tpmpolicy.PolicyAuthorizeNV(vName)
	// Counter admin branch: NV_ChangeAuth needs the ADMIN role, which requires
	// PolicyCommandCode in the session.
	pca := tpmpolicy.PolicyCommandCode(t.policy, tpmpolicy.CCNVChangeAuth)
	t.pc = tpmpolicy.PolicyOR(pca, av)
	for n, d := range map[string][]byte{
		"p.bin": t.policy, "b1.bin": t.b1, "b2.bin": b2, "av.bin": av, "pca.bin": pca, "pc.bin": t.pc,
		"v-steady.bin": tpmpolicy.DigestNV(t.plit), "v-bridge.bin": tpmpolicy.DigestNV(t.pbridge),
	} {
		if err := t.put(n, d); err != nil {
			return err
		}
	}
	if t.pe, err = t.trial([]string{"tpm2_policyor", "-l", "sha256:" + t.w("b1.bin") + "," + t.w("b2.bin")}); err != nil {
		return err
	}
	if err := t.put("pe.bin", t.pe); err != nil {
		return err
	}
	t.pcr11, err = t.trial([]string{"tpm2_policypcr", "-l", "sha256:11"})
	return err
}

// Policies are the expected policy digests for this boot.
type Policies struct {
	P, PE, PC []byte // hierarchies/A/S, epoch index, counter
	VAuth     []byte // authPolicy of index V (binds its Name)
	Steady    []byte // content of V for the Secure Boot state of this boot
	Bridge    []byte // content of V during a PCR 7 transition started with this boot chain
}

// ExpectedPolicies returns the policies of this boot.
func ExpectedPolicies(c Config, r Runner) (Policies, error) {
	t, err := newTPM(c, r)
	if err != nil {
		return Policies{}, err
	}
	defer os.RemoveAll(c.work())
	if err := t.prepare(); err != nil {
		return Policies{}, err
	}
	return Policies{t.policy, t.pe, t.pc, t.b1, tpmpolicy.DigestNV(t.plit), tpmpolicy.DigestNV(t.pbridge)}, nil
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
			// Verify runs as a separate process (test profile only)
			if err := os.WriteFile(filepath.Join(t.c.RunDir, "test-pause"), b, 0o600); err != nil {
				return f, err
			}
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

// pcrMode checks index V and finds out which PCR binding it holds: the
// Secure Boot state of this boot (steady), or this boot chain during a PCR 7
// transition. Anything else is a foreign Secure Boot configuration or boot
// chain and fails closed.
func (t *tpm) pcrMode() error {
	if err := t.checkIndex(PCRPolicy, PCRPolicy.Final, t.b1); err != nil {
		return err
	}
	v, err := ReadNV(t.r, PCRPolicy)
	if err != nil {
		return err
	}
	switch {
	case bytes.Equal(v, tpmpolicy.DigestNV(t.plit)):
		t.mode = modeSteady
	case bytes.Equal(v, tpmpolicy.DigestNV(t.pbridge)):
		t.mode = modeBridge
	default:
		return fmt.Errorf("PCR policy index %s holds %x: neither the Secure Boot state of this boot (PCR 7+12: %x) "+
			"nor a pending transition for this boot chain (PCR 0+2+4+12: %x); "+
			"the Secure Boot configuration, firmware or boot chain changed without a signed update",
			PCRPolicy.Handle, v[2:], t.plit, t.pbridge)
	}
	return nil
}

func (t *tpm) sel() (string, string) {
	if t.mode == modeBridge {
		return selBridge, t.w("pcrs-bridge.bin")
	}
	return selSteady, t.w("pcrs-steady.bin")
}

// writePCRPolicy rewrites index V through the owner hierarchy (policy P).
func (t *tpm) writePCRPolicy(file, newMode string) error {
	if _, err := t.session(sessP, "", "tpm2_nvwrite", PCRPolicy.Handle, "-C", "o", "-i", t.w(file), "-P"); err != nil {
		return fmt.Errorf("writing the PCR policy index: %w", err)
	}
	t.mode = newMode
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
	sel, vals := t.sel()
	pstar := [][]string{
		{"tpm2_policypcr", "-S", s, "-l", sel, "-f", vals},
		{"tpm2_policyauthorizenv", "-S", s, "-C", PCRPolicy.Handle, PCRPolicy.Handle},
	}
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
	allow     map[string]bool
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
// vendor CAs of the image and loads the signed allowlist. The certificates
// travel over the unauthenticated bus; their signatures are what counts.
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
		k, c, err := store.Verify(der, at)
		if err != nil {
			tr.problems = append(tr.problems, fmt.Sprintf("%s: %v", h, err))
			continue
		}
		if k.Alg != alg {
			tr.problems = append(tr.problems, fmt.Sprintf("%s holds a certificate for an %s key", h, k.Alg))
			continue
		}
		tr.certified = append(tr.certified, certifiedEK{k, fmt.Sprintf("EK certificate %s issued by %q", h, c.Issuer.String())})
	}
	if len(tr.certified) == 0 && len(tr.problems) == 0 {
		tr.problems = []string{"the TPM holds no EK certificate (NV 0x01C0000A / 0x01C00002)"}
	}
	b, err := os.ReadFile(t.c.EKAllowlist)
	switch {
	case err == nil:
		if tr.allow, err = ekcert.ParseAllowlist(b); err != nil {
			return tr, err
		}
	case !errors.Is(err, os.ErrNotExist):
		return tr, err
	}
	return tr, nil
}

// accept decides whether k is the authentic endorsement key.
func (tr ekTrust) accept(k ekcert.Key) (string, error) {
	for _, c := range tr.certified {
		if bytes.Equal(c.key.Name(), k.Name()) {
			return c.desc, nil
		}
	}
	if tr.allow[hex.EncodeToString(k.Name())] {
		return "signed EK allowlist of the release", nil
	}
	if len(tr.certified) > 0 {
		return "", fmt.Errorf("endorsement key %x (%s) is not the key of this TPM's EK certificate (%s): substituted key or foreign certificate",
			k.Name(), k.Alg, tr.certified[0].desc)
	}
	return "", fmt.Errorf("endorsement key %x (%s) is not authentic: no valid EK certificate (%s) and not in the signed EK allowlist",
		k.Name(), k.Alg, strings.Join(tr.problems, "; "))
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
func (t *tpm) useSalt(tr ekTrust, recorded []byte) error {
	k, err := t.readEK(SaltHandle)
	if err != nil {
		return fmt.Errorf("salt key %s: %w", SaltHandle, err)
	}
	src, err := tr.accept(k)
	if err != nil {
		return fmt.Errorf("salt key %s: %w", SaltHandle, err)
	}
	if recorded != nil && !bytes.Equal(k.Name(), recorded) {
		return fmt.Errorf("salt key %s Name %x does not match the recorded %x (substituted key?)", SaltHandle, k.Name(), recorded)
	}
	if err := t.put("salt.tr", k.SerializedTR(uint32(handleNum(SaltHandle)))); err != nil {
		return err
	}
	t.salt, t.saltSource = &k, src
	return nil
}

// recordedSalt authenticates the salt key against the trust anchors and
// record A (runtime users: state commits, selftest).
func (t *tpm) recordedSalt() error {
	nv, err := DefinedIndices(t.r)
	if err != nil {
		return err
	}
	tr, err := t.loadEKTrust(nv)
	if err != nil {
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
	return t.useSalt(tr, rd.SaltName)
}

// installSalt creates the authentic endorsement key and persists it at
// SaltHandle. policy selects authorization by policy P (locked TPM) instead
// of the empty hierarchy auth of a fresh TPM.
func (t *tpm) installSalt(tr ekTrust, policy bool) error {
	algs := ekcert.Algs
	if len(tr.certified) > 0 {
		algs = nil
		for _, c := range tr.certified {
			algs = append(algs, c.key.Alg)
		}
	} else if len(tr.allow) == 0 {
		return fmt.Errorf("the TPM's endorsement key cannot be authenticated: %s; no signed EK allowlist in this release", strings.Join(tr.problems, "; "))
	}
	if err := t.put("ek-policy.bin", ekcert.PolicyA); err != nil {
		return err
	}
	var problems []string
	for _, alg := range algs {
		if _, err := t.run("tpm2_flushcontext", "-t"); err != nil {
			return err
		}
		args, unique := alg.CreateArgs()
		if err := t.put("ek-unique.bin", unique); err != nil {
			return err
		}
		create := append(args, "-L", t.w("ek-policy.bin"), "-u", t.w("ek-unique.bin"), "-c", t.w("ek.ctx"))
		var err error
		if policy {
			_, err = t.session(sessP, "", append(append([]string{"tpm2_createprimary"}, create...), "-C", "e", "-P")...)
		} else {
			_, err = t.run("tpm2_createprimary", append([]string{"-C", "e"}, create...)...)
		}
		if err != nil {
			return err
		}
		k, err := t.readEK(t.w("ek.ctx"))
		if err == nil {
			_, err = tr.accept(k)
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
		return t.useSalt(tr, nil)
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
	work, err := os.MkdirTemp("", "enklave-ek-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	c.Work = work
	t := &tpm{c: c, r: r}
	if err := t.put("ek-policy.bin", ekcert.PolicyA); err != nil {
		return nil, err
	}
	var out []string
	for _, alg := range ekcert.Algs {
		args, unique := alg.CreateArgs()
		if err := t.put("ek-unique.bin", unique); err != nil {
			return nil, err
		}
		create := append([]string{"-C", "e"}, append(args, "-L", t.w("ek-policy.bin"), "-u", t.w("ek-unique.bin"), "-c", t.w("ek.ctx"))...)
		if _, err := t.run("tpm2_createprimary", create...); err != nil {
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
// the device fail closed. No enklave secret depends on the lockout: every
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
			fmt.Fprintf(os.Stderr, "enklave-varauth: warning: this TPM does not allow disabling its dictionary-attack lockout: %v\n", err)
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
