package varauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"enklave.local/base/internal/statefs"
	"enklave.local/base/internal/tpmpolicy"
)

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
// The session is salted to the authenticated salt key (work/salt.tr).
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
		{"tpm2_startauthsession", "--policy-session", "-S", s, "-c", filepath.Join(k.work, "salt.tr")},
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

// openStore opens the mounted state store with the given keys: it
// authenticates the salt key (EK trust anchors and record A) and checks the
// counter's policy. Only the state service calls it at runtime.
func openStore(c Config, r Runner, keys StateKeys, pause func(string)) (*statefs.Store, error) {
	t, err := newTPM(c, r)
	if err != nil {
		return nil, err
	}
	if err := t.prepare(); err != nil {
		return nil, err
	}
	if err := t.recordedSalt(); err != nil {
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

func (s tpmState) has(ix Index) bool { return s.nv[handleNum(ix.Handle)] }

func (s tpmState) count() int {
	n := 0
	for _, ix := range allIndices {
		if s.has(ix) {
			n++
		}
	}
	if s.pers[handleNum(SaltHandle)] {
		n++
	}
	return n
}

const allObjects = 7 // six NV indices and the salt key

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
	// G6: no volume key without DMA protection
	if err := RequireIOMMU(c); err != nil {
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
	if err := t.loadPolicies(espDev); err != nil {
		return "", err
	}
	st, err := readState(r)
	if err != nil {
		return "", err
	}
	if first {
		if st.count() != 0 || !st.h.Fresh() {
			return "", fmt.Errorf("first boot of /var on a TPM that is not fresh (%d enklave objects, %+v)", st.count(), st.h)
		}
		if _, err := r.Run("cryptsetup", "isLuks", varDev); err == nil {
			return "", fmt.Errorf("%s already carries a LUKS header on the first boot", varDev)
		}
	} else {
		if !st.h.Locked() {
			return "", fmt.Errorf("TPM hierarchies not locked on an enrolled machine: %+v (interrupted provisioning?)", st.h)
		}
		if !st.has(Epoch) || !st.has(PCRPolicy) || !st.has(Transition) {
			return "", errors.New("epoch, PCR policy or transition index missing on an enrolled machine")
		}
	}
	// how the endorsement key is authenticated decides the device's policyRef
	if err := t.chooseEK(st, first); err != nil {
		return "", err
	}
	f, err := t.selectedPolicy()
	if err != nil {
		return "", err
	}

	var key []byte
	verb := "opened"
	if first {
		if err := t.checkSignature(f); err != nil {
			return "", err
		}
		if key, err = t.provision(f, varDev); err != nil {
			return "", err
		}
		verb = "provisioned"
	} else {
		if err := t.authorize(f); err != nil {
			return "", err
		}
		if err := t.revoke(); err != nil {
			return "", err
		}
		if err := t.pcrMode(); err != nil {
			return "", err
		}
		// B2: while a Secure Boot variable update is in transit, the complete
		// Secure Boot state is checked here, before the volume key is read.
		if t.mode == modeBridge && !t.skipBridgeCheck {
			if err := t.checkBridge(); err != nil {
				return "", err
			}
		}
		// G7: the lockout is switched off only on a TPM that holds nothing
		// but enklave's objects
		if err := requireNoForeignObjects(r); err != nil {
			return "", err
		}
		// before the first salted session of this boot
		if err := t.disableDA(true); err != nil {
			return "", err
		}
		complete := st.count() == allObjects
		var rd *RecordData
		if st.has(Record) {
			b, err := ReadNV(r, Record)
			if err != nil {
				return "", err
			}
			d, err := ParseRecord(b)
			if err != nil {
				return "", err
			}
			rd = &d
		}
		heal := t.id.Release.HealBelow > 0 && (rd == nil || rd.Epoch < uint64(t.id.Release.HealBelow))
		switch {
		case heal:
			if key, err = t.heal(st, rd, varDev); err != nil {
				return "", fmt.Errorf("healing: %w", err)
			}
			verb = "healed"
		case !complete || rd == nil:
			return "", fmt.Errorf("partial enklave TPM state (%d of %d objects): interrupted provisioning, refusing", st.count(), allObjects)
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
	if err := os.WriteFile(c.SaltSourceFile(), []byte(t.saltSource+"\n"), 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s the state volume on %s (role %s, profile %s, epoch %d; TPM authenticated by %s)",
		verb, varDev, t.id.Role, t.id.Profile, t.epoch, t.saltSource), nil
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

// provision runs the genuine first boot on a fresh TPM. Order (N1):
//
//  1. the platform is checked: PolicyAuthorizeNV present, and the firmware's
//     event log replays to PCR 7 with db, dbx and KEK measured exactly once
//     (B7: a device that could not carry a signed Secure Boot update later is
//     never enrolled),
//  2. the endorsement key (authenticated by chooseEK) is persisted as the
//     salt key,
//  3. the indices that carry no secret and that policy P refers to are
//     defined with the still-empty owner auth: E (revocation bits), V
//     (PCR-bound part of P, holding this boot's Secure Boot state) and T
//     (transition state, idle),
//  4. the hierarchies are locked (policy P, random discarded authValues sent
//     encrypted to the EK, Clear disabled),
//  5. only then S, the volume, the counter C and the record A are created,
//     each authorized by policy P.
//
// Every later boot that finds a partial state fails closed.
func (t *tpm) provision(f tpmpolicy.File, varDev string) ([]byte, error) {
	if err := t.requireCommand("PolicyAuthorizeNV"); err != nil {
		return nil, err
	}
	if err := t.requireEventLog(); err != nil {
		return nil, err
	}
	if err := t.installSalt(false); err != nil {
		return nil, err
	}
	t.pause("salt-created")
	if err := t.defineFresh(Epoch, "pe.bin"); err != nil {
		return nil, err
	}
	if err := t.initEpoch(); err != nil {
		return nil, err
	}
	if err := t.put("t-idle.bin", make([]byte, Transition.Size)); err != nil {
		return nil, err
	}
	for _, w := range []struct {
		ix   Index
		file string
	}{{PCRPolicy, "v-steady.bin"}, {Transition, "t-idle.bin"}} {
		if err := t.defineFresh(w.ix, "b1.bin"); err != nil {
			return nil, err
		}
		if _, err := t.run("tpm2_nvwrite", w.ix.Handle, "-C", "o", "-i", t.w(w.file)); err != nil {
			return nil, err
		}
	}
	t.pause("epoch-defined")
	if err := t.authorize(f); err != nil {
		return nil, err
	}
	if err := t.revoke(); err != nil {
		return nil, err
	}
	if err := t.pcrMode(); err != nil {
		return nil, err
	}
	if err := t.checkIndex(Transition, Transition.Final, t.b1); err != nil {
		return nil, err
	}
	// The dictionary-attack lockout is disabled while the lockout auth is
	// still empty, before the first salted session, and only on a TPM that
	// holds nothing but enklave's objects (G7).
	if err := requireNoForeignObjects(t.r); err != nil {
		return nil, err
	}
	if err := t.disableDA(false); err != nil {
		return nil, err
	}
	if err := t.lockFresh(); err != nil {
		return nil, err
	}
	t.pause("locked")
	return t.provisionVolume(varDev)
}

// provisionVolume creates S, the LUKS2 volume, the counter and the empty
// state store. The record A is written by Verify (it needs PCR 15).
func (t *tpm) provisionVolume(varDev string) ([]byte, error) {
	if err := t.defineWithPolicy(Secret, "p.bin"); err != nil {
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
	tok := fmt.Sprintf(`{"type":"enklave-tpm2-nv","keyslots":["0"],"nv-secret":"%s","nv-record":"%s","nv-counter":"%s","nv-epoch":"%s","nv-pcrpolicy":"%s","salt":"%s","ref":"%s"}`,
		Secret.Handle, Record.Handle, Counter.Handle, Epoch.Handle, PCRPolicy.Handle, SaltHandle, t.id.Ref)
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
	if err := t.defineWithPolicy(Counter, "pc.bin"); err != nil {
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

// heal (N4) rotates the hierarchy authorization, re-creates the salt key
// from the endorsement seed, destroys every index that a compromised epoch
// could have learned (S, A, C) and re-provisions an empty state volume with
// a new key.
//
// The re-created salt key must be the endorsement key authenticated for
// this boot (EK certificate, or the device's signed admission) and, when
// record A still exists, must have the recorded Name (F4). The platform
// check of the first boot is repeated (B7).
func (t *tpm) heal(st tpmState, rd *RecordData, varDev string) ([]byte, error) {
	// Healing does not depend on whether a Secure Boot update is in transit:
	// V and T are not touched here, PCR 7 is bound exactly in both modes, and
	// the verify step of this boot completes the transition as usual.
	if err := t.requireEventLog(); err != nil {
		return nil, err
	}
	if st.pers[handleNum(SaltHandle)] {
		if err := t.owner("", "tpm2_evictcontrol", "-c", SaltHandle); err != nil {
			return nil, err
		}
	}
	if err := t.installSalt(true); err != nil {
		return nil, err
	}
	if rd != nil && !bytes.Equal(t.salt.Name(), rd.SaltName) {
		return nil, fmt.Errorf("re-created salt key Name %x differs from the recorded %x: not the endorsement key this device was provisioned with",
			t.salt.Name(), rd.SaltName)
	}
	if rd != nil {
		t.saltSource += "; re-created salt key has the Name recorded at provisioning"
	}
	if err := t.rotate(); err != nil {
		return nil, err
	}
	for _, ix := range []Index{Record, Secret, Counter} {
		if st.has(ix) {
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

// requireNoForeignObjects fails closed if the TPM holds an object enklave
// does not account for (G7). The dictionary-attack lockout is switched off
// on every boot; that is sound only while nothing in the TPM is protected
// by a guessable authValue (ForeignObjects).
func requireNoForeignObjects(r Runner) error {
	foreign, err := ForeignObjects(r)
	if err != nil {
		return err
	}
	if len(foreign) > 0 {
		return fmt.Errorf("the TPM holds objects that are not enklave's (%s): the dictionary-attack lockout is not switched off for them, refusing",
			strings.Join(foreign, ", "))
	}
	return nil
}

// RequireIOMMU fails closed unless DMA remapping is active (G6): the
// firmware describes an IOMMU (ACPI DMAR or IVRS), the kernel runs it, and
// every device group is translated (no identity/passthrough domain). The
// kernel command line demands this (iommu=force, intel_iommu=on,
// amd_iommu=force_isolation, strict); this check is what refuses the volume
// key when the platform does not deliver it, for example with VT-d/AMD-Vi
// switched off in the firmware setup, a setting that is not measured into a
// PCR enklave binds.
func RequireIOMMU(c Config) error {
	sys := c.Sys
	if sys == "" {
		sys = "/sys"
	}
	const why = ": no DMA protection, refusing to release the volume key (enable VT-d / AMD-Vi in the firmware setup)"
	acpi := false
	for _, t := range []string{"DMAR", "IVRS"} {
		if _, err := os.Stat(filepath.Join(sys, "firmware/acpi/tables", t)); err == nil {
			acpi = true
		}
	}
	if !acpi {
		return errors.New("the firmware describes no IOMMU (no ACPI DMAR or IVRS table)" + why)
	}
	if units, _ := filepath.Glob(filepath.Join(sys, "class/iommu/*")); len(units) == 0 {
		return errors.New("the kernel runs no IOMMU (/sys/class/iommu is empty)" + why)
	}
	groups, _ := filepath.Glob(filepath.Join(sys, "kernel/iommu_groups/*/type"))
	if len(groups) == 0 {
		return errors.New("no device is behind the IOMMU (no IOMMU groups)" + why)
	}
	for _, g := range groups {
		b, err := os.ReadFile(g)
		if err != nil {
			return err
		}
		if typ := strings.TrimSpace(string(b)); typ != "DMA" && typ != "DMA-FQ" && typ != "blocked" {
			return fmt.Errorf("IOMMU group %s is of type %q, not translated%s", filepath.Base(filepath.Dir(g)), typ, why)
		}
	}
	return nil
}
