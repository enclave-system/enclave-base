package varauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"enklave.local/base/internal/sbstate"
	"enklave.local/base/internal/statefs"
	"enklave.local/base/internal/tpmpolicy"
)

// ---------------------------------------------------------------- verify

// Verify authenticates the opened volume (PCR 15 against record A), checks
// every public area and the hierarchy lock, verifies the state store against
// its manifest and the TPM counter (anti-rollback, anti-splice) and then
// handles the release's signed Secure Boot variable updates.
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
	if t.id.Profile == "test" {
		if b, err := os.ReadFile(filepath.Join(c.RunDir, "test-pause")); err == nil {
			t.pauseAt = strings.TrimSpace(string(b))
		}
	}
	if err := t.runtimeEK(); err != nil {
		return "", err
	}
	f, err := t.cachedPolicy()
	if err != nil {
		return "", err
	}
	if err := t.authorize(f); err != nil {
		return "", err
	}
	st, err := readState(r)
	if err != nil {
		return "", err
	}
	if !st.h.Locked() {
		return "", fmt.Errorf("TPM hierarchies not locked: %+v", st.h)
	}
	if err := t.pcrMode(); err != nil {
		return "", err
	}
	provisioned, err := exists(c.ProvisionedFlag())
	if err != nil {
		return "", err
	}
	if provisioned {
		// (re-)provisioned in this boot by Unlock: pin the salt key now
		if err := t.useSalt(nil); err != nil {
			return "", err
		}
		if err := t.defineWithPolicy(Record, "p.bin"); err != nil {
			return "", err
		}
		rd := RecordData{PCR15: pcr15, Epoch: uint64(t.epoch), SaltName: t.salt.Name()}
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
	updates, err := t.secureBootUpdates()
	if err != nil {
		return "", err
	}
	for name, content := range map[string]string{
		c.ResultFile():     hex.EncodeToString(pcr15),
		c.CounterFile():    strconv.FormatUint(version, 10),
		c.EFIUpdatesFile(): updates,
	} {
		if err := os.WriteFile(name, []byte(content+"\n"), 0o600); err != nil {
			return "", err
		}
	}
	dev := ""
	if t.id.Release.DevKeys {
		dev = "; DEV KEYS (development build, never ship)"
	}
	return fmt.Sprintf("state volume verified: record %s (PCR 15 %x, provisioned at epoch %d), state version %d, %s/%s epoch %d, TPM locked, Secure Boot updates: %s%s",
		Record.Handle, pcr15, rd.Epoch, version, t.id.Role, t.id.Profile, t.epoch, updates, dev), nil
}

// ---------------------------------------------------------------- Secure Boot variable updates

// Transition states (last byte block of index T).
const (
	trIdle       = 0
	trArmed      = 1 // T and V are set for the update; the firmware may or may not have it
	trApplied    = 2 // the firmware took the update in a boot that saw it in the variable
	trRolledBack = 3 // the firmware lost an applied update again; not re-armed
)

// transState is the content of index T.
type transState struct {
	old, new []byte // sbstate.StateDigest before the update / the only state it may lead to
	state    byte
}

func (ts transState) bytes() []byte {
	b := make([]byte, Transition.Size)
	copy(b, ts.old)
	copy(b[32:], ts.new)
	b[64] = ts.state
	return b
}

func (t *tpm) readTransition() (transState, error) {
	if err := t.checkIndex(Transition, Transition.Final, t.b1); err != nil {
		return transState{}, err
	}
	b, err := ReadNV(t.r, Transition)
	if err != nil {
		return transState{}, err
	}
	return transState{old: b[:32], new: b[32:64], state: b[64]}, nil
}

func (t *tpm) writeTransition(ts transState) error {
	if err := t.put("t.bin", ts.bytes()); err != nil {
		return err
	}
	return t.writeIndex(Transition, "t.bin")
}

// pcr7Events returns the PCR 7 events of this boot if the TCG event log
// replays to the live PCR 7.
func (t *tpm) pcr7Events() ([]sbstate.Event, error) {
	log, err := os.ReadFile(t.c.EventLog)
	if err != nil {
		return nil, fmt.Errorf("TCG event log: %w", err)
	}
	evs, replay, err := sbstate.ParseLog(log, 7)
	if err != nil {
		return nil, err
	}
	live, err := ReadPCR(t.r, 7)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(replay, live) {
		return nil, fmt.Errorf("the TCG event log replays PCR 7 to %x, the TPM holds %x", replay, live)
	}
	return evs, nil
}

// updatable are the variables a release may update, as named in the event log.
var updatable = []string{"db-" + sbstate.GUIDSecurity, "dbx-" + sbstate.GUIDSecurity, "KEK-" + sbstate.GUIDGlobal}

// requireEventLog is the platform check of first provisioning and healing
// (B7): the firmware's event log must replay to PCR 7 and measure db, dbx
// and KEK exactly once each, as parseable signature lists. Otherwise a later
// signed Secure Boot update (the durable revocation of a release) could not
// be carried, so such a device is not enrolled.
func (t *tpm) requireEventLog() error {
	evs, err := t.pcr7Events()
	if err == nil {
		err = sbstate.HasVariables(evs, updatable)
	}
	if err == nil {
		_, err = sbstate.StateDigest(evs, updatable, nil)
	}
	if err != nil {
		return fmt.Errorf("this firmware cannot carry signed Secure Boot variable updates (dbx revocation), refusing to enrol the device: %w", err)
	}
	return nil
}

func (t *tpm) efi() sbstate.Vars {
	if t.c.EFI != nil {
		return t.c.EFI
	}
	return sbstate.EFIVarFS{Dir: "/sys/firmware/efi/efivars"}
}

// releaseUpdates loads the release's signed updates: all of them, those not
// yet in the firmware, the variables they touch and their signatures.
func (t *tpm) releaseUpdates() (all, todo []sbstate.Update, ids []string, add map[string][]sbstate.Signature, err error) {
	if all, err = sbstate.LoadUpdates(t.c.UpdatesDir); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("Secure Boot updates of this release: %w", err)
	}
	add = map[string][]sbstate.Signature{}
	for _, u := range all {
		if _, seen := add[u.ID()]; !seen {
			ids = append(ids, u.ID())
		}
		add[u.ID()] = append(add[u.ID()], u.Sigs...)
		cur, err := t.efi().Read(u.Var, u.GUID)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		done, err := u.Applied(cur)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if !done {
			todo = append(todo, u)
		}
	}
	return all, todo, ids, add, nil
}

// apply submits the updates to the firmware (which verifies their KEK/PK
// signature). It reports the failures and whether any variable changed.
func (t *tpm) apply(todo []sbstate.Update) (failed []string, changed bool) {
	for _, u := range todo {
		before, _ := t.efi().Read(u.Var, u.GUID)
		err := t.efi().Append(u.Var, u.GUID, u.Auth)
		after, rerr := t.efi().Read(u.Var, u.GUID)
		if rerr != nil || !bytes.Equal(before, after) {
			changed = true
		}
		if err == nil {
			if done, aerr := u.Applied(after); aerr != nil || !done {
				err = errors.New("the firmware accepted the write but the signatures are not in the variable")
			}
		}
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", u.File, err))
		}
	}
	return failed, changed
}

// checkBridge is the Secure Boot check of a boot in which index V binds the
// boot chain (PCR 0+2+4+12) instead of PCR 7. It runs BEFORE the volume key
// is read (B2) and needs nothing from the state volume: index T, written
// under policy P when the transition was armed, holds the digests of the
// only two Secure Boot states that may follow. The state of this boot, from
// the event log that replays to PCR 7, must be one of them:
//
//   - exactly the state before the update (the firmware has not taken it),
//   - exactly that state with the signatures of the release's signed updates
//     added to the updated variables (B3): nothing dropped, nothing else
//     added, Secure Boot on, PK/KEK/db and the signing authority unchanged.
//
// It returns whether the update is in the firmware.
func (t *tpm) checkBridge() (applied bool, err error) {
	ts, err := t.readTransition()
	if err != nil {
		return false, err
	}
	if ts.state != trArmed && ts.state != trApplied {
		return false, fmt.Errorf("PCR policy index binds the boot chain but no Secure Boot update is in transit (transition state %d)", ts.state)
	}
	evs, err := t.pcr7Events()
	if err != nil {
		return false, fmt.Errorf("Secure Boot update in transit: %w", err)
	}
	_, _, ids, _, err := t.releaseUpdates()
	if err != nil {
		return false, err
	}
	cur, err := sbstate.StateDigest(evs, ids, nil)
	if err != nil {
		return false, fmt.Errorf("Secure Boot update in transit: %w", err)
	}
	switch {
	case bytes.Equal(cur, ts.new):
		return true, nil
	case bytes.Equal(cur, ts.old):
		return false, nil
	}
	return false, fmt.Errorf("Secure Boot update in transit and the Secure Boot state of this boot (%x) is neither the state before the update (%x) nor exactly that state plus the signed update (%x): refusing before the volume key is read",
		cur, ts.old, ts.new)
}

// secureBootUpdates applies the signed Secure Boot variable updates shipped
// in /usr (dbx appends that revoke old UKIs, db/KEK appends) and moves the
// state volume's Secure Boot binding along (F3, B2, B3).
//
// A dbx/db/KEK change alters PCR 7 from the next boot on. Policy P does not
// hold PCR 7 itself: its PCR-bound part lives in index V.
//
//  1. Steady (V = PCR 7+12 of this boot), updates not yet in the firmware:
//     index T is armed with the digest of the current Secure Boot state and
//     the digest of that state plus the update; V is switched to PCR
//     0+2+4+12 (firmware code, option ROMs/drivers, every EFI binary on the
//     boot path, no ESP credentials); only then the updates are handed to
//     the firmware, and T is marked "applied". From the V write on, the old
//     PCR 7 alone opens nothing.
//  2. Next boot: checkBridge (before the volume key is read) accepts only
//     the two states pinned in T. If the update is in the firmware, V is set
//     to the new PCR 7+12 here and T is cleared.
//
// One shot: if an update that was marked applied is missing again (the
// variable store was rolled back), V returns to the old PCR 7 binding, T
// remembers "rolled back", and the transition is not armed again for this
// update. A power loss before the firmware took the update is retried; the
// boot chain binding never admits any other Secure Boot state.
func (t *tpm) secureBootUpdates() (string, error) {
	all, todo, ids, add, err := t.releaseUpdates()
	if err != nil {
		return "", err
	}
	total := len(all)
	ts, err := t.readTransition()
	if err != nil {
		return "", err
	}
	pending := func(failed []string) string {
		return fmt.Sprintf("pending: %d of %d update(s) handed to the firmware, reboot to complete%s", len(todo)-len(failed), total, failures(failed))
	}

	if t.mode == modeBridge {
		applied, err := t.checkBridge() // already passed in Unlock; needed for the decision here
		if err != nil {
			return "", err
		}
		if applied {
			if err := t.writePCRPolicy("v-steady.bin", modeSteady); err != nil {
				return "", err
			}
			if err := t.writeTransition(transState{}); err != nil {
				return "", err
			}
			if len(todo) > 0 {
				return "failed: NOT APPLIED: the firmware holds only part of the release's updates", nil
			}
			return fmt.Sprintf("current (%d update(s) in the firmware, Secure Boot state re-recorded after the update)", total), nil
		}
		if ts.state == trApplied {
			// the update was in the firmware and is gone: variable store rolled back
			if err := t.writePCRPolicy("v-steady.bin", modeSteady); err != nil {
				return "", err
			}
			ts.state = trRolledBack
			if err := t.writeTransition(ts); err != nil {
				return "", err
			}
			return "failed: NOT APPLIED: the firmware lost the update again (variable store rolled back); the transition is not opened again", nil
		}
		// armed, but the firmware never took it (power loss): hand it over again
		failed, changed := t.apply(todo)
		if changed {
			ts.state = trApplied
			if err := t.writeTransition(ts); err != nil {
				return "", err
			}
			return pending(failed), nil
		}
		if err := t.writePCRPolicy("v-steady.bin", modeSteady); err != nil {
			return "", err
		}
		if err := t.writeTransition(transState{}); err != nil {
			return "", err
		}
		return "failed" + failures(failed), nil
	}

	if len(todo) == 0 {
		if ts.state != trIdle {
			if err := t.writeTransition(transState{}); err != nil {
				return "", err
			}
		}
		return fmt.Sprintf("current (%d update(s) in the firmware)", total), nil
	}
	evs, err := t.pcr7Events()
	if err == nil {
		err = sbstate.HasVariables(evs, ids)
	}
	var old, next []byte
	if err == nil {
		old, err = sbstate.StateDigest(evs, ids, nil)
	}
	if err == nil {
		next, err = sbstate.StateDigest(evs, ids, add)
	}
	if err != nil {
		// cannot happen on an enrolled device unless the firmware changed (requireEventLog)
		return fmt.Sprintf("blocked: %d update(s) not applied, this firmware's PCR 7 log cannot carry the transition: %v", len(todo), err), nil
	}
	if ts.state == trRolledBack && bytes.Equal(ts.new, next) {
		return "failed: NOT APPLIED: the firmware lost this update before (variable store rolled back); the transition is not opened again", nil
	}
	if err := t.writeTransition(transState{old: old, new: next, state: trArmed}); err != nil {
		return "", err
	}
	if err := t.writePCRPolicy("v-bridge.bin", modeBridge); err != nil {
		return "", err
	}
	t.pause("pcr7-bridge")
	failed, changed := t.apply(todo)
	t.pause("pcr7-applied")
	if !changed {
		// the firmware took nothing: PCR 7 stays, return to the steady binding
		if err := t.writePCRPolicy("v-steady.bin", modeSteady); err != nil {
			return "", err
		}
		if err := t.writeTransition(transState{}); err != nil {
			return "", err
		}
		return "failed" + failures(failed), nil
	}
	if err := t.writeTransition(transState{old: old, new: next, state: trApplied}); err != nil {
		return "", err
	}
	return pending(failed), nil
}

func failures(f []string) string {
	if len(f) == 0 {
		return ""
	}
	return ": NOT APPLIED: " + strings.Join(f, "; ")
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
	if err := t.runtimeEK(); err != nil {
		return err
	}
	if pcr11, _, err := f.DecodeRef(t.id.Role, t.id.Profile, t.ref); err == nil {
		t.pcr11 = pcr11 // try the signed state even though PCR 11 moved on
	}
	if err := t.authorize(f); err != nil {
		return err
	}
	if err := t.pcrMode(); err != nil {
		return err
	}
	_, err = t.session(sessP, "", "tpm2_nvread", Secret.Handle, "-C", Secret.Handle, "-s", strconv.Itoa(Secret.Size), "-P")
	return err
}

// pauseHook is called at a test pause point (overridden in unit tests).
var pauseHook = func(string) { time.Sleep(time.Hour) }

// SaltName authenticates the persistent salt key (EK trust anchors and
// record A) and returns its Name and how it was authenticated (selftest).
func SaltName(c Config, r Runner) ([]byte, string, error) {
	t, err := newTPM(c, r)
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(c.work())
	if err := t.prepare(); err != nil {
		return nil, "", err
	}
	if err := t.recordedSalt(); err != nil {
		return nil, "", err
	}
	return t.salt.Name(), t.saltSource, nil
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
