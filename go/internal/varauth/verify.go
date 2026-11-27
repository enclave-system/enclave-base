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

	"enclave.local/base/internal/sbstate"
	"enclave.local/base/internal/statefs"
	"enclave.local/base/internal/tpmpolicy"
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
	if err := WriteUpdateStatus(c, updates); err != nil {
		return "", err
	}
	dev := ""
	if t.id.Release.DevKeys {
		dev = "; DEV KEYS (development build, never ship)"
	}
	return fmt.Sprintf("state volume verified: record %s (PCR 15 %x, provisioned at epoch %d), state version %d, %s/%s epoch %d, TPM locked, Secure Boot updates: %s%s",
		Record.Handle, pcr15, rd.Epoch, version, t.id.Role, t.id.Profile, t.epoch, updates, dev), nil
}

// UpdateStatus is the status of the release's signed Secure Boot variable
// updates as every local user and the console can read it (G9):
// <StatusDir>/secure-boot-updates.json. Status is "current", "pending"
// (reboot to complete), "failed" or "blocked"; with the last two a
// revocation shipped by this release is NOT in place.
type UpdateStatus struct {
	Status string `json:"status"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// ParseUpdateStatus splits the status line of secureBootUpdates.
func ParseUpdateStatus(line string) UpdateStatus {
	line = strings.TrimSpace(line)
	s := line
	if i := strings.IndexAny(line, " :"); i > 0 {
		s = line[:i]
	}
	return UpdateStatus{Status: s, OK: s == "current" || s == "pending", Detail: line}
}

// WriteUpdateStatus publishes the status outside the root-only run directory.
func WriteUpdateStatus(c Config, line string) error {
	if c.StatusDir == "" {
		return nil
	}
	if err := os.MkdirAll(c.StatusDir, 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(ParseUpdateStatus(line))
	if err != nil {
		return err
	}
	tmp := filepath.Join(c.StatusDir, ".secure-boot-updates.json.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.StatusDir, "secure-boot-updates.json"))
}

// ---------------------------------------------------------------- Secure Boot variable updates

// Index T (transition record). Layout:
//
//	[0]        state: 0 idle, 1 armed (index V holds a PolicyOR over a branch list)
//	[1]        1: an update of this transition was seen in the firmware variable
//	[2:98]     canonical digests (sbstate.StateDigest) of the Secure Boot state
//	           before the transition, before the update in flight, after it
//	[98:227]   branch list V holds (count, 4 digests)
//	[227:356]  branch list V is being switched to (count, 4 digests)
//	[356:493]  per-update record (count, 8 x (16-byte id, counter))
//
// A branch is the policy digest PolicyAuthorize(key, ref) + PolicyPCR(7, 12)
// for one exact PCR 7 value. Branch 0 is always the state before the
// transition.
//
// The per-update record is monotonic (G1): the counter of an update goes up
// every time the transition is armed for it, and to "seen" once the firmware
// variable held it. An entry is removed only while the firmware holds the
// update and V is bound to that very Secure Boot state. No release, with or
// without updates, clears it otherwise.
const (
	trIdle  = 0
	trArmed = 1

	maxBranches  = 4
	maxSeen      = 8
	seenInFW     = 0xFF // the firmware variable held this update once
	maxArmCount  = 3    // arming attempts per update that the firmware did not take
	trOffCur     = 98
	trOffNext    = 227
	trOffSeen    = 356
	trSeenRecord = 17
)

type seenEntry struct {
	id [16]byte
	n  byte
}

// transState is the content of index T.
type transState struct {
	state          byte
	applied        bool
	old, prev, new []byte
	cur, next      [][]byte
	seen           []seenEntry
}

func putList(b []byte, l [][]byte) {
	b[0] = byte(len(l))
	for i, d := range l {
		copy(b[1+32*i:], d)
	}
}

func getList(b []byte) ([][]byte, error) {
	if int(b[0]) > maxBranches {
		return nil, errors.New("transition index: bad branch count")
	}
	var l [][]byte
	for i := 0; i < int(b[0]); i++ {
		l = append(l, append([]byte{}, b[1+32*i:33+32*i]...))
	}
	return l, nil
}

func (ts transState) bytes() []byte {
	b := make([]byte, Transition.Size)
	b[0] = ts.state
	if ts.applied {
		b[1] = 1
	}
	copy(b[2:], ts.old)
	copy(b[34:], ts.prev)
	copy(b[66:], ts.new)
	putList(b[trOffCur:], ts.cur)
	putList(b[trOffNext:], ts.next)
	b[trOffSeen] = byte(len(ts.seen))
	for i, e := range ts.seen {
		copy(b[trOffSeen+1+trSeenRecord*i:], e.id[:])
		b[trOffSeen+1+trSeenRecord*i+16] = e.n
	}
	return b
}

func parseTransition(b []byte) (transState, error) {
	if len(b) != Transition.Size {
		return transState{}, fmt.Errorf("transition index: %d bytes", len(b))
	}
	ts := transState{state: b[0], applied: b[1] == 1, old: b[2:34], prev: b[34:66], new: b[66:98]}
	var err error
	if ts.cur, err = getList(b[trOffCur:]); err != nil {
		return ts, err
	}
	if ts.next, err = getList(b[trOffNext:]); err != nil {
		return ts, err
	}
	if ts.state > trArmed || int(b[trOffSeen]) > maxSeen {
		return ts, errors.New("transition index: bad content")
	}
	for i := 0; i < int(b[trOffSeen]); i++ {
		var e seenEntry
		copy(e.id[:], b[trOffSeen+1+trSeenRecord*i:])
		e.n = b[trOffSeen+1+trSeenRecord*i+16]
		ts.seen = append(ts.seen, e)
	}
	return ts, nil
}

// idle ends a transition. The per-update record stays.
func (ts *transState) idle() {
	*ts = transState{seen: ts.seen}
}

func (ts *transState) entry(id [16]byte) *seenEntry {
	for i := range ts.seen {
		if ts.seen[i].id == id {
			return &ts.seen[i]
		}
	}
	return nil
}

func (ts *transState) drop(id [16]byte) bool {
	for i := range ts.seen {
		if ts.seen[i].id == id {
			ts.seen = append(ts.seen[:i], ts.seen[i+1:]...)
			return true
		}
	}
	return false
}

func updateID(u sbstate.Update) (id [16]byte) {
	s := sha256.Sum256(u.Auth)
	copy(id[:], s[:])
	return id
}

func (t *tpm) readTransition() (transState, error) {
	if err := t.checkIndex(Transition, Transition.Final, t.b1); err != nil {
		return transState{}, err
	}
	b, err := ReadNV(t.r, Transition)
	if err != nil {
		return transState{}, err
	}
	return parseTransition(b)
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

// measured checks that this firmware can carry a signed Secure Boot update
// under a TPM-enforced binding: the event log replays to PCR 7, db, dbx and
// KEK are measured exactly once each as signature lists, and each is
// measured verbatim, so that the PCR 7 value after an update can be computed
// in advance (G3). It returns the events and the variables' content.
func (t *tpm) measured() ([]sbstate.Event, map[string][]byte, error) {
	evs, err := t.pcr7Events()
	if err != nil {
		return nil, nil, err
	}
	if err := sbstate.HasVariables(evs, updatable); err != nil {
		return nil, nil, err
	}
	if _, err := sbstate.StateDigest(evs, updatable, nil); err != nil {
		return nil, nil, err
	}
	content, err := sbstate.Verbatim(evs, updatable, t.efi())
	if err != nil {
		return nil, nil, err
	}
	p, err := sbstate.Predict(evs, content)
	if err != nil {
		return nil, nil, err
	}
	live, err := ReadPCR(t.r, 7)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(p, live) {
		return nil, nil, errors.New("PCR 7 cannot be recomputed from the measured variables")
	}
	return evs, content, nil
}

// requireEventLog is the platform check of first provisioning and healing
// (B7, G3). A device whose firmware could not carry a later signed Secure
// Boot update (the durable revocation of a release) under a TPM-enforced
// PCR 7 binding is not enrolled.
func (t *tpm) requireEventLog() error {
	if _, _, err := t.measured(); err != nil {
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

// releaseUpdates loads the release's signed updates: all of them and those
// not yet in the firmware.
func (t *tpm) releaseUpdates() (all, todo []sbstate.Update, err error) {
	if all, err = sbstate.LoadUpdates(t.c.UpdatesDir); err != nil {
		return nil, nil, fmt.Errorf("Secure Boot updates of this release: %w", err)
	}
	for _, u := range all {
		cur, err := t.efi().Read(u.Var, u.GUID)
		if err != nil {
			return nil, nil, err
		}
		done, err := u.Applied(cur)
		if err != nil {
			return nil, nil, err
		}
		if !done {
			todo = append(todo, u)
		}
	}
	return all, todo, nil
}

// branchFor returns the policy branch (PolicyAuthorize + PolicyPCR(7,12))
// for the PCR 7 value that the events of this boot give with the variables'
// content replaced.
func (t *tpm) branchFor(evs []sbstate.Event, content map[string][]byte) ([]byte, error) {
	pcr7, err := sbstate.Predict(evs, content)
	if err != nil {
		return nil, err
	}
	pcr12, err := ReadPCR(t.r, 12)
	if err != nil {
		return nil, err
	}
	if err := t.put("pcrs-pred.bin", append(pcr7, pcr12...)); err != nil {
		return nil, err
	}
	return t.trial([]string{"tpm2_policyauthorize", "-n", t.w("key.name"), "-q", t.w("ref.bin")},
		[]string{"tpm2_policypcr", "-l", selSteady, "-f", t.w("pcrs-pred.bin")})
}

// checkBridge is the software check of a boot in which index V holds a
// branch list (a signed Secure Boot update is in transit). It runs BEFORE
// the volume key is read (B2) and needs nothing from the state volume.
//
// The TPM itself already enforces the binding (G3): V authorizes exactly
// the PCR 7 values of the branch list, and no session of another Secure
// Boot state satisfies policy P. This check is the second, independent one:
// the Secure Boot state of this boot, from the event log that replays to
// PCR 7, must be one of the states index T pins:
//
//   - exactly the state before the transition,
//   - exactly the state before the update in flight,
//   - exactly that state with the signatures of that signed update added
//     (B3): nothing dropped, nothing else added, Secure Boot on, PK/KEK/db
//     and the signing authority unchanged.
func (t *tpm) checkBridge() error {
	ts, err := t.readTransition()
	if err != nil {
		return err
	}
	if ts.state != trArmed {
		return fmt.Errorf("PCR policy index holds a transition but no Secure Boot update is in transit (transition state %d)", ts.state)
	}
	evs, err := t.pcr7Events()
	if err != nil {
		return fmt.Errorf("Secure Boot update in transit: %w", err)
	}
	cur, err := sbstate.StateDigest(evs, updatable, nil)
	if err != nil {
		return fmt.Errorf("Secure Boot update in transit: %w", err)
	}
	for _, d := range [][]byte{ts.old, ts.prev, ts.new} {
		if bytes.Equal(cur, d) {
			return nil
		}
	}
	return fmt.Errorf("Secure Boot update in transit and the Secure Boot state of this boot (%x) is neither the state before the update (%x) nor exactly that state plus the signed update (%x): refusing before the volume key is read",
		cur, ts.old, ts.new)
}

func uniqueDigests(ds ...[]byte) [][]byte {
	var out [][]byte
	for _, d := range ds {
		dup := false
		for _, o := range out {
			dup = dup || bytes.Equal(o, d)
		}
		if !dup {
			out = append(out, d)
		}
	}
	return out
}

// secureBootUpdates applies the signed Secure Boot variable updates shipped
// in /usr (dbx appends that revoke old UKIs, db/KEK appends) and moves the
// state volume's Secure Boot binding along (F3, B2, B3, G1, G2, G3).
//
// A dbx/db/KEK change alters PCR 7 from the next boot on. Policy P does not
// hold PCR 7 itself: its PCR-bound part lives in index V.
//
// For each update, one at a time:
//
//  1. The PCR 7 value of the next boot is computed in advance: the events
//     of this boot with the variable's content replaced by "content plus
//     the update" (as edk2 stores it, and as a plain append).
//  2. Index T records the transition, then V is set to a PolicyOR over the
//     exact branches: the state before the transition, the current state,
//     and the computed ones. The TPM accepts no other PCR 7 value; there is
//     no moment in which PCR 7 is not bound.
//  3. The update is handed to the firmware and the variable is read back.
//     If it did not change, the update was refused: nothing is pending for
//     it. If it changed, it must hold exactly the old signatures plus the
//     update's, and V is narrowed to "before the transition" and the exact
//     value computed from what was read back. The record of what the
//     firmware took is what was read back, never what was sent (G2).
//
// The next boot comes up in one of the bound states. With the new state, V
// is set to it alone. With the old state after the firmware had held an
// update, the variable store was rolled back: V returns to the old state
// alone and the update is never armed again (the per-update record in T is
// monotonic, G1).
func (t *tpm) secureBootUpdates() (string, error) {
	all, todo, err := t.releaseUpdates()
	if err != nil {
		return "", err
	}
	total := len(all)
	ts, err := t.readTransition()
	if err != nil {
		return "", err
	}
	completed := false
	switch {
	case t.mode == modeBridge:
		rolledBack := bytes.Equal(t.plit, t.branches[0]) && ts.applied
		completed = !bytes.Equal(t.plit, t.branches[0])
		if err := t.writeSteady(); err != nil {
			return "", err
		}
		ts.idle()
		if err := t.writeTransition(ts); err != nil {
			return "", err
		}
		if rolledBack {
			return "failed: NOT APPLIED: the firmware lost the update again (variable store rolled back); the transition is not opened again", nil
		}
	case ts.state != trIdle:
		// V was already set back in an interrupted boot
		ts.idle()
		if err := t.writeTransition(ts); err != nil {
			return "", err
		}
	}
	// V is bound to the Secure Boot state of this boot alone. Updates the
	// firmware holds need no record any more.
	dropped := false
	for _, u := range all {
		in := true
		for _, o := range todo {
			in = in && o.File != u.File
		}
		if in && ts.drop(updateID(u)) {
			dropped = true
		}
	}
	if dropped {
		if err := t.writeTransition(ts); err != nil {
			return "", err
		}
	}
	if len(todo) == 0 {
		if completed {
			return fmt.Sprintf("current (%d update(s) in the firmware, Secure Boot state re-recorded after the update)", total), nil
		}
		return fmt.Sprintf("current (%d update(s) in the firmware)", total), nil
	}
	var failed []string
	var allowed []sbstate.Update
	fresh := 0 // updates that will need a new record entry
	for _, u := range todo {
		e := ts.entry(updateID(u))
		switch {
		case e != nil && e.n == seenInFW:
			failed = append(failed, u.File+": the firmware lost this update before (variable store rolled back); the transition is not opened again")
		case e != nil && e.n >= maxArmCount:
			failed = append(failed, fmt.Sprintf("%s: armed %d times and never taken by the firmware; not armed again", u.File, e.n))
		case e == nil && len(ts.seen)+fresh >= maxSeen:
			failed = append(failed, u.File+": the transition record is full")
		default:
			allowed = append(allowed, u)
			if e == nil {
				fresh++
			}
		}
	}
	if len(allowed) == 0 {
		return "failed" + failures(failed), nil
	}
	evs, content, err := t.measured()
	if err != nil {
		// cannot happen on an enrolled device unless the firmware changed (requireEventLog)
		return fmt.Sprintf("blocked: %d update(s) not applied, this firmware's PCR 7 log cannot carry the transition: %v", len(todo), err), nil
	}
	old, err := sbstate.StateDigest(evs, updatable, nil)
	if err != nil {
		return "", err
	}
	s0, exact, prevSet := t.plit, t.plit, old
	add := map[string][]sbstate.Signature{}
	taken, wide := 0, false
	var notes []string
	for _, u := range allowed {
		id := updateID(u)
		cur := content[u.ID()]
		payload, err := sbstate.AuthPayload(u.Auth)
		if err != nil {
			return "", err
		}
		cands, err := sbstate.AppendCandidates(cur, payload)
		if err != nil {
			return "", err
		}
		list := [][]byte{s0, exact}
		for _, c := range cands {
			content[u.ID()] = c
			b, err := t.branchFor(evs, content)
			if err != nil {
				return "", err
			}
			list = append(list, b)
		}
		content[u.ID()] = cur
		list = uniqueDigests(list...)
		add2 := map[string][]sbstate.Signature{}
		for k, v := range add {
			add2[k] = v
		}
		add2[u.ID()] = append(append([]sbstate.Signature{}, add[u.ID()]...), u.Sigs...)
		newSet, err := sbstate.StateDigest(evs, updatable, add2)
		if err != nil {
			return "", err
		}
		// the record entry exists from the moment the transition is armed
		// for this update, and only as long as it says something
		if ts.entry(id) == nil {
			ts.seen = append(ts.seen, seenEntry{id: id})
		}
		ts.entry(id).n++
		ts.state, ts.old, ts.prev, ts.new = trArmed, old, prevSet, newSet
		ts.cur, ts.next = t.branches, list
		if err := t.writeTransition(ts); err != nil {
			return "", err
		}
		if err := t.writeBridge(list); err != nil {
			return "", err
		}
		wide = true
		t.pause("pcr7-bridge")
		aerr := t.efi().Append(u.Var, u.GUID, u.Auth)
		after, err := t.efi().Read(u.Var, u.GUID)
		if err != nil {
			return "", err
		}
		t.pause("pcr7-applied")
		if bytes.Equal(after, cur) {
			// refused by the firmware: this arming opened nothing
			if e := ts.entry(id); e.n <= 1 {
				ts.drop(id)
			} else {
				e.n--
			}
			if aerr == nil {
				aerr = errors.New("the firmware accepted the write but left the variable unchanged")
			}
			failed = append(failed, fmt.Sprintf("%s: %v", u.File, aerr))
			continue
		}
		ok, err := sbstate.ExactlyAdded(cur, after, u.Sigs)
		if err != nil || !ok {
			return "", fmt.Errorf("after the signed update %s the firmware variable %s does not hold exactly its old signatures plus the update's (%v): not accepted as a Secure Boot state", u.File, u.Var, err)
		}
		content[u.ID()] = after
		if exact, err = t.branchFor(evs, content); err != nil {
			return "", err
		}
		predicted := false
		for _, b := range list {
			predicted = predicted || bytes.Equal(b, exact)
		}
		if !predicted {
			// handled (V is narrowed to the value read back below), but the
			// hardware model stores appends in a third form: report it
			notes = append(notes, u.File+": stored by the firmware in a form that was not predicted")
		}
		add, prevSet = add2, newSet
		taken++
		ts.entry(id).n = seenInFW
		ts.applied = true
		ts.prev, ts.cur, ts.next = newSet, t.branches, [][]byte{s0, exact}
		if err := t.writeTransition(ts); err != nil {
			return "", err
		}
		if err := t.writeBridge(ts.next); err != nil {
			return "", err
		}
		wide = false
	}
	if taken == 0 {
		// the firmware took nothing: PCR 7 stays, back to the binding of this boot
		if err := t.writeSteady(); err != nil {
			return "", err
		}
		ts.idle()
		if err := t.writeTransition(ts); err != nil {
			return "", err
		}
		return "failed" + failures(failed), nil
	}
	if wide {
		ts.new, ts.cur, ts.next = ts.prev, t.branches, [][]byte{s0, exact}
		if err := t.writeTransition(ts); err != nil {
			return "", err
		}
		if err := t.writeBridge(ts.next); err != nil {
			return "", err
		}
	}
	note := ""
	if len(notes) > 0 {
		note = "; note: " + strings.Join(notes, "; ")
	}
	return fmt.Sprintf("pending: %d of %d update(s) handed to the firmware, reboot to complete%s%s", taken, total, failures(failed), note), nil
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
// (systemd's .pcrsig and the enclave approved policy).
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
