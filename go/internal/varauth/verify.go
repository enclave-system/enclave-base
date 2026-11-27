package varauth

import (
	"bytes"
	"crypto/hmac"
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
	trust, err := t.loadEKTrust(st.nv)
	if err != nil {
		return "", err
	}
	provisioned, err := exists(c.ProvisionedFlag())
	if err != nil {
		return "", err
	}
	if provisioned {
		// (re-)provisioned in this boot by Unlock: pin the salt key now
		if err := t.useSalt(trust, nil); err != nil {
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
	if err := t.useSalt(trust, rd.SaltName); err != nil {
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
	var updates string
	if err := t.withState(func(root string) error {
		var verr error
		version, verr = (&statefs.Store{Root: root, Key: keys.MAC, Counter: counterRT{r, t.c.work(), keys.CounterAuth}}).Verify()
		if verr != nil {
			return verr
		}
		updates, verr = t.secureBootUpdates(root, keys.MAC)
		return verr
	}); err != nil {
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

// transition is kept in the state volume while index V binds the boot chain
// instead of PCR 7: the PCR 7 events before the update and the variables the
// release's signed updates may change.
type transition struct {
	Events []sbstate.Event `json:"events"`
	Vars   []string        `json:"vars"`
	MAC    string          `json:"mac,omitempty"`
}

func (tr transition) mac(key []byte) string {
	body, _ := json.Marshal(transition{Events: tr.Events, Vars: tr.Vars})
	h := hmac.New(sha256.New, key)
	h.Write([]byte("enklave-pcr7-transition-v1\x00"))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func writeSynced(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func removeSynced(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(path))
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

func (t *tpm) efi() sbstate.Vars {
	if t.c.EFI != nil {
		return t.c.EFI
	}
	return sbstate.EFIVarFS{Dir: "/sys/firmware/efi/efivars"}
}

// unapplied returns the release's updates whose signatures are not all in
// the firmware's variable yet.
func (t *tpm) unapplied() ([]sbstate.Update, int, error) {
	all, err := sbstate.LoadUpdates(t.c.UpdatesDir)
	if err != nil {
		return nil, 0, fmt.Errorf("Secure Boot updates of this release: %w", err)
	}
	var todo []sbstate.Update
	for _, u := range all {
		cur, err := t.efi().Read(u.Var, u.GUID)
		if err != nil {
			return nil, 0, err
		}
		done, err := u.Applied(cur)
		if err != nil {
			return nil, 0, err
		}
		if !done {
			todo = append(todo, u)
		}
	}
	return todo, len(all), nil
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

const transitionFile = ".pcr7"

// secureBootUpdates applies the signed Secure Boot variable updates shipped
// in /usr (dbx appends that revoke old UKIs, db/KEK appends) and moves the
// state volume's Secure Boot binding along (F3).
//
// A dbx/db/KEK change alters PCR 7 from the next boot on, by a value only
// the firmware determines. Policy P therefore does not hold PCR 7 itself:
// its PCR-bound part lives in index V, which an authorized boot rewrites:
//
//  1. Steady (V = PCR 7+12 of this boot), updates not yet in the firmware:
//     the PCR 7 events of this boot are stored in the state volume (MAC from
//     the volume key), V is switched to the *bridge* PCR 0+2+4+12 (firmware
//     code, option ROMs/drivers, every EFI binary on the boot path, no ESP
//     credentials), and only then the updates are handed to the firmware.
//     From this moment the old PCR 7 is no longer accepted by anything.
//  2. Next boot (bridge): the same firmware, boot loader and UKI started, so
//     only genuine code is running whatever the Secure Boot variables say.
//     It replays the event log against PCR 7 and requires the new PCR 7
//     events to equal the stored ones except for the content of the updated
//     variables: Secure Boot still on, PK/KEK/db and the signing authority
//     unchanged. Then V is set to the new PCR 7+12 and the bridge ends.
//
// A crash at any point leaves V satisfiable by the same boot chain, so the
// device is never bricked; a foreign Secure Boot configuration, firmware or
// loader satisfies neither binding. Devices whose firmware does not log the
// variable as expected keep their binding and report "blocked" (no brick).
func (t *tpm) secureBootUpdates(root string, macKey []byte) (string, error) {
	todo, total, err := t.unapplied()
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, transitionFile)
	var ids []string
	seen := map[string]bool{}
	for _, u := range todo {
		if !seen[u.ID()] {
			seen[u.ID()] = true
			ids = append(ids, u.ID())
		}
	}

	if t.mode == modeBridge {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("PCR 7 transition pending but its record is missing from the state volume: %w", err)
		}
		var tr transition
		if err := json.Unmarshal(b, &tr); err != nil || !hmac.Equal([]byte(tr.MAC), []byte(tr.mac(macKey))) {
			return "", errors.New("PCR 7 transition record is not authentic")
		}
		evs, err := t.pcr7Events()
		if err != nil {
			return "", fmt.Errorf("PCR 7 transition: %w", err)
		}
		if err := sbstate.Compare(tr.Events, evs, tr.Vars); err != nil {
			return "", fmt.Errorf("PCR 7 transition refused, the Secure Boot state changed beyond the signed updates: %w", err)
		}
		var failed []string
		if len(todo) > 0 {
			// interrupted before the firmware took the update: hand it over again
			var changed bool
			if failed, changed = t.apply(todo); changed {
				return fmt.Sprintf("pending: %d of %d update(s) handed to the firmware, reboot to complete%s", len(todo)-len(failed), total, failures(failed)), nil
			}
		}
		if err := t.writePCRPolicy("v-steady.bin", modeSteady); err != nil {
			return "", err
		}
		if err := removeSynced(path); err != nil {
			return "", err
		}
		if len(failed) > 0 {
			return "failed" + failures(failed), nil
		}
		return fmt.Sprintf("current (%d update(s) in the firmware, Secure Boot state re-recorded after the update)", total), nil
	}

	if err := removeSynced(path); err != nil { // stale record of a reverted transition
		return "", err
	}
	if len(todo) == 0 {
		return fmt.Sprintf("current (%d update(s) in the firmware)", total), nil
	}
	evs, err := t.pcr7Events()
	if err == nil {
		err = sbstate.HasVariables(evs, ids)
	}
	if err != nil {
		return fmt.Sprintf("blocked: %d update(s) not applied, this firmware's PCR 7 log cannot carry the transition: %v", len(todo), err), nil
	}
	tr := transition{Events: evs, Vars: ids}
	tr.MAC = tr.mac(macKey)
	b, _ := json.Marshal(tr)
	if err := writeSynced(path, b); err != nil {
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
		if err := removeSynced(path); err != nil {
			return "", err
		}
		return "failed" + failures(failed), nil
	}
	return fmt.Sprintf("pending: %d of %d update(s) handed to the firmware, reboot to complete%s", len(todo)-len(failed), total, failures(failed)), nil
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
	if pcr11, _, err := f.Decode(t.id.Role, t.id.Profile); err == nil {
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

// ReadCounter returns the TPM state counter (selftest). The session is
// salted to the salt key authenticated against the EK trust anchors and
// record A.
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
	if err := t.recordedSalt(); err != nil {
		return 0, err
	}
	return counterRT{r, c.work(), keys.CounterAuth}.Read()
}

// SaltName authenticates the persistent salt key (EK trust anchors and
// record A) and returns its Name and how it was authenticated (selftest).
func SaltName(c Config, r Runner) ([]byte, string, error) {
	t, err := newTPM(c, r)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(c.work(), 0o700); err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(c.work())
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
