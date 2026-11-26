package selftest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"enklave.local/base/internal/varauth"
)

// stateMount is where the encrypted persistent state volume is mounted.
const stateMount = "/var/lib/enklave"

// varConfig maps the varauth runtime paths below root.
func varConfig(root string) varauth.Config {
	c := varauth.DefaultConfig()
	c.RunDir = filepath.Join(root, "run/enklave")
	c.Work = filepath.Join(root, "run/enklave/selftest-work")
	c.PubKey = filepath.Join(root, "run/systemd/tpm2-pcr-public-key.pem")
	c.RoleFile = filepath.Join(root, "usr/lib/enklave/role")
	c.TestMarker = filepath.Join(root, "usr/lib/enklave/test-profile")
	c.ReleaseFile = filepath.Join(root, "usr/lib/enklave/release.json")
	c.StateRoot = filepath.Join(root, "var/lib/enklave")
	return c
}

// varDevice returns the partition carrying the LUKS header below the state
// volume: dm-crypt -> (dm-integrity ->) partition.
func varDevice(root string) (string, error) {
	m, err := findMount(root, stateMount)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "sys/dev/block", m.majmin, "slaves")
	for depth := 0; depth < 4; depth++ {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return "", err
		}
		if len(ents) != 1 {
			return "", fmt.Errorf("%s has %d slaves, want 1", dir, len(ents))
		}
		name := ents[0].Name()
		if !strings.HasPrefix(name, "dm-") {
			return "/dev/" + name, nil
		}
		dir = filepath.Join(root, "sys/block", name, "slaves")
	}
	return "", errors.New("state device stack too deep")
}

func luksDump(root string, r Runner) (string, string, error) {
	dev, err := varDevice(root)
	if err != nil {
		return "", "", err
	}
	out, err := r.Run("cryptsetup", "luksDump", dev)
	if err != nil {
		return "", "", fmt.Errorf("cryptsetup luksDump %s: %w", dev, err)
	}
	return dev, string(out), nil
}

// checkVarTPM: the volume is bound to the TPM through the enklave NV secret
// (no systemd-tpm2 token, which older UKIs could satisfy).
func checkVarTPM(root string, r Runner) (string, error) {
	dev, dump, err := luksDump(root, r)
	if err != nil {
		return "", err
	}
	if !strings.Contains(dump, "enklave-tpm2-nv") {
		return "", fmt.Errorf("no enklave-tpm2-nv token on %s", dev)
	}
	if strings.Contains(dump, "systemd-tpm2") {
		return "", fmt.Errorf("unexpected systemd-tpm2 token on %s", dev)
	}
	p, err := varauth.ExpectedPolicies(varConfig(root), r)
	if err != nil {
		return "", err
	}
	pub, err := varauth.ReadPublic(r, varauth.Secret)
	if err != nil {
		return "", err
	}
	if err := varauth.CheckPublic(varauth.Secret, pub, varauth.Secret.Final, p.P); err != nil {
		return "", err
	}
	return dev, nil
}

// checkVarAuthenticated: every NV index has its pinned public area and
// policy (bound to this role/profile), record A matches the verified PCR 15
// and the salt key, and the measurement log replays to the live PCR 15 with
// the volume key of the mounted state volume as first event.
func checkVarAuthenticated(root string, r Runner) (string, error) {
	c := varConfig(root)
	p, err := varauth.ExpectedPolicies(c, r)
	if err != nil {
		return "", err
	}
	for _, ck := range []struct {
		ix     varauth.Index
		policy []byte
	}{{varauth.Record, p.P}, {varauth.Secret, p.P}, {varauth.Counter, p.PC}, {varauth.Epoch, p.PE}} {
		pub, err := varauth.ReadPublic(r, ck.ix)
		if err != nil {
			return "", err
		}
		if err := varauth.CheckPublic(ck.ix, pub, ck.ix.Final, ck.policy); err != nil {
			return "", err
		}
	}
	b, err := varauth.ReadNV(r, varauth.Record)
	if err != nil {
		return "", err
	}
	rd, err := varauth.ParseRecord(b)
	if err != nil {
		return "", err
	}
	rec, err := readTrim(root, "run/enklave/var-authenticated")
	if err != nil {
		return "", err
	}
	if rec != hex.EncodeToString(rd.PCR15) {
		return "", fmt.Errorf("record PCR 15 %x, verified %s", rd.PCR15, rec)
	}
	salt, err := varauth.SaltName(c, r)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(salt, rd.SaltName) {
		return "", fmt.Errorf("salt key Name %x != recorded %x", salt, rd.SaltName)
	}

	log, err := os.ReadFile(filepath.Join(root, "run/log/systemd/tpm2-measure.log"))
	if err != nil {
		return "", err
	}
	replay, evs, err := varauth.ReplayPCR(log, 15)
	if err != nil {
		return "", err
	}
	live, err := varauth.ReadPCR(r, 15)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(replay, live) {
		return "", fmt.Errorf("PCR 15 %x does not replay from the measurement log (%x)", live, replay)
	}
	if len(evs) == 0 {
		return "", errors.New("no PCR 15 events in the measurement log")
	}
	m, err := findMount(root, stateMount)
	if err != nil {
		return "", err
	}
	u, err := readTrim(root, "sys/dev/block/"+m.majmin+"/dm/uuid")
	if err != nil {
		return "", err
	}
	parts := strings.Split(u, "-") // CRYPT-LUKS2-<uuid hex>-var
	if len(parts) < 4 {
		return "", fmt.Errorf("unexpected dm uuid %q", u)
	}
	first := evs[0].Content.String
	name, uuid, ok := strings.Cut(strings.TrimPrefix(first, "cryptsetup:"), ":")
	if !strings.HasPrefix(first, "cryptsetup:") || !ok || name != "var" ||
		strings.ToLower(strings.ReplaceAll(uuid, "-", "")) != strings.ToLower(parts[2]) {
		return "", fmt.Errorf("first PCR 15 event %q is not the volume key of the mounted state volume (%s)", first, parts[2])
	}
	return fmt.Sprintf("NV indices pinned, record %s (provisioned at epoch %d), salt key pinned, PCR 15 replayed (%d events, first %s)",
		rec, rd.Epoch, len(evs), first), nil
}

// checkVarIntegrity: LUKS2 with authenticated encryption and argon2id.
func checkVarIntegrity(root string, r Runner) (string, error) {
	dev, dump, err := luksDump(root, r)
	if err != nil {
		return "", err
	}
	for _, want := range []string{"cipher: aes-xts-plain64", "integrity: hmac(sha256)", "PBKDF:      argon2id"} {
		if !strings.Contains(dump, want) {
			return "", fmt.Errorf("%s: luksDump lacks %q", dev, want)
		}
	}
	return "aes-xts-plain64 + hmac(sha256), argon2id", nil
}

// checkVarRollback: the authenticated state manifest version equals the TPM
// counter and the version verified at boot.
func checkVarRollback(root string, r Runner) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "var/lib/enklave/.manifest"))
	if err != nil {
		return "", err
	}
	var m struct {
		Version uint64 `json:"version"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return "", err
	}
	ctr, err := varauth.ReadCounter(varConfig(root), r)
	if err != nil {
		return "", err
	}
	if m.Version != ctr {
		return "", fmt.Errorf("state manifest version %d != TPM counter %d", m.Version, ctr)
	}
	rec, err := readTrim(root, "run/enklave/var-counter")
	if err != nil {
		return "", err
	}
	if rec != fmt.Sprint(ctr) {
		return "", fmt.Errorf("verified version %q != TPM counter %d", rec, ctr)
	}
	return fmt.Sprintf("state version %d", ctr), nil
}

// checkTPMLocked: owner/endorsement/lockout auth set, Clear disabled, the
// platform hierarchy disabled (or held by firmware auth).
func checkTPMLocked(root string, r Runner) (string, error) {
	h, err := varauth.ReadHierarchy(r)
	if err != nil {
		return "", err
	}
	if !h.Locked() {
		return "", fmt.Errorf("TPM hierarchies not locked: %+v", h)
	}
	ps, err := readTrim(root, "run/enklave/platform")
	if err != nil {
		return "", err
	}
	switch {
	case !h.PhEnable && (ps == "disabled" || ps == "disabled-by-enklave"):
	case h.PhEnable && ps == "firmware-auth":
	default:
		return "", fmt.Errorf("platform hierarchy state %q with phEnable=%v", ps, h.PhEnable)
	}
	return "ownerAuthSet lockoutAuthSet endorsementAuthSet disableClear, platform " + ps, nil
}

// checkPCR11Sealed: PCR 11 has left every signed phase.
func checkPCR11Sealed(root string, r Runner) (string, error) {
	cur, err := varauth.CurrentPCR11Policy(varConfig(root), r)
	if err != nil {
		return "", err
	}
	signed, err := varauth.SignedPCR11Policies(filepath.Join(root, "run/systemd/tpm2-pcr-signature.json"),
		filepath.Join(root, "run/enklave/policy.json"))
	if err != nil {
		return "", err
	}
	for _, s := range signed {
		if strings.EqualFold(s, hex.EncodeToString(cur)) {
			return "", fmt.Errorf("PCR 11 still satisfies a signed policy (%s)", s)
		}
	}
	return fmt.Sprintf("current PCR 11 policy %x matches none of %d signed", cur, len(signed)), nil
}
