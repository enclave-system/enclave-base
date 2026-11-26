package selftest

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"enklave.local/base/internal/varauth"
)

// varConfig maps the varauth runtime paths below root.
func varConfig(root string) varauth.Config {
	c := varauth.DefaultConfig()
	c.RunDir = filepath.Join(root, "run/enklave/selftest")
	c.PubKey = filepath.Join(root, "run/systemd/tpm2-pcr-public-key.pem")
	return c
}

// varDevice returns the partition carrying the LUKS header below /var:
// /var -> dm-crypt -> (dm-integrity ->) partition.
func varDevice(root string) (string, error) {
	m, err := findMount(root, "/var")
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
	return "", errors.New("/var device stack too deep")
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

// checkVarTPM: /var is bound to the TPM through the enklave NV secret (and
// not through a systemd-tpm2 token, which older UKIs signed with the same PCR
// key could satisfy).
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
	p, _, err := varauth.ExpectedPolicies(varConfig(root), r)
	if err != nil {
		return "", err
	}
	pub, err := varauth.ReadPublic(r, varauth.Secret)
	if err != nil {
		return "", err
	}
	if err := varauth.CheckPublic(varauth.Secret, pub, varauth.Secret.Final, p); err != nil {
		return "", err
	}
	return dev, nil
}

// checkVarAuthenticated: every NV index has the pinned public area and
// authPolicy; the record equals the PCR 15 value verified before mount; the
// measurement log replays to the live PCR 15 and starts with the volume key
// measurement of the mounted /var.
func checkVarAuthenticated(root string, r Runner) (string, error) {
	p, pe, err := varauth.ExpectedPolicies(varConfig(root), r)
	if err != nil {
		return "", err
	}
	for _, ix := range []varauth.Index{varauth.Record, varauth.Secret, varauth.Counter, varauth.Epoch} {
		want := p
		if ix == varauth.Epoch {
			want = pe
		}
		pub, err := varauth.ReadPublic(r, ix)
		if err != nil {
			return "", err
		}
		if err := varauth.CheckPublic(ix, pub, ix.Final, want); err != nil {
			return "", err
		}
	}
	nv, err := varauth.ReadNV(r, varauth.Record)
	if err != nil {
		return "", err
	}
	rec, err := readTrim(root, "run/enklave/var-authenticated")
	if err != nil {
		return "", err
	}
	if rec != hex.EncodeToString(nv) {
		return "", fmt.Errorf("NV record holds %x, verified PCR 15 was %s", nv, rec)
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
	m, err := findMount(root, "/var")
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
	luksUUID := strings.ToLower(parts[2])
	first := evs[0].Content.String
	name, uuid, ok := strings.Cut(strings.TrimPrefix(first, "cryptsetup:"), ":")
	if !strings.HasPrefix(first, "cryptsetup:") || !ok || name != "var" ||
		strings.ToLower(strings.ReplaceAll(uuid, "-", "")) != luksUUID {
		return "", fmt.Errorf("first PCR 15 event %q is not the volume key of the mounted /var (%s)", first, luksUUID)
	}
	return fmt.Sprintf("NV indices pinned, record %s, PCR 15 replayed (%d events, first %s)", rec, len(evs), first), nil
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

// checkVarRollback: the anti-rollback value in /var equals the TPM counter.
func checkVarRollback(root string, r Runner) (string, error) {
	f, err := readTrim(root, "var/lib/enklave/rollback-counter")
	if err != nil {
		return "", err
	}
	b, err := varauth.ReadNV(r, varauth.Counter)
	if err != nil {
		return "", err
	}
	c := fmt.Sprint(binary.BigEndian.Uint64(b))
	if f != c {
		return "", fmt.Errorf("/var counter %s != TPM counter %s", f, c)
	}
	if rec, err := readTrim(root, "run/enklave/var-counter"); err != nil || rec != c {
		return "", fmt.Errorf("verified counter %q != TPM counter %s (%v)", rec, c, err)
	}
	return "counter " + c, nil
}

// checkTPMLocked: owner/endorsement/lockout auth set, TPM2_Clear disabled.
func checkTPMLocked(_ string, r Runner) (string, error) {
	h, err := varauth.ReadHierarchy(r)
	if err != nil {
		return "", err
	}
	if !h.Locked() {
		return "", fmt.Errorf("TPM hierarchies not locked: %+v", h)
	}
	return "ownerAuthSet lockoutAuthSet endorsementAuthSet disableClear", nil
}

// checkPCR11Sealed: after boot, PCR 11 has moved past every signed phase, so
// no signed policy (systemd's .pcrsig or the enklave approved policy) can be
// satisfied any more.
func checkPCR11Sealed(root string, r Runner) (string, error) {
	cur, err := varauth.CurrentPCR11Policy(varConfig(root), r)
	if err != nil {
		return "", err
	}
	var signed []string
	if b, err := os.ReadFile(filepath.Join(root, "run/systemd/tpm2-pcr-signature.json")); err == nil {
		var doc map[string][]struct {
			Pol string `json:"pol"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return "", fmt.Errorf("parse tpm2-pcr-signature.json: %w", err)
		}
		for _, e := range doc["sha256"] {
			signed = append(signed, e.Pol)
		}
	} else {
		return "", err
	}
	if b, err := os.ReadFile(filepath.Join(root, "run/enklave/policy.json")); err == nil {
		var f struct {
			PCR11Policy string `json:"pcr11_policy"`
		}
		if err := json.Unmarshal(b, &f); err != nil {
			return "", err
		}
		signed = append(signed, f.PCR11Policy)
	} else {
		return "", err
	}
	if len(signed) == 0 {
		return "", errors.New("no signed PCR 11 policies found")
	}
	for _, s := range signed {
		if strings.EqualFold(s, hex.EncodeToString(cur)) {
			return "", fmt.Errorf("PCR 11 still satisfies a signed policy (%s)", s)
		}
	}
	return fmt.Sprintf("current PCR 11 policy %x matches none of %d signed", cur, len(signed)), nil
}
