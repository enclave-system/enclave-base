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

	"enclave.local/base/internal/sbstate"
	"enclave.local/base/internal/tpmpolicy"
	"enclave.local/base/internal/varauth"
)

// stateMount is where the encrypted persistent state volume is mounted.
const stateMount = "/var/lib/enclave"

// varConfig maps the varauth runtime paths below root.
func varConfig(root string) varauth.Config {
	c := varauth.DefaultConfig()
	c.RunDir = filepath.Join(root, "run/enclave")
	c.Work = filepath.Join(root, "run/enclave/selftest-work")
	c.PubKey = filepath.Join(root, "run/systemd/tpm2-pcr-public-key.pem")
	c.RoleFile = filepath.Join(root, "usr/lib/enclave/role")
	c.TestMarker = filepath.Join(root, "usr/lib/enclave/test-profile")
	c.ReleaseFile = filepath.Join(root, "usr/lib/enclave/release.json")
	c.StateRoot = filepath.Join(root, "var/lib/enclave")
	c.EKCADir = filepath.Join(root, "usr/share/enclave/tpm-ek-ca")
	c.EKTestCADir = filepath.Join(root, "usr/share/enclave/tpm-ek-ca-test")
	c.WritersDir = filepath.Join(root, "usr/lib/enclave/state-writers.d")
	c.UpdatesDir = filepath.Join(root, "usr/lib/enclave/efi-updates")
	c.EventLog = filepath.Join(root, "sys/kernel/security/tpm0/binary_bios_measurements")
	c.EFI = sbstate.EFIVarFS{Dir: filepath.Join(root, "sys/firmware/efi/efivars")}
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

// checkVarTPM: the volume is bound to the TPM through the enclave NV secret
// (no systemd-tpm2 token, which older UKIs could satisfy).
func checkVarTPM(root string, r Runner) (string, error) {
	dev, dump, err := luksDump(root, r)
	if err != nil {
		return "", err
	}
	if !strings.Contains(dump, "enclave-tpm2-nv") {
		return "", fmt.Errorf("no enclave-tpm2-nv token on %s", dev)
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
// policy (bound to this role/profile); the PCR policy index holds the Secure
// Boot state of this boot (or this boot chain during a signed variable
// update); record A matches the verified PCR 15 and the salt key; the salt
// key is the endorsement key certified by a TPM vendor CA (or allowlisted);
// and the measurement log replays to the live PCR 15 with the volume key of
// the mounted state volume as first event.
func checkVarAuthenticated(root string, r Runner) (string, error) {
	c := varConfig(root)
	p, err := varauth.ExpectedPolicies(c, r)
	if err != nil {
		return "", err
	}
	for _, ck := range []struct {
		ix     varauth.Index
		policy []byte
	}{{varauth.Record, p.P}, {varauth.Secret, p.P}, {varauth.Counter, p.PC}, {varauth.Epoch, p.PE}, {varauth.PCRPolicy, p.VAuth}, {varauth.Transition, p.VAuth}} {
		pub, err := varauth.ReadPublic(r, ck.ix)
		if err != nil {
			return "", err
		}
		if err := varauth.CheckPublic(ck.ix, pub, ck.ix.Final, ck.policy); err != nil {
			return "", err
		}
	}
	// V holds the exact Secure Boot state of this boot, or, while a signed
	// variable update is in transit, a list of exact states that includes it
	binding, err := varauth.PCRBinding(c, r)
	if err != nil {
		return "", err
	}
	b, err := varauth.ReadNV(r, varauth.Record)
	if err != nil {
		return "", err
	}
	rd, err := varauth.ParseRecord(b)
	if err != nil {
		return "", err
	}
	rec, err := readTrim(root, "run/enclave/var-authenticated")
	if err != nil {
		return "", err
	}
	if rec != hex.EncodeToString(rd.PCR15) {
		return "", fmt.Errorf("record PCR 15 %x, verified %s", rd.PCR15, rec)
	}
	salt, saltSource, err := varauth.SaltName(c, r)
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
	return fmt.Sprintf("NV indices pinned, policy bound to %s, record %s (provisioned at epoch %d), salt key = EK authenticated by %s, PCR 15 replayed (%d events, first %s)",
		binding, rec, rd.Epoch, saltSource, len(evs), first), nil
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

// StateCall talks to the state service (replaced in tests).
var StateCall = func(root string, req varauth.StateRequest) (varauth.StateReply, error) {
	return varauth.StateCall(varConfig(root), req, nil)
}

// checkVarRollback: the authenticated state manifest version equals the TPM
// counter and the version verified at boot. The state service answers (it
// alone holds the state keys); the key file must be gone from /run.
func checkVarRollback(root string, _ Runner) (string, error) {
	if err := mustNotExist(root, "run/enclave/state.key"); err != nil {
		return "", fmt.Errorf("state keys left in /run: %w", err)
	}
	rep, err := StateCall(root, varauth.StateRequest{Op: "status"})
	if err != nil {
		return "", err
	}
	if rep.Version != rep.Counter {
		return "", fmt.Errorf("state manifest version %d != TPM counter %d", rep.Version, rep.Counter)
	}
	rec, err := readTrim(root, "run/enclave/var-counter")
	if err != nil {
		return "", err
	}
	if rec != fmt.Sprint(rep.Counter) {
		return "", fmt.Errorf("verified version %q != TPM counter %d", rec, rep.Counter)
	}
	return fmt.Sprintf("state version %d", rep.Counter), nil
}

// checkTPMLocked: owner/endorsement/lockout auth set, Clear disabled, the
// platform hierarchy disabled (or held by firmware auth), dictionary-attack
// lockout disabled.
func checkTPMLocked(root string, r Runner) (string, error) {
	h, err := varauth.ReadHierarchy(r)
	if err != nil {
		return "", err
	}
	if !h.Locked() {
		return "", fmt.Errorf("TPM hierarchies not locked: %+v", h)
	}
	ps, err := readTrim(root, "run/enclave/platform")
	if err != nil {
		return "", err
	}
	switch {
	case !h.PhEnable && (ps == "disabled" || ps == "disabled-by-enclave"):
	case h.PhEnable && ps == "firmware-auth":
	default:
		return "", fmt.Errorf("platform hierarchy state %q with phEnable=%v", ps, h.PhEnable)
	}
	// The endorsement key (salt key) is DA protected; a TPM in lockout
	// refuses salted sessions. enclave disables the lockout (no enclave
	// secret is a guessable authValue).
	da, err := varauth.ReadDA(r)
	if err != nil {
		return "", err
	}
	if da.InLockout || da.Interval != 0 {
		return "", fmt.Errorf("TPM dictionary-attack lockout not disabled (in lockout: %v, counter %d of %d, recovery time %d s)",
			da.InLockout, da.Counter, da.MaxTries, da.Interval)
	}
	// B6: with the lockout off, nothing in the TPM may depend on it
	foreign, err := varauth.ForeignObjects(r)
	if err != nil {
		return "", err
	}
	if len(foreign) > 0 {
		return "", fmt.Errorf("TPM holds objects enclave does not account for (%s): with the DA lockout disabled their authValues are not protected against guessing", strings.Join(foreign, ", "))
	}
	return "ownerAuthSet lockoutAuthSet endorsementAuthSet disableClear, DA lockout disabled and no foreign TPM objects, platform " + ps, nil
}

// checkPCR11Sealed: PCR 11 has left every signed phase.
func checkPCR11Sealed(root string, r Runner) (string, error) {
	cur, err := varauth.CurrentPCR11Policy(varConfig(root), r)
	if err != nil {
		return "", err
	}
	signed, err := varauth.SignedPCR11Policies(filepath.Join(root, "run/systemd/tpm2-pcr-signature.json"),
		filepath.Join(root, "run/enclave/policy.json"))
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

// checkEFIUpdates: every signed Secure Boot variable update shipped by this
// release (dbx revocations, db/KEK appends) is in the firmware and no PCR 7
// transition is pending.
func checkEFIUpdates(root string, _ Runner) (string, error) {
	s, err := readTrim(root, "run/enclave/efi-updates")
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(s, "current") {
		return "", errors.New(s)
	}
	return s, nil
}

// checkStateReadOnly: the state volume is mounted read-only; only
// "enclave-varauth state-exec" writes it, in a private mount namespace.
func checkStateReadOnly(root string, _ Runner) (string, error) {
	m, err := findMount(root, stateMount)
	if err != nil {
		return "", err
	}
	for _, o := range strings.Split(m.opts, ",") {
		if o == "ro" {
			return m.opts, nil
		}
	}
	return "", fmt.Errorf("%s mounted with options %q, not ro", stateMount, m.opts)
}

// checkDevKeys reports whether the image was signed with a development PKI.
// It is informational (test-profile images are always dev-signed) unless
// forbidDev is set: production acceptance runs the selftest with
// --forbid-dev-keys and rejects such builds. A test-profile image that
// claims production keys is always an error (the build refuses to sign it).
func checkDevKeys(root string, forbidDev bool) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "usr/lib/enclave/release.json"))
	if err != nil {
		return "", err
	}
	var rel tpmpolicy.Release
	if err := json.Unmarshal(b, &rel); err != nil {
		return "", err
	}
	_, terr := os.Stat(filepath.Join(root, "usr/lib/enclave/test-profile"))
	test := terr == nil
	switch {
	case rel.DevKeys && forbidDev:
		return "", errors.New("DEV KEYS: development build signed with a DEV-KEYS PKI, must not be deployed")
	case rel.DevKeys:
		return "DEV KEYS (development build, never ship)", nil
	case test:
		return "", errors.New("test-profile image without the dev-key marker")
	}
	return "production keys", nil
}
