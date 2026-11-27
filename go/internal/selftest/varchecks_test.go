package selftest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enklave.local/base/internal/ekcert"
	"enklave.local/base/internal/tpmpolicy"
	"enklave.local/base/internal/varauth"
)

const (
	luksDumpCmd   = "cryptsetup luksDump /dev/vda8"
	recordReadCmd = "tpm2_nvread 0x01800E01 -C 0x01800E01 -s 74"
	hierCmd       = "tpm2_getcap properties-variable"
	luksUUID      = "6f2fbea9-8c8b-4fd0-afd1-ce8615ab7632"

	pcrPolicyReadCmd = "tpm2_nvread 0x01800E05 -C 0x01800E05 -s 34"
	ekCertReadCmd    = "tpm2_nvread 0x01C0000A -C 0x01C0000A"

	goodLuksDump = "LUKS header information\nVersion:       \t2\nData segments:\n  0: crypt\n\toffset: 16777216 [bytes]\n" +
		"\tcipher: aes-xts-plain64\n\tsector: 512 [bytes]\n\tintegrity: hmac(sha256)\n" +
		"Keyslots:\n  0: luks2\n\tKey:        768 bits\n\tCipher:     aes-xts-plain64\n\tCipher key: 512 bits\n\tPBKDF:      argon2id\n" +
		"Tokens:\n  0: enklave-tpm2-nv\n\tKeyslot:    0\nDigests:\n"
	lockedHier = "TPM2_PT_PERMANENT:\n  ownerAuthSet:              1\n  endorsementAuthSet:        1\n  lockoutAuthSet:            1\n" +
		"  reserved1:                 0\n  disableClear:              1\n  inLockout:                 0\nTPM2_PT_STARTUP_CLEAR:\n  phEnable:                  1\n" +
		"TPM2_PT_LOCKOUT_COUNTER: 0x0\nTPM2_PT_MAX_AUTH_FAIL: 0x3\nTPM2_PT_LOCKOUT_INTERVAL: 0x0\nTPM2_PT_LOCKOUT_RECOVERY: 0x3E8\n"
)

var (
	// trial-session outputs of the fake runner
	fakeB1    = strings.Repeat("11", 32) // PolicyAuthorize(key, ref) = authPolicy of index V
	fakeAV    = strings.Repeat("33", 32)
	fakeLit   = strings.Repeat("aa", 32) // ... + PolicyPCR(7,12) of this boot
	fakePE    = strings.Repeat("bb", 32)
	fakePol11 = strings.Repeat("cc", 32) // current PCR 11 policy (after boot)
	// computed locally by varauth: P = PolicyAuthorizeNV(Name(V)), counter policy
	fakeP, fakePC = expectedPolicies()
	counter42     = "\x00\x00\x00\x00\x00\x00\x00\x2a"

	// endorsement key of the fake TPM, certified by a fake vendor CA
	ekKey, ekCA, ekCert = newEK()
	otherEK, _, _       = newEK()
	saltName            = string(ekKey.Name())
	recordVal           = strings.Repeat("\x15", 32) + "\x00\x00\x00\x00\x00\x00\x00\x00" + saltName
)

func unhex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func expectedPolicies() (string, string) {
	p := tpmpolicy.PolicyAuthorizeNV(tpmpolicy.NVName(0x01800E05, 0x22040002, unhex(fakeB1), 34))
	pc := tpmpolicy.PolicyOR(tpmpolicy.PolicyCommandCode(p, tpmpolicy.CCNVChangeAuth), unhex(fakeAV))
	return hex.EncodeToString(p), hex.EncodeToString(pc)
}

func newEK() (ekcert.Key, []byte, []byte) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "selftest fake TPM vendor"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var rdn pkix.RDNSequence
	for _, last := range []int{1, 2, 3} {
		rdn = append(rdn, pkix.RelativeDistinguishedNameSET{{Type: asn1.ObjectIdentifier{2, 23, 133, 2, last}, Value: "id:00001014"}})
	}
	name, _ := asn1.Marshal(rdn)
	san, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: name}})
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}},
		ExtraExtensions:    []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: san}}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &ek.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	k, err := ekcert.FromPublicKey(&ek.PublicKey)
	if err != nil {
		panic(err)
	}
	return k, caDER, der
}

func nvPublic(handle string, attrs uint32, size int, policy string) string {
	return fmt.Sprintf("%s:\n  name: 000b%s\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n"+
		"  attributes:\n    friendly: x\n    value: 0x%X\n  size: %d\n  authorization policy: %s\n\n",
		strings.ToLower(strings.TrimPrefix(handle, "0x")), strings.Repeat("ab", 32), attrs, size, strings.ToUpper(policy))
}

// measureLog builds a JSON-SEQ log and returns it with the replayed PCR 15.
func measureLog(events ...string) (string, []byte) {
	v := make([]byte, 32)
	var b strings.Builder
	for i, s := range events {
		d := sha256.Sum256([]byte(fmt.Sprintf("event-%d-%s", i, s)))
		n := sha256.Sum256(append(append([]byte{}, v...), d[:]...))
		v = n[:]
		fmt.Fprintf(&b, "\x1e{\"pcr\":15,\"digests\":[{\"hashAlg\":\"sha256\",\"digest\":\"%x\"}],"+
			"\"content_type\":\"systemd\",\"content\":{\"string\":%q,\"eventType\":\"x\"}}\n", d, s)
	}
	// an unrelated PCR 11 event must be ignored
	b.WriteString("\x1e{\"pcr\":11,\"digests\":[{\"hashAlg\":\"sha256\",\"digest\":\"" + strings.Repeat("00", 32) + "\"}],\"content\":{\"string\":\"leave-initrd\"}}\n")
	return b.String(), v
}

// state service as the selftest sees it
var (
	stateReply varauth.StateReply
	stateErr   error
	stateFiles map[string]bool
)

func init() {
	StateCall = func(root string, req varauth.StateRequest) (varauth.StateReply, error) {
		if stateErr != nil {
			return varauth.StateReply{}, stateErr
		}
		if req.Op == "read" && !stateFiles[req.Path] {
			return varauth.StateReply{}, errors.New(req.Path + ": file does not exist")
		}
		return stateReply, nil
	}
}

// goodRoot builds a fully passing fake root and runner.
func goodRoot(t *testing.T) (string, *fakeRunner) {
	root := t.TempDir()
	stateReply, stateErr, stateFiles = varauth.StateReply{OK: true, Version: 42, Counter: 42}, nil, map[string]bool{}
	put(t, root, sbPath, "\x06\x00\x00\x00\x01")
	put(t, root, smPath, "\x06\x00\x00\x00\x00")
	put(t, root, "sys/kernel/security/lockdown", "none integrity [confidentiality]\n")
	put(t, root, "sys/module/module/parameters/sig_enforce", "Y\n")
	put(t, root, "proc/self/mountinfo",
		"20 1 253:0 / /usr ro,relatime shared:1 - erofs /dev/mapper/usr ro\n"+
			"21 1 253:1 / /var/lib/enklave ro,nosuid,nodev,noexec,relatime shared:2 - ext4 /dev/mapper/var rw\n")
	put(t, root, "usr/share/enklave/tpm-ek-ca/Vendor/RootCA/ca.cer", string(ekCA))
	put(t, root, "run/enklave/efi-updates", "current (0 update(s) in the firmware)\n")
	put(t, root, "sys/dev/block/253:0/dm/uuid", "CRYPT-VERITY-abc-usr\n")
	put(t, root, "sys/dev/block/253:1/dm/uuid", "CRYPT-LUKS2-"+strings.ReplaceAll(luksUUID, "-", "")+"-var\n")
	// state volume (dm-crypt 253:1) -> dm-integrity dm-2 -> vda8, as with LUKS2 integrity
	for _, d := range []string{"sys/dev/block/253:1/slaves/dm-2", "sys/block/dm-2/slaves/vda8"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	put(t, root, "sys/module/apparmor/parameters/enabled", "Y\n")
	put(t, root, "usr/lib/enklave/role", " ref\n")
	put(t, root, "usr/lib/enklave/release.json", `{"epoch":0,"heal_below":0}`)
	put(t, root, "usr/lib/os-release", "NAME=Enklave\nIMAGE_VERSION=1.2.3\n")
	put(t, root, "proc/cmdline", "usrhash=ab lockdown=confidentiality systemd.import_credentials=no root=tmpfs\n")
	put(t, root, "run/enklave/var-authenticated", strings.Repeat("15", 32)+"\n")
	put(t, root, "run/enklave/var-counter", "42\n")
	put(t, root, "run/enklave/platform", "firmware-auth\n")
	put(t, root, "var/lib/enklave/.manifest", `{"version":42,"entries":[],"mac":"00"}`)
	put(t, root, "run/systemd/tpm2-pcr-signature.json", `{"sha256":[{"pcrs":[11],"pol":"`+strings.Repeat("dd", 32)+`"}]}`)
	put(t, root, "run/enklave/policy.json", `{"version":2,"pcr11_policy":"`+strings.Repeat("ee", 32)+`"}`)
	log, pcr15 := measureLog("cryptsetup:var:"+luksUUID, "machine-id:0123")
	put(t, root, "run/log/systemd/tpm2-measure.log", log)
	r := &fakeRunner{out: map[string]string{
		luksDumpCmd:                      goodLuksDump,
		"tpm2_nvreadpublic 0x01800E01":   nvPublic("0x01800E01", 0x22042808, 74, fakeP),
		"tpm2_nvreadpublic 0x01800E02":   nvPublic("0x01800E02", 0xB2082808, 64, fakeP),
		"tpm2_nvreadpublic 0x01800E03":   nvPublic("0x01800E03", 0x22080018, 8, fakePC),
		"tpm2_nvreadpublic 0x01800E04":   nvPublic("0x01800E04", 0x22040028, 8, fakePE),
		"tpm2_nvreadpublic 0x01800E05":   nvPublic("0x01800E05", 0x22040002, 34, fakeB1),
		pcrPolicyReadCmd:                 "\x00\x0b" + string(unhex(fakeLit)),
		"tpm2_nvreadpublic 0x01800E06":   nvPublic("0x01800E06", 0x22040002, 496, fakeB1),
		"tpm2_getcap handles-nv-index":   "- 0x1800E01\n- 0x1800E02\n- 0x1800E03\n- 0x1800E04\n- 0x1800E05\n- 0x1800E06\n- 0x1C0000A\n",
		"tpm2_getcap handles-persistent": "- 0x81000001\n- 0x81000E01\n- 0x81010001\n",
		ekCertReadCmd:                    string(ekCert) + strings.Repeat("\x00", 32),
		recordReadCmd:                    recordVal,
		hierCmd:                          lockedHier,
		"tpm2_pcrread sha256:7":          "  sha256:\n    7 : 0x" + strings.Repeat("07", 32) + "\n",
		"tpm2_pcrread sha256:0":          "  sha256:\n    0 : 0x" + strings.Repeat("F0", 32) + "\n",
		"tpm2_pcrread sha256:2":          "  sha256:\n    2 : 0x" + strings.Repeat("F2", 32) + "\n",
		"tpm2_pcrread sha256:4":          "  sha256:\n    4 : 0x" + strings.Repeat("F4", 32) + "\n",
		"tpm2_pcrread sha256:12":         "  sha256:\n    12: 0x" + strings.Repeat("00", 32) + "\n",
		"tpm2_pcrread sha256:15":         "  sha256:\n    15: 0x" + strings.ToUpper(hex.EncodeToString(pcr15)) + "\n",
		"nft -j list ruleset":            goodNft,
		unitsCmd:                         "sshd-not.service loaded active running x\nfoo.service loaded active running y\n",
	}}
	r.fn = func(name string, args []string) ([]byte, bool) {
		switch name {
		case "tpm2_loadexternal", "tpm2_startauthsession", "tpm2_flushcontext":
			return nil, true
		case "tpm2_policycommandcode":
			return []byte(strings.Repeat("dc", 32) + "\n"), true
		case "tpm2_policyauthorize":
			return []byte(strings.Repeat("11", 32) + "\n"), true
		case "tpm2_policynvwritten":
			return []byte(strings.Repeat("22", 32) + "\n"), true
		case "tpm2_policyauthvalue":
			return []byte(strings.Repeat("33", 32) + "\n"), true
		case "tpm2_policyor":
			return []byte(fakePE + "\n"), true
		case "tpm2_policypcr":
			for _, a := range args {
				if a == "sha256:7,12" {
					return []byte(fakeLit + "\n"), true
				}
				if a == "sha256:11" {
					return []byte(fakePol11 + "\n"), true
				}
			}
		case "tpm2_nvread": // counter via PolicyAuthValue session
			if len(args) > 0 && args[0] == "0x01800E03" {
				if c, ok := r.out["counter"]; ok {
					return []byte(c), true
				}
				return []byte(counter42), true
			}
		case "tpm2_readpublic": // public area of the salt key (EK)
			if p := argAfter(args, "-o"); p != "" && argAfter(args, "-c") == "0x81000E01" {
				pub := string(ekKey.TPM2B())
				if s, ok := r.out["salt"]; ok {
					pub = s
				}
				return nil, os.WriteFile(p, []byte(pub), 0o600) == nil
			}
		}
		return nil, false
	}
	return root, r
}

func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func TestVarChecksNotOk(t *testing.T) {
	cases := []struct {
		check  string
		name   string
		mutate func(t *testing.T, root string, r *fakeRunner)
	}{
		{"var_tpm_bound", "no enklave token", func(t *testing.T, root string, r *fakeRunner) {
			r.out[luksDumpCmd] = strings.Replace(goodLuksDump, "enklave-tpm2-nv", "other", 1)
		}},
		{"var_tpm_bound", "extra systemd-tpm2 token", func(t *testing.T, root string, r *fakeRunner) {
			r.out[luksDumpCmd] = goodLuksDump + "  1: systemd-tpm2\n"
		}},
		{"var_tpm_bound", "secret policy differs", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_nvreadpublic 0x01800E02"] = nvPublic("0x01800E02", 0xB2082808, 64, strings.Repeat("99", 32))
		}},
		{"var_tpm_bound", "secret not read-locked", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_nvreadpublic 0x01800E02"] = nvPublic("0x01800E02", 0xA2082808, 64, fakeP)
		}},
		{"var_authenticated", "record policy pinned", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_nvreadpublic 0x01800E01"] = nvPublic("0x01800E01", 0x22042808, 74, strings.Repeat("99", 32))
		}},
		{"var_authenticated", "record not write-locked", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_nvreadpublic 0x01800E01"] = nvPublic("0x01800E01", 0x22042008, 74, fakeP)
		}},
		{"var_authenticated", "epoch policy pinned", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_nvreadpublic 0x01800E04"] = nvPublic("0x01800E04", 0x22040028, 8, fakeP)
		}},
		{"var_authenticated", "counter missing", func(t *testing.T, root string, r *fakeRunner) {
			r.err = map[string]error{"tpm2_nvreadpublic 0x01800E03": errors.New("TPM_RC_HANDLE")}
		}},
		{"var_authenticated", "record mismatch", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "run/enklave/var-authenticated", strings.Repeat("aa", 32)+"\n")
		}},
		{"var_authenticated", "log does not replay", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_pcrread sha256:15"] = "  sha256:\n    15: 0x" + strings.Repeat("AB", 32) + "\n"
		}},
		{"var_authenticated", "first event not /var", func(t *testing.T, root string, r *fakeRunner) {
			log, pcr := measureLog("machine-id:0123", "cryptsetup:var:"+luksUUID)
			put(t, root, "run/log/systemd/tpm2-measure.log", log)
			r.out["tpm2_pcrread sha256:15"] = "  sha256:\n    15: 0x" + hex.EncodeToString(pcr) + "\n"
		}},
		{"var_authenticated", "first event other volume", func(t *testing.T, root string, r *fakeRunner) {
			log, pcr := measureLog("cryptsetup:var:00000000-8c8b-4fd0-afd1-ce8615ab7632")
			put(t, root, "run/log/systemd/tpm2-measure.log", log)
			r.out["tpm2_pcrread sha256:15"] = "  sha256:\n    15: 0x" + hex.EncodeToString(pcr) + "\n"
		}},
		{"var_authenticated", "no log", func(t *testing.T, root string, r *fakeRunner) {
			os.Remove(filepath.Join(root, "run/log/systemd/tpm2-measure.log"))
		}},
		{"var_integrity", "no pbkdf argon2id", func(t *testing.T, root string, r *fakeRunner) {
			r.out[luksDumpCmd] = strings.Replace(goodLuksDump, "argon2id", "pbkdf2", 1)
		}},
		{"var_integrity", "other cipher", func(t *testing.T, root string, r *fakeRunner) {
			r.out[luksDumpCmd] = strings.Replace(goodLuksDump, "cipher: aes-xts-plain64", "cipher: aes-cbc-essiv:sha256", 1)
		}},
		{"var_rollback", "counter ahead", func(t *testing.T, root string, r *fakeRunner) {
			stateReply.Counter = 43
		}},
		{"var_rollback", "state keys left in /run", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "run/enklave/state.key", strings.Repeat("k", 64))
		}},
		{"var_rollback", "state service not reachable", func(t *testing.T, root string, r *fakeRunner) {
			stateErr = errors.New("state service: connection refused")
		}},
		{"tpm_locked", "foreign NV index while the DA lockout is off", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_getcap handles-nv-index"] += "- 0x1500016\n"
		}},
		{"tpm_locked", "foreign persistent key while the DA lockout is off", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_getcap handles-persistent"] += "- 0x81000002\n"
		}},
		{"var_authenticated", "transition index Name differs", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_nvreadpublic 0x01800E06"] = nvPublic("0x01800E06", 0x22040002, 496, strings.Repeat("99", 32))
		}},
		{"var_authenticated", "salt key substituted", func(t *testing.T, root string, r *fakeRunner) {
			r.out["salt"] = string(otherEK.TPM2B())
		}},
		{"var_authenticated", "salt key is not an EK", func(t *testing.T, root string, r *fakeRunner) {
			r.out["salt"] = "\x00\x04junk"
		}},
		{"var_authenticated", "vendor CA bundle missing", func(t *testing.T, root string, r *fakeRunner) {
			os.RemoveAll(filepath.Join(root, "usr/share/enklave/tpm-ek-ca"))
		}},
		{"var_authenticated", "PCR policy index holds another Secure Boot state", func(t *testing.T, root string, r *fakeRunner) {
			r.out[pcrPolicyReadCmd] = "\x00\x0b" + strings.Repeat("\x77", 32)
		}},
		{"var_authenticated", "PCR policy index Name differs", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_nvreadpublic 0x01800E05"] = nvPublic("0x01800E05", 0x22040002, 34, strings.Repeat("99", 32))
		}},
		{"var_authenticated", "PCR policy index writable by its own auth", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_nvreadpublic 0x01800E05"] = nvPublic("0x01800E05", 0x22040006, 34, fakeB1)
		}},
		{"efi_updates", "transition pending", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "run/enklave/efi-updates", "pending: 1 of 1 update(s) handed to the firmware, reboot to complete\n")
		}},
		{"efi_updates", "update rejected by the firmware", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "run/enklave/efi-updates", "failed: NOT APPLIED: dbx-x.auth: EACCES\n")
		}},
		{"efi_updates", "no status", func(t *testing.T, root string, r *fakeRunner) {
			os.Remove(filepath.Join(root, "run/enklave/efi-updates"))
		}},
		{"state_readonly", "state volume writable", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "proc/self/mountinfo",
				"20 1 253:0 / /usr ro,relatime shared:1 - erofs /dev/mapper/usr ro\n"+
					"21 1 253:1 / /var/lib/enklave rw,nosuid,nodev,noexec,relatime shared:2 - ext4 /dev/mapper/var rw\n")
		}},
		{"dev_keys", "test profile without the dev marker", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "usr/lib/enklave/test-profile", "")
		}},
		{"dev_keys", "no release metadata", func(t *testing.T, root string, r *fakeRunner) {
			os.Remove(filepath.Join(root, "usr/lib/enklave/release.json"))
		}},
		{"tpm_locked", "platform enabled without firmware auth", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "run/enklave/platform", "disabled\n")
		}},
		{"tpm_locked", "owner auth empty", func(t *testing.T, root string, r *fakeRunner) {
			r.out[hierCmd] = strings.Replace(lockedHier, "ownerAuthSet:              1", "ownerAuthSet:              0", 1)
		}},
		{"tpm_locked", "lockout auth empty", func(t *testing.T, root string, r *fakeRunner) {
			r.out[hierCmd] = strings.Replace(lockedHier, "lockoutAuthSet:            1", "lockoutAuthSet:            0", 1)
		}},
		{"tpm_locked", "DA lockout enabled", func(t *testing.T, root string, r *fakeRunner) {
			r.out[hierCmd] = strings.Replace(lockedHier, "TPM2_PT_LOCKOUT_INTERVAL: 0x0", "TPM2_PT_LOCKOUT_INTERVAL: 0x3E8", 1)
		}},
		{"tpm_locked", "TPM in lockout", func(t *testing.T, root string, r *fakeRunner) {
			r.out[hierCmd] = strings.Replace(lockedHier, "inLockout:                 0", "inLockout:                 1", 1)
		}},
		{"pcr11_sealed", "systemd signature still valid", func(t *testing.T, root string, r *fakeRunner) {
			put(t, root, "run/systemd/tpm2-pcr-signature.json", `{"sha256":[{"pcrs":[11],"pol":"`+fakePol11+`"}]}`)
		}},
		{"pcr11_sealed", "no policy cache", func(t *testing.T, root string, r *fakeRunner) {
			os.Remove(filepath.Join(root, "run/enklave/policy.json"))
		}},
	}
	for _, c := range cases {
		t.Run(c.check+"/"+c.name, func(t *testing.T) {
			root, r := goodRoot(t)
			c.mutate(t, root, r)
			if x := find(t, RunChecks(root, r), c.check); x.OK || x.Detail == "" {
				t.Errorf("%+v", x)
			}
		})
	}
}

func TestVarChecksDetails(t *testing.T) {
	root, r := goodRoot(t)
	rs := RunChecks(root, r)
	for check, want := range map[string]string{
		"var_tpm_bound":     "/dev/vda8",
		"var_authenticated": "cryptsetup:var:" + luksUUID,
		"var_rollback":      "state version 42",
		"pcr11_sealed":      "matches none of 2 signed",
		"state_readonly":    "ro,nosuid",
		"efi_updates":       "current",
		"dev_keys":          "production keys",
	} {
		if x := find(t, rs, check); !x.OK || !strings.Contains(x.Detail, want) {
			t.Errorf("%s: %+v", check, x)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "run/enklave/selftest/work")); !errors.Is(err, os.ErrNotExist) {
		t.Error("selftest work dir left behind")
	}
}

func TestVarAuthenticatedDetails(t *testing.T) {
	root, r := goodRoot(t)
	x := find(t, RunChecks(root, r), "var_authenticated")
	for _, want := range []string{"policy bound to PCR 7+12", "EK certificate 0x01C0000A issued by", "selftest fake TPM vendor"} {
		if !x.OK || !strings.Contains(x.Detail, want) {
			t.Errorf("%+v lacks %q", x, want)
		}
	}
	// during a signed Secure Boot variable update V lists the exact states
	// the update may lead to; the state of this boot must be one of them
	other := unhex(strings.Repeat("ab", 32))
	tr := make([]byte, 496)
	tr[0], tr[227] = 1, 2
	copy(tr[228:], unhex(fakeLit))
	copy(tr[260:], other)
	r.out["tpm2_nvread 0x01800E06 -C 0x01800E06 -s 496"] = string(tr)
	r.out[pcrPolicyReadCmd] = string(tpmpolicy.DigestNV(tpmpolicy.PolicyOR(unhex(fakeLit), other)))
	if x := find(t, RunChecks(root, r), "var_authenticated"); !x.OK || !strings.Contains(x.Detail, "one of 2 exact Secure Boot states") {
		t.Errorf("%+v", x)
	}
	// a list that does not include the state of this boot
	copy(tr[228:], unhex(strings.Repeat("cd", 32)))
	r.out["tpm2_nvread 0x01800E06 -C 0x01800E06 -s 496"] = string(tr)
	r.out[pcrPolicyReadCmd] = string(tpmpolicy.DigestNV(tpmpolicy.PolicyOR(unhex(strings.Repeat("cd", 32)), other)))
	if x := find(t, RunChecks(root, r), "var_authenticated"); x.OK || !strings.Contains(x.Detail, "is none of them") {
		t.Errorf("%+v", x)
	}
}

// M2: dev-signed builds are reported; production acceptance rejects them.
func TestDevKeys(t *testing.T) {
	root, r := goodRoot(t)
	put(t, root, "usr/lib/enklave/release.json", `{"epoch":0,"heal_below":0,"dev_keys":true}`)
	x := find(t, RunChecks(root, r), "dev_keys")
	if !x.OK || !strings.Contains(x.Detail, "DEV KEYS") {
		t.Errorf("informational: %+v", x)
	}
	x = find(t, RunChecksWith(root, r, Options{ForbidDevKeys: true}), "dev_keys")
	if x.OK || !strings.Contains(x.Detail, "DEV KEYS") {
		t.Errorf("--forbid-dev-keys: %+v", x)
	}
	put(t, root, "usr/lib/enklave/test-profile", "")
	if x := find(t, RunChecks(root, r), "dev_keys"); !x.OK {
		t.Errorf("dev-signed test image: %+v", x)
	}
	put(t, root, "usr/lib/enklave/release.json", `{"epoch":0,"heal_below":0}`)
	os.Remove(filepath.Join(root, "usr/lib/enklave/test-profile"))
	if x := find(t, RunChecksWith(root, r, Options{ForbidDevKeys: true}), "dev_keys"); !x.OK || x.Detail != "production keys" {
		t.Errorf("production: %+v", x)
	}
}

// Without an EK certificate the device is one that was admitted per device:
// the selftest reports that, and its policies are those of the device's own ref.
func TestAdmittedDeviceReported(t *testing.T) {
	root, r := goodRoot(t)
	r.out["tpm2_getcap handles-nv-index"] = "- 0x1800E01\n- 0x1800E02\n- 0x1800E03\n- 0x1800E04\n- 0x1800E05\n- 0x1800E06\n"
	// production: an endorsement key without vendor certificate is refused (G5)
	if x := find(t, RunChecks(root, r), "var_authenticated"); x.OK || !strings.Contains(x.Detail, "production release accepts only endorsement keys certified by a TPM vendor") {
		t.Errorf("prod: %+v", x)
	}
	put(t, root, "usr/lib/enklave/release.json", `{"epoch":0,"heal_below":0,"dev_keys":true}`)
	x := find(t, RunChecks(root, r), "var_authenticated")
	if !x.OK || !strings.Contains(x.Detail, "signed per-device admission of EK") {
		t.Errorf("%+v", x)
	}
}
