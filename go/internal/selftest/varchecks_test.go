package selftest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	luksDumpCmd   = "cryptsetup luksDump /dev/vda8"
	recordReadCmd = "tpm2_nvread 0x01800E01 -C 0x01800E01 -s 32"
	counterRead   = "tpm2_nvread 0x01800E03 -C 0x01800E03 -s 8"
	hierCmd       = "tpm2_getcap properties-variable"
	luksUUID      = "6f2fbea9-8c8b-4fd0-afd1-ce8615ab7632"

	goodLuksDump = "LUKS header information\nVersion:       \t2\nData segments:\n  0: crypt\n\toffset: 16777216 [bytes]\n" +
		"\tcipher: aes-xts-plain64\n\tsector: 512 [bytes]\n\tintegrity: hmac(sha256)\n" +
		"Keyslots:\n  0: luks2\n\tKey:        768 bits\n\tCipher:     aes-xts-plain64\n\tCipher key: 512 bits\n\tPBKDF:      argon2id\n" +
		"Tokens:\n  0: enklave-tpm2-nv\n\tKeyslot:    0\nDigests:\n"
	lockedHier = "TPM2_PT_PERMANENT:\n  ownerAuthSet:              1\n  endorsementAuthSet:        1\n  lockoutAuthSet:            1\n" +
		"  reserved1:                 0\n  disableClear:              1\nTPM2_PT_STARTUP_CLEAR:\n  phEnable:                  1\n"
)

var (
	fakeP     = strings.Repeat("aa", 32)
	fakePE    = strings.Repeat("bb", 32)
	fakePol11 = strings.Repeat("cc", 32) // current PCR 11 policy (after boot)
	recordVal = strings.Repeat("\x15", 32)
)

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

// goodRoot builds a fully passing fake root and runner.
func goodRoot(t *testing.T) (string, *fakeRunner) {
	root := t.TempDir()
	put(t, root, sbPath, "\x06\x00\x00\x00\x01")
	put(t, root, smPath, "\x06\x00\x00\x00\x00")
	put(t, root, "sys/kernel/security/lockdown", "none integrity [confidentiality]\n")
	put(t, root, "sys/module/module/parameters/sig_enforce", "Y\n")
	put(t, root, "proc/self/mountinfo",
		"20 1 253:0 / /usr ro,relatime shared:1 - erofs /dev/mapper/usr ro\n"+
			"21 1 253:1 / /var rw,relatime shared:2 - ext4 /dev/mapper/var rw\n")
	put(t, root, "sys/dev/block/253:0/dm/uuid", "CRYPT-VERITY-abc-usr\n")
	put(t, root, "sys/dev/block/253:1/dm/uuid", "CRYPT-LUKS2-"+strings.ReplaceAll(luksUUID, "-", "")+"-var\n")
	// /var (dm-crypt 253:1) -> dm-integrity dm-2 -> vda8, as with LUKS2 integrity
	for _, d := range []string{"sys/dev/block/253:1/slaves/dm-2", "sys/block/dm-2/slaves/vda8"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	put(t, root, "sys/module/apparmor/parameters/enabled", "Y\n")
	put(t, root, "usr/lib/enklave/role", " ref\n")
	put(t, root, "usr/lib/os-release", "NAME=Enklave\nIMAGE_VERSION=1.2.3\n")
	put(t, root, "proc/cmdline", "usrhash=ab lockdown=confidentiality systemd.import_credentials=no root=tmpfs\n")
	put(t, root, "run/enklave/var-authenticated", strings.Repeat("15", 32)+"\n")
	put(t, root, "run/enklave/var-counter", "42\n")
	put(t, root, "var/lib/enklave/rollback-counter", "42\n")
	put(t, root, "run/systemd/tpm2-pcr-signature.json", `{"sha256":[{"pcrs":[11],"pol":"`+strings.Repeat("dd", 32)+`"}]}`)
	put(t, root, "run/enklave/policy.json", `{"version":1,"pcr11_policy":"`+strings.Repeat("ee", 32)+`"}`)
	log, pcr15 := measureLog("cryptsetup:var:"+luksUUID, "machine-id:0123")
	put(t, root, "run/log/systemd/tpm2-measure.log", log)
	r := &fakeRunner{out: map[string]string{
		luksDumpCmd:                    goodLuksDump,
		"tpm2_nvreadpublic 0x01800E01": nvPublic("0x01800E01", 0x22042808, 32, fakeP),
		"tpm2_nvreadpublic 0x01800E02": nvPublic("0x01800E02", 0xB2082808, 64, fakeP),
		"tpm2_nvreadpublic 0x01800E03": nvPublic("0x01800E03", 0x22040018, 8, fakeP),
		"tpm2_nvreadpublic 0x01800E04": nvPublic("0x01800E04", 0x22040028, 8, fakePE),
		recordReadCmd:                  recordVal,
		counterRead:                    "\x00\x00\x00\x00\x00\x00\x00\x2a",
		hierCmd:                        lockedHier,
		"tpm2_pcrread sha256:7":        "  sha256:\n    7 : 0x" + strings.Repeat("07", 32) + "\n",
		"tpm2_pcrread sha256:15":       "  sha256:\n    15: 0x" + strings.ToUpper(hex.EncodeToString(pcr15)) + "\n",
		"nft -j list ruleset":          goodNft,
		unitsCmd:                       "sshd-not.service loaded active running x\nfoo.service loaded active running y\n",
	}}
	r.fn = func(name string, args []string) ([]byte, bool) {
		switch name {
		case "tpm2_loadexternal", "tpm2_startauthsession", "tpm2_flushcontext", "tpm2_policycommandcode":
			return nil, true
		case "tpm2_policyauthorize":
			return []byte(strings.Repeat("11", 32) + "\n"), true
		case "tpm2_policynvwritten":
			return []byte(strings.Repeat("22", 32) + "\n"), true
		case "tpm2_policyor":
			return []byte(fakePE + "\n"), true
		case "tpm2_policypcr":
			for _, a := range args {
				if a == "sha256:7,12" {
					return []byte(fakeP + "\n"), true
				}
				if a == "sha256:11" {
					return []byte(fakePol11 + "\n"), true
				}
			}
		}
		return nil, false
	}
	return root, r
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
			r.out["tpm2_nvreadpublic 0x01800E01"] = nvPublic("0x01800E01", 0x22042808, 32, strings.Repeat("99", 32))
		}},
		{"var_authenticated", "record not write-locked", func(t *testing.T, root string, r *fakeRunner) {
			r.out["tpm2_nvreadpublic 0x01800E01"] = nvPublic("0x01800E01", 0x22042008, 32, fakeP)
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
			r.out[counterRead] = "\x00\x00\x00\x00\x00\x00\x00\x2b"
		}},
		{"var_rollback", "no file", func(t *testing.T, root string, r *fakeRunner) {
			os.Remove(filepath.Join(root, "var/lib/enklave/rollback-counter"))
		}},
		{"tpm_locked", "owner auth empty", func(t *testing.T, root string, r *fakeRunner) {
			r.out[hierCmd] = strings.Replace(lockedHier, "ownerAuthSet:              1", "ownerAuthSet:              0", 1)
		}},
		{"tpm_locked", "lockout auth empty", func(t *testing.T, root string, r *fakeRunner) {
			r.out[hierCmd] = strings.Replace(lockedHier, "lockoutAuthSet:            1", "lockoutAuthSet:            0", 1)
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
		"var_rollback":      "counter 42",
		"pcr11_sealed":      "matches none of 2 signed",
	} {
		if x := find(t, rs, check); !x.OK || !strings.Contains(x.Detail, want) {
			t.Errorf("%s: %+v", check, x)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "run/enklave/selftest/work")); !errors.Is(err, os.ErrNotExist) {
		t.Error("selftest work dir left behind")
	}
}
