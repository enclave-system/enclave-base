// Command enklave-sign-policy runs on the build host after mkosi. It
//
//  1. reads the single PCR 11 policy from the UKI's .pcrsig and proves that it
//     is exactly the phase enter-initrd:leave-initrd (recomputed with
//     systemd-measure from the UKI's own sections),
//  2. derives the TPM Name of the epoch index E on an ephemeral swtpm (same
//     public area as on the target: handle, attributes, authPolicy),
//  3. computes and signs the approved policy for the given security epoch
//     (see internal/tpmpolicy) with the PCR signing key,
//  4. writes the JSON next to the UKI and, with --image, into the image's ESP
//     at /EFI/enklave/policy/<uki>.json (mtools).
//
// Usage:
//
//	enklave-sign-policy --uki X.efi --key pcr-signing.key --pub pcr-signing.pub \
//	    --epoch N --out X.policy.json [--image X.raw]
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"enklave.local/base/internal/tpmpolicy"
	"enklave.local/base/internal/varauth"
)

const phase = "enter-initrd:leave-initrd"

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "enklave-sign-policy: "+format+"\n", a...)
	os.Exit(1)
}

func run(env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// sectionData returns the measured bytes of a PE section (min of virtual
// and raw size, as systemd-stub and ukify use).
func sectionData(s *pe.Section) ([]byte, error) {
	b, err := s.Data()
	if err != nil {
		return nil, err
	}
	if n := int(s.VirtualSize); n < len(b) {
		b = b[:n]
	}
	return b, nil
}

// pcrPolicyDigest computes PolicyPCR(sha256:11 = value) from a zero digest.
func pcrPolicyDigest(value []byte) []byte {
	sel := []byte{0, 0, 0, 1, 0x00, 0x0b, 3, 0x00, 0x08, 0x00} // TPML_PCR_SELECTION {sha256: 11}
	pd := sha256.Sum256(value)
	h := sha256.New()
	h.Write(make([]byte, 32))
	var cc [4]byte
	binary.BigEndian.PutUint32(cc[:], 0x0000017F) // TPM_CC_PolicyPCR
	h.Write(cc[:])
	h.Write(sel)
	h.Write(pd[:])
	return h.Sum(nil)
}

// provePhase recomputes PCR 11 for the phase from the UKI's sections and
// returns the matching PolicyPCR digest.
func provePhase(f *pe.File, tmp string) ([]byte, error) {
	measured := []string{".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".dtbauto",
		".uname", ".sbat", ".pcrpkey", ".profile", ".hwids"}
	var args []string
	for _, name := range measured {
		s := f.Section(name)
		if s == nil {
			continue
		}
		b, err := sectionData(s)
		if err != nil {
			return nil, err
		}
		p := filepath.Join(tmp, strings.TrimPrefix(name, "."))
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("--%s=%s", strings.TrimPrefix(name, "."), p))
	}
	args = append([]string{"calculate", "--bank=sha256", "--phase=" + phase, "--json=short"}, args...)
	out, err := run(nil, "/usr/lib/systemd/systemd-measure", args...)
	if err != nil {
		return nil, err
	}
	var doc struct {
		SHA256 []struct {
			Phase string `json:"phase"`
			PCR   int    `json:"pcr"`
			Hash  string `json:"hash"`
		} `json:"sha256"`
	}
	if err := json.Unmarshal(out, &doc); err != nil || len(doc.SHA256) != 1 || doc.SHA256[0].Phase != phase {
		return nil, fmt.Errorf("unexpected systemd-measure output %s (%v)", out, err)
	}
	v, err := hex.DecodeString(doc.SHA256[0].Hash)
	if err != nil || len(v) != 32 {
		return nil, fmt.Errorf("bad PCR 11 value %q", doc.SHA256[0].Hash)
	}
	return pcrPolicyDigest(v), nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func digest(out []byte) ([]byte, error) {
	f := strings.Fields(string(out))
	for i := len(f) - 1; i >= 0; i-- {
		if b, err := hex.DecodeString(strings.TrimPrefix(f[i], "0x")); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("no digest in %q", out)
}

// epochName defines E exactly as the target does (on a throw-away swtpm),
// initializes it and returns its TPM Name.
func epochName(pub, ref, tmp string) ([]byte, error) {
	state := filepath.Join(tmp, "swtpm")
	if err := os.MkdirAll(state, 0o700); err != nil {
		return nil, err
	}
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	pid := filepath.Join(tmp, "swtpm.pid")
	if _, err := run(nil, "swtpm", "socket", "--tpmstate", "dir="+state, "--tpm2",
		"--server", fmt.Sprintf("type=tcp,port=%d,bindaddr=127.0.0.1", port),
		"--ctrl", fmt.Sprintf("type=tcp,port=%d,bindaddr=127.0.0.1", port+1),
		"--flags", "not-need-init,startup-clear", "--daemon", "--pid", "file="+pid); err != nil {
		return nil, err
	}
	defer func() {
		if b, err := os.ReadFile(pid); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				if p, err := os.FindProcess(n); err == nil {
					p.Kill() //nolint:errcheck
				}
			}
		}
	}()
	time.Sleep(500 * time.Millisecond)
	env := []string{fmt.Sprintf("TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=%d", port)}
	w := func(n string) string { return filepath.Join(tmp, n) }
	if err := os.WriteFile(w("ref.bin"), []byte(ref), 0o600); err != nil {
		return nil, err
	}
	steps := [][]string{
		{"tpm2_loadexternal", "-C", "o", "-G", "rsa", "-u", pub, "-c", w("key.ctx"), "-n", w("key.name")},
		{"tpm2_startauthsession", "-S", w("t.ctx")},
		{"tpm2_policyauthorize", "-S", w("t.ctx"), "-n", w("key.name"), "-q", w("ref.bin"), "-L", w("b1.bin")},
		{"tpm2_flushcontext", w("t.ctx")},
		{"tpm2_startauthsession", "-S", w("t.ctx")},
		{"tpm2_policycommandcode", "-S", w("t.ctx"), "TPM2_CC_NV_SetBits"},
		{"tpm2_policynvwritten", "-S", w("t.ctx"), "-L", w("b2.bin"), "c"},
		{"tpm2_flushcontext", w("t.ctx")},
		{"tpm2_startauthsession", "-S", w("t.ctx")},
		{"tpm2_policyor", "-S", w("t.ctx"), "-l", "sha256:" + w("b1.bin") + "," + w("b2.bin"), "-L", w("pe.bin")},
		{"tpm2_flushcontext", w("t.ctx")},
		{"tpm2_nvdefine", varauth.Epoch.Handle, "-C", "o", "-s", strconv.Itoa(varauth.Epoch.Size),
			"-a", fmt.Sprintf("0x%08x", varauth.Epoch.Define), "-L", w("pe.bin"), "-g", "sha256"},
		{"tpm2_startauthsession", "--policy-session", "-S", w("s.ctx")},
		{"tpm2_policycommandcode", "-S", w("s.ctx"), "TPM2_CC_NV_SetBits"},
		{"tpm2_policynvwritten", "-S", w("s.ctx"), "c"},
		{"tpm2_policyor", "-S", w("s.ctx"), "-l", "sha256:" + w("b1.bin") + "," + w("b2.bin")},
		{"tpm2_nvsetbits", varauth.Epoch.Handle, "-C", varauth.Epoch.Handle, "-i", "0", "-P", "session:" + w("s.ctx")},
		{"tpm2_flushcontext", w("s.ctx")},
	}
	for _, st := range steps {
		if _, err := run(env, st[0], st[1:]...); err != nil {
			return nil, err
		}
	}
	out, err := run(env, "tpm2_nvreadpublic", varauth.Epoch.Handle)
	if err != nil {
		return nil, err
	}
	p, err := varauth.ParseNVPublic(out)
	if err != nil {
		return nil, err
	}
	if p.Attributes != varauth.Epoch.Final {
		return nil, fmt.Errorf("epoch index attributes 0x%08x, want 0x%08x", p.Attributes, varauth.Epoch.Final)
	}
	return p.Name, nil
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block in private key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("PCR signing key is not RSA")
	}
	return x509.ParsePKCS1PrivateKey(blk.Bytes)
}

// espOffset returns the byte offset of the ESP in a GPT image (sfdisk -J).
func espOffset(image string) (int64, error) {
	out, err := run(nil, "sfdisk", "-J", image)
	if err != nil {
		return 0, err
	}
	var doc struct {
		PartitionTable struct {
			SectorSize int64 `json:"sectorsize"`
			Partitions []struct {
				Start int64  `json:"start"`
				Type  string `json:"type"`
			} `json:"partitions"`
		} `json:"partitiontable"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return 0, err
	}
	ss := doc.PartitionTable.SectorSize
	if ss == 0 {
		ss = 512
	}
	for _, p := range doc.PartitionTable.Partitions {
		if strings.EqualFold(p.Type, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B") {
			return p.Start * ss, nil
		}
	}
	return 0, errors.New("no ESP in image")
}

func embed(image, file, name string) error {
	off, err := espOffset(image)
	if err != nil {
		return err
	}
	img := fmt.Sprintf("%s@@%d", image, off)
	for _, d := range []string{"::/EFI/enklave", "::/EFI/enklave/policy"} {
		if _, err := run(nil, "mdir", "-i", img, d); err != nil {
			if _, err := run(nil, "mmd", "-i", img, d); err != nil {
				return err
			}
		}
	}
	if _, err := run(nil, "mcopy", "-o", "-i", img, file, "::/EFI/enklave/policy/"+name); err != nil {
		return err
	}
	got, err := run(nil, "mtype", "-i", img, "::/EFI/enklave/policy/"+name)
	if err != nil {
		return err
	}
	want, _ := os.ReadFile(file)
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		return errors.New("policy file in ESP differs after copy")
	}
	return nil
}

func main() {
	uki := flag.String("uki", "", "UKI (.efi)")
	keyPath := flag.String("key", "", "PCR signing private key (PEM)")
	pub := flag.String("pub", "", "PCR signing public key (PEM)")
	epoch := flag.Int("epoch", -1, "security epoch of this release")
	out := flag.String("out", "", "output JSON")
	image := flag.String("image", "", "disk image whose ESP receives the JSON (optional)")
	role := flag.String("role", "", "image role (ref, client, ...)")
	profile := flag.String("profile", "", "prod or test")
	pkiDir := flag.String("pki", "", "PKI directory (checked for the DEV-KEYS marker)")
	allowDevProd := flag.Bool("allow-dev-key-for-prod", false, "development only: sign a prod image with dev keys")
	releasePath := flag.String("release", "", "release.json that went into the image (checked for the dev-key marker and epoch)")
	flag.Parse()
	if *uki == "" || *keyPath == "" || *pub == "" || *epoch < 0 || *out == "" || *pkiDir == "" || *releasePath == "" {
		flag.Usage()
		os.Exit(2)
	}
	ref, err := tpmpolicy.Ref(*role, *profile)
	if err != nil {
		die("%v", err)
	}
	// OOS-1: test images only with dev keys, prod images never with dev keys.
	_, devErr := os.Stat(filepath.Join(*pkiDir, "DEV-KEYS"))
	dev := devErr == nil
	switch {
	case *profile == "test" && !dev:
		die("refusing to sign a test-profile image with non-dev keys (%s has no DEV-KEYS marker)", *pkiDir)
	case *profile == "prod" && dev && !*allowDevProd:
		die("refusing to sign a prod image with dev keys (%s/DEV-KEYS); use --allow-dev-key-for-prod for development builds only", *pkiDir)
	case *profile == "prod" && dev:
		fmt.Fprintln(os.Stderr, "enklave-sign-policy: WARNING: prod image signed with DEV keys (development build, never ship)")
	}
	// M2: the image must carry the truth about its keys (verity-protected
	// release.json, covered by PCR 11 through the usr root hash).
	rb, err := os.ReadFile(*releasePath)
	if err != nil {
		die("%v", err)
	}
	var rel tpmpolicy.Release
	if err := json.Unmarshal(rb, &rel); err != nil {
		die("%s: %v", *releasePath, err)
	}
	if rel.DevKeys != dev {
		die("%s says dev_keys=%v but %s is %sa DEV-KEYS PKI: refusing to sign an image with a wrong dev-key marker",
			*releasePath, rel.DevKeys, *pkiDir, map[bool]string{true: "", false: "not "}[dev])
	}
	if rel.Epoch != *epoch {
		die("%s is for epoch %d, signing for epoch %d", *releasePath, rel.Epoch, *epoch)
	}
	tmp, err := os.MkdirTemp("", "enklave-sign-policy")
	if err != nil {
		die("%v", err)
	}
	defer os.RemoveAll(tmp)

	f, err := pe.Open(*uki)
	if err != nil {
		die("%v", err)
	}
	defer f.Close()
	s := f.Section(".pcrsig")
	if s == nil {
		die("%s has no .pcrsig section", *uki)
	}
	raw, err := sectionData(s)
	if err != nil {
		die("%v", err)
	}
	var sig map[string][]struct {
		PCRs []int  `json:"pcrs"`
		Pol  string `json:"pol"`
	}
	if err := json.Unmarshal(bytes.TrimRight(raw, "\x00"), &sig); err != nil {
		die("parse .pcrsig: %v", err)
	}
	if len(sig) != 1 || len(sig["sha256"]) != 1 || len(sig["sha256"][0].PCRs) != 1 || sig["sha256"][0].PCRs[0] != 11 {
		die(".pcrsig must hold exactly one sha256 PCR 11 policy, got %s", raw)
	}
	pol, err := hex.DecodeString(sig["sha256"][0].Pol)
	if err != nil || len(pol) != 32 {
		die("bad pol in .pcrsig")
	}
	want, err := provePhase(f, tmp)
	if err != nil {
		die("recomputing PCR 11: %v", err)
	}
	if !bytes.Equal(want, pol) {
		die(".pcrsig policy %x is not the %s phase (%x)", pol, phase, want)
	}

	name, err := epochName(*pub, ref, tmp)
	if err != nil {
		die("epoch index name: %v", err)
	}
	approved, err := tpmpolicy.Approved(pol, *epoch, name)
	if err != nil {
		die("%v", err)
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		die("%v", err)
	}
	h := sha256.Sum256(tpmpolicy.SignedMessage(approved, ref))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		die("%v", err)
	}
	doc := tpmpolicy.File{Version: 2, Role: *role, Profile: *profile, Epoch: *epoch, PCR11Policy: hex.EncodeToString(pol),
		Approved: hex.EncodeToString(approved), Ref: ref, Signature: base64.StdEncoding.EncodeToString(signature), DevKeys: dev}
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		die("%v", err)
	}
	keys := "production keys"
	if dev {
		keys = "DEV KEYS"
	}
	fmt.Printf("enklave-sign-policy: %s: phase %s proven, ref %s, epoch %d, %s, approved %x\n", filepath.Base(*uki), phase, ref, *epoch, keys, approved)
	if *image != "" {
		n := strings.TrimSuffix(filepath.Base(*uki), ".efi") + ".json"
		if err := embed(*image, *out, n); err != nil {
			die("embedding into %s: %v", *image, err)
		}
		fmt.Printf("enklave-sign-policy: embedded as ESP:/EFI/enklave/policy/%s\n", n)
	}
}
