package varauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"enklave.local/base/internal/tpmpolicy"
)

// ----------------------------------------------------------------- fake TPM

type nvIndex struct {
	attrs  uint32
	policy []byte
	data   []byte
	size   int
}

type fakeSession struct {
	policy                       bool
	pcr11, nvOK, authOK, pcrOK   bool
	orOK, initCC, initNotWritten bool
	vals                         []byte
	epochOp                      uint64
}

type fakeTPM struct {
	t       *testing.T
	pcr     map[int][]byte
	nv      map[uint64]*nvIndex
	sess    map[string]*fakeSession
	tickets map[string][]byte // ticket file -> approved digest
	hier    Hierarchy
	luks    map[string][]byte // device -> key
	opened  []byte
	repart  string
	mounts  []string
	fail    map[string]error
	calls   []string
	setbits []string
}

func newFakeTPM(t *testing.T) *fakeTPM {
	return &fakeTPM{
		t: t,
		pcr: map[int][]byte{
			7: bytes.Repeat([]byte{7}, 32), 11: bytes.Repeat([]byte{11}, 32),
			12: make([]byte, 32), 15: make([]byte, 32),
		},
		nv:      map[uint64]*nvIndex{},
		sess:    map[string]*fakeSession{},
		tickets: map[string][]byte{},
		luks:    map[string][]byte{},
		repart:  `[{"type":"var","activity":"create"}]`,
	}
}

func h(parts ...[]byte) []byte {
	s := sha256.New()
	for _, p := range parts {
		s.Write(p)
	}
	return s.Sum(nil)
}

func fakePol11(pcr11 []byte) []byte { return h([]byte("pcr11"), pcr11) }

var (
	fakeB1 = h([]byte("authorize"), []byte(tpmpolicy.Ref))
	fakeB2 = h([]byte("init-setbits-notwritten"))
	fakePE = h([]byte("or"), fakeB1, fakeB2)
)

func fakeP(vals []byte) []byte { return h([]byte("p"), fakeB1, vals) }

func fakeName(handle uint64, attrs uint32, policy []byte) []byte {
	var b [8]byte
	binary.BigEndian.PutUint32(b[:4], uint32(handle))
	binary.BigEndian.PutUint32(b[4:], attrs)
	return append([]byte{0, 0x0b}, h(b[:], policy)...)
}

func arg(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (f *fakeTPM) read(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		f.t.Fatalf("fake TPM: reading %s: %v", p, err)
	}
	return b
}

func hexOut(b []byte) []byte { return []byte(hex.EncodeToString(b) + "\n") }

func (f *fakeTPM) index(handle string) (*nvIndex, uint64, error) {
	n := handleNum(handle)
	ix := f.nv[n]
	if ix == nil {
		return nil, n, errors.New("TPM_RC_HANDLE")
	}
	return ix, n, nil
}

// authorizedBy checks a "-P session:x" against the index policy.
func (f *fakeTPM) authorizedBy(args []string, ix *nvIndex, isSetBits bool) error {
	p := arg(args, "-P")
	if !strings.HasPrefix(p, "session:") {
		return errors.New("no policy session")
	}
	s := f.sess[strings.TrimPrefix(p, "session:")]
	if s == nil || !s.policy {
		return errors.New("bad session")
	}
	var digest []byte
	switch {
	case s.orOK && s.initCC && s.initNotWritten:
		if !isSetBits || ix.attrs&attrWritten != 0 {
			return errors.New("TPM_RC_POLICY_FAIL (init branch)")
		}
		digest = fakePE
	case s.orOK && s.authOK:
		digest = fakePE
	case s.pcrOK && s.authOK:
		digest = fakeP(s.vals)
	default:
		return errors.New("TPM_RC_POLICY_FAIL (incomplete session)")
	}
	if !bytes.Equal(digest, ix.policy) {
		return errors.New("TPM_RC_POLICY_FAIL (digest)")
	}
	return nil
}

func (f *fakeTPM) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	switch name {
	case "systemd-repart":
		return []byte(f.repart), nil
	case "tpm2_pcrread":
		n, _ := strconv.Atoi(strings.TrimPrefix(args[0], "sha256:"))
		return []byte(fmt.Sprintf("  sha256:\n    %d : 0x%X\n", n, f.pcr[n])), nil
	case "tpm2_loadexternal", "tpm2_flushcontext":
		if name == "tpm2_flushcontext" {
			delete(f.sess, args[0])
		}
		return nil, nil
	case "tpm2_startauthsession":
		f.sess[arg(args, "-S")] = &fakeSession{policy: args[0] == "--policy-session"}
		return nil, nil
	case "tpm2_policyauthorize":
		s := f.sess[arg(args, "-S")]
		if !s.policy {
			return hexOut(fakeB1), nil
		}
		approved := f.read(arg(args, "-i"))
		ok := bytes.Equal(f.tickets[arg(args, "-t")], approved) && s.pcr11 && s.nvOK
		op := make([]byte, 8)
		binary.BigEndian.PutUint64(op, s.epochOp)
		eix := f.nv[handleNum(Epoch.Handle)]
		if eix == nil {
			return nil, errors.New("no E")
		}
		cur := tpmpolicy.PolicyNV(fakePol11(f.pcr[11]), op, 0, 0x000B, fakeName(handleNum(Epoch.Handle), eix.attrs, eix.policy))
		if !ok || !bytes.Equal(cur, approved) {
			return nil, errors.New("TPM_RC_POLICY_FAIL (authorize)")
		}
		s.authOK = true
		return nil, nil
	case "tpm2_policypcr":
		s := f.sess[arg(args, "-S")]
		if arg(args, "-l") == "sha256:11" {
			s.pcr11 = true
			return hexOut(fakePol11(f.pcr[11])), nil
		}
		vals := f.read(arg(args, "-f"))
		if s.policy {
			if !bytes.Equal(vals, append(append([]byte{}, f.pcr[7]...), f.pcr[12]...)) {
				return nil, errors.New("TPM_RC_VALUE (pcr)")
			}
			s.pcrOK, s.vals = true, vals
			return nil, nil
		}
		return hexOut(fakeP(vals)), nil
	case "tpm2_policycommandcode":
		f.sess[arg(args, "-S")].initCC = args[len(args)-1] == "TPM2_CC_NV_SetBits"
		return nil, nil
	case "tpm2_policynvwritten":
		f.sess[arg(args, "-S")].initNotWritten = args[len(args)-1] == "c"
		return hexOut(fakeB2), nil
	case "tpm2_policyor":
		s := f.sess[arg(args, "-S")]
		s.orOK = true
		return hexOut(fakePE), nil
	case "tpm2_policynv":
		s := f.sess[arg(args, "-S")]
		op := binary.BigEndian.Uint64(f.read(arg(args, "-i")))
		eix := f.nv[handleNum(args[len(args)-2])]
		if eix == nil || eix.attrs&attrWritten == 0 {
			return nil, errors.New("TPM_RC_NV_UNINITIALIZED")
		}
		if binary.BigEndian.Uint64(eix.data)&op != 0 {
			return nil, errors.New("TPM_RC_POLICY (bit set)")
		}
		s.nvOK, s.epochOp = true, op
		return nil, nil
	case "tpm2_verifysignature":
		msg, sig := f.read(arg(args, "-m")), f.read(arg(args, "-s"))
		if string(sig) != "SIG:"+hex.EncodeToString(msg) {
			return nil, errors.New("TPM_RC_SIGNATURE")
		}
		f.tickets[arg(args, "-t")] = bytes.TrimSuffix(msg, []byte(tpmpolicy.Ref))
		return nil, nil
	case "tpm2_getcap":
		if args[0] == "handles-nv-index" {
			var b strings.Builder
			for n := range f.nv {
				fmt.Fprintf(&b, "- 0x%X\n", n)
			}
			return []byte(b.String()), nil
		}
		v := func(x bool) int {
			if x {
				return 1
			}
			return 0
		}
		return []byte(fmt.Sprintf("TPM2_PT_PERMANENT:\n  ownerAuthSet:              %d\n  endorsementAuthSet:        %d\n"+
			"  lockoutAuthSet:            %d\n  reserved1:                 0\n  disableClear:              %d\n"+
			"TPM2_PT_STARTUP_CLEAR:\n  phEnable:                  1\n",
			v(f.hier.OwnerAuthSet), v(f.hier.EndorsementAuthSet), v(f.hier.LockoutAuthSet), v(f.hier.DisableClear))), nil
	case "tpm2_nvdefine":
		n := handleNum(args[0])
		if f.nv[n] != nil {
			return nil, errors.New("TPM_RC_NV_DEFINED")
		}
		if f.hier.OwnerAuthSet {
			return nil, errors.New("TPM_RC_BAD_AUTH (owner)")
		}
		a, _ := strconv.ParseUint(strings.TrimPrefix(arg(args, "-a"), "0x"), 16, 32)
		size, _ := strconv.Atoi(arg(args, "-s"))
		f.nv[n] = &nvIndex{attrs: uint32(a), policy: f.read(arg(args, "-L")), size: size}
		return nil, nil
	case "tpm2_nvsetbits":
		ix, _, err := f.index(args[0])
		if err != nil {
			return nil, err
		}
		if err := f.authorizedBy(args, ix, true); err != nil {
			return nil, err
		}
		bits, _ := strconv.ParseUint(strings.TrimPrefix(arg(args, "-i"), "0x"), 16, 64)
		if ix.data == nil {
			ix.data = make([]byte, 8)
		}
		binary.BigEndian.PutUint64(ix.data, binary.BigEndian.Uint64(ix.data)|bits)
		ix.attrs |= attrWritten
		f.setbits = append(f.setbits, arg(args, "-i"))
		return nil, nil
	case "tpm2_nvwrite":
		ix, _, err := f.index(args[0])
		if err != nil {
			return nil, err
		}
		if ix.attrs&attrWriteLocked != 0 {
			return nil, errors.New("TPM_RC_NV_LOCKED")
		}
		if err := f.authorizedBy(args, ix, false); err != nil {
			return nil, err
		}
		ix.data = f.read(arg(args, "-i"))
		ix.attrs |= attrWritten
		return nil, nil
	case "tpm2_nvwritelock":
		ix, _, err := f.index(args[0])
		if err != nil {
			return nil, err
		}
		if err := f.authorizedBy(args, ix, false); err != nil {
			return nil, err
		}
		ix.attrs |= attrWriteLocked
		return nil, nil
	case "tpm2_nvreadlock":
		ix, _, err := f.index(args[0])
		if err != nil {
			return nil, err
		}
		if err := f.authorizedBy(args, ix, false); err != nil {
			return nil, err
		}
		ix.attrs |= attrReadLocked
		return nil, nil
	case "tpm2_nvincrement":
		ix, _, err := f.index(args[0])
		if err != nil {
			return nil, err
		}
		if err := f.authorizedBy(args, ix, false); err != nil {
			return nil, err
		}
		if ix.data == nil {
			ix.data = make([]byte, 8)
			binary.BigEndian.PutUint64(ix.data, 41) // counters start at an arbitrary value
		}
		binary.BigEndian.PutUint64(ix.data, binary.BigEndian.Uint64(ix.data)+1)
		ix.attrs |= attrWritten
		return nil, nil
	case "tpm2_nvread":
		ix, _, err := f.index(args[0])
		if err != nil {
			return nil, err
		}
		if ix.attrs&attrWritten == 0 {
			return nil, errors.New("TPM_RC_NV_UNINITIALIZED")
		}
		if ix.attrs&attrPolicyRead != 0 {
			if ix.attrs&attrReadLocked != 0 {
				return nil, errors.New("TPM_RC_NV_LOCKED (read)")
			}
			if err := f.authorizedBy(args, ix, false); err != nil {
				return nil, err
			}
		}
		return append([]byte{}, ix.data...), nil
	case "tpm2_nvreadpublic":
		ix, n, err := f.index(args[0])
		if err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf("0x%x:\n  name: %x\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n"+
			"  attributes:\n    friendly: x\n    value: 0x%X\n  size: %d\n  authorization policy: %X\n\n",
			n, fakeName(n, ix.attrs, ix.policy), ix.attrs, ix.size, ix.policy)), nil
	case "tpm2_clearcontrol":
		if f.hier.LockoutAuthSet {
			return nil, errors.New("TPM_RC_BAD_AUTH (lockout)")
		}
		f.hier.DisableClear = true
		return nil, nil
	case "tpm2_changeauth":
		switch arg(args, "-c") {
		case "l":
			f.hier.LockoutAuthSet = true
		case "o":
			f.hier.OwnerAuthSet = true
		case "e":
			f.hier.EndorsementAuthSet = true
		}
		return nil, nil
	case "cryptsetup":
		dev := args[len(args)-1]
		switch args[0] {
		case "isLuks":
			if f.luks[dev] == nil {
				return nil, errors.New("not luks")
			}
		case "luksFormat":
			f.luks[dev] = f.read(arg(args, "--key-file"))
		}
		return nil, nil
	case "/usr/lib/systemd/systemd-cryptsetup":
		key := f.read(args[3])
		os.Remove(args[3]) // keyfile-erase
		if !bytes.Equal(f.luks[args[2]], key) {
			return nil, errors.New("wrong key")
		}
		f.opened = key
		f.pcr[15] = h(make([]byte, 32), h([]byte("cryptsetup:var"), key)) // volume key measurement
		return nil, nil
	case "mount", "umount":
		f.mounts = append(f.mounts, name+" "+args[len(args)-1])
		return nil, nil
	case "mkfs.ext4":
		return nil, nil
	}
	f.t.Fatalf("fake TPM: unexpected command %s %v", name, args)
	return nil, nil
}

// ----------------------------------------------------------------- helpers

type env struct {
	c   Config
	f   *fakeTPM
	dev string
}

func signedPolicy(t *testing.T, pcr11 []byte, epoch int) tpmpolicy.File {
	t.Helper()
	eName := fakeName(handleNum(Epoch.Handle), Epoch.Final, fakePE)
	approved, err := tpmpolicy.Approved(fakePol11(pcr11), epoch, eName)
	if err != nil {
		t.Fatal(err)
	}
	sig := "SIG:" + hex.EncodeToString(tpmpolicy.SignedMessage(approved))
	return tpmpolicy.File{Version: 1, Epoch: epoch, PCR11Policy: hex.EncodeToString(fakePol11(pcr11)),
		Approved: hex.EncodeToString(approved), Ref: tpmpolicy.Ref, Signature: base64.StdEncoding.EncodeToString([]byte(sig))}
}

func newEnv(t *testing.T) *env {
	d := t.TempDir()
	e := &env{
		c: Config{RunDir: filepath.Join(d, "run"), PubKey: filepath.Join(d, "pub.pem"),
			PolicyDir: "EFI/enklave/policy", RollbackRel: "lib/enklave/rollback-counter"},
		f:   newFakeTPM(t),
		dev: "/dev/vda8",
	}
	e.installPolicy(t, signedPolicy(t, e.f.pcr[11], 0))
	return e
}

func (e *env) installPolicy(t *testing.T, p tpmpolicy.File) {
	t.Helper()
	dir := filepath.Join(e.c.espMount(), e.c.PolicyDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("uki-epoch%d.json", p.Epoch)), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// boot runs repart, unlock and verify like the units do.
func (e *env) boot(t *testing.T) error {
	t.Helper()
	// /run is a tmpfs: drop state of the previous boot, keep ESP + /var dirs
	for _, p := range []string{e.c.CreatedFlag(), e.c.policyCache(), e.c.ResultFile(), e.c.CounterFile(), e.c.EpochFile()} {
		os.Remove(p)
	}
	for _, ix := range e.f.nv {
		ix.attrs &^= attrReadLocked // READ_STCLEAR
	}
	e.f.pcr[15] = make([]byte, 32)
	if err := Repart(e.c, e.f, []string{"--dry-run=no"}); err != nil {
		return fmt.Errorf("repart: %w", err)
	}
	if _, err := Unlock(e.c, e.f, e.dev, "/dev/vda1"); err != nil {
		return fmt.Errorf("unlock: %w", err)
	}
	if _, err := Verify(e.c, e.f); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}

func (e *env) laterBoots() { e.f.repart = `[{"type":"var","activity":"unchanged"}]` }

func (e *env) fileCounter(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.c.varMount(), e.c.RollbackRel))
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func (e *env) tpmCounter() uint64 {
	return binary.BigEndian.Uint64(e.f.nv[handleNum(Counter.Handle)].data)
}

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Fatalf("err = %v, want %q", err, sub)
	}
}

// ----------------------------------------------------------------- tests

func TestFirstAndLaterBoots(t *testing.T) {
	e := newEnv(t)
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	f := e.f
	for _, ix := range allIndices {
		got := f.nv[handleNum(ix.Handle)]
		if got == nil || got.attrs != ix.Final {
			t.Fatalf("%s: %+v", ix.Name, got)
		}
	}
	if !f.hier.Locked() {
		t.Error("hierarchies not locked after first boot")
	}
	if !bytes.Equal(f.nv[handleNum(Secret.Handle)].data, f.opened) || len(f.opened) != 64 {
		t.Error("secret index does not hold the LUKS key")
	}
	if e.fileCounter(t) != e.tpmCounter() {
		t.Errorf("file %d tpm %d", e.fileCounter(t), e.tpmCounter())
	}
	if _, err := os.Stat(e.c.keyFile()); !errors.Is(err, os.ErrNotExist) {
		t.Error("key file left behind")
	}
	if _, err := os.Stat(e.c.work()); !errors.Is(err, os.ErrNotExist) {
		t.Error("work dir left behind")
	}
	joined := strings.Join(f.calls, "\n")
	for _, want := range []string{
		"--integrity hmac-sha256", "--pbkdf argon2id", "--cipher aes-xts-plain64", "--key-size 512",
		"headless=true,keyfile-erase,tpm2-measure-pcr=yes", "tpm2_clearcontrol -C l s", "cryptsetup token import",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in calls", want)
		}
	}

	c1 := e.tpmCounter()
	e.laterBoots()
	f.calls = nil
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if e.tpmCounter() != c1+1 || e.fileCounter(t) != c1+1 {
		t.Errorf("counter did not advance: tpm %d file %d", e.tpmCounter(), e.fileCounter(t))
	}
	joined = strings.Join(f.calls, "\n")
	for _, bad := range []string{"tpm2_nvdefine", "luksFormat", "mkfs", "tpm2_changeauth", "tpm2_clearcontrol"} {
		if strings.Contains(joined, bad) {
			t.Errorf("later boot ran %s", bad)
		}
	}
	if f.nv[handleNum(Secret.Handle)].attrs&attrReadLocked == 0 {
		t.Error("secret not read-locked after unlock")
	}
	if _, err := ReadNV(f, Secret); err == nil {
		t.Error("secret readable after boot")
	}
}

func TestAttacks(t *testing.T) {
	cases := []struct {
		name string
		prep func(t *testing.T, e *env)
		want string
	}{
		{"swapped volume (other key)", func(t *testing.T, e *env) {
			e.f.luks[e.dev] = bytes.Repeat([]byte{0xAA}, 64)
		}, "wrong key"},
		{"snapshot rollback", func(t *testing.T, e *env) {
			p := filepath.Join(e.c.varMount(), e.c.RollbackRel)
			if err := os.WriteFile(p, []byte(strconv.FormatUint(e.fileCounter(t)-1, 10)), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "ROLLBACK"},
		{"rollback file deleted", func(t *testing.T, e *env) {
			os.Remove(filepath.Join(e.c.varMount(), e.c.RollbackRel))
		}, "anti-rollback file missing"},
		{"tainted PCR 12", func(t *testing.T, e *env) { e.f.pcr[12] = bytes.Repeat([]byte{1}, 32) }, "PCR 12"},
		{"PCR 7 changed", func(t *testing.T, e *env) { e.f.pcr[7] = bytes.Repeat([]byte{9}, 32) }, "authPolicy"},
		{"other UKI (PCR 11)", func(t *testing.T, e *env) { e.f.pcr[11] = bytes.Repeat([]byte{12}, 32) }, "no signed approved policy"},
		{"forged signature", func(t *testing.T, e *env) {
			p := signedPolicy(t, e.f.pcr[11], 0)
			p.Signature = base64.StdEncoding.EncodeToString([]byte("SIG:00"))
			os.RemoveAll(filepath.Join(e.c.espMount(), e.c.PolicyDir))
			e.installPolicy(t, p)
		}, "signature rejected"},
		{"tampered epoch claim", func(t *testing.T, e *env) {
			p := signedPolicy(t, e.f.pcr[11], 0)
			p.Epoch = 3
			os.RemoveAll(filepath.Join(e.c.espMount(), e.c.PolicyDir))
			e.installPolicy(t, p)
		}, "does not match epoch"},
		{"epoch revoked", func(t *testing.T, e *env) {
			binary.BigEndian.PutUint64(e.f.nv[handleNum(Epoch.Handle)].data, 1)
		}, "revoked"},
		{"secret index removed", func(t *testing.T, e *env) { delete(e.f.nv, handleNum(Secret.Handle)) }, "missing"},
		{"record index removed", func(t *testing.T, e *env) { delete(e.f.nv, handleNum(Record.Handle)) }, "missing"},
		{"record altered", func(t *testing.T, e *env) {
			e.f.nv[handleNum(Record.Handle)].data = bytes.Repeat([]byte{3}, 32)
		}, "does not match NV record"},
		{"weak secret attributes", func(t *testing.T, e *env) {
			e.f.nv[handleNum(Secret.Handle)].attrs |= 0x2 // OWNERWRITE
		}, "attributes"},
		{"counter policy replaced", func(t *testing.T, e *env) {
			e.f.nv[handleNum(Counter.Handle)].policy = bytes.Repeat([]byte{5}, 32)
		}, "authorization"},
		{"tpm error", func(t *testing.T, e *env) {
			e.f.fail = map[string]error{"tpm2_nvincrement": errors.New("boom")}
		}, "boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if err := e.boot(t); err != nil {
				t.Fatal(err)
			}
			e.laterBoots()
			tc.prep(t, e)
			err := e.boot(t)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				if tc.name == "counter policy replaced" && err != nil && strings.Contains(err.Error(), "authPolicy") {
					return
				}
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCrashBetweenFileAndCounterRecovers(t *testing.T) {
	e := newEnv(t)
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	e.laterBoots()
	c := e.tpmCounter()
	// simulate: F written as C+1, power lost before the TPM increment
	p := filepath.Join(e.c.varMount(), e.c.RollbackRel)
	if err := os.WriteFile(p, []byte(strconv.FormatUint(c+1, 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if e.tpmCounter() != c+2 || e.fileCounter(t) != c+2 {
		t.Errorf("tpm %d file %d, want %d", e.tpmCounter(), e.fileCounter(t), c+2)
	}
}

func TestFirstBootRefusals(t *testing.T) {
	cases := []struct {
		name string
		prep func(t *testing.T, e *env)
		want string
	}{
		{"pre-defined index", func(t *testing.T, e *env) {
			e.f.nv[handleNum(Secret.Handle)] = &nvIndex{attrs: 0x00060006, size: 64}
		}, "already exists"},
		{"tainted PCR 12", func(t *testing.T, e *env) { e.f.pcr[12] = bytes.Repeat([]byte{1}, 32) }, "PCR 12"},
		{"existing LUKS header", func(t *testing.T, e *env) { e.f.luks[e.dev] = []byte("x") }, "LUKS header"},
		{"owner auth already set", func(t *testing.T, e *env) { e.f.hier.OwnerAuthSet = true }, "not a fresh TPM"},
		{"no policy for this UKI", func(t *testing.T, e *env) {
			os.RemoveAll(filepath.Join(e.c.espMount(), e.c.PolicyDir))
		}, "no signed approved policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			tc.prep(t, e)
			wantErr(t, e.boot(t), tc.want)
			if tc.name != "pre-defined index" && len(e.f.luks[e.dev]) == 64 {
				t.Error("volume formatted despite refusal")
			}
		})
	}
}

func TestInterruptedLockdownCompletes(t *testing.T) {
	e := newEnv(t)
	e.f.fail = map[string]error{"tpm2_changeauth": errors.New("power loss")}
	wantErr(t, e.boot(t), "power loss")
	e.f.fail = nil
	e.laterBoots()
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if !e.f.hier.Locked() {
		t.Error("lock-down not completed")
	}
}

func TestRevocationOfOlderEpochs(t *testing.T) {
	e := newEnv(t)
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	e.laterBoots()
	// update to an epoch-2 UKI: new PCR 11 value, policy signed for epoch 2
	e.f.pcr[11] = bytes.Repeat([]byte{0x22}, 32)
	e.installPolicy(t, signedPolicy(t, e.f.pcr[11], 2))
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	if v := binary.BigEndian.Uint64(e.f.nv[handleNum(Epoch.Handle)].data); v != 3 {
		t.Fatalf("E = %x, want 3 (epochs 0 and 1 revoked)", v)
	}
	// the old epoch-0 UKI can no longer read the key
	e.f.pcr[11] = bytes.Repeat([]byte{11}, 32)
	wantErr(t, e.boot(t), "revoked")
}

func TestRepart(t *testing.T) {
	for _, tc := range []struct {
		json    string
		created bool
		err     bool
	}{
		{`[{"type":"esp","activity":"unchanged"},{"type":"var","activity":"create"}]`, true, false},
		{`[{"type":"var","activity":"unchanged"}]`, false, false},
		{`[]`, false, true},
		{`[{"type":"var","activity":"create"},{"type":"var","activity":"create"}]`, false, true},
		{`not json`, false, true},
	} {
		e := newEnv(t)
		e.f.repart = tc.json
		err := Repart(e.c, e.f, []string{"--definitions=/x"})
		if (err != nil) != tc.err {
			t.Errorf("%s: err = %v", tc.json, err)
		}
		if _, serr := os.Stat(e.c.CreatedFlag()); (serr == nil) != tc.created {
			t.Errorf("%s: created flag = %v", tc.json, serr == nil)
		}
	}
	e := newEnv(t)
	e.f.pcr[12] = bytes.Repeat([]byte{1}, 32)
	wantErr(t, Repart(e.c, e.f, nil), "PCR 12")
	for _, c := range e.f.calls {
		if strings.HasPrefix(c, "systemd-repart") {
			t.Error("repart ran with tainted PCR 12")
		}
	}
}

// Output captured from tpm2-tools 5.7 on swtpm.
const realPublic = `0x1800e01:
  name: 000b07faf7a954ae3470233469a156a097f0f8ce25d985477420176931486d2394e4
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: policywrite|writelocked|writedefine|authread|no_da|written
    value: 0x22042808
  size: 32
  authorization policy: EB05C41A8B59DE8F4426211037729B203124BC759E30950A87CFCE5B00FF5B84

`

func TestParseNVPublicReal(t *testing.T) {
	p, err := ParseNVPublic([]byte(realPublic))
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := hex.DecodeString("EB05C41A8B59DE8F4426211037729B203124BC759E30950A87CFCE5B00FF5B84")
	if p.NameAlg != 0xB || p.Attributes != Record.Final || p.Size != 32 || !bytes.Equal(p.AuthPolicy, pol) || len(p.Name) != 34 {
		t.Errorf("%+v", p)
	}
	if err := CheckPublic(Record, p, Record.Final, pol); err != nil {
		t.Error(err)
	}
	if err := CheckPublic(Record, p, Record.Final, nil); err == nil {
		t.Error("empty expected policy accepted")
	}
	if _, err := ParseNVPublic([]byte("0x1800e01:\n  size: 32\n")); err == nil {
		t.Error("incomplete output accepted")
	}
	// attribute constants as observed on swtpm
	want := map[string]uint32{"record": 0x22042808, "secret": 0xB2082808, "counter": 0x22040018, "epoch": 0x22040028}
	for _, ix := range allIndices {
		if ix.Final != want[ix.Name] {
			t.Errorf("%s final 0x%08x, want 0x%08x", ix.Name, ix.Final, want[ix.Name])
		}
	}
}

func TestReadHierarchyReal(t *testing.T) {
	out := "TPM2_PT_PERMANENT:\n  ownerAuthSet:              1\n  endorsementAuthSet:        1\n  lockoutAuthSet:            1\n" +
		"  reserved1:                 0\n  disableClear:              1\n  inLockout:                 0\nTPM2_PT_STARTUP_CLEAR:\n  phEnable:                  1\n"
	f := &fakeRunnerStr{out: out}
	h, err := ReadHierarchy(f)
	if err != nil || !h.Locked() {
		t.Fatalf("%+v %v", h, err)
	}
	f.out = strings.Replace(out, "disableClear:              1", "disableClear:              0", 1)
	if h, _ := ReadHierarchy(f); h.Locked() {
		t.Error("disableClear=0 reported locked")
	}
	f.out = "TPM2_PT_STARTUP_CLEAR:\n"
	if _, err := ReadHierarchy(f); err == nil {
		t.Error("missing flags accepted")
	}
}

type fakeRunnerStr struct{ out string }

func (f *fakeRunnerStr) Run(string, ...string) ([]byte, error) { return []byte(f.out), nil }

func TestProbeAfterBootRefused(t *testing.T) {
	e := newEnv(t)
	if err := e.boot(t); err != nil {
		t.Fatal(err)
	}
	// keep the policy cache, move PCR 11 past the signed phase (sysinit)
	os.MkdirAll(e.c.RunDir, 0o700)
	b, _ := json.Marshal(signedPolicy(t, e.f.pcr[11], 0))
	os.WriteFile(e.c.policyCache(), b, 0o600)
	e.f.pcr[11] = bytes.Repeat([]byte{0x5c}, 32)
	if err := Probe(e.c, e.f); err == nil {
		t.Fatal("key readable after boot")
	}
	// even with the phase still valid, the read lock holds
	e.f.pcr[11] = bytes.Repeat([]byte{11}, 32)
	if err := Probe(e.c, e.f); err == nil || !strings.Contains(err.Error(), "LOCKED") {
		t.Fatalf("read lock not effective: %v", err)
	}
}
