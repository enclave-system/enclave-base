package varauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"enklave.local/base/internal/ekcert"
	"enklave.local/base/internal/sbstate/sbtest"
	"enklave.local/base/internal/tpmpolicy"
)

// fakeTPM models the TPM objects and policy semantics enklave relies on.
// Policy digests are computed as a chain like on a real TPM (with fake
// primitives, except PolicyNV which uses the real formula), so a session
// satisfies an object only if it reproduces that object's authPolicy.

type nvIdx struct {
	attrs  uint32
	policy []byte
	data   []byte
	size   int
	auth   string
}

type hierarchy struct {
	auth   string
	policy []byte
}

type fsess struct {
	policy, salted bool
	dec, encr      bool // parameter encryption attributes (salted default: both)
	d              []byte
	avUsed         bool
	cc             string
}

type ticket struct {
	approved []byte
	ref      string
}

type fakeTPM struct {
	t          *testing.T
	pcr        map[int][]byte
	nv         map[uint64]*nvIdx
	sess       map[string]*fsess
	tickets    map[string]ticket
	h          map[string]*hierarchy
	disClear   bool
	phEnable   bool
	pers       map[uint64][]byte // persistent objects: TPM2B_PUBLIC
	ek         *ecdsa.PrivateKey // derived from the endorsement seed
	luks       map[string][]byte
	stateDir   string
	repart     string
	fail       map[string]error
	calls      []string
	violations []string
	// noAuthorizeNV models a TPM older than library revision 1.38.
	noAuthorizeNV bool
	// Dictionary-attack state (defaults of swtpm). The endorsement key is DA
	// protected: after it was used as a salt key, a power cut without
	// TPM2_Shutdown counts as a failed authorization.
	daCounter, daMax, daInterval, daRecovery uint64
	daUsed                                   bool
	// mitm, if set, rewrites every TPM2_ReadPublic response for a persistent
	// key (an active bus interposer); readPubs counts the responses.
	mitm     func(n int, real []byte) []byte
	readPubs int
}

// readPublic is what the host sees for TPM2_ReadPublic of a persistent key.
func (f *fakeTPM) readPublic(handle uint64) []byte {
	real := f.pers[handle]
	if real == nil || f.mitm == nil {
		return real
	}
	f.readPubs++
	return f.mitm(f.readPubs, real)
}

func newFakeTPM(t *testing.T, stateDir string) *fakeTPM {
	return &fakeTPM{
		t: t,
		pcr: map[int][]byte{
			0: bytes.Repeat([]byte{0xf0}, 32), 2: bytes.Repeat([]byte{0xf2}, 32), 4: bytes.Repeat([]byte{0xf4}, 32),
			7: bytes.Repeat([]byte{7}, 32), 11: bytes.Repeat([]byte{11}, 32),
			12: make([]byte, 32), 15: make([]byte, 32),
		},
		nv: map[uint64]*nvIdx{}, sess: map[string]*fsess{}, tickets: map[string]ticket{},
		h:        map[string]*hierarchy{"o": {}, "e": {}, "l": {}, "p": {auth: "firmware"}},
		phEnable: true,
		pers:     map[uint64][]byte{},
		ek:       newEKKey(),
		daMax:    3, daInterval: 1000, daRecovery: 1000,
		luks:     map[string][]byte{},
		stateDir: stateDir,
		repart:   `[{"type":"var","activity":"create"}]`,
	}
}

func h(parts ...[]byte) []byte {
	s := sha256.New()
	for _, p := range parts {
		s.Write(p)
	}
	return s.Sum(nil)
}

func newEKKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// ekPublic is the TPM2B_PUBLIC of the endorsement key the TPM derives.
func (f *fakeTPM) ekPublic() []byte {
	k, err := ekcert.FromPublicKey(&f.ek.PublicKey)
	if err != nil {
		panic(err)
	}
	return k.TPM2B()
}

// powerCut models a power loss (no TPM2_Shutdown) followed by TPM2_Startup.
func (f *fakeTPM) powerCut() {
	if f.daUsed && f.daInterval != 0 {
		f.daCounter++
	}
	f.daUsed = false
}

func (f *fakeTPM) inLockout() bool { return f.daInterval != 0 && f.daCounter >= f.daMax }

// nvName is the real TPM Name of an index.
func nvName(handle uint64, ix *nvIdx) []byte {
	return tpmpolicy.NVName(uint32(handle), ix.attrs, ix.policy, ix.size)
}

var ccCodes = map[string]uint32{"TPM2_CC_NV_ChangeAuth": tpmpolicy.CCNVChangeAuth, "TPM2_CC_NV_SetBits": tpmpolicy.CCNVSetBits}

// pcrConcat returns the values of a "sha256:a,b,c" selection.
func (f *fakeTPM) pcrConcat(sel string) []byte {
	var out []byte
	for _, s := range strings.Split(strings.TrimPrefix(sel, "sha256:"), ",") {
		n, _ := strconv.Atoi(s)
		out = append(out, f.pcr[n]...)
	}
	return out
}

func fakePol11(pcr11 []byte) []byte { return h([]byte("pcr11"), make([]byte, 32), pcr11) }

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

func (f *fakeTPM) violate(format string, a ...any) {
	f.violations = append(f.violations, fmt.Sprintf(format, a...))
}

// sessionAuth parses "session:x[+hex:auth]".
func (f *fakeTPM) sessionAuth(v string) (*fsess, string, error) {
	if !strings.HasPrefix(v, "session:") {
		return nil, "", fmt.Errorf("not a session: %q", v)
	}
	name, auth, _ := strings.Cut(strings.TrimPrefix(v, "session:"), "+hex:")
	s := f.sess[name]
	if s == nil {
		return nil, "", errors.New("unknown session")
	}
	return s, auth, nil
}

// authEntity checks authorization of an entity with authValue/policy.
func (f *fakeTPM) authEntity(v string, auth string, policy []byte, admin string) (*fsess, error) {
	if v == "" {
		if auth != "" {
			return nil, errors.New("TPM_RC_BAD_AUTH 0x9a2 authorization failure")
		}
		return nil, nil
	}
	s, given, err := f.sessionAuth(v)
	if err != nil {
		return nil, err
	}
	if !s.policy { // HMAC session: knows the authValue
		if given != auth {
			return nil, errors.New("TPM_RC_BAD_AUTH 0x9a2 authorization failure")
		}
		return s, nil
	}
	if len(policy) == 0 || !bytes.Equal(s.d, policy) {
		return nil, errors.New("TPM_RC_POLICY_FAIL 0x99d")
	}
	if s.avUsed && given != auth {
		return nil, errors.New("TPM_RC_AUTH_FAIL 0x98e")
	}
	if admin != "" && s.cc != admin {
		return nil, errors.New("TPM_RC_POLICY_FAIL 0x99d (admin role needs PolicyCommandCode)")
	}
	return s, nil
}

func (f *fakeTPM) requireEnc(s *fsess, want, what string) {
	if s == nil || !s.salted || (want == "decrypt" && !s.dec) || (want == "encrypt" && !s.encr) {
		f.violate("%s without a salted %s session", what, want)
	}
}

// garbled models the real TPM: the parameter-encryption key of a policy
// authorization session includes the authValue of the authorized entity, so
// an encrypted parameter decrypts to garbage when the caller does not supply
// that (non-empty) authValue (observed with swtpm and tpm2-tools 5.7).
func (f *fakeTPM) garbled(v, entityAuth string) bool {
	s, given, err := f.sessionAuth(v)
	return err == nil && s.policy && s.salted && s.dec && entityAuth != "" && given != entityAuth
}

func (f *fakeTPM) nvIndex(handle string) (*nvIdx, uint64, error) {
	n := handleNum(handle)
	if ix := f.nv[n]; ix != nil {
		return ix, n, nil
	}
	return nil, n, errors.New("TPM_RC_HANDLE")
}

func (f *fakeTPM) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	s := f.sess[arg(args, "-S")]
	switch name {
	case "systemd-repart":
		return []byte(f.repart), nil
	case "tpm2_pcrread":
		n, _ := strconv.Atoi(strings.TrimPrefix(args[0], "sha256:"))
		return []byte(fmt.Sprintf("  sha256:\n    %d : 0x%X\n", n, f.pcr[n])), nil
	case "tpm2_loadexternal":
		return nil, nil
	case "tpm2_flushcontext":
		if args[0] != "-t" {
			delete(f.sess, args[0])
		}
		return nil, nil
	case "tpm2_startauthsession":
		ns := &fsess{policy: args[0] == "--policy-session", d: make([]byte, 32)}
		if args[0] == "--hmac-session" {
			ns.policy = false
		}
		if c := arg(args, "-c"); c != "" {
			// The salt is encrypted to the public key the host holds for the
			// handle: the one inside a serialized ESYS_TR, or, for a raw
			// handle, whatever ESYS's own TPM2_ReadPublic returns.
			var handle uint64
			var seen []byte
			if strings.HasPrefix(c, "0x") {
				handle = handleNum(c)
				seen = f.readPublic(handle)
			} else {
				tr := f.read(c)
				handle = uint64(binary.BigEndian.Uint32(tr[:4]))
				seen = tr[4+2+34+4:]
			}
			if f.pers[handle] == nil {
				return nil, errors.New("TPM_RC_HANDLE (salt key)")
			}
			if !bytes.Equal(seen, f.pers[handle]) {
				// the salt was encrypted to a key the TPM does not hold: whoever
				// holds that key learns the session key; the TPM itself cannot
				// decrypt the salt and refuses (0x2C4 on swtpm)
				f.violate("session salted to a substituted key (bus interposer learns the session key)")
				return nil, errors.New("TPM_RC_VALUE 0x2C4 (salt not decryptable by the TPM)")
			}
			if f.inLockout() {
				return nil, errors.New("TPM_RC_LOCKOUT 0x921: the TPM is in DA lockout mode")
			}
			f.daUsed = true
			ns.salted = true
			ns.dec, ns.encr = true, true // tpm2_startauthsession -c enables both
		}
		trial := args[0] != "--policy-session" && args[0] != "--hmac-session"
		if trial {
			ns.policy = false
		}
		f.sess[arg(args, "-S")] = ns
		return nil, nil
	case "tpm2_sessionconfig":
		for _, a := range args[1:] {
			on := strings.HasPrefix(a, "--enable-")
			switch strings.TrimPrefix(strings.TrimPrefix(a, "--enable-"), "--disable-") {
			case "decrypt":
				f.sess[args[0]].dec = on
			case "encrypt":
				f.sess[args[0]].encr = on
			}
		}
		return nil, nil
	case "tpm2_policyauthorize":
		ref := string(f.read(arg(args, "-q")))
		if len(ref) > 64 { // policyRef is a TPM2B_NONCE (seen with tpm2-tools: "size is larger than buffer")
			return nil, errors.New("policyRef larger than 64 bytes")
		}
		if a := arg(args, "-i"); a != "" { // real session
			approved := f.read(a)
			tk := f.tickets[arg(args, "-t")]
			if !bytes.Equal(tk.approved, approved) || tk.ref != ref || !bytes.Equal(s.d, approved) {
				return nil, errors.New("TPM_RC_POLICY_FAIL 0x99d (authorize)")
			}
		}
		s.d = h([]byte("authorize"), []byte(ref))
		return hexOut(s.d), nil
	case "tpm2_policypcr":
		sel := arg(args, "-l")
		if sel == "sha256:11" {
			s.d = h([]byte("pcr11"), s.d, f.pcr[11])
			return hexOut(s.d), nil
		}
		vals := f.read(arg(args, "-f"))
		if s.policy && !bytes.Equal(vals, f.pcrConcat(sel)) {
			return nil, errors.New("TPM_RC_VALUE (pcr)")
		}
		s.d = h([]byte("p"), []byte(sel), s.d, vals)
		return hexOut(s.d), nil
	case "tpm2_policyauthorizenv":
		ix, n, err := f.nvIndex(args[len(args)-1])
		if err != nil {
			return nil, err
		}
		if ix.attrs&attrWritten == 0 {
			return nil, errors.New("TPM_RC_NV_UNINITIALIZED")
		}
		if s.policy && !bytes.Equal(ix.data, tpmpolicy.DigestNV(s.d)) {
			return nil, errors.New("TPM_RC_VALUE 0x84 (policy does not match the NV index)")
		}
		s.d = tpmpolicy.PolicyAuthorizeNV(nvName(n, ix))
		return hexOut(s.d), nil
	case "tpm2_policycommandcode":
		s.cc = args[len(args)-1]
		s.d = tpmpolicy.PolicyCommandCode(s.d, ccCodes[s.cc])
		return hexOut(s.d), nil
	case "tpm2_policynvwritten":
		s.d = h([]byte("nw"), s.d)
		return hexOut(s.d), nil
	case "tpm2_policyauthvalue":
		s.avUsed = true
		s.d = h([]byte("av"), s.d)
		return hexOut(s.d), nil
	case "tpm2_policyor":
		files := strings.Split(strings.TrimPrefix(arg(args, "-l"), "sha256:"), ",")
		var bs [][]byte
		ok := false
		for _, p := range files {
			b := f.read(p)
			bs = append(bs, b)
			ok = ok || bytes.Equal(b, s.d)
		}
		if s.policy && !ok {
			return nil, errors.New("TPM_RC_VALUE (policyor)")
		}
		s.d = tpmpolicy.PolicyOR(bs...)
		return hexOut(s.d), nil
	case "tpm2_policynv":
		op := f.read(arg(args, "-i"))
		eix := f.nv[handleNum(args[len(args)-2])]
		if eix == nil || eix.attrs&attrWritten == 0 {
			return nil, errors.New("TPM_RC_NV_UNINITIALIZED")
		}
		if s.policy && binary.BigEndian.Uint64(eix.data)&binary.BigEndian.Uint64(op) != 0 {
			return nil, errors.New("TPM_RC_POLICY 0x126 (bit set)")
		}
		s.d = tpmpolicy.PolicyNV(s.d, op, 0, 0x000B, nvName(handleNum(Epoch.Handle), eix))
		return nil, nil
	case "tpm2_verifysignature":
		msg, sig := f.read(arg(args, "-m")), f.read(arg(args, "-s"))
		if string(sig) != "SIG:"+hex.EncodeToString(msg) || len(msg) < 32 {
			return nil, errors.New("TPM_RC_SIGNATURE")
		}
		f.tickets[arg(args, "-t")] = ticket{msg[:32], string(msg[32:])}
		return nil, nil
	case "tpm2_getcap":
		var b strings.Builder
		switch args[0] {
		case "commands":
			b.WriteString("TPM2_CC_PolicyAuthorizeNV:\n  value: 0x6000192\n")
			if f.noAuthorizeNV {
				b.Reset()
			}
		case "handles-nv-index":
			for n := range f.nv {
				fmt.Fprintf(&b, "- 0x%X\n", n)
			}
		case "handles-persistent":
			for n := range f.pers {
				fmt.Fprintf(&b, "- 0x%X\n", n)
			}
		case "properties-variable":
			v := func(x bool) int {
				if x {
					return 1
				}
				return 0
			}
			fmt.Fprintf(&b, "TPM2_PT_PERMANENT:\n  ownerAuthSet:              %d\n  endorsementAuthSet:        %d\n"+
				"  lockoutAuthSet:            %d\n  reserved1:                 0\n  disableClear:              %d\n  inLockout:                 %d\n"+
				"TPM2_PT_STARTUP_CLEAR:\n  phEnable:                  %d\n  shEnable:                  1\n"+
				"TPM2_PT_LOCKOUT_COUNTER: 0x%X\nTPM2_PT_MAX_AUTH_FAIL: 0x%X\nTPM2_PT_LOCKOUT_INTERVAL: 0x%X\nTPM2_PT_LOCKOUT_RECOVERY: 0x%X\n",
				v(f.h["o"].auth != ""), v(f.h["e"].auth != ""), v(f.h["l"].auth != ""), v(f.disClear), v(f.inLockout()), v(f.phEnable),
				f.daCounter, f.daMax, f.daInterval, f.daRecovery)
		}
		return []byte(b.String()), nil
	case "tpm2_dictionarylockout":
		// lockout hierarchy authorization; a policy session works in lockout too
		l := f.h["l"]
		if _, err := f.authEntity(arg(args, "-p"), l.auth, l.policy, ""); err != nil {
			return nil, err
		}
		if args[0] == "-c" {
			f.daCounter = 0
			return nil, nil
		}
		f.daMax, _ = strconv.ParseUint(arg(args, "-n"), 10, 64)
		f.daInterval, _ = strconv.ParseUint(arg(args, "-t"), 10, 64)
		f.daRecovery, _ = strconv.ParseUint(arg(args, "-l"), 10, 64)
		return nil, nil
	case "tpm2_hierarchycontrol":
		if f.h["p"].auth != "" {
			return nil, errors.New("exit status 1 (ERROR: Esys_HierarchyControl(0x9A2) - tpm:session(1):authorization failure without DA implications)")
		}
		f.phEnable = false
		return nil, nil
	case "tpm2_setprimarypolicy":
		hi := f.h[arg(args, "-C")]
		if _, err := f.authEntity(arg(args, "-P"), hi.auth, hi.policy, ""); err != nil {
			return nil, err
		}
		hi.policy = f.read(arg(args, "-L"))
		if f.garbled(arg(args, "-P"), hi.auth) {
			hi.policy = h([]byte("garbage"), hi.policy)
		}
		return nil, nil
	case "tpm2_clearcontrol":
		if f.h["l"].auth != "" {
			return nil, errors.New("TPM_RC_BAD_AUTH (lockout)")
		}
		f.disClear = true
		return nil, nil
	case "tpm2_changeauth":
		target := arg(args, "-c")
		var newAuth string
		for _, a := range args {
			if strings.HasPrefix(a, "hex:") {
				newAuth = strings.TrimPrefix(a, "hex:")
			}
		}
		if hi := f.h[target]; hi != nil {
			sx, err := f.authEntity(arg(args, "-p"), hi.auth, hi.policy, "")
			if err != nil {
				return nil, err
			}
			old := hi.auth
			hi.auth = newAuth
			if aux := f.sess[arg(args, "-S")]; aux != nil && !aux.policy {
				f.requireEnc(aux, "decrypt", "changeauth "+target) // auxiliary encryption session
			} else {
				f.requireEnc(sx, "decrypt", "changeauth "+target)
				if f.garbled(arg(args, "-p"), old) {
					hi.auth = "garbage"
				}
			}
			return nil, nil
		}
		ix, _, err := f.nvIndex(target)
		if err != nil {
			return nil, err
		}
		sx, err := f.authEntity(arg(args, "-p"), ix.auth, ix.policy, "TPM2_CC_NV_ChangeAuth")
		if err != nil {
			return nil, err
		}
		f.requireEnc(sx, "decrypt", "nv changeauth")
		ix.auth = newAuth
		return nil, nil
	case "tpm2_createek": // endorsement hierarchy authorization
		hi := f.h["e"]
		if _, err := f.authEntity(arg(args, "-P"), hi.auth, hi.policy, ""); err != nil {
			return nil, err
		}
		pub := f.ekPublic()
		if arg(args, "-G") != "ecc" {
			pub = []byte("OTHER") // only the ECC EK exists in this model
		}
		if err := os.WriteFile(arg(args, "-u"), pub, 0o600); err != nil {
			return nil, err
		}
		return nil, os.WriteFile(arg(args, "-c"), pub, 0o600)
	case "tpm2_evictcontrol":
		o := f.h["o"]
		if _, err := f.authEntity(arg(args, "-P"), o.auth, o.policy, ""); err != nil {
			return nil, err
		}
		c := arg(args, "-c")
		if strings.HasPrefix(c, "0x") { // evict a persistent object
			delete(f.pers, handleNum(c))
			return nil, nil
		}
		var target string
		for _, a := range args {
			if strings.HasPrefix(a, "0x81") {
				target = a
			}
		}
		f.pers[handleNum(target)] = f.read(c)
		return nil, nil
	case "tpm2_readpublic":
		var pub []byte
		if c := arg(args, "-c"); strings.HasPrefix(c, "0x") {
			pub = f.readPublic(handleNum(c))
		} else {
			pub = f.read(c) // transient object context
			if f.mitm != nil {
				f.readPubs++
				pub = f.mitm(f.readPubs, pub)
			}
		}
		if pub == nil {
			return nil, errors.New("TPM_RC_HANDLE")
		}
		return nil, os.WriteFile(arg(args, "-o"), pub, 0o600)
	case "tpm2_nvdefine":
		n := handleNum(args[0])
		if f.nv[n] != nil {
			return nil, errors.New("TPM_RC_NV_DEFINED")
		}
		o := f.h["o"]
		if _, err := f.authEntity(arg(args, "-P"), o.auth, o.policy, ""); err != nil {
			return nil, err
		}
		a, _ := strconv.ParseUint(strings.TrimPrefix(arg(args, "-a"), "0x"), 16, 32)
		size, _ := strconv.Atoi(arg(args, "-s"))
		f.nv[n] = &nvIdx{attrs: uint32(a), policy: f.read(arg(args, "-L")), size: size}
		return nil, nil
	case "tpm2_nvundefine":
		o := f.h["o"]
		if _, err := f.authEntity(arg(args, "-P"), o.auth, o.policy, ""); err != nil {
			return nil, err
		}
		delete(f.nv, handleNum(args[0]))
		return nil, nil
	case "tpm2_nvsetbits", "tpm2_nvwrite", "tpm2_nvwritelock", "tpm2_nvreadlock", "tpm2_nvincrement", "tpm2_nvread":
		ix, n, err := f.nvIndex(args[0])
		if err != nil {
			return nil, err
		}
		auth := arg(args, "-P")
		readAuthFree := name == "tpm2_nvread" && ix.attrs&attrAuthRead != 0 && auth == ""
		var sx *fsess
		if arg(args, "-C") == "o" { // owner authorization
			if name != "tpm2_nvwrite" || ix.attrs&attrOwnerWrite == 0 {
				return nil, errors.New("TPM_RC_NV_AUTHORIZATION (owner)")
			}
			if sx, err = f.authEntity(auth, f.h["o"].auth, f.h["o"].policy, ""); err != nil {
				return nil, err
			}
		} else if !readAuthFree {
			if ix.attrs&attrOwnerWrite != 0 && name != "tpm2_nvread" {
				return nil, errors.New("TPM_RC_NV_AUTHORIZATION (index auth cannot write an owner-write index)")
			}
			if sx, err = f.authEntity(auth, ix.auth, ix.policy, ""); err != nil {
				return nil, err
			}
			if sx == nil && ix.attrs&(attrPolicyWrite|attrPolicyRead) != 0 {
				return nil, errors.New("TPM_RC_AUTH_UNAVAILABLE (policy index)")
			}
		}
		switch name {
		case "tpm2_nvsetbits":
			if sx != nil && sx.cc == "TPM2_CC_NV_SetBits" && ix.attrs&attrWritten != 0 {
				return nil, errors.New("TPM_RC_POLICY_FAIL (init branch on written index)")
			}
			bits, _ := strconv.ParseUint(strings.TrimPrefix(arg(args, "-i"), "0x"), 16, 64)
			if ix.data == nil {
				ix.data = make([]byte, 8)
			}
			binary.BigEndian.PutUint64(ix.data, binary.BigEndian.Uint64(ix.data)|bits)
			ix.attrs |= attrWritten
		case "tpm2_nvwrite":
			if ix.attrs&attrWriteLocked != 0 {
				return nil, errors.New("TPM_RC_NV_LOCKED")
			}
			ix.data = f.read(arg(args, "-i"))
			ix.attrs |= attrWritten
			if n == handleNum(Secret.Handle) {
				f.requireEnc(sx, "decrypt", "secret write")
			}
		case "tpm2_nvwritelock":
			ix.attrs |= attrWriteLocked
		case "tpm2_nvreadlock":
			ix.attrs |= attrReadLocked
		case "tpm2_nvincrement":
			if ix.data == nil {
				ix.data = make([]byte, 8)
				binary.BigEndian.PutUint64(ix.data, 41)
			}
			binary.BigEndian.PutUint64(ix.data, binary.BigEndian.Uint64(ix.data)+1)
			ix.attrs |= attrWritten
		case "tpm2_nvread":
			if ix.attrs&attrWritten == 0 {
				return nil, errors.New("TPM_RC_NV_UNINITIALIZED")
			}
			if ix.attrs&attrReadLocked != 0 {
				return nil, errors.New("TPM_RC_NV_LOCKED (read)")
			}
			if n == handleNum(Secret.Handle) {
				f.requireEnc(sx, "encrypt", "secret read")
			}
			return append([]byte{}, ix.data...), nil
		}
		return nil, nil
	case "tpm2_nvreadpublic":
		ix, n, err := f.nvIndex(args[0])
		if err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf("0x%x:\n  name: %x\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n"+
			"  attributes:\n    friendly: x\n    value: 0x%X\n  size: %d\n  authorization policy: %X\n\n",
			n, nvName(n, ix), ix.attrs, ix.size, ix.policy)), nil
	case "cryptsetup":
		dev := args[len(args)-1]
		switch args[0] {
		case "isLuks":
			if f.luks[dev] == nil {
				return nil, errors.New("not luks")
			}
		case "luksFormat":
			f.luks[dev] = f.read(arg(args, "--key-file"))
		case "erase":
			if f.luks[dev] == nil {
				return nil, errors.New("not luks")
			}
			f.luks[dev] = []byte("erased")
		}
		return nil, nil
	case "/usr/lib/systemd/systemd-cryptsetup":
		key := f.read(args[3])
		os.Remove(args[3])
		if !bytes.Equal(f.luks[args[2]], key) {
			return nil, errors.New("wrong key")
		}
		f.pcr[15] = h(make([]byte, 32), h([]byte("cryptsetup:var"), key))
		return nil, nil
	case "mkfs.ext4":
		ents, _ := os.ReadDir(f.stateDir)
		for _, e := range ents {
			os.RemoveAll(filepath.Join(f.stateDir, e.Name()))
		}
		return nil, os.MkdirAll(filepath.Join(f.stateDir, "lost+found"), 0o700)
	case "mount", "umount":
		return nil, nil
	}
	f.t.Fatalf("fake TPM: unexpected command %s %v", name, args)
	return nil, nil
}

// ----------------------------------------------------------------- env

// testCA issues the EK certificates of the fake TPMs ("TPM vendor").
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var (
	vendorOnce sync.Once
	vendor     *testCA
	testNow    = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
)

func newTestCA(cn string) *testCA {
	key := newEKKey()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: testNow.Add(-24 * time.Hour), NotAfter: testNow.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, key}
}

func vendorCA() *testCA {
	vendorOnce.Do(func() { vendor = newTestCA("fake TPM vendor EK CA") })
	return vendor
}

// ekCertificate issues an EK certificate like TPM vendors do (critical
// directoryName subjectAltName with the TPM attributes, EK extended key usage).
func (ca *testCA) ekCertificate(pub *ecdsa.PublicKey) []byte { return ca.certificate(pub, nil) }

func (ca *testCA) certificate(pub *ecdsa.PublicKey, mut func(*x509.Certificate)) []byte {
	var rdn pkix.RDNSequence
	for _, last := range []int{1, 2, 3} { // tcg-at-tpmManufacturer, -Model, -Version
		rdn = append(rdn, pkix.RelativeDistinguishedNameSET{{Type: asn1.ObjectIdentifier{2, 23, 133, 2, last}, Value: "id:00001014"}})
	}
	name, _ := asn1.Marshal(rdn)
	san, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: name}})
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour),
		KeyUsage:           x509.KeyUsageKeyAgreement,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}},
		ExtraExtensions:    []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: san}}}
	if mut != nil {
		mut(tpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		panic(err)
	}
	return der
}

// setEKCert stores an EK certificate in the ECC EK certificate index (padded
// like a fixed-size NV index); nil removes the index.
func (f *fakeTPM) setEKCert(der []byte) {
	n := handleNum(ekcert.ECC.CertHandle())
	if der == nil {
		delete(f.nv, n)
		return
	}
	data := append(append([]byte{}, der...), make([]byte, 64)...)
	f.nv[n] = &nvIdx{attrs: attrAuthRead | attrNoDA | attrWritten, data: data, size: len(data)}
}

type env struct {
	c   Config
	f   *fakeTPM
	fw  *sbtest.Firmware
	dev string
	// pcr7, if set, overrides the PCR 7 the firmware would produce
	pcr7 []byte
	// badLog makes the firmware hand out an unusable event log
	badLog bool

	role, profile string
	epoch         int
	admitted      [][]byte // EK Names with a signed per-device admission
	requireFTPM   bool
	srv           *StateServer
}

func refOf(role, profile string) string { r, _ := tpmpolicy.Ref(role, profile); return r }

func fakePE(ref string) []byte {
	b1 := h([]byte("authorize"), []byte(ref))
	b2 := h([]byte("nw"), tpmpolicy.PolicyCommandCode(make([]byte, 32), tpmpolicy.CCNVSetBits))
	return tpmpolicy.PolicyOR(b1, b2)
}

func signed(t *testing.T, pcr11 []byte, epoch int, role, profile string) tpmpolicy.File {
	t.Helper()
	return signedRef(t, pcr11, epoch, role, profile, refOf(role, profile))
}

// signedEK signs the per-device admission of the endorsement key with the given Name.
func signedEK(t *testing.T, pcr11 []byte, epoch int, role, profile string, name []byte) tpmpolicy.File {
	t.Helper()
	f := signedRef(t, pcr11, epoch, role, profile, tpmpolicy.RefEK(refOf(role, profile), name))
	f.EK = hex.EncodeToString(name)
	return f
}

// signedRef signs the approved policy for an explicit policyRef (the base
// ref, or the per-device ref of an admitted endorsement key).
func signedRef(t *testing.T, pcr11 []byte, epoch int, role, profile, ref string) tpmpolicy.File {
	t.Helper()
	eName := tpmpolicy.NVName(uint32(handleNum(Epoch.Handle)), Epoch.Final, fakePE(ref), Epoch.Size)
	approved, err := tpmpolicy.Approved(fakePol11(pcr11), epoch, eName)
	if err != nil {
		t.Fatal(err)
	}
	sig := "SIG:" + hex.EncodeToString(tpmpolicy.SignedMessage(approved, ref))
	return tpmpolicy.File{Version: 2, Role: role, Profile: profile, Epoch: epoch, PCR11Policy: hex.EncodeToString(fakePol11(pcr11)),
		Approved: hex.EncodeToString(approved), Ref: ref, Signature: b64(sig)}
}

func newEnv(t *testing.T, profile string) *env {
	d := t.TempDir()
	c := Config{
		RunDir: filepath.Join(d, "run"), PubKey: filepath.Join(d, "pub.pem"), PolicyDir: "EFI/enklave/policy",
		RoleFile: filepath.Join(d, "usr/role"), TestMarker: filepath.Join(d, "usr/test-profile"),
		ReleaseFile: filepath.Join(d, "usr/release.json"), StateRoot: filepath.Join(d, "run", "statecheck"), // the fake "mount" is the check mount point
		EKCADir: filepath.Join(d, "usr/tpm-ek-ca"), EKTestCADir: filepath.Join(d, "usr/tpm-ek-ca-test"),
		WritersDir: filepath.Join(d, "usr/state-writers.d"), UpdatesDir: filepath.Join(d, "usr/efi-updates"),
		EventLog: filepath.Join(d, "sys/binary_bios_measurements"),
		Now:      func() time.Time { return testNow },
	}
	e := &env{c: c, f: newFakeTPM(t, c.stateMount()), fw: sbtest.NewFirmware(), dev: "/dev/vda8"}
	e.c.EFI = e.fw
	os.MkdirAll(c.WritersDir, 0o755)
	os.WriteFile(filepath.Join(c.WritersDir, "config.json"),
		[]byte(`{"unit":"enklave-config.service","exec":["/bin/sh","-c","cat > \"$ENKLAVE_STATE_DIR/config\""]}`), 0o644)
	os.MkdirAll(filepath.Join(c.EKCADir, "Vendor/RootCA"), 0o755)
	os.MkdirAll(filepath.Dir(c.EventLog), 0o755)
	os.WriteFile(filepath.Join(c.EKCADir, "Vendor/RootCA/ca.cer"), vendorCA().cert.Raw, 0o644)
	e.f.setEKCert(vendorCA().ekCertificate(&e.f.ek.PublicKey))
	e.setImage(t, "ref", profile, 0, 0)
	return e
}

func (e *env) setImage(t *testing.T, role, profile string, epoch, heal int) {
	t.Helper()
	os.MkdirAll(filepath.Dir(e.c.RoleFile), 0o755)
	os.WriteFile(e.c.RoleFile, []byte(role+"\n"), 0o644)
	os.Remove(e.c.TestMarker)
	if profile == "test" {
		os.WriteFile(e.c.TestMarker, nil, 0o644)
	}
	// prod: production keys; dev and test images are signed with a development PKI
	os.WriteFile(e.c.ReleaseFile, []byte(fmt.Sprintf(`{"epoch":%d,"heal_below":%d,"dev_keys":%v,"require_ftpm":%v}`,
		epoch, heal, profile != "prod", e.requireFTPM)), 0o644)
	e.role, e.profile, e.epoch = role, profile, epoch
	e.f.pcr[11] = h([]byte("uki"), []byte(fmt.Sprintf("%s/%s/%d", role, profile, epoch)))
	e.install(t, signed(t, e.f.pcr[11], epoch, role, profile))
	for _, name := range e.admitted {
		e.install(t, signedEK(t, e.f.pcr[11], epoch, role, profile, name))
	}
}

// admit ships a signed per-device admission for the EK with the given Name
// with this and every later release (B1).
func (e *env) admit(t *testing.T, name []byte) {
	t.Helper()
	e.admitted = append(e.admitted, name)
	e.install(t, signedEK(t, e.f.pcr[11], e.epoch, e.role, e.profile, name))
}

func (e *env) ekName() []byte {
	k, _ := ekcert.FromPublicKey(&e.f.ek.PublicKey)
	return k.Name()
}

func (e *env) install(t *testing.T, p tpmpolicy.File) {
	t.Helper()
	dir := filepath.Join(e.c.espMount(), e.c.PolicyDir)
	os.MkdirAll(dir, 0o700)
	b := mustJSON(p)
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%s-%d-%x.json", p.Role, p.Profile, p.Epoch, h([]byte(p.Ref))[:6])), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// boot runs repart, unlock and verify like the units do (fresh /run).
func (e *env) boot(t *testing.T) error {
	t.Helper()

	for _, p := range []string{e.c.CreatedFlag(), e.c.ProvisionedFlag(), e.c.policyCache(), e.c.ResultFile(),
		e.c.CounterFile(), e.c.StateKeyFile(), e.c.PlatformFile(), e.c.EFIUpdatesFile(), e.c.SaltSourceFile(),
		filepath.Join(e.c.RunDir, "test-pause")} {
		os.Remove(p)
	}
	for _, ix := range e.f.nv {
		ix.attrs &^= attrReadLocked
	}
	e.f.pcr[15] = make([]byte, 32)
	e.srv = nil
	// the firmware measures the Secure Boot variables of this boot into PCR 7
	log, pcr7 := e.fw.Boot()
	if e.badLog {
		log = log[:len(log)/2]
	}
	if err := os.WriteFile(e.c.EventLog, log, 0o600); err != nil {
		t.Fatal(err)
	}
	if e.pcr7 != nil {
		pcr7 = e.pcr7 // PCR 7 not explained by the event log
	}
	e.f.pcr[7] = pcr7
	if err := Repart(e.c, e.f, []string{"--dry-run=no"}); err != nil {
		return fmt.Errorf("repart: %w", err)
	}
	if _, err := Unlock(e.c, e.f, e.dev, "/dev/vda1"); err != nil {
		return fmt.Errorf("unlock: %w", err)
	}
	if _, err := Verify(e.c, e.f); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if len(e.f.violations) > 0 {
		t.Fatalf("secrets crossed the bus unprotected: %v", e.f.violations)
	}
	return nil
}

func (e *env) later() { e.f.repart = `[{"type":"var","activity":"unchanged"}]` }

func (e *env) counter() uint64 {
	return binary.BigEndian.Uint64(e.f.nv[handleNum(Counter.Handle)].data)
}

// state returns the state service of this boot (it takes the keys out of /run).
func (e *env) state(t *testing.T) *StateServer {
	t.Helper()
	if e.srv == nil {
		s, err := NewStateServer(e.c, e.f)
		if err != nil {
			t.Fatal(err)
		}
		e.srv = s
	}
	return e.srv
}

// commit writes data/config through the image's test writer, called from
// the unit the writer is reserved for.
func (e *env) commit(t *testing.T, rel, content string) {
	t.Helper()
	if rel != "config" {
		t.Fatalf("the test writer writes config only, not %s", rel)
	}
	in := filepath.Join(t.TempDir(), "in")
	os.WriteFile(in, []byte(content), 0o600)
	f, _ := os.Open(in)
	defer f.Close()
	if rep := e.state(t).Handle(StateRequest{Op: "exec", Writer: "config"}, "enklave-config.service", f); !rep.OK {
		t.Fatal(rep.Error)
	}
}

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Fatalf("err = %v, want %q", err, sub)
	}
}

func handlesOf(m map[uint64]*nvIdx) []string {
	var s []string
	for n := range m {
		s = append(s, fmt.Sprintf("0x%X", n))
	}
	sort.Strings(s)
	return s
}
