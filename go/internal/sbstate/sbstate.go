// Package sbstate reads the UEFI Secure Boot state that firmware measures
// into PCR 7: the TCG event log, the signature databases (EFI signature
// lists) and signed variable updates ("*.auth", e.g. a dbx append).
//
// It is used to move the state volume's PCR 7 binding across a signed
// Secure Boot variable update without ever accepting an unknown Secure Boot
// configuration (package varauth).
package sbstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// Event types (TCG PC Client Platform Firmware Profile).
const (
	EvNoAction          = 0x00000003
	EvVariableDriverCfg = 0x80000001 // EV_EFI_VARIABLE_DRIVER_CONFIG
	algSHA256           = 0x000B
)

// GUIDs of the Secure Boot variables (textual form as in efivarfs names).
const (
	GUIDGlobal   = "8be4df61-93ca-11d2-aa0d-00e098032b8c" // PK, KEK, SecureBoot
	GUIDSecurity = "d719b2cb-3d3a-4596-a3bc-dad00e67656f" // db, dbx
)

// VarGUID returns the vendor GUID of an updatable Secure Boot variable.
func VarGUID(name string) (string, error) {
	switch name {
	case "db", "dbx":
		return GUIDSecurity, nil
	case "KEK":
		return GUIDGlobal, nil
	}
	return "", fmt.Errorf("unsupported Secure Boot variable %q (dbx, db, KEK)", name)
}

// Event is one PCR 7 measurement.
type Event struct {
	Type   uint32 `json:"type"`
	Digest string `json:"digest"` // sha256, hex
	// Var is "<name>-<guid>" for an EV_EFI_VARIABLE_DRIVER_CONFIG event whose
	// logged data matches its digest; empty otherwise.
	Var string `json:"var,omitempty"`
	// Data is the variable content of such an event (authenticated by Digest).
	Data []byte `json:"-"`
}

func guidString(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}

// variableName parses a UEFI_VARIABLE_DATA event and returns "<name>-<guid>"
// and the variable data.
func variableName(data []byte) (string, []byte) {
	if len(data) < 32 {
		return "", nil
	}
	nameLen := binary.LittleEndian.Uint64(data[16:24])
	dataLen := binary.LittleEndian.Uint64(data[24:32])
	if nameLen > 256 || dataLen > uint64(len(data)) || 32+nameLen*2+dataLen != uint64(len(data)) {
		return "", nil
	}
	u := make([]uint16, nameLen)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(data[32+2*i:])
	}
	return string(utf16.Decode(u)) + "-" + guidString(data[:16]), data[32+nameLen*2:]
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n uint64) []byte {
	if r.err != nil || n > uint64(len(r.b)) {
		r.err = errors.New("truncated TCG event log")
		return make([]byte, n&0xffff)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}
func (r *reader) u32() uint32 { return binary.LittleEndian.Uint32(r.take(4)) }
func (r *reader) u16() uint16 { return binary.LittleEndian.Uint16(r.take(2)) }

// ParseLog parses a crypto-agile TCG event log (TCG_PCR_EVENT2 records after
// the "Spec ID Event03" header) and returns the events of one PCR together
// with the SHA-256 PCR value they replay to.
func ParseLog(log []byte, pcr uint32) ([]Event, []byte, error) {
	r := &reader{b: log}
	// header: TCG_PCR_EVENT (SHA-1 format)
	r.u32()
	if t := r.u32(); t != EvNoAction && r.err == nil {
		return nil, nil, errors.New("TCG event log does not start with a Spec ID event")
	}
	r.take(20)
	hdr := r.take(uint64(r.u32()))
	if r.err != nil {
		return nil, nil, r.err
	}
	if len(hdr) < 28 || string(hdr[:15]) != "Spec ID Event03" {
		return nil, nil, errors.New("not a TCG 2.0 (crypto-agile) event log")
	}
	sizes := map[uint16]uint64{}
	n := binary.LittleEndian.Uint32(hdr[24:28])
	if uint64(len(hdr)) < 28+uint64(n)*4 {
		return nil, nil, errors.New("truncated Spec ID event")
	}
	for i := uint32(0); i < n; i++ {
		sizes[binary.LittleEndian.Uint16(hdr[28+4*i:])] = uint64(binary.LittleEndian.Uint16(hdr[30+4*i:]))
	}
	if sizes[algSHA256] != 32 {
		return nil, nil, errors.New("TCG event log has no SHA-256 bank")
	}
	value := make([]byte, 32)
	var out []Event
	for len(r.b) > 0 {
		// the kernel may pad the log with zero or 0xff bytes
		if len(r.b) < 16 || bytes.Equal(r.b[:8], make([]byte, 8)) || bytes.Equal(r.b[:4], []byte{0xff, 0xff, 0xff, 0xff}) {
			break
		}
		index, typ, count := r.u32(), r.u32(), r.u32()
		var digest []byte
		for i := uint32(0); i < count && r.err == nil; i++ {
			alg := r.u16()
			sz, ok := sizes[alg]
			if !ok {
				return nil, nil, fmt.Errorf("TCG event log uses undeclared algorithm 0x%04x", alg)
			}
			d := r.take(sz)
			if alg == algSHA256 {
				digest = d
			}
		}
		data := r.take(uint64(r.u32()))
		if r.err != nil {
			return nil, nil, r.err
		}
		if index != pcr || typ == EvNoAction {
			continue
		}
		if digest == nil {
			return nil, nil, fmt.Errorf("PCR %d event without a SHA-256 digest", pcr)
		}
		s := sha256.Sum256(append(append([]byte{}, value...), digest...))
		value = s[:]
		e := Event{Type: typ, Digest: hex.EncodeToString(digest)}
		if d := sha256.Sum256(data); typ == EvVariableDriverCfg && bytes.Equal(d[:], digest) {
			e.Var, e.Data = variableName(data)
		}
		out = append(out, e)
	}
	return out, value, nil
}

// HasVariables reports whether each named variable ("<name>-<guid>") has
// exactly one authenticated EV_EFI_VARIABLE_DRIVER_CONFIG event.
func HasVariables(evs []Event, vars []string) error {
	for _, v := range vars {
		n := 0
		for _, e := range evs {
			if e.Var == v {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("firmware measured variable %s %d times into PCR 7, want once", v, n)
		}
	}
	return nil
}

// StateDigest is a canonical digest of a Secure Boot state as measured into
// PCR 7. Every event contributes its type and digest, except the variables
// named in updated: those contribute the SET of their signatures (type and
// data, without owner and list layout), united with add[variable].
//
// It is used to pin, before a signed variable update is handed to the
// firmware, exactly two states that may follow: the unchanged one
// (StateDigest(old, vars, nil)) and the one in which each updated variable
// holds exactly its old signatures plus those of the signed update
// (StateDigest(old, vars, update)). After the update the same function over
// the new event log with add == nil must give the second value. Any other
// change (Secure Boot off, other PK/KEK/db, another signing authority, a
// dropped or foreign dbx entry, an additional or missing event) gives a
// different digest.
func StateDigest(evs []Event, updated []string, add map[string][]Signature) ([]byte, error) {
	upd := map[string]bool{}
	for _, v := range updated {
		upd[v] = true
	}
	h := sha256.New()
	fmt.Fprintf(h, "enklave-sb-state-v1\x00%d\x00", len(evs))
	for _, e := range evs {
		fmt.Fprintf(h, "%08x\x00", e.Type)
		if e.Var == "" || !upd[e.Var] {
			fmt.Fprintf(h, "d\x00%s\x00", e.Digest)
			continue
		}
		sigs, err := ParseESL(e.Data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Var, err)
		}
		set := map[string]bool{}
		for _, s := range append(sigs, add[e.Var]...) {
			set[s.Type+":"+s.Data] = true
		}
		keys := make([]string, 0, len(set))
		for k := range set {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(h, "v\x00%s\x00%d\x00%s\x00", e.Var, len(keys), strings.Join(keys, "\x00"))
	}
	return h.Sum(nil), nil
}

// ---------------------------------------------------------------- signature lists

// Signature is one entry of an EFI signature database, without its owner GUID.
type Signature struct {
	Type string // signature type GUID
	Data string // hex
}

// ParseESL parses concatenated EFI_SIGNATURE_LISTs.
func ParseESL(b []byte) ([]Signature, error) {
	var out []Signature
	for len(b) > 0 {
		if len(b) < 28 {
			return nil, errors.New("truncated EFI signature list")
		}
		listSize := uint64(binary.LittleEndian.Uint32(b[16:20]))
		hdrSize := uint64(binary.LittleEndian.Uint32(b[20:24]))
		sigSize := uint64(binary.LittleEndian.Uint32(b[24:28]))
		if listSize < 28 || listSize > uint64(len(b)) || sigSize <= 16 || 28+hdrSize > listSize || (listSize-28-hdrSize)%sigSize != 0 {
			return nil, errors.New("malformed EFI signature list")
		}
		typ := guidString(b[:16])
		for e := b[28+hdrSize : listSize]; len(e) > 0; e = e[sigSize:] {
			out = append(out, Signature{typ, hex.EncodeToString(e[16:sigSize])})
		}
		b = b[listSize:]
	}
	return out, nil
}

// AuthPayload returns the signature lists carried by an authenticated
// variable update (EFI_VARIABLE_AUTHENTICATION_2: EFI_TIME, WIN_CERTIFICATE).
func AuthPayload(auth []byte) ([]byte, error) {
	if len(auth) < 16+8 {
		return nil, errors.New("truncated authenticated variable update")
	}
	n := uint64(binary.LittleEndian.Uint32(auth[16:20]))
	if n < 24 || 16+n > uint64(len(auth)) || binary.LittleEndian.Uint16(auth[22:24]) != 0x0EF1 {
		return nil, errors.New("malformed authenticated variable update (WIN_CERTIFICATE_UEFI_GUID expected)")
	}
	return auth[16+n:], nil
}

// Update is a signed Secure Boot variable update shipped by a release.
type Update struct {
	File string // base name, "<variable>-<anything>.auth"
	Var  string // dbx, db or KEK
	GUID string
	Auth []byte
	Sigs []Signature
}

// ID is the event-log identity of the updated variable.
func (u Update) ID() string { return u.Var + "-" + u.GUID }

// LoadUpdates reads every "<variable>-*.auth" file of a directory. A missing
// directory means no updates; any malformed file is an error (the directory
// is part of the signed image).
func LoadUpdates(dir string) ([]Update, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.auth"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []Update
	for _, f := range files {
		base := filepath.Base(f)
		name, _, ok := strings.Cut(base, "-")
		if !ok {
			return nil, fmt.Errorf("%s: name must be <variable>-<id>.auth", base)
		}
		guid, err := VarGUID(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", base, err)
		}
		auth, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		payload, err := AuthPayload(auth)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", base, err)
		}
		sigs, err := ParseESL(payload)
		if err != nil || len(sigs) == 0 {
			return nil, fmt.Errorf("%s: no usable signature list (%v)", base, err)
		}
		out = append(out, Update{base, name, guid, auth, sigs})
	}
	return out, nil
}

// Applied reports whether every signature of the update is present in the
// variable's current content.
func (u Update) Applied(current []byte) (bool, error) {
	have, err := ParseESL(current)
	if err != nil {
		return false, fmt.Errorf("%s: %w", u.Var, err)
	}
	set := map[Signature]bool{}
	for _, s := range have {
		set[s] = true
	}
	for _, s := range u.Sigs {
		if !set[s] {
			return false, nil
		}
	}
	return true, nil
}

// ---------------------------------------------------------------- efivarfs

// Vars gives access to UEFI variables.
type Vars interface {
	// Read returns the variable data (without attributes); a missing
	// variable is empty.
	Read(name, guid string) ([]byte, error)
	// Append submits an authenticated append write.
	Append(name, guid string, auth []byte) error
}

// EFIVarFS is Vars on a mounted efivarfs.
type EFIVarFS struct{ Dir string }

const (
	attrsAuthAppend = 0x00000067 // NV | BS | RT | TIME_BASED_AUTHENTICATED_WRITE_ACCESS | APPEND_WRITE
	fsIocGetFlags   = 0x80086601
	fsIocSetFlags   = 0x40086602
	fsImmutable     = 0x00000010
)

func (v EFIVarFS) path(name, guid string) string { return filepath.Join(v.Dir, name+"-"+guid) }

// Read implements Vars.
func (v EFIVarFS) Read(name, guid string) ([]byte, error) {
	b, err := os.ReadFile(v.path(name, guid))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("efivarfs %s: short read", name)
	}
	return b[4:], nil
}

// Append implements Vars: one write of attributes plus the signed update.
// The firmware verifies the signature; the kernel only passes it on.
func (v EFIVarFS) Append(name, guid string, auth []byte) error {
	p := v.path(name, guid)
	if f, err := os.Open(p); err == nil {
		// existing variables are immutable in efivarfs by default
		var flags uint64 // the kernel uses the low 32 bits
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetFlags, uintptr(unsafe.Pointer(&flags))); e == 0 && flags&fsImmutable != 0 {
			flags &^= fsImmutable
			if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocSetFlags, uintptr(unsafe.Pointer(&flags))); e != 0 {
				f.Close()
				return fmt.Errorf("efivarfs %s: clearing the immutable flag: %w", name, e)
			}
		}
		f.Close()
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	buf := make([]byte, 4, 4+len(auth))
	binary.LittleEndian.PutUint32(buf, attrsAuthAppend)
	_, werr := f.Write(append(buf, auth...))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("efivarfs %s: firmware rejected the signed update: %w", name, werr)
	}
	return nil
}

// ---------------------------------------------------------------- PCR 7 prediction

// guidBytes converts the textual GUID form to its EFI_GUID encoding.
func guidBytes(s string) ([]byte, error) {
	h, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(h) != 16 || len(s) != 36 {
		return nil, fmt.Errorf("bad GUID %q", s)
	}
	return []byte{h[3], h[2], h[1], h[0], h[5], h[4], h[7], h[6], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]}, nil
}

// VariableData builds the UEFI_VARIABLE_DATA structure that firmware
// measures for a variable "<name>-<guid>" with the given content.
func VariableData(id string, data []byte) ([]byte, error) {
	if len(id) < 38 || id[len(id)-37] != '-' {
		return nil, fmt.Errorf("bad variable id %q", id)
	}
	g, err := guidBytes(id[len(id)-36:])
	if err != nil {
		return nil, err
	}
	u := utf16.Encode([]rune(id[:len(id)-37]))
	b := make([]byte, 0, 32+2*len(u)+len(data))
	b = append(b, g...)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(u)))
	b = binary.LittleEndian.AppendUint64(b, uint64(len(data)))
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return append(b, data...), nil
}

// Predict replays the PCR 7 events of this boot with the content of the
// given variables ("<name>-<guid>") replaced: the PCR 7 value of the next
// boot if exactly those variables change to exactly that content. With an
// empty map it is the PCR 7 of this boot.
func Predict(evs []Event, content map[string][]byte) ([]byte, error) {
	value := make([]byte, 32)
	for _, e := range evs {
		d, err := hex.DecodeString(e.Digest)
		if err != nil || len(d) != 32 {
			return nil, fmt.Errorf("bad event digest %q", e.Digest)
		}
		if c, ok := content[e.Var]; ok && e.Var != "" {
			vd, err := VariableData(e.Var, c)
			if err != nil {
				return nil, err
			}
			s := sha256.Sum256(vd)
			d = s[:]
		}
		s := sha256.Sum256(append(append([]byte{}, value...), d...))
		value = s[:]
	}
	return value, nil
}

// Verbatim requires that the firmware measured each named variable exactly
// as the variable store returns it now: the event digest is the digest of
// UEFI_VARIABLE_DATA built from the variable's content. Only then can the
// PCR 7 value after a variable update be computed in advance. It returns
// the current content by variable id.
func Verbatim(evs []Event, ids []string, vars Vars) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, id := range ids {
		for _, e := range evs {
			if e.Var != id {
				continue
			}
			vd, err := VariableData(id, e.Data)
			if err != nil {
				return nil, err
			}
			if s := sha256.Sum256(vd); hex.EncodeToString(s[:]) != e.Digest {
				return nil, fmt.Errorf("firmware measures variable %s in a form that cannot be reproduced", id)
			}
			cur, err := vars.Read(id[:len(id)-37], id[len(id)-36:])
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(cur, e.Data) {
				return nil, fmt.Errorf("variable %s differs from what the firmware measured at boot (changed since boot, or not measured verbatim)", id)
			}
			out[id] = append([]byte{}, e.Data...)
		}
		if _, ok := out[id]; !ok {
			return nil, fmt.Errorf("firmware did not measure variable %s", id)
		}
	}
	return out, nil
}

type eslList struct {
	head    []byte // type GUID
	sigHdr  []byte
	sigSize uint64
	entries [][]byte
}

func splitESL(b []byte) ([]eslList, error) {
	var out []eslList
	for len(b) > 0 {
		if len(b) < 28 {
			return nil, errors.New("truncated EFI signature list")
		}
		listSize := uint64(binary.LittleEndian.Uint32(b[16:20]))
		hdrSize := uint64(binary.LittleEndian.Uint32(b[20:24]))
		sigSize := uint64(binary.LittleEndian.Uint32(b[24:28]))
		if listSize < 28 || listSize > uint64(len(b)) || sigSize <= 16 || 28+hdrSize > listSize || (listSize-28-hdrSize)%sigSize != 0 {
			return nil, errors.New("malformed EFI signature list")
		}
		l := eslList{head: b[:16], sigHdr: b[28 : 28+hdrSize], sigSize: sigSize}
		for e := b[28+hdrSize : listSize]; len(e) > 0; e = e[sigSize:] {
			l.entries = append(l.entries, e[:sigSize])
		}
		out = append(out, l)
		b = b[listSize:]
	}
	return out, nil
}

// AppendCandidates returns the contents a signature database may have
// after the firmware processed an authenticated APPEND of payload to cur:
// edk2 (and firmware derived from it) drops entries of the new lists that
// the variable already holds and appends the rest; a plain implementation
// appends the payload as it is. Both are "cur plus the update".
func AppendCandidates(cur, payload []byte) ([][]byte, error) {
	have, err := splitESL(cur)
	if err != nil {
		return nil, err
	}
	add, err := splitESL(payload)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, l := range have {
		for _, e := range l.entries {
			seen[string(l.head)+string(e)] = true
		}
	}
	filtered := append([]byte{}, cur...)
	for _, l := range add {
		var keep [][]byte
		for _, e := range l.entries {
			if !seen[string(l.head)+string(e)] {
				keep = append(keep, e)
			}
		}
		if len(keep) == 0 {
			continue
		}
		filtered = append(filtered, l.head...)
		filtered = binary.LittleEndian.AppendUint32(filtered, uint32(28+len(l.sigHdr)+len(keep)*int(l.sigSize)))
		filtered = binary.LittleEndian.AppendUint32(filtered, uint32(len(l.sigHdr)))
		filtered = binary.LittleEndian.AppendUint32(filtered, uint32(l.sigSize))
		filtered = append(filtered, l.sigHdr...)
		for _, e := range keep {
			filtered = append(filtered, e...)
		}
	}
	raw := append(append([]byte{}, cur...), payload...)
	if bytes.Equal(raw, filtered) {
		return [][]byte{raw}, nil
	}
	return [][]byte{filtered, raw}, nil
}

// ExactlyAdded reports whether the signature set of after is exactly the
// set of before united with add: nothing dropped, nothing else added.
func ExactlyAdded(before, after []byte, add []Signature) (bool, error) {
	b, err := ParseESL(before)
	if err != nil {
		return false, err
	}
	a, err := ParseESL(after)
	if err != nil {
		return false, err
	}
	want := map[Signature]bool{}
	for _, s := range append(b, add...) {
		want[s] = true
	}
	got := map[Signature]bool{}
	for _, s := range a {
		if !want[s] {
			return false, nil
		}
		got[s] = true
	}
	return len(got) == len(want), nil
}
