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
}

func guidString(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}

// variableName parses a UEFI_VARIABLE_DATA event and returns "<name>-<guid>".
func variableName(data []byte) string {
	if len(data) < 32 {
		return ""
	}
	nameLen := binary.LittleEndian.Uint64(data[16:24])
	dataLen := binary.LittleEndian.Uint64(data[24:32])
	if nameLen > 256 || dataLen > uint64(len(data)) || 32+nameLen*2+dataLen != uint64(len(data)) {
		return ""
	}
	u := make([]uint16, nameLen)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(data[32+2*i:])
	}
	return string(utf16.Decode(u)) + "-" + guidString(data[:16])
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
			e.Var = variableName(data)
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

// Compare checks that the PCR 7 events after a variable update equal those
// before it, except for the content of the updated variables: same number
// and types of events, every other event with an identical digest. Any other
// difference means a different Secure Boot configuration (other keys, Secure
// Boot disabled, another signing authority) and is refused.
func Compare(before, after []Event, updated []string) error {
	if len(before) != len(after) {
		return fmt.Errorf("PCR 7 has %d events, had %d before the update", len(after), len(before))
	}
	allowed := map[string]bool{}
	for _, v := range updated {
		allowed[v] = true
	}
	for i := range before {
		b, a := before[i], after[i]
		switch {
		case b.Type != a.Type || b.Var != a.Var:
			return fmt.Errorf("PCR 7 event %d changed its kind (type 0x%x %q, was 0x%x %q)", i, a.Type, a.Var, b.Type, b.Var)
		case b.Digest == a.Digest:
		case a.Var != "" && allowed[a.Var]:
		default:
			what := a.Var
			if what == "" {
				what = fmt.Sprintf("type 0x%x", a.Type)
			}
			return fmt.Errorf("PCR 7 event %d (%s) changed although no signed update covers it", i, what)
		}
	}
	return nil
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
