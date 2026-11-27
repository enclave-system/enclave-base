// Package sbtest builds synthetic Secure Boot state (TCG event logs, EFI
// signature lists, authenticated updates) and a fake firmware for tests.
package sbtest

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"unicode/utf16"
)

// GUIDBytes converts the textual GUID form to its EFI_GUID encoding.
func GUIDBytes(s string) []byte {
	h, _ := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return []byte{h[3], h[2], h[1], h[0], h[5], h[4], h[7], h[6], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]}
}

func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func le64(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }

// SHA256Type is EFI_CERT_SHA256_GUID.
const SHA256Type = "c1c41626-504c-4092-aca9-41f936934328"

// ESL builds one EFI_SIGNATURE_LIST of SHA-256 hashes.
func ESL(hashes ...[]byte) []byte {
	b := append(GUIDBytes(SHA256Type), le32(uint32(28+len(hashes)*48))...)
	b = append(b, le32(0)...)
	b = append(b, le32(48)...)
	for _, h := range hashes {
		b = append(b, make([]byte, 16)...) // owner
		b = append(b, h...)
	}
	return b
}

// Auth wraps signature lists into an EFI_VARIABLE_AUTHENTICATION_2 blob
// (the signature itself is a placeholder).
func Auth(payload []byte) []byte {
	b := make([]byte, 16) // EFI_TIME
	cert := []byte("pkcs7-placeholder")
	b = append(b, le32(uint32(24+len(cert)))...)
	b = append(b, 0x00, 0x02, 0xF1, 0x0E) // revision, WIN_CERT_TYPE_EFI_GUID
	b = append(b, make([]byte, 16)...)
	b = append(b, cert...)
	return append(b, payload...)
}

// VarEvent is a UEFI_VARIABLE_DATA event body.
func VarEvent(guid, name string, data []byte) []byte {
	u := utf16.Encode([]rune(name))
	b := append(GUIDBytes(guid), le64(uint64(len(u)))...)
	b = append(b, le64(uint64(len(data)))...)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return append(b, data...)
}

// Ev is one event to log.
type Ev struct {
	PCR, Type uint32
	Data      []byte
}

// Log builds a crypto-agile event log (SHA-1 and SHA-256 banks) and returns
// it with the SHA-256 value of the given PCR.
func Log(pcr uint32, evs []Ev) ([]byte, []byte) {
	spec := append([]byte("Spec ID Event03\x00"), le32(0)...)
	spec = append(spec, 0, 2, 0, 2)
	spec = append(spec, le32(2)...)
	spec = append(spec, 0x04, 0x00, 20, 0, 0x0b, 0x00, 32, 0)
	spec = append(spec, 0)
	log := append(le32(0), le32(3)...)
	log = append(log, make([]byte, 20)...)
	log = append(log, le32(uint32(len(spec)))...)
	log = append(log, spec...)
	value := make([]byte, 32)
	for _, e := range evs {
		d := sha256.Sum256(e.Data)
		log = append(log, le32(e.PCR)...)
		log = append(log, le32(e.Type)...)
		log = append(log, le32(2)...)
		log = append(log, 0x04, 0x00)
		log = append(log, make([]byte, 20)...)
		log = append(log, 0x0b, 0x00)
		log = append(log, d[:]...)
		log = append(log, le32(uint32(len(e.Data)))...)
		log = append(log, e.Data...)
		if e.PCR == pcr && e.Type != 3 {
			s := sha256.Sum256(append(append([]byte{}, value...), d[:]...))
			value = s[:]
		}
	}
	return log, value
}

// Firmware is a fake UEFI variable store that measures like edk2: SecureBoot,
// PK, KEK, db, dbx, a separator and the db authority into PCR 7.
type Firmware struct {
	SecureBoot byte
	Vars       map[string][]byte // "<name>-<guid>" -> data
	Authority  []byte
	// Reject, if set, makes Append fail (firmware refuses the update).
	Reject error
	// Extra events appended to PCR 7 (e.g. an attacker-enrolled authority).
	Extra []Ev
}

const (
	guidGlobal   = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
	guidSecurity = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
)

// NewFirmware returns a Secure Boot configuration with enklave-like keys.
func NewFirmware() *Firmware {
	return &Firmware{SecureBoot: 1, Authority: []byte("enklave db certificate"), Vars: map[string][]byte{
		"PK-" + guidGlobal: []byte("pk"), "KEK-" + guidGlobal: []byte("kek"),
		"db-" + guidSecurity: ESL(sha256Of("db")), "dbx-" + guidSecurity: nil,
	}}
}

func sha256Of(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

// Read implements sbstate.Vars.
func (f *Firmware) Read(name, guid string) ([]byte, error) { return f.Vars[name+"-"+guid], nil }

// Append implements sbstate.Vars (the payload is appended as is).
func (f *Firmware) Append(name, guid string, auth []byte) error {
	if f.Reject != nil {
		return f.Reject
	}
	n := binary.LittleEndian.Uint32(auth[16:20])
	f.Vars[name+"-"+guid] = append(append([]byte{}, f.Vars[name+"-"+guid]...), auth[16+n:]...)
	return nil
}

// Boot returns the event log and PCR 7 of a boot with the current variables.
func (f *Firmware) Boot() ([]byte, []byte) {
	evs := []Ev{
		{0, 8, []byte("crtm")},
		{7, 0x80000001, VarEvent(guidGlobal, "SecureBoot", []byte{f.SecureBoot})},
		{7, 0x80000001, VarEvent(guidGlobal, "PK", f.Vars["PK-"+guidGlobal])},
		{7, 0x80000001, VarEvent(guidGlobal, "KEK", f.Vars["KEK-"+guidGlobal])},
		{7, 0x80000001, VarEvent(guidSecurity, "db", f.Vars["db-"+guidSecurity])},
		{7, 0x80000001, VarEvent(guidSecurity, "dbx", f.Vars["dbx-"+guidSecurity])},
		{7, 4, []byte{0, 0, 0, 0}},
		{4, 0x80000003, []byte("systemd-boot")},
		{7, 0x800000E0, VarEvent(guidSecurity, "db", f.Authority)},
	}
	return Log(7, append(evs, f.Extra...))
}
