// Package ekcert authenticates a TPM's endorsement key (EK).
//
// The EK is the key every enclave session is salted to. Its public area is
// never taken on trust from the TPM bus: it is rebuilt locally from the
// TCG default EK template and the public key of the TPM's EK certificate,
// which must chain to a TPM vendor CA shipped in the verity-protected /usr
// (or the EK's Name must be listed in the signed allowlist of the release).
// A key an interposer substitutes on the bus therefore has no acceptable
// Name, and a session salted to the authenticated public key can only be
// decrypted by the genuine TPM.
package ekcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Alg is an EK algorithm of the TCG EK Credential Profile (low range).
type Alg string

const (
	// RSA is the RSA 2048 EK (template L-1), certificate in NV 0x01C00002.
	RSA Alg = "rsa2048"
	// ECC is the NIST P-256 EK (template L-2), certificate in NV 0x01C0000A.
	ECC Alg = "ecc256"

	// ChainFirst and ChainLast bound the NV range that may hold the EK
	// certificate chain (intermediate CA certificates).
	ChainFirst = 0x01C00100
	ChainLast  = 0x01C001FF
)

// Algs lists the supported EKs in order of preference.
var Algs = []Alg{ECC, RSA}

// CertHandle is the NV index of the EK certificate.
func (a Alg) CertHandle() string {
	if a == ECC {
		return "0x01C0000A"
	}
	return "0x01C00002"
}

// Tool is the algorithm name for "tpm2_createek -G", which creates the EK
// from the TCG default template (checked on swtpm: the result equals the
// public area that FromPublicKey builds from the EK certificate).
func (a Alg) Tool() string {
	if a == ECC {
		return "ecc"
	}
	return "rsa"
}

// PolicyA is the authPolicy of the default EK templates:
// PolicySecret(TPM_RH_ENDORSEMENT).
var PolicyA = mustHex("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func be16(v int) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, uint16(v)); return b }

// templateHead is the part of TPMT_PUBLIC before the unique field.
func templateHead(a Alg) []byte {
	var b []byte
	if a == ECC {
		b = append(b, 0x00, 0x23) // TPM_ALG_ECC
	} else {
		b = append(b, 0x00, 0x01) // TPM_ALG_RSA
	}
	b = append(b, 0x00, 0x0b)             // nameAlg sha256
	b = append(b, 0x00, 0x03, 0x00, 0xb2) // fixedTPM|fixedParent|sensitiveDataOrigin|adminWithPolicy|restricted|decrypt
	b = append(b, be16(len(PolicyA))...)
	b = append(b, PolicyA...)
	b = append(b, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43) // AES-128-CFB
	b = append(b, 0x00, 0x10)                         // scheme NULL
	if a == ECC {
		b = append(b, 0x00, 0x03) // TPM_ECC_NIST_P256
		b = append(b, 0x00, 0x10) // kdf NULL
	} else {
		b = append(b, 0x08, 0x00)             // 2048 bits
		b = append(b, 0x00, 0x00, 0x00, 0x00) // exponent 0 = 65537
	}
	return b
}

// Key is an authenticated EK: algorithm and the complete public area.
type Key struct {
	Alg    Alg
	Public []byte // TPMT_PUBLIC
}

// Name is the TPM Name of the key: TPM_ALG_SHA256 || H(TPMT_PUBLIC).
func (k Key) Name() []byte {
	h := sha256.Sum256(k.Public)
	return append([]byte{0x00, 0x0b}, h[:]...)
}

// TPM2B returns the key as a TPM2B_PUBLIC (the format of tpm2_readpublic -o).
func (k Key) TPM2B() []byte { return append(be16(len(k.Public)), k.Public...) }

// SerializedTR returns the ESYS_TR serialization (tpm2-tss
// Esys_TR_Serialize / "tpm2_readpublic -t") of the key at a persistent
// handle. A session started with this file ("tpm2_startauthsession -c") is
// salted to exactly this public key; ESYS issues no TPM2_ReadPublic.
func (k Key) SerializedTR(handle uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, handle)
	n := k.Name()
	b = append(b, be16(len(n))...)
	b = append(b, n...)
	b = append(b, 0, 0, 0, 1) // IESYSC_KEY_RSRC
	return append(b, k.TPM2B()...)
}

func fixed(v *big.Int, size int) ([]byte, error) {
	if v == nil || v.Sign() <= 0 || len(v.Bytes()) > size {
		return nil, errors.New("public key value out of range")
	}
	return v.FillBytes(make([]byte, size)), nil
}

// FromPublicKey builds the EK that a TPM derives from the default template
// for the given public key (from an EK certificate).
func FromPublicKey(pub any) (Key, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if p.N.BitLen() != 2048 || p.E != 65537 {
			return Key{}, fmt.Errorf("EK certificate holds RSA %d (e=%d), want RSA 2048 (e=65537)", p.N.BitLen(), p.E)
		}
		n, err := fixed(p.N, 256)
		if err != nil {
			return Key{}, err
		}
		return Key{RSA, append(append(templateHead(RSA), be16(256)...), n...)}, nil
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() {
			return Key{}, fmt.Errorf("EK certificate holds curve %s, want P-256", p.Curve.Params().Name)
		}
		x, err := fixed(p.X, 32)
		if err != nil {
			return Key{}, err
		}
		y, err := fixed(p.Y, 32)
		if err != nil {
			return Key{}, err
		}
		b := append(append(templateHead(ECC), be16(32)...), x...)
		return Key{ECC, append(append(b, be16(32)...), y...)}, nil
	}
	return Key{}, fmt.Errorf("unsupported EK public key type %T", pub)
}

// FromTPM2B parses a TPM2B_PUBLIC (tpm2_readpublic -o) and requires it to be
// exactly a default-template EK. Anything else (other attributes, policy,
// symmetric algorithm, sizes) is rejected.
func FromTPM2B(b []byte) (Key, error) {
	if len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
		return Key{}, errors.New("malformed TPM2B_PUBLIC")
	}
	pub := b[2:]
	for _, a := range Algs {
		head := templateHead(a)
		want := len(head) + 2 + 256
		if a == ECC {
			want = len(head) + 2 + 32 + 2 + 32
		}
		if len(pub) != want || !bytes.Equal(pub[:len(head)], head) {
			continue
		}
		u := pub[len(head):]
		if a == RSA && binary.BigEndian.Uint16(u) != 256 {
			continue
		}
		if a == ECC && (binary.BigEndian.Uint16(u) != 32 || binary.BigEndian.Uint16(u[34:]) != 32) {
			continue
		}
		return Key{a, append([]byte{}, pub...)}, nil
	}
	return Key{}, errors.New("public area is not a default-template endorsement key (RSA 2048 or ECC P-256)")
}

// ---------------------------------------------------------------- CA store

// Store holds the trusted TPM vendor CAs.
type Store struct {
	Roots, Intermediates *x509.CertPool
	NRoots, NInter       int
	Skipped              []string // files that hold no parseable certificate
	vendor               map[[32]byte]string
}

// FirmwareVendors are the bundle directories of vendors whose TPMs are
// firmware TPMs (no external bus): AMD fTPM and Pluton, Intel PTT, Qualcomm.
// The other directories (Atmel, Infineon, NationZ, Nuvoton, STMicro) are
// discrete TPMs.
var FirmwareVendors = map[string]bool{"AMD": true, "Intel": true, "QC": true}

// Info describes a validated EK certificate.
type Info struct {
	Issuer string
	Vendor string // bundle directory of the trust anchor ("AMD", "Infineon", ...)
}

// Firmware reports whether the certificate was issued by a firmware-TPM vendor.
func (i Info) Firmware() bool { return FirmwareVendors[i.Vendor] }

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool(), vendor: map[[32]byte]string{}}
}

// ParseCertificates parses one or more certificates in DER (possibly
// concatenated or padded) or PEM form.
func ParseCertificates(b []byte) []*x509.Certificate {
	var out []*x509.Certificate
	if bytes.Contains(b, []byte("-----BEGIN")) {
		for {
			var blk *pem.Block
			if blk, b = pem.Decode(b); blk == nil {
				return out
			}
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				out = append(out, c)
			}
		}
	}
	for len(b) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(b, &raw)
		if err != nil {
			return out
		}
		if c, err := x509.ParseCertificate(raw.FullBytes); err == nil {
			out = append(out, c)
		}
		b = rest
	}
	return out
}

// AddDir loads a CA directory tree in the layout of the vendor bundle
// (<vendor>/RootCA, <vendor>/IntermediateCA). Every certificate of the bundle
// is a trust anchor: the bundle is the curated list of TPM vendor CAs, several
// vendors publish issuing CAs whose root is not part of it (AMD fTPM) or is
// encoded or signed in ways crypto/x509 rejects (SHA-1, differing name
// encodings), and revocation of an issuing CA cannot be checked offline
// anyway. A missing directory is an error; unparseable files are recorded
// in Skipped.
func (s *Store) AddDir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		kind := filepath.Base(filepath.Dir(path))
		if kind != "RootCA" && kind != "IntermediateCA" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		vendor := filepath.Base(dir)
		if rel, err := filepath.Rel(dir, path); err == nil {
			if parts := strings.Split(filepath.ToSlash(rel), "/"); len(parts) > 2 {
				vendor = parts[0]
			}
		}
		certs := ParseCertificates(b)
		if len(certs) == 0 {
			s.Skipped = append(s.Skipped, path)
			return nil
		}
		for _, c := range certs {
			s.Roots.AddCert(c)
			s.vendor[sha256.Sum256(c.Raw)] = vendor
			if kind == "RootCA" {
				s.NRoots++
			} else {
				s.NInter++
			}
		}
		return nil
	})
}

// AddIntermediates adds untrusted chain certificates (from the TPM's NV).
func (s *Store) AddIntermediates(b []byte) {
	for _, c := range ParseCertificates(b) {
		s.Intermediates.AddCert(c)
		s.NInter++
	}
}

var (
	oidEKU       = asn1.ObjectIdentifier{2, 23, 133, 8, 1} // tcg-kp-EKCertificate
	oidAnyEKU    = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidTPMAttrs  = []asn1.ObjectIdentifier{{2, 23, 133, 2, 1}, {2, 23, 133, 2, 2}, {2, 23, 133, 2, 3}} // manufacturer, model, version
	oidSAN       = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAESOAEP = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
)

// publicKey returns the certificate's public key. Several TPM vendors
// declare the EK as id-RSAES-OAEP, which crypto/x509 does not decode.
func publicKey(c *x509.Certificate) (any, error) {
	if c.PublicKey != nil {
		return c.PublicKey, nil
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if rest, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil || len(rest) != 0 {
		return nil, errors.New("malformed subjectPublicKeyInfo")
	}
	if !spki.Algorithm.Algorithm.Equal(oidRSAESOAEP) && !spki.Algorithm.Algorithm.Equal(oidRSA) {
		return nil, fmt.Errorf("unsupported EK public key algorithm %v", spki.Algorithm.Algorithm)
	}
	k, err := x509.ParsePKCS1PublicKey(spki.Key.RightAlign())
	if err != nil {
		return nil, fmt.Errorf("EK public key: %w", err)
	}
	return k, nil
}

// trimDER cuts the padding that follows a DER certificate in a fixed-size
// NV index.
func trimDER(b []byte) ([]byte, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("EK certificate is not DER: %w", err)
	}
	return raw.FullBytes, nil
}

// hasEKU reports whether a certificate is marked for EK certificates.
func hasEKU(c *x509.Certificate) bool {
	for _, o := range c.UnknownExtKeyUsage {
		if o.Equal(oidEKU) {
			return true
		}
	}
	return false
}

// chainAllowsEKU applies the extended-key-usage rules of RFC 5280 to the
// EK usage, which crypto/x509 does not know: the leaf must carry
// tcg-kp-EKCertificate, and an issuing CA below the trust anchor that
// restricts its usages must include it (or anyExtendedKeyUsage).
// markedEK reports whether a certificate is issued as an EK certificate
// (G11): it carries the extended key usage tcg-kp-EKCertificate, or, if it
// carries no extended key usage at all, a certificate policy from the TCG
// arc (2.23.133), which the TCG EK Credential Profile allows vendors to use
// instead. A certificate with other extended key usages only is refused.
func markedEK(c *x509.Certificate) bool {
	if hasEKU(c) {
		return true
	}
	if len(c.ExtKeyUsage)+len(c.UnknownExtKeyUsage) != 0 {
		return false
	}
	for _, o := range c.PolicyIdentifiers {
		if len(o) > 3 && o[0] == 2 && o[1] == 23 && o[2] == 133 {
			return true
		}
	}
	return false
}

func chainAllowsEKU(chain []*x509.Certificate) bool {
	if !markedEK(chain[0]) {
		return false
	}
	for _, c := range chain[1 : len(chain)-1] {
		if len(c.ExtKeyUsage)+len(c.UnknownExtKeyUsage) == 0 || hasEKU(c) {
			continue
		}
		any := false
		for _, u := range c.ExtKeyUsage {
			any = any || u == x509.ExtKeyUsageAny
		}
		for _, o := range c.UnknownExtKeyUsage {
			any = any || o.Equal(oidAnyEKU)
		}
		if !any {
			return false
		}
	}
	return true
}

// tpmAttributes checks the subjectAltName of an EK certificate: the TCG EK
// Credential Profile requires a directoryName with the TPM manufacturer,
// model and version attributes.
func tpmAttributes(c *x509.Certificate) error {
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidSAN) {
			continue
		}
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(e.Value, &names); err != nil || len(rest) != 0 {
			return errors.New("malformed subjectAltName")
		}
		for _, n := range names {
			if n.Class != asn1.ClassContextSpecific || n.Tag != 4 {
				continue
			}
			var rdns pkix.RDNSequence
			if _, err := asn1.Unmarshal(n.Bytes, &rdns); err != nil {
				return errors.New("malformed directoryName in subjectAltName")
			}
			found := 0
			for _, want := range oidTPMAttrs {
				for _, set := range rdns {
					for _, atv := range set {
						if atv.Type.Equal(want) {
							found++
						}
					}
				}
			}
			if found >= len(oidTPMAttrs) {
				return nil
			}
		}
	}
	return errors.New("EK certificate lacks the TPM manufacturer, model and version in its subjectAltName (TCG EK Credential Profile)")
}

// Verify validates an EK certificate (as read from the TPM's NV) against
// the store at the given time and returns the EK it certifies.
func (s *Store) Verify(der []byte, now time.Time) (Key, Info, error) {
	der, err := trimDER(der)
	if err != nil {
		return Key{}, Info{}, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return Key{}, Info{}, fmt.Errorf("EK certificate: %w", err)
	}
	if c.IsCA {
		return Key{}, Info{}, errors.New("EK certificate is a CA certificate")
	}
	if err := tpmAttributes(c); err != nil {
		return Key{}, Info{}, err
	}
	// EK certificates carry the TPM model in a critical subjectAltName with
	// a directoryName, which crypto/x509 reports as unhandled.
	var unhandled []asn1.ObjectIdentifier
	for _, o := range c.UnhandledCriticalExtensions {
		if !o.Equal(oidSAN) {
			unhandled = append(unhandled, o)
		}
	}
	c.UnhandledCriticalExtensions = unhandled
	// crypto/x509 can only enforce the key usages it knows; "any" here just
	// turns its own check off. The EK usage is enforced on every chain by
	// chainAllowsEKU below.
	chains, err := c.Verify(x509.VerifyOptions{
		Roots: s.Roots, Intermediates: s.Intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return Key{}, Info{}, fmt.Errorf("EK certificate (issuer %q) does not chain to a trusted TPM vendor CA: %w", c.Issuer.String(), err)
	}
	info := Info{Issuer: c.Issuer.String()}
	ok := false
	for _, ch := range chains {
		if chainAllowsEKU(ch) {
			info.Vendor, ok = s.vendor[sha256.Sum256(ch[len(ch)-1].Raw)], true
			break
		}
	}
	if !ok {
		return Key{}, Info{}, fmt.Errorf("certificate (issuer %q) is not issued for endorsement keys (extended key usage tcg-kp-EKCertificate missing in the certificate or excluded by its chain, and no TCG certificate policy in its place)", c.Issuer.String())
	}
	pub, err := publicKey(c)
	if err != nil {
		return Key{}, Info{}, err
	}
	k, err := FromPublicKey(pub)
	return k, info, err
}

// ParseAllowlist parses the signed EK allowlist: one EK Name (hex,
// 000b || SHA-256 of the public area) per line; "#" starts a comment.
func ParseAllowlist(b []byte) (map[string]bool, error) {
	m := map[string]bool{}
	for i, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		n, err := hex.DecodeString(line)
		if err != nil || len(n) != 34 || n[0] != 0 || n[1] != 0x0b {
			return nil, fmt.Errorf("EK allowlist line %d: not a SHA-256 TPM Name", i+1)
		}
		m[line] = true
	}
	return m, nil
}
