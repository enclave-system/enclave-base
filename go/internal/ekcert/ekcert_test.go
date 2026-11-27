package ekcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// swtpmStore trusts the CA that issued testdata/swtpm-ek.der.
func swtpmStore(t *testing.T) *Store {
	s := NewStore()
	for _, c := range ParseCertificates(read(t, "swtpm-root.crt.pem")) {
		s.Roots.AddCert(c)
	}
	s.AddIntermediates(read(t, "swtpm-issuer.crt.pem"))
	return s
}

var vectorTime = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

// The vectors were captured from swtpm 0.7.1 (swtpm_setup --create-ek-cert,
// EK created from the default template (tpm2_createek), persisted at
// 0x81000E01, "tpm2_readpublic -o -n -t").
func TestSwtpmVector(t *testing.T) {
	k, c, err := swtpmStore(t).Verify(read(t, "swtpm-ek.der"), vectorTime)
	if err != nil {
		t.Fatal(err)
	}
	if k.Alg != RSA || c.Issuer != "CN=swtpm-localca" || c.Firmware() {
		t.Errorf("alg %s info %+v", k.Alg, c)
	}
	if !bytes.Equal(k.TPM2B(), read(t, "swtpm-p2.pub")) {
		t.Error("public area rebuilt from the certificate differs from the TPM's")
	}
	if !bytes.Equal(k.Name(), read(t, "swtpm-p2.name")) {
		t.Errorf("name %x", k.Name())
	}
	if !bytes.Equal(k.SerializedTR(0x81000E01), read(t, "swtpm-salt.tr")) {
		t.Error("serialized ESYS_TR differs from tpm2_readpublic -t")
	}
	back, err := FromTPM2B(read(t, "swtpm-p2.pub"))
	if err != nil || !bytes.Equal(back.Name(), k.Name()) || back.Alg != RSA {
		t.Errorf("FromTPM2B: %v", err)
	}
}

func TestFromTPM2BRejectsOtherTemplates(t *testing.T) {
	good := read(t, "swtpm-p2.pub")
	for name, mut := range map[string]func(b []byte){
		"userWithAuth set":   func(b []byte) { b[9] |= 0x40 },
		"not restricted":     func(b []byte) { b[7] &^= 0x01 },
		"other authPolicy":   func(b []byte) { b[12] ^= 1 },
		"other symmetric":    func(b []byte) { b[2+8+34+3] = 0x00; b[2+8+34+2] = 0x01 },
		"wrong outer length": func(b []byte) { b[1]++ },
	} {
		b := append([]byte{}, good...)
		mut(b)
		if _, err := FromTPM2B(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := FromTPM2B(good[:100]); err == nil {
		t.Error("truncated public accepted")
	}
}

// ---------------------------------------------------------------- synthetic CAs

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, cn string, parent *ca) *ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: vectorTime.Add(-time.Hour), NotAfter: vectorTime.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &ca{c, key}
}

// ekCert issues an EK certificate with the critical directoryName SAN and
// the EK extended key usage that real TPM vendors use.
func ekCert(t *testing.T, issuer *ca, pub any, mut func(*x509.Certificate)) []byte {
	t.Helper()
	san := tpmSAN(2, 23, 133, 2, 1, 2, 23, 133, 2, 2, 2, 23, 133, 2, 3)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: vectorTime.Add(-time.Hour), NotAfter: vectorTime.Add(time.Hour),
		KeyUsage:           x509.KeyUsageKeyEncipherment,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}},
		ExtraExtensions:    []pkix.Extension{{Id: oidSAN, Critical: true, Value: san}}}
	if mut != nil {
		mut(tpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, issuer.cert, pub, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// tpmSAN builds a subjectAltName with a directoryName holding one attribute
// per given OID (five arcs each).
func tpmSAN(arcs ...int) []byte {
	var rdn pkix.RDNSequence
	for i := 0; i+5 <= len(arcs); i += 5 {
		rdn = append(rdn, pkix.RelativeDistinguishedNameSET{{Type: asn1.ObjectIdentifier(arcs[i : i+5]), Value: "id:00001014"}})
	}
	san, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: mustMarshal(rdn)}})
	return san
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVerify(t *testing.T) {
	root := newCA(t, "vendor root", nil)
	inter := newCA(t, "vendor EK CA", root)
	foreign := newCA(t, "foreign root", nil)
	s := NewStore()
	s.Roots.AddCert(root.cert)
	s.AddIntermediates(inter.cert.Raw)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	good := ekCert(t, inter, &ek.PublicKey, nil)
	k, _, err := s.Verify(append(append([]byte{}, good...), bytes.Repeat([]byte{0xff}, 100)...), vectorTime) // NV padding
	if err != nil {
		t.Fatal(err)
	}
	want, _ := FromPublicKey(&ek.PublicKey)
	if k.Alg != ECC || !bytes.Equal(k.Name(), want.Name()) || len(k.Public) != 2+2+4+2+32+6+2+4+2+32+2+32 {
		t.Errorf("key %+v", k)
	}
	if back, err := FromTPM2B(k.TPM2B()); err != nil || back.Alg != ECC {
		t.Errorf("ECC FromTPM2B: %v", err)
	}

	cases := map[string]struct {
		der  []byte
		at   time.Time
		want string
	}{
		"foreign CA":     {ekCert(t, foreign, &ek.PublicKey, nil), vectorTime, "does not chain"},
		"expired":        {good, vectorTime.Add(48 * time.Hour), "does not chain"},
		"not yet valid":  {good, vectorTime.Add(-48 * time.Hour), "does not chain"},
		"garbage":        {[]byte{0xff, 0xff, 0xff}, vectorTime, "not DER"},
		"empty index":    {bytes.Repeat([]byte{0}, 64), vectorTime, "EK certificate"},
		"CA certificate": {inter.cert.Raw, vectorTime, "CA certificate"},
		"other critical ext": {ekCert(t, inter, &ek.PublicKey, func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}})
		}), vectorTime, "does not chain"},
	}
	// B4: EK certificate profile
	cases["no EK extended key usage"] = struct {
		der  []byte
		at   time.Time
		want string
	}{ekCert(t, inter, &ek.PublicKey, func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil }), vectorTime, "not issued for endorsement keys"}
	// G11: without any extended key usage, a TCG certificate policy marks the EK certificate
	cases["no EKU and a foreign certificate policy"] = struct {
		der  []byte
		at   time.Time
		want string
	}{ekCert(t, inter, &ek.PublicKey, func(c *x509.Certificate) {
		c.UnknownExtKeyUsage = nil
		c.PolicyIdentifiers = []asn1.ObjectIdentifier{{1, 2, 276, 0, 68, 1, 20, 1}}
	}), vectorTime, "not issued for endorsement keys"}
	cases["other EKU with a TCG certificate policy"] = struct {
		der  []byte
		at   time.Time
		want string
	}{ekCert(t, inter, &ek.PublicKey, func(c *x509.Certificate) {
		c.UnknownExtKeyUsage = nil
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.PolicyIdentifiers = []asn1.ObjectIdentifier{{2, 23, 133, 2, 99}}
	}), vectorTime, "not issued for endorsement keys"}
	cases["other extended key usage only"] = struct {
		der  []byte
		at   time.Time
		want string
	}{ekCert(t, inter, &ek.PublicKey, func(c *x509.Certificate) {
		c.UnknownExtKeyUsage = nil
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}), vectorTime, "not issued for endorsement keys"}
	cases["no TPM attributes in the subjectAltName"] = struct {
		der  []byte
		at   time.Time
		want string
	}{ekCert(t, inter, &ek.PublicKey, func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: oidSAN, Critical: true, Value: tpmSAN(2, 23, 133, 2, 1)}}
	}), vectorTime, "manufacturer, model and version"}
	cases["no subjectAltName"] = struct {
		der  []byte
		at   time.Time
		want string
	}{ekCert(t, inter, &ek.PublicKey, func(c *x509.Certificate) { c.ExtraExtensions = nil }), vectorTime, "manufacturer, model and version"}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases["P-384 EK"] = struct {
		der  []byte
		at   time.Time
		want string
	}{ekCert(t, inter, &p384.PublicKey, nil), vectorTime, "P-256"}
	for name, tc := range cases {
		if _, _, err := s.Verify(tc.der, tc.at); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	// a certificate without the intermediate in the store does not verify
	bare := NewStore()
	bare.Roots.AddCert(root.cert)
	if _, _, err := bare.Verify(good, vectorTime); err == nil {
		t.Error("verified without the intermediate CA")
	}
}

// Vendors such as Infineon declare the EK as id-RSAES-OAEP.
func TestRSAESOAEPKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: oidRSAESOAEP, Parameters: asn1.NullRawValue},
		asn1.BitString{Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey), BitLength: 8 * len(x509.MarshalPKCS1PublicKey(&key.PublicKey))}})
	got, err := publicKey(&x509.Certificate{RawSubjectPublicKeyInfo: spki})
	if err != nil {
		t.Fatal(err)
	}
	k, err := FromPublicKey(got)
	want, _ := FromPublicKey(&key.PublicKey)
	if err != nil || !bytes.Equal(k.Name(), want.Name()) || k.Alg != RSA {
		t.Errorf("%v", err)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := FromPublicKey(&small.PublicKey); err == nil {
		t.Error("RSA 1024 EK accepted")
	}
	if _, err := FromPublicKey("x"); err == nil {
		t.Error("unknown key type accepted")
	}
}

func TestAllowlist(t *testing.T) {
	n := "000b" + strings.Repeat("ab", 32)
	m, err := ParseAllowlist([]byte("# dev VMs\n" + strings.ToUpper(n) + "  # vm 1\n\n"))
	if err != nil || !m[n] || len(m) != 1 {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"zz", "000b00", "0004" + strings.Repeat("ab", 32)} {
		if _, err := ParseAllowlist([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if m, _ := ParseAllowlist(nil); len(m) != 0 {
		t.Error("empty allowlist not empty")
	}
	_ = hex.EncodeToString
}

func TestAddDir(t *testing.T) {
	root := newCA(t, "r", nil)
	inter := newCA(t, "i", root)
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "V/RootCA"), 0o755)
	os.MkdirAll(filepath.Join(d, "V/IntermediateCA"), 0o755)
	os.WriteFile(filepath.Join(d, "V/RootCA/r.cer"), root.cert.Raw, 0o644)
	os.WriteFile(filepath.Join(d, "V/IntermediateCA/i.cer"), inter.cert.Raw, 0o644)
	os.WriteFile(filepath.Join(d, "V/IntermediateCA/junk.cer"), []byte("junk"), 0o644)
	os.WriteFile(filepath.Join(d, "V/README"), []byte("ignored"), 0o644)
	s := NewStore()
	if err := s.AddDir(d); err != nil {
		t.Fatal(err)
	}
	if s.NRoots != 1 || s.NInter != 1 || len(s.Skipped) != 1 {
		t.Errorf("%d roots %d intermediates, skipped %v", s.NRoots, s.NInter, s.Skipped)
	}
	if err := NewStore().AddDir(filepath.Join(d, "missing")); err == nil {
		t.Error("missing CA directory accepted")
	}
}

// An issuing CA that restricts its extended key usages to something else
// cannot issue EK certificates; vendors are classified by bundle directory.
func TestChainEKUAndVendor(t *testing.T) {
	root := newCA(t, "root", nil)
	tlsOnly := newCA(t, "tls issuing CA", root)
	tlsOnly.cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} // as parsed from such a CA
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, _ := x509.ParseCertificate(ekCert(t, tlsOnly, &ek.PublicKey, nil))
	if chainAllowsEKU([]*x509.Certificate{leaf, tlsOnly.cert, root.cert}) {
		t.Error("EK certificate accepted below a CA restricted to TLS server certificates")
	}
	tlsOnly.cert.ExtKeyUsage = nil
	if !chainAllowsEKU([]*x509.Certificate{leaf, tlsOnly.cert, root.cert}) {
		t.Error("unrestricted issuing CA refused")
	}

	d := t.TempDir()
	for _, v := range []string{"Intel", "Infineon"} {
		ca := newCA(t, v+" EK CA", nil)
		os.MkdirAll(filepath.Join(d, v, "RootCA"), 0o755)
		os.WriteFile(filepath.Join(d, v, "RootCA", "ca.cer"), ca.cert.Raw, 0o644)
		s := NewStore()
		if err := s.AddDir(d); err != nil {
			t.Fatal(err)
		}
		_, info, err := s.Verify(ekCert(t, ca, &ek.PublicKey, nil), vectorTime)
		if err != nil || info.Vendor != v || info.Firmware() != (v == "Intel") {
			t.Errorf("%s: %+v %v", v, info, err)
		}
	}
}

// G11: a vendor certificate without extended key usage is accepted when it
// carries a certificate policy from the TCG arc.
func TestTCGPolicyInsteadOfEKU(t *testing.T) {
	root := newCA(t, "root", nil)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := NewStore()
	s.Roots.AddCert(root.cert)
	der := ekCert(t, root, &ek.PublicKey, func(c *x509.Certificate) {
		c.UnknownExtKeyUsage = nil
		c.PolicyIdentifiers = []asn1.ObjectIdentifier{{2, 23, 133, 2, 99}}
	})
	if _, _, err := s.Verify(der, vectorTime); err != nil {
		t.Fatalf("TCG policy OID instead of the EKU: %v", err)
	}
}
