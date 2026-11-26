package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

func newKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func writeTree(t testing.TB, files map[string]string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func buildBundle(t testing.TB, priv ed25519.PrivateKey, role string, version uint64, files map[string]string) ([]byte, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if err := Build(writeTree(t, files, 0o640), role, version, testNow, &buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), Sign(priv, buf.Bytes())
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type rawEntry struct {
	name string
	typ  byte
	body []byte
	link string
}

func rawTar(t testing.TB, entries []rawEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o640, Linkname: e.link}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func manifestEntry(t testing.TB, m Manifest) rawEntry {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return rawEntry{name: "manifest.json", body: b}
}

func goodManifest(files ...FileEntry) Manifest {
	if files == nil {
		files = []FileEntry{}
	}
	return Manifest{Format: 1, Role: "r", Version: 1, Created: "2026-11-26T12:00:00Z", Files: files}
}

func TestBuildVerifyRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	b, sig := buildBundle(t, priv, "gateway", 7, map[string]string{"a.conf": "hello", "sub/b.conf": "world"})
	m, err := Verify(pub, b, sig)
	if err != nil {
		t.Fatal(err)
	}
	if m.Role != "gateway" || m.Version != 7 || m.Format != 1 || m.Created != "2026-11-26T12:00:00Z" {
		t.Fatalf("manifest: %+v", m)
	}
	want := []FileEntry{
		{Path: "a.conf", SHA256: sum([]byte("hello")), Mode: "0640"},
		{Path: "sub/b.conf", SHA256: sum([]byte("world")), Mode: "0640"},
	}
	if len(m.Files) != 2 || m.Files[0] != want[0] || m.Files[1] != want[1] {
		t.Fatalf("files: %+v", m.Files)
	}
}

func TestBuildDeterministic(t *testing.T) {
	dir := writeTree(t, map[string]string{"z": "1", "a": "2", "m/x": "3"}, 0o644)
	var b1, b2 bytes.Buffer
	if err := Build(dir, "r", 1, testNow, &b1); err != nil {
		t.Fatal(err)
	}
	if err := Build(dir, "r", 1, testNow, &b2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1.Bytes(), b2.Bytes()) {
		t.Fatal("builds differ")
	}
}

func TestBuildRejectsSymlink(t *testing.T) {
	dir := writeTree(t, map[string]string{"a": "1"}, 0o644)
	if err := os.Symlink("a", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	if err := Build(dir, "r", 1, testNow, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for symlink in source")
	}
}

func TestVerifyRejectsTamperedByte(t *testing.T) {
	pub, priv := newKey(t)
	b, sig := buildBundle(t, priv, "r", 1, map[string]string{"a": "hello"})
	for i := range b {
		c := append([]byte(nil), b...)
		c[i] ^= 0x01
		if _, err := Verify(pub, c, sig); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("byte %d: got %v", i, err)
		}
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv := newKey(t)
	other, _ := newKey(t)
	b, sig := buildBundle(t, priv, "r", 1, map[string]string{"a": "x"})
	if _, err := Verify(other, b, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
	if _, err := Verify(other, b, sig[:10]); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("short sig: got %v", err)
	}
}

func TestVerifyRejectsUnsafePaths(t *testing.T) {
	pub, priv := newKey(t)
	body := []byte("x")
	fe := func(p string) FileEntry { return FileEntry{Path: p, SHA256: sum(body), Mode: "0640"} }
	cases := map[string][]rawEntry{
		"dotdot":   {manifestEntry(t, goodManifest(fe("../x"))), {name: "files/../x", body: body}},
		"dotdot-n": {manifestEntry(t, goodManifest(fe("a/../../x"))), {name: "files/a/../../x", body: body}},
		"absolute": {manifestEntry(t, goodManifest(fe("/etc/x"))), {name: "files//etc/x", body: body}},
		"abs-name": {manifestEntry(t, goodManifest(fe("x"))), {name: "/etc/x", body: body}},
		"dot":      {manifestEntry(t, goodManifest(fe("./x"))), {name: "files/./x", body: body}},
		"empty":    {manifestEntry(t, goodManifest(fe("a//x"))), {name: "files/a//x", body: body}},
		"symlink":  {manifestEntry(t, goodManifest(fe("x"))), {name: "files/x", typ: tar.TypeSymlink, link: "/etc/passwd"}},
		"hardlink": {manifestEntry(t, goodManifest(fe("x"))), {name: "files/x", typ: tar.TypeLink, link: "files/y"}},
		"device":   {manifestEntry(t, goodManifest(fe("x"))), {name: "files/x", typ: tar.TypeChar}},
		"outside":  {manifestEntry(t, goodManifest(fe("x"))), {name: "other/x", body: body}},
	}
	for name, es := range cases {
		b := rawTar(t, es)
		if _, err := Verify(pub, b, Sign(priv, b)); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestVerifyRejectsHashMismatch(t *testing.T) {
	pub, priv := newKey(t)
	e := FileEntry{Path: "x", SHA256: sum([]byte("other")), Mode: "0640"}
	b := rawTar(t, []rawEntry{manifestEntry(t, goodManifest(e)), {name: "files/x", body: []byte("x")}})
	if _, err := Verify(pub, b, Sign(priv, b)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	pub, priv := newKey(t)
	body := []byte("x")
	fe := func(p, mode string) FileEntry { return FileEntry{Path: p, SHA256: sum(body), Mode: mode} }
	file := func(p string) rawEntry { return rawEntry{name: "files/" + p, body: body} }
	m := func(f ...FileEntry) rawEntry { return manifestEntry(t, goodManifest(f...)) }
	badFormat := goodManifest()
	badFormat.Format = 2
	badTime := goodManifest()
	badTime.Created = "yesterday"
	cases := map[string][]rawEntry{
		"manifest-not-first": {file("x"), m(fe("x", "0640"))},
		"no-manifest":        {file("x")},
		"duplicate-manifest": {m(fe("x", "0640"), fe("x", "0640")), file("x")},
		"duplicate-tar":      {m(fe("x", "0640")), file("x"), file("x")},
		"extra-in-tar":       {m(fe("x", "0640")), file("x"), file("y")},
		"missing-in-tar":     {m(fe("x", "0640"), fe("y", "0640")), file("x")},
		"mode-not-octal":     {m(fe("x", "rw-r--r--")), file("x")},
		"mode-89":            {m(fe("x", "0689")), file("x")},
		"mode-setuid":        {m(fe("x", "4755")), file("x")},
		"mode-sticky":        {m(fe("x", "1644")), file("x")},
		"mode-groupwrite":    {m(fe("x", "0660")), file("x")},
		"mode-worldwrite":    {m(fe("x", "0646")), file("x")},
		"file-and-dir":       {m(fe("x", "0640"), fe("x/y", "0640")), file("x"), file("x/y")},
		"bad-format":         {manifestEntry(t, badFormat)},
		"bad-created":        {manifestEntry(t, badTime)},
		"bad-hash-syntax":    {m(FileEntry{Path: "x", SHA256: "zz", Mode: "0640"}), file("x")},
		"manifest-garbage":   {{name: "manifest.json", body: []byte("{")}},
		"manifest-unknown":   {{name: "manifest.json", body: []byte(`{"format":1,"role":"r","version":1,"created":"2026-11-26T12:00:00Z","files":[],"x":1}`)}},
	}
	for name, es := range cases {
		b := rawTar(t, es)
		_, err := Verify(pub, b, Sign(priv, b))
		if !errors.Is(err, ErrBadFormat) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// not gzip at all, but correctly signed
	junk := []byte("not a gzip")
	if _, err := Verify(pub, junk, Sign(priv, junk)); !errors.Is(err, ErrBadFormat) {
		t.Errorf("junk: got %v", err)
	}
}

func TestVerifyRejectsTooManyEntries(t *testing.T) {
	pub, priv := newKey(t)
	fs := make([]FileEntry, MaxEntries+1)
	for i := range fs {
		fs[i] = FileEntry{Path: "f" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676)), SHA256: sum(nil), Mode: "0640"}
	}
	b := rawTar(t, []rawEntry{manifestEntry(t, goodManifest(fs...))})
	if _, err := Verify(pub, b, Sign(priv, b)); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyRejectsOversize(t *testing.T) {
	pub, priv := newKey(t)
	big := make([]byte, MaxTotalSize+1)
	e := FileEntry{Path: "x", SHA256: sum(big), Mode: "0640"}
	b := rawTar(t, []rawEntry{manifestEntry(t, goodManifest(e)), {name: "files/x", body: big}})
	if _, err := Verify(pub, b, Sign(priv, b)); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("got %v", err)
	}
}
