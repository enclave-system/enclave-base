package bundle

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var cachedPub ed25519.PublicKey
var cachedPriv ed25519.PrivateKey

func testKeys(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	if cachedPub == nil {
		cachedPub, cachedPriv = newKey(t)
	}
	return cachedPub, cachedPriv
}

func readFile(t testing.TB, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplyFirstVersion(t *testing.T) {
	pub, priv := newKey(t)
	b, sig := buildBundle(t, priv, "gateway", 1, map[string]string{"app.conf": "hello", "d/x": "y"})
	root := filepath.Join(t.TempDir(), "cfg")
	v, err := Apply(ApplyOptions{Root: root, Role: "gateway", Pub: pub}, b, sig)
	if err != nil || v != 1 {
		t.Fatalf("v=%d err=%v", v, err)
	}
	if got := readFile(t, filepath.Join(root, "current", "app.conf")); got != "hello" {
		t.Fatalf("content %q", got)
	}
	fi, _ := os.Stat(filepath.Join(root, "current", "app.conf"))
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
	di, _ := os.Stat(filepath.Join(root, "current", "d"))
	if di.Mode().Perm() != 0o755 {
		t.Fatalf("dir mode %v", di.Mode())
	}
	if l, _ := os.Readlink(filepath.Join(root, "current")); l != "versions/1" {
		t.Fatalf("link %q", l)
	}
	if got := readFile(t, filepath.Join(root, "state.json")); got != `{"version":1}` {
		t.Fatalf("state %q", got)
	}
}

func TestApplyWrongRole(t *testing.T) {
	pub, priv := newKey(t)
	b, sig := buildBundle(t, priv, "gateway", 1, map[string]string{"a": "x"})
	root := filepath.Join(t.TempDir(), "cfg")
	_, err := Apply(ApplyOptions{Root: root, Role: "vault", Pub: pub}, b, sig)
	if !errors.Is(err, ErrWrongRole) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("root was created: %v", err)
	}
}

func TestApplyBadSignatureTouchesNothing(t *testing.T) {
	pub, priv := newKey(t)
	b, sig := buildBundle(t, priv, "gateway", 1, map[string]string{"a": "x"})
	b[len(b)/2] ^= 1
	root := filepath.Join(t.TempDir(), "cfg")
	if _, err := Apply(ApplyOptions{Root: root, Role: "gateway", Pub: pub}, b, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("root was created: %v", err)
	}
}

func apply(t testing.TB, root string, n uint64, keep int) error {
	t.Helper()
	pub, priv := testKeys(t)
	b, sig := buildBundle(t, priv, "gateway", n, map[string]string{"app.conf": fmt.Sprintf("v%d", n)})
	_, err := Apply(ApplyOptions{Root: root, Role: "gateway", Pub: pub, Keep: keep}, b, sig)
	return err
}

func TestApplyRollbackRejected(t *testing.T) {
	root := t.TempDir()
	if err := apply(t, root, 5, 3); err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint64{5, 4} {
		if err := apply(t, root, n, 3); !errors.Is(err, ErrRollback) {
			t.Fatalf("v%d: got %v", n, err)
		}
	}
	if l, _ := os.Readlink(filepath.Join(root, "current")); l != "versions/5" {
		t.Fatalf("link %q", l)
	}
	if got := readFile(t, filepath.Join(root, "current", "app.conf")); got != "v5" {
		t.Fatalf("content %q", got)
	}
}

func TestApplyKeepsLastN(t *testing.T) {
	root := t.TempDir()
	for n := uint64(1); n <= 5; n++ {
		if err := apply(t, root, n, 3); err != nil {
			t.Fatal(err)
		}
	}
	es, _ := os.ReadDir(filepath.Join(root, "versions"))
	var got []string
	for _, e := range es {
		got = append(got, e.Name())
	}
	if fmt.Sprint(got) != "[3 4 5]" {
		t.Fatalf("versions: %v", got)
	}
}

func TestApplyInterruptedKeepsPrevious(t *testing.T) {
	root := t.TempDir()
	if err := apply(t, root, 1, 3); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	applyHookAfterExtract = func(v uint64) error { return boom }
	err := apply(t, root, 2, 3)
	applyHookAfterExtract = nil
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if l, _ := os.Readlink(filepath.Join(root, "current")); l != "versions/1" {
		t.Fatalf("link %q", l)
	}
	if got := readFile(t, filepath.Join(root, "state.json")); got != `{"version":1}` {
		t.Fatalf("state %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, "versions", "2")); !os.IsNotExist(err) {
		t.Fatalf("versions/2 exists: %v", err)
	}
	var tmps []string
	filepath.Walk(root, func(p string, _ os.FileInfo, _ error) error {
		if filepath.Ext(p) == ".tmp" {
			tmps = append(tmps, p)
		}
		return nil
	})
	if len(tmps) != 0 {
		t.Fatalf("leftover tmp: %v", tmps)
	}
	if err := apply(t, root, 2, 3); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(root, "current", "app.conf")); got != "v2" {
		t.Fatalf("content %q", got)
	}
}

func TestApplyCleansOrphanTmp(t *testing.T) {
	root := t.TempDir()
	if err := apply(t, root, 1, 3); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(root, "versions", "2.tmp", "junk"), 0o755)
	os.WriteFile(filepath.Join(root, "state.json.tmp"), []byte("x"), 0o644)
	os.Symlink("versions/9", filepath.Join(root, "current.tmp"))
	if err := apply(t, root, 2, 3); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"versions/2.tmp", "state.json.tmp", "current.tmp"} {
		if _, err := os.Lstat(filepath.Join(root, p)); !os.IsNotExist(err) {
			t.Errorf("%s remains", p)
		}
	}
}
