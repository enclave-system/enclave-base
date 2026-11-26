package statefs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type memCounter struct {
	v    uint64
	fail error
}

func (c *memCounter) Read() (uint64, error) { return c.v, nil }
func (c *memCounter) Increment() error {
	if c.fail != nil {
		return c.fail
	}
	c.v++
	return nil
}

type crash struct{ phase string }

func newStore(t *testing.T) (*Store, *memCounter) {
	t.Helper()
	c := &memCounter{v: 41}
	s := &Store{Root: t.TempDir(), Key: []byte("k-0123456789abcdef0123456789abcd"), Counter: c}
	if err := os.Mkdir(filepath.Join(s.Root, "lost+found"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	return s, c
}

func write(rel, content string) func(string) error {
	return func(st string) error {
		p := filepath.Join(st, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, []byte(content), 0o644)
	}
}

func mustExec(t *testing.T, s *Store, w func(string) error) uint64 {
	t.Helper()
	v, err := s.Exec(w)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func read(t *testing.T, s *Store, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.Root, "data", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// snapshot copies the whole volume (what an attacker with the disk can do).
func snapshot(t *testing.T, s *Store) string {
	t.Helper()
	d := t.TempDir()
	if out, err := exec.Command("cp", "-a", s.Root+"/.", d).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	return d
}

func restore(t *testing.T, s *Store, snap string) {
	t.Helper()
	ents, _ := os.ReadDir(s.Root)
	for _, e := range ents {
		os.RemoveAll(filepath.Join(s.Root, e.Name()))
	}
	if out, err := exec.Command("cp", "-a", snap+"/.", s.Root).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
}

func TestCommitAndVerify(t *testing.T) {
	s, c := newStore(t)
	if v, err := s.Verify(); err != nil || v != 41 {
		t.Fatalf("%d %v", v, err)
	}
	v := mustExec(t, s, write("config/current", "one"))
	if v != 42 || c.v != 42 || read(t, s, "config/current") != "one" {
		t.Fatalf("v=%d c=%d", v, c.v)
	}
	mustExec(t, s, func(st string) error { return os.Symlink("current", filepath.Join(st, "config/link")) })
	mustExec(t, s, func(st string) error { return os.Remove(filepath.Join(st, "config/link")) })
	if v, err := s.Verify(); err != nil || v != 44 {
		t.Fatalf("%d %v", v, err)
	}
	for _, p := range []string{".staging", ".manifest.next"} {
		if _, err := os.Lstat(filepath.Join(s.Root, p)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind", p)
		}
	}
}

func TestWriterErrorChangesNothing(t *testing.T) {
	s, c := newStore(t)
	mustExec(t, s, write("a", "1"))
	if _, err := s.Exec(func(st string) error {
		os.WriteFile(filepath.Join(st, "a"), []byte("2"), 0o644)
		return errors.New("writer failed")
	}); err == nil {
		t.Fatal("writer error swallowed")
	}
	if read(t, s, "a") != "1" || c.v != 42 {
		t.Error("failed writer changed state")
	}
	if _, err := s.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestTamperingDetected(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Store, old string){
		"file content changed": func(t *testing.T, s *Store, old string) {
			os.WriteFile(filepath.Join(s.Root, "data/a"), []byte("evil"), 0o644)
		},
		"older file content spliced": func(t *testing.T, s *Store, old string) {
			b, _ := os.ReadFile(filepath.Join(old, "data/a"))
			os.WriteFile(filepath.Join(s.Root, "data/a"), b, 0o644)
		},
		"older manifest spliced": func(t *testing.T, s *Store, old string) {
			b, _ := os.ReadFile(filepath.Join(old, ".manifest"))
			os.WriteFile(filepath.Join(s.Root, ".manifest"), b, 0o600)
		},
		"file added": func(t *testing.T, s *Store, old string) {
			os.WriteFile(filepath.Join(s.Root, "data/extra"), nil, 0o644)
		},
		"file removed": func(t *testing.T, s *Store, old string) { os.Remove(filepath.Join(s.Root, "data/a")) },
		"mode changed": func(t *testing.T, s *Store, old string) { os.Chmod(filepath.Join(s.Root, "data/a"), 0o4755) },
		"manifest MAC broken": func(t *testing.T, s *Store, old string) {
			p := filepath.Join(s.Root, ".manifest")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, []byte(strings.Replace(string(b), `"version": 43`, `"version": 44`, 1)), 0o600)
		},
		"forged next manifest": func(t *testing.T, s *Store, old string) {
			b, _ := os.ReadFile(filepath.Join(old, ".manifest"))
			os.WriteFile(filepath.Join(s.Root, ".manifest.next"), b, 0o600)
		},
		"unexpected root entry": func(t *testing.T, s *Store, old string) {
			os.WriteFile(filepath.Join(s.Root, "payload"), nil, 0o644)
		},
		"fifo in data": func(t *testing.T, s *Store, old string) {
			syscall.Mkfifo(filepath.Join(s.Root, "data/fifo"), 0o644)
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := newStore(t)
			mustExec(t, s, write("a", "version-1"))
			old := snapshot(t, s)
			mustExec(t, s, write("a", "version-2"))
			tamper(t, s, old)
			if _, err := s.Verify(); err == nil {
				t.Fatal("tampering accepted")
			}
		})
	}
}

func TestSnapshotRollbackDetected(t *testing.T) {
	s, _ := newStore(t)
	mustExec(t, s, write("a", "1"))
	old := snapshot(t, s)
	mustExec(t, s, write("a", "2"))
	restore(t, s, old)
	if _, err := s.Verify(); !errors.Is(err, ErrRollback) {
		t.Fatalf("err = %v", err)
	}
}

func TestCrashConsistency(t *testing.T) {
	for _, phase := range []string{"next-written", "exchanged", "manifest-committed", "increment"} {
		t.Run(phase, func(t *testing.T) {
			s, c := newStore(t)
			mustExec(t, s, write("a", "old"))
			if phase == "increment" {
				c.fail = errors.New("power loss")
			} else {
				s.Pause = func(p string) {
					if p == phase {
						panic(crash{p})
					}
				}
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						if _, ok := r.(crash); !ok {
							panic(r)
						}
					}
				}()
				s.Exec(write("a", "new")) //nolint:errcheck
			}()
			s.Pause, c.fail = nil, nil
			v, err := s.Verify()
			if err != nil {
				t.Fatalf("not recoverable after crash at %s: %v", phase, err)
			}
			got := read(t, s, "a")
			if got != "old" && got != "new" {
				t.Fatalf("content %q", got)
			}
			if c.v != v {
				t.Errorf("counter %d != version %d", c.v, v)
			}
			// and the store keeps working
			mustExec(t, s, write("b", "x"))
			if _, err := s.Verify(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInitRefusesNonEmpty(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Init(); err == nil {
		t.Error("re-init accepted")
	}
	s2 := &Store{Root: t.TempDir(), Key: []byte("k"), Counter: &memCounter{}}
	os.WriteFile(filepath.Join(s2.Root, "junk"), nil, 0o644)
	if err := s2.Init(); err == nil {
		t.Error("init on a volume with foreign content")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	s, c := newStore(t)
	mustExec(t, s, write("a", "1"))
	other := &Store{Root: s.Root, Key: []byte("other-key"), Counter: c}
	if _, err := other.Verify(); err == nil {
		t.Fatal("manifest accepted with another key")
	}
}
