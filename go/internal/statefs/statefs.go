// Package statefs is the authenticated, rollback-protected persistent state
// store on the encrypted /var/lib/enclave volume.
//
// dm-integrity authenticates each sector but not its version: an attacker
// with the disk could splice older ciphertext sectors back in. Therefore
// only data written through this package is persistent, and it is covered
// by a manifest (path, type, mode, owner, SHA-256 / symlink target of every
// entry under data/) whose HMAC key is derived from the TPM-held /var key and
// whose version is bound to a TPM NV counter. Any spliced or rolled-back
// content changes a hash, the MAC or the version and fails closed at boot.
//
// Layout below Root:
//
//	data/            the state (consumers read it at /var/lib/enclave/data)
//	.manifest        current manifest (JSON with MAC)
//	.manifest.next   prepared manifest of an in-flight commit
//	.staging/        prepared data tree of an in-flight commit
//	lost+found/      created by mkfs, ignored
//
// Commit protocol (Exec): copy data -> .staging, run the writer on .staging,
// write .manifest.next (version+1), exchange data and .staging atomically
// (renameat2 RENAME_EXCHANGE), rename .manifest.next -> .manifest, increment
// the TPM counter, remove the old tree. Boot recovery (Verify) rolls an
// interrupted commit forward or back, so a crash never bricks the device.
package statefs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// Counter is the TPM NV counter the manifest version is bound to.
type Counter interface {
	Read() (uint64, error)
	Increment() error
}

// Store is a state store rooted at a mounted volume.
type Store struct {
	Root    string
	Key     []byte // HMAC key (derived from the TPM-held /var key)
	Counter Counter
	// Pause, if set, is called at named points of a commit (tests only).
	Pause func(phase string)
}

// Entry is one manifest entry.
type Entry struct {
	Path   string `json:"path"`
	Type   string `json:"type"` // d, f or l
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}

// Manifest is the authenticated description of data/.
type Manifest struct {
	Version uint64  `json:"version"`
	Entries []Entry `json:"entries"`
	MAC     string  `json:"mac"`
}

var (
	// ErrRollback reports an older manifest than the TPM counter allows.
	ErrRollback = errors.New("state ROLLBACK detected")
	// ErrTampered reports content that does not match the manifest.
	ErrTampered = errors.New("state does not match its authenticated manifest")
)

func (s *Store) p(name string) string { return filepath.Join(s.Root, name) }

func (s *Store) pause(phase string) {
	if s.Pause != nil {
		s.Pause(phase)
	}
}

func (s *Store) mac(m Manifest) []byte {
	body, _ := json.Marshal(struct {
		Version uint64  `json:"version"`
		Entries []Entry `json:"entries"`
	}{m.Version, m.Entries})
	h := hmac.New(sha256.New, s.Key)
	h.Write([]byte("enclave-state-manifest-v1\x00"))
	h.Write(body)
	return h.Sum(nil)
}

// Scan describes a tree. Only directories, regular files and symlinks are
// allowed.
func Scan(dir string) ([]Entry, error) {
	var es []Entry
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		if rel == "." {
			return nil
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("no stat_t")
		}
		e := Entry{Path: filepath.ToSlash(rel), Mode: uint32(fi.Mode().Perm() | (fi.Mode() & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky))), UID: st.Uid, GID: st.Gid}
		switch {
		case fi.Mode().IsDir():
			e.Type = "d"
		case fi.Mode().IsRegular():
			e.Type = "f"
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return err
			}
			e.SHA256 = hex.EncodeToString(h.Sum(nil))
		case fi.Mode()&fs.ModeSymlink != 0:
			e.Type = "l"
			if e.Target, err = os.Readlink(path); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: unsupported file type %v", rel, fi.Mode().Type())
		}
		es = append(es, e)
		return nil
	})
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
	return es, err
}

func (s *Store) build(dir string, version uint64) (Manifest, error) {
	es, err := Scan(dir)
	if err != nil {
		return Manifest{}, err
	}
	if es == nil {
		es = []Entry{}
	}
	m := Manifest{Version: version, Entries: es}
	m.MAC = hex.EncodeToString(s.mac(m))
	return m, nil
}

func (s *Store) load(name string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(s.p(name))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("%s: %w", name, err)
	}
	mac, err := hex.DecodeString(m.MAC)
	if err != nil || !hmac.Equal(mac, s.mac(m)) {
		return m, fmt.Errorf("%s: %w (bad MAC)", name, ErrTampered)
	}
	return m, nil
}

func (s *Store) matches(dir string, m Manifest) bool {
	es, err := Scan(dir)
	if err != nil {
		return false
	}
	if es == nil {
		es = []Entry{}
	}
	a, _ := json.Marshal(es)
	b, _ := json.Marshal(m.Entries)
	return bytes.Equal(a, b)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Store) writeManifest(name string, m Manifest) error {
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	tmp := s.p(name + ".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.p(name)); err != nil {
		return err
	}
	return syncDir(s.Root)
}

func (s *Store) checkRoot() error {
	ents, err := os.ReadDir(s.Root)
	if err != nil {
		return err
	}
	for _, e := range ents {
		switch e.Name() {
		case "data", ".manifest", ".manifest.next", ".manifest.tmp", ".manifest.next.tmp", ".staging", ".lock", "lost+found":
		default:
			return fmt.Errorf("unexpected entry %q in the state volume: %w", e.Name(), ErrTampered)
		}
	}
	return nil
}

func (s *Store) lock() (func(), error) {
	f, err := os.OpenFile(s.p(".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil //nolint:errcheck
}

// Init creates an empty store. The counter must already hold its first value.
func (s *Store) Init() error {
	if err := s.checkRoot(); err != nil {
		return err
	}
	if _, err := os.Lstat(s.p(".manifest")); err == nil {
		return errors.New("state store already initialized")
	}
	if err := os.Mkdir(s.p("data"), 0o755); err != nil {
		return err
	}
	c, err := s.Counter.Read()
	if err != nil {
		return err
	}
	m, err := s.build(s.p("data"), c)
	if err != nil {
		return err
	}
	return s.writeManifest(".manifest", m)
}

// Verify recovers an interrupted commit, checks data/ against the
// authenticated manifest and binds its version to the TPM counter
// (version == counter, or counter+1 after a crash before the increment).
// It returns the verified version.
func (s *Store) Verify() (uint64, error) {
	unlock, err := s.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := s.checkRoot(); err != nil {
		return 0, err
	}
	cur, err := s.load(".manifest")
	if err != nil {
		return 0, err
	}
	if _, err := os.Lstat(s.p(".manifest.next")); err == nil {
		next, err := s.load(".manifest.next")
		if err != nil {
			return 0, err
		}
		if next.Version != cur.Version+1 {
			return 0, fmt.Errorf(".manifest.next version %d does not follow %d: %w", next.Version, cur.Version, ErrTampered)
		}
		switch {
		case s.matches(s.p("data"), next):
			// exchanged, manifest not yet renamed: roll forward
		case s.matches(s.p("data"), cur) && s.matches(s.p(".staging"), next):
			if err := exchange(s.p("data"), s.p(".staging")); err != nil {
				return 0, err
			}
			if err := syncDir(s.Root); err != nil {
				return 0, err
			}
		case s.matches(s.p("data"), cur):
			// prepared manifest without a complete staging tree: roll back
			if err := os.Remove(s.p(".manifest.next")); err != nil {
				return 0, err
			}
			next = Manifest{}
		default:
			return 0, fmt.Errorf("interrupted commit with inconsistent data: %w", ErrTampered)
		}
		if next.MAC != "" {
			if err := os.Rename(s.p(".manifest.next"), s.p(".manifest")); err != nil {
				return 0, err
			}
			if err := syncDir(s.Root); err != nil {
				return 0, err
			}
			cur = next
		}
	}
	for _, leftover := range []string{".staging", ".manifest.tmp", ".manifest.next.tmp"} {
		if err := os.RemoveAll(s.p(leftover)); err != nil {
			return 0, err
		}
	}
	if !s.matches(s.p("data"), cur) {
		return 0, fmt.Errorf("data/ differs from manifest version %d: %w", cur.Version, ErrTampered)
	}
	c, err := s.Counter.Read()
	if err != nil {
		return 0, err
	}
	switch {
	case cur.Version == c:
	case cur.Version == c+1:
		if err := s.Counter.Increment(); err != nil {
			return 0, err
		}
		if c2, err := s.Counter.Read(); err != nil || c2 != cur.Version {
			return 0, fmt.Errorf("TPM counter did not advance to %d (%d, %v)", cur.Version, c2, err)
		}
	case cur.Version < c:
		return 0, fmt.Errorf("manifest version %d < TPM counter %d (old snapshot?): %w", cur.Version, c, ErrRollback)
	default:
		return 0, fmt.Errorf("manifest version %d ahead of TPM counter %d: %w", cur.Version, c, ErrTampered)
	}
	return cur.Version, nil
}

// Exec runs writer on a copy of data/ and commits the result atomically.
func (s *Store) Exec(writer func(staging string) error) (uint64, error) {
	unlock, err := s.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	cur, err := s.load(".manifest")
	if err != nil {
		return 0, err
	}
	if _, err := os.Lstat(s.p(".manifest.next")); err == nil {
		return 0, errors.New("an interrupted commit is pending (reboot to recover)")
	}
	if !s.matches(s.p("data"), cur) {
		return 0, fmt.Errorf("data/ differs from the manifest: %w", ErrTampered)
	}
	c, err := s.Counter.Read()
	if err != nil {
		return 0, err
	}
	if c != cur.Version {
		return 0, fmt.Errorf("manifest version %d != TPM counter %d", cur.Version, c)
	}
	if err := os.RemoveAll(s.p(".staging")); err != nil {
		return 0, err
	}
	if err := copyTree(s.p("data"), s.p(".staging")); err != nil {
		return 0, err
	}
	if err := writer(s.p(".staging")); err != nil {
		os.RemoveAll(s.p(".staging"))
		return 0, err
	}
	if err := syncTree(s.p(".staging")); err != nil {
		return 0, err
	}
	next, err := s.build(s.p(".staging"), cur.Version+1)
	if err != nil {
		os.RemoveAll(s.p(".staging"))
		return 0, err
	}
	if err := s.writeManifest(".manifest.next", next); err != nil {
		return 0, err
	}
	s.pause("next-written")
	if err := exchange(s.p("data"), s.p(".staging")); err != nil {
		return 0, err
	}
	if err := syncDir(s.Root); err != nil {
		return 0, err
	}
	s.pause("exchanged")
	if err := os.Rename(s.p(".manifest.next"), s.p(".manifest")); err != nil {
		return 0, err
	}
	if err := syncDir(s.Root); err != nil {
		return 0, err
	}
	s.pause("manifest-committed")
	if err := s.Counter.Increment(); err != nil {
		return 0, err
	}
	if c2, err := s.Counter.Read(); err != nil || c2 != next.Version {
		return 0, fmt.Errorf("TPM counter did not advance to %d (%d, %v)", next.Version, c2, err)
	}
	if err := os.RemoveAll(s.p(".staging")); err != nil {
		return 0, err
	}
	return next.Version, nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		to := filepath.Join(dst, rel)
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		switch {
		case fi.Mode().IsDir():
			if err := os.Mkdir(to, fi.Mode().Perm()); err != nil {
				return err
			}
		case fi.Mode().IsRegular():
			in, err := os.Open(path)
			if err != nil {
				return err
			}
			out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm())
			if err != nil {
				in.Close()
				return err
			}
			_, err = io.Copy(out, in)
			in.Close()
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		case fi.Mode()&fs.ModeSymlink != 0:
			t, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.Symlink(t, to); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: unsupported file type", rel)
		}
		if err := os.Lchown(to, int(st.Uid), int(st.Gid)); err != nil && !errors.Is(err, syscall.EPERM) {
			return err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			return os.Chmod(to, fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky))
		}
		return nil
	})
}

func syncTree(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return f.Sync()
	})
}

// HasPending reports whether an interrupted commit awaits recovery.
func (s *Store) HasPending() bool {
	_, err := os.Lstat(s.p(".manifest.next"))
	return err == nil
}

// Read returns a regular file of the state after authenticating it: the
// manifest's MAC, the manifest version against the TPM counter, and the
// file's hash against its manifest entry. Consumers read state through this
// (or check the same way) so that a write that bypassed the commit protocol
// is detected at the read, not only at the next boot.
//
// The volume is mounted read-only for readers, so no lock file is taken;
// the state service serializes reads and commits.
func (s *Store) Read(rel string) ([]byte, error) {
	m, err := s.load(".manifest")
	if err != nil {
		return nil, err
	}
	c, err := s.Counter.Read()
	if err != nil {
		return nil, err
	}
	if m.Version != c {
		return nil, fmt.Errorf("manifest version %d != TPM counter %d: %w", m.Version, c, ErrRollback)
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	for _, e := range m.Entries {
		if e.Path != rel {
			continue
		}
		if e.Type != "f" {
			return nil, fmt.Errorf("%s is not a regular file", rel)
		}
		p := filepath.Join(s.p("data"), filepath.FromSlash(rel))
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: %w", rel, ErrTampered)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != e.SHA256 {
			return nil, fmt.Errorf("%s differs from its manifest entry: %w", rel, ErrTampered)
		}
		return b, nil
	}
	return nil, fmt.Errorf("%s: %w", rel, fs.ErrNotExist)
}

// Status returns the authenticated manifest version and the TPM counter.
func (s *Store) Status() (version, counter uint64, err error) {
	m, err := s.load(".manifest")
	if err != nil {
		return 0, 0, err
	}
	c, err := s.Counter.Read()
	return m.Version, c, err
}
