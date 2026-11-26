package bundle

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// ApplyOptions configures Apply.
type ApplyOptions struct {
	Root string
	Role string
	Pub  ed25519.PublicKey
	Keep int // number of versions to retain; <=0 means 3
}

const defaultKeep = 3

// applyHookAfterExtract is a test hook, called after a version has been
// extracted and synced but before it is made visible.
var applyHookAfterExtract func(version uint64) error

type state struct {
	Version uint64 `json:"version"`
}

// Apply verifies the bundle and atomically installs it as the current
// version. On any failure the previously installed version stays in place.
func Apply(opts ApplyOptions, bundle, sig []byte) (uint64, error) {
	m, files, err := open(opts.Pub, bundle, sig)
	if err != nil {
		return 0, err
	}
	if m.Role != opts.Role {
		return 0, fmt.Errorf("%w: bundle is for %q, this machine is %q", ErrWrongRole, m.Role, opts.Role)
	}
	keep := opts.Keep
	if keep <= 0 {
		keep = defaultKeep
	}

	if err := ensureRoot(opts.Root); err != nil {
		return 0, err
	}
	// Serialize all Applies on this Root; everything below, including the
	// rollback check, runs under the lock.
	unlock, err := lockRoot(opts.Root)
	if err != nil {
		return 0, err
	}
	defer unlock()

	versions := filepath.Join(opts.Root, "versions")
	if err := ensureVersionsDir(versions); err != nil {
		return 0, err
	}
	floor, err := rollbackFloor(opts.Root, versions)
	if err != nil {
		return 0, err
	}
	if m.Version <= floor {
		return 0, fmt.Errorf("%w: bundle %d, installed %d", ErrRollback, m.Version, floor)
	}
	if err := cleanupTmp(opts.Root); err != nil {
		return 0, err
	}

	name := strconv.FormatUint(m.Version, 10)
	tmp := filepath.Join(versions, name+".tmp")
	final := filepath.Join(versions, name)

	if err := extract(tmp, files); err != nil {
		os.RemoveAll(tmp)
		return 0, err
	}
	if applyHookAfterExtract != nil {
		if err := applyHookAfterExtract(m.Version); err != nil {
			os.RemoveAll(tmp)
			return 0, err
		}
	}
	// A leftover versions/<N> is from a crash after rename but before state
	// was written (N > state.version); it is not referenced by anything valid.
	if err := os.RemoveAll(final); err != nil {
		os.RemoveAll(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, final); err != nil {
		os.RemoveAll(tmp)
		return 0, err
	}
	if err := syncDir(versions); err != nil {
		return 0, err
	}

	linkTmp := filepath.Join(opts.Root, "current.tmp")
	os.Remove(linkTmp)
	if err := os.Symlink(filepath.Join("versions", name), linkTmp); err != nil {
		return 0, err
	}
	if err := os.Rename(linkTmp, filepath.Join(opts.Root, "current")); err != nil {
		return 0, err
	}
	if err := syncDir(opts.Root); err != nil {
		return 0, err
	}
	if err := writeState(opts.Root, m.Version); err != nil {
		return 0, err
	}
	pruneVersions(versions, keep, m.Version)
	return m.Version, nil
}

func readState(root string) (uint64, error) {
	b, err := os.ReadFile(filepath.Join(root, "state.json"))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return 0, fmt.Errorf("state.json: %w", err)
	}
	return s.Version, nil
}

func writeState(root string, v uint64) error {
	b, _ := json.Marshal(state{Version: v})
	tmp := filepath.Join(root, "state.json.tmp")
	if err := writeSynced(tmp, b, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(root, "state.json")); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(root)
}

func writeSynced(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode) // exact mode, independent of umask
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func extract(tmp string, files []payload) error {
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	dirs := map[string]struct{}{tmp: {}}
	if err := os.Mkdir(tmp, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		full := filepath.Join(tmp, filepath.FromSlash(f.entry.Path))
		dir := filepath.Dir(full)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		for d := dir; d != tmp; d = filepath.Dir(d) {
			dirs[d] = struct{}{}
		}
		if err := writeSynced(full, f.data, f.mode); err != nil {
			return err
		}
	}
	for d := range dirs {
		if err := os.Chmod(d, 0o755); err != nil {
			return err
		}
		if err := syncDir(d); err != nil {
			return err
		}
	}
	return nil
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// cleanupTmp removes orphaned *.tmp left by an interrupted Apply.
func cleanupTmp(root string) error {
	for _, p := range []string{"current.tmp", "state.json.tmp"} {
		if err := os.RemoveAll(filepath.Join(root, p)); err != nil {
			return err
		}
	}
	es, err := os.ReadDir(filepath.Join(root, "versions"))
	if err != nil {
		return err
	}
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".tmp") {
			if err := os.RemoveAll(filepath.Join(root, "versions", e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// pruneVersions removes all but the newest keep versions, never the one just
// applied and never anything at or above it. Best effort: the new version is
// already live, so failures here are not reported as Apply failures.
func pruneVersions(versions string, keep int, applied uint64) {
	nums, err := listVersions(versions)
	if err != nil {
		return
	}
	for i := keep; i < len(nums); i++ {
		if nums[i] < applied {
			os.RemoveAll(filepath.Join(versions, strconv.FormatUint(nums[i], 10)))
		}
	}
}

// listVersions returns the numeric versions/<N> entries, newest first.
// *.tmp and other names are ignored.
func listVersions(versions string) ([]uint64, error) {
	es, err := os.ReadDir(versions)
	if err != nil {
		return nil, err
	}
	var nums []uint64
	for _, e := range es {
		n, err := strconv.ParseUint(e.Name(), 10, 64)
		if err == nil && strconv.FormatUint(n, 10) == e.Name() {
			nums = append(nums, n)
		}
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] > nums[j] })
	return nums, nil
}

// rollbackFloor is the highest version known to have been installed:
// max(state.json, highest versions/<N>, target of current). A missing or
// zeroed state.json therefore cannot reopen old versions; a corrupt one
// fails closed.
func rollbackFloor(root, versions string) (uint64, error) {
	floor, err := readState(root)
	if err != nil {
		return 0, err
	}
	nums, err := listVersions(versions)
	if err != nil {
		return 0, err
	}
	if len(nums) > 0 && nums[0] > floor {
		floor = nums[0]
	}
	if l, err := os.Readlink(filepath.Join(root, "current")); err == nil {
		if n, err := strconv.ParseUint(filepath.Base(l), 10, 64); err == nil && n > floor {
			floor = n
		}
	}
	return floor, nil
}

func ensureRoot(root string) error {
	if fi, err := os.Stat(root); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s: not a directory", root)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	return os.Chmod(root, 0o755)
}

func ensureVersionsDir(versions string) error {
	fi, err := os.Lstat(versions)
	if os.IsNotExist(err) {
		if err := os.Mkdir(versions, 0o755); err != nil {
			return err
		}
		return os.Chmod(versions, 0o755)
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() { // Lstat: a symlink is not a directory here
		return fmt.Errorf("%s: not a plain directory", versions)
	}
	return nil
}

func lockRoot(root string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(root, ".lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
