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
	cur, err := readState(opts.Root)
	if err != nil {
		return 0, err
	}
	if m.Version <= cur {
		return 0, fmt.Errorf("%w: bundle %d, installed %d", ErrRollback, m.Version, cur)
	}
	keep := opts.Keep
	if keep <= 0 {
		keep = defaultKeep
	}

	versions := filepath.Join(opts.Root, "versions")
	if err := os.MkdirAll(versions, 0o755); err != nil {
		return 0, err
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
	pruneVersions(versions, keep)
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

// pruneVersions removes all but the newest keep versions. Best effort: the
// new version is already live, so failures here are not reported as Apply
// failures.
func pruneVersions(versions string, keep int) {
	es, err := os.ReadDir(versions)
	if err != nil {
		return
	}
	var nums []uint64
	for _, e := range es {
		n, err := strconv.ParseUint(e.Name(), 10, 64)
		if err == nil && strconv.FormatUint(n, 10) == e.Name() {
			nums = append(nums, n)
		}
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] > nums[j] })
	for i := keep; i < len(nums); i++ {
		os.RemoveAll(filepath.Join(versions, strconv.FormatUint(nums[i], 10)))
	}
}
