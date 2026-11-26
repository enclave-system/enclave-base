// Package bundle implements signed, rollback-protected, atomically applied
// configuration bundles.
package bundle

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"
)

const (
	// FormatVersion is the only bundle format version understood.
	FormatVersion = 1
	// ManifestName is the name of the mandatory first tar entry.
	ManifestName = "manifest.json"
	// FilesPrefix is the tar directory holding the payload files.
	FilesPrefix = "files/"

	// MaxTotalSize caps the sum of all payload file sizes.
	MaxTotalSize = 64 << 20
	// MaxEntries caps the number of payload files.
	MaxEntries = 4096

	maxManifestSize = 4 << 20
	maxPathLen      = 1024
	// Upper bound for the uncompressed tar stream (payload + manifest + headers/padding).
	maxStreamSize = MaxTotalSize + maxManifestSize + (MaxEntries+2)*2048
)

var (
	ErrBadSignature = errors.New("bundle: bad signature")
	ErrBadFormat    = errors.New("bundle: bad format")
	ErrWrongRole    = errors.New("bundle: wrong role")
	ErrRollback     = errors.New("bundle: version is not newer than installed version")
	ErrUnsafePath   = errors.New("bundle: unsafe path or entry type")
	ErrHashMismatch = errors.New("bundle: file hash mismatch")
)

// Manifest describes a bundle. It is the first entry of the tar archive.
type Manifest struct {
	Format  int         `json:"format"`
	Role    string      `json:"role"`
	Version uint64      `json:"version"`
	Created string      `json:"created"` // RFC3339 UTC
	Files   []FileEntry `json:"files"`
}

// FileEntry describes one payload file stored as files/<Path>.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"` // octal, e.g. "0640"
}

// validatePath accepts only clean, relative, slash-separated paths.
func validatePath(p string) error {
	if p == "" || len(p) > maxPathLen || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
		return fmt.Errorf("%w: %q", ErrUnsafePath, p)
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." {
			return fmt.Errorf("%w: %q", ErrUnsafePath, p)
		}
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %q", ErrUnsafePath, p)
		}
	}
	return nil
}

// parseMode accepts octal permission strings without setuid/setgid/sticky
// bits and without group/world write.
func parseMode(s string) (fs.FileMode, error) {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil || len(s) > 4 || v&^0o777 != 0 || v&0o022 != 0 {
		return 0, fmt.Errorf("%w: mode %q", ErrBadFormat, s)
	}
	return fs.FileMode(v), nil
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validate checks a parsed manifest and returns the parsed modes by path.
func (m *Manifest) validate() (map[string]fs.FileMode, error) {
	if m.Format != FormatVersion {
		return nil, fmt.Errorf("%w: unsupported format %d", ErrBadFormat, m.Format)
	}
	if m.Role == "" {
		return nil, fmt.Errorf("%w: empty role", ErrBadFormat)
	}
	if _, err := time.Parse(time.RFC3339, m.Created); err != nil {
		return nil, fmt.Errorf("%w: created: %v", ErrBadFormat, err)
	}
	if len(m.Files) > MaxEntries {
		return nil, fmt.Errorf("%w: too many files", ErrBadFormat)
	}
	modes := make(map[string]fs.FileMode, len(m.Files))
	for _, f := range m.Files {
		if err := validatePath(f.Path); err != nil {
			return nil, err
		}
		if _, dup := modes[f.Path]; dup {
			return nil, fmt.Errorf("%w: duplicate path %q", ErrBadFormat, f.Path)
		}
		mode, err := parseMode(f.Mode)
		if err != nil {
			return nil, err
		}
		if !validHash(f.SHA256) {
			return nil, fmt.Errorf("%w: bad sha256 for %q", ErrBadFormat, f.Path)
		}
		modes[f.Path] = mode
	}
	// A path must not be both a file and a directory of another file.
	for p := range modes {
		for i := 0; i < len(p); i++ {
			if p[i] == '/' {
				if _, clash := modes[p[:i]]; clash {
					return nil, fmt.Errorf("%w: %q is both file and directory", ErrBadFormat, p[:i])
				}
			}
		}
	}
	return modes, nil
}
