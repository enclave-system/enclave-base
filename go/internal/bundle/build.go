package bundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type buildFile struct {
	entry FileEntry
	data  []byte
}

// Build writes a deterministic tar.gz bundle of the regular files in srcDir.
func Build(srcDir, role string, version uint64, now time.Time, w io.Writer) error {
	if role == "" {
		return fmt.Errorf("%w: empty role", ErrBadFormat)
	}
	var files []buildFile
	var total int64
	err := filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: not a regular file", p)
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if err := validatePath(rel); err != nil {
			return err
		}
		perm := info.Mode().Perm()
		if perm&0o022 != 0 {
			return fmt.Errorf("%s: group/world-writable mode %04o", p, perm)
		}
		if len(files) >= MaxEntries {
			return fmt.Errorf("%w: too many files", ErrBadFormat)
		}
		total += info.Size()
		if total > MaxTotalSize {
			return fmt.Errorf("%w: payload too large", ErrBadFormat)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		h := sha256.Sum256(data)
		files = append(files, buildFile{
			entry: FileEntry{Path: rel, SHA256: hex.EncodeToString(h[:]), Mode: fmt.Sprintf("%04o", perm)},
			data:  data,
		})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].entry.Path < files[j].entry.Path })

	m := Manifest{
		Format:  FormatVersion,
		Role:    role,
		Version: version,
		Created: now.UTC().Format(time.RFC3339),
		Files:   make([]FileEntry, len(files)),
	}
	for i, f := range files {
		m.Files[i] = f.entry
	}
	mb, err := json.Marshal(m)
	if err != nil {
		return err
	}

	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	mtime := now.UTC().Truncate(time.Second)
	put := func(name string, mode int64, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: int64(len(data)),
			ModTime: mtime, Format: tar.FormatUSTAR,
		}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := put(ManifestName, 0o644, mb); err != nil {
		return err
	}
	for _, f := range files {
		mode, _ := parseMode(f.entry.Mode)
		if err := put(FilesPrefix+f.entry.Path, int64(mode), f.data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
