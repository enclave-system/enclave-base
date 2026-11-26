package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

// Sign returns the raw 64-byte Ed25519 signature over the full bundle bytes.
func Sign(priv ed25519.PrivateKey, bundle []byte) []byte {
	return ed25519.Sign(priv, bundle)
}

// Verify checks the signature (before anything is decompressed), the format,
// all paths and all hashes, and returns the manifest.
func Verify(pub ed25519.PublicKey, bundle, sig []byte) (Manifest, error) {
	m, _, err := open(pub, bundle, sig)
	return m, err
}

type payload struct {
	entry FileEntry
	mode  fs.FileMode
	data  []byte
}

// open verifies the bundle and returns its manifest and file contents,
// in manifest order.
func open(pub ed25519.PublicKey, bundle, sig []byte) (Manifest, []payload, error) {
	var zero Manifest
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(pub, bundle, sig) {
		return zero, nil, ErrBadSignature
	}
	gz, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		return zero, nil, fmt.Errorf("%w: gzip: %v", ErrBadFormat, err)
	}
	lr := &io.LimitedReader{R: gz, N: maxStreamSize}
	tr := tar.NewReader(lr)

	hdr, err := tr.Next()
	if err != nil || hdr.Name != ManifestName || hdr.Typeflag != tar.TypeReg {
		return zero, nil, fmt.Errorf("%w: %s must be the first entry", ErrBadFormat, ManifestName)
	}
	if hdr.Size < 0 || hdr.Size > maxManifestSize {
		return zero, nil, fmt.Errorf("%w: manifest too large", ErrBadFormat)
	}
	mb, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
	if err != nil {
		return zero, nil, fmt.Errorf("%w: manifest: %v", ErrBadFormat, err)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(mb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return zero, nil, fmt.Errorf("%w: manifest: %v", ErrBadFormat, err)
	}
	if dec.More() {
		return zero, nil, fmt.Errorf("%w: trailing data in manifest", ErrBadFormat)
	}
	modes, err := m.validate()
	if err != nil {
		return zero, nil, err
	}
	byPath := make(map[string]int, len(m.Files))
	for i, f := range m.Files {
		byPath[f.Path] = i
	}

	out := make([]payload, len(m.Files))
	seen := make([]bool, len(m.Files))
	nseen := 0
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return zero, nil, fmt.Errorf("%w: tar: %v", ErrBadFormat, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return zero, nil, fmt.Errorf("%w: entry %q has type %q", ErrUnsafePath, hdr.Name, hdr.Typeflag)
		}
		rel, ok := strings.CutPrefix(hdr.Name, FilesPrefix)
		if !ok {
			return zero, nil, fmt.Errorf("%w: entry %q outside %s", ErrUnsafePath, hdr.Name, FilesPrefix)
		}
		if err := validatePath(rel); err != nil {
			return zero, nil, err
		}
		i, ok := byPath[rel]
		if !ok {
			return zero, nil, fmt.Errorf("%w: %q not in manifest", ErrBadFormat, rel)
		}
		if seen[i] {
			return zero, nil, fmt.Errorf("%w: duplicate entry %q", ErrBadFormat, rel)
		}
		if hdr.Size < 0 || hdr.Size > MaxTotalSize-total {
			return zero, nil, fmt.Errorf("%w: payload too large", ErrBadFormat)
		}
		total += hdr.Size
		data, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil || int64(len(data)) != hdr.Size {
			return zero, nil, fmt.Errorf("%w: short read of %q", ErrBadFormat, rel)
		}
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != m.Files[i].SHA256 {
			return zero, nil, fmt.Errorf("%w: %q", ErrHashMismatch, rel)
		}
		seen[i] = true
		nseen++
		out[i] = payload{entry: m.Files[i], mode: modes[rel], data: data}
	}
	if nseen != len(m.Files) {
		return zero, nil, fmt.Errorf("%w: manifest lists files missing from archive", ErrBadFormat)
	}
	// Drain so the gzip checksum is verified and trailing garbage is bounded.
	if _, err := io.Copy(io.Discard, lr); err != nil || lr.N <= 0 {
		return zero, nil, fmt.Errorf("%w: trailing data", ErrBadFormat)
	}
	return m, out, nil
}
