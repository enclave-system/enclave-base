// Command enklave-cfg builds, signs, verifies and applies signed
// configuration bundles.
package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"enklave.local/base/internal/bundle"
)

const (
	defaultRoleFile = "/usr/lib/enklave/role"
	defaultPubFile  = "/usr/share/enklave/keys/config-signing.pub"
)

func main() { os.Exit(run(os.Args[1:])) }

func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, bundle.ErrBadSignature):
		return 2
	case errors.Is(err, bundle.ErrWrongRole):
		return 3
	case errors.Is(err, bundle.ErrRollback):
		return 4
	case errors.Is(err, bundle.ErrBadFormat), errors.Is(err, bundle.ErrUnsafePath), errors.Is(err, bundle.ErrHashMismatch):
		return 5
	}
	return 1
}

func run(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: enklave-cfg build|sign|verify|apply [flags]")
		return 1
	}
	var err error
	switch args[0] {
	case "build":
		err = cmdBuild(args[1:])
	case "sign":
		err = cmdSign(args[1:])
	case "verify":
		err = cmdVerify(args[1:])
	case "apply":
		err = cmdApply(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "enklave-cfg: unknown command %q\n", args[0])
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "enklave-cfg:", err)
	}
	return exitCode(err)
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	return fs
}

func cmdBuild(args []string) error {
	fs := newFlags("build")
	role := fs.String("role", "", "target role")
	version := fs.Uint64("version", 0, "bundle version")
	dir := fs.String("dir", "", "source directory")
	out := fs.String("out", "", "output bundle file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *role == "" || *dir == "" || *out == "" || *version == 0 {
		return errors.New("build: --role, --version (>0), --dir and --out are required")
	}
	var buf bytes.Buffer
	if err := bundle.Build(*dir, *role, *version, time.Now(), &buf); err != nil {
		return err
	}
	return os.WriteFile(*out, buf.Bytes(), 0o644)
}

func cmdSign(args []string) error {
	fs := newFlags("sign")
	keyFile := fs.String("key", "", "private key file (64 raw bytes)")
	in := fs.String("in", "", "bundle file")
	out := fs.String("out", "", "signature output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *in == "" || *out == "" {
		return errors.New("sign: --key, --in and --out are required")
	}
	kb, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	if len(kb) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key must be %d raw bytes, got %d", ed25519.PrivateKeySize, len(kb))
	}
	b, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, bundle.Sign(ed25519.PrivateKey(kb), b), 0o644)
}

func readPub(path string) (ed25519.PublicKey, error) {
	pb, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(pb) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d raw bytes, got %d", ed25519.PublicKeySize, len(pb))
	}
	return ed25519.PublicKey(pb), nil
}

func readBundle(fs *flag.FlagSet) ([]byte, []byte, error) {
	if fs.NArg() != 2 {
		return nil, nil, errors.New("expected arguments: <bundle> <bundle.sig>")
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return nil, nil, err
	}
	sig, err := os.ReadFile(fs.Arg(1))
	return b, sig, err
}

func cmdVerify(args []string) error {
	fs := newFlags("verify")
	pubFile := fs.String("pub", defaultPubFile, "public key file (32 raw bytes)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, err := readPub(*pubFile)
	if err != nil {
		return err
	}
	b, sig, err := readBundle(fs)
	if err != nil {
		return err
	}
	m, err := bundle.Verify(pub, b, sig)
	if err != nil {
		return err
	}
	fmt.Printf("ok role=%s version=%d files=%d\n", m.Role, m.Version, len(m.Files))
	return nil
}

func cmdApply(args []string) error {
	fs := newFlags("apply")
	pubFile := fs.String("pub", defaultPubFile, "public key file (32 raw bytes)")
	root := fs.String("root", "", "configuration root directory")
	role := fs.String("role", "", "machine role (default: contents of "+defaultRoleFile+")")
	keep := fs.Int("keep", 3, "versions to keep")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *root == "" {
		return errors.New("apply: --root is required")
	}
	if *role == "" {
		rb, err := os.ReadFile(defaultRoleFile)
		if err != nil {
			return fmt.Errorf("no --role given and %w", err)
		}
		*role = strings.TrimSpace(string(rb))
	}
	pub, err := readPub(*pubFile)
	if err != nil {
		return err
	}
	b, sig, err := readBundle(fs)
	if err != nil {
		return err
	}
	v, err := bundle.Apply(bundle.ApplyOptions{Root: *root, Role: *role, Pub: pub, Keep: *keep}, b, sig)
	if err != nil {
		return err
	}
	fmt.Printf("applied version %d\n", v)
	return nil
}
