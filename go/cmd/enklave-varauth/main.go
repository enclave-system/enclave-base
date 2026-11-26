// Command enklave-varauth authenticates the encrypted /var volume against a
// write-once TPM NV index (see package varauth).
//
//	enklave-varauth repart [systemd-repart args...]   create /var, record first boot
//	enklave-varauth verify                            provision (first boot) / verify
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"enklave.local/base/internal/varauth"
)

type execRunner struct{}

func (execRunner) Run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: enklave-varauth repart [args...] | verify")
		os.Exit(2)
	}
	c := varauth.DefaultConfig()
	switch os.Args[1] {
	case "repart":
		if err := varauth.Repart(c, execRunner{}, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "enklave-varauth: creating /var FAILED: %v\n", err)
			os.Exit(1)
		}
	case "verify":
		msg, err := varauth.Verify(c, execRunner{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "enklave-varauth: /var AUTHENTICATION FAILED, refusing to mount /var: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "enklave-varauth: %s\n", msg)
	default:
		fmt.Fprintf(os.Stderr, "enklave-varauth: unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
