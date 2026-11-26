// Command enklave-varauth creates, unlocks and authenticates the encrypted
// /var (see package varauth).
//
//	enklave-varauth repart [systemd-repart args...]   create /var partition, record first boot
//	enklave-varauth unlock <var-partition> <esp>      open /var as /dev/mapper/var
//	enklave-varauth verify                            authenticate, anti-rollback, lock TPM
//	enklave-varauth probe                             (tests) try to read the key after boot
package main

import (
	"fmt"
	"os"

	"enklave.local/base/internal/varauth"
)

func fail(what string, err error) {
	fmt.Fprintf(os.Stderr, "enklave-varauth: %s FAILED, refusing to mount /var: %v\n", what, err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: enklave-varauth repart [args...] | unlock <dev> <esp> | verify | probe")
		os.Exit(2)
	}
	c := varauth.DefaultConfig()
	r := execRunner{}
	switch os.Args[1] {
	case "repart":
		if err := varauth.Repart(c, r, os.Args[2:]); err != nil {
			fail("creating /var", err)
		}
	case "unlock":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: enklave-varauth unlock <var-partition> <esp>")
			os.Exit(2)
		}
		msg, err := varauth.Unlock(c, r, os.Args[2], os.Args[3])
		if err != nil {
			fail("/var UNLOCK", err)
		}
		fmt.Fprintf(os.Stderr, "enklave-varauth: %s\n", msg)
	case "verify":
		msg, err := varauth.Verify(c, r)
		if err != nil {
			fail("/var AUTHENTICATION", err)
		}
		fmt.Fprintf(os.Stderr, "enklave-varauth: %s\n", msg)
	case "probe":
		if err := varauth.Probe(c, r); err != nil {
			fmt.Printf("refused: %v\n", err)
			return
		}
		fmt.Println("KEY READABLE")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "enklave-varauth: unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
