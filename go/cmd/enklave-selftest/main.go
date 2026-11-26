// Command enklave-selftest runs the in-image security self-checks and
// emits one JSON line per check.
package main

import (
	"os"

	"enklave.local/base/internal/selftest"
)

func main() {
	os.Exit(selftest.Main(os.Args[0], os.Args[1:], selftest.ExecRunner{}, selftest.DefaultPowerOff, os.Stderr))
}
