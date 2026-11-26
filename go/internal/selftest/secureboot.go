package selftest

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// PowerOff powers the machine off (injectable for tests).
type PowerOff func(Runner)

// DefaultPowerOff tries systemctl first, then the reboot syscall.
func DefaultPowerOff(r Runner) {
	powerOff(r, func() error { return syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF) })
}

func powerOff(r Runner, sys func() error) {
	if _, err := r.Run("systemctl", "poweroff", "--force", "--force"); err != nil {
		_ = sys()
	}
}

func requireSecureBoot(args []string, r Runner, off PowerOff, stderr io.Writer) int {
	fs := flag.NewFlagSet("require-secureboot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "/", "filesystem root")
	logOnly := fs.Bool("log-only", false, "log and exit 1 instead of powering off")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: enklave-selftest require-secureboot [--root /] [--log-only]")
		return 2
	}
	_, err := efiBool(*root, "SecureBoot", 1)
	if err == nil {
		return 0
	}
	if *logOnly {
		fmt.Fprintf(stderr, "enklave: Secure Boot not enabled (%v); log-only, not powering off\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "enklave: Secure Boot not enabled (%v); powering off\n", err)
	off(r)
	return 1
}

// Main is the testable entry point. argv0 is os.Args[0]; args exclude it.
func Main(argv0 string, args []string, r Runner, off PowerOff, stderr io.Writer) int {
	if filepath.Base(argv0) == "require-secureboot" {
		return requireSecureBoot(args, r, off, stderr)
	}
	if len(args) > 0 && args[0] == "require-secureboot" {
		return requireSecureBoot(args[1:], r, off, stderr)
	}
	fs := flag.NewFlagSet("enklave-selftest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "output file or device (required)")
	root := fs.String("root", "/", "filesystem root")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: enklave-selftest --out PATH [--root /] | require-secureboot [--root /] [--log-only]")
		return 2
	}
	w, err := openOut(*out)
	if err != nil {
		fmt.Fprintln(stderr, "enklave-selftest:", err)
		return 1
	}
	defer w.Close()
	if WriteResults(w, RunChecks(*root, r)) {
		return 0
	}
	return 1
}

// openOut opens without truncating (it may be a device such as /dev/ttyS0);
// it creates the file only if the path does not exist.
func openOut(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil && os.IsNotExist(err) && !strings.HasPrefix(path, "/dev/") {
		return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	}
	return f, err
}
