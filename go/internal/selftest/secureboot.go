package selftest

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// PowerOff powers the machine off (injectable for tests).
type PowerOff func(Runner)

// DefaultPowerOff tries systemctl first, then the reboot syscall, and never
// returns: it keeps retrying so a machine without Secure Boot cannot go on
// booting because the guard exited.
func DefaultPowerOff(r Runner) {
	powerOff(r, func() error { return syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF) },
		time.Sleep, os.Stderr, 10*time.Second, 5*time.Second, 0)
}

// powerOff runs systemctl (bounded by cmdTimeout), then retries sys every
// retryEvery. maxRetries == 0 means forever; tests use a bound.
func powerOff(r Runner, sys func() error, sleep func(time.Duration), log io.Writer,
	cmdTimeout, retryEvery time.Duration, maxRetries int) {
	type res struct{ err error }
	ch := make(chan res, 1)
	go func() {
		_, err := r.Run("systemctl", "poweroff", "--force", "--force")
		ch <- res{err}
	}()
	select {
	case x := <-ch:
		if x.err == nil {
			return
		}
		fmt.Fprintf(log, "enklave: systemctl poweroff failed: %v\n", x.err)
	case <-time.After(cmdTimeout):
		fmt.Fprintln(log, "enklave: systemctl poweroff timed out")
	}
	for i := 0; maxRetries == 0 || i < maxRetries; i++ {
		if err := sys(); err != nil {
			fmt.Fprintf(log, "enklave: reboot(POWER_OFF) failed: %v\n", err)
		}
		sleep(retryEvery)
	}
}

func requireSecureBoot(args []string, r Runner, off PowerOff, stderr io.Writer) int {
	fs := flag.NewFlagSet("require-secureboot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "/", "filesystem root")
	logOnly := fs.Bool("log-only", false, "log and exit 1 instead of powering off")
	perr := fs.Parse(args)
	usage := perr != nil || fs.NArg() != 0
	if usage {
		// Fail closed: a usage error must never skip the guard.
		fmt.Fprintln(stderr, "usage: enklave-selftest require-secureboot [--root /] [--log-only]")
	}
	_, err := efiBool(*root, "SecureBoot", 1)
	switch {
	case err == nil && usage:
		return 2
	case err == nil:
		return 0
	}
	if *logOnly {
		fmt.Fprintf(stderr, "enklave: Secure Boot not enabled (%v); log-only, not powering off\n", err)
	} else {
		fmt.Fprintf(stderr, "enklave: Secure Boot not enabled (%v); powering off\n", err)
		off(r)
	}
	if usage {
		return 2
	}
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
