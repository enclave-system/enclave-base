// Command enklave-varauth creates, unlocks, authenticates and heals the
// encrypted state volume and commits state changes (see packages varauth,
// statefs).
//
//	enklave-varauth repart [systemd-repart args...]   lock platform, create the partition
//	enklave-varauth unlock <var-partition> <esp>      open the volume (provision/heal)
//	enklave-varauth verify                            authenticate, check state, TPM lock
//	enklave-varauth sealed                            PCR 11 must have left the signed phase
//	enklave-varauth state-exec -- CMD [ARGS...]       run CMD on a staged copy of the
//	                                                  state ($ENKLAVE_STATE_DIR, "{}"
//	                                                  in ARGS) and commit atomically
//	enklave-varauth ek-name                           print the Names of this TPM's
//	                                                  endorsement keys (for the signed
//	                                                  EK allowlist of a release)
//	enklave-varauth probe                             (tests) try to read the key after boot
//
// The state volume is mounted read-only. state-exec re-executes itself in a
// private mount namespace and makes the volume writable only there, so no
// other process (root included) can write the state through the mount.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"enklave.local/base/internal/varauth"
)

func fail(what string, err error) {
	fmt.Fprintf(os.Stderr, "enklave-varauth: %s FAILED: %v\n", what, err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: enklave-varauth repart|unlock|verify|sealed|state-exec|ek-name|probe ...")
		os.Exit(2)
	}
	c := varauth.DefaultConfig()
	r := execRunner{}
	switch os.Args[1] {
	case "repart":
		if err := varauth.Repart(c, r, os.Args[2:]); err != nil {
			fail("creating the state partition (refusing to mount /var/lib/enklave)", err)
		}
	case "unlock":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: enklave-varauth unlock <var-partition> <esp>")
			os.Exit(2)
		}
		msg, err := varauth.Unlock(c, r, os.Args[2], os.Args[3])
		if err != nil {
			fail("UNLOCK (refusing to mount /var/lib/enklave)", err)
		}
		fmt.Fprintf(os.Stderr, "enklave-varauth: %s\n", msg)
	case "verify":
		msg, err := varauth.Verify(c, r)
		if err != nil {
			fail("AUTHENTICATION (refusing to mount /var/lib/enklave)", err)
		}
		fmt.Fprintf(os.Stderr, "enklave-varauth: %s\n", msg)
		// One status line on the serial port, also in production (which has
		// no serial console): evidence of a successful unlock for VM tests,
		// and the runtime-visible marker of a development build.
		dev := ""
		if id, err := varauth.LoadIdentity(c); err != nil || id.Release.DevKeys {
			dev = " [DEV KEYS: development build, never ship]"
		}
		if f, err := os.OpenFile("/dev/ttyS0", os.O_WRONLY|syscall.O_NOCTTY, 0); err == nil {
			fmt.Fprintf(f, "enklave: state volume unlocked and verified%s\n", dev)
			if u, err := os.ReadFile(c.EFIUpdatesFile()); err == nil {
				fmt.Fprintf(f, "enklave: Secure Boot updates: %s", u)
			}
			f.Close()
		}
	case "sealed":
		msg, err := varauth.Sealed(c, r, "/run/systemd/tpm2-pcr-signature.json")
		if err != nil {
			fail("PCR 11 SEAL CHECK", err)
		}
		fmt.Fprintf(os.Stderr, "enklave-varauth: %s\n", msg)
	case "state-exec":
		args := os.Args[2:]
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: enklave-varauth state-exec -- CMD [ARGS...]")
			os.Exit(2)
		}
		if os.Getenv(nsEnv) != "1" {
			os.Exit(reexecPrivate())
		}
		os.Exit(stateExec(c, r, args))
	case "ek-name":
		names, err := varauth.EKNames(c, r)
		if err != nil {
			fail("ek-name", err)
		}
		for _, n := range names {
			fmt.Println(n)
		}
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

const (
	nsEnv   = "ENKLAVE_STATE_NS"
	mntBase = syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC
)

// reexecPrivate runs this command again in a new mount namespace (with
// private propagation, set by the Go runtime for CLONE_NEWNS).
func reexecPrivate() int {
	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
	cmd.Env = append(os.Environ(), nsEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS}
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fail("state-exec (private mount namespace)", err)
	}
	return 0
}

// writableState makes the state volume writable in this (private) mount
// namespace only. It refuses to run in the mount namespace of PID 1: the
// read-only mount everyone else sees must never change.
func writableState(root string) (func(), error) {
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return nil, err
	}
	init, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		return nil, err
	}
	if self == init {
		return nil, errors.New("not in a private mount namespace")
	}
	if err := syscall.Mount("", root, "", syscall.MS_REMOUNT|mntBase, ""); err != nil {
		return nil, fmt.Errorf("making %s writable in the private namespace: %w", root, err)
	}
	return func() {
		syscall.Sync()
		if err := syscall.Mount("", root, "", syscall.MS_REMOUNT|syscall.MS_RDONLY|mntBase, ""); err != nil {
			fmt.Fprintf(os.Stderr, "enklave-state: warning: could not return %s to read-only: %v\n", root, err)
		}
	}, nil
}

// stateExec runs args against a staged copy of the state and commits it.
func stateExec(c varauth.Config, r execRunner, args []string) int {
	restore, err := writableState(c.StateRoot)
	if err != nil {
		fail("state-exec", err)
	}
	defer restore()
	work, err := os.MkdirTemp(c.RunDir, "state-exec-")
	if err != nil {
		restore()
		fail("state-exec", err)
	}
	defer os.RemoveAll(work)
	c.Work = work
	var pause func(string)
	if _, err := os.Stat(c.TestMarker); err == nil {
		if at := os.Getenv("ENKLAVE_STATE_PAUSE"); at != "" { // test profile only
			pause = func(p string) {
				if p == at {
					msg := "enklave-state: TEST PAUSE at " + p + "\n"
					os.Stderr.WriteString(msg)
					if f, err := os.OpenFile("/dev/ttyS0", os.O_WRONLY, 0); err == nil {
						f.WriteString(msg)
						f.Close()
					}
					time.Sleep(time.Hour)
				}
			}
		}
	}
	s, err := varauth.OpenStore(c, r, pause)
	if err != nil {
		restore()
		os.RemoveAll(work)
		fail("state-exec", err)
	}
	v, err := s.Exec(func(staging string) error {
		a := make([]string, len(args))
		for i, x := range args {
			a[i] = strings.ReplaceAll(x, "{}", staging)
		}
		cmd := exec.Command(a[0], a[1:]...)
		cmd.Env = append(os.Environ(), "ENKLAVE_STATE_DIR="+staging)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	})
	if err != nil {
		restore()
		os.RemoveAll(work)
		fail("state-exec", err)
	}
	fmt.Fprintf(os.Stderr, "enklave-state: committed state version %d\n", v)
	return 0
}
