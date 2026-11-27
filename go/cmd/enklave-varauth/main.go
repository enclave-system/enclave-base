// Command enklave-varauth creates, unlocks, authenticates and heals the
// encrypted state volume and runs the state service (see packages varauth,
// statefs).
//
//	enklave-varauth repart [systemd-repart args...]   lock platform, create the partition
//	enklave-varauth unlock <var-partition> <esp>      open the volume (provision/heal)
//	enklave-varauth verify                            authenticate, check state, TPM lock
//	enklave-varauth sealed                            PCR 11 must have left the signed phase
//	enklave-varauth state-serve                       the state service (enklave-state.service)
//	enklave-varauth state-exec <writer>               ask the state service to run a writer
//	                                                  defined by the image; stdin is its input
//	enklave-varauth state-read <path>                 print a state file after authenticating it
//	enklave-varauth state-status                      authenticated state version and TPM counter
//	enklave-varauth ek-name                           print the Names of this TPM's
//	                                                  endorsement keys (for a signed
//	                                                  per-device admission)
//	enklave-varauth probe                             (tests) try to read the key after boot
//
// The state volume is mounted read-only. Only the state service writes it:
// it holds the state keys (taken out of /run before any other service
// starts), makes the volume writable in its own mount namespace for one
// commit, runs only writers defined in the verity-protected image, and
// accepts a writer only from the systemd unit the image reserves it for.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
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
		fmt.Fprintln(os.Stderr, "usage: enklave-varauth repart|unlock|verify|sealed|state-serve|state-exec|state-read|state-status|ek-name|probe ...")
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
	case "state-serve":
		if err := serve(c, r); err != nil {
			fail("state service", err)
		}
	case "state-exec":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: enklave-varauth state-exec <writer>   (stdin is handed to the writer)")
			os.Exit(2)
		}
		rep, err := varauth.StateCall(c, varauth.StateRequest{Op: "exec", Writer: os.Args[2], Pause: os.Getenv("ENKLAVE_STATE_PAUSE")}, os.Stdin)
		if err != nil {
			fail("state-exec", err)
		}
		fmt.Fprintf(os.Stderr, "enklave-state: committed state version %d\n", rep.Version)
	case "state-read":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: enklave-varauth state-read <path below data/>")
			os.Exit(2)
		}
		rep, err := varauth.StateCall(c, varauth.StateRequest{Op: "read", Path: os.Args[2]}, nil)
		if err != nil {
			fail("state-read", err)
		}
		os.Stdout.Write(rep.Data)
	case "state-status":
		rep, err := varauth.StateCall(c, varauth.StateRequest{Op: "status"}, nil)
		if err != nil {
			fail("state-status", err)
		}
		fmt.Printf("version %d counter %d\n", rep.Version, rep.Counter)
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

const mntBase = syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC

// remount makes the state volume writable or read-only in this process's
// mount namespace. It refuses to run in the mount namespace of PID 1
// (enklave-state.service has PrivateMounts=yes): the read-only mount
// everyone else sees must never change.
func remount(root string) func(rw bool) error {
	return func(rw bool) error {
		self, err := os.Readlink("/proc/self/ns/mnt")
		if err != nil {
			return err
		}
		init1, err := os.Readlink("/proc/1/ns/mnt")
		if err != nil {
			return err
		}
		if self == init1 {
			return errors.New("the state service is not in a private mount namespace")
		}
		flags := uintptr(syscall.MS_REMOUNT | mntBase)
		if !rw {
			syscall.Sync()
			flags |= syscall.MS_RDONLY
		}
		if err := syscall.Mount("", root, "", flags, ""); err != nil {
			return fmt.Errorf("remounting %s (rw=%v) in the private namespace: %w", root, rw, err)
		}
		return nil
	}
}

// serve runs the state service: take the keys out of /run, listen, tell
// systemd that the keys are gone (Type=notify), serve.
func serve(c varauth.Config, r execRunner) error {
	s, err := varauth.NewStateServer(c, r)
	if err != nil {
		return err
	}
	s.Remount = remount(c.StateRoot)
	s.Pause = func(p string) { // test profile only (checked by the server)
		msg := "enklave-state: TEST PAUSE at " + p + "\n"
		os.Stderr.WriteString(msg)
		if f, err := os.OpenFile("/dev/ttyS0", os.O_WRONLY, 0); err == nil {
			f.WriteString(msg)
			f.Close()
		}
		time.Sleep(time.Hour)
	}
	os.Remove(c.StateSocket())
	old := syscall.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: c.StateSocket(), Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return err
	}
	if sock := os.Getenv("NOTIFY_SOCKET"); sock != "" {
		if conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"}); err == nil {
			conn.Write([]byte("READY=1")) //nolint:errcheck
			conn.Close()
		}
	}
	fmt.Fprintf(os.Stderr, "enklave-state: serving %s (%d writer(s) defined by the image)\n", c.StateSocket(), len(s.Writers))
	return s.Serve(l)
}
