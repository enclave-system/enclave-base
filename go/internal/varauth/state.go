package varauth

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"enklave.local/base/internal/bundle"
	"enklave.local/base/internal/statefs"
)

// The state service (B8, G4) is the only writer of the state volume and the
// only holder of the state keys at runtime.
//
//   - The unlock step leaves the derived keys in /run/enklave/state.key for
//     the verify step and this service. The service reads and deletes the
//     file when it starts, ordered before local-fs.target, so no other
//     service ever sees it.
//   - A commit is not "run this command": the caller names a WRITER, and the
//     command of a writer is fixed in the verity-protected image
//     (/usr/lib/enklave/state-writers.d/<id>.json).
//   - What a commit can put into the state does not depend on who triggers
//     it. Each writer declares its input:
//     "none": the writer gets no input from the caller at all.
//     "signed-bundle": the caller's input must be an enklave bundle signed
//     with the config-signing key, for this role, with a version higher
//     than the last one this writer accepted. The service verifies all
//     of that before it runs the writer, and records the accepted
//     version inside the authenticated state.
//     A writer without such a declaration is refused (the test profile
//     alone may declare "unverified").
//   - The caller is authenticated with SO_PEERCRED (uid 0) and SO_PEERPIDFD
//     and must be in the cgroup /system.slice/<unit> of the unit the writer
//     names. This keeps ordinary services apart. It is not a boundary
//     against root: a root process can move itself into that cgroup. Such a
//     process can trigger a writer; it cannot make the service accept
//     content that is not signed, not for this role, or not newer.
//   - Reads go through the service too: every read authenticates the
//     manifest (MAC), its version (TPM counter) and the file's hash.

// Writer input kinds.
const (
	InputNone       = "none"
	InputBundle     = "signed-bundle"
	InputUnverified = "unverified" // test profile only
)

// maxInput bounds a signed input (signature + bundle).
const maxInput = 64 << 20

// Writer is one entry of the image's writer allowlist.
type Writer struct {
	ID    string   `json:"-"`
	Unit  string   `json:"unit"`  // systemd unit the caller must run in
	Exec  []string `json:"exec"`  // command; "{}" and $ENKLAVE_STATE_DIR are the staged copy
	Input string   `json:"input"` // none, signed-bundle (unverified: test profile only)
}

// LoadWriters reads the writer allowlist. A missing directory means that
// this image has no writer. test admits writers with unverified input.
func LoadWriters(dir string, test bool) (map[string]Writer, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	out := map[string]Writer{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var w Writer
		if err := json.Unmarshal(b, &w); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		w.ID = strings.TrimSuffix(filepath.Base(f), ".json")
		if !strings.HasSuffix(w.Unit, ".service") || strings.ContainsAny(w.Unit, "/ ") || len(w.Exec) == 0 || !filepath.IsAbs(w.Exec[0]) {
			return nil, fmt.Errorf("%s: a writer needs a .service unit and an absolute command", f)
		}
		if strings.ContainsAny(w.ID, "/. ") || w.ID == "" {
			return nil, fmt.Errorf("%s: bad writer name", f)
		}
		switch {
		case w.Input == InputNone || w.Input == InputBundle:
		case w.Input == InputUnverified && test:
		default:
			return nil, fmt.Errorf("%s: a writer must declare its input as %q or %q (got %q): input that the service cannot verify is not accepted", f, InputNone, InputBundle, w.Input)
		}
		out[w.ID] = w
	}
	// A bundle is bound to the role and to a version, not to a writer. With
	// two signed-bundle writers, a bundle signed for one could be handed to
	// the other. An image therefore has at most one (the test profile adds
	// its probe writer next to the role's).
	n := 0
	for _, w := range out {
		if w.Input == InputBundle {
			n++
		}
	}
	if n > 1 && !test {
		return nil, fmt.Errorf("%s: %d writers take signed bundles; an image may define one (a bundle is not bound to a writer)", dir, n)
	}
	return out, nil
}

// StateRequest is one request to the state service (one JSON line).
type StateRequest struct {
	Op     string `json:"op"`               // exec, read, status
	Writer string `json:"writer,omitempty"` // exec
	Path   string `json:"path,omitempty"`   // read
	Pause  string `json:"pause,omitempty"`  // exec, test profile only
}

// StateReply is the answer (one JSON line).
type StateReply struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Version uint64 `json:"version"`
	Counter uint64 `json:"counter"`
	Data    []byte `json:"data,omitempty"`
}

// StateServer serves the state socket.
type StateServer struct {
	C       Config
	R       Runner
	Writers map[string]Writer
	// Remount makes the state volume writable (true) or read-only again in
	// the service's private mount namespace.
	Remount func(rw bool) error
	// Pause is called at named commit phases (test profile only).
	Pause func(phase string)

	keys StateKeys
	test bool
	role string
	mu   sync.Mutex
}

// NewStateServer takes the state keys out of /run (the file is deleted) and
// loads the writer allowlist.
func NewStateServer(c Config, r Runner) (*StateServer, error) {
	keys, err := LoadStateKeys(c)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(c.StateKeyFile()); err != nil {
		return nil, err
	}
	id, err := LoadIdentity(c)
	if err != nil {
		return nil, err
	}
	w, err := LoadWriters(c.WritersDir, id.Profile == "test")
	if err != nil {
		return nil, err
	}
	return &StateServer{C: c, R: r, Writers: w, keys: keys, test: id.Profile == "test", role: id.Role}, nil
}

func (s *StateServer) store(pause func(string)) (*statefs.Store, func(), error) {
	work, err := os.MkdirTemp(s.C.RunDir, "state-")
	if err != nil {
		return nil, nil, err
	}
	c := s.C
	c.Work = work
	st, err := openStore(c, s.R, s.keys, pause)
	if err != nil {
		os.RemoveAll(work)
		return nil, nil, err
	}
	return st, func() { os.RemoveAll(work) }, nil
}

// versionFile holds the last input version a writer accepted. It lives in
// the state itself, so it is covered by the manifest MAC and the TPM counter.
func versionFile(staging, writer string) string {
	return filepath.Join(staging, ".input-version-"+writer)
}

// verifiedInput reads the caller's input for a signed-bundle writer and
// verifies it: 64-byte Ed25519 signature followed by the bundle, signed with
// the config-signing key of the image, for this role.
func (s *StateServer) verifiedInput(stdin *os.File) (sig, b []byte, m bundle.Manifest, err error) {
	if stdin == nil {
		return nil, nil, m, errors.New("this writer needs a signed bundle as input")
	}
	in, err := io.ReadAll(io.LimitReader(stdin, maxInput+1))
	if err != nil {
		return nil, nil, m, err
	}
	if len(in) > maxInput || len(in) <= ed25519.SignatureSize {
		return nil, nil, m, errors.New("input is not a signed bundle (signature followed by the bundle)")
	}
	pub, err := os.ReadFile(s.C.ConfigPub)
	if err != nil {
		return nil, nil, m, err
	}
	sig, b = in[:ed25519.SignatureSize], in[ed25519.SignatureSize:]
	if m, err = bundle.Verify(ed25519.PublicKey(pub), b, sig); err != nil {
		return nil, nil, m, fmt.Errorf("input refused: %w", err)
	}
	if m.Role != s.role {
		return nil, nil, m, fmt.Errorf("input refused: bundle is for role %q, this is %q", m.Role, s.role)
	}
	return sig, b, m, nil
}

// Handle serves one request. cgroup is the cgroup path of the authenticated
// caller; stdin is the caller's input for a writer (may be nil).
func (s *StateServer) Handle(req StateRequest, cgroup string, stdin *os.File) StateReply {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(err error) StateReply { return StateReply{Error: err.Error()} }
	switch req.Op {
	case "status", "read":
		st, done, err := s.store(nil)
		if err != nil {
			return fail(err)
		}
		defer done()
		v, c, err := st.Status()
		if err != nil {
			return fail(err)
		}
		rep := StateReply{OK: true, Version: v, Counter: c}
		if req.Op == "read" {
			if rep.Data, err = st.Read(req.Path); err != nil {
				return fail(err)
			}
		}
		return rep
	case "exec":
		w, ok := s.Writers[req.Writer]
		if !ok {
			return fail(fmt.Errorf("unknown state writer %q: writers are defined by the image only", req.Writer))
		}
		if cgroup != "/system.slice/"+w.Unit {
			return fail(fmt.Errorf("caller in cgroup %q is not authorized for state writer %q (reserved for /system.slice/%s)", cgroup, w.ID, w.Unit))
		}
		// G4: what the writer may consume is decided here, before anything runs
		var sig, in []byte
		var m bundle.Manifest
		switch w.Input {
		case InputNone:
			stdin = nil
		case InputBundle:
			var err error
			if sig, in, m, err = s.verifiedInput(stdin); err != nil {
				return fail(err)
			}
		case InputUnverified:
			if !s.test {
				return fail(errors.New("unverified writer input outside the test profile"))
			}
		default:
			return fail(fmt.Errorf("writer %q declares no verifiable input", w.ID))
		}
		var pause func(string)
		if s.test && req.Pause != "" && s.Pause != nil {
			pause = func(p string) {
				if p == req.Pause {
					s.Pause(p)
				}
			}
		}
		st, done, err := s.store(pause)
		if err != nil {
			return fail(err)
		}
		defer done()
		if s.Remount != nil {
			if err := s.Remount(true); err != nil {
				return fail(err)
			}
			defer s.Remount(false) //nolint:errcheck
		}
		v, err := st.Exec(func(staging string) error {
			a := make([]string, len(w.Exec))
			for i, x := range w.Exec {
				a[i] = strings.ReplaceAll(x, "{}", staging)
			}
			cmd := exec.Command(a[0], a[1:]...)
			cmd.Env = append(os.Environ(), "ENKLAVE_STATE_DIR="+staging)
			cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
			if w.Input != InputBundle {
				if stdin != nil {
					cmd.Stdin = stdin
				}
				return cmd.Run()
			}
			// the version must go up; the last one is read from the verified copy
			vf := versionFile(staging, w.ID)
			var last uint64
			if b, err := os.ReadFile(vf); err == nil {
				if last, err = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err != nil {
					return fmt.Errorf("recorded input version of writer %q: %w", w.ID, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if m.Version <= last {
				return fmt.Errorf("input refused: bundle version %d is not newer than the accepted version %d", m.Version, last)
			}
			dir, err := os.MkdirTemp(s.C.RunDir, "input-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(dir)
			for name, data := range map[string][]byte{"bundle": in, "bundle.sig": sig} {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
					return err
				}
			}
			cmd.Env = append(cmd.Env, "ENKLAVE_INPUT_BUNDLE="+filepath.Join(dir, "bundle"), "ENKLAVE_INPUT_SIG="+filepath.Join(dir, "bundle.sig"),
				"ENKLAVE_INPUT_VERSION="+strconv.FormatUint(m.Version, 10))
			cmd.Stdin = bytes.NewReader(in)
			if err := cmd.Run(); err != nil {
				return err
			}
			if err := os.RemoveAll(vf); err != nil {
				return err
			}
			return os.WriteFile(vf, []byte(strconv.FormatUint(m.Version, 10)+"\n"), 0o600)
		})
		if err != nil {
			return fail(err)
		}
		return StateReply{OK: true, Version: v, Counter: v}
	}
	return fail(fmt.Errorf("unknown operation %q", req.Op))
}

const soPeerPidfd = 77 // SO_PEERPIDFD (Linux 6.5)

// peerUnit authenticates the peer of a unix connection: uid 0, and the
// full cgroup path its process is in (G4: the whole path is compared, a
// cgroup that merely ends in the unit name does not count). The pidfd of the peer (taken by the
// kernel at connect time) guards the /proc lookup against pid reuse.
func peerUnit(conn *net.UnixConn) (string, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return "", err
	}
	var cred *syscall.Ucred
	pidfd := -1
	var cerr, perr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		pidfd, perr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, soPeerPidfd)
	}); err != nil {
		return "", err
	}
	if cerr != nil {
		return "", cerr
	}
	if perr != nil {
		return "", fmt.Errorf("SO_PEERPIDFD: %w", perr)
	}
	defer syscall.Close(pidfd)
	if cred.Uid != 0 {
		return "", fmt.Errorf("caller uid %d is not root", cred.Uid)
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", cred.Pid))
	if err != nil {
		return "", err
	}
	// the process the kernel recorded at connect() must still be that pid
	fi, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", pidfd))
	if err != nil || !strings.Contains(string(fi), "\nPid:\t"+strconv.Itoa(int(cred.Pid))+"\n") {
		return "", errors.New("peer process changed during authentication")
	}
	if _, _, e := syscall.Syscall6(424 /* pidfd_send_signal */, uintptr(pidfd), 0, 0, 0, 0, 0); e != 0 {
		return "", fmt.Errorf("peer process is gone: %w", e)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p, nil
		}
	}
	return "", nil
}

// Serve accepts connections until the listener is closed. Each connection
// carries one request line, optionally with one file descriptor (the
// writer's stdin) as SCM_RIGHTS.
func (s *StateServer) Serve(l *net.UnixListener) error {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			rep := s.serveConn(conn)
			b, _ := json.Marshal(rep)
			conn.Write(append(b, '\n')) //nolint:errcheck
		}()
	}
}

func (s *StateServer) serveConn(conn *net.UnixConn) StateReply {
	unit, err := peerUnit(conn)
	if err != nil {
		return StateReply{Error: "caller not authenticated: " + err.Error()}
	}
	buf, oob := make([]byte, 4096), make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return StateReply{Error: err.Error()}
	}
	var stdin *os.File
	if msgs, err := syscall.ParseSocketControlMessage(oob[:oobn]); err == nil {
		for _, m := range msgs {
			if fds, err := syscall.ParseUnixRights(&m); err == nil {
				for i, fd := range fds {
					if i == 0 && stdin == nil {
						stdin = os.NewFile(uintptr(fd), "writer-stdin")
						defer stdin.Close()
					} else {
						syscall.Close(fd)
					}
				}
			}
		}
	}
	var req StateRequest
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		return StateReply{Error: "bad request: " + err.Error()}
	}
	return s.Handle(req, unit, stdin)
}

// StateCall sends one request to the state service. stdin, if not nil, is
// handed to the writer.
func StateCall(c Config, req StateRequest, stdin *os.File) (StateReply, error) {
	var rep StateReply
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.StateSocket(), Net: "unix"})
	if err != nil {
		return rep, fmt.Errorf("state service: %w", err)
	}
	defer conn.Close()
	b, _ := json.Marshal(req)
	var oob []byte
	if stdin != nil {
		oob = syscall.UnixRights(int(stdin.Fd()))
	}
	if _, _, err := conn.WriteMsgUnix(append(b, '\n'), oob, nil); err != nil {
		return rep, err
	}
	line, err := bufio.NewReaderSize(conn, 1<<20).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return rep, fmt.Errorf("state service: %w", err)
	}
	if err := json.Unmarshal(line, &rep); err != nil {
		return rep, err
	}
	if !rep.OK {
		return rep, errors.New(rep.Error)
	}
	return rep, nil
}
