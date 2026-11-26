// Package selftest implements the in-image security self-checks. All file
// access is relative to a configurable root so the checks can be tested
// against a fake tree; external commands go through an injectable Runner.
package selftest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runner runs external commands (nft, cryptsetup, systemctl).
type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

// ExecRunner is the production Runner.
type ExecRunner struct{}

// Run executes the command and returns its stdout.
func (ExecRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// Result is the outcome of one check.
type Result struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

const efiGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

var validRoles = map[string]bool{
	"ref": true, "client": true, "gateway": true, "terminal": true,
	"console": true, "sluice": true, "backup": true, "fileserver": true,
}

type check struct {
	name string
	fn   func(root string, r Runner) (string, error)
}

func checkList() []check {
	return []check{
		{"secureboot", func(root string, _ Runner) (string, error) { return efiBool(root, "SecureBoot", 1) }},
		{"setupmode_off", func(root string, _ Runner) (string, error) { return efiBool(root, "SetupMode", 0) }},
		{"lockdown", checkLockdown},
		{"module_sig_enforce", func(root string, _ Runner) (string, error) {
			return fileEquals(root, "sys/module/module/parameters/sig_enforce", "Y")
		}},
		{"usr_verity", func(root string, _ Runner) (string, error) { return dmUUIDPrefix(root, "/usr", "CRYPT-VERITY-") }},
		{"usr_readonly", checkUsrRO},
		{"var_luks", func(root string, _ Runner) (string, error) { return dmUUIDPrefix(root, "/var", "CRYPT-LUKS2-") }},
		{"var_tpm_bound", checkVarTPM},
		{"no_pkg_manager", checkNoPkg},
		{"apparmor", func(root string, _ Runner) (string, error) {
			return fileEquals(root, "sys/module/apparmor/parameters/enabled", "Y")
		}},
		{"nft_default_drop", checkNft},
		{"no_getty", checkNoGetty},
		{"ipv6_absent", checkIPv6Absent},
		{"role", checkRole},
		{"version", checkVersion},
	}
}

// RunChecks runs all checks in the fixed order. The marker check is appended
// only when the test-profile file exists. It never panics on check errors.
func RunChecks(root string, r Runner) []Result {
	var out []Result
	run := func(c check) {
		res := Result{Check: c.name}
		func() {
			defer func() {
				if p := recover(); p != nil {
					res.OK, res.Detail = false, fmt.Sprintf("panic: %v", p)
				}
			}()
			d, err := c.fn(root, r)
			if err != nil {
				res.OK, res.Detail = false, err.Error()
				return
			}
			res.OK, res.Detail = true, d
		}()
		out = append(out, res)
	}
	for _, c := range checkList() {
		run(c)
	}
	if _, err := os.Stat(filepath.Join(root, "usr/lib/enklave/test-profile")); err == nil {
		run(check{"marker", checkMarker})
	}
	return out
}

// WriteResults writes one JSON line per result plus the done line. It reports
// whether every result was ok.
func WriteResults(w io.Writer, rs []Result) bool {
	all := true
	enc := json.NewEncoder(w)
	for _, r := range rs {
		all = all && r.OK
		_ = enc.Encode(r)
	}
	_ = enc.Encode(struct {
		Check string `json:"check"`
		OK    bool   `json:"ok"`
	}{"done", all})
	return all
}

func readTrim(root, rel string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func fileEquals(root, rel, want string) (string, error) {
	v, err := readTrim(root, rel)
	if err != nil {
		return "", err
	}
	if v != want {
		return "", fmt.Errorf("%s is %q, want %q", rel, v, want)
	}
	return v, nil
}

// efiVarValue returns the first value byte of an EFI variable (after the 4
// attribute bytes).
func efiVarValue(root, name string) (byte, error) {
	rel := "sys/firmware/efi/efivars/" + name + "-" + efiGUID
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return 0, err
	}
	if len(b) < 5 {
		return 0, fmt.Errorf("%s too short (%d bytes)", name, len(b))
	}
	return b[4], nil
}

func efiBool(root, name string, want byte) (string, error) {
	v, err := efiVarValue(root, name)
	if err != nil {
		return "", err
	}
	if v != want {
		return "", fmt.Errorf("%s is %d, want %d", name, v, want)
	}
	return fmt.Sprintf("%s=%d", name, v), nil
}

func checkLockdown(root string, _ Runner) (string, error) {
	v, err := readTrim(root, "sys/kernel/security/lockdown")
	if err != nil {
		return "", err
	}
	if !strings.Contains(v, "[confidentiality]") {
		return "", fmt.Errorf("lockdown is %q", v)
	}
	return v, nil
}

type mount struct{ majmin, opts string }

func findMount(root, point string) (mount, error) {
	b, err := os.ReadFile(filepath.Join(root, "proc/self/mountinfo"))
	if err != nil {
		return mount{}, err
	}
	var found *mount
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 6 && f[4] == point {
			found = &mount{majmin: f[2], opts: f[5]}
		}
	}
	if found == nil {
		return mount{}, fmt.Errorf("no mount for %s", point)
	}
	return *found, nil
}

func dmUUIDPrefix(root, point, prefix string) (string, error) {
	m, err := findMount(root, point)
	if err != nil {
		return "", err
	}
	u, err := readTrim(root, "sys/dev/block/"+m.majmin+"/dm/uuid")
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(u, prefix) {
		return "", fmt.Errorf("%s dm uuid %q lacks prefix %s", point, u, prefix)
	}
	return u, nil
}

func checkUsrRO(root string, _ Runner) (string, error) {
	m, err := findMount(root, "/usr")
	if err != nil {
		return "", err
	}
	for _, o := range strings.Split(m.opts, ",") {
		if o == "ro" {
			return m.opts, nil
		}
	}
	return "", fmt.Errorf("/usr mounted with options %q, not ro", m.opts)
}

func checkVarTPM(root string, r Runner) (string, error) {
	m, err := findMount(root, "/var")
	if err != nil {
		return "", err
	}
	ents, err := os.ReadDir(filepath.Join(root, "sys/dev/block", m.majmin, "slaves"))
	if err != nil {
		return "", err
	}
	if len(ents) == 0 {
		return "", errors.New("/var device has no slaves")
	}
	dev := "/dev/" + ents[0].Name()
	out, err := r.Run("cryptsetup", "luksDump", dev)
	if err != nil {
		return "", fmt.Errorf("cryptsetup luksDump %s: %w", dev, err)
	}
	if !strings.Contains(string(out), "systemd-tpm2") {
		return "", fmt.Errorf("no systemd-tpm2 token on %s", dev)
	}
	return dev, nil
}

func checkNoPkg(root string, _ Runner) (string, error) {
	for _, p := range []string{"usr/bin/apt", "usr/bin/apt-get", "usr/bin/dpkg", "var/lib/dpkg"} {
		if _, err := os.Lstat(filepath.Join(root, p)); err == nil {
			return "", fmt.Errorf("/%s exists", p)
		}
	}
	return "", nil
}

func checkNft(_ string, r Runner) (string, error) {
	out, err := r.Run("nft", "-j", "list", "ruleset")
	if err != nil {
		return "", fmt.Errorf("nft: %w", err)
	}
	var doc struct {
		Nftables []struct {
			Chain *struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Policy string `json:"policy"`
			} `json:"chain"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return "", fmt.Errorf("parse nft json: %w", err)
	}
	pol := map[string]string{}
	for _, e := range doc.Nftables {
		if c := e.Chain; c != nil && c.Family == "inet" && c.Table == "enklave" {
			pol[c.Name] = c.Policy
		}
	}
	for _, n := range []string{"input", "forward", "output"} {
		if pol[n] != "drop" {
			return "", fmt.Errorf("inet enklave chain %s policy %q, want drop", n, pol[n])
		}
	}
	return "input/forward/output drop", nil
}

func checkNoGetty(_ string, r Runner) (string, error) {
	out, err := r.Run("systemctl", "list-units", "--all", "--plain", "--no-legend", "--state=active")
	if err != nil {
		return "", fmt.Errorf("systemctl: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.Contains(f[0], "getty") {
			return "", fmt.Errorf("active unit %s", f[0])
		}
	}
	return "", nil
}

func checkIPv6Absent(root string, _ Runner) (string, error) {
	if _, err := os.Stat(filepath.Join(root, "proc/net/if_inet6")); err == nil {
		return "", errors.New("/proc/net/if_inet6 exists")
	}
	return "", nil
}

func checkRole(root string, _ Runner) (string, error) {
	v, err := readTrim(root, "usr/lib/enklave/role")
	if err != nil {
		return "", err
	}
	if !validRoles[v] {
		return "", fmt.Errorf("invalid role %q", v)
	}
	return v, nil
}

func checkVersion(root string, _ Runner) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "usr/lib/os-release"))
	if err != nil {
		return "unknown", nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "IMAGE_VERSION="); ok {
			return strings.Trim(v, `"'`), nil
		}
	}
	return "unknown", nil
}

func checkMarker(root string, _ Runner) (string, error) {
	if _, err := os.Stat(filepath.Join(root, "var/lib/enklave/marker")); err != nil {
		return "", err
	}
	return "present", nil
}
