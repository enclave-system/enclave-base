// Package selftest implements the in-image security self-checks. All file
// access is relative to a configurable root so the checks can be tested
// against a fake tree; external commands go through an injectable Runner.
package selftest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"enklave.local/base/internal/varauth"
)

// Runner runs external commands (nft, cryptsetup, systemctl).
type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

// ExecRunner is the production Runner.
type ExecRunner struct{}

// Run executes the command and returns its stdout.
func (ExecRunner) Run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
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

// Options modify the check list.
type Options struct {
	// ForbidDevKeys turns the informational dev_keys check into a failure
	// for images signed with a development PKI (production acceptance).
	ForbidDevKeys bool
}

func checkList(o Options) []check {
	return []check{
		{"secureboot", func(root string, _ Runner) (string, error) { return efiBool(root, "SecureBoot", 1) }},
		{"setupmode_off", func(root string, _ Runner) (string, error) { return efiBool(root, "SetupMode", 0) }},
		{"lockdown", checkLockdown},
		{"module_sig_enforce", func(root string, _ Runner) (string, error) {
			return fileEquals(root, "sys/module/module/parameters/sig_enforce", "Y")
		}},
		{"usr_verity", func(root string, _ Runner) (string, error) { return dmUUIDPrefix(root, "/usr", "CRYPT-VERITY-") }},
		{"usr_readonly", checkUsrRO},
		{"var_luks", func(root string, _ Runner) (string, error) { return dmUUIDPrefix(root, stateMount, "CRYPT-LUKS2-") }},
		{"var_tpm_bound", checkVarTPM},
		{"var_authenticated", checkVarAuthenticated},
		{"var_integrity", checkVarIntegrity},
		{"var_rollback", checkVarRollback},
		{"state_readonly", checkStateReadOnly},
		{"efi_updates", checkEFIUpdates},
		{"tpm_locked", checkTPMLocked},
		{"pcr11_sealed", checkPCR11Sealed},
		{"no_pkg_manager", checkNoPkg},
		{"apparmor", func(root string, _ Runner) (string, error) {
			return fileEquals(root, "sys/module/apparmor/parameters/enabled", "Y")
		}},
		{"nft_default_drop", checkNft},
		{"no_getty", checkNoGetty},
		{"ipv6_absent", checkIPv6Absent},
		{"no_credentials", checkNoCredentials},
		{"role", checkRole},
		{"version", checkVersion},
		{"dev_keys", func(root string, _ Runner) (string, error) { return checkDevKeys(root, o.ForbidDevKeys) }},
	}
}

// RunChecks runs all checks in the fixed order. The marker check is appended
// only when the test-profile file exists. It never panics on check errors.
func RunChecks(root string, r Runner) []Result { return RunChecksWith(root, r, Options{}) }

// RunChecksWith is RunChecks with options.
func RunChecksWith(root string, r Runner, o Options) []Result {
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
	for _, c := range checkList(o) {
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

// mustNotExist succeeds only if the path definitively does not exist; any
// other stat error (e.g. ENOTDIR, EACCES) is a failure.
func mustNotExist(root, rel string) error {
	_, err := os.Lstat(filepath.Join(root, rel))
	switch {
	case err == nil:
		return fmt.Errorf("/%s exists", rel)
	case errors.Is(err, fs.ErrNotExist):
		return nil
	}
	return err
}

func checkNoPkg(root string, _ Runner) (string, error) {
	for _, p := range []string{"usr/bin/apt", "usr/bin/apt-get", "usr/bin/dpkg", "var/lib/dpkg"} {
		if err := mustNotExist(root, p); err != nil {
			return "", err
		}
	}
	return "", nil
}

// nftFamily is the family of the base "enklave" table. The enklave kernels are
// built without IPv6, and "inet" tables need CONFIG_NF_TABLES_INET (depends on
// IPV6), so the ruleset uses an "ip" table.
const nftFamily = "ip"

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
		if c := e.Chain; c != nil && c.Family == nftFamily && c.Table == "enklave" {
			pol[c.Name] = c.Policy
		}
	}
	for _, n := range []string{"input", "forward", "output"} {
		if pol[n] != "drop" {
			return "", fmt.Errorf("%s enklave chain %s policy %q, want drop", nftFamily, n, pol[n])
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
	if err := mustNotExist(root, "proc/net/if_inet6"); err != nil {
		return "", err
	}
	return "", nil
}

const noCredentialsArg = "systemd.import_credentials=no"

// checkNoCredentials verifies that systemd does not import credentials from
// unauthenticated sources (ESP via systemd-stub, SMBIOS, fw_cfg): the signed
// kernel command line must disable the import, and no system credential may
// be present.
func checkNoCredentials(root string, _ Runner) (string, error) {
	cl, err := os.ReadFile(filepath.Join(root, "proc/cmdline"))
	if err != nil {
		return "", err
	}
	// The kernel/systemd use the last occurrence of an option: the last
	// systemd.import_credentials= token must be exactly "no".
	last := ""
	for _, f := range strings.Fields(string(cl)) {
		if strings.HasPrefix(f, "systemd.import_credentials=") || f == "systemd.import_credentials" {
			last = f
		}
	}
	if last != noCredentialsArg {
		return "", fmt.Errorf("last systemd.import_credentials token is %q, want %s", last, noCredentialsArg)
	}
	ents, err := os.ReadDir(filepath.Join(root, "run/credentials/@system"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return "", err
	case len(ents) > 0:
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		return "", fmt.Errorf("system credentials present: %s", strings.Join(names, ","))
	}
	return "import disabled, no system credentials", nil
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

// checkMarker reads the test marker through the state service: the read is
// authenticated against the manifest and the TPM counter.
func checkMarker(root string, _ Runner) (string, error) {
	if _, err := StateCall(root, varauth.StateRequest{Op: "read", Path: "marker"}); err != nil {
		return "", err
	}
	return "present (authenticated read)", nil
}
