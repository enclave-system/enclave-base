package ekcert

import (
	"os"
	"path/filepath"
	"testing"
)

// bundleDir is the TPM vendor CA bundle shipped in /usr/share/enclave/tpm-ek-ca.
const bundleDir = "../../../mkosi/mkosi.extra/usr/share/enclave/tpm-ek-ca"

// The shipped bundle must load and every vendor must contribute trust
// anchors (a parser or bundle problem would otherwise only show on real
// hardware).
func TestVendorBundle(t *testing.T) {
	vendors, err := os.ReadDir(bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	all := NewStore()
	if err := all.AddDir(bundleDir); err != nil {
		t.Fatal(err)
	}
	for _, f := range all.Skipped {
		t.Logf("not parseable (ignored at runtime): %s", f)
	}
	// 2026-11-17 bundle: six STMicro files with a malformed serial number
	// (each re-issued as "..._2.crt", which parses) and one Qualcomm file.
	if len(all.Skipped) > 7 {
		t.Errorf("%d bundle files are not parseable", len(all.Skipped))
	}
	want := map[string]int{"AMD": 5, "Infineon": 9, "Intel": 6, "NationZ": 5, "Nuvoton": 17, "STMicro": 6}
	for _, v := range vendors {
		if !v.IsDir() {
			continue
		}
		if v.Name() == "Microsoft" {
			t.Error("the Microsoft directory holds the vTPM/AIK root (virtual TPMs) and must not be shipped")
		}
		s := NewStore()
		if err := s.AddDir(filepath.Join(bundleDir, v.Name())); err != nil {
			t.Fatal(err)
		}
		t.Logf("%-9s %2d root CAs, %3d issuing CAs", v.Name(), s.NRoots, s.NInter)
		if s.NRoots < want[v.Name()] || s.NRoots == 0 {
			t.Errorf("%s: %d root CAs, want at least %d", v.Name(), s.NRoots, want[v.Name()])
		}
		delete(want, v.Name())
	}
	for v := range want {
		t.Errorf("vendor %s missing from the bundle", v)
	}
	if _, err := os.Stat(filepath.Join(bundleDir, "SOURCE")); err != nil {
		t.Errorf("bundle provenance file missing: %v", err)
	}
}
