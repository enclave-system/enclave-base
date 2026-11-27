package sbstate

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enklave.local/base/internal/sbstate/sbtest"
)

func hash(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

const dbxID = "dbx-" + GUIDSecurity

func TestParseLogAndCompare(t *testing.T) {
	fw := sbtest.NewFirmware()
	log, pcr7 := fw.Boot()
	before, v, err := ParseLog(log, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v, pcr7) || len(before) != 7 {
		t.Fatalf("replay %x (%d events), want %x", v, len(before), pcr7)
	}
	if before[0].Var != "SecureBoot-"+GUIDGlobal || before[4].Var != dbxID || before[5].Var != "" || before[6].Var != "" {
		t.Errorf("variables %+v", before)
	}
	if err := HasVariables(before, []string{dbxID}); err != nil {
		t.Error(err)
	}
	if err := HasVariables(before, []string{"dbt-" + GUIDSecurity}); err == nil {
		t.Error("unmeasured variable accepted")
	}
	// padded log (the kernel may hand out trailing zeros)
	if _, v2, err := ParseLog(append(append([]byte{}, log...), make([]byte, 64)...), 7); err != nil || !bytes.Equal(v2, pcr7) {
		t.Errorf("padded log: %v", err)
	}
	if _, _, err := ParseLog(log[:len(log)-5], 7); err == nil {
		t.Error("truncated log accepted")
	}
	if _, _, err := ParseLog([]byte("garbage that is long enough to hold a header ......"), 7); err == nil {
		t.Error("garbage accepted")
	}

	after := func(mut func(f *sbtest.Firmware)) []Event {
		f := sbtest.NewFirmware()
		mut(f)
		l, _ := f.Boot()
		evs, _, err := ParseLog(l, 7)
		if err != nil {
			t.Fatal(err)
		}
		return evs
	}
	dbx := func(f *sbtest.Firmware) { f.Vars[dbxID] = sbtest.ESL(hash("revoked uki")) }
	if err := Compare(before, after(dbx), []string{dbxID}); err != nil {
		t.Errorf("signed dbx update refused: %v", err)
	}
	if err := Compare(before, before, []string{dbxID}); err != nil {
		t.Errorf("unchanged state refused: %v", err)
	}
	for name, tc := range map[string]struct {
		mut  func(f *sbtest.Firmware)
		want string
	}{
		"dbx changed without an update": {dbx, "no signed update"},
		"secure boot disabled":          {func(f *sbtest.Firmware) { dbx(f); f.SecureBoot = 0 }, "SecureBoot"},
		"db key added":                  {func(f *sbtest.Firmware) { dbx(f); f.Vars["db-"+GUIDSecurity] = []byte("attacker") }, "db-"},
		"other authority":               {func(f *sbtest.Firmware) { dbx(f); f.Authority = []byte("attacker cert") }, "type 0x800000e0"},
		"additional event": {func(f *sbtest.Firmware) {
			dbx(f)
			f.Extra = []sbtest.Ev{{PCR: 7, Type: 0x800000E0, Data: []byte("second authority")}}
		}, "events"},
	} {
		upd := []string{dbxID}
		if name == "dbx changed without an update" {
			upd = nil
		}
		if err := Compare(before, after(tc.mut), upd); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestUpdates(t *testing.T) {
	d := t.TempDir()
	h1, h2 := hash("uki 1"), hash("uki 2")
	os.WriteFile(filepath.Join(d, "dbx-epoch0.auth"), sbtest.Auth(sbtest.ESL(h1, h2)), 0o644)
	us, err := LoadUpdates(d)
	if err != nil || len(us) != 1 || us[0].Var != "dbx" || us[0].ID() != dbxID || len(us[0].Sigs) != 2 {
		t.Fatalf("%+v %v", us, err)
	}
	for cur, want := range map[string]bool{
		"":                     false,
		string(sbtest.ESL(h1)): false,
		string(sbtest.ESL(h2)) + string(sbtest.ESL(hash("other"), h1)): true,
	} {
		if got, err := us[0].Applied([]byte(cur)); err != nil || got != want {
			t.Errorf("Applied = %v, %v; want %v", got, err, want)
		}
	}
	if _, err := us[0].Applied([]byte("garbage that is not a list ....")); err == nil {
		t.Error("malformed variable content accepted")
	}
	if us, err := LoadUpdates(filepath.Join(d, "missing")); err != nil || len(us) != 0 {
		t.Errorf("missing directory: %v %v", us, err)
	}
	for name, content := range map[string][]byte{
		"PK-x.auth":    sbtest.Auth(sbtest.ESL(h1)),
		"noname.auth":  sbtest.Auth(sbtest.ESL(h1)),
		"dbx-bad.auth": []byte("short"),
		"dbx-nil.auth": sbtest.Auth(nil),
	} {
		bad := t.TempDir()
		os.WriteFile(filepath.Join(bad, name), content, 0o644)
		if _, err := LoadUpdates(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestEFIVarFS(t *testing.T) {
	v := EFIVarFS{t.TempDir()}
	if b, err := v.Read("dbx", GUIDSecurity); err != nil || b != nil {
		t.Fatalf("missing variable: %v %v", b, err)
	}
	if err := v.Append("dbx", GUIDSecurity, []byte("AUTH")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(v.Dir, "dbx-"+GUIDSecurity))
	if !bytes.Equal(raw, append([]byte{0x67, 0, 0, 0}, "AUTH"...)) {
		t.Errorf("wrote %x", raw)
	}
	if b, _ := v.Read("dbx", GUIDSecurity); string(b) != "AUTH" {
		t.Errorf("read %q", b)
	}
	if _, err := VarGUID("PK"); err == nil {
		t.Error("PK update accepted")
	}
}
