package sbstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
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

}

// B3: after a signed update the Secure Boot state must be exactly the old
// state with the update's signatures added to the updated variable.
func TestStateDigest(t *testing.T) {
	boot := func(mut func(f *sbtest.Firmware)) []Event {
		f := sbtest.NewFirmware()
		f.Vars[dbxID] = sbtest.ESL(hash("old revocation 1"), hash("old revocation 2"))
		if mut != nil {
			mut(f)
		}
		l, _ := f.Boot()
		evs, _, err := ParseLog(l, 7)
		if err != nil {
			t.Fatal(err)
		}
		return evs
	}
	upd := map[string][]Signature{dbxID: {{sbtest.SHA256Type, hexOf(hash("revoked uki"))}}}
	vars := []string{dbxID}
	old, _ := StateDigest(boot(nil), vars, nil)
	want, err := StateDigest(boot(nil), vars, upd)
	if err != nil || bytes.Equal(old, want) {
		t.Fatalf("expectation: %v", err)
	}
	state := func(mut func(f *sbtest.Firmware)) []byte {
		d, err := StateDigest(boot(mut), vars, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	dbx := func(sigs ...[]byte) func(f *sbtest.Firmware) {
		return func(f *sbtest.Firmware) { f.Vars[dbxID] = sbtest.ESL(sigs...) }
	}
	o1, o2, n := hash("old revocation 1"), hash("old revocation 2"), hash("revoked uki")
	for name, d := range map[string][]byte{
		"appended as one list":  state(dbx(o1, o2, n)),
		"reordered by firmware": state(dbx(n, o2, o1)),
		"appended as a second list": state(func(f *sbtest.Firmware) {
			f.Vars[dbxID] = append(sbtest.ESL(o1, o2), sbtest.ESL(n)...)
		}),
	} {
		if !bytes.Equal(d, want) {
			t.Errorf("%s: not accepted as the updated state", name)
		}
	}
	if !bytes.Equal(state(nil), old) {
		t.Error("unchanged state differs from the old digest")
	}
	for name, mut := range map[string]func(f *sbtest.Firmware){
		"older dbx entry dropped":       dbx(o1, n),
		"all older entries dropped":     dbx(n),
		"foreign dbx entry added":       dbx(o1, o2, n, hash("x")),
		"update missing, entry dropped": dbx(o1),
		"dbx emptied":                   dbx(),
		"secure boot disabled":          func(f *sbtest.Firmware) { dbx(o1, o2, n)(f); f.SecureBoot = 0 },
		"db key added":                  func(f *sbtest.Firmware) { dbx(o1, o2, n)(f); f.Vars["db-"+GUIDSecurity] = []byte("attacker") },
		"KEK replaced":                  func(f *sbtest.Firmware) { dbx(o1, o2, n)(f); f.Vars["KEK-"+GUIDGlobal] = []byte("attacker") },
		"other authority":               func(f *sbtest.Firmware) { dbx(o1, o2, n)(f); f.Authority = []byte("attacker cert") },
		"additional event": func(f *sbtest.Firmware) {
			dbx(o1, o2, n)(f)
			f.Extra = []sbtest.Ev{{PCR: 7, Type: 0x800000E0, Data: []byte("second authority")}}
		},
	} {
		if d := state(mut); bytes.Equal(d, want) || bytes.Equal(d, old) {
			t.Errorf("%s: accepted", name)
		}
	}
	// db and KEK appends follow the same rule
	for _, id := range []string{"db-" + GUIDSecurity, "KEK-" + GUIDGlobal} {
		f := sbtest.NewFirmware()
		f.Vars[id] = sbtest.ESL(hash("key 1"))
		l, _ := f.Boot()
		before, _, _ := ParseLog(l, 7)
		add := map[string][]Signature{id: {{sbtest.SHA256Type, hexOf(hash("key 2"))}}}
		want, _ := StateDigest(before, []string{id}, add)
		for content, ok := range map[string]bool{
			string(sbtest.ESL(hash("key 1"), hash("key 2"))):                true,
			string(sbtest.ESL(hash("key 2"))):                               false, // replaced instead of appended
			string(sbtest.ESL(hash("key 1"), hash("key 2"), hash("key 3"))): false,
		} {
			f.Vars[id] = []byte(content)
			l, _ := f.Boot()
			after, _, _ := ParseLog(l, 7)
			got, err := StateDigest(after, []string{id}, nil)
			if err != nil || bytes.Equal(got, want) != ok {
				t.Errorf("%s: accepted=%v, want %v (%v)", id, bytes.Equal(got, want), ok, err)
			}
		}
	}
	// a variable that is not a signature list cannot be an update target
	bad := boot(func(f *sbtest.Firmware) { f.Vars[dbxID] = []byte("garbage that is not a list ....") })
	if _, err := StateDigest(bad, vars, nil); err == nil {
		t.Error("malformed variable accepted")
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

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

// G3: the PCR 7 value after a variable update is computed in advance.
func TestPredict(t *testing.T) {
	fw := sbtest.NewFirmware()
	fw.Vars[dbxID] = sbtest.ESL(hash("old"))
	log, pcr7 := fw.Boot()
	evs, _, err := ParseLog(log, 7)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"db-" + GUIDSecurity, dbxID, "KEK-" + GUIDGlobal}
	content, err := Verbatim(evs, ids, fw)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := Predict(evs, content); err != nil || !bytes.Equal(p, pcr7) {
		t.Fatalf("this boot: %x %v, PCR 7 %x", p, err, pcr7)
	}
	if p, _ := Predict(evs, nil); !bytes.Equal(p, pcr7) {
		t.Fatal("replay without substitution")
	}
	// after a signed append the firmware of the next boot measures exactly the predicted value
	upd := sbtest.ESL(hash("revoked"))
	cands, err := AppendCandidates(content[dbxID], upd)
	if err != nil || len(cands) != 1 {
		t.Fatalf("candidates %d %v", len(cands), err)
	}
	content[dbxID] = cands[0]
	want, _ := Predict(evs, content)
	if err := fw.Append("dbx", GUIDSecurity, sbtest.Auth(upd)); err != nil {
		t.Fatal(err)
	}
	if _, next := fw.Boot(); !bytes.Equal(next, want) || bytes.Equal(next, pcr7) {
		t.Fatalf("next boot PCR 7 %x, predicted %x", next, want)
	}
	// any other content gives another value
	content[dbxID] = sbtest.ESL(hash("revoked"))
	if p, _ := Predict(evs, content); bytes.Equal(p, want) {
		t.Fatal("dropped entry predicted to the same PCR 7")
	}
	// a variable that changed since boot, or is not measured as stored
	if _, err := Verbatim(evs, ids, fw); err == nil {
		t.Error("variable changed since boot not noticed")
	}
	fw2 := sbtest.NewFirmware()
	fw2.Skip = "dbx"
	log2, _ := fw2.Boot()
	evs2, _, _ := ParseLog(log2, 7)
	if _, err := Verbatim(evs2, ids, fw2); err == nil {
		t.Error("unmeasured variable accepted")
	}
	if _, err := VariableData("dbx", nil); err == nil {
		t.Error("variable id without GUID accepted")
	}
}

func TestAppendCandidates(t *testing.T) {
	a, b, c := hash("a"), hash("b"), hash("c")
	// the update repeats an entry the variable holds: edk2 drops it, a plain append keeps it
	cur := sbtest.ESL(a, b)
	cands, err := AppendCandidates(cur, sbtest.ESL(b, c))
	if err != nil || len(cands) != 2 {
		t.Fatalf("%d %v", len(cands), err)
	}
	if !bytes.Equal(cands[0], append(append([]byte{}, cur...), sbtest.ESL(c)...)) {
		t.Errorf("edk2 form: %x", cands[0])
	}
	if !bytes.Equal(cands[1], append(append([]byte{}, cur...), sbtest.ESL(b, c)...)) {
		t.Errorf("plain form: %x", cands[1])
	}
	for _, cand := range cands {
		if ok, err := ExactlyAdded(cur, cand, []Signature{{sbtest.SHA256Type, hex.EncodeToString(b)}, {sbtest.SHA256Type, hex.EncodeToString(c)}}); !ok || err != nil {
			t.Errorf("candidate is not old plus update: %v", err)
		}
	}
	if _, err := AppendCandidates([]byte("junk"), sbtest.ESL(a)); err == nil {
		t.Error("malformed variable accepted")
	}
	add := []Signature{{sbtest.SHA256Type, hex.EncodeToString(c)}}
	for name, after := range map[string][]byte{
		"entry dropped": sbtest.ESL(a, c), "nothing added": sbtest.ESL(a, b), "foreign entry": sbtest.ESL(a, b, c, hash("x")),
	} {
		if ok, _ := ExactlyAdded(cur, after, add); ok {
			t.Errorf("%s accepted as old plus update", name)
		}
	}
	if ok, _ := ExactlyAdded(cur, sbtest.ESL(c, b, a), add); !ok {
		t.Error("same set in another order refused")
	}
}
