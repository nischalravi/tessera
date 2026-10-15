package flatfile_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func codes(errs []flatfile.RowError) []string {
	var out []string
	for _, e := range errs {
		out = append(out, fmt.Sprintf("%d:%s", e.Row, e.Code))
	}
	return out
}

func hasCode(errs []flatfile.RowError, row int, code string) bool {
	for _, e := range errs {
		if e.Row == row && e.Code == code {
			return true
		}
	}
	return false
}

func TestNeutralize(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "",
		"plain":             "plain",
		"=SUM(A1)":          "'=SUM(A1)",
		"+1":                "'+1",
		"-1":                "'-1",
		"@cmd":              "'@cmd",
		"\t=1":              "'\t=1",
		"\r=1":              "'\r=1",
		"a=b":               "a=b",
		"'=already":         "'=already",
		"=HYPERLINK(\"x\")": "'=HYPERLINK(\"x\")",
	} {
		if got := flatfile.Neutralize(in); got != want {
			t.Errorf("Neutralize(%q) = %q, want %q", in, got, want)
		}
		if again := flatfile.Neutralize(flatfile.Neutralize(in)); again != flatfile.Neutralize(in) {
			t.Errorf("Neutralize is not idempotent on %q: %q", in, again)
		}
	}
}

func TestSafeFilename(t *testing.T) {
	for in, want := range map[string]string{
		"accounts.csv":           "accounts.csv",
		"C:\\temp\\acc.csv":      "acc.csv",
		"../../etc/passwd":       "passwd",
		"=cmd|calc!A0.csv":       "_cmd_calc_A0.csv",
		"@sum.csv":               "_sum.csv",
		"-1.csv":                 "'-1.csv",
		"":                       "upload.csv",
		"///":                    "upload.csv",
		"a\nb.csv":               "a_b.csv",
		strings.Repeat("x", 300): strings.Repeat("x", 100),
	} {
		if got := flatfile.SafeFilename(in); got != want {
			t.Errorf("SafeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	var many strings.Builder
	many.WriteString("id,name\n")
	for i := 0; i <= flatfile.MaxRows; i++ {
		fmt.Fprintf(&many, "%d,n\n", i)
	}
	var wide []string
	for i := 0; i <= flatfile.MaxColumns; i++ {
		wide = append(wide, fmt.Sprintf("c%d", i))
	}
	for _, tc := range []struct {
		name string
		raw  string
		code string // the single file-level error, "" for a parsed file
		rows int
	}{
		{"ok", "id,name\n1,a\n2,b\n", "", 2},
		{"byte order mark", "\xef\xbb\xbfid,name\n1,a\n", "", 1},
		{"blank lines are not rows", "id,name\n\n1,a\n  \n2,b\n", "", 2},
		{"crlf", "id,name\r\n1,a\r\n", "", 1},
		{"quoted comma", "id,name\n1,\"a,b\"\n", "", 1},
		{"latin-1 bytes", "id,name\n1,caf\xe9\n", flatfile.CodeNotUTF8, 0},
		{"utf-16 bytes", "\xff\xfei\x00d\x00\n\x00", flatfile.CodeNotUTF8, 0},
		{"nul byte", "id,name\n1,a\x00b\n", flatfile.CodeNotUTF8, 0},
		{"empty file", "", flatfile.CodeNoHeader, 0},
		{"empty header name", "id,,x\n1,2,3\n", flatfile.CodeNoHeader, 0},
		{"repeated header", "id,ID\n1,2\n", flatfile.CodeDuplicateCol, 0},
		{"bare quote", "id,name\n1,a\"b\n", flatfile.CodeBadCSV, 0},
		{"unterminated quote", "id,name\n1,\"ab\n", flatfile.CodeBadCSV, 0},
		{"too many rows", many.String(), flatfile.CodeTooManyRows, 0},
		{"too many columns", strings.Join(wide, ",") + "\n", flatfile.CodeTooManyColumns, 0},
		{"oversized", "id\n" + strings.Repeat("x", flatfile.MaxBytes), flatfile.CodeFileTooLarge, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tbl, errs := flatfile.Parse([]byte(tc.raw))
			if tc.code != "" {
				if tbl != nil || len(errs) != 1 || errs[0].Code != tc.code || errs[0].Row != 0 {
					t.Fatalf("got table %v errors %v, want one file error %s", tbl != nil, codes(errs), tc.code)
				}
				return
			}
			if tbl == nil || len(errs) != 0 || len(tbl.Rows) != tc.rows || len(tbl.Short) != 0 {
				t.Fatalf("got %+v, %v; want %d rows", tbl, errs, tc.rows)
			}
		})
	}
}

func TestParse_WrongColumnCountIsReportedPerRow(t *testing.T) {
	tbl, errs := flatfile.Parse([]byte("id,name,mail\n1,a,x\n2,b\n3,c,y,z\n4,d,w\n"))
	if tbl == nil || len(errs) != 0 {
		t.Fatalf("%v %v", tbl, errs)
	}
	if got := codes(tbl.Short); len(got) != 2 || got[0] != "2:column_count" || got[1] != "3:column_count" {
		t.Errorf("short rows = %v", got)
	}
	if len(tbl.Rows) != 2 || tbl.Rows[0].Num != 1 || tbl.Rows[1].Num != 4 || tbl.Total != 4 {
		t.Errorf("rows = %+v total %d", tbl.Rows, tbl.Total)
	}
}

func goodMapping() *flatfile.Mapping {
	return &flatfile.Mapping{System: "hr-app", Name: "HR app", Owner: "hr@example.com",
		Accounts:     flatfile.AccountCols{AccountID: "UserID", Username: "Login", Email: "Mail", IdentityID: "EmpNo", Status: "State"},
		Entitlements: &flatfile.EntitlementCols{AccountID: "UserID", Entitlement: "Role", Name: "RoleName", Privileged: "Admin"}}
}

func TestMappingValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		mut   func(m *flatfile.Mapping)
		field string // "" = valid
	}{
		"ok":                         {func(*flatfile.Mapping) {}, ""},
		"no entitlements":            {func(m *flatfile.Mapping) { m.Entitlements = nil }, ""},
		"system upper case":          {func(m *flatfile.Mapping) { m.System = "HR" }, "system"},
		"system with slash":          {func(m *flatfile.Mapping) { m.System = "a/b" }, "system"},
		"system empty":               {func(m *flatfile.Mapping) { m.System = "" }, "system"},
		"name empty":                 {func(m *flatfile.Mapping) { m.Name = "  " }, "name"},
		"name control char":          {func(m *flatfile.Mapping) { m.Name = "a\nb" }, "name"},
		"account id missing":         {func(m *flatfile.Mapping) { m.Accounts.AccountID = "" }, "accounts.account_id"},
		"username missing":           {func(m *flatfile.Mapping) { m.Accounts.Username = "" }, "accounts.username"},
		"column padded":              {func(m *flatfile.Mapping) { m.Accounts.Email = " Mail" }, "accounts.email"},
		"column serves two fields":   {func(m *flatfile.Mapping) { m.Accounts.Email = "login" }, "accounts"},
		"entitlement column missing": {func(m *flatfile.Mapping) { m.Entitlements.Entitlement = "" }, "entitlements.entitlement"},
		"entitlement dup column":     {func(m *flatfile.Mapping) { m.Entitlements.Name = "role" }, "entitlements"},
	} {
		t.Run(name, func(t *testing.T) {
			m := goodMapping()
			tc.mut(m)
			err := m.Validate()
			switch fe, _ := err.(*flatfile.FieldError); {
			case tc.field == "" && err != nil:
				t.Errorf("unexpected %v", err)
			case tc.field != "" && (fe == nil || fe.Field != tc.field):
				t.Errorf("got %v, want an error on %s", err, tc.field)
			}
		})
	}
}

func TestMappingStoreRoundTrip(t *testing.T) {
	m := goodMapping()
	row, err := m.ToStore()
	if err != nil {
		t.Fatal(err)
	}
	back, err := flatfile.FromStore(row)
	if err != nil || *back.Entitlements != *m.Entitlements || back.Accounts != m.Accounts || back.Name != m.Name {
		t.Errorf("round trip = %+v, %v", back, err)
	}
	m.Entitlements = nil
	row, _ = m.ToStore()
	if back, err := flatfile.FromStore(row); err != nil || back.Entitlements != nil {
		t.Errorf("no entitlements: %+v, %v", back, err)
	}
	if _, err := flatfile.FromStore(&store.FlatMapping{System: "x", AccountCols: "not json"}); err == nil {
		t.Error("unreadable mapping accepted")
	}
}

func parse(t *testing.T, csv string) *flatfile.Table {
	t.Helper()
	tbl, errs := flatfile.Parse([]byte(csv))
	if tbl == nil {
		t.Fatalf("parse: %v", errs)
	}
	return tbl
}

func TestAccountRecords(t *testing.T) {
	const head = "UserID,Login,Mail,EmpNo,State\n"
	long := strings.Repeat("x", flatfile.MaxCellRunes+1)
	for _, tc := range []struct {
		name string
		csv  string
		want []string // "row:code" in order; nil = valid
	}{
		{"valid", head + "u1,alice,Alice@T.Example,,active\nu2,bob,,bob,Enabled\nu3,carol,,,suspended\n", nil},
		{"missing id", head + ",alice,,,\n", []string{"1:required"}},
		{"missing username", head + "u1,,,,\n", []string{"1:required"}},
		{"formula in id", head + "=1+1,alice,,,\n", []string{"1:formula_prefix"}},
		{"formula in identity id", head + "u1,alice,,@x,\n", []string{"1:formula_prefix"}},
		{"formula in email", head + "u1,alice,+a@b.example,,\n", []string{"1:formula_prefix"}},
		{"bad email", head + "u1,alice,not-an-email,,\n", []string{"1:invalid_email"}},
		{"bad email spaces", head + "u1,alice,a b@c.example,,\n", []string{"1:invalid_email"}},
		{"bad status", head + "u1,alice,,,maybe\n", []string{"1:invalid_status"}},
		{"duplicate id", head + "u1,a,,,\nu1,b,,,\n", []string{"2:duplicate_key"}},
		{"too long", head + "u1," + long + ",,,\n", []string{"1:too_long"}},
		{"control char", head + "u1,\"a\nb\",,,\n", []string{"1:control_character"}},
		{"wrong column count", head + "u1,alice\nu2,bob,,,\n", []string{"1:column_count"}},
		{"every bad row is listed", head + ",a,,,\nu2,,,,\nu3,c,bad,,\nu4,d,,,ok\n", []string{"1:required", "2:required", "3:invalid_email", "4:invalid_status"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs, errs := goodMapping().AccountRecords(parse(t, tc.csv))
			if tc.want == nil {
				if len(errs) != 0 || len(recs) == 0 {
					t.Fatalf("got %d records, errors %v", len(recs), codes(errs))
				}
				return
			}
			if got := codes(errs); strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("errors %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAccountRecords_MissingMappedColumn(t *testing.T) {
	_, errs := goodMapping().AccountRecords(parse(t, "UserID,Login\nu1,a\n"))
	if len(errs) != 3 || !hasCode(errs, 0, flatfile.CodeMissingColumn) {
		t.Errorf("errors %v, want one missing_column per absent column (Mail, EmpNo, State)", codes(errs))
	}
	// matching ignores case
	if _, errs := goodMapping().AccountRecords(parse(t, "userid,LOGIN,mail,empno,state\nu1,a,,,\n")); len(errs) != 0 {
		t.Errorf("case-insensitive header: %v", codes(errs))
	}
}

func TestAccountRecords_NormalisesAndNeutralises(t *testing.T) {
	recs, errs := goodMapping().AccountRecords(parse(t,
		"UserID,Login,Mail,EmpNo,State\nu1,\"=HYPERLINK(\"\"http://evil\"\")\",Alice@T.Example,e1,Locked\nu2,-2+3,,,\n"))
	if len(errs) != 0 || len(recs) != 2 {
		t.Fatalf("%v", codes(errs))
	}
	f := recs[0].Fields
	if f["username"] != `'=HYPERLINK("http://evil")` || f["email"] != "alice@t.example" || f["status"] != "disabled" || f["identity_id"] != "e1" {
		t.Errorf("fields = %v", f)
	}
	if recs[1].Fields["username"] != "'-2+3" || recs[1].Fields["status"] != "active" {
		t.Errorf("fields = %v", recs[1].Fields)
	}
}

func TestEntitlementRecords(t *testing.T) {
	const head = "UserID,Role,RoleName,Admin\n"
	known := map[string]bool{"u1": true, "u2": true}
	for _, tc := range []struct {
		name string
		csv  string
		want []string
	}{
		{"valid", head + "u1,r1,Role one,yes\nu1,r2,,no\nu2,r1,,\n", nil},
		{"unknown account", head + "u9,r1,,\n", []string{"1:unknown_account"}},
		{"missing entitlement", head + "u1,,,\n", []string{"1:required"}},
		{"formula in entitlement", head + "u1,=r1,,\n", []string{"1:formula_prefix"}},
		{"bad privileged", head + "u1,r1,,perhaps\n", []string{"1:invalid_value"}},
		{"duplicate pair", head + "u1,r1,,\nu1,r1,,yes\n", []string{"2:duplicate_key"}},
		{"wrong column count", head + "u1,r1\n", []string{"1:column_count"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs, errs := goodMapping().EntitlementRecords(parse(t, tc.csv), known)
			if tc.want == nil {
				if len(errs) != 0 || len(recs) != 3 {
					t.Fatalf("got %d records, errors %v", len(recs), codes(errs))
				}
				if recs[1].Fields["name"] != "r2" || recs[0].Fields["privileged"] != "true" || recs[2].Fields["privileged"] != "false" {
					t.Errorf("fields = %v %v %v", recs[0].Fields, recs[1].Fields, recs[2].Fields)
				}
				return
			}
			if got := codes(errs); strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("errors %v, want %v", got, tc.want)
			}
		})
	}
	m := goodMapping()
	m.Entitlements = nil
	if _, errs := m.EntitlementRecords(parse(t, head), known); len(errs) != 1 {
		t.Errorf("mapping without entitlement columns: %v", codes(errs))
	}
}

func rows(recs []flatfile.Record, kind string, uploadID string) []*store.FlatRecord {
	var out []*store.FlatRecord
	for _, r := range recs {
		out = append(out, &store.FlatRecord{System: "hr-app", Kind: kind, Key: r.Key, Data: r.Data(), Hash: r.Hash, UploadID: uploadID})
	}
	return out
}

func TestDiff(t *testing.T) {
	mp := goodMapping()
	const head = "UserID,Login,Mail,EmpNo,State\n"
	v1, _ := mp.AccountRecords(parse(t, head+"u1,a,,,\nu2,b,,,\nu3,c,,,\nu4,d,,,\n"))
	prev := rows(v1, flatfile.KindAccounts, "up1")

	// u1 same, u2 renamed and disabled, u3 gone, u4 same, u5 new
	v2, _ := mp.AccountRecords(parse(t, head+"u5,e,,,\nu2,b2,,,disabled\nu4,d,,,\nu1,a,,,\n"))
	d := flatfile.Diff(flatfile.KindAccounts, prev, v2)
	label := func(cs []flatfile.Change) string {
		var out []string
		for _, c := range cs {
			out = append(out, c.Label+"("+c.Detail+")")
		}
		return strings.Join(out, ",")
	}
	if label(d.Added) != "u5()" || label(d.Removed) != "u3()" || label(d.Changed) != "u2(status, username)" || d.Unchanged != 2 {
		t.Errorf("added %s removed %s changed %s unchanged %d", label(d.Added), label(d.Removed), label(d.Changed), d.Unchanged)
	}
	if got := len(d.All()); got != 3 {
		t.Errorf("All() = %d", got)
	}
	// the same file again: nothing
	if d := flatfile.Diff(flatfile.KindAccounts, rows(v2, flatfile.KindAccounts, "up2"), v2); len(d.All()) != 0 || d.Unchanged != 4 {
		t.Errorf("identical file: %+v", d)
	}
	// from nothing: everything is added, in key order
	d = flatfile.Diff(flatfile.KindAccounts, nil, v1)
	if label(d.Added) != "u1(),u2(),u3(),u4()" {
		t.Errorf("first upload: %s", label(d.Added))
	}
	// entitlement keys read back as "account / entitlement"
	ev, _ := mp.EntitlementRecords(parse(t, "UserID,Role,RoleName,Admin\nu1,r1,,\n"), map[string]bool{"u1": true})
	if d := flatfile.Diff(flatfile.KindEntitlements, rows(ev, flatfile.KindEntitlements, "x"), nil); label(d.Removed) != "u1 / r1()" {
		t.Errorf("removed entitlement label: %s", label(d.Removed))
	}
}
