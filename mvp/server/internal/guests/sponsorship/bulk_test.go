package sponsorship_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const header = "email,given_name,family_name,population,starts_at,ends_at,purpose\n"

func csvRow(email, pop, ends string) string {
	return fmt.Sprintf("%s,Gwen,Guest,%s,,%s,workshop\n", email, pop, ends)
}

func (e *env) bulk(raw string, dry bool) *sponsorship.BulkResult {
	e.t.Helper()
	rows, err := sponsorship.ParseCSV(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	var res *sponsorship.BulkResult
	e.must(func(tx *store.TenantTx) (err error) {
		res, err = e.svc.BulkInvite(tx, e.carol, rows, dry, now)
		return err
	})
	return res
}

func (e *env) count() (n int) {
	e.t.Helper()
	e.must(func(tx *store.TenantTx) error {
		ss, err := tx.Sponsorships(store.SponsorshipFilter{})
		n = len(ss)
		return err
	})
	return n
}

func TestBulkInvite_PerRowResults(t *testing.T) {
	e := newEnv(t)
	prod := e.catalog("group:aws:ProdAdmin", "medium")
	d10, d40 := day(10).Format("2006-01-02"), day(40).Format("2006-01-02")
	row := func(email, pop, ends string) string {
		return csvRow(email, pop, ends)[:len(csvRow(email, pop, ends))-1] + ",\n"
	}
	file := header[:len(header)-1] + ",bundle\n" +
		row("ok1@x.example", "visitor", d10) + // line 2: ok
		row("carol@t.example", "visitor", d10) + // 3: the sponsor herself
		row("ok1@x.example", "visitor", d10) + // 4: the same address twice
		row("late@x.example", "visitor", d40) + // 5: over the visitor maximum
		row("nonsense", "visitor", d10) + // 6: not an email
		row("pop@x.example", "student", d10) + // 7: unknown population
		"baddate@x.example,Gwen,Guest,visitor,,31/12/2026,workshop,\n" + // 8: a date that does not parse
		"short@x.example,Gwen\n" + // 9: too few columns
		row("alice@t.example", "visitor", d10) + // 10: a known person's address: accepted like any
		fmt.Sprintf("big@x.example,Gwen,Guest,contractor,,%s,project,%d\n", d40, prod) // 11: needs a second approver

	dry := e.bulk(file, true)
	if e.count() != 0 {
		t.Fatal("a dry run wrote sponsorships")
	}
	run := e.bulk(file, false)
	if len(dry.Rows) != len(run.Rows) || len(run.Rows) != 10 {
		t.Fatalf("rows: dry %d, run %d", len(dry.Rows), len(run.Rows))
	}
	want := []struct {
		status, code string
	}{
		{"ok", ""}, {"refused", "cannot_sponsor_self"}, {"refused", "duplicate_in_file"}, {"refused", "exceeds_max_duration"},
		{"refused", "invalid_email"}, {"refused", "unknown_population"}, {"refused", "invalid_dates"}, {"refused", "invalid_row"},
		{"ok", ""}, {"needs_approval", ""},
	}
	for i, w := range want {
		d, r := dry.Rows[i], run.Rows[i]
		wantRun := w.status
		if w.status != "refused" {
			wantRun = "created"
		}
		if d.Status != w.status || d.Code != w.code {
			t.Errorf("dry row %d (line %d) = %s %q, want %s %q: %s", i, d.Row, d.Status, d.Code, w.status, w.code, d.Message)
		}
		if r.Status != wantRun || r.Code != w.code {
			t.Errorf("run row %d (line %d) = %s %q, want %s %q: %s", i, r.Row, r.Status, r.Code, wantRun, w.code, r.Message)
		}
		if d.PolicyVersion != e.svc.Policy.Version || r.PolicyVersion != d.PolicyVersion {
			t.Errorf("row %d policy version %q / %q", i, d.PolicyVersion, r.PolicyVersion)
		}
		if (r.Status == "created") != (r.SponsorshipID != "") || d.SponsorshipID != "" {
			t.Errorf("row %d sponsorship ids: dry %q run %q", i, d.SponsorshipID, r.SponsorshipID)
		}
		if i > 0 && d.Row <= dry.Rows[i-1].Row {
			t.Errorf("rows are not in file order: %d after %d", d.Row, dry.Rows[i-1].Row)
		}
	}
	if !run.Rows[9].NeedsApproval || run.Rows[0].NeedsApproval {
		t.Error("needs_approval flags")
	}
	if run.Created != 3 || run.Refused != 7 || dry.WouldCreate != 3 || dry.Refused != 7 || run.BatchID == "" || dry.BatchID != "" {
		t.Errorf("summaries: dry %+v run %+v", dry, run)
	}
	// only the three permitted rows were written, tied to one batch, as bulk intake
	if n := e.count(); n != 3 {
		t.Fatalf("%d sponsorships written", n)
	}
	e.must(func(tx *store.TenantTx) error {
		ss, err := tx.Sponsorships(store.SponsorshipFilter{})
		for _, s := range ss {
			in, ierr := tx.Intake(s.IntakeID)
			if ierr != nil || in.Channel != store.ChannelBulkInvite || in.BatchID == nil || *in.BatchID != run.BatchID ||
				in.MatchMode != store.MatchSelfAsserted {
				t.Errorf("intake = %+v, %v", in, ierr)
			}
		}
		return err
	})
	acts := e.auditActions()
	if acts["sponsorship.create"] != 3 || acts["sponsorship.bulk_invite"] != 1 || acts["sponsorship.bulk_preview"] != 1 {
		t.Errorf("audit = %v", acts)
	}
}

// Row 51 of a visitor file is refused in the preview exactly as the run refuses it.
func TestBulkInvite_LimitsCountRowsBeforeThem(t *testing.T) {
	e := newEnv(t)
	d10 := day(10).Format("2006-01-02")
	var b strings.Builder
	b.WriteString(header)
	for i := 0; i < 52; i++ {
		b.WriteString(csvRow(fmt.Sprintf("v%d@x.example", i), "visitor", d10))
	}
	dry := e.bulk(b.String(), true)
	run := e.bulk(b.String(), false)
	for name, r := range map[string]*sponsorship.BulkResult{"dry": dry, "run": run} {
		if r.Refused != 2 || r.Rows[49].Code != "" || r.Rows[50].Code != "sponsor_limit_reached" || r.Rows[51].Code != "sponsor_limit_reached" {
			t.Errorf("%s: refused %d, rows 50-52 = %q %q %q", name, r.Refused, r.Rows[49].Code, r.Rows[50].Code, r.Rows[51].Code)
		}
	}
	if e.count() != 50 {
		t.Errorf("%d written", e.count())
	}
	// the daily limit counts what the sponsor invited in the last day, across files
	d := e.bulk(header+csvRow("more@x.example", "volunteer", d10), true)
	if d.Rows[0].Code != "daily_invite_limit" {
		t.Errorf("the 51st invitation of the day = %+v", d.Rows[0])
	}
	// ... but not yesterday's
	var later *sponsorship.BulkResult
	rows, _ := sponsorship.ParseCSV(header + csvRow("more@x.example", "volunteer", day(11).Format("2006-01-02")))
	e.must(func(tx *store.TenantTx) (err error) {
		later, err = e.svc.BulkInvite(tx, e.carol, rows, true, now.Add(25*time.Hour))
		return err
	})
	if later.Rows[0].Status != "ok" {
		t.Errorf("a day later = %+v", later.Rows[0])
	}
}

func TestBulkInvite_ParseCSV(t *testing.T) {
	for name, tc := range map[string]struct{ raw, code string }{
		"empty":           {"", "empty_file"},
		"header only":     {header, "empty_file"},
		"wrong header":    {"mail,name\na,b\n", "invalid_header"},
		"missing column":  {"email,given_name,family_name,population,starts_at,ends_at\n", "invalid_header"},
		"extra column":    {strings.TrimSpace(header) + ",password\n", "invalid_header"},
		"too many rows":   {header + strings.Repeat(csvRow("a@x.example", "visitor", "2030-01-01"), 501), "too_many_rows"},
		"broken quoting":  {header + "\"a@x.example,Gwen\n", "invalid_csv"},
		"bom and quoting": {"\ufeff" + header + "\"a@x.example\",\"Gwen\",\"Guest, Jr\",visitor,,2030-01-01,\"a, b\"\n", ""},
		"500 rows":        {header + strings.Repeat(csvRow("a@x.example", "visitor", "2030-01-01"), 500), ""},
	} {
		t.Run(name, func(t *testing.T) {
			rows, err := sponsorship.ParseCSV(tc.raw)
			if code(err) != tc.code {
				t.Fatalf("error = %v, want %q", err, tc.code)
			}
			if tc.code == "" && (len(rows) == 0 || rows[0].Code != "") {
				t.Errorf("rows = %+v", rows)
			}
		})
	}
	rows, _ := sponsorship.ParseCSV("\ufeff" + header + "\"a@x.example\",\"Gwen\",\"Guest, Jr\",VISITOR,2030-01-01,2030-01-09T10:00:00Z,\"a, b\"\n")
	r := rows[0].Invite
	if r.FamilyName != "Guest, Jr" || r.Population != "visitor" || r.Purpose != "a, b" || r.StartsAt.Day() != 1 || r.EndsAt.Hour() != 10 || rows[0].Line != 2 {
		t.Errorf("row = %+v", rows[0])
	}
}

func TestBulkInvite_NeedsASponsorIdentity(t *testing.T) {
	e := newEnv(t)
	rows, _ := sponsorship.ParseCSV(header + csvRow("a@x.example", "visitor", day(5).Format("2006-01-02")))
	err := e.do(func(tx *store.TenantTx) error {
		_, err := e.svc.BulkInvite(tx, e.admin, rows, true, now)
		return err
	})
	e.wantCode(err, "sponsor_identity_required")
}

// The outbox: approvers are asked, the sponsor is told, a transfer target is asked.
func TestSponsorship_Notifications(t *testing.T) {
	e := newEnv(t)
	prod := e.catalog("group:aws:ProdAdmin", "medium")
	user := func(name string, ident *int64, role string) string {
		var id string
		e.must(func(tx *store.TenantTx) error {
			u := &store.PlatformUser{DisplayName: name, IdentityID: ident, CreatedAt: now}
			if err := tx.InsertPlatformUser(u); err != nil {
				return err
			}
			id = u.ID.String()
			if role != "" {
				src := "manual"
				if role == "policy_admin" {
					src = "bootstrap" // admin roles are not assigned by hand
				}
				return tx.InsertRoleAssignment(&store.RoleAssignment{UserID: u.ID, Role: role, Source: src, CreatedAt: now})
			}
			return nil
		})
		return id
	}
	pat := user("Pat", nil, "policy_admin")
	op := user("Olu", nil, "operator") // an operator does not approve sponsorships
	carolU := user("Carol", e.carol.IdentityID, "viewer")
	bobU := user("Bob", e.bob.IdentityID, "viewer")
	e.carol.UserID, e.bob.UserID = uuid.MustParse(carolU), uuid.MustParse(bobU)
	e.admin.UserID = uuid.MustParse(pat)

	in := invite("n@x.example", "contractor", day(60))
	in.Bundle = []int64{prod}
	res := e.invited(e.carol, in)
	kinds := func(u string) (out []string) {
		e.must(func(tx *store.TenantTx) error {
			ns, err := tx.Notifications(u, false, 50)
			for _, n := range ns {
				out = append(out, n.Kind)
			}
			return err
		})
		return out
	}
	if k := kinds(pat); len(k) != 1 || k[0] != "sponsorship.approval_needed" {
		t.Errorf("approver notifications = %v", k)
	}
	if k := kinds(op); len(k) != 0 {
		t.Errorf("an operator was asked to approve: %v", k)
	}
	if k := kinds(carolU); len(k) != 0 {
		t.Errorf("the requester was asked to approve: %v", k)
	}
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.Approve(tx, e.admin, res.Sponsorship.ID, now)
		return err
	})
	if k := kinds(carolU); len(k) != 1 || k[0] != "sponsorship.decided" {
		t.Errorf("sponsor notifications = %v", k)
	}
	if k := kinds(pat); len(k) != 1 {
		t.Errorf("the approver told of their own decision: %v", k)
	}
	rej := e.invited(e.carol, in)
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.Reject(tx, e.admin, rej.Sponsorship.ID, "no budget", now)
		return err
	})
	if k := kinds(carolU); len(k) != 2 {
		t.Errorf("after the rejection: %v", k)
	}
	e.must(func(tx *store.TenantTx) error {
		_, err := e.svc.Transfer(tx, e.carol, res.Sponsorship.ID, e.f.B.IDs["bob"], "leaving", now)
		return err
	})
	if k := kinds(bobU); len(k) != 1 || k[0] != "sponsorship.transfer" {
		t.Errorf("target notifications = %v", k)
	}
}
