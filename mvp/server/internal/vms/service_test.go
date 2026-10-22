package vms_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vms/vmsfake"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/vms"
)

var now = storetest.Now

type rig struct {
	t      *testing.T
	f      *storetest.Fixture
	svc    *vms.Service
	fake   *vmsfake.Fake
	srv    *connsynctest.Server
	sealer *seal.Sealer
	ctx    context.Context
}

func newRig(t *testing.T) *rig {
	f := storetest.TwoTenants(t)
	fk := vmsfake.New("fieldglass", "client-1", "s3cret-value")
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, f: f, fake: fk, srv: srv, sealer: sealer, ctx: audit.WithSystemActor(context.Background(), "vms.sync")}
	r.svc = &vms.Service{DB: f.DB, Sealer: sealer, HTTP: hc, RT: connsynctest.Runtime, Keyer: storetest.IdentityKeyer(t),
		Clock: func() time.Time { return now }}
	r.do(func(c *store.TenantTx) error {
		for _, e := range []struct{ x, mail string }{{"emp-1", "dana@corp.example"}, {"emp-2", "lee@corp.example"}} {
			m := e.mail
			if _, err := c.InsertIdentity(&store.Identity{ExternalID: e.x, Name: e.x, Email: &m, Type: "human", Status: "active", CreatedAt: now}); err != nil {
				return err
			}
		}
		return nil
	})
	return r
}

func (r *rig) do(fn func(c *store.TenantTx) error) {
	r.t.Helper()
	if err := r.f.DB.InTenant(r.ctx, r.f.B.ID, fn); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) addSource(id, vendor, base, settings, credential string) {
	r.t.Helper()
	enc, err := vms.SealCredential(r.sealer, r.f.B.ID, id, credential)
	if err != nil {
		r.t.Fatal(err)
	}
	ver := "v1"
	r.do(func(c *store.TenantTx) error {
		return c.InsertVmsSource(&store.VmsSource{ID: id, Vendor: vendor, Name: id, BaseURL: base, Settings: settings,
			CredentialEnc: enc, CredentialVer: &ver, Status: store.VmsActive, CreatedBy: "test"}, now)
	})
}

func (r *rig) source(id string) *store.VmsSource {
	r.t.Helper()
	var s *store.VmsSource
	r.do(func(c *store.TenantTx) (err error) { s, err = c.VmsSource(id); return })
	return s
}

func ws() []vmsfake.Worker {
	return []vmsfake.Worker{
		{ID: "W-1", First: "Casey", Last: "Contractor", Email: "casey@agency.example", Status: "Active", Start: "2026-09-01",
			End: now.AddDate(0, 0, 60).Format("2006-01-02"), Supplier: "Acme", ManagerEmail: "dana@corp.example", Modified: now.Add(-48 * time.Hour)},
		{ID: "W-2", First: "Robin", Last: "Temp", Email: "robin@agency.example", Status: "Active", Start: "2026-09-01",
			End: now.AddDate(0, 0, 30).Format("2006-01-02"), Supplier: "Acme", ManagerID: "emp-2", Modified: now.Add(-24 * time.Hour)},
		{ID: "W-3", First: "Sam", Last: "NoBoss", Email: "sam@agency.example", Status: "Active", Start: "2026-09-01",
			End: now.AddDate(0, 0, 30).Format("2006-01-02"), Supplier: "Acme", Modified: now.Add(-1 * time.Hour)},
	}
}

func contractors(t *testing.T, r *rig) map[string]*store.Lifecycle {
	out := map[string]*store.Lifecycle{}
	r.do(func(c *store.TenantTx) error {
		all, err := c.Lifecycles()
		if err != nil {
			return err
		}
		for _, l := range all {
			if l.WorkerType == store.WorkerContractor {
				p, _ := c.Identity(l.IdentityID)
				out[p.ExternalID] = l
			}
		}
		return nil
	})
	return out
}

func TestSync_FieldglassCreatesContractorsAndKeepsAWatermark(t *testing.T) {
	r := newRig(t)
	r.fake.Set(ws()...)
	r.addSource("fg", store.VmsFieldglass, r.srv.URL, "{}", "client-1:s3cret-value")

	reps, err := r.svc.Sync(r.ctx, r.f.B.ID)
	if err != nil || len(reps) != 1 {
		t.Fatalf("Sync = %v, %v", reps, err)
	}
	rep := reps[0]
	if rep.Status != vms.StatusOK || rep.Records != 3 || rep.Applied["created"] != 2 || rep.Applied["review"] != 1 {
		t.Fatalf("report = %+v", rep)
	}
	got := contractors(t, r)
	if len(got) != 2 || got["vms-fieldglass-W-1"] == nil || got["vms-fieldglass-W-2"] == nil || got["vms-fieldglass-W-3"] != nil {
		t.Fatalf("contractors = %v (a worker without a sponsor must not exist)", got)
	}
	src := r.source("fg")
	if src.LastResult == nil || *src.LastResult != "ok" || src.Cursor == nil || !src.Cursor.Equal(now.Add(-time.Hour)) ||
		!strings.Contains(src.LastCounts, `"created":2`) {
		t.Errorf("source = %+v", src)
	}
	// the next sync asks only for what changed since the watermark
	if reps, _ = r.svc.Sync(r.ctx, r.f.B.ID); reps[0].Records != 0 {
		t.Errorf("second sync read %d records", reps[0].Records)
	}
	if q := r.fake.Queries(); !strings.Contains(q[len(q)-1], "modified_after") {
		t.Errorf("last query %q has no watermark", q[len(q)-1])
	}
	// the vendor gives the third worker a sponsor and extends the first
	w := ws()
	w[0].End, w[0].Modified = now.AddDate(0, 0, 90).Format("2006-01-02"), now.Add(time.Minute)
	w[2].ManagerEmail, w[2].Modified = "lee@corp.example", now.Add(2*time.Minute)
	r.fake.Set(w...)
	reps, _ = r.svc.Sync(r.ctx, r.f.B.ID)
	if reps[0].Records != 2 || reps[0].Applied["started"] != 1 || reps[0].Applied["created"] != 1 {
		t.Errorf("third sync = %+v", reps[0])
	}
	if l := contractors(t, r)["vms-fieldglass-W-1"]; !l.EndsAt.Equal(now.AddDate(0, 0, 90).Truncate(24 * time.Hour)) {
		t.Errorf("W-1 ends %v", l.EndsAt)
	}
	// the end date drives the leaver plan: past it, the sweep ends the term
	r.do(func(c *store.TenantTx) error {
		res, err := lifecycle.Sweep(c, now.AddDate(0, 0, 45))
		if err != nil || res.Ended != 2 {
			t.Errorf("Sweep = %+v, %v; want W-2 and W-3 ended", res, err)
		}
		return nil
	})
	r.do(func(c *store.TenantTx) error {
		n, err := c.IntakeEventsByChannel(store.ChannelVMS, 100)
		if err != nil || len(n) < 5 {
			t.Errorf("vms intake events = %d, %v", len(n), err)
		}
		return nil
	})
}

func TestSync_FailureKeepsTheWatermarkAndHidesSecrets(t *testing.T) {
	r := newRig(t)
	r.fake.Set(ws()...)
	r.addSource("fg", store.VmsFieldglass, r.srv.URL, "{}", "client-1:s3cret-value")
	if _, err := r.svc.Sync(r.ctx, r.f.B.ID); err != nil {
		t.Fatal(err)
	}
	before := r.source("fg").Cursor

	r.fake.SetFaults(vmsfake.Faults{ListStatus: 500})
	reps, err := r.svc.Sync(r.ctx, r.f.B.ID)
	if err != nil || reps[0].Status != vms.StatusFailed {
		t.Fatalf("Sync = %+v, %v", reps, err)
	}
	src := r.source("fg")
	if src.LastResult == nil || *src.LastResult != "failed" || src.LastError == nil || !src.Cursor.Equal(*before) {
		t.Errorf("source = %+v", src)
	}
	for _, leak := range []string{"s3cret", "leaky", "tok-fieldglass"} {
		if strings.Contains(reps[0].Error, leak) || strings.Contains(*src.LastError, leak) {
			t.Errorf("the error carries %q: %q", leak, reps[0].Error)
		}
	}
	// a wrong secret is a failed sync, not a crash
	r.fake.SetFaults(vmsfake.Faults{})
	r.addSource("bad", store.VmsFieldglass, r.srv.URL, "{}", "client-1:wrong")
	reps, _ = r.svc.Sync(r.ctx, r.f.B.ID, "bad")
	if len(reps) != 1 || reps[0].Status != vms.StatusFailed || strings.Contains(reps[0].Error, "wrong") {
		t.Errorf("wrong secret = %+v", reps)
	}
}

func TestSync_CredentialIsBoundToItsSourceAndTenant(t *testing.T) {
	r := newRig(t)
	r.fake.Set(ws()...)
	r.addSource("fg", store.VmsFieldglass, r.srv.URL, "{}", "client-1:s3cret-value")
	// a blob sealed for another source cannot be moved onto this one
	other, _ := vms.SealCredential(r.sealer, r.f.B.ID, "elsewhere", "client-1:s3cret-value")
	src := r.source("fg")
	src.CredentialEnc = other
	r.do(func(c *store.TenantTx) error { return c.UpdateVmsSource(src, now) })
	reps, _ := r.svc.Sync(r.ctx, r.f.B.ID)
	if reps[0].Status != vms.StatusFailed || !strings.Contains(reps[0].Error, "cannot be opened") {
		t.Errorf("report = %+v", reps[0])
	}
	if tok, _ := r.fake.Counts(); tok != 0 {
		t.Error("a request went out with a credential that did not open")
	}
	// another tenant's sync sees none of this tenant's sources
	if reps, err := r.svc.Sync(r.ctx, r.f.A.ID); err != nil || len(reps) != 0 {
		t.Errorf("tenant A synced %v, %v", reps, err)
	}
}

func TestSync_PausedAndUploadOnlySourcesAreSkipped(t *testing.T) {
	r := newRig(t)
	r.addSource("paused", store.VmsFieldglass, r.srv.URL, "{}", "client-1:s3cret-value")
	r.addSource("file", store.VmsCSV, "", "{}", "")
	src := r.source("paused")
	src.Status = store.VmsPaused
	r.do(func(c *store.TenantTx) error { return c.UpdateVmsSource(src, now) })
	reps, err := r.svc.Sync(r.ctx, r.f.B.ID)
	if err != nil || len(reps) != 2 || reps[0].Status != vms.StatusSkipped || reps[1].Status != vms.StatusSkipped {
		t.Errorf("reports = %+v, %v", reps, err)
	}
	if tok, lists := r.fake.Counts(); tok+lists != 0 {
		t.Error("a skipped source made a request")
	}
}

func TestImport_CSV(t *testing.T) {
	r := newRig(t)
	r.addSource("file", store.VmsCSV, "", "{}", "")
	end := now.AddDate(0, 0, 40).Format("2006-01-02")
	file := "worker_id,name,email,supplier,sponsor_email,status,end_date\n" +
		"C-1,Casey Contractor,casey@agency.example,Acme,dana@corp.example,active," + end + "\n" +
		"C-2,Robin Temp,robin@agency.example,Acme,,active," + end + "\n" +
		"C-3,Sam NoEnd,sam@agency.example,Acme,dana@corp.example,active,\n"
	rep, err := r.svc.Import(r.ctx, r.f.B.ID, "file", strings.NewReader(file))
	if err != nil || rep.Records != 3 || rep.Applied["created"] != 1 || rep.Applied["review"] != 1 || rep.Applied["rejected"] != 1 {
		t.Fatalf("report = %+v, %v", rep, err)
	}
	// the same file again changes nothing
	rep, err = r.svc.Import(r.ctx, r.f.B.ID, "file", strings.NewReader(file))
	if err != nil || rep.Applied["duplicate"] != 3 {
		t.Errorf("replay = %+v, %v", rep, err)
	}
	if _, err := r.svc.Import(r.ctx, r.f.B.ID, "file", strings.NewReader("junk")); err == nil {
		t.Error("an unreadable file was accepted")
	}
	r.addSource("fg", store.VmsFieldglass, r.srv.URL, "{}", "client-1:s3cret-value")
	if _, err := r.svc.Import(r.ctx, r.f.B.ID, "fg", strings.NewReader(file)); err == nil {
		t.Error("a file was accepted for a REST source")
	}
	if _, err := r.svc.Import(r.ctx, r.f.A.ID, "file", strings.NewReader(file)); err == nil {
		t.Error("tenant A imported into tenant B's source")
	}
}

// The leavers a contractor feed ends are judged under that feed's own deletion guard settings: with a
// threshold of 1 an import that ends four contractors applies one and holds three (the default
// threshold of the small tenant would let all four through).
func TestImport_EndedContractorsAreHeldUnderTheFeedsOwnThreshold(t *testing.T) {
	r := newRig(t)
	r.addSource("file", store.VmsCSV, "", "{}", "")
	end := now.AddDate(0, 0, 40).Format("2006-01-02")
	file := func(status string) string {
		s := "worker_id,name,email,supplier,sponsor_email,status,end_date\n"
		for _, w := range []string{"C-1", "C-2", "C-3", "C-4"} {
			s += w + ",Person " + w + "," + strings.ToLower(w) + "@agency.example,Acme,dana@corp.example," + status + "," + end + "\n"
		}
		return s
	}
	if rep, err := r.svc.Import(r.ctx, r.f.B.ID, "file", strings.NewReader(file("active"))); err != nil || rep.Applied["created"] != 4 {
		t.Fatalf("create = %+v, %v", rep, err)
	}
	one := 1
	r.do(func(c *store.TenantTx) error {
		return deleteguard.SetSource(c, deleteguard.SourcePolicy{Kind: deleteguard.SrcVMS, SourceID: "file", Category: deleteguard.CatIdentities,
			Mode: deleteguard.ModeHoldExcess, MaxCount: &one, WindowMinutes: 60}, nil, now)
	})
	if rep, err := r.svc.Import(r.ctx, r.f.B.ID, "file", strings.NewReader(file("ended"))); err != nil || rep.Records != 4 {
		t.Fatalf("end = %+v, %v", rep, err)
	}
	r.do(func(c *store.TenantTx) error {
		ended := 0
		all, err := c.Lifecycles()
		if err != nil {
			return err
		}
		for _, l := range all {
			if p, err := c.Identity(l.IdentityID); err != nil {
				return err
			} else if l.WorkerType == store.WorkerContractor && p.Status != "active" {
				ended++
			}
		}
		if ended != 1 {
			t.Errorf("%d contractors ended, want the 1 the feed's threshold allows", ended)
		}
		hs, err := c.DeletionHolds("held", "identities", 10, 0)
		if err != nil || len(hs) != 1 || hs[0].ItemCount != 3 || !strings.Contains(hs[0].Reason, `"source_override":true`) ||
			!strings.Contains(hs[0].Reason, `"source_ref":"file"`) {
			t.Errorf("holds = %+v, %v", hs, err)
		}
		return nil
	})
}
