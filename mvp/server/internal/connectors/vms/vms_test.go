package vms

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/vms/vmsfake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const credential = "client-1:s3cret-value"

func workers() []vmsfake.Worker {
	return []vmsfake.Worker{
		{ID: "W-1", First: "Casey", Last: "Contractor", Email: "casey@agency.example", Status: "Active", Start: "2026-09-01", End: "2026-12-31",
			Supplier: "Acme Staffing", Role: "Analyst", ManagerEmail: "dana@corp.example", ManagerID: "emp-1", Modified: t0.Add(-48 * time.Hour)},
		{ID: "W-2", First: "Robin", Last: "Temp", Email: "robin@agency.example", Status: "Pending Start", Start: "2026-11-01", End: "2027-02-01",
			Supplier: "Acme Staffing", Role: "Tester", ManagerEmail: "lee@corp.example", Modified: t0.Add(-24 * time.Hour)},
		{ID: "W-3", First: "Sam", Last: "Done", Email: "sam@agency.example", Status: "Terminated", Start: "2026-01-01", End: "2026-09-30",
			Supplier: "Other Co", Role: "Dev", ManagerEmail: "dana@corp.example", Modified: t0.Add(-1 * time.Hour)},
	}
}

type rig struct {
	srv  *connsynctest.Server
	fake *vmsfake.Fake
	conn connectors.VmsConnector
	ns   *connsynctest.NoSleep
}

func newRig(t *testing.T, vendor string) *rig {
	t.Helper()
	fk := vmsfake.New(vendor, "client-1", "s3cret-value")
	fk.Set(workers()...)
	srv := connsynctest.New(t, fk)
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Vendor: vendor, BaseURL: srv.URL, Credential: credential}, connsynctest.Runtime, hc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	ns := &connsynctest.NoSleep{}
	b := connsync.Backoff{Base: time.Millisecond, Max: time.Second, Sleep: ns.Sleep}
	switch x := c.(type) {
	case *Fieldglass:
		x.api.Backoff = b
	case *Beeline:
		x.api.Backoff = b
	}
	return &rig{srv: srv, fake: fk, conn: c, ns: ns}
}

func (r *rig) read(since *time.Time) ([]*connectors.VmsRecord, error) {
	var out []*connectors.VmsRecord
	err := r.conn.VmsRecords(context.Background(), since, func(x *connectors.VmsRecord) error {
		out = append(out, x)
		return nil
	})
	return out, err
}

// The two REST vendors yield the same records from the same data: this is the
// contract the intake relies on.
func TestRESTVendorsYieldTheSameRecords(t *testing.T) {
	for _, vendor := range []string{store.VmsFieldglass, store.VmsBeeline} {
		t.Run(vendor, func(t *testing.T) {
			r := newRig(t, vendor)
			recs, err := r.read(nil)
			if err != nil || len(recs) != 3 {
				t.Fatalf("records = %d, %v", len(recs), err)
			}
			if tok, lists := r.fake.Counts(); tok != 1 || lists != 2 {
				t.Errorf("token requests %d, listings %d; want 1 token and 2 pages", tok, lists)
			}
			a, b, c := recs[0], recs[1], recs[2]
			if a.System != vendor || a.WorkerID != "W-1" || a.Name != "Casey Contractor" || a.Email != "casey@agency.example" ||
				a.Supplier != "Acme Staffing" || a.Role != "Analyst" || a.SponsorEmail != "dana@corp.example" ||
				a.SponsorEmployeeID != "emp-1" || a.Status != connectors.VmsActive {
				t.Errorf("record 1 = %+v", a)
			}
			if a.EndsAt == nil || !a.EndsAt.Equal(time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)) || a.StartsAt == nil ||
				!a.UpdatedAt.Equal(t0.Add(-48*time.Hour)) {
				t.Errorf("record 1 dates = %v %v %v", a.StartsAt, a.EndsAt, a.UpdatedAt)
			}
			if b.Status != connectors.VmsPending || c.Status != connectors.VmsEnded {
				t.Errorf("statuses = %s, %s", b.Status, c.Status)
			}
			ids := map[string]bool{}
			for _, x := range recs {
				if x.EventID == "" || ids[x.EventID] {
					t.Errorf("event id %q is empty or repeated", x.EventID)
				}
				ids[x.EventID] = true
			}
			// the same data read again has the same event ids; a changed record has a new one
			again, _ := r.read(nil)
			if again[0].EventID != a.EventID {
				t.Error("an unchanged record changed its event id")
			}
			w := workers()
			w[0].End = "2027-01-31"
			w[0].Modified = t0
			r.fake.Set(w...)
			changed, _ := r.read(nil)
			if changed[0].EventID == a.EventID {
				t.Error("a changed record kept its event id")
			}
		})
	}
}

func TestIncrementalReadSendsTheWatermark(t *testing.T) {
	for _, vendor := range []string{store.VmsFieldglass, store.VmsBeeline} {
		t.Run(vendor, func(t *testing.T) {
			r := newRig(t, vendor)
			since := t0.Add(-30 * time.Hour)
			recs, err := r.read(&since)
			if err != nil || len(recs) != 2 || recs[0].WorkerID != "W-2" {
				t.Fatalf("records = %v, %v", recs, err)
			}
			if q := r.fake.Queries()[0]; !strings.Contains(q, "modified_") {
				t.Errorf("first query %q has no watermark", q)
			}
		})
	}
}

func TestRESTFaults(t *testing.T) {
	cases := []struct {
		name   string
		faults vmsfake.Faults
		check  func(t *testing.T, r *rig, recs []*connectors.VmsRecord, err error)
	}{
		{"token refused", vmsfake.Faults{TokenStatus: 401}, func(t *testing.T, _ *rig, _ []*connectors.VmsRecord, err error) {
			if connsync.Status(err) != 401 {
				t.Errorf("err = %v, want a 401", err)
			}
		}},
		{"throttled then served", vmsfake.Faults{Throttle: 2}, func(t *testing.T, r *rig, recs []*connectors.VmsRecord, err error) {
			if err != nil || len(recs) != 3 || len(r.ns.Waits) < 2 {
				t.Errorf("recs %d, err %v, waits %v", len(recs), err, r.ns.Waits)
			}
		}},
		{"server error", vmsfake.Faults{ListStatus: 500}, func(t *testing.T, _ *rig, _ []*connectors.VmsRecord, err error) {
			if connsync.Status(err) != 500 || strings.Contains(err.Error(), "leaky") {
				t.Errorf("err = %v", err)
			}
		}},
		{"not json", vmsfake.Faults{Malformed: true}, func(t *testing.T, _ *rig, _ []*connectors.VmsRecord, err error) {
			if !errors.Is(err, connsync.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		}},
		{"next page on another host", vmsfake.Faults{NextOffOrigin: true}, func(t *testing.T, _ *rig, _ []*connectors.VmsRecord, err error) {
			if err == nil || !strings.Contains(err.Error(), "leaves the configured host") {
				t.Errorf("err = %v", err)
			}
		}},
		{"pages that loop", vmsfake.Faults{LoopForever: true}, func(t *testing.T, _ *rig, _ []*connectors.VmsRecord, err error) {
			if !errors.Is(err, connsync.ErrPaging) {
				t.Errorf("err = %v, want ErrPaging", err)
			}
		}},
		{"token of another type", vmsfake.Faults{WrongTokenType: true}, func(t *testing.T, _ *rig, _ []*connectors.VmsRecord, err error) {
			if err == nil || !strings.Contains(err.Error(), "no bearer token") {
				t.Errorf("err = %v", err)
			}
		}},
	}
	for _, vendor := range []string{store.VmsFieldglass, store.VmsBeeline} {
		for _, tc := range cases {
			t.Run(vendor+"/"+tc.name, func(t *testing.T) {
				r := newRig(t, vendor)
				r.fake.SetFaults(tc.faults)
				recs, err := r.read(nil)
				tc.check(t, r, recs, err)
				if err != nil && strings.Contains(err.Error(), "s3cret") {
					t.Error("the error carries the secret")
				}
			})
		}
	}
}

func TestWrongCredentialIsRefused(t *testing.T) {
	r := newRig(t, store.VmsFieldglass)
	fg := r.conn.(*Fieldglass)
	_, secret, _ := ParseCredential("client-1:wrong")
	fg.tok = newTokenSource("client-1", secret, fg.base.String()+"/api/oauth2/v2.0/token", fg.api, func() time.Time { return t0 })
	fg.api.Authorize = fg.tok.authorization
	if _, err := r.read(nil); connsync.Status(err) != http.StatusUnauthorized {
		t.Errorf("err = %v, want 401", err)
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	hc, _ := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	rt := connsync.Runtime{Env: "prod"}
	good := Config{Vendor: store.VmsFieldglass, BaseURL: "https://fg.example.com", Credential: credential}
	cases := map[string]func(c *Config){
		"http in prod":        func(c *Config) { c.BaseURL = "http://fg.example.com" },
		"a path in the URL":   func(c *Config) { c.BaseURL = "https://fg.example.com/api" },
		"an IP literal":       func(c *Config) { c.BaseURL = "https://10.0.0.1" },
		"no credential":       func(c *Config) { c.Credential = "" },
		"a bare token":        func(c *Config) { c.Credential = "abc" },
		"a traversal path":    func(c *Config) { c.Settings.WorkersPath = "/api/../admin" },
		"a csv-only setting":  func(c *Config) { c.Settings.DateFormat = "2006-01-02" },
		"a huge page":         func(c *Config) { c.Settings.PageSize = 5000 },
		"csv is not REST":     func(c *Config) { c.Vendor = store.VmsCSV },
		"a vendor of its own": func(c *Config) { c.Vendor = "workday" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := good
			mut(&c)
			if _, err := New(c, rt, hc, nil); err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := New(good, rt, hc, nil); err != nil {
		t.Errorf("good config refused: %v", err)
	}
	if _, err := New(good, rt, nil, nil); err == nil {
		t.Error("accepted without a safehttp client")
	}
}

// A mapping takes a custom field from the worker's own JSON in place of the documented one, and without a
// mapping nothing changes (the event ids of existing sources stay as they were).
func TestRESTFieldMapping(t *testing.T) {
	custom := func(ws []vmsfake.Worker) []vmsfake.Worker {
		ws[0].Custom = map[string]any{"sponsor": map[string]any{"mail": "erin@corp.example", "emp": 4711}, "term_end": "2027-03-31", "active": true,
			"blank": "", "obj": map[string]any{"x": 1}}
		ws[0].ManagerEmail, ws[0].ManagerID = "", ""
		return ws
	}
	for _, vendor := range []string{store.VmsFieldglass, store.VmsBeeline} {
		t.Run(vendor, func(t *testing.T) {
			fk := vmsfake.New(vendor, "client-1", "s3cret-value")
			fk.Set(custom(workers())...)
			srv := connsynctest.New(t, fk)
			hc, err := safehttp.NewForTest(t, srv.Options(0))
			if err != nil {
				t.Fatal(err)
			}
			read := func(m map[string]string) []*connectors.VmsRecord {
				t.Helper()
				c, err := New(Config{Vendor: vendor, BaseURL: srv.URL, Credential: credential, Settings: Settings{Mapping: m}}, connsynctest.Runtime, hc, func() time.Time { return t0 })
				if err != nil {
					t.Fatal(err)
				}
				var out []*connectors.VmsRecord
				if err := c.VmsRecords(context.Background(), nil, func(x *connectors.VmsRecord) error { out = append(out, x); return nil }); err != nil {
					t.Fatal(err)
				}
				return out
			}
			plain := read(nil)
			if plain[0].SponsorEmail != "" || plain[0].SponsorEmployeeID != "" {
				t.Fatalf("unmapped record has a sponsor: %+v", plain[0])
			}
			mapped := read(map[string]string{"sponsor_email": "custom_fields.sponsor.mail", "sponsor_employee_id": "custom_fields.sponsor.emp",
				"end_date": "custom_fields.term_end", "role": "custom_fields.blank", "supplier": "custom_fields.obj", "status": "custom_fields.nope"})
			a := mapped[0]
			if a.SponsorEmail != "erin@corp.example" || a.SponsorEmployeeID != "4711" || a.EndsAt == nil ||
				!a.EndsAt.Equal(time.Date(2027, 3, 31, 0, 0, 0, 0, time.UTC)) {
				t.Errorf("mapped record = %+v", a)
			}
			// an empty, missing or non-plain value leaves the documented field
			if a.Role != "Analyst" || a.Supplier != "Acme Staffing" || a.Status != connectors.VmsActive {
				t.Errorf("fallbacks: role %q supplier %q status %q", a.Role, a.Supplier, a.Status)
			}
			if a.EventID == plain[0].EventID {
				t.Error("a mapped sponsor kept the event id of the unmapped record")
			}
			if again := read(nil); again[0].EventID != plain[0].EventID || again[1].EventID != plain[1].EventID {
				t.Error("reading without a mapping changed event ids")
			}
			// records without the custom field are untouched by a mapping
			if mapped[1].SponsorEmail != "lee@corp.example" || mapped[1].EventID != plain[1].EventID {
				t.Errorf("record 2 changed: %+v", mapped[1])
			}
		})
	}
}

func TestMappingValidation(t *testing.T) {
	ok := Settings{Mapping: map[string]string{"sponsor_email": "custom_fields.sponsor.mail", "end_date": "term_end"}}
	if err := ok.Validate(store.VmsFieldglass); err != nil {
		t.Errorf("good REST mapping refused: %v", err)
	}
	for name, m := range map[string]map[string]string{
		"first_name": {"first_name": "fn"}, "a path with a space": {"email": "custom fields.mail"}, "a leading dot": {"email": ".mail"},
		"brackets": {"email": "a[0].b"}, "too deep": {"email": "a.b.c.d.e.f.g"}, "an unknown field": {"nope": "x"},
	} {
		if err := (&Settings{Mapping: m}).Validate(store.VmsBeeline); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (&Settings{DateFormat: "2006-01-02"}).Validate(store.VmsFieldglass); err == nil {
		t.Error("date_format on a REST vendor was accepted")
	}
}
