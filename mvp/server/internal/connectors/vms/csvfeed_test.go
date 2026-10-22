package vms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const goodCSV = "\xef\xbb\xbfworker_id,first_name,last_name,email,supplier,role,sponsor_email,sponsor_employee_id,status,start_date,end_date\n" +
	"C-1,Casey,Contractor,casey@agency.example,Acme,Analyst,dana@corp.example,,Active,2026-09-01,2026-12-31\n" +
	"\n" +
	"C-2,Robin,Temp,robin@agency.example,Acme,Tester,,emp-7,pending start,2026-11-01,2027-02-01\n" +
	"C-3,Sam,Done,sam@agency.example,Other,Dev,dana@corp.example,,Completed,2026-01-01,2026-09-30\n" +
	"C-4,Lee,NoEnd,lee@agency.example,Other,Dev,dana@corp.example,,,,\n"

func TestParseCSV(t *testing.T) {
	res, err := ParseCSV(strings.NewReader(goodCSV), Settings{}, t0)
	if err != nil || len(res.Records) != 4 || res.BadRows != 0 {
		t.Fatalf("res = %+v, %v", res, err)
	}
	a, b, c, d := res.Records[0], res.Records[1], res.Records[2], res.Records[3]
	if a.System != "csv" || a.Name != "Casey Contractor" || a.Status != connectors.VmsActive || a.SponsorEmail != "dana@corp.example" ||
		a.EndsAt == nil || a.EndsAt.Format("2006-01-02") != "2026-12-31" || !a.UpdatedAt.Equal(t0) {
		t.Errorf("row 1 = %+v", a)
	}
	if b.Status != connectors.VmsPending || b.SponsorEmployeeID != "emp-7" || c.Status != connectors.VmsEnded {
		t.Errorf("rows 2, 3 = %+v, %+v", b, c)
	}
	if d.EndsAt != nil || d.Status != connectors.VmsActive {
		t.Errorf("row 4 = %+v", d) // read as is: the intake rejects a record without an end date
	}
	// the same file imported later reads as the same versions; a changed row has a new id
	later, _ := ParseCSV(strings.NewReader(strings.Replace(goodCSV, "2026-12-31", "2027-01-31", 1)), Settings{}, t0.Add(time.Hour))
	if later.Records[0].EventID == a.EventID || later.Records[1].EventID != b.EventID {
		t.Error("event ids do not follow the facts")
	}
}

func TestParseCSVMappingAndDates(t *testing.T) {
	file := "Contractor No;Full Name;Work Email;Manager Email;Finish\n"
	file = strings.ReplaceAll(file, ";", ",") + "77,Kim Lo,kim@agency.example,dana@corp.example,31/12/2026\n"
	set := Settings{DateFormat: "02/01/2006", Mapping: map[string]string{"worker_id": "Contractor No", "name": "Full Name",
		"email": "Work Email", "sponsor_email": "Manager Email", "end_date": "Finish"}}
	if err := set.Validate("csv"); err != nil {
		t.Fatal(err)
	}
	res, err := ParseCSV(strings.NewReader(file), set, t0)
	if err != nil || len(res.Records) != 1 {
		t.Fatalf("res = %+v, %v", res, err)
	}
	if r := res.Records[0]; r.WorkerID != "77" || r.Name != "Kim Lo" || r.EndsAt == nil || r.EndsAt.Format("2006-01-02") != "2026-12-31" {
		t.Errorf("record = %+v", r)
	}
}

func TestParseCSVRefusesBadFiles(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"no worker column": "email,name\na@b.example,A\n",
		"no email column":  "worker_id,name\n1,A\n",
		"no name column":   "worker_id,email\n1,a@b.example\n",
		"binary":           "worker_id,email,name\n1,a@b.example,\x00A\n",
		"not utf-8":        "worker_id,email,name\n1,a@b.example,\xff\xfe\n",
		"a stray quote":    "worker_id,email,name\n1,a@b.example,A\"B\n",
		"too many rows":    "worker_id,email,name\n" + strings.Repeat("1,a@b.example,A\n", MaxCSVRows+1),
		"a file too large": "worker_id,email,name\n" + strings.Repeat("x", MaxCSVBytes),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCSV(strings.NewReader(in), Settings{}, t0); !errors.Is(err, ErrCSV) {
				t.Errorf("err = %v, want ErrCSV", err)
			}
		})
	}
}

func TestSettingsValidate(t *testing.T) {
	bad := []Settings{
		{Mapping: map[string]string{"nope": "x"}},
		{Mapping: map[string]string{"email": " "}},
		{DateFormat: "not a layout"},
		{CSVPath: "relative"},
		{WorkersPath: "/x"},
	}
	for i, s := range bad {
		if err := s.Validate("csv"); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestFetchCSV(t *testing.T) {
	var auth string
	srv := connsynctest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/feeds/contractors.csv" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		fmt.Fprint(w, goodCSV)
	}))
	hc, err := safehttp.NewForTest(t, srv.Options(0))
	if err != nil {
		t.Fatal(err)
	}
	f := &CSVFetcher{URL: srv.URL + "/feeds/contractors.csv", Token: connsync.NewSecret("tok-123"), HC: hc, Now: func() time.Time { return t0 }}
	res, err := f.Fetch(context.Background())
	if err != nil || len(res.Records) != 4 || auth != "Bearer tok-123" {
		t.Fatalf("res %v, err %v, auth %q", res, err, auth)
	}
	f.URL = srv.URL + "/missing.csv"
	if _, err := f.Fetch(context.Background()); connsync.Status(err) != 404 {
		t.Errorf("err = %v, want 404", err)
	}
}
