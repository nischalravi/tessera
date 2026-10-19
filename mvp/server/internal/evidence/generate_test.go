package evidence_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/evidence"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

func h(n float64) time.Time { return testkit.Now.Add(time.Duration(n * float64(time.Hour))) }

func unzip(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		if out[f.Name], err = io.ReadAll(rc); err != nil {
			t.Fatal(err)
		}
		_ = rc.Close()
	}
	return out
}

func records(t *testing.T, b []byte) []map[string]string {
	t.Helper()
	rows, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]string
	for _, r := range rows[1:] {
		m := map[string]string{}
		for i, name := range rows[0] {
			m[name] = r[i]
		}
		out = append(out, m)
	}
	return out
}

// seedLeaver: dave (terminated, with an Okta account and an AWS account) is
// the subject of a leaver event effective at +1h; his Okta grant is revoked at
// +2.5h and his AWS grant is left in place.
func seedLeaver(t *testing.T, st *testkit.DB, ids testkit.IDs) {
	t.Helper()
	testkit.Write(t, st, func(c *store.TenantTx) error {
		dave := ids["dave"]
		if _, err := c.InsertHrisEvent(&store.HrisEvent{ExternalID: "EV-DAVE", Type: "leaver", IdentityID: &dave,
			Payload: ojson.Object{}, EffectiveAt: h(1), Status: "pending"}); err != nil {
			return err
		}
		e, err := c.EdgeBetween(graph.Key("account", ids["acct:okta:dave"]), graph.Key("group", ids["group:okta:eng"]))
		if err != nil {
			return err
		}
		return c.RevokeEdge(e.ID, h(2.5), "jml")
	})
}

func generate(t *testing.T, st *testkit.DB, ids testkit.IDs, fw string, mutate func(*evidence.Input)) *evidence.Result {
	t.Helper()
	f, ok := evidence.Lookup(fw)
	if !ok {
		t.Fatalf("no framework %s", fw)
	}
	in := evidence.Input{ID: "pack-1", Framework: f, From: h(-1), To: h(48), Now: h(72), By: "Auditor", Tenant: "t"}
	if mutate != nil {
		mutate(&in)
	}
	return testkit.Get(t, st, func(c *store.TenantTx) (*evidence.Result, error) { return evidence.Generate(c, in) })
}

// TestManifestCoversEveryFile: the ZIP holds the files the manifest lists,
// each with the SHA-256 and row count the manifest states; manifest.sha256 is
// the SHA-256 of manifest.json; and the same input gives the same bytes.
func TestManifestCoversEveryFile(t *testing.T) {
	st, ids := testkit.Tiny(t)
	seedLeaver(t, st, ids)
	for _, fw := range evidence.IDs() {
		t.Run(fw, func(t *testing.T) {
			res := generate(t, st, ids, fw, nil)
			files := unzip(t, res.Zip)
			sum := sha256.Sum256(files["manifest.json"])
			if hex.EncodeToString(sum[:]) != res.SHA256 || string(files["manifest.sha256"]) != res.SHA256+"  manifest.json\n" {
				t.Errorf("manifest hash %s does not match the ZIP", res.SHA256)
			}
			var m evidence.Manifest
			if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
				t.Fatal(err)
			}
			if m.Framework != fw || m.PackID != "pack-1" || len(m.Controls) == 0 {
				t.Errorf("manifest = %+v", m)
			}
			want := []string{evidence.FileUsers, evidence.FileJML, evidence.FileCampaigns, evidence.FileItems,
				evidence.FilePrivileged, evidence.FileRevoked, "README.txt"}
			if len(m.Files) != len(want) {
				t.Fatalf("manifest lists %d files, want %d", len(m.Files), len(want))
			}
			for i, fi := range m.Files {
				body, ok := files[fi.Name]
				if !ok || fi.Name != want[i] {
					t.Fatalf("file %d = %q (in zip: %v), want %q", i, fi.Name, ok, want[i])
				}
				s := sha256.Sum256(body)
				if hex.EncodeToString(s[:]) != fi.SHA256 || len(body) != fi.Bytes {
					t.Errorf("%s: manifest hash/size do not match the file", fi.Name)
				}
				if strings.HasSuffix(fi.Name, ".csv") && fi.Rows != len(records(t, body)) {
					t.Errorf("%s: manifest says %d rows, file has %d", fi.Name, fi.Rows, len(records(t, body)))
				}
			}
			for _, c := range m.Controls {
				for _, f := range c.Files {
					if _, ok := files[f]; !ok {
						t.Errorf("control %s names %s, which is not in the pack", c.ID, f)
					}
				}
			}
			if again := generate(t, st, ids, fw, nil); !bytes.Equal(again.Zip, res.Zip) || again.SHA256 != res.SHA256 {
				t.Error("the same input gave a different pack")
			}
		})
	}
}

func TestUsersListingHasSourceAndRowCounts(t *testing.T) {
	st, ids := testkit.Tiny(t)
	res := generate(t, st, ids, "soc2", nil)
	rows := records(t, unzip(t, res.Zip)[evidence.FileUsers])
	per := map[string]int{}
	for _, r := range rows {
		per[r["source"]]++
	}
	if len(rows) != 7 || per["okta"] != 4 || per["aws"] != 2 || per["snowflake"] != 1 {
		t.Errorf("users rows = %d, by source %v", len(rows), per)
	}
	for src, n := range per {
		if res.Manifest.SourceRows[src] != n {
			t.Errorf("manifest counts %d rows for %s, file has %d", res.Manifest.SourceRows[src], src, n)
		}
	}
	// an account created after the end of the period is not listed
	late := h(60)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := c.InsertAccount(&store.Account{System: "late", ExternalID: "l", Username: "l", Kind: "user", Status: "active",
			CreatedAt: &late})
		return err
	})
	if r := records(t, unzip(t, generate(t, st, ids, "soc2", nil).Zip)[evidence.FileUsers]); len(r) != 7 {
		t.Errorf("an account created after the period is listed: %d users", len(r))
	}
	if r := records(t, unzip(t, generate(t, st, ids, "soc2", func(in *evidence.Input) { in.To = h(61) }).Zip)[evidence.FileUsers]); len(r) != 8 {
		t.Errorf("an account created during the period is not listed: %d users", len(r))
	}
}

func TestJMLTimings(t *testing.T) {
	st, ids := testkit.Tiny(t)
	seedLeaver(t, st, ids)
	rows := records(t, unzip(t, generate(t, st, ids, "sox_itgc", nil).Zip)[evidence.FileJML])
	by := map[string]map[string]string{}
	for _, r := range rows {
		by[r["system"]] = r
	}
	if len(rows) != 2 {
		t.Fatalf("JML rows = %v", rows)
	}
	okta := by["okta"]
	if okta["result"] != "removed" || okta["hours_to_last_removal"] != "1.50" || okta["grants_held_at_termination"] != "1" ||
		okta["hr_event_external_id"] != "EV-DAVE" || okta["last_access_removed_at"] == "" {
		t.Errorf("okta row = %v", okta)
	}
	if aws := by["aws"]; aws["result"] != "access_remains" || aws["hours_to_last_removal"] != "" || aws["grants_still_held"] != "1" {
		t.Errorf("aws row (dave's missed offboarding) = %v", aws)
	}
	if _, ok := okta["name"]; ok {
		t.Error("JML rows should carry ids only")
	}
	// a period that does not contain the event has no sample
	none := generate(t, st, ids, "sox_itgc", func(in *evidence.Input) { in.From, in.To = h(2), h(48) })
	if r := records(t, unzip(t, none.Zip)[evidence.FileJML]); len(r) != 0 {
		t.Errorf("event outside the period sampled: %v", r)
	}
	// boundary: the period is [from, to), so an event exactly at to is out and exactly at from is in
	at := func(from, to float64) int {
		res := generate(t, st, ids, "sox_itgc", func(in *evidence.Input) { in.From, in.To = h(from), h(to) })
		return len(records(t, unzip(t, res.Zip)[evidence.FileJML]))
	}
	if at(1, 5) != 2 || at(-5, 1) != 0 {
		t.Errorf("event at +1h: in [1,5) = %d rows, in [-5,1) = %d rows; want 2 and 0", at(1, 5), at(-5, 1))
	}
}

func TestRevocationsAreVerified(t *testing.T) {
	st, ids := testkit.Tiny(t)
	seedLeaver(t, st, ids)
	rows := records(t, unzip(t, generate(t, st, ids, "iso27001", nil).Zip)[evidence.FileRevoked])
	if len(rows) != 1 {
		t.Fatalf("revocations = %v", rows)
	}
	r := rows[0]
	if r["reason"] != "jml" || r["currently_held"] != "false" || !strings.HasPrefix(r["verification"], "verified") ||
		r["span_closed_at"] == "" || !strings.Contains(r["grant"], "eng") {
		t.Errorf("revocation row = %v", r)
	}
	// the grant is held again (a manual re-add): the verification fails
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := c.InsertEdge(&store.GrantEdge{Src: graph.Key("account", ids["acct:okta:dave"]),
			Dst: graph.Key("group", ids["group:okta:eng"]), Relation: "member_of", Source: "manual", CreatedAt: h(3)})
		return err
	})
	rows = records(t, unzip(t, generate(t, st, ids, "iso27001", nil).Zip)[evidence.FileRevoked])
	if len(rows) != 1 || rows[0]["currently_held"] != "true" || !strings.HasPrefix(rows[0]["verification"], "failed") {
		t.Errorf("after the grant came back: %v", rows)
	}
}

func TestPrivilegedAccessIsAsOfPeriodEnd(t *testing.T) {
	st, ids := testkit.Tiny(t)
	priv := func(to float64) map[string]bool {
		res := generate(t, st, ids, "soc2", func(in *evidence.Input) { in.From, in.To = h(-100), h(to) })
		out := map[string]bool{}
		for _, r := range records(t, unzip(t, res.Zip)[evidence.FilePrivileged]) {
			out[r["identity_id"]+" "+r["permission"]] = true
			if r["path"] == "" || r["access"] == "" {
				t.Errorf("privileged row without a path: %v", r)
			}
		}
		return out
	}
	got := priv(48)
	found := false
	for k := range got {
		if strings.HasSuffix(k, " iam:*") {
			found = true
		}
	}
	if !found {
		t.Errorf("carol's prod admin is missing from the privileged list: %v", got)
	}
	// the period ends before the grants were ingested: nobody had access then
	if before := priv(-1); len(before) != 0 {
		t.Errorf("privileged access before any grant existed: %v", before)
	}
}

func TestCampaignExport(t *testing.T) {
	st, ids := testkit.Tiny(t)
	pols := testkit.Policies(t)
	var items int
	testkit.Write(t, st, func(c *store.TenantTx) error {
		id, err := reviews.GenerateCampaign(c, h(5), "Q4 review", 60, pols)
		if err != nil {
			return err
		}
		its, err := c.CampaignItems(id)
		items = len(its)
		return err
	})
	files := unzip(t, generate(t, st, ids, "pci_dss_v4", nil).Zip)
	camps := records(t, files[evidence.FileCampaigns])
	if len(camps) != 1 || camps[0]["name"] != "Q4 review" || camps[0]["items"] != itoa(items) || items == 0 {
		t.Errorf("campaigns = %v (items %d)", camps, items)
	}
	if got := len(records(t, files[evidence.FileItems])); got != items {
		t.Errorf("review_items has %d rows, want %d", got, items)
	}
	if !strings.Contains(string(files["README.txt"]), "7.2.4") {
		t.Error("the PCI pack does not say that exception-only reviews may not satisfy 7.2.4")
	}
	// a campaign created outside the period is not exported
	out := generate(t, st, ids, "pci_dss_v4", func(in *evidence.Input) { in.From, in.To = h(6), h(48) })
	if r := records(t, unzip(t, out.Zip)[evidence.FileCampaigns]); len(r) != 0 {
		t.Errorf("campaign outside the period exported: %v", r)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// TestCSVFormulaEscaping: a cell that starts with = + - or @ is neutralized.
func TestCSVFormulaEscaping(t *testing.T) {
	st, ids := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		for i, name := range []string{"=HYPERLINK(\"http://x\")", "+1", "-2", "@SUM(A1)"} {
			if _, err := c.InsertAccount(&store.Account{System: "evil", ExternalID: itoa(i), Username: name, Kind: "user",
				Status: "active"}); err != nil {
				return err
			}
		}
		return nil
	})
	body := unzip(t, generate(t, st, ids, "soc2", nil).Zip)[evidence.FileUsers]
	n := 0
	for _, r := range records(t, body) {
		if r["source"] != "evil" {
			continue
		}
		n++
		if !strings.HasPrefix(r["username"], "'") {
			t.Errorf("username %q starts a formula", r["username"])
		}
	}
	if n != 4 {
		t.Errorf("found %d of the 4 hostile accounts", n)
	}
}

func TestEmptyPeriodRefused(t *testing.T) {
	st, _ := testkit.Tiny(t)
	f, _ := evidence.Lookup("soc2")
	err := st.ReadTenant(context.Background(), st.Tenant, func(c *store.TenantTx) error {
		_, err := evidence.Generate(c, evidence.Input{Framework: f, From: h(1), To: h(1), Now: h(2)})
		return err
	})
	if err == nil {
		t.Error("an empty period was accepted")
	}
}
