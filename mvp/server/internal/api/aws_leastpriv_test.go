package api

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// seedUsage stores CloudTrail state, gaps and one used call for alice, as the
// LP-1 ingest would.
func seedUsage(t *testing.T, c awsClient, s3 string, gaps ...*store.AWSUsageGap) {
	t.Helper()
	now := testkit.Now.UTC()
	dayAgo := func(n int) string { return now.AddDate(0, 0, -n).Format("2006-01-02") }
	err := c.st.DB.InTenant(context.Background(), c.st.Tenant, func(tx *store.TenantTx) error {
		if err := tx.PutAWSUsageState(&store.AWSUsageState{ConnectorID: "conn-1", Source: store.AWSUsageCloudTrail,
			CoveredFrom: dayAgo(120), CoveredTo: dayAgo(0), S3DataEvents: s3, UpdatedAt: now}); err != nil {
			return err
		}
		for _, g := range gaps {
			g.ConnectorID, g.RecordedAt = "conn-1", now
			if err := tx.PutAWSUsageGap(g); err != nil {
				return err
			}
		}
		for i := 0; i < 60; i += 3 {
			if err := tx.SetAWSUsage(&store.AWSUsageDay{ConnectorID: "conn-1", PrincipalARN: awstest.EstateAlice, Action: "s3:ListBucket",
				ResourceScope: "*", Day: dayAgo(i), Source: store.AWSUsageCloudTrail, Count: 1, LastSeen: now}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// newAWSEvalDated is newAWSEval with the estate's alice created on the given date.
func newAWSEvalDated(t *testing.T, create string) awsClient {
	t.Helper()
	return newAWSEvalFor(t, create, "")
}

// newAWSEvalFor is newAWSEvalDated with the snapshot collected by the given connector ("": none).
func newAWSEvalFor(t *testing.T, create, connector string) awsClient {
	t.Helper()
	c := newRD(t, withAWSCatalog)
	snap, err := awstest.Estate()
	if err != nil {
		t.Fatal(err)
	}
	snap.Principals[awstest.EstateAlice].CreateDate = create
	col := &awsorg.Collection{Snapshot: snap, AccountIDs: []string{awstest.EstateDev, awstest.EstateProd}}
	if snap.ID, err = awsorg.ContentID(col); err != nil {
		t.Fatal(err)
	}
	err = c.st.DB.InTenant(context.Background(), c.st.Tenant, func(tx *store.TenantTx) error {
		_, err := awsorg.Persist(tx, col, awsorg.PersistInput{Source: store.AWSSourceConnector, ConnectorID: connector, CatalogVersion: "awstest-1"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return awsClient{c, snap.ID}
}

func lpItems(t *testing.T, v map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, it := range v["items"].([]any) {
		m := it.(map[string]any)
		out[m["action"].(string)] = m
	}
	return out
}

func lpLevel(t *testing.T, items map[string]map[string]any, action string) string {
	t.Helper()
	it := items[action]
	if it == nil {
		t.Fatalf("%s is not in the answer", action)
	}
	return it["confidence"].(map[string]any)["level"].(string)
}

func TestAWSLeastPrivConfidence(t *testing.T) {
	c := newAWSEvalFor(t, "2020-01-01T00:00:00Z", "conn-1")
	base := "/api/aws/principals/" + awstest.EstateAlice + "/least-privilege?connector=conn-1&limit=500"
	path := base

	// nothing ingested: unknown, never high
	items := lpItems(t, c.get(path, 200))
	if items["s3:GetObject"]["used"] != false || lpLevel(t, items, "s3:GetObject") != "unknown" {
		t.Fatalf("before ingest: %v", items["s3:GetObject"])
	}

	// data events off: object actions stay unknown, never high
	seedUsage(t, c, store.AWSDataEventsDisabled)
	items = lpItems(t, c.get(path, 200))
	if got := lpLevel(t, items, "s3:GetObject"); got != "unknown" {
		t.Errorf("GetObject with data events off = %v", got)
	}
	// the used management call is a used finding, not an unused one
	if lb := items["s3:ListBucket"]; lb != nil && (lb["used"] != true || lb["last_used"] == nil) {
		t.Errorf("ListBucket = %v", lb)
	}

	// data events on: the same permission can be high
	seedUsage(t, c, store.AWSDataEventsEnabled)
	items = lpItems(t, c.get(path, 200))
	if got := lpLevel(t, items, "s3:GetObject"); got != "high" {
		t.Errorf("GetObject with data events on = %v: %v", got, items["s3:GetObject"])
	}

	// without a creation date in the snapshot, the level is capped at medium
	undated := newAWSEvalFor(t, "", "conn-1")
	seedUsage(t, undated, store.AWSDataEventsEnabled)
	items = lpItems(t, undated.get(base, 200))
	if got := lpLevel(t, items, "s3:GetObject"); got != "medium" {
		t.Errorf("no creation date = %v", got)
	}

	// a future digest gap (issue #680) lowers it to low with no schema change
	seedUsage(t, c, store.AWSDataEventsEnabled, &store.AWSUsageGap{Source: store.AWSUsageCloudTrail, Ref: "s3://logs/x", Code: "digest_missing",
		Day: testkit.Now.UTC().AddDate(0, 0, -3).Format("2006-01-02")})
	items = lpItems(t, c.get(path, 200))
	if got := lpLevel(t, items, "s3:GetObject"); got != "low" {
		t.Errorf("digest gap = %v", got)
	}

	// a window longer than the logs is not high
	items = lpItems(t, c.get(path+"&unused_days=300", 200))
	if got := lpLevel(t, items, "s3:GetObject"); got == "high" {
		t.Errorf("window longer than the logs = %v", got)
	}
}

// A snapshot with no connector has no usage evidence of its own (issue #693, as #688): naming a connector would
// borrow another source's complete logs and rate used permissions as high-confidence unused, so it is refused, and
// the answer without one is rated with no evidence, never high.
func TestAWSLeastPrivNoConnectorSnapshotTakesNoEvidence(t *testing.T) {
	c := newAWSEvalDated(t, "2020-01-01T00:00:00Z") // snapshot with no connector
	seedUsage(t, c, store.AWSDataEventsEnabled)     // conn-1: complete logs, none naming the snapshot as its own
	base := "/api/aws/principals/" + awstest.EstateAlice + "/least-privilege?limit=500"
	rec := c.do("GET", base+"&connector=conn-1", "")
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "connector_unknown_for_snapshot") {
		t.Fatalf("connector on a snapshot with none: %d %.200s", rec.Code, rec.Body.String())
	}
	items := lpItems(t, c.get(base, 200))
	for a, it := range items {
		if lvl := it["confidence"].(map[string]any)["level"]; lvl == "high" {
			t.Errorf("%s rated %v with no usage evidence", a, lvl)
		}
	}
	if got := lpLevel(t, items, "s3:GetObject"); got != "unknown" {
		t.Errorf("GetObject with no evidence = %v", got)
	}
	for a, it := range items {
		reasons, _ := it["confidence"].(map[string]any)["reasons"].([]any)
		if len(reasons) != 1 || !strings.Contains(reasons[0].(string), "no connector") {
			t.Errorf("%s reasons = %v, want the no-connector reason", a, reasons)
		}
	}
	if v := c.get(base, 200); v["connector"] != "" {
		t.Errorf("view connector = %v, want \"\"", v["connector"])
	}
}

func TestAWSLeastPrivRefusesBadInput(t *testing.T) {
	c := newAWSEvalFor(t, "2020-01-01T00:00:00Z", "c")
	base := "/api/aws/principals/" + awstest.EstateAlice + "/least-privilege"
	for name, tc := range map[string]struct {
		path string
		want int
	}{
		"bad unused_days":                {base + "?connector=c&unused_days=0", 422},
		"huge unused_days":               {base + "?connector=c&unused_days=9999", 422},
		"supplied created is refused":    {base + "?connector=c&created=2000-01-01", 422},
		"bad service":                    {base + "?connector=c&service=S3:x", 422},
		"bad limit":                      {base + "?connector=c&limit=0", 422},
		"control character in connector": {base + "?connector=c%0A", 422},
		"unknown principal":              {"/api/aws/principals/arn:aws:iam::111111111111:user/nobody/least-privilege?connector=c", 404},
		"unknown snapshot":               {base + "?connector=c&snapshot=" + strings.Repeat("0", 64), 404},
	} {
		if rec := c.do("GET", tc.path, ""); rec.Code != tc.want {
			t.Errorf("%s: %d, want %d: %.200s", name, rec.Code, tc.want, rec.Body.String())
		}
	}
}

// The usage evidence is the snapshot's own connector's (issue #688). Another connector of the tenant whose logs
// cover the window and hold no rows for the principal must not be able to rate a used permission as high-confidence
// unused: asking for it is refused, and the snapshot's own connector (named or implied) answers as before.
func TestAWSLeastPrivEvidenceIsTheSnapshotsConnector(t *testing.T) {
	c := newAWSEvalFor(t, "2020-01-01T00:00:00Z", "conn-1")
	seedUsage(t, c, store.AWSDataEventsEnabled) // conn-1: alice used s3:ListBucket every third day
	now := testkit.Now.UTC()
	if err := c.st.DB.InTenant(context.Background(), c.st.Tenant, func(tx *store.TenantTx) error {
		return tx.PutAWSUsageState(&store.AWSUsageState{ConnectorID: "conn-2", Source: store.AWSUsageCloudTrail,
			CoveredFrom: now.AddDate(0, 0, -120).Format("2006-01-02"), CoveredTo: now.Format("2006-01-02"),
			S3DataEvents: store.AWSDataEventsEnabled, UpdatedAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	base := "/api/aws/principals/" + awstest.EstateAlice + "/least-privilege?limit=500"
	for name, tc := range map[string]struct {
		query string
		want  int
	}{
		"the snapshot's connector, implied": {"", 200},
		"the snapshot's connector, named":   {"&connector=conn-1", 200},
		"another connector of the tenant":   {"&connector=conn-2", 422},
		"a connector that does not exist":   {"&connector=conn-9", 422},
	} {
		rec := c.do("GET", base+tc.query, "")
		if rec.Code != tc.want {
			t.Errorf("%s: %d, want %d: %.200s", name, rec.Code, tc.want, rec.Body.String())
		}
		if tc.want == 422 && !strings.Contains(rec.Body.String(), "connector_mismatch") {
			t.Errorf("%s: %.200s", name, rec.Body.String())
		}
	}
	items := lpItems(t, c.get(base, 200))
	if lb := items["s3:ListBucket"]; lb != nil && lb["used"] != true {
		t.Errorf("ListBucket under the snapshot's connector = %v", lb)
	}
}
