package api

import (
	"context"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// seedCalls stores CloudTrail state (data events on, 120 days covered) and, for alice, one usage row per call on
// every third day of the last 60.
func seedCalls(t *testing.T, c awsClient, calls ...[2]string) {
	seedCallsFor(t, c.st, "conn-1", calls...)
}

// seedCallsFor is seedCalls for a connector of the given id.
func seedCallsFor(t *testing.T, st *testkit.DB, connector string, calls ...[2]string) {
	t.Helper()
	now := testkit.Now.UTC()
	dayAgo := func(n int) string { return now.AddDate(0, 0, -n).Format("2006-01-02") }
	err := st.DB.InTenant(context.Background(), st.Tenant, func(tx *store.TenantTx) error {
		if err := tx.PutAWSUsageState(&store.AWSUsageState{ConnectorID: connector, Source: store.AWSUsageCloudTrail,
			CoveredFrom: dayAgo(120), CoveredTo: dayAgo(0), S3DataEvents: store.AWSDataEventsEnabled, UpdatedAt: now}); err != nil {
			return err
		}
		for i := 0; i < 60; i += 3 {
			for _, call := range calls {
				if err := tx.SetAWSUsage(&store.AWSUsageDay{ConnectorID: connector, PrincipalARN: awstest.EstateAlice, Action: call[0],
					ResourceScope: call[1], Day: dayAgo(i), Source: store.AWSUsageCloudTrail, Count: 1, LastSeen: now}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

const rsPath = "/api/aws/principals/" + awstest.EstateAlice + "/right-size"

func rsBody(extra string) string {
	return `{"policy_arn":"` + awstest.EstateS3Read + `"` + extra + `}`
}

// A right-size is verified by re-evaluating the narrower policy (issue #659): alice used one object, so S3Read
// shrinks to it, the used call stays allowed at EXACT fidelity, and the answer carries the document and the diff.
func TestAWSRightSizeVerified(t *testing.T) {
	c := newAWSEvalFor(t, "2020-01-01T00:00:00Z", "conn-1")
	seedCalls(t, c, [2]string{"s3:GetObject", "arn:aws:s3:::prod-pii/customers.csv"},
		[2]string{"s3:ListBucket", "arn:aws:s3:::prod-pii"}) // alice cannot list: stale usage, skipped, never "broken"
	v := c.json("POST", rsPath, rsBody(""), 200)
	if v["verdict"] != "verified" || v["exclusive"] != true || v["connector"] != "conn-1" {
		t.Fatalf("answer = %v", v)
	}
	if conf := v["confidence"].(map[string]any)["level"]; conf != "high" || v["auto_eligible"] != true {
		t.Errorf("confidence %v, auto_eligible %v", conf, v["auto_eligible"])
	}
	if doc := v["document"].(string); !strings.Contains(doc, `prod-pii/customers.csv"`) || strings.Contains(doc, "ListBucket") {
		t.Errorf("document = %s", doc)
	}
	check := v["verification"].(map[string]any)
	if len(check["kept"].([]any)) != 1 || len(check["broken"].([]any)) != 0 || len(check["inexact"].([]any)) != 0 || check["added"].(float64) != 0 || check["removed"].(float64) == 0 {
		t.Errorf("verification = %v", check)
	}
	if sk := v["skipped_calls"].([]any); len(sk) != 1 || sk[0].(map[string]any)["action"] != "s3:ListBucket" {
		t.Errorf("skipped = %v", sk)
	}
	d := v["diff"].(map[string]any)
	if d["summary"].(map[string]any)["lost"].(float64) == 0 || d["summary"].(map[string]any)["gained"].(float64) != 0 || len(d["changes"].([]any)) == 0 {
		t.Errorf("diff = %v", d)
	}
}

// A candidate that would give more than it takes is refused with the reason: a call logged with no resource
// scope ("*") would widen S3Read to every object.
func TestAWSRightSizeRefusesWhatWidens(t *testing.T) {
	c := newAWSEvalFor(t, "2020-01-01T00:00:00Z", "conn-1")
	seedCalls(t, c, [2]string{"s3:GetObject", "*"})
	v := c.json("POST", rsPath, rsBody(""), 200)
	if v["verdict"] == "verified" || v["auto_eligible"] != false {
		t.Fatalf("a widening candidate was not refused: %v", v)
	}
	if v["verdict"] != "refused" || len(v["reasons"].([]any)) == 0 {
		t.Errorf("verdict %v reasons %v", v["verdict"], v["reasons"])
	}
}

// With no usage there is nothing to keep: refused, and the reason says to detach.
func TestAWSRightSizeNoUsageIsRefused(t *testing.T) {
	c := newAWSEvalFor(t, "2020-01-01T00:00:00Z", "conn-1")
	v := c.json("POST", rsPath, rsBody(""), 200)
	if v["verdict"] != "refused" || v["document"] != "" || !strings.Contains(v["reasons"].([]any)[0].(string), "detach") {
		t.Errorf("answer = %v", v)
	}
}

// The connector binding of #688 and #693 holds here too: another connector's logs are not evidence, and a
// snapshot with no connector has none.
func TestAWSRightSizeEvidenceIsTheSnapshotsConnector(t *testing.T) {
	c := newAWSEvalFor(t, "2020-01-01T00:00:00Z", "conn-1")
	if rec := c.do("POST", rsPath, rsBody(`,"connector":"other"`)); rec.Code != 422 || !strings.Contains(rec.Body.String(), "connector_mismatch") {
		t.Errorf("other connector: %d %.200s", rec.Code, rec.Body.String())
	}
	none := newAWSEvalDated(t, "2020-01-01T00:00:00Z")
	if rec := none.do("POST", rsPath, rsBody(`,"connector":"conn-1"`)); rec.Code != 422 || !strings.Contains(rec.Body.String(), "connector_unknown_for_snapshot") {
		t.Errorf("connector on a connector-less snapshot: %d %.200s", rec.Code, rec.Body.String())
	}
	if rec := none.do("POST", rsPath, rsBody("")); rec.Code != 422 || !strings.Contains(rec.Body.String(), "no_usage_evidence") {
		t.Errorf("connector-less snapshot: %d %.200s", rec.Code, rec.Body.String())
	}
}

func TestAWSRightSizeRefusesBadInput(t *testing.T) {
	c := newAWSEvalFor(t, "2020-01-01T00:00:00Z", "conn-1")
	for name, tc := range map[string]struct {
		path, body string
		want       int
	}{
		"no policy":         {rsPath, `{}`, 422},
		"unknown field":     {rsPath, rsBody(`,"created":"2000-01-01"`), 422},
		"unknown policy":    {rsPath, `{"policy_arn":"arn:aws:iam::111111111111:policy/Nope"}`, 404},
		"inline policy":     {rsPath, `{"policy_arn":"` + awstest.EstateAlice + `#inline/assume"}`, 422},
		"bad unused_days":   {rsPath, rsBody(`,"unused_days":9999`), 422},
		"negative days":     {rsPath, rsBody(`,"unused_days":-1`), 422},
		"control character": {rsPath, `{"policy_arn":"a\nb"}`, 422},
		"unknown principal": {"/api/aws/principals/arn:aws:iam::111111111111:user/nobody/right-size", rsBody(""), 404},
		"unknown snapshot":  {rsPath, rsBody(`,"snapshot":"` + strings.Repeat("0", 64) + `"`), 404},
		"not a JSON object": {rsPath, `[]`, 422},
		"bad profile":       {rsPath, rsBody(`,"profile":"nope"`), 422},
	} {
		if rec := c.do("POST", tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("%s: %d, want %d: %.200s", name, rec.Code, tc.want, rec.Body.String())
		}
	}
}
