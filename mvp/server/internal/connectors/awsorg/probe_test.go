package awsorg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
)

func TestProbe_Organization(t *testing.T) {
	res, err := newCollector(t, newReplay(t), orgConfig()).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.OrgID != "o-example12345" || res.RoleARN != "arn:aws:iam::111111111111:role/TesseraReader" || res.Accounts < 1 {
		t.Errorf("probe = %+v", res)
	}
}

func TestProbe_Accounts(t *testing.T) {
	cfg := &Config{Regions: []string{"us-east-1"}, AccountIDs: []string{acctMember}}
	res, err := newCollector(t, newReplay(t), cfg).Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.OrgID != "" || res.Accounts != 1 || !strings.HasSuffix(res.RoleARN, ":role/TesseraReader") {
		t.Errorf("probe = %+v", res)
	}
	empty := &Collector{Client: testClient(newReplay(t), nil), Config: &Config{Regions: []string{"us-east-1"}}, Base: baseCreds()}
	if _, err := empty.Probe(context.Background()); err == nil {
		t.Error("a probe with no account configured succeeded")
	}
}

func govParams(secret string) governed.Params {
	return governed.Params{Type: governed.AWSOrg, Secret: secret, Settings: map[string]string{
		"regions": "us-east-1", "management_account_id": acctMgmt, "external_id": externalID}}
}

func credJSON(secret string) string {
	b, _ := json.Marshal(Credentials{AccessKeyID: baseKeyID, SecretAccessKey: secret})
	return string(b)
}

func TestGovernedProber(t *testing.T) {
	p, err := GovernedProber(govParams(credJSON(baseSecret)), newReplay(t), func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Authenticate(context.Background())
	if err != nil || !a.OK || a.Mode != "assume_role" || !strings.Contains(a.Identity, ":role/TesseraReader") {
		t.Fatalf("authenticate = %+v, %v", a, err)
	}
	s, err := p.Sample(context.Background(), connectors.SampleQuery{Op: "probe"})
	if err != nil || !s.Available || s.Objects < 1 || s.PerClass["account"] < 1 {
		t.Fatalf("sample = %+v, %v", s, err)
	}
	// operations an AWS connection cannot answer are unsupported, never a pass
	if _, err := p.Connect(context.Background()); err == nil || err != connectors.ErrUnsupported {
		t.Errorf("connect: %v", err)
	}
	if _, err := p.EffectiveRights(context.Background(), "self"); err != connectors.ErrUnsupported {
		t.Errorf("effective rights: %v", err)
	}
}

// A refused signature is an answer to the authentication check (OK false), not an error.
func TestGovernedProber_RefusedKeys(t *testing.T) {
	p, err := GovernedProber(govParams(credJSON("wrongSecretKeyForTestsOnly0123456789abcd")), newReplay(t), func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Authenticate(context.Background())
	if err != nil || a.OK {
		t.Fatalf("authenticate with wrong keys = %+v, %v", a, err)
	}
}

func TestGovernedProber_Input(t *testing.T) {
	for name, secret := range map[string]string{"not json": "AKIA", "unknown field": `{"access_key_id":"` + baseKeyID + `","secret_access_key":"` + baseSecret + `","password":"x"}`,
		"short key": `{"access_key_id":"x","secret_access_key":"` + baseSecret + `"}`} {
		if _, err := GovernedProber(govParams(secret), newReplay(t), nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := govParams(credJSON(baseSecret))
	p.Settings["regions"] = ""
	if _, err := GovernedProber(p, newReplay(t), nil); err == nil {
		t.Error("no regions: accepted")
	}
}
