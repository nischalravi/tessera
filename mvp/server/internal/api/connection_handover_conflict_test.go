package api

import (
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// A source of the same name with different settings is an explicit conflict, not a silent
// success while the other source is the one that is read.
func TestHandover_NameTakenByADifferentSourceIsAConflict(t *testing.T) {
	t.Parallel()
	st := testkit.Demo(t)
	sealer := testSealer()
	typ, _ := governed.Lookup(governed.Fieldglass)
	p := governed.Params{Type: governed.Fieldglass, BaseURL: "https://fg.example.com", Secret: "c:s"}
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := handoverVMS(c, sealer, "Contractors", "c1", typ, p, testkit.Now)
		return err
	})
	other := p
	other.BaseURL = "https://other.example.com"
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var re *readiness.Error
		if _, err := handoverVMS(c, sealer, "Contractors", "c2", typ, other, testkit.Now); !errors.As(err, &re) || re.Code != "handover_conflict" {
			t.Errorf("different URL: %v", err)
		}
		if _, err := handoverVMS(c, sealer, "Contractors", "c1", typ, p, testkit.Now); !errors.Is(err, errHandoverExists) {
			t.Errorf("same feed: %v", err)
		}
		return nil
	})

	ap := governed.Params{Type: governed.AWSOrg, Secret: awsSecret, Settings: map[string]string{"regions": "us-east-1",
		"management_account_id": "111111111111", "external_id": "tessera-abc123"}}
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := handoverAWS(c, sealer, true, "AWS", ap, testkit.Now)
		return err
	})
	diff := ap
	diff.Settings = map[string]string{"regions": "eu-west-1", "management_account_id": "111111111111", "external_id": "tessera-abc123"}
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var re *readiness.Error
		if _, err := handoverAWS(c, sealer, true, "AWS", diff, testkit.Now); !errors.As(err, &re) || re.Code != "handover_conflict" {
			t.Errorf("different regions: %v", err)
		}
		if _, err := handoverAWS(c, sealer, true, "AWS", ap, testkit.Now); !errors.Is(err, errHandoverExists) {
			t.Errorf("same connector: %v", err)
		}
		return nil
	})
}
