package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/catalog"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// levelCatalog is awstest.Catalog with access levels, which the loop needs to tell privileged actions apart.
type levelCatalog struct {
	awstest.Catalog
	level catalog.AccessLevel
}

func (c levelCatalog) AccessLevel(string) catalog.AccessLevel { return c.level }

func levelsOf(l catalog.AccessLevel) func(*Config) {
	return func(c *Config) {
		c.AWSCatalog = func() (*AWSCatalog, error) {
			ac, err := testAWSCatalog()
			if ac != nil {
				ac.Cat = levelCatalog{level: l}
			}
			return ac, err
		}
	}
}

func withLeveledCatalog(c *Config) { levelsOf(catalog.AccessRead)(c) }

// Privileged permissions are suggest-only (design §4, §11 decision 3) and the guard fails closed: a removed
// permissions-management action, an action of unknown level and a catalog with no access levels all refuse the
// candidate, so nothing is staged and the tick, even in auto mode, has nothing to execute; a non-privileged
// removal goes through.
func TestLPAPI_PrivilegedSuggestOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  func(*Config)
		want int
	}{
		{"permissions management removed", levelsOf(catalog.AccessPermissionsManagement), http.StatusUnprocessableEntity},
		{"unknown access level", levelsOf(catalog.AccessUnknown), http.StatusUnprocessableEntity},
		{"catalog without access levels", withAWSCatalog, http.StatusUnprocessableEntity},
		{"write is not privileged", levelsOf(catalog.AccessWrite), http.StatusCreated},
		{"read is not privileged", levelsOf(catalog.AccessRead), http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newAWSWBWith(t, tc.opt)
			w.enable()
			setLP(t, w, func(s *store.LPSettings) { s.Mode = store.LPModeAuto })
			v := w.c.json("POST", rsPath, rsBody(""), 200).(map[string]any)
			body := fmt.Sprintf(`{"principal":%q,"policy_arn":%q,"candidate_sha256":%q}`, awstest.EstateAlice, awstest.EstateS3Read, asString(v["document_sha256"]))
			r := w.c.do("POST", "/api/lp/candidates", body)
			if r.Code != tc.want {
				t.Fatalf("candidate: %d %s, want %d", r.Code, r.Body, tc.want)
			}
			if tc.want != http.StatusUnprocessableEntity {
				return
			}
			if !strings.Contains(r.Body.String(), "privileged_suggest_only") {
				t.Fatalf("refusal = %s", r.Body)
			}
			w.lpTick(testkit.Now.Add(8 * 24 * time.Hour))
			items := w.c.json("GET", "/api/lp/revocations", "", 200).(map[string]any)["items"].([]any)
			if len(items) != 0 || len(w.ops()) != 0 {
				t.Fatalf("a refused candidate left %d revocations and %d operations", len(items), len(w.ops()))
			}
		})
	}
}
