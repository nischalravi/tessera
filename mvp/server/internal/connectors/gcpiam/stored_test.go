package gcpiam_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/gcpiam"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// FromStored reads the scope from the stored config and the service account key from the credential,
// refuses what does not open without echoing the key, and lets only the dev overrides replace the
// Google endpoints (a loopback fake is refused in prod).
func TestFromStored(t *testing.T) {
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	noEnv := func(string) string { return "" }
	prod := connsync.Runtime{Env: "prod"}
	_, key := newKey(t)
	for _, tc := range []struct {
		name string
		s    gcpiam.Stored
		good bool
	}{
		{"project", gcpiam.Stored{ProjectIDs: "alpha-proj-1, beta-proj-2", Credential: key}, true},
		{"organization", gcpiam.Stored{OrganizationID: "123456789", Credential: key}, true},
		{"folders", gcpiam.Stored{FolderIDs: "111,222", Credential: key}, true},
		{"no credential", gcpiam.Stored{ProjectIDs: "alpha-proj-1"}, false},
		{"key is not JSON", gcpiam.Stored{ProjectIDs: "alpha-proj-1", Credential: "hunter2"}, false},
		{"no scope", gcpiam.Stored{Credential: key}, false},
		{"bad organization", gcpiam.Stored{OrganizationID: "acme", Credential: key}, false},
		{"bad folder", gcpiam.Stored{FolderIDs: "x", Credential: key}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := gcpiam.FromStored(tc.s, noEnv, prod, hc, nil)
			if (err == nil) != tc.good {
				t.Fatalf("FromStored = %v, want ok=%v", err, tc.good)
			}
			if err != nil {
				if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "hunter2") {
					t.Errorf("error echoes the credential: %v", err)
				}
				return
			}
			if c.System() != "gcp" {
				t.Errorf("system %q", c.System())
			}
		})
	}
	for _, k := range []string{"TESSERA_GCP_CRM_URL", "TESSERA_GCP_IAM_URL", "TESSERA_GCP_TOKEN_URL"} {
		env := func(name string) string {
			if name == k {
				return "https://127.0.0.1:9"
			}
			return ""
		}
		if _, err := gcpiam.FromStored(gcpiam.Stored{ProjectIDs: "alpha-proj-1", Credential: key}, env, prod, hc, nil); err == nil {
			t.Errorf("prod accepted %s", k)
		}
	}
}
