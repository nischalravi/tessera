package readiness

import (
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sqldb"
)

// Endpoints lists every place a connector sends its credential, nested ones included.
func TestConnConfigEndpoints(t *testing.T) {
	cfg := ConnConfig{Host: "ldap.example.org", Port: 636, OrgURL: "https://o.example.org", Settings: map[string]string{"host": "ssh.example.org", "user": "x"},
		Rest: &restgen.Spec{BaseURL: "https://api.example.org", Auth: restgen.Auth{TokenURL: "https://auth.example.org/token"}},
		SQL:  &sqldb.Config{Host: "db.example.org", Port: 5432}}
	want := []string{"host=ldap.example.org:636", "org_url=https://o.example.org", "rest.auth.token_url=https://auth.example.org/token",
		"rest.base_url=https://api.example.org", "settings.host=ssh.example.org", "sql.host=db.example.org:5432"}
	if got := cfg.Endpoints(); !slices.Equal(got, want) {
		t.Errorf("Endpoints = %v, want %v", got, want)
	}
	if got := (ConnConfig{}).Endpoints(); len(got) != 0 {
		t.Errorf("an empty config has endpoints %v", got)
	}
}
