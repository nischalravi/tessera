package reviews_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"

	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var update = flag.Bool("update", false, "rewrite testdata/golden/review_population_v1.json")

// goldenPath is the published test vector of the population hash (see
// mvp/README.md, "Review populations"). An auditor can recompute the hash of
// the rows with any RFC 8785 (JCS) implementation and SHA-256; this test does
// exactly that, independently of reviews.PopulationHash, then requires
// reviews.PopulationHash to agree. Regenerate with:
//
//	go test ./internal/reviews -run Golden -update
const goldenPath = "../../testdata/golden/review_population_v1.json"

const goldenDomain = "tessera-review-population-v1"

type goldenRow struct {
	Ordinal       int    `json:"ordinal"`
	EdgeID        int64  `json:"edge_id"`
	IdentityID    int64  `json:"identity_id"`
	IdentityRef   string `json:"identity_ref"`
	AccountRef    string `json:"account_ref"`
	System        string `json:"system"`
	Entitlement   string `json:"entitlement"`
	EdgeSrc       string `json:"edge_src"`
	EdgeDst       string `json:"edge_dst"`
	InScopeReason string `json:"in_scope_reason"`
	Disposition   string `json:"disposition"`
}

type goldenCase struct {
	Name      string      `json:"name"`
	Rows      []goldenRow `json:"rows"`
	Canonical []string    `json:"canonical"`
	Hash      string      `json:"hash"`
}

type goldenFile struct {
	Description string       `json:"description"`
	Algorithm   string       `json:"algorithm"`
	Cases       []goldenCase `json:"cases"`
}

// independent computes the canonical lines and the hash from the rows the way
// the documentation tells an auditor to.
func independent(t *testing.T, rows []goldenRow) ([]string, string) {
	t.Helper()
	lines := []string{}
	for _, r := range rows {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		c, err := jcs.Transform(raw)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(c))
	}
	sum := sha256.Sum256([]byte(goldenDomain + "\x00" + strings.Join(lines, "\n")))
	return lines, hex.EncodeToString(sum[:])
}

func storeRows(rows []goldenRow) []*store.PopulationRow {
	var out []*store.PopulationRow
	for _, r := range rows {
		out = append(out, &store.PopulationRow{Ordinal: r.Ordinal, EdgeID: r.EdgeID, IdentityID: r.IdentityID,
			IdentityRef: r.IdentityRef, AccountRef: r.AccountRef, System: r.System, Entitlement: r.Entitlement,
			EdgeSrc: r.EdgeSrc, EdgeDst: r.EdgeDst, InScopeReason: r.InScopeReason, Disposition: r.Disposition})
	}
	return out
}

func goldenCases() []goldenCase {
	return []goldenCase{
		{Name: "empty population"},
		{Name: "one row", Rows: []goldenRow{{1, 4021, 17, "alice@larkspur.example", "alice", "okta", "Okta Admins",
			"account:31", "group:12", "standing_grant", "review"}}},
		{Name: "three rows, escaping and non-ASCII", Rows: []goldenRow{
			{1, 7, 3, "svc-etl", "svc-etl", "aws", "ProdAdmin \"break glass\" <ops>", "account:5", "group:9", "standing_grant", "review"},
			{2, 12, 4, "zoë.o'brien", "zoë", "github", "Org owners ✓ \\ backslash", "account:6", "group:10", "standing_grant", "auto_certified"},
			{3, 4021, 17, "alice@larkspur.example", "alice", "okta", "Okta Admins", "account:31", "group:12", "standing_grant", "auto_certified"}}},
		{Name: "role membership rows (issue #365)", Rows: []goldenRow{
			{1, 0, 17, "alice@larkspur.example", "", "business_role", "Role AP Clerk", "role:ap-clerk", "identity:17", "role_membership", "review"},
			{2, 4021, 17, "alice@larkspur.example", "alice", "okta", "Okta Admins", "account:31", "group:12", "standing_grant", "review"}}},
	}
}

func TestPopulationHashGoldenVector(t *testing.T) {
	cases := goldenCases()
	for i := range cases {
		cases[i].Canonical, cases[i].Hash = independent(t, cases[i].Rows)
	}
	want := goldenFile{
		Description: "Tessera review population hash v1 test vector. Each case lists population rows in ascending ordinal. " +
			"The canonical form of a row is its JSON object canonicalized with RFC 8785 (JCS). The hash is the lower-hex " +
			"SHA-256 of the bytes of the domain string, one 0x00 byte, then the canonical rows joined by a single \\n " +
			"(no trailing newline). The empty population hashes the domain and the 0x00 byte.",
		Algorithm: "sha256(\"tessera-review-population-v1\" || 0x00 || JCS(row1) || \"\\n\" || JCS(row2) || ... )",
		Cases:     cases,
	}
	if *update {
		b, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(goldenPath) // #nosec G304 -- fixed test path
	if err != nil {
		t.Fatal(err)
	}
	var got goldenFile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Cases) != len(want.Cases) {
		t.Fatalf("%d golden cases, want %d (run with -update after reviewing the change)", len(got.Cases), len(want.Cases))
	}
	for i, gc := range got.Cases {
		t.Run(gc.Name, func(t *testing.T) {
			lines, hash := independent(t, gc.Rows)
			if strings.Join(lines, "\n") != strings.Join(gc.Canonical, "\n") || hash != gc.Hash {
				t.Errorf("the vector in %s does not follow its own description:\n canonical %q\n hash %s", goldenPath, lines, hash)
			}
			h, err := reviews.PopulationHash(storeRows(gc.Rows))
			if err != nil || h != gc.Hash {
				t.Errorf("reviews.PopulationHash = %s (%v), golden %s", h, err, gc.Hash)
			}
			if gc.Hash != want.Cases[i].Hash {
				t.Errorf("the golden hash changed: %s, was %s (the hash contract is frozen; bump the version instead)", want.Cases[i].Hash, gc.Hash)
			}
		})
	}
}
