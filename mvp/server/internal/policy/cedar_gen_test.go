package policy_test

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// genConn is a random world: identities of every type and status, owners that
// are active, terminated or missing, three systems with privileged and
// environment-tagged resources, group chains, direct grants, aged secrets and
// registered MFA methods of every strength. The same seed gives the same world.
type genConn struct {
	seed int64
	now  time.Time
}

func (genConn) System() string      { return "gen" }
func (genConn) DisplayName() string { return "generated world" }
func (genConn) TypeName() string    { return "GenConnector" }

func (genConn) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

func sp(s string) *string { return &s }

func (g genConn) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	r := rand.New(rand.NewSource(g.seed))
	pick := func(xs ...string) string { return xs[r.Intn(len(xs))] }
	days := func(n int) time.Time { return g.now.Add(-time.Duration(n) * 24 * time.Hour) }
	res := &connectors.DiscoveryResult{}

	// identities
	n := 12 + r.Intn(24)
	var humans []string
	for i := 0; i < n; i++ {
		typ := pick("human", "human", "human", "human", "service", "service", "ai_agent")
		x := fmt.Sprintf("u%d", i)
		rec := connectors.IdentityRecord{ExternalID: x, Name: fmt.Sprintf("%s-%d", typ, i), Type: typ,
			Email: sp(x + "@gen.example")}
		if r.Intn(3) > 0 {
			rec.Department = sp(pick("Engineering", "Finance", "Data", "Legal"))
		}
		if r.Intn(5) == 0 {
			t := days(1 + r.Intn(60))
			rec.Status, rec.TerminatedAt = "terminated", &t
		}
		if typ == "human" {
			humans = append(humans, x)
		}
		res.Identities = append(res.Identities, rec)
	}
	for i := range res.Identities {
		rec := &res.Identities[i]
		if rec.Type != "human" && r.Intn(6) > 0 && len(humans) > 0 {
			rec.Owner = &connectors.IdentityRef{ExternalID: humans[r.Intn(len(humans))]}
		}
	}

	// resources and permissions
	var perms []string
	nres := 6 + r.Intn(8)
	for i := 0; i < nres; i++ {
		sys := pick("aws", "snowflake", "workday")
		var env *string
		if e := pick("prod", "prod", "staging", "dev", ""); e != "" {
			env = sp(e)
		}
		var tags []string
		for _, t := range []string{"pii", "payments", "secret"} {
			if r.Intn(3) == 0 {
				tags = append(tags, t)
			}
		}
		x := fmt.Sprintf("res%d", i)
		res.Resources = append(res.Resources, connectors.ResourceRecord{System: sys, ExternalID: x, Name: sys + "/" + x, Kind: "thing",
			Environment: env, Tags: tags})
		for j := 0; j < 1+r.Intn(2); j++ {
			px := fmt.Sprintf("%s-p%d", x, j)
			res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: sys, ExternalID: px,
				Action:             pick("s3:GetObject", "iam:*", "snowflake:SELECT", "payments:create", "payments:approve"),
				ResourceExternalID: x, Privileged: r.Intn(3) == 0})
			perms = append(perms, sys+"/"+px)
		}
	}

	// groups: okta groups map to role groups, role groups grant permissions
	var oktaGroups, roles []string
	for i := 0; i < 4+r.Intn(3); i++ {
		x := fmt.Sprintf("g%d", i)
		res.Groups = append(res.Groups, connectors.GroupRecord{System: "okta", ExternalID: x, Name: x, Privileged: r.Intn(4) == 0,
			Requestable: r.Intn(2) == 0})
		oktaGroups = append(oktaGroups, x)
	}
	for i := 0; i < 3+r.Intn(3); i++ {
		sys := pick("aws", "snowflake")
		x := fmt.Sprintf("role%d", i)
		res.Groups = append(res.Groups, connectors.GroupRecord{System: sys, ExternalID: x, Name: x, Kind: "role",
			Privileged: r.Intn(3) == 0})
		roles = append(roles, sys+"/"+x)
	}
	ref := func(kind, s string) connectors.Ref {
		for i := range s {
			if s[i] == '/' {
				return connectors.Ref{Kind: kind, System: s[:i], ExternalID: s[i+1:]}
			}
		}
		return connectors.Ref{Kind: kind, System: "okta", ExternalID: s}
	}
	seen := map[[2]string]bool{}
	edge := func(src, dst connectors.Ref, rel string) {
		k := [2]string{src.System + "/" + src.ExternalID + "/" + src.Kind, dst.System + "/" + dst.ExternalID + "/" + dst.Kind}
		if !seen[k] {
			seen[k] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: src, Dst: dst, Relation: rel})
		}
	}
	for _, og := range oktaGroups {
		for j := 0; j < 1+r.Intn(2); j++ {
			edge(ref("group", og), ref("group", roles[r.Intn(len(roles))]), "maps_to")
		}
	}
	for _, ro := range roles {
		for j := 0; j < 1+r.Intn(3); j++ {
			edge(ref("group", ro), ref("perm", perms[r.Intn(len(perms))]), "grants")
		}
	}

	// accounts, memberships, direct grants, secrets, methods
	res.AuthSource = &connectors.AuthMethodSource{System: "okta"}
	for i := range res.Identities {
		id := res.Identities[i]
		var oktaAcct string
		for _, sys := range []string{"okta", "aws", "snowflake"} {
			if sys != "okta" && r.Intn(2) == 0 {
				continue
			}
			x := fmt.Sprintf("%s-%s", sys, id.ExternalID)
			acct := connectors.AccountRecord{System: sys, ExternalID: x, Username: x, Identity: &connectors.IdentityRef{ExternalID: id.ExternalID},
				Kind: map[string]string{"human": "user", "service": "service", "ai_agent": "agent"}[id.Type]}
			if r.Intn(6) == 0 {
				acct.Status = "disabled"
			}
			res.Accounts = append(res.Accounts, acct)
			a := connectors.Ref{Kind: "account", System: sys, ExternalID: x}
			if sys == "okta" {
				oktaAcct = x
				for j := 0; j < r.Intn(3); j++ {
					edge(a, ref("group", oktaGroups[r.Intn(len(oktaGroups))]), "member_of")
				}
			} else {
				for j := 0; j < r.Intn(3); j++ {
					if r.Intn(2) == 0 {
						edge(a, ref("group", roles[r.Intn(len(roles))]), "member_of")
					} else {
						edge(a, ref("perm", perms[r.Intn(len(perms))]), "direct_grant")
					}
				}
			}
			if id.Type != "human" && r.Intn(2) == 0 {
				sec := connectors.SecretRecord{System: sys, ExternalID: "k-" + x, Account: a, Kind: "access_key", Name: "KEY" + x,
					CreatedAt: days(1 + r.Intn(500))}
				if r.Intn(3) == 0 {
					rot := days(r.Intn(120))
					sec.LastRotatedAt = &rot
				}
				res.Secrets = append(res.Secrets, sec)
			}
		}
		if oktaAcct != "" && r.Intn(5) > 0 {
			for j := 0; j < r.Intn(3); j++ {
				kind, strength := "sms", "sms_voice"
				switch r.Intn(5) {
				case 0:
					kind, strength = "passkey", "phishing_resistant"
				case 1:
					kind, strength = "app_push", "push"
				case 2:
					kind, strength = "totp", "otp"
				case 3:
					kind, strength = "app_push", "push_number_match"
				}
				res.AuthMethods = append(res.AuthMethods, connectors.AuthMethodRecord{
					Account:    connectors.Ref{Kind: "account", System: "okta", ExternalID: oktaAcct},
					ExternalID: fmt.Sprintf("m-%s-%d", id.ExternalID, j), Strength: strength, Kind: kind, Label: kind})
			}
		}
	}
	return res, nil
}

var genTenant = tenancy.MustParse("00000000-0000-4000-8000-0000000000b1")

// genWorld ingests the generated world of the seed into a fresh database.
func genWorld(tb testing.TB, seed int64) *testkit.DB {
	tb.Helper()
	st := testkit.Open(tb)
	testkit.CreateTenant(tb, st, genTenant, "gen")
	db := &testkit.DB{DB: st, Tenant: genTenant}
	testkit.Write(tb, db, func(c *store.TenantTx) error {
		_, err := ingest.Sync(c, testkit.Now, []connectors.Connector{genConn{seed: seed, now: testkit.Now}}, nil)
		return err
	})
	return db
}
