package connectors

import (
	"context"
	"strings"
	"time"
)

func tinyDays(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func tinyIdent(x string) *IdentityRef { return &IdentityRef{ExternalID: x} }

func tinyAcct(system, xid string) Ref {
	return Ref{Kind: "account", System: system, ExternalID: xid}
}
func tinyGroup(system, xid string) Ref {
	return Ref{Kind: "group", System: system, ExternalID: xid}
}
func tinyPerm(system, xid string) Ref {
	return Ref{Kind: "perm", System: system, ExternalID: xid}
}

// Tiny is a minimal Connector describing the tiny world (see the package
// comment of internal/testkit for its shape). It is the second demo tenant
// ("globex") and the isolation-test fixture.
//
// Sentinel, when set, is appended to every name and resource tag and folded
// into every email, so a test can prove that no response for another tenant
// contains it. Domain is the email domain (default "t.example").
type Tiny struct {
	Now      time.Time
	Sentinel string
	Domain   string
}

// mark appends the sentinel to a display string.
func (t Tiny) mark(s string) string {
	if t.Sentinel == "" {
		return s
	}
	return s + " " + t.Sentinel
}

// email builds local@domain, folding in the sentinel.
func (t Tiny) email(local string) string {
	d := t.Domain
	if d == "" {
		d = "t.example"
	}
	if t.Sentinel != "" {
		local += "." + strings.ToLower(t.Sentinel)
	}
	return local + "@" + d
}

// System implements Connector.
func (Tiny) System() string { return "tiny" }

// DisplayName implements Connector.
func (Tiny) DisplayName() string { return "Tiny test connector" }

// TypeName implements Connector.
func (Tiny) TypeName() string { return "TinyConnector" }

// Discover implements Connector.
func (t Tiny) Discover(context.Context) (*DiscoveryResult, error) {
	term := t.Now.Add(-tinyDays(10))
	human := func(xid, name, dept string, mgr *IdentityRef) IdentityRecord {
		return IdentityRecord{ExternalID: xid, Name: t.mark(name), Type: "human", Email: sp(t.email(xid)), Department: sp(dept),
			Manager: mgr}
	}
	tags := func(ts ...string) []string {
		if t.Sentinel != "" {
			ts = append(ts, t.Sentinel)
		}
		return ts
	}
	dave := human("dave", "Dave", "Data", tinyIdent("carol"))
	dave.Status, dave.TerminatedAt = "terminated", &term
	r := &DiscoveryResult{
		Identities: []IdentityRecord{
			human("alice", "Alice", "Engineering", tinyIdent("carol")),
			human("bob", "Bob", "Finance", tinyIdent("carol")),
			human("carol", "Carol", "Engineering", nil),
			dave,
			{ExternalID: "svc-etl", Name: t.mark("svc-etl"), Type: "service", Owner: tinyIdent("dave")},
			{ExternalID: "helper-bot", Name: t.mark("Helper Bot"), Type: "ai_agent", Owner: tinyIdent("alice")},
		},
		Resources: []ResourceRecord{
			{System: "aws", ExternalID: "customer-pii", Name: t.mark("s3://customer-pii"), Kind: "s3_bucket", Environment: sp("prod"), Tags: tags("pii")},
			{System: "aws", ExternalID: "ml-artifacts", Name: t.mark("s3://ml-artifacts"), Kind: "s3_bucket", Environment: sp("staging"), Tags: tags()},
			{System: "aws", ExternalID: "prod", Name: t.mark("aws/prod"), Kind: "aws_account", Environment: sp("prod"), Tags: tags()},
			{System: "workday", ExternalID: "payments", Name: t.mark("Supplier Payments"), Kind: "business_process", Environment: sp("prod"), Tags: tags("payments")},
			{System: "snowflake", ExternalID: "CUSTOMERS", Name: t.mark("snowflake/CUSTOMERS"), Kind: "database", Environment: sp("prod"), Tags: tags("pii")},
		},
		Permissions: []PermissionRecord{
			{System: "aws", ExternalID: "get-pii", Action: "s3:GetObject", ResourceExternalID: "customer-pii"},
			{System: "aws", ExternalID: "put-ml", Action: "s3:PutObject", ResourceExternalID: "ml-artifacts"},
			{System: "aws", ExternalID: "admin-prod", Action: "iam:*", ResourceExternalID: "prod", Privileged: true},
			{System: "workday", ExternalID: "pay-create", Action: "payments:create", ResourceExternalID: "payments"},
			{System: "workday", ExternalID: "pay-approve", Action: "payments:approve", ResourceExternalID: "payments"},
			{System: "snowflake", ExternalID: "select-customers", Action: "snowflake:SELECT", ResourceExternalID: "CUSTOMERS"},
		},
		Groups: []GroupRecord{
			{System: "okta", ExternalID: "eng", Name: t.mark("eng")},
			{System: "okta", ExternalID: "platform", Name: t.mark("platform")},
			{System: "okta", ExternalID: "payments-clerks", Name: t.mark("payments-clerks")},
			{System: "okta", ExternalID: "payments-approvers", Name: t.mark("payments-approvers")},
			{System: "aws", ExternalID: "DevAdmin", Name: t.mark("DevAdmin"), Kind: "role"},
			{System: "aws", ExternalID: "ProdAdmin", Name: t.mark("ProdAdmin"), Kind: "role", Privileged: true, Requestable: true},
			{System: "snowflake", ExternalID: "ANALYST", Name: t.mark("ANALYST"), Kind: "role"},
			{System: "snowflake", ExternalID: "PII_READER", Name: t.mark("PII_READER"), Kind: "role"},
		},
		Accounts: []AccountRecord{
			{System: "okta", ExternalID: "alice", Username: t.email("alice"), Identity: tinyIdent("alice")},
			{System: "okta", ExternalID: "bob", Username: t.email("bob"), Identity: tinyIdent("bob")},
			{System: "okta", ExternalID: "carol", Username: t.email("carol"), Identity: tinyIdent("carol")},
			{System: "okta", ExternalID: "dave", Username: t.email("dave"), Identity: tinyIdent("dave"), Status: "disabled"},
			{System: "aws", ExternalID: "dave-iam", Username: "dave", Identity: tinyIdent("dave")}, // missed in offboarding
			{System: "aws", ExternalID: "svc-etl", Username: "svc-etl", Identity: tinyIdent("svc-etl"), Kind: "service"},
			{System: "snowflake", ExternalID: "HELPER_BOT", Username: "HELPER_BOT", Identity: tinyIdent("helper-bot"), Kind: "agent"},
		},
		Edges: []EdgeRecord{
			{Src: tinyAcct("okta", "alice"), Dst: tinyGroup("okta", "eng"), Relation: "member_of"},
			{Src: tinyGroup("okta", "eng"), Dst: tinyGroup("aws", "DevAdmin"), Relation: "maps_to"},
			{Src: tinyGroup("aws", "DevAdmin"), Dst: tinyPerm("aws", "get-pii"), Relation: "grants"},
			{Src: tinyGroup("aws", "DevAdmin"), Dst: tinyPerm("aws", "put-ml"), Relation: "grants"},
			{Src: tinyAcct("okta", "bob"), Dst: tinyGroup("okta", "payments-clerks"), Relation: "member_of"},
			{Src: tinyAcct("okta", "bob"), Dst: tinyGroup("okta", "payments-approvers"), Relation: "member_of"},
			{Src: tinyGroup("okta", "payments-clerks"), Dst: tinyPerm("workday", "pay-create"), Relation: "grants"},
			{Src: tinyGroup("okta", "payments-approvers"), Dst: tinyPerm("workday", "pay-approve"), Relation: "grants"},
			{Src: tinyAcct("okta", "carol"), Dst: tinyGroup("okta", "platform"), Relation: "member_of"},
			{Src: tinyAcct("okta", "carol"), Dst: tinyGroup("okta", "eng"), Relation: "member_of"},
			{Src: tinyGroup("okta", "platform"), Dst: tinyGroup("aws", "ProdAdmin"), Relation: "maps_to"},
			{Src: tinyGroup("aws", "ProdAdmin"), Dst: tinyPerm("aws", "admin-prod"), Relation: "grants"},
			{Src: tinyAcct("okta", "dave"), Dst: tinyGroup("okta", "eng"), Relation: "member_of"},
			{Src: tinyAcct("aws", "dave-iam"), Dst: tinyPerm("aws", "get-pii"), Relation: "direct_grant"},
			{Src: tinyAcct("aws", "svc-etl"), Dst: tinyPerm("aws", "get-pii"), Relation: "direct_grant"},
			{Src: tinyAcct("snowflake", "HELPER_BOT"), Dst: tinyGroup("snowflake", "ANALYST"), Relation: "member_of"},
			{Src: tinyGroup("snowflake", "ANALYST"), Dst: tinyGroup("snowflake", "PII_READER"), Relation: "maps_to"},
			{Src: tinyGroup("snowflake", "PII_READER"), Dst: tinyPerm("snowflake", "select-customers"), Relation: "grants"},
		},
		Secrets: []SecretRecord{
			{System: "aws", ExternalID: "svc-etl-key", Account: tinyAcct("aws", "svc-etl"), Kind: "access_key", Name: t.mark("AKIAETL"),
				CreatedAt: t.Now.Add(-tinyDays(400))},
		},
		Delegations: []DelegationRecord{
			{Agent: IdentityRef{ExternalID: "helper-bot"}, Principal: IdentityRef{ExternalID: "alice"},
				Scopes: []string{"snowflake:query"}},
		},
	}
	return r, nil
}

// StreamEvents implements Connector: alice uses PutObject on
// ml-artifacts every third day and never touches customer-pii; carol last used
// prod admin 75 days ago; bob created a payment yesterday.
func (t Tiny) StreamEvents(_ context.Context, _ *time.Time, yield func(Event) error) error {
	for d := 0; d < 90; d += 3 {
		if err := yield(&UsageRecord{Identity: *tinyIdent("alice"), Permission: tinyPerm("aws", "put-ml"), Day: t.Now.Add(-tinyDays(d)), Count: 5}); err != nil {
			return err
		}
	}
	if err := yield(&UsageRecord{Identity: *tinyIdent("carol"), Permission: tinyPerm("aws", "admin-prod"), Day: t.Now.Add(-tinyDays(75)), Count: 1}); err != nil {
		return err
	}
	return yield(&UsageRecord{Identity: *tinyIdent("bob"), Permission: tinyPerm("workday", "pay-create"), Day: t.Now.Add(-tinyDays(1)), Count: 3})
}
