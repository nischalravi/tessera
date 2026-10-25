package agentmap_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/agentmap"
)

func TestPerson(t *testing.T) {
	for _, tc := range []struct {
		in, email, text string
	}{
		{"Pat@Acme.example", "pat@acme.example", "Pat@Acme.example"},
		{"  olu@acme.example ", "olu@acme.example", "olu@acme.example"},
		{"a-team", "", "a-team"},
		{"arn:aws:iam::1:user/x", "", "arn:aws:iam::1:user/x"},
		{"a b@c.d", "", "a b@c.d"},
		{"", "", ""},
	} {
		ref, text := agentmap.Person(tc.in)
		if (ref == nil) != (tc.email == "") || ref != nil && ref.Email != tc.email || text != tc.text {
			t.Errorf("Person(%q) = %v, %q", tc.in, ref, text)
		}
	}
	if _, text := agentmap.Person(strings.Repeat("x", 1000)); len(text) != 256 {
		t.Errorf("a long value is clipped to %d", len(text))
	}
}

func TestClipDropsControlCharacters(t *testing.T) {
	if got := agentmap.Clip("a\x00b\nc\x7fd", 10); got != "abcd" {
		t.Errorf("Clip = %q", got)
	}
	if got := agentmap.Clip("abcdef", 3); got != "abc" {
		t.Errorf("Clip = %q", got)
	}
}

func TestBuild(t *testing.T) {
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	res := agentmap.Build("x-sys", "x:", "An X agent", []agentmap.Agent{
		{ID: "1", Name: "one", Kind: "x_agent", Owner: "Pat@acme.example", Creator: "svc", Created: created, PII: true, Tags: []string{"anonymous_access"},
			Access: []agentmap.Access{{Resource: "r1", Name: "R1", Kind: "k", Action: "invoke"}, {Resource: "r2", Name: "R2", Kind: "k", Action: "exec", Privileged: true, Tags: []string{"code_execution"}}}},
		{ID: "2", Disabled: true, Access: []agentmap.Access{{Resource: "r1", Name: "R1", Kind: "k", Action: "invoke"}}},
	})
	if len(res.Identities) != 2 || res.Identities[0].ExternalID != "x:1" || res.Identities[0].Owner == nil || res.Identities[0].Owner.Email != "pat@acme.example" || res.Identities[0].Type != "ai_agent" {
		t.Fatalf("identities = %+v", res.Identities)
	}
	if res.Identities[1].Name != "2" || res.Identities[1].Status != "disabled" || *res.Identities[1].Description != "An X agent" {
		t.Errorf("second identity = %+v", res.Identities[1])
	}
	if a := res.Agents[0]; a.Kind != "x_agent" || a.SponsorRef != "Pat@acme.example" || a.CreatorRef != "svc" || a.Creator != nil {
		t.Errorf("agent = %+v", a)
	}
	if res.Accounts[0].CreatedAt == nil || !res.Accounts[0].CreatedAt.Equal(created) || res.Accounts[1].CreatedAt != nil {
		t.Errorf("accounts = %+v", res.Accounts)
	}
	// a resource and a permission two agents share are listed once, and both are granted it
	if len(res.Resources) != 2 || len(res.Permissions) != 2 || len(res.Edges) != 3 {
		t.Errorf("resources %d permissions %d edges %d", len(res.Resources), len(res.Permissions), len(res.Edges))
	}
	if r := res.Resources[1]; !slices.Equal(r.Tags, []string{"anonymous_access", "pii", "code_execution"}) {
		t.Errorf("tags = %v", r.Tags)
	}
	if !res.Permissions[1].Privileged || res.Permissions[0].Privileged {
		t.Errorf("permissions = %+v", res.Permissions)
	}
	if !slices.Equal(res.AgentSnapshotOf, []string{"x-sys"}) {
		t.Errorf("snapshot of = %v", res.AgentSnapshotOf)
	}
}
