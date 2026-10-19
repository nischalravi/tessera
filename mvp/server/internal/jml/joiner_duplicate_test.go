package jml_test

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func joinerPayload(email, hrID string) ojson.Object {
	p := ojson.Object{{Key: "name", Value: "Noor Achterberg"}, {Key: "email", Value: email}, {Key: "department", Value: "Data"}}
	if hrID != "" {
		p = append(p, ojson.KV{Key: "employee_id", Value: hrID})
	}
	return p
}

func addIdentity(t *testing.T, st *testkit.DB, xid, email, status string) int64 {
	t.Helper()
	var id int64
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		id, err = c.InsertIdentity(&store.Identity{ExternalID: xid, Name: "Existing " + xid, Email: &email, Type: "human",
			Status: status, CreatedAt: testkit.Now})
		return err
	})
	return id
}

var joinerSeq atomic.Int64

func executeJoiner(t *testing.T, st *testkit.DB, payload ojson.Object) error {
	t.Helper()
	return st.InTenant(t.Context(), st.Tenant, func(c *store.TenantTx) error {
		evID, err := c.InsertHrisEvent(&store.HrisEvent{ExternalID: fmt.Sprintf("j-%d", joinerSeq.Add(1)), Type: "joiner", Payload: payload,
			EffectiveAt: testkit.Now, Status: "pending"})
		if err != nil {
			return err
		}
		_, err = jml.ExecuteEvent(c, testkit.Now, evID, store.UserRef{Display: "jml-automation"}, testkit.Policies(t))
		return err
	})
}

func activeCount(t *testing.T, st *testkit.DB) int {
	t.Helper()
	n := 0
	for _, i := range testkit.Get(t, st, func(c *store.TenantTx) ([]*store.Identity, error) { return c.Identities() }) {
		if i.Status == "active" && i.Name == "Noor Achterberg" {
			n++
		}
	}
	return n
}

func TestJoinerDuplicateRefused(t *testing.T) {
	tests := []struct {
		name         string
		xid, email   string // the existing active identity
		payloadEmail string
		payloadHR    string
		wantOn       string
	}{
		{"email in another case", "emp-70", "Noor.Achterberg@Larkspur.example", " noor.ACHTERBERG@larkspur.example ", "", "email"},
		{"hr id", "emp-71", "someone.else@larkspur.example", "noor@larkspur.example", "emp-71", "hr_id"},
		{"both match: email reported", "emp-72", "noor@larkspur.example", "noor@larkspur.example", "emp-72", "email"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, _ := testkit.Tiny(t)
			existing := addIdentity(t, st, tt.xid, tt.email, "active")
			before := len(testkit.Get(t, st, func(c *store.TenantTx) ([]*store.Identity, error) { return c.Identities() }))
			err := executeJoiner(t, st, joinerPayload(tt.payloadEmail, tt.payloadHR))
			var ex *jml.ExistsError
			if !errors.As(err, &ex) || ex.ExistingID != existing || ex.MatchedOn != tt.wantOn {
				t.Fatalf("err = %v, want ExistsError{%d, %s}", err, existing, tt.wantOn)
			}
			if after := len(testkit.Get(t, st, func(c *store.TenantTx) ([]*store.Identity, error) { return c.Identities() })); after != before {
				t.Errorf("identities %d -> %d: a refused joiner left a row", before, after)
			}
		})
	}
}

func TestJoinerRehireAfterLeaverAllowed(t *testing.T) {
	st, _ := testkit.Tiny(t)
	old := addIdentity(t, st, "emp-80", "noor.achterberg@larkspur.example", "terminated")
	// the former employee returns with the same email and HR id
	if err := executeJoiner(t, st, joinerPayload("Noor.Achterberg@larkspur.example", "emp-80")); err != nil {
		t.Fatalf("rehire: %v", err)
	}
	if n := activeCount(t, st); n != 1 {
		t.Errorf("active Noor identities = %d, want 1", n)
	}
	testkit.Read(t, st, func(c *store.TenantTx) error {
		o, err := c.Identity(old)
		if err != nil || o.Status != "terminated" {
			t.Errorf("old identity = %+v, %v; want it left terminated", o, err)
		}
		return nil
	})
	// and now a second join is a duplicate of the rehired identity
	var ex *jml.ExistsError
	if err := executeJoiner(t, st, joinerPayload("noor.achterberg@larkspur.example", "")); !errors.As(err, &ex) {
		t.Errorf("second join after rehire: %v, want ExistsError", err)
	}
}

func TestJoinerHRIDBecomesExternalID(t *testing.T) {
	st, _ := testkit.Tiny(t)
	if err := executeJoiner(t, st, joinerPayload("noor@larkspur.example", "emp-90")); err != nil {
		t.Fatal(err)
	}
	var ex *jml.ExistsError
	if err := executeJoiner(t, st, joinerPayload("other@larkspur.example", "emp-90")); !errors.As(err, &ex) || ex.MatchedOn != "hr_id" {
		t.Errorf("same HR id, new email: %v, want hr_id ExistsError", err)
	}
}
