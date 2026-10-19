package readiness

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var (
	ingrid = Person{Key: "user:ingrid", Display: "ingrid"} // attested the items
	pam    = Person{Key: "user:pam", Display: "pam"}       // requests
	olu    = Person{Key: "user:olu", Display: "olu"}       // approves
)

// writeEnabledReady creates a demo AD connection with write_mode scoped,
// attested by ingrid, and drives it to dry_run_reconciled.
func writeEnabledReady(t *testing.T, s *Service, st Scope, name string) string {
	t.Helper()
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: name, ConnectorType: "demo-ad", System: strings.ToLower(strings.ReplaceAll(name, " ", "-")),
			Config: json.RawMessage(`{"technical_owner":"Ingrid Lindqvist","business_owner":"Thandiwe Mokoena","write_mode":"scoped"}`)},
			ingrid.Display, t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		if _, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/tessera/ad"}, ingrid.Display, t0); err != nil {
			return err
		}
		for _, item := range append([]string{"base.writeback.scope", "base.writeback.dryrun"}, adAttestations...) {
			// the write-back items that checks verify cannot be attested
			if _, err := s.Attest(c, id, item, "checked in the console", ingrid.Display, t0); err != nil && codeOf(err) != "not_attestable" {
				return err
			}
		}
		if _, err := s.Skip(c, id, "ad.tls.signing_cb", "Scheduled for the Q1 domain controller upgrade", nil, ingrid.Display, t0); err != nil {
			return err
		}
		if _, err := s.Transition(c, id, store.StateReadyToValidate, ingrid.Display, t0); err != nil {
			return err
		}
		b, err = s.Current(c, id, t0)
		if err != nil {
			return err
		}
		if err := s.advanceAfterValidation(c, b, ingrid.Display, t0); err != nil {
			return err
		}
		_, err = s.Transition(c, id, store.StateDryRunReconciled, ingrid.Display, t0)
		return err
	})
	return id
}

func newWriteEnabled(t *testing.T) (Scope, *Service, string) {
	t.Helper()
	st, s := newStore(t), newSvc(t)
	// evidence finishing after the 72 h request window keeps the gate open at
	// every time the tests use (live evidence otherwise expires after 24 h)
	(&fakeEvidence{on: true, runAt: t0.Add(ActivationTTL + time.Hour)}).install(s)
	id := writeEnabledReady(t, s, st, "AD writeback")
	if got := state(t, s, st, id); got != store.StateDryRunReconciled {
		t.Fatalf("setup: state %s, want dry_run_reconciled", got)
	}
	return st, s, id
}

func try(st Scope, fn func(c *store.TenantTx) error) error {
	return st.Write(context.Background(), fn)
}

func latest(t *testing.T, st Scope, id string) *store.ActivationRequest {
	t.Helper()
	var a *store.ActivationRequest
	read(t, st, func(c *store.TenantTx) error {
		var err error
		a, err = c.LatestActivationRequest(id)
		return err
	})
	return a
}

// TestTwoPerson_DirectActivationRefused: the gate refuses a write-enabled
// revision with no approval, so no caller of Activate can skip the second person.
func TestTwoPerson_DirectActivationRefused(t *testing.T) {
	st, s, id := newWriteEnabled(t)
	err := try(st, func(c *store.TenantTx) error {
		_, _, err := s.Activate(c, id, pam.Display, t0)
		return err
	})
	var re *Error
	if codeOf(err) != "activation_blocked" || !asErr(err, &re) || len(re.Report.Blocking) != 1 || re.Report.Blocking[0].Item != ApprovalItem {
		t.Fatalf("direct activation of a write-enabled revision: %v", err)
	}
	var two bool
	read(t, st, func(c *store.TenantTx) error {
		var err error
		two, err = s.RequiresSecondPerson(c, id)
		return err
	})
	if !two {
		t.Error("RequiresSecondPerson = false for write_mode scoped")
	}
}

func asErr(err error, re **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*re = e
	}
	return ok
}

func TestTwoPerson_RequestApproveActivates(t *testing.T) {
	st, s, id := newWriteEnabled(t)
	var first *store.ActivationRequest
	write(t, st, func(c *store.TenantTx) error {
		var err error
		first, err = s.RequestActivation(c, id, pam, t0)
		return err
	})
	if first.Status != store.ActivationPending || first.RequestedBy != "pam" || first.WriteMode != "scoped" ||
		!first.ExpiresAt.Equal(t0.Add(ActivationTTL)) {
		t.Fatalf("request = %+v", first)
	}
	if got := state(t, s, st, id); got != store.StateDryRunReconciled {
		t.Fatalf("requesting changed the state to %s", got)
	}
	// a repeat request returns the open one
	write(t, st, func(c *store.TenantTx) error {
		again, err := s.RequestActivation(c, id, pam, t0.Add(time.Minute))
		if err == nil && again.ID != first.ID {
			t.Errorf("repeat request made a new request %s", again.ID)
		}
		return err
	})

	for _, tc := range []struct {
		name string
		by   Person
	}{
		{"the requester", pam},
		{"an attestor of the revision", ingrid},
		{"an attestor, spelled differently", Person{Key: "user:ingrid2", Display: "INGRID"}},
		{"nobody", Person{}},
	} {
		err := try(st, func(c *store.TenantTx) error {
			_, _, err := s.ApproveActivation(c, id, tc.by, "", t0.Add(time.Hour))
			return err
		})
		if codeOf(err) != "two_person_rule" {
			t.Errorf("%s approving: %v, want two_person_rule", tc.name, err)
		}
	}
	if got := state(t, s, st, id); got != store.StateDryRunReconciled {
		t.Fatalf("a refused approval left the state at %s", got)
	}

	write(t, st, func(c *store.TenantTx) error {
		_, ac, err := s.ApproveActivation(c, id, olu, "reviewed the write scope", t0.Add(time.Hour))
		if err == nil && ac.ConnectionID() != id {
			t.Errorf("active connection %s", ac.ConnectionID())
		}
		return err
	})
	if got := state(t, s, st, id); got != store.StateActive {
		t.Fatalf("state after approval = %s, want active", got)
	}
	a := latest(t, st, id)
	if a.Status != store.ActivationApplied || a.DecidedBy != "olu" || a.DecidedByKey == a.RequestedByKey || a.DecisionNote != "reviewed the write scope" {
		t.Errorf("applied request = %+v", a)
	}
	var events []string
	read(t, st, func(c *store.TenantTx) error {
		es, err := c.AuditLog(0)
		for _, e := range es {
			events = append(events, e.Action)
		}
		return err
	})
	for _, want := range []string{"connection.activation.requested", "connection.activation.approved", "connection.activated"} {
		found := false
		for _, e := range events {
			found = found || e == want
		}
		if !found {
			t.Errorf("no %s audit event in %v", want, events)
		}
	}
	// the approval is spent: it cannot be approved again
	err := try(st, func(c *store.TenantTx) error {
		_, _, err := s.ApproveActivation(c, id, olu, "", t0.Add(2*time.Hour))
		return err
	})
	if codeOf(err) != "no_activation_request" {
		t.Errorf("second approval: %v", err)
	}
}

func TestTwoPerson_StaleExpiredAndRejected(t *testing.T) {
	t.Run("a config change after the request refuses the approval", func(t *testing.T) {
		st, s, id := newWriteEnabled(t)
		write(t, st, func(c *store.TenantTx) error {
			_, err := s.RequestActivation(c, id, pam, t0)
			return err
		})
		write(t, st, func(c *store.TenantTx) error {
			_, err := s.PatchConfig(c, id, []byte(`{"host":"dc09.corp.larkspur.example"}`), pam.Display, t0)
			return err
		})
		err := try(st, func(c *store.TenantTx) error {
			_, _, err := s.ApproveActivation(c, id, olu, "", t0)
			return err
		})
		if c := codeOf(err); c != "activation_blocked" && c != "activation_request_stale" {
			t.Errorf("approving a request made for another configuration: %v", err)
		}
		if got := state(t, s, st, id); got == store.StateActive {
			t.Error("the connection was activated against a changed configuration")
		}
	})
	t.Run("an expired request cannot be approved", func(t *testing.T) {
		st, s, id := newWriteEnabled(t)
		write(t, st, func(c *store.TenantTx) error {
			_, err := s.RequestActivation(c, id, pam, t0)
			return err
		})
		err := try(st, func(c *store.TenantTx) error {
			_, _, err := s.ApproveActivation(c, id, olu, "", t0.Add(ActivationTTL))
			return err
		})
		if codeOf(err) != "activation_request_expired" {
			t.Errorf("approving after the window: %v", err)
		}
	})
	t.Run("reject and cancel close the request", func(t *testing.T) {
		st, s, id := newWriteEnabled(t)
		request := func() {
			write(t, st, func(c *store.TenantTx) error {
				_, err := s.RequestActivation(c, id, pam, t0)
				return err
			})
		}
		request()
		write(t, st, func(c *store.TenantTx) error {
			a, err := s.RejectActivation(c, id, pam, "changed my mind", t0)
			if err == nil && a.Status != store.ActivationCancelled {
				t.Errorf("requester's close = %s, want cancelled", a.Status)
			}
			return err
		})
		request() // a new request is possible once the old one is closed
		write(t, st, func(c *store.TenantTx) error {
			a, err := s.RejectActivation(c, id, olu, "scope too broad", t0)
			if err == nil && (a.Status != store.ActivationRejected || a.DecidedBy != "olu") {
				t.Errorf("other person's close = %+v", a)
			}
			return err
		})
		err := try(st, func(c *store.TenantTx) error {
			_, _, err := s.ApproveActivation(c, id, olu, "", t0)
			return err
		})
		if codeOf(err) != "no_activation_request" {
			t.Errorf("approving a rejected request: %v", err)
		}
	})
	t.Run("a superseded request is closed by the next one", func(t *testing.T) {
		st, s, id := newWriteEnabled(t)
		write(t, st, func(c *store.TenantTx) error {
			_, err := s.RequestActivation(c, id, pam, t0)
			return err
		})
		var second *store.ActivationRequest
		write(t, st, func(c *store.TenantTx) error { // the first window has passed
			var err error
			second, err = s.RequestActivation(c, id, pam, t0.Add(ActivationTTL+time.Minute))
			return err
		})
		if second == nil || !second.ExpiresAt.After(t0.Add(ActivationTTL)) {
			t.Fatalf("second request = %+v", second)
		}
	})
}

// TestTwoPerson_ReadOnlyNeedsNoSecondPerson: write_mode off keeps the
// single-step activation, and a request for it is refused.
func TestTwoPerson_ReadOnlyNeedsNoSecondPerson(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	(&fakeEvidence{on: true, runAt: t0}).install(s)
	id := createAD(t, s, st, "AD readonly")
	readyToActivate(t, s, st, id)
	var two bool
	read(t, st, func(c *store.TenantTx) error {
		var err error
		two, err = s.RequiresSecondPerson(c, id)
		return err
	})
	if two {
		t.Error("RequiresSecondPerson = true for write_mode off")
	}
	err := try(st, func(c *store.TenantTx) error {
		_, err := s.RequestActivation(c, id, pam, t0)
		return err
	})
	if codeOf(err) != "second_approver_not_required" {
		t.Errorf("request for a read-only revision: %v", err)
	}
	write(t, st, func(c *store.TenantTx) error {
		_, _, err := s.Activate(c, id, pam.Display, t0)
		return err
	})
	if got := state(t, s, st, id); got != store.StateActive {
		t.Errorf("state = %s", got)
	}
}
