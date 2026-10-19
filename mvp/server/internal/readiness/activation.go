package readiness

import (
	"errors"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Two-person activation (design §4.4, §9; DR-10). A revision whose write_mode
// is not "off" can write to the customer's directory, so activating it needs
// two different people: one requests (RequestActivation), another approves
// (ApproveActivation), and the approval applies the activation in the same
// transaction. Phase 0's admin-change workflow (PR12, issue #16) does not
// exist yet; the request table here is the `connection.activate` change type
// of that workflow, held in readiness until it lands.

// ActivationTTL is how long a request waits for its second person (the 72 h
// approval window of Phase 0 §15.2).
const ActivationTTL = 72 * time.Hour

// Person is who acts: Key is the stable principal key compared by the
// two-person rule (for a user, "user:<uuid>"), Display is what the audit
// trail and attestations record.
type Person struct{ Key, Display string }

// RequiresSecondPerson reports whether activating the connection's
// in-progress revision needs a second approver.
func (s *Service) RequiresSecondPerson(c *store.TenantTx, connID string) (bool, error) {
	_, _, pending, err := Revisions(c, connID)
	if err != nil {
		return false, err
	}
	if pending == nil {
		return false, nil
	}
	// The mode the gate reads is the config's; the column mirrors it. Either
	// being write-enabled needs the second person.
	cfg, err := DecodeConfig([]byte(pending.Config))
	if err != nil {
		return false, err
	}
	return writeMode(cfg) != "off" || pending.WriteMode != "off", nil
}

// RequestActivation records the first person's request to activate a
// write-enabled revision. The gate is evaluated now, so a request is never
// made for a revision that could not be activated; it is evaluated again at
// approval. A repeat request by the same person returns the open one.
func (s *Service) RequestActivation(c *store.TenantTx, connID string, by Person, now time.Time) (*store.ActivationRequest, error) {
	_, _, b, _, err := s.activationGate(c, connID, by.Display, now, true)
	if err != nil {
		return nil, err
	}
	mode := writeMode(b.Config)
	if mode == "off" {
		return nil, conflict("second_approver_not_required", "this revision is read-only (write_mode off); activate it directly")
	}
	open, err := c.PendingActivationRequest(connID)
	switch {
	case err == nil:
		if open.RevisionID == b.Rev.ID && open.ConfigHash == b.ConfigHash && now.Before(open.ExpiresAt) {
			return open, nil // still valid: the second person decides it
		}
		status, why := store.ActivationCancelled, "superseded: the revision or its configuration changed"
		if open.RevisionID == b.Rev.ID && open.ConfigHash == b.ConfigHash {
			status, why = store.ActivationExpired, "expired without approval"
		}
		if err := c.DecideActivationRequest(open.ID, status, "system", "system", why, now); err != nil {
			return nil, err
		}
		if err := c.Audit(now, "system", "connection.activation."+status, ojson.Object{{Key: "connection_id", Value: connID},
			{Key: "request_id", Value: open.ID}, {Key: "reason", Value: why}}); err != nil {
			return nil, err
		}
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	req := &store.ActivationRequest{ID: store.NewID(), ConnectionID: connID, RevisionID: b.Rev.ID, ConfigHash: b.ConfigHash,
		WriteMode: mode, RequestedByKey: by.Key, RequestedBy: by.Display, RequestedAt: now,
		ExpiresAt: now.Add(ActivationTTL)}
	if err := c.InsertActivationRequest(req); err != nil {
		return nil, err
	}
	if err := c.Audit(now, by.Display, "connection.activation.requested", ojson.Object{{Key: "connection_id", Value: connID},
		{Key: "revision_id", Value: b.Rev.ID}, {Key: "request_id", Value: req.ID}, {Key: "write_mode", Value: req.WriteMode},
		{Key: "config_hash", Value: b.ConfigHash}, {Key: "expires_at", Value: store.RT(req.ExpiresAt)}}); err != nil {
		return nil, err
	}
	return c.PendingActivationRequest(connID)
}

// ApproveActivation is the `connection.activate` applier: a second person
// approves the open request and, in the same transaction, the activation is
// applied after the gate is evaluated once more. Refused (409) when the
// approver is the requester or attested any item of the revision (an
// attestation and the approval cannot both be by one person), or when the
// request is stale (the revision or its config hash changed) or expired.
func (s *Service) ApproveActivation(c *store.TenantTx, connID string, by Person, note string, now time.Time) (*Bundle, ActiveConnection, error) {
	req, err := c.PendingActivationRequest(connID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ActiveConnection{}, conflict("no_activation_request", "no activation request is waiting for approval")
	}
	if err != nil {
		return nil, ActiveConnection{}, err
	}
	if by.Key == "" || by.Key == req.RequestedByKey {
		return nil, ActiveConnection{}, newErr(403, "two_person_rule", "the person who requested the activation cannot approve it")
	}
	if !now.Before(req.ExpiresAt) {
		return nil, ActiveConnection{}, conflict("activation_request_expired", "the request expired at %s; request again",
			req.ExpiresAt.UTC().Format(time.RFC3339))
	}
	_, _, b, _, err := s.activationGate(c, connID, by.Display, now, true)
	if err != nil {
		return nil, ActiveConnection{}, err
	}
	if req.RevisionID != b.Rev.ID || req.ConfigHash != b.ConfigHash || req.WriteMode != writeMode(b.Config) {
		return nil, ActiveConnection{}, conflict("activation_request_stale",
			"the revision changed after the request was made; request activation again")
	}
	atts, err := c.Attestations(b.Rev.ID)
	if err != nil {
		return nil, ActiveConnection{}, err
	}
	for item, a := range atts {
		if strings.EqualFold(a.ActorID, by.Display) {
			return nil, ActiveConnection{}, newErr(403, "two_person_rule",
				"%s attested %s on this revision and cannot also approve its activation", by.Display, item)
		}
	}
	if err := c.DecideActivationRequest(req.ID, store.ActivationApplied, by.Key, by.Display, note, now); err != nil {
		return nil, ActiveConnection{}, err
	}
	if err := c.Audit(now, by.Display, "connection.activation.approved", ojson.Object{{Key: "connection_id", Value: connID},
		{Key: "revision_id", Value: b.Rev.ID}, {Key: "request_id", Value: req.ID}, {Key: "requested_by", Value: req.RequestedBy},
		{Key: "note", Value: note}}); err != nil {
		return nil, ActiveConnection{}, err
	}
	// The applied request is now evidence: the gate, evaluated once more
	// inside Activate, accepts the approval for this exact config hash.
	return s.Activate(c, connID, by.Display, now)
}

// RejectActivation closes the open request: the requester cancels it, anyone
// else with connections.activate rejects it. Closing narrows access, so it
// needs no second person.
func (s *Service) RejectActivation(c *store.TenantTx, connID string, by Person, note string, now time.Time) (*store.ActivationRequest, error) {
	req, err := c.PendingActivationRequest(connID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, conflict("no_activation_request", "no activation request is waiting for approval")
	}
	if err != nil {
		return nil, err
	}
	status := store.ActivationRejected
	if by.Key == req.RequestedByKey {
		status = store.ActivationCancelled
	}
	if err := c.DecideActivationRequest(req.ID, status, by.Key, by.Display, note, now); err != nil {
		return nil, err
	}
	if err := c.Audit(now, by.Display, "connection.activation."+status, ojson.Object{{Key: "connection_id", Value: connID},
		{Key: "revision_id", Value: req.RevisionID}, {Key: "request_id", Value: req.ID}, {Key: "note", Value: note}}); err != nil {
		return nil, err
	}
	return c.LatestActivationRequest(connID)
}
