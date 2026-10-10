package readiness

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Transitions is the state machine (§4.1): from → allowed next states.
// Forward steps are gated; backward steps happen when evidence is
// invalidated; superseded is the old live revision after a swap (K6).
var Transitions = map[string][]string{
	store.StateDraft:            {store.StateReadyToValidate, store.StateRetired},
	store.StateReadyToValidate:  {store.StateValidated, store.StateDraft, store.StateRetired},
	store.StateValidated:        {store.StateDryRunReconciled, store.StateReadyToValidate, store.StateRetired},
	store.StateDryRunReconciled: {store.StateActive, store.StateValidated, store.StateRetired},
	store.StateActive:           {store.StateDegraded, store.StateRetired, store.StateSuperseded},
	store.StateDegraded:         {store.StateActive, store.StateRetired, store.StateSuperseded},
}

// CanTransition reports whether the state machine has the edge from → to.
func CanTransition(from, to string) bool { return slices.Contains(Transitions[from], to) }

// IsPending reports whether a state is one of the in-progress states.
func IsPending(state string) bool {
	return state == store.StateDraft || state == store.StateReadyToValidate || state == store.StateValidated ||
		state == store.StateDryRunReconciled
}

// IsLive reports whether a state is a live (syncing) state.
func IsLive(state string) bool { return state == store.StateActive || state == store.StateDegraded }

// previous is the state a pending revision falls back to when its own gate no longer holds.
var previous = map[string]string{
	store.StateReadyToValidate:  store.StateDraft,
	store.StateValidated:        store.StateReadyToValidate,
	store.StateDryRunReconciled: store.StateValidated,
}

// setState is the single place this package writes a revision state. It
// compare-and-sets on (state, config hash, evidence sequence).
func (s *Service) setState(c *store.TenantTx, b *Bundle, to string, report *GateReport, actor, reason string, now time.Time) error {
	from := b.Rev.State
	if !CanTransition(from, to) {
		return conflict("invalid_transition", "%s cannot move from %s to %s", b.Conn.Name, from, to)
	}
	var gate *string
	if report != nil {
		raw, err := json.Marshal(report)
		if err != nil {
			return err
		}
		g := string(raw)
		gate = &g
	}
	ch := store.StateChange{RevisionID: b.Rev.ID, From: from, To: to, ConfigHash: b.Rev.ConfigHash,
		EvidenceSeq: b.Rev.EvidenceSeq, GateReport: gate, Now: now}
	if to == store.StateActive {
		ch.ActivatedBy = &actor
	}
	if err := c.SetRevisionState(ch); errors.Is(err, store.ErrStateConflict) {
		return conflict("state_conflict", "the revision changed while the gate was evaluated; reload and retry")
	} else if err != nil {
		return err
	}
	b.Rev.State = to
	return c.Audit(now, actor, "connection.state_changed", ojson.Object{{Key: "connection_id", Value: b.Conn.ID},
		{Key: "revision_id", Value: b.Rev.ID}, {Key: "from", Value: from}, {Key: "to", Value: to},
		{Key: "reason", Value: reason}, {Key: "config_hash", Value: b.Rev.ConfigHash}})
}

// settle moves an in-progress revision back while the gate of its current
// state no longer holds (config changed, attestation invalidated, evidence
// expired), then stores the item states.
func (s *Service) settle(c *store.TenantTx, b *Bundle, actor string, now time.Time, why string) error {
	for IsPending(b.Rev.State) && b.Rev.State != store.StateDraft {
		g := b.Gate(b.Rev.State, now)
		if !g.Blocks() {
			break
		}
		if err := s.setState(c, b, previous[b.Rev.State], nil, actor, "invalidated: "+why, now); err != nil {
			return err
		}
	}
	return s.persist(c, b, now)
}

// persist stores the evaluated item states for reporting.
func (s *Service) persist(c *store.TenantTx, b *Bundle, now time.Time) error {
	states := make([]*store.ItemState, 0, len(b.Eval.Items))
	for _, it := range b.Eval.Items {
		st := &store.ItemState{RevisionID: b.Rev.ID, ItemID: it.ID, Level: string(it.Level), Status: it.Status,
			Source: "system", ConfigHash: b.ConfigHash, UpdatedAt: now}
		switch {
		case it.Status == StatusSkipped:
			st.Source, st.ActorID, st.Note, st.ReviewBy = "skip", &it.Skip.ActorID, &it.Skip.Reason, &it.Skip.ReviewBy
		case it.Status == StatusNotApplicable || it.Status == StatusBlocked:
		case it.HasKind(template.Data):
			st.Source = "data"
		case it.HasKind(template.Live):
			st.Source = "live"
		default:
			st.Source = "attestation"
		}
		if st.Source == "attestation" && it.Attestation != nil {
			st.ActorID, st.Note = &it.Attestation.ActorID, &it.Attestation.Note
		}
		for _, p := range it.Parts {
			if p.RunID != "" {
				id := p.RunID
				st.CheckRunID = &id
			}
		}
		states = append(states, st)
	}
	if err := c.ReplaceItemStates(b.Rev.ID, states); err != nil {
		return err
	}
	return s.RecordScore(c, b, now)
}

// Transition performs a user-requested forward step: draft →
// ready_to_validate or validated → dry_run_reconciled. A refused step
// returns 409 with the gate report.
func (s *Service) Transition(c *store.TenantTx, connID, to, actor string, now time.Time) (*Bundle, error) {
	if to != store.StateReadyToValidate && to != store.StateDryRunReconciled {
		return nil, unprocessable("invalid_target", "to must be ready_to_validate or dry_run_reconciled; use /activate or /retire")
	}
	_, _, pending, err := Revisions(c, connID)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return nil, conflict("no_pending_revision", "the connection has no revision in setup")
	}
	b, err := s.Load(c, pending, now)
	if err != nil {
		return nil, err
	}
	if err := s.settle(c, b, actor, now, "re-evaluated"); err != nil {
		return nil, err
	}
	g := b.Gate(to, now)
	if b.Rev.State != requiredFrom[to] {
		g.Blocking = append([]Blocker{{Item: "state", Status: b.Rev.State, Reason: "the revision must be " + requiredFrom[to] + " first"}}, g.Blocking...)
		return nil, blocked("transition_blocked", g)
	}
	if g.Blocks() {
		return nil, blocked("transition_blocked", g)
	}
	if err := s.setState(c, b, to, g, actor, "requested", now); err != nil {
		return nil, err
	}
	return b, s.persist(c, b, now)
}

// requiredFrom is the state a user-requested forward step starts from.
var requiredFrom = map[string]string{
	store.StateReadyToValidate:  store.StateDraft,
	store.StateDryRunReconciled: store.StateValidated,
}

// advanceAfterValidation moves ready_to_validate → validated when the gate
// holds after a validation run (the system transition of §4.2).
func (s *Service) advanceAfterValidation(c *store.TenantTx, b *Bundle, actor string, now time.Time) error {
	if err := s.settle(c, b, actor, now, "validation run"); err != nil {
		return err
	}
	if b.Rev.State == store.StateReadyToValidate {
		if g := b.Gate(store.StateValidated, now); !g.Blocks() {
			if err := s.setState(c, b, store.StateValidated, g, "system", "validation passed", now); err != nil {
				return err
			}
		}
	}
	return s.persist(c, b, now)
}

// ActiveConnection is a connection revision that passed every gate. Only
// this package can construct one (unexported fields), so code that syncs
// into the live graph cannot be handed a draft connection (§4.4).
type ActiveConnection struct {
	connectionID, revisionID, system, connectorType, name string
}

// ConnectionID returns the connection id.
func (a ActiveConnection) ConnectionID() string { return a.connectionID }

// RevisionID returns the live revision id.
func (a ActiveConnection) RevisionID() string { return a.revisionID }

// System returns the graph system name.
func (a ActiveConnection) System() string { return a.system }

// ConnectorType returns the connector type.
func (a ActiveConnection) ConnectorType() string { return a.connectorType }

// Name returns the connection name.
func (a ActiveConnection) Name() string { return a.name }

// ActiveConnections lists the live connections (active or degraded: reads
// continue while degraded, §7.5).
func (s *Service) ActiveConnections(c *store.TenantTx) ([]ActiveConnection, error) {
	conns, err := c.Connections()
	if err != nil {
		return nil, err
	}
	var out []ActiveConnection
	for _, conn := range conns {
		if conn.ActiveRevisionID == nil || conn.RetiredAt != nil {
			continue
		}
		rev, err := c.Revision(*conn.ActiveRevisionID)
		if err != nil {
			return nil, err
		}
		if IsLive(rev.State) {
			out = append(out, ActiveConnection{conn.ID, rev.ID, conn.System, conn.ConnectorType, conn.Name})
		}
	}
	return out, nil
}

// CanWrite reports whether write-back may apply changes through a
// connection: only an active (not degraded) revision in scoped write mode (§4.4).
func (s *Service) CanWrite(c *store.TenantTx, connID string) (bool, error) {
	_, live, _, err := Revisions(c, connID)
	if err != nil || live == nil {
		return false, err
	}
	return live.State == store.StateActive && live.WriteMode == "scoped", nil
}

// Activate re-evaluates every gate from stored evidence and, in one
// transaction, swaps the in-progress revision in as the live one.
func (s *Service) Activate(c *store.TenantTx, connID, actor string, now time.Time) (*Bundle, ActiveConnection, error) {
	conn, live, pending, err := Revisions(c, connID)
	if err != nil {
		return nil, ActiveConnection{}, err
	}
	if conn.RetiredAt != nil {
		return nil, ActiveConnection{}, conflict("connection_retired", "connection %s is retired", conn.Name)
	}
	if !IsDemoType(conn.ConnectorType) && s.Env != "dev" {
		return nil, ActiveConnection{}, newErr(http.StatusForbidden, "phase0_required",
			"%s connections can be activated only after tenancy, RBAC and step-up land (Phase 0, DR-10)", conn.ConnectorType)
	}
	if pending == nil {
		return nil, ActiveConnection{}, conflict("no_pending_revision", "nothing to activate")
	}
	b, err := s.Load(c, pending, now)
	if err != nil {
		return nil, ActiveConnection{}, err
	}
	if err := s.settle(c, b, actor, now, "re-evaluated at activation"); err != nil {
		return nil, ActiveConnection{}, err
	}
	g := b.Gate(store.StateActive, now)
	if b.Rev.State != store.StateDryRunReconciled {
		g.Blocking = append([]Blocker{{Item: "state", Status: b.Rev.State, Reason: "activation needs dry_run_reconciled"}}, g.Blocking...)
	}
	if g.Blocks() {
		return nil, ActiveConnection{}, blocked("activation_blocked", g)
	}
	if live != nil {
		old, err := s.Load(c, live, now)
		if err != nil {
			return nil, ActiveConnection{}, err
		}
		if err := s.setState(c, old, store.StateSuperseded, nil, actor, "replaced by revision "+b.Rev.ID, now); err != nil {
			return nil, ActiveConnection{}, err
		}
	}
	if err := s.setState(c, b, store.StateActive, g, actor, "activated", now); err != nil {
		return nil, ActiveConnection{}, err
	}
	if err := c.SetConnectionLive(conn.ID, &b.Rev.ID, "ok", now); err != nil {
		return nil, ActiveConnection{}, err
	}
	if err := c.Audit(now, actor, "connection.activated", ojson.Object{{Key: "connection_id", Value: conn.ID},
		{Key: "revision_id", Value: b.Rev.ID}, {Key: "gate_report", Value: g}}); err != nil {
		return nil, ActiveConnection{}, err
	}
	return b, ActiveConnection{conn.ID, b.Rev.ID, conn.System, conn.ConnectorType, conn.Name}, s.persist(c, b, now)
}

// Retire retires a connection: its in-progress and live revisions move to
// retired, and the connection stops syncing. Data already synced stays
// read-only for the retention period.
func (s *Service) Retire(c *store.TenantTx, connID, actor string, now time.Time) error {
	conn, live, pending, err := Revisions(c, connID)
	if err != nil {
		return err
	}
	if conn.RetiredAt != nil {
		return conflict("connection_retired", "connection %s is already retired", conn.Name)
	}
	for _, rev := range []*store.ConnectionRevision{pending, live} {
		if rev == nil {
			continue
		}
		b, err := s.Load(c, rev, now)
		if err != nil {
			return err
		}
		if err := s.setState(c, b, store.StateRetired, nil, actor, "retired", now); err != nil {
			return err
		}
	}
	if err := c.SetConnectionLive(conn.ID, nil, "none", now); err != nil {
		return err
	}
	if err := c.MarkConnectionRetired(conn.ID, now); err != nil {
		return err
	}
	return c.Audit(now, actor, "connection.retired", ojson.Object{{Key: "connection_id", Value: conn.ID},
		{Key: "name", Value: conn.Name}})
}

// Degrade moves a live revision to degraded (system; the scheduled checks of
// DR-9 call it). Reads continue; write-back stops (CanWrite is false).
func (s *Service) Degrade(c *store.TenantTx, connID, reason string, now time.Time) error {
	return s.setLive(c, connID, store.StateActive, store.StateDegraded, "degraded", "connection.degraded", reason, now)
}

// Recover moves a degraded revision back to active once the cause cleared.
func (s *Service) Recover(c *store.TenantTx, connID, reason string, now time.Time) error {
	return s.setLive(c, connID, store.StateDegraded, store.StateActive, "ok", "connection.recovered", reason, now)
}

func (s *Service) setLive(c *store.TenantTx, connID, from, to, health, event, reason string, now time.Time) error {
	conn, live, _, err := Revisions(c, connID)
	if err != nil {
		return err
	}
	if live == nil || live.State != from {
		return conflict("invalid_transition", "connection %s is not %s", conn.Name, from)
	}
	b, err := s.Load(c, live, now)
	if err != nil {
		return err
	}
	if err := s.setState(c, b, to, nil, "system", reason, now); err != nil {
		return err
	}
	if err := c.SetConnectionLive(conn.ID, &live.ID, health, now); err != nil {
		return err
	}
	return c.Audit(now, "system", event, ojson.Object{{Key: "connection_id", Value: conn.ID}, {Key: "reason", Value: reason}})
}
