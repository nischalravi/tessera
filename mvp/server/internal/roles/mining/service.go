package mining

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// JobKind is the queue kind that computes a queued run.
const JobKind = "role_mining"

// Worker is the actor of the queue job in audit events.
const Worker = "role_mining.worker"

// Run limits.
const (
	// InlineMaxPeople: a run over at most this many people is computed in the
	// request; a larger one is queued as a job.
	InlineMaxPeople = 500
	// RunTimeout bounds the computation of one run.
	RunTimeout = 2 * time.Minute
	// MaxJobAttempts is how often the queue tries a run.
	MaxJobAttempts = 2
	maxError       = 500
	staleAfter     = time.Hour
)

// Actor is the signed-in user.
type Actor = requests.Actor

// Error is a refused change; Code is stable for API clients.
type Error = requests.Error

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Enqueuer adds the job of a queued run in the caller's transaction
// (queue.Queue.EnqueueTx has this shape).
type Enqueuer func(tx *store.TenantTx, kind, payload, key string, runAt time.Time, maxAttempts int) (bool, error)

type jobPayload struct {
	RunID string `json:"run_id"`
}

func actorName(by Actor) string {
	if by.Display == "" {
		return "unknown"
	}
	return by.Display
}

func userID(by Actor) *string {
	if by.UserID == uuid.Nil {
		return nil
	}
	s := by.UserID.String()
	return &s
}

// Request records a run and, when it is small and async is false, computes it
// in the caller's transaction. Otherwise it queues the job that does. One run
// is active at a time.
func Request(tx *store.TenantTx, p Params, by Actor, async bool, enq Enqueuer, now time.Time) (*store.MiningRun, error) {
	p, err := p.Normalize()
	if err != nil {
		var pe *ParamError
		if errors.As(err, &pe) {
			return nil, refuse(422, "invalid_params", "%s", pe.Msg)
		}
		return nil, err
	}
	// a run still queued after staleAfter was lost (a dead job); it no longer blocks a new one
	if active, err := tx.ActiveMiningRun(); err == nil && now.Sub(active.CreatedAt) < staleAfter {
		return nil, refuse(409, "run_in_progress", "a mining run is already queued or running")
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	run := &store.MiningRun{ID: uuid.NewString(), Status: store.MiningQueued, Params: string(raw), Algorithm: Algorithm,
		RequestedBy: userID(by), RequestedActor: actorName(by), CreatedAt: now}
	if err := tx.InsertMiningRun(run); err != nil {
		return nil, err
	}
	in, err := Load(tx)
	if err != nil {
		return nil, err
	}
	n := 0
	for _, x := range in.People {
		if match(p.Department, x.Department) && match(p.Title, x.Title) && match(p.Type, x.Type) {
			n++
		}
	}
	inline := !async && n <= InlineMaxPeople
	mode := "queued"
	if inline {
		mode = "inline"
	}
	if err := tx.Audit(now, actorName(by), "role_mining.run", ojson.Object{{Key: "run_id", Value: run.ID},
		{Key: "mode", Value: mode}, {Key: "people", Value: n}, {Key: "params", Value: json.RawMessage(raw)}}); err != nil {
		return nil, err
	}
	if !inline {
		payload, err := json.Marshal(jobPayload{run.ID})
		if err != nil {
			return nil, err
		}
		if _, err := enq(tx, JobKind, string(payload), run.ID, time.Time{}, MaxJobAttempts); err != nil {
			return nil, err
		}
		return run, nil
	}
	if err := compute(context.Background(), tx, run, in, Worker, now); err != nil {
		return nil, err
	}
	return tx.MiningRun(run.ID)
}

// Execute computes a queued run (the queue job). A run that is already
// finished is left alone, so a delivered-twice job is harmless. A run that
// cannot be mined (too many people) is recorded as failed; a cancelled
// context is returned so the queue tries again.
func Execute(ctx context.Context, tx *store.TenantTx, runID string, now time.Time) error {
	run, err := tx.MiningRun(runID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if run.Status == store.MiningSucceeded || run.Status == store.MiningFailed {
		return nil
	}
	in, err := Load(tx)
	if err != nil {
		return err
	}
	return compute(ctx, tx, run, in, Worker, now)
}

func compute(ctx context.Context, tx *store.TenantTx, run *store.MiningRun, in Input, actor string, now time.Time) error {
	if err := tx.StartMiningRun(run.ID, now); err != nil {
		return err
	}
	var p Params
	if err := json.Unmarshal([]byte(run.Params), &p); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()
	out, err := Mine(ctx, p, in)
	fin := &store.MiningRun{ID: run.ID, Status: store.MiningSucceeded}
	var me *InputError
	switch {
	case errors.As(err, &me):
		fin.Status, fin.Error = store.MiningFailed, me.Msg
	case errors.Is(err, context.DeadlineExceeded):
		fin.Status, fin.Error = store.MiningFailed, "the run took longer than "+RunTimeout.String()+"; narrow it with a filter"
	case err != nil:
		return err
	default:
		fin.SnapshotHash, fin.People, fin.Entitlements, fin.Candidates = out.SnapshotHash, out.People, out.Entitlements, len(out.Candidates)
		fin.SkippedExisting, fin.Truncated = out.SkippedExisting, out.Truncated
		for _, c := range out.Candidates {
			sc, err := storeCandidate(run.ID, c)
			if err != nil {
				return err
			}
			if err := tx.InsertMiningCandidate(sc); err != nil {
				return err
			}
		}
	}
	if len(fin.Error) > maxError {
		fin.Error = fin.Error[:maxError]
	}
	if err := tx.FinishMiningRun(fin, now); err != nil {
		return err
	}
	return tx.Audit(now, actor, "role_mining.complete", ojson.Object{{Key: "run_id", Value: run.ID},
		{Key: "status", Value: fin.Status}, {Key: "snapshot_hash", Value: fin.SnapshotHash},
		{Key: "candidates", Value: fin.Candidates}, {Key: "truncated", Value: fin.Truncated}})
}

func storeCandidate(runID string, c Candidate) (*store.MiningCandidate, error) {
	ents, err := json.Marshal(c.Entitlements)
	if err != nil {
		return nil, err
	}
	members, err := json.Marshal(c.Members)
	if err != nil {
		return nil, err
	}
	outliers, err := json.Marshal(c.Outliers)
	if err != nil {
		return nil, err
	}
	sc := &store.MiningCandidate{ID: uuid.NewString(), RunID: runID, Rank: c.Rank, Name: c.Name, Entitlements: string(ents),
		Members: string(members), Outliers: string(outliers), Coverage: len(c.Members), Confidence: c.Confidence,
		Cohesion: c.Cohesion, Similarity: c.Similarity}
	if c.Rule != nil {
		b, err := json.Marshal(c.Rule)
		if err != nil {
			return nil, err
		}
		s := string(b)
		sc.Rule = &s
	}
	if c.SimilarRole != "" {
		sc.SimilarRoleID = &c.SimilarRole
	}
	return sc, nil
}

// ---------------------------------------------------------------- decisions

// Edit is what an admin may change before accepting. Empty fields keep the
// candidate's; Entitlements may only drop entitlements of the candidate.
type Edit struct {
	Name         string
	Description  string
	Risk         string
	Entitlements []int64
}

// Accepted is the result of accepting a candidate.
type Accepted struct {
	Candidate *store.MiningCandidate
	Role      *roles.Result
}

func openCandidate(tx *store.TenantTx, id string) (*store.MiningCandidate, error) {
	c, err := tx.MiningCandidate(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "candidate_not_found", "candidate not found")
	} else if err != nil {
		return nil, err
	}
	if c.Status != store.CandidateOpen {
		return nil, refuse(409, "candidate_decided", "this candidate was already %s", c.Status)
	}
	return c, nil
}

// Accept creates a business role from an open candidate through the roles
// service (versioned, audited): not requestable, no birthright rule and no
// members, so it grants and removes nothing. The suggested rule goes in the
// description; assignment and the rule follow the usual role flows.
func Accept(tx *store.TenantTx, id string, e Edit, by Actor, now time.Time) (*Accepted, error) {
	c, err := openCandidate(tx, id)
	if err != nil {
		return nil, err
	}
	var ents []int64
	if err := json.Unmarshal([]byte(c.Entitlements), &ents); err != nil {
		return nil, err
	}
	total := len(ents)
	if len(e.Entitlements) > 0 {
		for _, g := range e.Entitlements {
			if !slices.Contains(ents, g) {
				return nil, refuse(422, "invalid_entitlements", "entitlement %d is not part of this candidate", g)
			}
		}
		ents = e.Entitlements
	}
	spec := roles.Spec{Name: strings.TrimSpace(e.Name), Description: strings.TrimSpace(e.Description), Risk: e.Risk,
		Entitlements: ents, Note: fmt.Sprintf("Mined: run %s, candidate %d", c.RunID, c.Rank)}
	if spec.Name == "" {
		spec.Name = c.Name
	}
	if spec.Description == "" {
		spec.Description = describe(c)
	}
	if spec.Risk == "" {
		spec.Risk = "medium"
		for _, g := range ents {
			if gr, err := tx.Group(g); err == nil && gr.Privileged {
				spec.Risk = "high"
				break
			}
		}
	}
	res, err := roles.Create(tx, spec, by, false, now)
	if err != nil {
		return nil, err
	}
	rid := res.Role.ID
	if err := tx.DecideMiningCandidate(c.ID, store.CandidateAccepted, userID(by), actorName(by), now, "", &rid); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actorName(by), "role_mining.accept", ojson.Object{{Key: "candidate_id", Value: c.ID},
		{Key: "run_id", Value: c.RunID}, {Key: "rank", Value: c.Rank}, {Key: "role_id", Value: rid},
		{Key: "name", Value: spec.Name}, {Key: "entitlements", Value: len(ents)}, {Key: "coverage", Value: c.Coverage},
		{Key: "edited", Value: spec.Name != c.Name || len(ents) != total}}); err != nil {
		return nil, err
	}
	c, err = tx.MiningCandidate(c.ID)
	return &Accepted{Candidate: c, Role: res}, err
}

// Dismiss records why an open candidate is not wanted.
func Dismiss(tx *store.TenantTx, id, reason string, by Actor, now time.Time) (*store.MiningCandidate, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > requests.MaxReason {
		return nil, refuse(422, "reason_required", "a reason of 1 to %d characters is required", requests.MaxReason)
	}
	c, err := openCandidate(tx, id)
	if err != nil {
		return nil, err
	}
	if err := tx.DecideMiningCandidate(c.ID, store.CandidateDismissed, userID(by), actorName(by), now, reason, nil); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actorName(by), "role_mining.dismiss", ojson.Object{{Key: "candidate_id", Value: c.ID},
		{Key: "run_id", Value: c.RunID}, {Key: "rank", Value: c.Rank}, {Key: "name", Value: c.Name},
		{Key: "reason", Value: reason}}); err != nil {
		return nil, err
	}
	return tx.MiningCandidate(c.ID)
}

func describe(c *store.MiningCandidate) string {
	s := fmt.Sprintf("Suggested by role mining: %d people hold all of these entitlements.", c.Coverage)
	if c.Rule != nil {
		var r Rule
		if json.Unmarshal([]byte(*c.Rule), &r) == nil && len(r.Values) > 0 {
			s += fmt.Sprintf(" Suggested birthright rule: %s is %s (%d%% precision, %d%% recall).", r.Attribute,
				strings.Join(r.Values, " or "), r.Precision, r.Recall)
		}
	}
	return s + " Review the members before assigning anyone."
}
