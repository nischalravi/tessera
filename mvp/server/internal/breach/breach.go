// Package breach is vendor breach response (issue #475): given a vendor or
// integration that was breached (Railway, GhostAction), list every credential
// tied to it, run rotation and containment as one tracked plan, verify by
// re-reading, and export the evidence.
//
// It orchestrates and duplicates nothing:
//
//   - secrets are rotated by internal/rotation (its bulk "vendor compromised"
//     run: no grace period, owners notified, one job per secret);
//   - OAuth grants are revoked by internal/oauthapps (four-eyes gate, provider
//     revoke, provider re-read), driven by the API layer because it calls
//     providers outside a transaction;
//   - GitHub tokens (internal/ghtokens) and service accounts have no revoke
//     API Tessera can call: they are manual items a person does and attests,
//     unless a re-read already shows them gone.
//
// The rules: an item is verified only by a re-read of Tessera's own record of
// the credential after the work (a rotation job that reached "verified" or
// beyond, a grant that is revoked or removed, a token or account that is gone
// or disabled), never by the fact that a request was made. A plan completes
// only when every item is verified or attested. Nothing here holds secret
// material.
package breach

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/rotation"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Error is a refusal with the HTTP status and code the API answers.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, a ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Service drives breach plans over the rotation service.
type Service struct {
	Rotation *rotation.Service
}

var vendorRE = regexp.MustCompile(`^[a-z0-9][a-z0-9 ._&-]{0,63}$`)

// NormalizeVendor lower-cases and trims a vendor name and checks it.
func NormalizeVendor(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if !vendorRE.MatchString(v) {
		return "", refuse(http.StatusUnprocessableEntity, "invalid_vendor",
			"vendor must be a vendor or system name such as github: letters, digits, spaces and . _ & -, at most 64 characters")
	}
	return v, nil
}

// Candidate is one credential tied to a vendor.
type Candidate struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Label  string `json:"label"`
	Action string `json:"action"`
	Detail string `json:"detail,omitempty"`
}

// Inventory lists every credential tied to the vendor, read from Tessera's own
// records: secrets of the system, live OAuth grants of apps the vendor
// publishes, GitHub tokens (for github) and service accounts of the system.
func (s *Service) Inventory(tx *store.TenantTx, vendor string, now time.Time) ([]Candidate, error) {
	out := []Candidate{}
	bp, err := s.Rotation.BulkPlanFor(tx, vendor, now)
	var prob *rotation.Problem
	switch {
	case errors.As(err, &prob) && (prob.Code == "no_secrets" || prob.Code == "invalid_system"):
	case err != nil:
		return nil, err
	default:
		for _, it := range bp.Items {
			c := Candidate{Kind: store.BreachKindSecret, Ref: strconv.FormatInt(it.SecretID, 10), Label: it.Name + " (" + it.Kind + ")",
				Action: store.BreachActionRotate}
			if it.Action != rotation.ActionRotate && it.Action != rotation.ActionInFlight {
				c.Action, c.Detail = store.BreachActionManual, it.Reason
				if c.Detail == "" {
					c.Detail = "no rotation policy can rotate it: the owner rotates it by hand"
				}
			}
			out = append(out, c)
		}
	}
	apps, err := tx.OAuthApps()
	if err != nil {
		return nil, err
	}
	for _, app := range apps {
		if !matchesVendor(app, vendor) {
			continue
		}
		grants, err := tx.OAuthGrantsOf(app.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range grants {
			if g.Status != store.OAuthActive && g.Status != store.OAuthRevokeFailed {
				continue
			}
			who := g.UserRef
			if who == "" {
				who = g.Kind
			}
			out = append(out, Candidate{Kind: store.BreachKindOAuthGrant, Ref: g.ID, Label: app.Name + " / " + who, Action: store.BreachActionRevoke})
		}
	}
	if vendor == "github" {
		tokens, err := tx.GitHubTokens()
		if err != nil {
			return nil, err
		}
		for _, t := range tokens {
			if t.Status != store.GHTokenActive {
				continue
			}
			how := "revoke it in the GitHub organization settings (GitHub has no API to revoke a personal access token)"
			if t.Kind == store.GHActionsSecret {
				how = "rotate the value and update it in the repository or organization secrets"
			}
			out = append(out, Candidate{Kind: store.BreachKindGitHubToken, Ref: t.ID, Label: t.Name + " (" + t.Kind + ")",
				Action: store.BreachActionManual, Detail: how})
		}
	}
	accts, err := tx.Accounts()
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if strings.ToLower(a.System) != vendor || a.Kind != "service" || a.Status == "disabled" {
			continue
		}
		out = append(out, Candidate{Kind: store.BreachKindServiceAccount, Ref: strconv.FormatInt(a.ID, 10), Label: a.Username + " (service account)",
			Action: store.BreachActionManual, Detail: "disable the account or rotate its credentials at the vendor, then attest"})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Label < out[j].Label
	})
	return out, nil
}

// matchesVendor is the vendor match of oauthapps.MatchesVendor (publisher or
// app name), kept in step with the vendor revoke that acts on the same set.
func matchesVendor(app *store.OAuthApp, vendor string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	return norm(app.Publisher) == vendor || norm(app.Name) == vendor
}

// Create records a plan for the vendor, with an item for every credential the
// inventory finds. It changes nothing at the vendor: Start does that.
func (s *Service) Create(tx *store.TenantTx, vendor, reason, actor string, now time.Time) (*View, error) {
	v, err := NormalizeVendor(vendor)
	if err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	if len(reason) < 10 || len(reason) > 500 {
		return nil, refuse(http.StatusUnprocessableEntity, "reason_required", "reason must say why (10 to 500 characters)")
	}
	cands, err := s.Inventory(tx, v, now)
	if err != nil {
		return nil, err
	}
	if len(cands) == 0 {
		return nil, refuse(http.StatusNotFound, "no_credentials", "no credential tied to %q is recorded", v)
	}
	p := &store.BreachPlan{Vendor: v, Reason: reason, CreatedBy: actor, CreatedAt: now}
	if err := tx.InsertBreachPlan(p); err != nil {
		return nil, err
	}
	if err := addCandidates(tx, p.ID, cands, now); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actor, "breach.plan.created", ojson.Object{{Key: "plan_id", Value: p.ID}, {Key: "vendor", Value: v},
		{Key: "reason", Value: reason}, {Key: "credentials", Value: len(cands)}}); err != nil {
		return nil, err
	}
	return s.View(tx, p.ID, now)
}

func addCandidates(tx *store.TenantTx, planID string, cands []Candidate, now time.Time) error {
	for _, c := range cands {
		if err := tx.AddBreachItem(planID, &store.BreachItem{Kind: c.Kind, Ref: c.Ref, Label: c.Label, Action: c.Action, Detail: c.Detail}, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) plan(tx *store.TenantTx, id string) (*store.BreachPlan, error) {
	p, err := tx.BreachPlan(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(http.StatusNotFound, "not_found", "no such breach plan")
	}
	return p, err
}

// Start runs the plan's rotation: it adds credentials that appeared since the
// plan was made, queues the vendor-compromised rotation of the vendor's
// secrets (internal/rotation, no grace period, owners notified) and marks the
// plan running. The OAuth revoke and the verification follow (see API). It is
// safe to call again: the rotation is queued once.
func (s *Service) Start(tx *store.TenantTx, id, actor string, now time.Time) (*View, error) {
	p, err := s.plan(tx, id)
	if err != nil {
		return nil, err
	}
	if p.Status == store.BreachCompleted {
		return nil, refuse(http.StatusConflict, "plan_completed", "this plan is already completed")
	}
	cands, err := s.Inventory(tx, p.Vendor, now)
	if err != nil {
		return nil, err
	}
	if err := addCandidates(tx, p.ID, cands, now); err != nil {
		return nil, err
	}
	var bulkID *string
	if p.BulkID == nil {
		bp, err := s.Rotation.BulkPlanFor(tx, p.Vendor, now)
		var prob *rotation.Problem
		switch {
		case errors.As(err, &prob) && (prob.Code == "no_secrets" || prob.Code == "invalid_system"):
		case err != nil:
			return nil, err
		case bp.Counts.Rotate > 0:
			b, err := s.Rotation.ExecuteBulk(tx, rotation.BulkInput{System: p.Vendor, Reason: "vendor breach response: " + p.Reason, PlanHash: bp.Hash}, actor, now)
			if err != nil {
				return nil, err
			}
			bulkID = &b.ID
		}
	}
	if err := tx.StartBreachPlan(p.ID, bulkID, actor, now); err != nil {
		return nil, err
	}
	n := 0
	if bulkID != nil {
		n = 1
	}
	if err := tx.Audit(now, actor, "breach.plan.started", ojson.Object{{Key: "plan_id", Value: p.ID}, {Key: "vendor", Value: p.Vendor},
		{Key: "rotation_queued", Value: n}}); err != nil {
		return nil, err
	}
	return s.View(tx, p.ID, now)
}

// RecordRevoke notes what an OAuth revoke did to the plan's grant items. A
// grant is only verified later, by Verify's re-read of the grant.
func (s *Service) RecordRevoke(tx *store.TenantTx, id string, results map[string]RevokeResult, now time.Time) error {
	items, err := tx.BreachItems(id)
	if err != nil {
		return err
	}
	for _, it := range items {
		r, ok := results[it.Ref]
		if it.Kind != store.BreachKindOAuthGrant || !ok || it.State == store.BreachVerified || it.State == store.BreachAttested {
			continue
		}
		if err := tx.SetBreachItemState(it.ID, r.State, r.Detail, nil, nil, now); err != nil {
			return err
		}
	}
	return nil
}

// RevokeResult is the outcome of the revoke of one grant, as an item state.
type RevokeResult struct {
	State  string // in_progress (revoked, awaiting the re-read), failed, or pending (a person must)
	Detail string
}

// Attest records that a person did a manual item. The note says what was done.
func (s *Service) Attest(tx *store.TenantTx, planID, itemID, note, actor string, now time.Time) (*View, error) {
	p, err := s.plan(tx, planID)
	if err != nil {
		return nil, err
	}
	note = strings.TrimSpace(note)
	if len(note) < 10 || len(note) > 500 {
		return nil, refuse(http.StatusUnprocessableEntity, "note_required", "note must say what was done (10 to 500 characters)")
	}
	if p.Status != store.BreachRunning {
		return nil, refuse(http.StatusConflict, "plan_not_running", "start the plan before attesting its items")
	}
	it, err := tx.BreachItem(planID, itemID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(http.StatusNotFound, "not_found", "no such item in this plan")
	}
	if err != nil {
		return nil, err
	}
	if it.Action != store.BreachActionManual {
		return nil, refuse(http.StatusConflict, "not_manual", "only manual items are attested; this one is verified by a re-read")
	}
	if it.State == store.BreachVerified {
		return nil, refuse(http.StatusConflict, "already_verified", "a re-read already verified this item")
	}
	if err := tx.AttestBreachItem(it.ID, actor, note, now); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, actor, "breach.item.attested", ojson.Object{{Key: "plan_id", Value: p.ID}, {Key: "item_id", Value: it.ID},
		{Key: "kind", Value: it.Kind}, {Key: "label", Value: it.Label}, {Key: "note", Value: note}}); err != nil {
		return nil, err
	}
	return s.verify(tx, p, actor, now, false)
}

// Verify re-reads every item that is not yet verified or attested, and
// completes the plan when none is left.
func (s *Service) Verify(tx *store.TenantTx, id, actor string, now time.Time) (*View, error) {
	p, err := s.plan(tx, id)
	if err != nil {
		return nil, err
	}
	return s.verify(tx, p, actor, now, true)
}

type secretCheck struct {
	JobID    string  `json:"job_id"`
	JobState string  `json:"job_state"`
	Verified *string `json:"verified_at,omitempty"`
	Read     any     `json:"old_credential_re_read,omitempty"`
}

func (s *Service) verify(tx *store.TenantTx, p *store.BreachPlan, actor string, now time.Time, audit bool) (*View, error) {
	items, err := tx.BreachItems(p.ID)
	if err != nil {
		return nil, err
	}
	secrets, err := tx.Secrets()
	if err != nil {
		return nil, err
	}
	secretByID := map[string]*store.Secret{}
	for _, sc := range secrets {
		secretByID[strconv.FormatInt(sc.ID, 10)] = sc
	}
	tokens, err := tx.GitHubTokens()
	if err != nil {
		return nil, err
	}
	tokenByID := map[string]*store.GitHubToken{}
	for _, t := range tokens {
		tokenByID[t.ID] = t
	}
	accts, err := tx.Accounts()
	if err != nil {
		return nil, err
	}
	acctByID := map[string]*store.Account{}
	for _, a := range accts {
		acctByID[strconv.FormatInt(a.ID, 10)] = a
	}
	for _, it := range items {
		if it.State == store.BreachVerified || it.State == store.BreachAttested {
			continue
		}
		state, detail, evidence, err := s.reread(tx, p, it, secretByID, tokenByID, acctByID)
		if err != nil {
			return nil, err
		}
		if state == "" {
			continue
		}
		var ev *string
		var at *time.Time
		if evidence != nil {
			raw, err := json.Marshal(evidence)
			if err != nil {
				return nil, err
			}
			e := string(raw)
			ev = &e
		}
		if state == store.BreachVerified {
			at = &now
		}
		if state == it.State && detail == it.Detail && state != store.BreachVerified {
			continue
		}
		if err := tx.SetBreachItemState(it.ID, state, detail, ev, at, now); err != nil {
			return nil, err
		}
	}
	v, err := s.View(tx, p.ID, now)
	if err != nil {
		return nil, err
	}
	if p.Status == store.BreachRunning && v.Report.Complete {
		raw, err := json.Marshal(v.Report)
		if err != nil {
			return nil, err
		}
		if err := tx.CompleteBreachPlan(p.ID, string(raw), now); err != nil {
			return nil, err
		}
		if v, err = s.View(tx, p.ID, now); err != nil {
			return nil, err
		}
		if err := tx.Audit(now, actor, "breach.plan.completed", ojson.Object{{Key: "plan_id", Value: p.ID}, {Key: "vendor", Value: p.Vendor},
			{Key: "verified", Value: v.Report.Counts.Verified}, {Key: "attested", Value: v.Report.Counts.Attested}}); err != nil {
			return nil, err
		}
	}
	if audit {
		if err := tx.Audit(now, actor, "breach.plan.verified", ojson.Object{{Key: "plan_id", Value: p.ID}, {Key: "vendor", Value: p.Vendor},
			{Key: "total", Value: v.Report.Counts.Total}, {Key: "verified", Value: v.Report.Counts.Verified},
			{Key: "attested", Value: v.Report.Counts.Attested}, {Key: "failed", Value: v.Report.Counts.Failed},
			{Key: "open", Value: v.Report.Counts.Open}}); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// reread returns the state a fresh read of the credential shows, "" for no change.
func (s *Service) reread(tx *store.TenantTx, p *store.BreachPlan, it *store.BreachItem, secrets map[string]*store.Secret,
	tokens map[string]*store.GitHubToken, accts map[string]*store.Account) (state, detail string, evidence any, err error) {
	switch it.Kind {
	case store.BreachKindSecret:
		return s.rereadSecret(tx, p, it, secrets)
	case store.BreachKindOAuthGrant:
		g, err := tx.OAuthGrant(it.Ref)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return store.BreachVerified, "the grant no longer exists", map[string]string{"grant": "gone"}, nil
		case err != nil:
			return "", "", nil, err
		case g.Status == store.OAuthRevoked || g.Status == store.OAuthRemoved:
			return store.BreachVerified, "the grant is " + g.Status, map[string]string{"grant_status": g.Status}, nil
		case g.Status == store.OAuthRevokeFailed:
			return store.BreachFailed, "the provider refused the revoke: " + g.RevokeError, nil, nil
		}
		return "", "", nil, nil
	case store.BreachKindGitHubToken:
		t, ok := tokens[it.Ref]
		if !ok || t.Status == store.GHTokenRemoved {
			return store.BreachVerified, "the credential no longer appears in the GitHub organization", map[string]string{"token": "gone"}, nil
		}
	case store.BreachKindServiceAccount:
		a, ok := accts[it.Ref]
		if !ok || a.Status == "disabled" {
			return store.BreachVerified, "the account is disabled or gone", map[string]string{"account": "disabled"}, nil
		}
	}
	return "", "", nil, nil
}

func (s *Service) rereadSecret(tx *store.TenantTx, p *store.BreachPlan, it *store.BreachItem, secrets map[string]*store.Secret) (string, string, any, error) {
	sc, ok := secrets[it.Ref]
	if ok && sc.Status != "active" {
		return store.BreachVerified, "the secret is " + sc.Status, map[string]string{"secret_status": sc.Status}, nil
	}
	if !ok {
		return store.BreachVerified, "the secret no longer exists", map[string]string{"secret": "gone"}, nil
	}
	if p.StartedAt == nil {
		return "", "", nil, nil
	}
	id, _ := strconv.ParseInt(it.Ref, 10, 64)
	jobs, err := tx.RotationJobs(store.RotationJobFilter{SecretID: id, Limit: 50})
	if err != nil {
		return "", "", nil, err
	}
	var job *store.RotationJob
	for _, j := range jobs {
		if !j.CreatedAt.Before(*p.StartedAt) && (job == nil || j.CreatedAt.After(job.CreatedAt)) {
			job = j
		}
	}
	if job == nil {
		return "", "", nil, nil
	}
	switch job.State {
	case "verified", "old_deleted":
		ev := secretCheck{JobID: job.ID, JobState: job.State}
		if job.VerifiedAt != nil {
			t := job.VerifiedAt.UTC().Format(time.RFC3339)
			ev.Verified = &t
		}
		detail := "rotated: the rotation job is " + job.State
		if job.Verification != nil {
			ev.Read = json.RawMessage(*job.Verification)
			detail = verifiedDetail(*job.Verification)
		}
		return store.BreachVerified, detail, ev, nil
	case "failed", "cancelled":
		d := "the rotation job " + job.State
		if job.LastError != nil && *job.LastError != "" {
			d += ": " + *job.LastError
		}
		return store.BreachFailed, d, nil, nil
	}
	return store.BreachInProgress, "rotation job " + job.ID + " is " + job.State, nil, nil
}

// ---------------------------------------------------------------- views

// Counts summarises a plan.
type Counts struct {
	Total      int `json:"total"`
	Verified   int `json:"verified"`
	Attested   int `json:"attested"`
	Failed     int `json:"failed"`
	InProgress int `json:"in_progress"`
	Pending    int `json:"pending"`
	// Open is every item that is not verified or attested.
	Open int `json:"open"`
}

// Report is the completion report: what was tied to the vendor and where each
// credential stands. Complete is true only when nothing is open.
type Report struct {
	Vendor   string     `json:"vendor"`
	Counts   Counts     `json:"counts"`
	Complete bool       `json:"complete"`
	Items    []ItemView `json:"items"`
}

// ItemView is one credential of a plan.
type ItemView struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	Ref          string          `json:"ref"`
	Label        string          `json:"label"`
	Action       string          `json:"action"`
	State        string          `json:"state"`
	Detail       string          `json:"detail"`
	Verification json.RawMessage `json:"verification,omitempty"`
	VerifiedAt   *time.Time      `json:"verified_at"`
	AttestedBy   *string         `json:"attested_by"`
	AttestedNote *string         `json:"attested_note"`
}

// View is a plan with its items and report.
type View struct {
	ID          string     `json:"id"`
	Vendor      string     `json:"vendor"`
	Reason      string     `json:"reason"`
	Status      string     `json:"status"`
	RotationRun *string    `json:"rotation_run_id"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedBy   *string    `json:"started_by"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Items       []ItemView `json:"items"`
	Report      Report     `json:"report"`
}

// View returns one plan with its items and the report as it stands.
func (s *Service) View(tx *store.TenantTx, id string, _ time.Time) (*View, error) {
	p, err := s.plan(tx, id)
	if err != nil {
		return nil, err
	}
	return viewOf(tx, p)
}

func viewOf(tx *store.TenantTx, p *store.BreachPlan) (*View, error) {
	items, err := tx.BreachItems(p.ID)
	if err != nil {
		return nil, err
	}
	v := &View{ID: p.ID, Vendor: p.Vendor, Reason: p.Reason, Status: p.Status, RotationRun: p.BulkID, CreatedBy: p.CreatedBy,
		CreatedAt: p.CreatedAt, StartedBy: p.StartedBy, StartedAt: p.StartedAt, CompletedAt: p.CompletedAt, Items: []ItemView{}}
	c := &v.Report.Counts
	for _, it := range items {
		iv := ItemView{ID: it.ID, Kind: it.Kind, Ref: it.Ref, Label: it.Label, Action: it.Action, State: it.State, Detail: it.Detail,
			VerifiedAt: it.VerifiedAt, AttestedBy: it.AttestedBy, AttestedNote: it.AttestedNote}
		if it.Verification != nil {
			iv.Verification = json.RawMessage(*it.Verification)
		}
		v.Items = append(v.Items, iv)
		c.Total++
		switch it.State {
		case store.BreachVerified:
			c.Verified++
		case store.BreachAttested:
			c.Attested++
		case store.BreachFailed:
			c.Failed++
		case store.BreachInProgress:
			c.InProgress++
		default:
			c.Pending++
		}
	}
	c.Open = c.Total - c.Verified - c.Attested
	v.Report = Report{Vendor: p.Vendor, Counts: *c, Complete: c.Total > 0 && c.Open == 0, Items: v.Items}
	return v, nil
}

// Summary is a plan in a list.
type Summary struct {
	ID          string     `json:"id"`
	Vendor      string     `json:"vendor"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by"`
	CompletedAt *time.Time `json:"completed_at"`
	Counts      Counts     `json:"counts"`
}

// List returns the plans, newest first.
func (s *Service) List(tx *store.TenantTx) ([]Summary, error) {
	ps, err := tx.BreachPlans()
	if err != nil {
		return nil, err
	}
	out := make([]Summary, 0, len(ps))
	for _, p := range ps {
		v, err := viewOf(tx, p)
		if err != nil {
			return nil, err
		}
		out = append(out, Summary{ID: p.ID, Vendor: p.Vendor, Status: p.Status, CreatedAt: p.CreatedAt, CreatedBy: p.CreatedBy,
			CompletedAt: p.CompletedAt, Counts: v.Report.Counts})
	}
	return out, nil
}

// verifiedDetail says what the rotation job's re-read actually observed, so the
// evidence never claims more than the provider showed.
func verifiedDetail(verification string) string {
	var v struct {
		Evidence string `json:"evidence"`
	}
	_ = json.Unmarshal([]byte(verification), &v)
	switch v.Evidence {
	case rotation.EvidenceAgeAndLastUse:
		return "rotated: a re-read showed the old credential disabled and unused since"
	case rotation.EvidenceAbsent:
		return "rotated: a re-read showed the old credential gone"
	case rotation.EvidenceAgeOnly:
		return "rotated: the provider shows only the old credential's age, not whether it is disabled"
	}
	return "rotated: the rotation job recorded a re-read without evidence detail"
}
