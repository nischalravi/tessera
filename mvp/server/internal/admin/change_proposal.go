package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Config proposals by machine clients (issue #721). A machine client never holds an admin role and can never pass a
// step-up, so it cannot write configuration. It can instead PROPOSE a change: a config.proposal change request
// that a human admin approves with a step-up, and that is applied only then. Two change types carry it.
//
//   - api_client.propose.grant gives a machine client the config.propose scope. Two admins always: one requests it
//     (admin.change.request, step-up), a different one approves it (admin.change.approve, step-up). No other path adds
//     the scope: the UI, the API and the CLI refuse it at registration.
//   - config.proposal is one write (a catalog item, a business role, a SoD ruleset or a security alert rule) filed by
//     such a client through POST /api/proposals/... It is two-person, with no cooling-off, so the approval applies it.
//
// The request row is the ordinary admin_change_requests row, so the state machine, the payload hash the approver must
// echo, the 72 hour window, the notifications and the audit trail are the existing ones. It is filed in the name of
// the client's owner (requested_by_user_id is a platform user), so the owner can never approve it either: the store's
// approve statement and the table CHECK refuse an approver equal to the requester, and SameActor refuses a person who
// is the same as the requester through a linked identity. admin_change_proposals names the client, which every
// transition's audit event then carries as client_id.
const (
	TypeConfigProposal = "config.proposal"
	TypeProposeGrant   = "api_client.propose.grant"
)

// The kinds of config.proposal.
const (
	KindCatalogItem = "catalog_item"
	KindRole        = "role"
	KindSoDRuleset  = "sod_ruleset"
	KindAlertRule   = "alert_rule"
)

// ProposalKinds lists the kinds a machine client can propose.
var ProposalKinds = []string{KindCatalogItem, KindRole, KindSoDRuleset, KindAlertRule}

// maxProposalBody bounds a proposal's body: a role with many entitlements is a few KB.
const maxProposalBody = 256 << 10

// CatalogItemBody is the body of a catalog_item proposal (the body of PUT /api/catalog/items/{group_id}); the
// proposal's id is the group id.
type CatalogItemBody struct {
	Requestable         bool     `json:"requestable"`
	Description         string   `json:"description"`
	OwnerIdentityID     *int64   `json:"owner_identity_id"`
	Risk                string   `json:"risk"`
	EligibleTypes       []string `json:"eligible_types"`
	EligibleDepartments []string `json:"eligible_departments"`
	DefaultHours        *float64 `json:"default_hours"`
	MaxHours            *float64 `json:"max_hours"`
	Populations         []string `json:"populations"`
	ApprovalStages      []string `json:"approval_stages"`
	EscalateAfterHours  *float64 `json:"escalate_after_hours"`
}

// RoleBody is the body of a role proposal (POST/PUT /api/roles): the proposal's id is empty to create a role and the
// role id to change one (then Version is the version the proposer read).
type RoleBody struct {
	Version         int         `json:"version"`
	Key             string      `json:"key"`
	Name            string      `json:"name"`
	Description     string      `json:"description"`
	OwnerIdentityID *int64      `json:"owner_identity_id"`
	Risk            string      `json:"risk"`
	Requestable     bool        `json:"requestable"`
	Birthright      *roles.Rule `json:"birthright"`
	Entitlements    []int64     `json:"entitlement_group_ids"`
	Note            string      `json:"note"`
}

// SoDRulesetBody is the body of a sod_ruleset proposal (POST/PUT /api/sod/rulesets): the proposal's id is empty to
// create a ruleset and the ruleset id to change one.
type SoDRulesetBody struct {
	Version     int    `json:"version"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     *bool  `json:"enabled"`
	Note        string `json:"note"`
}

// AlertRuleBody is the body of an alert_rule proposal (PUT /api/alerts/rules/{rule_id}); the proposal's id is the rule id.
type AlertRuleBody struct {
	Enabled       bool   `json:"enabled"`
	Severity      string `json:"severity"`
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
}

type proposalPayload struct {
	Kind string          `json:"kind"`
	ID   string          `json:"id"`
	Body json.RawMessage `json:"body"`
}

type proposeGrantPayload struct {
	ClientID string `json:"client_id"`
}

func init() {
	changeTypes[TypeConfigProposal] = typed(TypeConfigProposal, nil, planProposal, applyProposal, summarizeProposal)
	changeTypes[TypeProposeGrant] = typed(TypeProposeGrant, nil, planProposeGrant, applyProposeGrant,
		func(_ *env, v *proposeGrantPayload) string {
			return "Let machine client " + v.ClientID + " propose configuration changes (scope " + string(auth.ScopeConfigPropose) +
				"): it can only file requests that a person approves with a step-up; it can never approve or apply one"
		})
}

// strictBody decodes a proposal body into T, refusing unknown fields and trailing data.
func strictBody[T any](raw json.RawMessage) (*T, error) {
	var v T
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return nil, invalid("body: %v", err)
	}
	if dec.More() {
		return nil, invalid("body: trailing data")
	}
	return &v, nil
}

// decodeProposalBody decodes the body of a proposal of this kind.
func decodeProposalBody(kind string, raw json.RawMessage) (any, error) {
	switch kind {
	case KindCatalogItem:
		return strictBody[CatalogItemBody](raw)
	case KindRole:
		return strictBody[RoleBody](raw)
	case KindSoDRuleset:
		return strictBody[SoDRulesetBody](raw)
	case KindAlertRule:
		return strictBody[AlertRuleBody](raw)
	}
	return nil, invalid("kind %q: want one of %s", kind, strings.Join(ProposalKinds, ", "))
}

// checkProposalID validates the id the kind needs: the group id of a catalog item, the id of the role or ruleset
// being changed (empty to create one) and the id of an alert rule.
func checkProposalID(kind, id string) error {
	switch kind {
	case KindCatalogItem:
		if n, err := strconv.ParseInt(id, 10, 64); err != nil || n < 1 {
			return invalid("id is the group id of the catalog item")
		}
	case KindAlertRule:
		if id == "" || len(id) > 64 {
			return invalid("id is the id of the alert rule")
		}
	case KindRole, KindSoDRuleset:
		if len(id) > 64 {
			return invalid("id is at most 64 characters")
		}
	}
	return nil
}

// ProposalPayload validates a proposal and returns the payload of its change request, with the body in canonical
// form (the decoded body marshalled again), so the hash the approver echoes does not depend on how the client
// spelled its JSON.
func ProposalPayload(kind, id string, body json.RawMessage) (json.RawMessage, error) {
	if len(body) == 0 || len(body) > maxProposalBody {
		return nil, invalid("body is required and at most %d bytes", maxProposalBody)
	}
	if err := checkProposalID(kind, id); err != nil {
		return nil, err
	}
	v, err := decodeProposalBody(kind, body)
	if err != nil {
		return nil, err
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return nil, invalid("body: %v", err)
	}
	return json.Marshal(proposalPayload{Kind: kind, ID: id, Body: canon})
}

// proposerUser checks that the machine client may propose now and returns the user it is filed in the name of: the
// client's owner. A client with no active owner, a disabled one or one without the scope proposes nothing.
func (e *env) proposerUser(clientID string) (uuid.UUID, error) {
	cl, err := e.tx.APIClientByClientID(clientID)
	if errors.Is(err, store.ErrNotFound) {
		return uuid.Nil, newErr(403, "forbidden", "unknown client")
	} else if err != nil {
		return uuid.Nil, err
	}
	switch {
	case cl.Kind != "machine" || cl.Status != store.ClientActive:
		return uuid.Nil, newErr(403, "forbidden", "the client is not an active machine client")
	case !slices.Contains(cl.AllowedScopes, string(auth.ScopeConfigPropose)):
		return uuid.Nil, newErr(403, "forbidden", "the client does not hold the %s scope", auth.ScopeConfigPropose)
	case cl.OwnerUserID == nil:
		return uuid.Nil, newErr(403, "owner_required", "a client that proposes changes needs an owner, the person accountable for it")
	}
	u, err := e.tx.PlatformUser(*cl.OwnerUserID)
	if errors.Is(err, store.ErrNotFound) {
		return uuid.Nil, newErr(403, "owner_required", "the owner of the client is gone")
	} else if err != nil {
		return uuid.Nil, err
	}
	if u.Status != "active" {
		return uuid.Nil, newErr(403, "owner_required", "the owner of the client is disabled")
	}
	return u.ID, nil
}

// Reasons a proposal ends without applying, stored as the request's failure text and carried by the audit event.
const (
	ReasonProposerRevoked = "proposer_revoked"
	ReasonPayloadTampered = "payload_tampered"
)

// proposerStillValid is the re-check at approve and apply (issue #743): the client that filed the proposal is still an
// active machine client holding config.propose with an active owner, the same test as at submit. A proposal filed by a
// credential the tenant has since withdrawn is refused, 409 proposer_revoked, and the caller marks the request failed.
func (e *env) proposerStillValid(ch *store.AdminChange) error {
	if ch.Type != TypeConfigProposal {
		return nil
	}
	client, err := e.tx.AdminChangeProposer(ch.ID)
	if err != nil {
		return err
	}
	revoked := conflict(ReasonProposerRevoked, "the client that filed this proposal is revoked, lost %s or has no active owner", auth.ScopeConfigPropose)
	if client == "" {
		return revoked
	}
	if _, err := e.proposerUser(client); err != nil {
		var ae *Error
		if errors.As(err, &ae) {
			return revoked
		}
		return err
	}
	return nil
}

// CancelProposalsOf cancels the open proposals of a machine client that was revoked or lost config.propose, in the
// caller's transaction: each request ends cancelled with reason proposer_revoked and an admin.change.cancelled event
// naming the client. by is the admin who revoked it; it returns how many were cancelled.
func (s *Service) CancelProposalsOf(tx *store.TenantTx, clientID string, by *uuid.UUID, display string) (int, error) {
	open, err := tx.OpenAdminChangesOfProposer(clientID)
	if err != nil {
		return 0, err
	}
	now := s.now()
	for _, ch := range open {
		who := ch.RequestedBy
		if by != nil {
			who = *by
		}
		if err := tx.CancelAdminChangeWhy(ch.ID, who, now, ReasonProposerRevoked); err != nil {
			return 0, err
		}
		if ch, err = tx.AdminChange(ch.ID); err != nil {
			return 0, err
		}
		e := s.env(tx, now, ch.RequestedBy)
		if err := e.ended(ch); err != nil {
			return 0, err
		}
		if err := e.transition(ch, TransCancelled, display); err != nil {
			return 0, err
		}
	}
	return len(open), nil
}

// SetClientScopes replaces a machine client's scopes. Dropping config.propose cancels the client's open proposals in the
// same transaction.
func (s *Service) SetClientScopes(tx *store.TenantTx, clientID string, scopes []string, by *uuid.UUID, display string) error {
	cl, err := tx.APIClientByClientID(clientID)
	if err != nil {
		return err
	}
	if err := tx.SetAPIClientScopes(clientID, scopes); err != nil {
		return err
	}
	had, has := slices.Contains(cl.AllowedScopes, string(auth.ScopeConfigPropose)), slices.Contains(scopes, string(auth.ScopeConfigPropose))
	if had && !has {
		_, err = s.CancelProposalsOf(tx, clientID, by, display)
	}
	return err
}

// SubmitProposal files a config.proposal in the name of the machine client p. The client needs the config.propose
// scope (checked here against the token, and in proposerUser against the stored client) and no role. The request
// waits for a human admin: only POST /api/admin/change-requests/{id}/approve (admin.change.approve, step-up) moves it.
func (s *Service) SubmitProposal(ctx context.Context, p *auth.Principal, kind, id string, body json.RawMessage) (*store.AdminChange, error) {
	if p == nil || p.Kind != auth.KindAPIClient || p.ClientID == "" {
		return nil, newErr(403, "forbidden", "only a machine client proposes changes")
	}
	if d := auth.Check(p, auth.PermConfigPropose, nil, s.now()); d != nil {
		return nil, denied(d)
	}
	payload, err := ProposalPayload(kind, id, body)
	if err != nil {
		return nil, err
	}
	return s.submit(ctx, p, SubmitInput{Type: TypeConfigProposal, Payload: payload}, p.ClientID)
}

// ---------------------------------------------------------------- config.proposal

func planProposal(e *env, v *proposalPayload) (plan, error) {
	if err := checkProposalID(v.Kind, v.ID); err != nil {
		return plan{}, err
	}
	body, err := decodeProposalBody(v.Kind, v.Body)
	if err != nil {
		return plan{}, err
	}
	switch b := body.(type) {
	case *CatalogItemBody:
		gid, _ := strconv.ParseInt(v.ID, 10, 64)
		g, err := e.tx.Group(gid)
		if errors.Is(err, store.ErrNotFound) {
			return plan{}, notFound("group")
		} else if err != nil {
			return plan{}, err
		}
		if err := requests.CheckItem(e.tx, g, b.spec()); err != nil {
			return plan{}, proposalErr(err)
		}
		if b.EscalateAfterHours != nil && (*b.EscalateAfterHours < 0 || *b.EscalateAfterHours > requests.MaxHours) {
			return plan{}, invalid("escalate_after_hours is between 0 and %d", requests.MaxHours)
		}
	case *RoleBody:
		// a dry run validates the spec (and the version of a role being changed) and saves nothing
		by := requests.Actor{UserID: e.by}
		var err error
		if v.ID == "" {
			_, err = roles.Create(e.tx, b.spec(), by, true, e.now)
		} else {
			_, err = roles.Update(e.tx, v.ID, b.Version, b.spec(), by, true, e.now)
		}
		if err != nil {
			return plan{}, proposalErr(err)
		}
	case *SoDRulesetBody:
		if v.ID == "" {
			if strings.TrimSpace(b.Name) == "" {
				return plan{}, invalid("name is required")
			}
			if b.Key = strings.TrimSpace(b.Key); b.Key != "" && !sod.ValidKey(b.Key) {
				return plan{}, invalid("key is 1 to %d letters, digits, '.', '_', ':' or '-'", sod.MaxKey)
			}
		} else if _, err := e.tx.SodRuleset(v.ID); errors.Is(err, store.ErrNotFound) {
			return plan{}, notFound("ruleset")
		} else if err != nil {
			return plan{}, err
		}
	case *AlertRuleBody:
		if err := alerts.CheckRule(v.ID, b.spec()); err != nil {
			return plan{}, proposalErr(err)
		}
	}
	return plan{twoPerson: true, target: v.Kind + ":" + v.ID}, nil
}

func (b *CatalogItemBody) spec() requests.ItemSpec {
	return requests.ItemSpec{Requestable: b.Requestable, Description: b.Description, OwnerIdentityID: b.OwnerIdentityID,
		Risk: b.Risk, EligibleTypes: b.EligibleTypes, EligibleDepartments: b.EligibleDepartments,
		DefaultHours: b.DefaultHours, MaxHours: b.MaxHours, Populations: b.Populations}
}

func (b *RoleBody) spec() roles.Spec {
	return roles.Spec{Key: b.Key, Name: b.Name, Description: b.Description, OwnerIdentityID: b.OwnerIdentityID, Risk: b.Risk,
		Requestable: b.Requestable, Birthright: b.Birthright, Entitlements: b.Entitlements, Note: b.Note}
}

func (b *AlertRuleBody) spec() alerts.RuleSpec {
	return alerts.RuleSpec{Enabled: b.Enabled, Severity: b.Severity, Threshold: b.Threshold, WindowMinutes: b.WindowMinutes}
}

// proposalErr turns what the domain writers return into an API error.
func proposalErr(err error) error {
	var re *requests.Error
	var rl *roles.Error
	var al *alerts.Error
	switch {
	case errors.As(err, &re):
		return newErr(re.Status, re.Code, "%s", re.Msg)
	case errors.As(err, &rl):
		return newErr(rl.Status, rl.Code, "%s", rl.Msg)
	case errors.As(err, &al):
		return newErr(al.Status, al.Code, "%s", al.Msg)
	}
	var se *sod.Refusal
	if errors.As(err, &se) {
		return newErr(se.Status, se.Code, "%s", se.Msg)
	}
	return err
}

// applyProposal makes the write, as the admin who approved it (their id is the actor of the domain event, and the
// change's own events carry the client id). Nothing here runs for a request nobody approved.
func applyProposal(e *env, ch *store.AdminChange, v *proposalPayload) error {
	if ch.ApprovedBy == nil {
		return conflict("invalid_state", "a proposal is applied only after a person approved it")
	}
	if err := e.proposerStillValid(ch); err != nil {
		return err
	}
	if _, err := planProposal(e, v); err != nil {
		return err
	}
	by := *ch.ApprovedBy
	display := e.name(by)
	body, err := decodeProposalBody(v.Kind, v.Body)
	if err != nil {
		return err
	}
	switch b := body.(type) {
	case *CatalogItemBody:
		return applyCatalogItem(e, v, b, requests.Actor{UserID: by, Display: display})
	case *RoleBody:
		actor := requests.Actor{UserID: by, Display: display}
		if v.ID == "" {
			_, err = roles.Create(e.tx, b.spec(), actor, false, e.now)
		} else {
			_, err = roles.Update(e.tx, v.ID, b.Version, b.spec(), actor, false, e.now)
		}
		return proposalErr(err)
	case *SoDRulesetBody:
		w := &sod.Writer{Tx: e.tx, By: sod.Actor{UserID: by, Display: display}, Now: e.now}
		in := sod.RulesetInput{Key: b.Key, Name: b.Name, Description: b.Description, Enabled: b.Enabled == nil || *b.Enabled, Note: b.Note}
		if v.ID == "" {
			_, err = w.CreateRuleset(in)
		} else {
			_, err = w.UpdateRuleset(v.ID, b.Version, in)
		}
		return proposalErr(err)
	case *AlertRuleBody:
		return proposalErr(alerts.SetRule(e.tx, v.ID, b.spec(), alerts.Actor{UserID: by.String(), Display: display}, e.now))
	}
	return invalid("kind %q", v.Kind)
}

func applyCatalogItem(e *env, v *proposalPayload, b *CatalogItemBody, by requests.Actor) error {
	gid, _ := strconv.ParseInt(v.ID, 10, 64)
	it, err := requests.PutItem(e.tx, gid, b.spec(), by, e.now)
	if err != nil {
		return proposalErr(err)
	}
	if b.ApprovalStages == nil && b.EscalateAfterHours == nil {
		return nil
	}
	stages, hours, err := requests.Policy(e.tx, it.ID)
	if err != nil {
		return err
	}
	if b.ApprovalStages != nil {
		stages = b.ApprovalStages
	}
	if b.EscalateAfterHours != nil {
		hours = *b.EscalateAfterHours
	}
	return proposalErr(requests.SetPolicy(e.tx, it.ID, stages, hours, by, e.now))
}

// summarizeProposal tells the approver what is proposed, by whom and what it would change.
func summarizeProposal(e *env, v *proposalPayload) string {
	body, err := decodeProposalBody(v.Kind, v.Body)
	if err != nil {
		return "Proposed configuration change (" + v.Kind + ")"
	}
	var what string
	switch b := body.(type) {
	case *CatalogItemBody:
		what = fmt.Sprintf("set catalog item of group %s (requestable %t, risk %s)", v.ID, b.Requestable, b.Risk)
	case *RoleBody:
		if v.ID == "" {
			what = fmt.Sprintf("create business role %q (risk %s, %d entitlements, requestable %t)", b.Name, b.Risk, len(b.Entitlements), b.Requestable)
		} else {
			what = fmt.Sprintf("change business role %s to %q (risk %s, %d entitlements, requestable %t)", v.ID, b.Name, b.Risk, len(b.Entitlements), b.Requestable)
		}
	case *SoDRulesetBody:
		if v.ID == "" {
			what = fmt.Sprintf("create SoD ruleset %q", b.Name)
		} else {
			what = fmt.Sprintf("change SoD ruleset %s to %q", v.ID, b.Name)
		}
	case *AlertRuleBody:
		what = fmt.Sprintf("set alert rule %s (enabled %t, severity %s, threshold %d in %d minutes)", v.ID, b.Enabled, b.Severity, b.Threshold, b.WindowMinutes)
	}
	return "Proposed by a machine client: " + what
}

// ---------------------------------------------------------------- api_client.propose.grant

// planProposeGrant: the client is an active machine client with an active owner that does not hold the scope yet.
// Two admins always, with no cooling-off: the scope carries no permission to change anything by itself.
func planProposeGrant(e *env, v *proposeGrantPayload) (plan, error) {
	if v.ClientID == "" || len(v.ClientID) > 64 {
		return plan{}, invalid("client_id is the id of the machine client")
	}
	cl, err := e.tx.APIClientByClientID(v.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return plan{}, notFound("client")
	} else if err != nil {
		return plan{}, err
	}
	switch {
	case cl.Kind != "machine":
		return plan{}, conflict("not_machine_client", "only a machine client can hold %s", auth.ScopeConfigPropose)
	case cl.Status != store.ClientActive:
		return plan{}, conflict("client_disabled", "the client is disabled")
	case slices.Contains(cl.AllowedScopes, string(auth.ScopeConfigPropose)):
		return plan{}, conflict("already_granted", "the client already holds %s", auth.ScopeConfigPropose)
	case cl.OwnerUserID == nil:
		return plan{}, conflict("owner_required", "the client has no owner: a client that proposes changes needs the person accountable for it")
	}
	u, err := e.tx.PlatformUser(*cl.OwnerUserID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return plan{}, err
	}
	if err != nil || u.Status != "active" {
		return plan{}, conflict("owner_required", "the owner of the client is gone or disabled")
	}
	return plan{twoPerson: true, target: v.ClientID}, nil
}

func applyProposeGrant(e *env, ch *store.AdminChange, v *proposeGrantPayload) error {
	if _, err := planProposeGrant(e, v); err != nil {
		return err
	}
	cl, err := e.tx.APIClientByClientID(v.ClientID)
	if err != nil {
		return err
	}
	scopes := append(slices.Clone(cl.AllowedScopes), string(auth.ScopeConfigPropose))
	if err := e.tx.SetAPIClientScopes(v.ClientID, scopes); err != nil {
		return err
	}
	detail := ojson.Object{{Key: "client_id", Value: v.ClientID}, {Key: "scope", Value: string(auth.ScopeConfigPropose)},
		{Key: "change_id", Value: ch.ID.String()}, {Key: "requested_by", Value: ch.RequestedBy.String()}}
	if ch.ApprovedBy != nil {
		detail = append(detail, ojson.KV{Key: "approved_by", Value: ch.ApprovedBy.String()})
	}
	_, err = audit.Record(e.tx.Context(), e.tx, "api_client.propose_granted", detail, audit.At(e.now),
		audit.Target("admin_change", ch.ID.String()))
	return err
}

// ProposalResult is the id of the row an applied proposal made or changed, so the client that proposed a create can
// find it: the group id of a catalog item and the rule id of an alert rule (the proposal's own id), the id of a role
// or a SoD ruleset (looked up by its key). It is "" for a request that is not an applied proposal, and for a create
// that named no key (the server derived one the client cannot know).
func ProposalResult(tx *store.TenantTx, ch *store.AdminChange) string {
	if ch.Type != TypeConfigProposal || ch.Status != store.ChangeApplied {
		return ""
	}
	_, v, err := decodeStored(ch)
	if err != nil {
		return ""
	}
	p := v.(*proposalPayload)
	if p.ID != "" {
		return p.ID
	}
	body, err := decodeProposalBody(p.Kind, p.Body)
	if err != nil {
		return ""
	}
	switch b := body.(type) {
	case *RoleBody:
		if r, err := tx.BusinessRoleByKey(strings.TrimSpace(b.Key)); err == nil && b.Key != "" {
			return r.ID
		}
	case *SoDRulesetBody:
		if r, err := tx.SodRulesetByKey(strings.TrimSpace(b.Key)); err == nil && b.Key != "" {
			return r.ID
		}
	}
	return ""
}
