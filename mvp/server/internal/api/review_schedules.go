package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Scheduled access reviews (issue #166):
//
//	GET  /api/reviews/schedules                     templates with their recent runs
//	POST /api/reviews/schedules                     create
//	PUT  /api/reviews/schedules/{schedule_id}       replace the settings
//	POST /api/reviews/schedules/{schedule_id}/run   launch now, outside the schedule

func (s *Server) registerReviewScheduleRoutes() {
	manage := need(auth.PermReviewsManage)
	s.handle(http.MethodGet, "/api/reviews/schedules", read, need(auth.PermGraphRead), s.listReviewSchedules)
	s.handle(http.MethodPost, "/api/reviews/schedules", write, manage, s.createReviewSchedule)
	s.handle(http.MethodPut, "/api/reviews/schedules/{schedule_id}", write, manage, s.updateReviewSchedule)
	s.handle(http.MethodPost, "/api/reviews/schedules/{schedule_id}/run", write, manage, s.runReviewSchedule)
}

type scheduleBody struct {
	Name                 string     `json:"name"`
	System               *string    `json:"system"`
	PrivilegedOnly       bool       `json:"privileged_only"`
	UnusedDays           *int       `json:"unused_days"`
	DurationDays         *int       `json:"duration_days"`
	ReminderDays         *int       `json:"reminder_days"`
	CloseOut             string     `json:"close_out"`
	EscalationIdentityID *int64     `json:"escalation_identity_id"`
	EscalationDays       *int       `json:"escalation_days"`
	Recurrence           string     `json:"recurrence"`
	FirstRunAt           *time.Time `json:"first_run_at"`
	Enabled              *bool      `json:"enabled"`
	// RoleIDs scopes the review to these business roles' memberships (issue
	// #214). Omitted: kept on update, none on create. An empty list clears it.
	RoleIDs *[]string `json:"role_ids"`
	// ReviewType runs the schedule as a review type (issue #298): reviewers and
	// close-out then follow the type's settings. Omitted: kept on update, none on
	// create. "" clears it.
	ReviewType *string `json:"review_type"`
}

func intOr(p *int, d int) int {
	if p == nil {
		return d
	}
	return *p
}

func (b scheduleBody) apply(t *store.ReviewTemplate) {
	t.Name, t.System, t.PrivilegedOnly = b.Name, b.System, b.PrivilegedOnly
	t.UnusedDays, t.DurationDays, t.ReminderDays = intOr(b.UnusedDays, 60), intOr(b.DurationDays, 14), intOr(b.ReminderDays, 3)
	t.CloseOut, t.EscalationIdentityID, t.EscalationDays = b.CloseOut, b.EscalationIdentityID, intOr(b.EscalationDays, 7)
	if t.CloseOut == "" {
		t.CloseOut = "revoke"
	}
	t.Recurrence = b.Recurrence
	if b.FirstRunAt != nil {
		u := b.FirstRunAt.UTC()
		t.NextRunAt = &u
	}
	t.Enabled = b.Enabled == nil || *b.Enabled
}

type launchView struct {
	ID         string     `json:"id"`
	Period     string     `json:"period"`
	CampaignID int64      `json:"campaign_id"`
	LaunchedAt time.Time  `json:"launched_at"`
	DueAt      time.Time  `json:"due_at"`
	RemindedAt *time.Time `json:"reminded_at"`
	Escalated  *time.Time `json:"escalated_at"`
	ClosedAt   *time.Time `json:"closed_at"`
	Revoked    int        `json:"revoked"`
}

type scheduleView struct {
	ID                 string       `json:"id"`
	Name               string       `json:"name"`
	System             *string      `json:"system"`
	PrivilegedOnly     bool         `json:"privileged_only"`
	UnusedDays         int          `json:"unused_days"`
	DurationDays       int          `json:"duration_days"`
	ReminderDays       int          `json:"reminder_days"`
	CloseOut           string       `json:"close_out"`
	EscalationReviewer *personBrief `json:"escalation_reviewer"`
	EscalationDays     int          `json:"escalation_days"`
	Recurrence         string       `json:"recurrence"`
	NextRunAt          *time.Time   `json:"next_run_at"`
	Enabled            bool         `json:"enabled"`
	UpdatedAt          time.Time    `json:"updated_at"`
	Launches           []launchView `json:"launches"`
	RoleIDs            []string     `json:"role_ids"`
	ReviewType         *string      `json:"review_type"`
}

type personBrief struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func scheduleViewOf(tx *store.TenantTx, t *store.ReviewTemplate) (scheduleView, error) {
	v := scheduleView{ID: t.ID, Name: t.Name, System: t.System, PrivilegedOnly: t.PrivilegedOnly, UnusedDays: t.UnusedDays,
		DurationDays: t.DurationDays, ReminderDays: t.ReminderDays, CloseOut: t.CloseOut, EscalationDays: t.EscalationDays,
		Recurrence: t.Recurrence, NextRunAt: t.NextRunAt, Enabled: t.Enabled, UpdatedAt: t.UpdatedAt, Launches: []launchView{}}
	var err error
	if v.RoleIDs, err = tx.ReviewTemplateRoles(t.ID); err != nil {
		return v, err
	}
	if t.EscalationIdentityID != nil {
		i, err := tx.Identity(*t.EscalationIdentityID)
		if err != nil {
			return v, err
		}
		v.EscalationReviewer = &personBrief{i.ID, i.Name}
	}
	if rt, err := reviews.TemplateType(tx, t.ID); err != nil {
		return v, err
	} else if rt != "" {
		v.ReviewType = &rt
	}
	ls, err := tx.ReviewLaunches(t.ID)
	if err != nil {
		return v, err
	}
	for i, l := range ls {
		if i == 10 {
			break
		}
		v.Launches = append(v.Launches, launchView{l.ID, l.PeriodKey, l.CampaignID, l.LaunchedAt, l.DueAt, l.RemindedAt,
			l.EscalatedAt, l.ClosedAt, l.Revoked})
	}
	return v, nil
}

func scheduleErr(err error) error {
	var se *reviews.SpecError
	if errors.As(err, &se) {
		return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: se.Code, Msg: se.Msg}
	}
	return err
}

func (s *Server) listReviewSchedules(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx := store.TxFrom(r.Context())
	ts, err := tx.ReviewTemplates()
	if err != nil {
		return nil, err
	}
	out := make([]scheduleView, 0, len(ts))
	for _, t := range ts {
		v, err := scheduleViewOf(tx, t)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) putSchedule(r *http.Request, t *store.ReviewTemplate, b scheduleBody, insert bool) (any, error) {
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	b.apply(t)
	t.UpdatedAt = now
	if err := reviews.ValidateTemplate(tx, t); err != nil {
		return nil, scheduleErr(err)
	}
	var roleIDs []string
	if b.RoleIDs != nil {
		var rerr error
		if roleIDs, rerr = reviews.ValidateRoleScope(tx, *b.RoleIDs); rerr != nil {
			return nil, scheduleErr(rerr)
		}
	}
	var err error
	if insert {
		err = tx.InsertReviewTemplate(t)
	} else {
		err = tx.UpdateReviewTemplate(t)
	}
	if err != nil {
		return nil, err
	}
	if b.RoleIDs != nil {
		if err := tx.SetReviewTemplateRoles(t.ID, roleIDs); err != nil {
			return nil, err
		}
	}
	if b.ReviewType != nil {
		if err := reviews.SetTemplateType(tx, t.ID, strings.TrimSpace(*b.ReviewType)); err != nil {
			return nil, scheduleErr(err)
		}
	}
	next := ""
	if t.NextRunAt != nil {
		next = timeutil.ISO(*t.NextRunAt)
	}
	if err := tx.Audit(now, principal(r).Display, "review.schedule.put", ojson.Object{{Key: "schedule_id", Value: t.ID},
		{Key: "name", Value: t.Name}, {Key: "recurrence", Value: t.Recurrence}, {Key: "next_run_at", Value: next},
		{Key: "close_out", Value: t.CloseOut}, {Key: "enabled", Value: t.Enabled},
		{Key: "role_ids", Value: roleScopeForAudit(tx, t.ID)}, {Key: "review_type", Value: scheduleTypeForAudit(tx, t.ID)}}); err != nil {
		return nil, err
	}
	v, err := scheduleViewOf(tx, t)
	if err != nil {
		return nil, err
	}
	if insert {
		return statusBody{http.StatusCreated, v}, nil
	}
	return v, nil
}

func (s *Server) createReviewSchedule(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b scheduleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	t := &store.ReviewTemplate{ID: uuid.NewString(), CreatedAt: now}
	if pr := principal(r); pr != nil && pr.UserID != nil {
		id := pr.UserID.String()
		t.CreatedBy = &id
	}
	return s.putSchedule(r, t, b, true)
}

func (s *Server) schedule(r *http.Request, p *params) (*store.ReviewTemplate, error) {
	t, err := store.TxFrom(r.Context()).ReviewTemplate(strings.TrimSpace(p.path["schedule_id"]))
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "schedule_not_found", Msg: "schedule not found"}
	}
	return t, err
}

func (s *Server) updateReviewSchedule(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, err := s.schedule(r, p)
	if err != nil {
		return nil, err
	}
	var b scheduleBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if b.FirstRunAt == nil { // keep the current next run unless a new one is given
		b.FirstRunAt = t.NextRunAt
	}
	return s.putSchedule(r, t, b, false)
}

func (s *Server) runReviewSchedule(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	t, err := s.schedule(r, p)
	if err != nil {
		return nil, err
	}
	pols, err := s.policies()
	if err != nil {
		return nil, err
	}
	l, err := reviews.RunNow(store.TxFrom(r.Context()), t.ID, s.clock().UTC(), pols, principal(r).Display)
	if errors.Is(err, reviews.ErrAlreadyLaunched) {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "already_launched",
			Msg: "this schedule was just run; wait a second and run it again"}
	}
	if err != nil {
		return nil, err
	}
	if l == nil { // nothing in scope: no campaign, the skip is audited
		return statusBody{http.StatusOK, map[string]any{"skipped": true, "reason": "no grants are in scope for this schedule, so no campaign was created"}}, nil
	}
	return statusBody{http.StatusCreated, launchView{l.ID, l.PeriodKey, l.CampaignID, l.LaunchedAt, l.DueAt, l.RemindedAt,
		l.EscalatedAt, l.ClosedAt, l.Revoked}}, nil
}

// scheduleTypeForAudit is the review type of a schedule as the audit event records it ("" for none).
func scheduleTypeForAudit(tx *store.TenantTx, id string) string {
	t, _ := reviews.TemplateType(tx, id)
	return t
}
