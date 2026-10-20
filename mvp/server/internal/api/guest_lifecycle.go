package api

import (
	"context"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	guestlife "github.com/nischalravi/tessera/mvp/server/internal/guests/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// The guest lifecycle API (guest accounts design §8, issue #74):
//
//	GET  /api/guest-lifecycle                      counts and settings (guests.read)
//	GET  /api/guest-lifecycle/items?bucket=...     the rows behind one count (guests.read; default expiring_30)
//	GET  /api/guest-lifecycle/tasks                the open tasks the caller may decide (guests.sponsor)
//	POST /api/guest-lifecycle/tasks/{id}/resolve   {"action": accept|decline|keep|confirm|dismiss}
//	GET|PUT /api/admin/guest-lifecycle             the tenant's settings (guest_lifecycle.configure)
//	POST /public/t/{slug}/guest/renewal-request    {"token"}: the guest's "request renewal" link
//
// The public route always answers 202 {"status":"received"}, whether or not the
// token was good, so it says nothing about which tokens exist.

func (s *Server) registerGuestLifecycleRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	s.handle(G, "/api/guest-lifecycle", read, need(auth.PermGuestsRead), s.guestLifecycleOverview)
	s.handle(G, "/api/guest-lifecycle/items", read, need(auth.PermGuestsRead), s.guestLifecycleItems)
	s.handle(G, "/api/guest-lifecycle/tasks", read, need(auth.PermGuestsSponsor), s.guestLifecycleTasks)
	s.handle(P, "/api/guest-lifecycle/tasks/{task_id}/resolve", write, needStepUp(auth.PermGuestsSponsor, auth.StepUpPolicy), s.resolveGuestTask)
	s.handle(G, "/api/admin/guest-lifecycle", read, need(auth.PermGuestLifecycleConfigure), s.getGuestLifecycleSettings)
	s.handle(http.MethodPut, "/api/admin/guest-lifecycle", write, needStepUp(auth.PermGuestLifecycleConfigure, auth.StepUpPolicy), s.putGuestLifecycleSettings)
	s.handle(P, "/public/t/{slug}/guest/renewal-request", noTenant, publicRoute, s.guestRenewalRequest)
}

type glSettingsView struct {
	SponsorReminderDays  []int          `json:"sponsor_reminder_days"`
	GuestReminderDays    int            `json:"guest_reminder_days"`
	TransferDeadlineDays int            `json:"transfer_deadline_days"`
	OnSponsorDeparture   string         `json:"on_sponsor_departure"`
	ConversionDualStatus string         `json:"conversion_dual_status"`
	GraceDays            map[string]int `json:"grace_days"`
	RetentionDays        int            `json:"retention_days"`
	RetentionDaysVisitor int            `json:"retention_days_visitor"`
	KeepRematchHashes    bool           `json:"keep_rematch_hashes"`
	UpdatedAt            *string        `json:"updated_at"`
}

func viewGLSettings(st store.GuestLifecycleSettings) glSettingsView {
	v := glSettingsView{SponsorReminderDays: st.SponsorReminderDays, GuestReminderDays: st.GuestReminderDays,
		TransferDeadlineDays: st.TransferDeadlineDays, OnSponsorDeparture: st.OnSponsorDeparture,
		ConversionDualStatus: st.ConversionDualStatus, GraceDays: st.GraceDays, RetentionDays: st.RetentionDays,
		RetentionDaysVisitor: st.RetentionDaysVisitor, KeepRematchHashes: st.KeepRematchHashes}
	if st.UpdatedAt != nil {
		t := timeutil.ISO(*st.UpdatedAt)
		v.UpdatedAt = &t
	}
	return v
}

func (s *Server) guestLifecycleOverview(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	counts, err := guestlife.Counts(tx, now)
	if err != nil {
		return nil, err
	}
	st, err := tx.GuestLifecycleSettings()
	if err != nil {
		return nil, err
	}
	return struct {
		Buckets  []string       `json:"buckets"`
		Counts   map[string]int `json:"counts"`
		Settings glSettingsView `json:"settings"`
	}{guestlife.Buckets, counts, viewGLSettings(st)}, nil
}

// glItems marks which rows' tasks the caller may decide.
func (s *Server) glItems(r *http.Request, items []guestlife.Item) ([]guestlife.Item, error) {
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	for i := range items {
		if items[i].TaskID == "" {
			continue
		}
		t, err := tx.LifecycleTask(items[i].TaskID)
		if err != nil {
			return nil, err
		}
		if t.Status == store.TaskOpen {
			if items[i].CanAct, err = guestlife.MayAct(tx, act, t); err != nil {
				return nil, err
			}
		}
	}
	return items, nil
}

func (s *Server) guestLifecycleItems(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	bucket := qs(p, "bucket")
	if bucket == "" {
		bucket = guestlife.BucketExpiring30
	}
	items, err := guestlife.Items(store.TxFrom(r.Context()), bucket, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	if items, err = s.glItems(r, items); err != nil {
		return nil, err
	}
	return struct {
		Bucket string           `json:"bucket"`
		Items  []guestlife.Item `json:"items"`
	}{bucket, items}, nil
}

// guestLifecycleTasks is the Inbox's part: the open tasks the caller may decide.
func (s *Server) guestLifecycleTasks(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	out := []guestlife.Item{}
	for _, b := range []string{guestlife.BucketPendingTransfer, guestlife.BucketRenewals, guestlife.BucketDualStatus} {
		items, err := guestlife.Items(tx, b, now)
		if err != nil {
			return nil, err
		}
		if items, err = s.glItems(r, items); err != nil {
			return nil, err
		}
		for _, it := range items {
			if it.CanAct {
				out = append(out, it)
			}
		}
	}
	return struct {
		Tasks []guestlife.Item `json:"tasks"`
	}{out}, nil
}

type resolveTaskBody struct {
	Action string `json:"action"`
}

func (s *Server) resolveGuestTask(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b resolveTaskBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	t, err := s.guestLife.Resolve(store.TxFrom(r.Context()), act, p.path["task_id"], b.Action, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	out := struct {
		ID            string  `json:"id"`
		Kind          string  `json:"kind"`
		SponsorshipID string  `json:"sponsorship_id"`
		Status        string  `json:"status"`
		Outcome       *string `json:"outcome"`
	}{t.ID, t.Kind, t.SponsorshipID, t.Status, t.Outcome}
	return out, nil
}

func (s *Server) getGuestLifecycleSettings(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	st, err := store.TxFrom(r.Context()).GuestLifecycleSettings()
	if err != nil {
		return nil, err
	}
	return viewGLSettings(st), nil
}

type putGLSettingsBody struct {
	SponsorReminderDays  []int          `json:"sponsor_reminder_days"`
	GuestReminderDays    int            `json:"guest_reminder_days"`
	TransferDeadlineDays int            `json:"transfer_deadline_days"`
	OnSponsorDeparture   string         `json:"on_sponsor_departure"`
	ConversionDualStatus string         `json:"conversion_dual_status"`
	GraceDays            map[string]int `json:"grace_days"`
	RetentionDays        int            `json:"retention_days"`
	RetentionDaysVisitor int            `json:"retention_days_visitor"`
	KeepRematchHashes    bool           `json:"keep_rematch_hashes"`
}

func (s *Server) putGuestLifecycleSettings(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b putGLSettingsBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	st := store.GuestLifecycleSettings{SponsorReminderDays: b.SponsorReminderDays, GuestReminderDays: b.GuestReminderDays,
		TransferDeadlineDays: b.TransferDeadlineDays, OnSponsorDeparture: b.OnSponsorDeparture, ConversionDualStatus: b.ConversionDualStatus,
		GraceDays: b.GraceDays, RetentionDays: b.RetentionDays, RetentionDaysVisitor: b.RetentionDaysVisitor, KeepRematchHashes: b.KeepRematchHashes}
	got, err := guestlife.PutSettings(store.TxFrom(r.Context()), st, act, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return viewGLSettings(got), nil
}

var renewalReceived = statusBody{http.StatusAccepted, ojson.Object{{Key: "status", Value: "received"}}}

type renewalRequestBody struct {
	Token string `json:"token"`
}

// guestRenewalRequest is the public "request renewal" link. Every answer is the
// same 202 (a rate limit aside, which does not depend on the token either).
func (s *Server) guestRenewalRequest(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	begin := time.Now()
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	var b renewalRequestBody
	if resp, ok := s.claimBody(w, r, &b); !ok {
		return resp, nil
	}
	defer s.claimFloor(r.Context(), begin)
	// the per-IP limit comes first and does not look at the token or the tenant, so
	// it answers the same for every call; its own buckets keep claim/start's intact
	if !s.claimLim.renewIP.AllowAt(s.rateKey(r), c.now) {
		return s.claimThrottled(c, "renewal_ip", 6*time.Minute)
	}
	if !c.ok || len(b.Token) != claim.TokenLen {
		return renewalReceived, nil
	}
	if !s.claimLim.renewTenant.AllowAt(ratelimit.TenantKey(c.t.ID.String()), c.now) {
		return s.claimThrottled(c, "renewal_request", 6*time.Second)
	}
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		return s.guestLife.RequestRenewal(tx, b.Token, c.now)
	})
	if err != nil {
		return nil, err
	}
	return renewalReceived, nil
}

// queueGuestLifecycleSweep runs the guest lifecycle jobs of one tenant on the
// durable queue (reminders, transfer deadlines, step-up renewals, conversions,
// grace and retention; issue #74). A pass that did nothing leaves no job run.
func (s *Server) queueGuestLifecycleSweep(ctx context.Context, j queue.Job) (any, error) {
	res, err := s.guestLife.SweepTenant(audit.WithSystemActor(ctx, guestlife.Sweeper), s.store, j.Tenant, s.clock())
	if res.Zero() && err == nil {
		return nil, nil
	}
	return res, err
}
