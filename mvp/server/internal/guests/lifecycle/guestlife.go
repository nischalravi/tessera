// Package guestlife is the lifecycle of a sponsored guest after the invitation
// (guest accounts design §8, issue #74 / GU-11): reminders before a sponsorship
// ends, the guest's request for a renewal, the transfer tasks that follow a
// sponsor's departure, the conversion of a guest or contractor to an employee,
// and what happens when the last affiliation ends: the grace period, the
// deprovisioning of the person and, after the retention period, the purge of
// their personal data to a tombstone.
//
// The sponsorship's own changes (renew with a step-up, take over, end or
// suspend, return) are in internal/guests/sponsorship; this package decides
// when they happen. Everything runs in the caller's tenant transaction, with
// its audit event; Sweep runs every step for one tenant, and the server's
// sweeper records it as a job run.
//
// The audit ledger is never changed here: a purge reduces operational tables
// only, and its audit event counts what it reduced without naming any of it.
package guestlife

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Sweeper is the actor of the lifecycle jobs' events.
const Sweeper = "guest.lifecycle.sweeper"

// Error is a refused change; Code is stable for API clients.
type Error = requests.Error

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Actor is the signed-in user acting (the sponsorship package's).
type Actor = sponsorship.Actor

// Service runs the guest lifecycle.
type Service struct {
	Sponsors *sponsorship.Service
	// Secrets and BaseURL carry the guest's "request renewal" link in the
	// reminder email (the link is never stored: only its hash is). Without them
	// the guest's reminder is not sent.
	Secrets *notify.Secrets
	BaseURL string
	// TenantName is the display name of a tenant for the guest's email.
	TenantName func(context.Context, tenancy.ID) string
}

// New returns a Service over the sponsor service.
func New(sp *sponsorship.Service) *Service { return &Service{Sponsors: sp} }

func (s *Service) tenantName(tx *store.TenantTx) string {
	if s.TenantName != nil {
		if n := strings.TrimSpace(s.TenantName(tx.Context(), tx.Tenant())); n != "" {
			return n
		}
	}
	return "Tessera"
}

func sweeper() Actor { return Actor{Display: Sweeper} }

func daysLeft(end, now time.Time) int {
	d := int(end.Sub(now).Hours() / 24)
	if end.Sub(now) > time.Duration(d)*24*time.Hour {
		d++
	}
	return max(d, 0)
}

func iso(t time.Time) string { return timeutil.ISO(t) }

func kv(k string, v any) ojson.KV { return ojson.KV{Key: k, Value: v} }
