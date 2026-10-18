package store

import (
	"database/sql"
	"time"
)

// Identity lifecycle (schema/0220_lifecycle.sql, issue #159).

// Worker types.
const (
	WorkerEmployee   = "employee"
	WorkerContractor = "contractor"
	WorkerIntern     = "intern"
	WorkerPartner    = "partner"
	WorkerVendor     = "vendor"
	WorkerGuest      = "guest"
)

// Lifecycle is an identity's worker type, sponsor and dates.
type Lifecycle struct {
	IdentityID   int64
	WorkerType   string
	SponsorID    *int64
	Organization *string
	StartsAt     *time.Time
	EndsAt       *time.Time
	WarnedDays   *int // smallest warning threshold sent; nil: none
	EndedAt      *time.Time
	Source       string // manual, hris
	UpdatedBy    *string
	UpdatedAt    time.Time
}

// LifecycleEvent is one entry of an identity's lifecycle history.
type LifecycleEvent struct {
	ID          int64
	IdentityID  int64
	Event       string // set, extended, converted, warned, ended
	WorkerType  *string
	EndsAt      *time.Time
	Note        *string
	ActorUserID *string
	Actor       string
	At          time.Time
}

const lcCols = `l.identity_id, l.worker_type, l.sponsor_identity_id, l.organization, l.starts_at, l.ends_at, l.warned_days,
	l.ended_at, l.source, l.updated_by, l.updated_at`

var (
	lcList = tq("identity_lifecycle.list", `
		SELECT `+lcCols+` FROM identity_lifecycle l WHERE l.tenant_id = @tenant ORDER BY l.identity_id`)
	lcGet = tq("identity_lifecycle.get", `
		SELECT `+lcCols+` FROM identity_lifecycle l WHERE l.tenant_id = @tenant AND l.identity_id = @identity_id`)
	lcDue = tq("identity_lifecycle.due", `
		SELECT `+lcCols+` FROM identity_lifecycle l WHERE l.tenant_id = @tenant AND l.ended_at IS NULL
			AND l.ends_at IS NOT NULL AND l.ends_at <= @by ORDER BY l.ends_at, l.identity_id`)
	lcPut = tq("identity_lifecycle.put", `
		INSERT INTO identity_lifecycle (tenant_id, identity_id, worker_type, sponsor_identity_id, organization, starts_at,
			ends_at, warned_days, ended_at, source, updated_by, updated_at)
		VALUES (@tenant, @identity_id, @worker_type, @sponsor_identity_id, @organization, @starts_at, @ends_at,
			@warned_days, @ended_at, @source, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, identity_id) DO UPDATE SET worker_type = excluded.worker_type,
			sponsor_identity_id = excluded.sponsor_identity_id, organization = excluded.organization,
			starts_at = excluded.starts_at, ends_at = excluded.ends_at, warned_days = excluded.warned_days,
			ended_at = excluded.ended_at, source = excluded.source, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)
	lcWarn = tq("identity_lifecycle.warn", `
		UPDATE identity_lifecycle SET warned_days = @days
		WHERE tenant_id = @tenant AND identity_id = @identity_id AND ended_at IS NULL`)
	lcEnd = tq("identity_lifecycle.end", `
		UPDATE identity_lifecycle SET ended_at = @at
		WHERE tenant_id = @tenant AND identity_id = @identity_id AND ended_at IS NULL`)

	lceInsert = tq("identity_lifecycle_events.insert", `
		INSERT INTO identity_lifecycle_events (tenant_id, identity_id, event, worker_type, ends_at, note, actor_user_id, actor, at)
		VALUES (@tenant, @identity_id, @event, @worker_type, @ends_at, @note, @actor_user_id, @actor, @at)`)
	lceFor = tq("identity_lifecycle_events.for_identity", `
		SELECT e.id, e.identity_id, e.event, e.worker_type, e.ends_at, e.note, e.actor_user_id, e.actor, e.at
		FROM identity_lifecycle_events e WHERE e.tenant_id = @tenant AND e.identity_id = @identity_id ORDER BY e.id`)
)

func scanLifecycle(s scanner) (*Lifecycle, error) {
	var l Lifecycle
	var sponsor sql.NullInt64
	var org, by sql.NullString
	var starts, ends, ended, updated nullTime
	var warned sql.NullInt64
	if err := s.Scan(&l.IdentityID, &l.WorkerType, &sponsor, &org, &starts, &ends, &warned, &ended, &l.Source, &by,
		&updated); err != nil {
		return nil, err
	}
	l.SponsorID, l.Organization, l.UpdatedBy = intp(sponsor), strp(org), strp(by)
	if warned.Valid {
		d := int(warned.Int64)
		l.WarnedDays = &d
	}
	var err error
	if l.StartsAt, err = starts.ptr(); err != nil {
		return nil, err
	}
	if l.EndsAt, err = ends.ptr(); err != nil {
		return nil, err
	}
	if l.EndedAt, err = ended.ptr(); err != nil {
		return nil, err
	}
	l.UpdatedAt, err = updated.val()
	return &l, err
}

func scanLifecycleEvent(s scanner) (*LifecycleEvent, error) {
	var e LifecycleEvent
	var wt, note, uid sql.NullString
	var ends, at nullTime
	if err := s.Scan(&e.ID, &e.IdentityID, &e.Event, &wt, &ends, &note, &uid, &e.Actor, &at); err != nil {
		return nil, err
	}
	e.WorkerType, e.Note, e.ActorUserID = strp(wt), strp(note), strp(uid)
	var err error
	if e.EndsAt, err = ends.ptr(); err != nil {
		return nil, err
	}
	e.At, err = at.val()
	return &e, err
}

// Lifecycles returns every lifecycle row, by identity id.
func (tx *TenantTx) Lifecycles() ([]*Lifecycle, error) { return collect(tx, scanLifecycle, lcList) }

// LifecycleFor returns an identity's lifecycle, or ErrNotFound (an employee
// with no end date).
func (tx *TenantTx) LifecycleFor(identityID int64) (*Lifecycle, error) {
	return one(tx, scanLifecycle, lcGet, sql.Named("identity_id", identityID))
}

// LifecyclesEndingBy returns the rows not yet ended whose end date is at or
// before by, soonest first.
func (tx *TenantTx) LifecyclesEndingBy(by time.Time) ([]*Lifecycle, error) {
	return collect(tx, scanLifecycle, lcDue, sql.Named("by", T(by)))
}

func intArg(i *int) any {
	if i == nil {
		return nil
	}
	return *i
}

// PutLifecycle inserts or replaces an identity's lifecycle row.
func (tx *TenantTx) PutLifecycle(l *Lifecycle) error {
	_, err := tx.exec(lcPut, sql.Named("identity_id", l.IdentityID), sql.Named("worker_type", l.WorkerType),
		sql.Named("sponsor_identity_id", IP(l.SponsorID)), sql.Named("organization", SP(l.Organization)),
		sql.Named("starts_at", TP(l.StartsAt)), sql.Named("ends_at", TP(l.EndsAt)),
		sql.Named("warned_days", intArg(l.WarnedDays)), sql.Named("ended_at", TP(l.EndedAt)),
		sql.Named("source", l.Source), sql.Named("updated_by", SP(l.UpdatedBy)), sql.Named("updated_at", T(l.UpdatedAt)))
	return err
}

// MarkLifecycleWarned records the warning threshold sent.
func (tx *TenantTx) MarkLifecycleWarned(identityID int64, days int) error {
	_, err := tx.exec(lcWarn, sql.Named("identity_id", identityID), sql.Named("days", days))
	return err
}

// MarkLifecycleEnded records the end; ErrNotFound if it had already ended.
func (tx *TenantTx) MarkLifecycleEnded(identityID int64, at time.Time) error {
	res, err := tx.exec(lcEnd, sql.Named("identity_id", identityID), sql.Named("at", T(at)))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AddLifecycleEvent appends to an identity's lifecycle history.
func (tx *TenantTx) AddLifecycleEvent(e *LifecycleEvent) error {
	_, err := tx.exec(lceInsert, sql.Named("identity_id", e.IdentityID), sql.Named("event", e.Event),
		sql.Named("worker_type", SP(e.WorkerType)), sql.Named("ends_at", TP(e.EndsAt)), sql.Named("note", SP(e.Note)),
		sql.Named("actor_user_id", SP(e.ActorUserID)), sql.Named("actor", e.Actor), sql.Named("at", T(e.At)))
	return err
}

// LifecycleEvents returns an identity's lifecycle history, oldest first.
func (tx *TenantTx) LifecycleEvents(identityID int64) ([]*LifecycleEvent, error) {
	return collect(tx, scanLifecycleEvent, lceFor, sql.Named("identity_id", identityID))
}
