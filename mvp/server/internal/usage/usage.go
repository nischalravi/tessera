// Package usage derives usage statistics from daily-aggregated usage events.
package usage

import (
	"database/sql"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Stat summarizes how an identity used one permission in the last 90 days.
type Stat struct {
	LastUsed     *time.Time
	Events90d    int
	ActiveDays90 int
}

// DaysSince is whole days since last use (nil if never used).
func (s Stat) DaysSince(now time.Time) *int {
	if s.LastUsed == nil {
		return nil
	}
	d := timeutil.Days(now, *s.LastUsed)
	return &d
}

type pair struct{ identity, perm int64 }

// Index answers usage questions for one point in time.
type Index struct {
	Now        time.Time
	stats      map[pair]Stat
	ByIdentity map[int64]time.Time
}

// Get returns the stat for identity/permission (zero value if never used).
func (u *Index) Get(identityID, permID int64) Stat { return u.stats[pair{identityID, permID}] }

// Unused reports whether the permission went unused for at least days.
func (u *Index) Unused(identityID, permID int64, days int) bool {
	st := u.Get(identityID, permID)
	return st.LastUsed == nil || timeutil.Days(u.Now, *st.LastUsed) >= days
}

// Description is the API rendering of a Stat.
type Description struct {
	LastUsed      *string `json:"last_used"`
	DaysSinceUsed *int    `json:"days_since_used"`
	Events90d     int     `json:"events_90d"`
	ActiveDays90d int     `json:"active_days_90d"`
}

// Describe renders the usage of a permission by an identity.
func (u *Index) Describe(identityID, permID int64) Description {
	st := u.Get(identityID, permID)
	return Description{timeutil.ISOPtr(st.LastUsed), st.DaysSince(u.Now), st.Events90d, st.ActiveDays90}
}

// Build loads the 90-day usage index as of now.
func Build(c *store.Conn, now time.Time) (*Index, error) {
	since := now.Add(-90 * 24 * time.Hour)
	rows, err := c.Query(`SELECT identity_id, permission_id, max(day), sum(count), count(id) FROM usage_events
		WHERE day >= ? GROUP BY identity_id, permission_id`, store.T(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	u := &Index{Now: now, stats: map[pair]Stat{}, ByIdentity: map[int64]time.Time{}}
	for rows.Next() {
		var iid, pid int64
		var last sql.NullString
		var total, days sql.NullInt64
		if err := rows.Scan(&iid, &pid, &last, &total, &days); err != nil {
			return nil, err
		}
		st := Stat{Events90d: int(total.Int64), ActiveDays90: int(days.Int64)}
		if last.Valid {
			t, err := timeutil.ParseDB(last.String)
			if err != nil {
				return nil, err
			}
			st.LastUsed = &t
			if cur, ok := u.ByIdentity[iid]; !ok || t.After(cur) {
				u.ByIdentity[iid] = t
			}
		}
		u.stats[pair{iid, pid}] = st
	}
	return u, rows.Err()
}
