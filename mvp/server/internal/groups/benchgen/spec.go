// Package benchgen builds a synthetic "large university" tenant for the groups
// scale gate (design docs/design/groups-grouper-parity.md section 6.7, GR-17)
// and measures the section 6.7 targets against it.
//
// The generator loads a tenant of the reference shape at a percentage of its
// size (Spec.Percent: 100 is the reference tenant). It writes through the
// store and the membership engine, never around the tenant scope, in bounded
// transactions. Measure runs the operations of the table in section 6.7 and
// returns one Result per target; a failed target is reported, never relaxed.
//
// It is used by cmd/tessera-bench (`tessera-bench groups`), by the REST gate in
// internal/api and by a small smoke test that keeps the harness working.
package benchgen

import (
	"fmt"
	"time"
)

// Spec says how big the tenant is and how thoroughly it is measured.
type Spec struct {
	// Percent of the reference tenant: 100 is 150,000 groups, 25,000 folders,
	// 600,000 identities and 3,000,000 direct memberships. SQLite numbers of
	// the design apply to 10 and below; Postgres is the 100 target.
	Percent float64
	// Seed makes the shape (not the timings) repeatable.
	Seed int64
	// Samples is the number of latency samples per operation (default 500).
	Samples int
	// Loader is the number of membership changes in the loader run (default
	// 50,000, the figure of the design; it is not scaled with the tenant).
	Loader int
	// DBPath is the SQLite file, when the caller knows it: Generate then measures
	// how much it grows while the effective memberships are materialized (the
	// storage target is about grp_effective and its index).
	DBPath string
	// Now is the clock of every operation (nil: the wall clock).
	Now func() time.Time
	// Log receives progress lines (nil: silent).
	Log func(format string, args ...any)
}

func (s *Spec) defaults() {
	if s.Percent <= 0 {
		s.Percent = 10
	}
	if s.Seed == 0 {
		s.Seed = 1
	}
	if s.Samples <= 0 {
		s.Samples = 500
	}
	if s.Loader <= 0 {
		s.Loader = 50000
	}
}

func (s Spec) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(format, args...)
	}
}

// Counts are the sizes of the generated tenant.
type Counts struct {
	Groups     int // basic groups in the four nesting levels
	Folders    int
	Identities int
	Direct     int // direct identity rows of the leaf groups
	Ref        int // members of the reference group (ref:student:enrolled)
	Policy     int // policy groups that use the group the reference is nested into
	Browse     int // children of the folder the browser test lists
	Roster     int // course roster groups of one term (design question 9)
}

// floor keeps a tiny tenant (the smoke test) meaningful.
func scaled(full int, f float64, min int) int { return max(min, int(float64(full)*f)) }

// Counts returns the sizes for the spec.
func (s Spec) Counts() Counts {
	f := s.Percent / 100
	return Counts{
		Groups:     scaled(150000, f, 80),
		Folders:    scaled(25000, f, 8),
		Identities: scaled(600000, f, 300),
		Direct:     scaled(3000000, f, 400),
		Ref:        scaled(45000, f, 40),
		Policy:     scaled(400, f, 4),
		Browse:     scaled(5000, f, 50),
		Roster:     scaled(20000, f, 40),
	}
}

// Stats describes what was generated, as measured after the load.
type Stats struct {
	Counts    Counts
	Effective int64 // rows of grp_effective over the generated groups
	Built     time.Duration
}

func (st Stats) String() string {
	c := st.Counts
	return fmt.Sprintf("%d groups, %d folders, %d identities, %d direct rows, %d effective rows, ref group %d, %d policy groups, %d browse children; built in %s",
		c.Groups, c.Folders, c.Identities, c.Direct, st.Effective, c.Ref, c.Policy, c.Browse, st.Built.Round(time.Second))
}
