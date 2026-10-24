package reconcile

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Meta is what reconciliation needs to know about the connection.
type Meta struct {
	ConnectionID string
	System       string
	SystemName   string // display name of the system, e.g. "Okta"
	TemplateID   string
	Role         string // authoritative | account_source
	// Inventory: the source reports findings or records, not accounts; the
	// staged account data checks do not apply.
	Inventory        bool
	CorrelationKey   string
	HRAttribute      string
	HRItem           string // checklist item that maps the HR id
	RequiredAttrs    []string
	RecommendedAttrs []string
	Thresholds       map[string]float64
	ExpectedUsers    *int
	ExpectedGroups   *int
	Privileged       map[string][]string // privileged group name → expected members
	StaleDays        int
	Now              time.Time
}

// FindingRef is the part of a finding that data checks read.
type FindingRef struct {
	Code, Variant, Severity, Status string
	Count                           int
}

// Snapshot is a staged dry run: read-only input to findings and data checks.
type Snapshot struct {
	ID          string
	Meta        Meta
	Accounts    []*store.StagedAccount
	Groups      []*store.StagedGroup
	Memberships []store.StagedMembership
	Stats       []store.AttrStat
	Identities  []*store.StagedIdentity
	Findings    []FindingRef

	groupByXID map[string]*store.StagedGroup
	effective  map[string][]string // account xid → every group reached, nesting resolved
}

// RunID returns the dry run id.
func (s *Snapshot) RunID() string { return s.ID }

// LoadSnapshot reads a staged run.
func LoadSnapshot(c *store.TenantTx, runID string, meta Meta) (*Snapshot, error) {
	s := &Snapshot{ID: runID, Meta: meta}
	var err error
	if s.Accounts, err = c.StagedAccounts(runID); err != nil {
		return nil, err
	}
	if s.Groups, err = c.StagedGroups(runID); err != nil {
		return nil, err
	}
	if s.Memberships, err = c.StagedMemberships(runID); err != nil {
		return nil, err
	}
	if s.Stats, err = c.AttrStats(runID); err != nil {
		return nil, err
	}
	if s.Identities, err = c.StagedIdentities(runID); err != nil {
		return nil, err
	}
	fs, err := c.RunFindings(runID)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		s.Findings = append(s.Findings, FindingRef{Code: f.Code, Variant: f.Variant, Severity: f.Severity, Status: f.Status, Count: f.Count})
	}
	s.index()
	return s, nil
}

func (s *Snapshot) index() {
	s.groupByXID = map[string]*store.StagedGroup{}
	for _, g := range s.Groups {
		s.groupByXID[g.ExternalID] = g
	}
	parents := map[[2]string][]string{} // (kind, xid) → groups
	for _, m := range s.Memberships {
		k := [2]string{m.MemberKind, m.MemberXID}
		parents[k] = append(parents[k], m.GroupXID)
	}
	s.effective = map[string][]string{}
	for _, a := range s.Accounts {
		seen := map[string]bool{}
		queue := slices.Clone(parents[[2]string{"account", a.ExternalID}])
		for len(queue) > 0 { // breadth-first with cycle detection
			g := queue[0]
			queue = queue[1:]
			if seen[g] {
				continue
			}
			seen[g] = true
			queue = append(queue, parents[[2]string{"group", g}]...)
		}
		for g := range seen {
			s.effective[a.ExternalID] = append(s.effective[a.ExternalID], g)
		}
		slices.Sort(s.effective[a.ExternalID])
	}
}

// Group returns a staged group by external id.
func (s *Snapshot) Group(xid string) (*store.StagedGroup, bool) {
	g, ok := s.groupByXID[xid]
	return g, ok
}

// EffectiveGroups returns every group an account reaches (nesting resolved).
func (s *Snapshot) EffectiveGroups(accountXID string) []string { return s.effective[accountXID] }

// PrivilegedGroups returns the privileged groups an account reaches.
func (s *Snapshot) PrivilegedGroups(accountXID string) []*store.StagedGroup {
	var out []*store.StagedGroup
	for _, x := range s.effective[accountXID] {
		if g, ok := s.groupByXID[x]; ok && g.Privileged {
			out = append(out, g)
		}
	}
	return out
}

// Stat returns an attribute's fill count in a class.
func (s *Snapshot) Stat(class, attr string) (store.AttrStat, bool) {
	for _, st := range s.Stats {
		if st.Class == class && st.Attribute == attr {
			return st, true
		}
	}
	return store.AttrStat{}, false
}

// ClassTotal returns the number of objects of a class.
func (s *Snapshot) ClassTotal(class string) int {
	if st, ok := s.Stat(class, "*"); ok {
		return st.Total
	}
	return 0
}

// Classes lists the object classes with staged statistics.
func (s *Snapshot) Classes() []string {
	var out []string
	for _, st := range s.Stats {
		if !slices.Contains(out, st.Class) {
			out = append(out, st.Class)
		}
	}
	return out
}

// IsService reports whether an account is a non-human account.
func IsService(a *store.StagedAccount) bool { return a.Kind != "" && a.Kind != "user" }

// Expired reports whether an account's expiry (AD accountExpires as a
// FILETIME, or LDAP shadowExpire in days) is in the past.
func Expired(a *store.StagedAccount, now time.Time) bool {
	if v := a.Attributes["accountExpires"]; v != "" && v != "0" && v != "9223372036854775807" {
		if ft, err := strconv.ParseInt(v, 10, 64); err == nil {
			unix := ft/10_000_000 - 11644473600
			return time.Unix(unix, 0).Before(now)
		}
	}
	if v := a.Attributes["shadowExpire"]; v != "" && v != "-1" {
		if d, err := strconv.Atoi(v); err == nil {
			return time.Unix(int64(d)*86400, 0).Before(now)
		}
	}
	return false
}

// Enabled reports whether an account is active and not expired.
func Enabled(a *store.StagedAccount, now time.Time) bool {
	return strings.EqualFold(a.Status, "active") && !Expired(a, now)
}

// FindingStatus returns the status of a finding code in this run, if any.
func (s *Snapshot) FindingStatus(code string) []FindingRef {
	var out []FindingRef
	for _, f := range s.Findings {
		if f.Code == code {
			out = append(out, f)
		}
	}
	return out
}
