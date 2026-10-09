package reconcile

import (
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
)

// Prepare returns a copy of a discovery result whose accounts all carry the
// template's mapped attributes and whose stats cover the template's required
// and recommended attributes. Connectors that already map attributes (the
// simulated AD) keep theirs; the existing demo connectors get the canonical
// mapping of their template. Values are only ever used to compute counts and
// correlation keys; findings keep ids and names.
func Prepare(templateID string, res *connectors.DiscoveryResult, attrs []string) *connectors.DiscoveryResult {
	out := *res
	out.Accounts = make([]connectors.AccountRecord, len(res.Accounts))
	for i, a := range res.Accounts {
		if a.Attributes == nil {
			a.Attributes = canonical(templateID, a)
		}
		out.Accounts[i] = a
	}
	if res.Stats != nil { // deep copy: the connector may cache its result
		st := &connectors.DiscoveryStats{Classes: map[string]*connectors.ClassStats{}}
		for k, cs := range res.Stats.Classes {
			c := &connectors.ClassStats{Total: cs.Total, Attributes: map[string]connectors.AttrStat{}}
			for a, v := range cs.Attributes {
				c.Attributes[a] = v
			}
			st.Classes[k] = c
		}
		out.Stats = st
	}
	if out.Stats == nil {
		out.Stats = connectors.StatsFromAccounts(out.Accounts, func(a *connectors.AccountRecord) string {
			if a.Kind == "" || a.Kind == "user" {
				return "user"
			}
			return "service"
		})
		if len(res.Identities) > 0 {
			out.Stats.Classes["worker"] = workerStats(res.Identities)
		}
	}
	for _, cs := range out.Stats.Classes {
		for _, attr := range attrs {
			if _, ok := cs.Attributes[attr]; !ok {
				cs.Attributes[attr] = connectors.AttrStat{}
			}
		}
	}
	return &out
}

func ts(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// canonical maps a normalized account record to the template's attribute names.
func canonical(templateID string, a connectors.AccountRecord) map[string]string {
	m := map[string]string{}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	hrID := ""
	if a.Identity != nil && (a.Kind == "" || a.Kind == "user") {
		hrID = a.Identity.ExternalID
	} else if a.Identity != nil {
		set("owner_ref", a.Identity.ExternalID) // the non-human identity, whose owner is known live
	}
	email := ""
	if strings.Contains(a.Username, "@") {
		email = a.Username
	}
	switch templateID {
	case "okta":
		set("id", a.ExternalID)
		set("login", a.Username)
		status := map[string]string{"active": "ACTIVE", "disabled": "DEPROVISIONED", "suspended": "SUSPENDED"}[a.Status]
		set("status", status)
		set("created", ts(a.CreatedAt))
		set("email", email)
		set("employeeNumber", hrID)
		set("lastLogin", ts(a.LastLoginAt))
	case "workday":
		set("worker_id", a.ExternalID)
		set("status", a.Status)
	default:
		set("id", a.ExternalID)
		set("userName", a.Username)
		set("active", a.Status)
		set("employeeNumber", hrID)
		set("email", email)
	}
	return m
}

func workerStats(ids []connectors.IdentityRecord) *connectors.ClassStats {
	cs := &connectors.ClassStats{Attributes: map[string]connectors.AttrStat{}}
	inc := func(k string, ok bool) {
		s := cs.Attributes[k]
		if ok {
			s.Present++
			s.Distinct++
		}
		cs.Attributes[k] = s
	}
	for _, x := range ids {
		if x.Type != "human" {
			continue
		}
		cs.Total++
		inc("worker_id", x.ExternalID != "")
		inc("worker_type", false) // the demo HR feed does not carry worker type
		inc("legal_name", x.Name != "")
		inc("status", x.Status != "")
		inc("hire_date", x.HiredAt != nil)
		inc("termination_date", x.TerminatedAt != nil)
		inc("manager", x.Manager != nil)
		inc("supervisory_org", x.Department != nil)
		inc("cost_center", false)
		inc("location", false)
		inc("work_email", x.Email != nil)
	}
	return cs
}
