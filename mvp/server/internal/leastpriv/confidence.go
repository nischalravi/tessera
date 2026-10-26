package leastpriv

import (
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Confidence model for unused-access findings (issue #645, LP-2; design
// docs/design/differentiators-plan.md, "Provable least privilege").
//
// A recommendation says "this permission was not used in the window". How far
// that can be trusted depends on what was watched: whether the logs cover the
// whole window, whether the source records this kind of call at all, what could
// not be read, how old the identity is, and whether it runs jobs less often
// than the window is long. Assess turns those into one of four levels with the
// reasons. The model only ever lowers a level: each rule is a ceiling, and the
// answer is the lowest ceiling, so adding a gap or shrinking the coverage can
// never raise it.
//
// Levels: high (safe to act on), medium (review first), low (do not act on it),
// unknown (the sources cannot say: nothing was ingested, or the call is of a
// kind the source does not record). A permission that was used is not an
// unused finding; it is reported low with the reason "used".

// Confidence levels, from most to least trusted.
const (
	ConfHigh    = "high"
	ConfMedium  = "medium"
	ConfLow     = "low"
	ConfUnknown = "unknown"
)

// gapDigestPrefix marks the gap codes of CloudTrail digest validation (issue
// #680): logs missing from the digest chain or that failed validation. The
// store keeps the code as free text, so #680 needs no schema change. A code the
// model does not know lowers the level to medium rather than being ignored.
const gapDigestPrefix = "digest_"

// Thresholds of the rules, in days.
const (
	youngIdentityDays = 14 // an identity younger than this has too short a history to judge: low
	staleLogDays      = 2  // logs ending more than this many days before now leave the newest days unwatched
	minPeriodicWindow = 14 // below this window the quiet-stretch rule is not applied
)

// rank orders the levels, higher is more trusted. unknown is not on the scale.
func rank(level string) int {
	switch level {
	case ConfHigh:
		return 3
	case ConfMedium:
		return 2
	case ConfLow:
		return 1
	}
	return 0
}

// AWSEvidence is what was ingested for one connector: the state of each source
// and the gaps. It is the same for every principal of the connector.
type AWSEvidence struct {
	States []*store.AWSUsageState
	Gaps   []*store.AWSUsageGap
}

// PrincipalFacts are what is known of the principal.
type PrincipalFacts struct {
	ARN string
	// Created is when the identity was created; nil when not known (the AWS
	// snapshot does not carry it yet), which caps the level at medium.
	Created *time.Time
	// ActiveDays are the days (YYYY-MM-DD) with any usage row of the principal,
	// for any action: a dormant or bursty principal may run a job that is
	// longer than the window.
	ActiveDays []string
}

// Confidence is the answer for one permission.
type Confidence struct {
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
}

// dataEventPrefixes are the S3 calls CloudTrail logs only as data events. With
// data events off, "no log of GetObject" is not "no GetObject".
var dataEventPrefixes = []string{
	"GetObject", "PutObject", "DeleteObject", "RestoreObject", "AbortMultipartUpload",
	"ListMultipartUploadParts", "ReplicateObject", "ReplicateDelete", "ReplicateTags", "BypassGovernanceRetention",
}

// IsDataEventAction reports whether CloudTrail records the action only as a
// data event (S3 object-level actions). Matching is case-insensitive.
func IsDataEventAction(action string) bool {
	svc, name, ok := strings.Cut(action, ":")
	if !ok || !strings.EqualFold(svc, "s3") {
		return false
	}
	for _, p := range dataEventPrefixes {
		if len(name) >= len(p) && strings.EqualFold(name[:len(p)], p) {
			return true
		}
	}
	return false
}

func parseDay(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", s)
	return t, err == nil
}

func dayOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// Assess rates the claim "action was not used by the principal in the last
// unusedDays days, as of now". used says the action was in fact seen in the
// window. unusedDays below 1 is taken as 1.
func Assess(now time.Time, unusedDays int, action string, used bool, ev AWSEvidence, p PrincipalFacts) Confidence {
	if used {
		return Confidence{ConfLow, []string{"the permission was used in the window: not an unused finding"}}
	}
	if unusedDays < 1 {
		unusedDays = 1
	}
	today := dayOf(now)
	start := today.AddDate(0, 0, -(unusedDays - 1))
	dataEvent := IsDataEventAction(action)

	var ct *store.AWSUsageState
	for _, s := range ev.States {
		if s.Source == store.AWSUsageCloudTrail {
			ct = s
		}
	}
	// unknown: the source cannot say
	if ct == nil || ct.CoveredFrom == "" || ct.CoveredTo == "" {
		return Confidence{ConfUnknown, []string{"no CloudTrail usage has been ingested for this connector"}}
	}
	if dataEvent && ct.S3DataEvents != store.AWSDataEventsEnabled {
		why := "S3 data events are not logged on the trail"
		if ct.S3DataEvents == store.AWSDataEventsUnknown {
			why = "it is not known whether S3 data events are logged on the trail"
		}
		return Confidence{ConfUnknown, []string{why + ", so object-level calls are not in the logs"}}
	}
	from, okF := parseDay(ct.CoveredFrom)
	to, okT := parseDay(ct.CoveredTo)
	if !okF || !okT || to.Before(from) {
		return Confidence{ConfUnknown, []string{"the CloudTrail coverage dates are unreadable"}}
	}
	for _, g := range ev.Gaps {
		if dataEvent && g.Code == "data_events_unknown" {
			return Confidence{ConfUnknown, []string{"it is not known whether data events are logged: " + g.Code}}
		}
	}

	level := ConfHigh
	var reasons []string
	ceil := func(l, why string) {
		if rank(l) < rank(level) {
			level = l
		}
		reasons = append(reasons, why)
	}

	// window coverage: the days of the window the logs span
	lo, hi := maxTime(from, start), minTime(to, today)
	covered := 0
	if !hi.Before(lo) {
		covered = int(hi.Sub(lo).Hours()/24) + 1
	}
	switch {
	case covered*2 < unusedDays:
		ceil(ConfLow, fmt.Sprintf("the logs cover %d of the %d days of the window", covered, unusedDays))
	case covered < unusedDays:
		ceil(ConfMedium, fmt.Sprintf("the logs cover %d of the %d days of the window", covered, unusedDays))
	}
	if late := int(today.Sub(minTime(to, today)).Hours() / 24); late > staleLogDays {
		ceil(ConfMedium, fmt.Sprintf("the newest log day is %d days old", late))
	}

	// source completeness
	for _, g := range ev.Gaps {
		if why, l := gapEffect(g, p.ARN, start, today); why != "" {
			ceil(l, why)
		}
	}

	// identity age
	if p.Created == nil {
		ceil(ConfMedium, "the identity's creation date is not known")
	} else {
		age := int(today.Sub(dayOf(*p.Created)).Hours() / 24)
		switch {
		case age < youngIdentityDays:
			ceil(ConfLow, fmt.Sprintf("the identity is %d days old: too little history", age))
		case age < unusedDays:
			ceil(ConfMedium, fmt.Sprintf("the identity is %d days old, younger than the %d-day window", age, unusedDays))
		}
	}

	// periodic jobs
	if why := periodic(p.ActiveDays, start, today, unusedDays); why != "" {
		ceil(ConfMedium, why)
	}

	if len(reasons) == 0 {
		reasons = []string{fmt.Sprintf("complete logs for the %d-day window, no gaps, and an established identity", unusedDays)}
	}
	return Confidence{level, reasons}
}

// gapEffect says whether a gap touches the claim, and the ceiling it sets.
func gapEffect(g *store.AWSUsageGap, principal string, start, today time.Time) (string, string) {
	if g.Day != "" {
		if d, ok := parseDay(g.Day); ok && (d.Before(start) || d.After(today)) {
			return "", "" // a day outside the window
		}
	}
	switch {
	case strings.HasPrefix(g.Code, gapDigestPrefix):
		return fmt.Sprintf("CloudTrail logs are missing or not validated (%s)", g.Code), ConfLow
	case g.Code == "unmapped_actions", g.Code == "data_events_unknown":
		return "", "" // not about this permission (data events are handled above)
	case g.Source == store.AWSUsageAccessAdvisor:
		if g.Ref != principal {
			return "", ""
		}
		return fmt.Sprintf("Access Advisor could not read this principal (%s)", g.Code), ConfMedium
	}
	return fmt.Sprintf("part of the CloudTrail logs could not be ingested (%s)", g.Code), ConfMedium
}

// periodic returns why the principal's activity pattern leaves room for a job
// that runs less often than the window, or "".
func periodic(active []string, start, today time.Time, window int) string {
	days := map[time.Time]bool{}
	for _, s := range active {
		if d, ok := parseDay(s); ok && !d.Before(start) && !d.After(today) {
			days[d] = true
		}
	}
	if len(days) == 0 {
		return "the principal shows no activity at all in the window; it may run a job less often than that"
	}
	// the longest quiet stretch, counting both edges of the window
	prev, longest := start.AddDate(0, 0, -1), 0
	for d := start; !d.After(today.AddDate(0, 0, 1)); d = d.AddDate(0, 0, 1) {
		if days[d] || d.After(today) {
			if q := int(d.Sub(prev).Hours()/24) - 1; q > longest {
				longest = q
			}
			prev = d
		}
	}
	if window >= minPeriodicWindow && longest*2 > window {
		return fmt.Sprintf("the principal's activity is sparse (a %d-day quiet stretch in a %d-day window): a periodic job may fall outside it", longest, window)
	}
	return ""
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
