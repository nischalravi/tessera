package admin

import (
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/retention"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeRetentionUpdate changes how many days each data class stays online
// before it is archived (issue #298, internal/retention). The payload names
// only the classes that change. Two people and a step-up on both sides, like
// every change of the tenant's own compliance posture: the requester
// proposes, a different admin approves what the payload hash says. There is no
// cooling-off: shortening a retention only moves records to the archive
// sooner (nothing is lost), and a longer one keeps them online longer.
const TypeRetentionUpdate = "retention.update"

type retentionPayload struct {
	AuditDays     *int `json:"audit_days,omitempty"`
	CampaignsDays *int `json:"review_campaigns_days,omitempty"`
	RequestsDays  *int `json:"requests_days,omitempty"`
	JobRunsDays   *int `json:"job_runs_days,omitempty"`
	OutboxDays    *int `json:"notifications_days,omitempty"`
}

// each lists the classes the payload sets, in the order of retention.Classes.
func (v *retentionPayload) each() []struct {
	class string
	days  int
} {
	var out []struct {
		class string
		days  int
	}
	for _, c := range []struct {
		class string
		days  *int
	}{{store.ClassAudit, v.AuditDays}, {store.ClassCampaigns, v.CampaignsDays}, {store.ClassRequests, v.RequestsDays},
		{store.ClassJobRuns, v.JobRunsDays}, {store.ClassOutbox, v.OutboxDays}} {
		if c.days != nil {
			out = append(out, struct {
				class string
				days  int
			}{c.class, *c.days})
		}
	}
	return out
}

func init() {
	changeTypes[TypeRetentionUpdate] = typed(TypeRetentionUpdate, nil, planRetention, applyRetention,
		func(_ *env, v *retentionPayload) string {
			var parts []string
			for _, c := range v.each() {
				parts = append(parts, fmt.Sprintf("%s %d days", c.class, c.days))
			}
			return "Change log retention (" + strings.Join(parts, ", ") + ")"
		})
}

// planRetention refuses a payload that sets nothing, a class below its floor
// or above its ceiling, or a value the class already has. Always two people.
func planRetention(e *env, v *retentionPayload) (plan, error) {
	set := v.each()
	if len(set) == 0 {
		return plan{}, invalid("name at least one class: audit_days, review_campaigns_days, requests_days, job_runs_days or notifications_days")
	}
	cur, err := retention.Effective(e.tx)
	if err != nil {
		return plan{}, err
	}
	have := map[string]int{}
	for _, s := range cur {
		have[s.Name] = s.Days
	}
	for _, c := range set {
		if err := retention.Check(c.class, c.days); err != nil {
			return plan{}, invalid("%v", err)
		}
		if have[c.class] == c.days {
			return plan{}, invalid("%s is already %d days", c.class, c.days)
		}
	}
	return plan{twoPerson: true, target: "retention"}, nil
}

func applyRetention(e *env, ch *store.AdminChange, v *retentionPayload) error {
	if _, err := planRetention(e, v); err != nil {
		return err
	}
	cur, err := retention.Effective(e.tx)
	if err != nil {
		return err
	}
	have := map[string]int{}
	for _, s := range cur {
		have[s.Name] = s.Days
	}
	detail := ojson.Object{{Key: "change_id", Value: ch.ID.String()}, {Key: "requested_by", Value: ch.RequestedBy.String()}}
	if ch.ApprovedBy != nil {
		detail = append(detail, ojson.KV{Key: "approved_by", Value: ch.ApprovedBy.String()})
	}
	for _, c := range v.each() {
		if err := e.tx.SetRetentionPolicy(c.class, c.days, e.now, ch.ID.String()); err != nil {
			return err
		}
		detail = append(detail, ojson.KV{Key: c.class, Value: ojson.Object{{Key: "from_days", Value: have[c.class]}, {Key: "to_days", Value: c.days}}})
	}
	// in the transaction that applies the change, next to admin.change.applied
	_, err = audit.Record(e.tx.Context(), e.tx, "retention.updated", detail, audit.At(e.now),
		audit.Target("admin_change", ch.ID.String()))
	return err
}
