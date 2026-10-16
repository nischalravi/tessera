package reviews

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/usage"
)

// Group-membership campaigns (issue #57, GR-14; design
// docs/design/groups-grouper-parity.md §10.4). Attestation of a native group is
// a campaign of this engine, so it shares its items, decisions and audit; unlike
// the exception-only campaign of GenerateCampaign, every member of the group is
// an item (attestation asks the owners to vouch for all of them), and each
// carries the usage context of what the identity can do.

// GroupMember is one identity of a group's frozen population.
type GroupMember struct {
	Identity int64
	How      string // direct | nested
	// Membership says how the identity came to be a member (source, reason,
	// dates, the groups it is nested through); it is shown to the reviewer.
	Membership ojson.Object
}

// GroupCampaign is what GenerateGroupCampaign made.
type GroupCampaign struct {
	ID    int64
	Items map[int64]int64 // identity id -> review item id
}

// groupRef is how a group is named in an item's edge columns: the same text on
// every item of the campaign, and not a node of the grant graph, so a decision
// on the item revokes no grant edge. The prefix is not "group": the review item
// guard trigger reads that prefix as the id of a connected-system group.
func groupRef(id string) string { return "native-group:" + id }

// GenerateGroupCampaign creates a review campaign with one item per member.
// unusedDays is the idle threshold of the usage context. Members must be
// distinct identities of the transaction's tenant.
func GenerateGroupCampaign(c *store.TenantTx, now time.Time, name string, unusedDays int, groupID, groupName string, members []GroupMember) (*GroupCampaign, error) {
	if unusedDays < 1 {
		unusedDays = 90
	}
	g, err := graph.Build(c, now)
	if err != nil {
		return nil, err
	}
	u, err := usage.Build(c, now)
	if err != nil {
		return nil, err
	}
	people, _, err := c.IdentityMap()
	if err != nil {
		return nil, err
	}
	campID, err := c.InsertCampaign(&store.ReviewCampaign{Name: name, CreatedAt: now, Status: "open", UnusedDays: unusedDays})
	if err != nil {
		return nil, err
	}
	// peer coverage: how many active people of the department are in the group
	deptSize, deptIn := map[string]int{}, map[string]int{}
	for _, p := range people {
		if p.Type == "human" && p.Status == "active" {
			deptSize[deref(p.Department)]++
		}
	}
	for _, m := range members {
		if p := people[m.Identity]; p != nil && p.Type == "human" && p.Status == "active" {
			deptIn[deref(p.Department)]++
		}
	}
	for _, m := range members {
		ident := people[m.Identity]
		if ident == nil {
			return nil, fmt.Errorf("reviews: group campaign: identity %d is not in the tenant", m.Identity)
		}
		eff := g.EffectivePermissions(m.Identity)
		var last *time.Time
		usedN, events, perms := 0, 0, 0
		privileged := false
		if eff != nil {
			for _, ep := range eff.Values() {
				perms++
				s := u.Get(m.Identity, ep.PermID)
				events += s.Events90d
				privileged = privileged || ep.Privileged
				if s.LastUsed != nil {
					if timeutil.Days(now, *s.LastUsed) < unusedDays {
						usedN++
					}
					if last == nil || s.LastUsed.After(*last) {
						last = s.LastUsed
					}
				}
			}
		}
		reasons := []string{}
		if perms > 0 && usedN == 0 {
			reasons = append(reasons, fmt.Sprintf("unused_%dd", unusedDays))
		}
		if privileged && (last == nil || timeutil.Days(now, *last) >= 30) {
			reasons = append(reasons, "privileged_idle")
		}
		if ident.Status != "active" {
			reasons = append(reasons, "inactive_identity")
		}
		var daysSince any
		if last != nil {
			daysSince = timeutil.Days(now, *last)
		}
		var coverage any
		if n := deptSize[deref(ident.Department)]; ident.Type == "human" && n > 0 {
			coverage = ojson.Float(timeutil.Round(float64(deptIn[deref(ident.Department)])/float64(n), 2))
		}
		ctx := ojson.Object{
			// what the identity can do, and how much of it it has used: the groups of this
			// campaign do not grant downstream entitlements yet (provisioning is GR-11), so
			// the usage is the identity's as a whole
			{Key: "usage_scope", Value: "identity"},
			{Key: "permissions", Value: perms},
			{Key: "permissions_used", Value: usedN},
			{Key: "last_used", Value: timeutil.ISOPtr(last)},
			{Key: "days_since_used", Value: daysSince},
			{Key: "events_90d", Value: events},
			{Key: "privileged", Value: privileged},
			{Key: "peer_coverage", Value: coverage},
			{Key: "how", Value: m.How},
			{Key: "membership", Value: m.Membership},
		}
		ctxJSON, err := store.JSON(ctx)
		if err != nil {
			return nil, err
		}
		if err := c.InsertReviewItem(&store.ReviewItem{CampaignID: campID, IdentityID: m.Identity, EdgeSrc: groupRef(groupID),
			EdgeDst: fmt.Sprintf("identity:%d", m.Identity), GrantLabel: ident.Name + " in " + groupName, Reasons: reasons,
			Context: json.RawMessage(ctxJSON)}); err != nil {
			return nil, err
		}
	}
	if err := c.SetCampaignTotals(campID, len(members), 0); err != nil {
		return nil, err
	}
	items, err := c.CampaignItems(campID)
	if err != nil {
		return nil, err
	}
	out := &GroupCampaign{ID: campID, Items: make(map[int64]int64, len(items))}
	for _, it := range items {
		out.Items[it.IdentityID] = it.ID
	}
	if len(out.Items) != len(members) {
		return nil, errors.New("reviews: group campaign: a member appears twice")
	}
	if len(members) == 0 {
		// nothing to decide: the campaign is complete as it starts
		if err := c.CompleteCampaign(campID); err != nil {
			return nil, err
		}
	}
	return out, c.Audit(now, "system", "review.campaign_created", ojson.Object{{Key: "campaign", Value: name},
		{Key: "items", Value: len(members)}, {Key: "total", Value: len(members)}})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
