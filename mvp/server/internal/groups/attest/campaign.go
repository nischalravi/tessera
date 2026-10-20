package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/gov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/inbox"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Defaults of a campaign started without settings (a manual start, a micro-certification).
const (
	DefaultWindowDays = 30
	DefaultMicroDays  = 14
	// unusedDays is the idle threshold of the usage context shown to reviewers.
	unusedDays = 90
)

// StartInput says what to start. The zero value is a periodic campaign with
// the settings that apply to the group.
type StartInput struct {
	Kind string // periodic (default) | micro
	// Identity is the one member a micro-certification is about.
	Identity int64
	// WindowDays overrides the due date of a micro-certification (default 14).
	WindowDays int
	RuleID     string
}

func (e Env) eng() *engine.Engine {
	if e.Engine != nil {
		return e.Engine
	}
	return engine.New(0)
}

// hashPopulation is the SHA-256 of the sorted "identity:how" lines.
func hashPopulation(members []reviews.GroupMember) string {
	h := sha256.New()
	for _, m := range members {
		fmt.Fprintf(h, "%d:%s\n", m.Identity, m.How)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// membership describes how an identity came to be a member of the group.
func (e Env) membership(g *store.NativeGroup, identity int64) (how string, detail ojson.Object, err error) {
	list := store.MembersListID(e.Tx.Tenant())
	active, err := e.Tx.GrpDirectIdentityActive(g.ID, list, identity, e.Now)
	if err != nil {
		return "", nil, err
	}
	if active {
		m, err := e.Tx.GrpDirectFind(g.ID, list, store.MemberIdentity, strconv.FormatInt(identity, 10))
		if err != nil {
			return "", nil, err
		}
		d := ojson.Object{{Key: "source", Value: m.Source}, {Key: "granted_at", Value: m.CreatedAt.UTC().Format(time.RFC3339)}}
		if m.SourceRef != nil {
			d = append(d, ojson.KV{Key: "source_ref", Value: *m.SourceRef})
		}
		if m.Reason != nil && *m.Reason != "" {
			d = append(d, ojson.KV{Key: "reason", Value: *m.Reason})
		}
		if m.DisabledAt != nil {
			d = append(d, ojson.KV{Key: "disabled_at", Value: m.DisabledAt.UTC().Format(time.RFC3339)})
		}
		return "direct", d, nil
	}
	// nested: name the groups it comes through
	var via []store.GroupID
	if g.Definition == store.DefinitionBasic {
		via, err = e.Tx.GrpDirectActiveChildren(g.ID, list, e.Now)
	} else {
		via, err = e.Tx.GrpFactors(g.ID)
	}
	if err != nil {
		return "", nil, err
	}
	names := []string{}
	for _, id := range via {
		if len(names) == 10 {
			break
		}
		if g.Definition == store.DefinitionBasic {
			if s, err := e.Tx.GrpEffectiveSupport(id, list, identity); err != nil {
				return "", nil, err
			} else if s == 0 {
				continue
			}
		}
		c, err := e.Tx.GrpGroup(id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		names = append(names, c.Name)
	}
	return "nested", ojson.Object{{Key: "source", Value: "nested"}, {Key: "via", Value: names}}, nil
}

// population freezes the group's members: every identity the engine counts as a
// member now, never a truncated list (a group over MaxPopulation is refused).
func (e Env) population(g *store.NativeGroup) ([]reviews.GroupMember, error) {
	list := store.MembersListID(e.Tx.Tenant())
	tooBig := gov.Conflict("population_too_large", "group %q has more than %d members: attest it through its subgroups", g.Name, MaxPopulation)
	var ids []int64
	for off := 0; ; off += 1000 {
		rows, err := e.Tx.GrpEffectiveList(g.ID, list, 1000, off)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			ids = append(ids, r.Identity)
		}
		if len(ids) > MaxPopulation {
			return nil, tooBig
		}
		if len(rows) < 1000 {
			break
		}
	}
	if n, err := e.Tx.GrpEffectiveCount(g.ID, list); err != nil {
		return nil, err
	} else if n != len(ids) {
		return nil, gov.Conflict("population_incomplete", "group %q is being recomputed: try again when it is clean", g.Name)
	}
	slices.Sort(ids)
	out := make([]reviews.GroupMember, 0, len(ids))
	for _, id := range ids {
		how, detail, err := e.membership(g, id)
		if err != nil {
			return nil, err
		}
		out = append(out, reviews.GroupMember{Identity: id, How: how, Membership: detail})
	}
	return out, nil
}

// emit writes an attestation event in the caller's transaction.
func (e Env) emit(typ string, c *store.GrpAttestCampaign, data map[string]any) error {
	ev := events.New(typ, c.ID, e.Now, e.cause())
	ev.CauseRef = e.CauseRef
	data["group"], data["campaign"], data["kind"] = string(c.GroupID), c.ID, c.Kind
	ev.Data = events.Data(data)
	return pit.Emit(e.Tx, ev)
}

func (e Env) audit(action string, c *store.GrpAttestCampaign, extra ...ojson.KV) error {
	d := ojson.Object{{Key: "campaign_id", Value: c.ID}, {Key: "group_id", Value: string(c.GroupID)}, {Key: "kind", Value: c.Kind},
		{Key: "status", Value: c.Status}}
	d = append(d, extra...)
	_, err := e.Tx.RecordAudit(store.AuditRecord{At: e.Now, Action: action, LegacyActor: "groups", TargetType: "attestation",
		TargetID: c.ID, Detail: d})
	return err
}

// taskDetail is what an Inbox task of a campaign carries.
type taskDetail struct {
	Campaign string `json:"campaign"`
	Group    string `json:"group"`
	Members  int    `json:"members"`
}

// openTasks asks the reviewers, in the Inbox, to attest.
func (e Env) openTasks(g *store.NativeGroup, c *store.GrpAttestCampaign, subject *int64) error {
	kind, title := store.TaskAttestation, "Attest the members of "+g.Name
	if c.Kind == store.AttestMicro {
		kind, title = store.TaskMicroCertification, "Certify a membership of "+g.Name
	}
	in := inbox.Input{Kind: kind, Title: title, Detail: taskDetail{Campaign: c.ID, Group: string(g.ID), Members: c.PopulationCount},
		ObjectType: store.RuleOwnerGroup, ObjectID: string(g.ID), Subject: subject, DueAt: &c.DueAt, DedupeKey: "attest:" + c.ID}
	if c.ReviewerType != store.ReviewersGroup || c.ReviewerGroup == nil {
		_, _, err := inbox.Open(e.Tx, e.Now, in)
		return err
	}
	list := store.MembersListID(e.Tx.Tenant())
	rows, err := e.Tx.GrpEffectiveList(*c.ReviewerGroup, list, MaxReviewerTasks, 0)
	if err != nil {
		return err
	}
	for _, r := range rows {
		who := r.Identity
		in.Assignee, in.DedupeKey = &who, fmt.Sprintf("attest:%s:%d", c.ID, who)
		if _, _, err := inbox.Open(e.Tx, e.Now, in); err != nil {
			return err
		}
	}
	return nil
}

// closeTasks closes the open Inbox tasks of a campaign.
func (e Env) closeTasks(c *store.GrpAttestCampaign, status string) error {
	tasks, err := e.Tx.GrpTasks(store.GrpTaskFilter{Status: store.TaskOpen, ObjectType: store.RuleOwnerGroup, ObjectID: string(c.GroupID)})
	if err != nil {
		return err
	}
	for _, t := range tasks {
		var d taskDetail
		if json.Unmarshal([]byte(t.Detail), &d) != nil || d.Campaign != c.ID {
			continue
		}
		if err := inbox.CloseSystem(e.Tx, e.Now, t.ID, status, e.By); err != nil {
			return err
		}
	}
	return nil
}

// Start freezes the group's population and opens a campaign for it. For a
// periodic campaign the group's applicable settings apply (defaults when it has
// none); a second open periodic campaign is a 409. Starting a
// micro-certification of an identity that already has an open one returns that
// campaign (created is false).
func Start(e Env, groupID store.GroupID, in StartInput) (c *store.GrpAttestCampaign, created bool, err error) {
	if in.Kind == "" {
		in.Kind = store.AttestPeriodic
	}
	if in.Kind != store.AttestPeriodic && in.Kind != store.AttestMicro {
		return nil, false, gov.Invalid("invalid_kind", "kind is periodic or micro")
	}
	g, err := e.Tx.GrpGroup(groupID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, gov.NotFound("no such group")
	}
	if err != nil {
		return nil, false, err
	}
	if g.Status != store.GroupActive {
		return nil, false, gov.Conflict("group_not_active", "group %q is %s: only an active group is attested", g.Name, g.Status)
	}
	// what the campaign is started with, frozen into it
	c = &store.GrpAttestCampaign{ID: uuid.NewString(), GroupID: g.ID, Kind: in.Kind, StartedAt: e.Now, OverdueAction: store.OverdueNone,
		ReviewerType: store.ReviewersAdmins, ReminderDays: "[]", ActsAs: e.By}
	if e.By != "" {
		by := e.By
		c.StartedBy = &by
	}
	window := DefaultWindowDays
	if in.Kind == store.AttestMicro {
		window = DefaultMicroDays
		if in.WindowDays > 0 {
			window = in.WindowDays
		}
		if in.RuleID != "" {
			c.RuleID = &in.RuleID
		}
	} else if s, _, ok, err := effective(e.Tx, store.RuleOwnerGroup, string(g.ID)); err != nil {
		return nil, false, err
	} else if ok {
		window, c.OverdueAction, c.ReviewerType, c.ReviewerGroup, c.ReminderDays = s.WindowDays, s.OverdueAction, s.ReviewerType,
			s.ReviewerGroup, s.ReminderDays
		c.ActsAs = s.UpdatedBy
	}
	if c.ActsAs == "" {
		return nil, false, gov.Forbidden("attestation_needs_user", "an attestation acts with the authority of a user: start it as one, or save settings first")
	}
	if window < 1 || window > MaxWindow {
		return nil, false, gov.Invalid("invalid_window", "window_days is 1 to %d", MaxWindow)
	}
	c.DueAt = e.Now.AddDate(0, 0, window)

	var members []reviews.GroupMember
	var subject *int64
	open, err := e.Tx.GrpAttestCampaigns(store.GrpAttestFilter{Group: g.ID, Status: store.AttestOpen, Limit: 1000})
	if err != nil {
		return nil, false, err
	}
	switch in.Kind {
	case store.AttestPeriodic:
		for _, o := range open {
			if o.Kind == store.AttestPeriodic {
				return nil, false, &gov.Error{Kind: gov.KindConflict, Code: "attestation_open",
					Msg: fmt.Sprintf("group %q already has an open attestation", g.Name), Extra: map[string]any{"campaign": o.ID}}
			}
		}
		if members, err = e.population(g); err != nil {
			return nil, false, err
		}
	case store.AttestMicro:
		if in.Identity < 1 {
			return nil, false, gov.Invalid("invalid_identity", "a micro-certification is about one identity")
		}
		for _, o := range open {
			if o.Kind != store.AttestMicro {
				continue
			}
			items, err := e.Tx.GrpAttestItems(o.ID)
			if err != nil {
				return nil, false, err
			}
			if len(items) == 1 && items[0].Identity == in.Identity {
				return o, false, nil
			}
		}
		is, err := e.eng().IsMember(e.Tx, e.Now, g.ID, store.MembersListID(e.Tx.Tenant()), in.Identity)
		if err != nil {
			return nil, false, err
		}
		if !is {
			return nil, false, gov.Conflict("not_a_member", "the identity is not a member of %q", g.Name)
		}
		how, detail, err := e.membership(g, in.Identity)
		if err != nil {
			return nil, false, err
		}
		members = []reviews.GroupMember{{Identity: in.Identity, How: how, Membership: detail}}
		subject = &in.Identity
	}
	c.PopulationCount, c.PopulationHash = len(members), hashPopulation(members)

	name := fmt.Sprintf("Attestation of %s (%s)", g.Name, e.Now.UTC().Format("2006-01-02"))
	if in.Kind == store.AttestMicro {
		name = fmt.Sprintf("Micro-certification of %s (%s)", g.Name, e.Now.UTC().Format("2006-01-02"))
	}
	rc, err := reviews.GenerateGroupCampaign(e.Tx, e.Now, name, unusedDays, string(g.ID), g.Name, members)
	if err != nil {
		return nil, false, err
	}
	c.ReviewCampaign = &rc.ID
	if err := e.Tx.InsertGrpAttestCampaign(c); err != nil {
		return nil, false, err
	}
	for _, m := range members {
		rid := rc.Items[m.Identity]
		if err := e.Tx.InsertGrpAttestItem(&store.GrpAttestItem{CampaignID: c.ID, GroupID: g.ID, Identity: m.Identity, How: m.How,
			ReviewItem: &rid}); err != nil {
			return nil, false, err
		}
	}
	if err := e.emit(events.AttestationDue, c, map[string]any{"due_at": c.DueAt.UTC().Format(time.RFC3339), "population": c.PopulationCount,
		"population_hash": c.PopulationHash}); err != nil {
		return nil, false, err
	}
	if err := e.audit("groups.attestation.started", c, ojson.KV{Key: "population", Value: c.PopulationCount},
		ojson.KV{Key: "population_hash", Value: c.PopulationHash}, ojson.KV{Key: "due_at", Value: c.DueAt.UTC().Format(time.RFC3339)}); err != nil {
		return nil, false, err
	}
	if len(members) == 0 {
		// nothing to attest: the campaign is complete as it starts
		return c, true, e.complete(c, store.AttestCompleted, map[string]any{"empty": true})
	}
	return c, true, e.openTasks(g, c, subject)
}

// complete closes a campaign with a status, writes its event and closes its Inbox tasks.
func (e Env) complete(c *store.GrpAttestCampaign, status string, data map[string]any) error {
	c.Status, c.ClosedAt = status, &e.Now
	if err := e.Tx.SaveGrpAttestCampaign(c); err != nil {
		return err
	}
	data["status"] = status
	if err := e.emit(events.AttestationCompleted, c, data); err != nil {
		return err
	}
	if err := e.audit("groups.attestation.completed", c); err != nil {
		return err
	}
	return e.closeTasks(c, store.TaskDone)
}

// Verify recomputes the count and hash of a campaign's stored items and says
// whether they still match what was frozen when it started: the proof that the
// population is complete and was not edited afterwards.
func Verify(tx *store.TenantTx, campaignID string) (bool, error) {
	c, err := tx.GrpAttestCampaign(campaignID)
	if errors.Is(err, store.ErrNotFound) {
		return false, gov.NotFound("no such attestation")
	}
	if err != nil {
		return false, err
	}
	items, err := tx.GrpAttestItems(c.ID) // ordered by identity id
	if err != nil {
		return false, err
	}
	members := make([]reviews.GroupMember, len(items))
	for i, it := range items {
		members[i] = reviews.GroupMember{Identity: it.Identity, How: it.How}
	}
	return len(items) == c.PopulationCount && hashPopulation(members) == c.PopulationHash, nil
}
