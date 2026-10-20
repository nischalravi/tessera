package sod

import (
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Actor is who made a change.
type Actor struct {
	UserID  uuid.UUID
	Display string
}

func (a Actor) uid() *string {
	if a.UserID == uuid.Nil {
		return nil
	}
	s := a.UserID.String()
	return &s
}

// Writer makes versioned, audited changes in one tenant transaction. Quiet
// skips the audit events (seeding describes data that was already there).
type Writer struct {
	Tx    *store.TenantTx
	By    Actor
	Now   time.Time
	Quiet bool
	// OnActivate runs, in the same transaction, when a mitigation becomes
	// active. The API uses it to queue the job that re-opens the violation at
	// the end date.
	OnActivate func(m *store.SodMitigation) error

	batch bool
	dirty map[string]string // ruleset id -> note, touched once at the end of a batch
}

func (w *Writer) audit(action string, d ojson.Object) error {
	if w.Quiet {
		return nil
	}
	return w.Tx.Audit(w.Now, w.By.Display, action, d)
}

func (w *Writer) version(kind, id string, ver int, snap any, note string) error {
	var n *string
	if note != "" {
		n = &note
	}
	return w.Tx.AddSodVersion(&store.SodVersion{Kind: kind, ObjectID: id, Version: ver, Snapshot: mustJSON(snap), Note: n,
		ChangedBy: w.By.uid(), Actor: w.By.Display, ChangedAt: w.Now})
}

func (w *Writer) owner(id *int64) error {
	if id == nil {
		return nil
	}
	if _, err := w.Tx.Identity(*id); errors.Is(err, store.ErrNotFound) {
		return refuse(422, "owner_not_found", "the owner is not a known identity")
	} else {
		return err
	}
}

func clean(s string) string { return strings.TrimSpace(s) }

// ------------------------------------------------------------ functions

// FunctionInput is a function's editable content. Key is chosen at creation
// (from the name when empty) and never changes.
type FunctionInput struct {
	Key         string
	Name        string
	Description string
	OwnerID     *int64
	Selectors   []Selector
	Note        string
}

func (w *Writer) checkFunction(in *FunctionInput, selfID string) error {
	in.Name, in.Description, in.Note = clean(in.Name), clean(in.Description), clean(in.Note)
	if err := checkText(in.Name, in.Description, in.Note); err != nil {
		return err
	}
	if err := validateSelectors(in.Selectors); err != nil {
		return err
	}
	for i := range in.Selectors {
		s := &in.Selectors[i]
		if s.EntitlementID == nil {
			continue
		}
		p, err := w.Tx.Permission(*s.EntitlementID)
		if errors.Is(err, store.ErrNotFound) {
			return refuse(422, "invalid_selectors", "selector %d: entitlement %d does not exist", i+1, *s.EntitlementID)
		} else if err != nil {
			return err
		}
		if p.System != s.System {
			return refuse(422, "invalid_selectors", "selector %d: entitlement %d belongs to %s, not %s", i+1, p.ID, p.System, s.System)
		}
	}
	if err := w.owner(in.OwnerID); err != nil {
		return err
	}
	if other, err := w.Tx.SodFunctionByName(in.Name); err == nil && other.ID != selfID {
		return refuse(409, "name_taken", "a function named %q exists", in.Name)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func functionSnapshot(f *store.SodFunction) map[string]any {
	var sels []Selector
	_ = json.Unmarshal([]byte(f.Selectors), &sels)
	return map[string]any{"key": f.Key, "name": f.Name, "description": f.Description, "owner_identity_id": f.OwnerID,
		"selectors": sels, "status": f.Status}
}

func functionDetail(f *store.SodFunction) ojson.Object {
	return ojson.Object{{Key: "function_id", Value: f.ID}, {Key: "key", Value: f.Key}, {Key: "name", Value: f.Name},
		{Key: "version", Value: f.Version}}
}

// CreateFunction saves a new function (version 1).
func (w *Writer) CreateFunction(in FunctionInput) (*store.SodFunction, error) {
	if in.Key = clean(in.Key); in.Key == "" {
		in.Key = Slug(in.Name)
	}
	if !ValidKey(in.Key) {
		return nil, refuse(422, "invalid_key", "a key of 1 to %d letters, digits, '.', '_', ':' or '-' is required", MaxKey)
	}
	if err := w.checkFunction(&in, ""); err != nil {
		return nil, err
	}
	if _, err := w.Tx.SodFunctionByKey(in.Key); err == nil {
		return nil, refuse(409, "key_taken", "a function with key %q exists", in.Key)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	f := &store.SodFunction{ID: uuid.NewString(), Key: in.Key, Name: in.Name, Description: in.Description, OwnerID: in.OwnerID,
		Selectors: mustJSON(in.Selectors), Status: store.SodActive, Version: 1, CreatedAt: w.Now, UpdatedBy: w.By.uid(), UpdatedAt: w.Now}
	if err := w.Tx.InsertSodFunction(f); err != nil {
		return nil, err
	}
	if err := w.version(store.SodKindFunction, f.ID, 1, functionSnapshot(f), in.Note); err != nil {
		return nil, err
	}
	return f, w.audit("sod.function.create", functionDetail(f))
}

// UpdateFunction saves new content as the next version; ver must be current.
func (w *Writer) UpdateFunction(id string, ver int, in FunctionInput) (*store.SodFunction, error) {
	old, err := w.Tx.SodFunction(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "function_not_found", "function not found")
	} else if err != nil {
		return nil, err
	}
	if old.Status != store.SodActive {
		return nil, refuse(409, "function_retired", "%s is retired", old.Name)
	}
	if ver != old.Version {
		return nil, refuse(409, "version_conflict", "the function changed since version %d (now %d); reload it", ver, old.Version)
	}
	if err := w.checkFunction(&in, id); err != nil {
		return nil, err
	}
	f := *old
	f.Name, f.Description, f.OwnerID, f.Selectors = in.Name, in.Description, in.OwnerID, mustJSON(in.Selectors)
	f.Version, f.UpdatedBy, f.UpdatedAt = old.Version+1, w.By.uid(), w.Now
	if err := w.Tx.SaveSodFunction(&f, old.Version); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "version_conflict", "the function changed; reload it")
	} else if err != nil {
		return nil, err
	}
	if err := w.version(store.SodKindFunction, f.ID, f.Version, functionSnapshot(&f), in.Note); err != nil {
		return nil, err
	}
	if err := w.touchFunctionRulesets(f.ID, "function "+f.Key+" changed"); err != nil {
		return nil, err
	}
	return &f, w.audit("sod.function.update", functionDetail(&f))
}

// risksUsing lists the active risks that name the function.
func (w *Writer) risksUsing(functionID string) ([]*store.SodRisk, error) {
	links, err := w.Tx.SodRiskFunctions()
	if err != nil {
		return nil, err
	}
	risks, err := w.Tx.SodRisks()
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, l := range links {
		if l.FunctionID == functionID {
			used[l.RiskID] = true
		}
	}
	var out []*store.SodRisk
	for _, r := range risks {
		if used[r.ID] && r.Status == store.SodActive {
			out = append(out, r)
		}
	}
	return out, nil
}

func (w *Writer) touchFunctionRulesets(functionID, note string) error {
	rs, err := w.risksUsing(functionID)
	if err != nil {
		return err
	}
	for _, r := range rs {
		if err := w.touch(r.RulesetID, note); err != nil {
			return err
		}
	}
	return nil
}

// RetireFunction retires a function no active risk uses.
func (w *Writer) RetireFunction(id, reason string) (*store.SodFunction, error) {
	old, err := w.Tx.SodFunction(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "function_not_found", "function not found")
	} else if err != nil {
		return nil, err
	}
	reason = clean(reason)
	switch {
	case old.Status != store.SodActive:
		return nil, refuse(409, "function_retired", "%s is already retired", old.Name)
	case reason == "" || len(reason) > MaxNote:
		return nil, refuse(422, "invalid_reason", "a reason of 1 to %d characters is required", MaxNote)
	}
	if used, err := w.risksUsing(id); err != nil {
		return nil, err
	} else if len(used) > 0 {
		return nil, refuse(409, "function_in_use", "%s is used by %d risk(s); remove it from them first", old.Name, len(used))
	}
	f := *old
	f.Status, f.Version, f.UpdatedBy, f.UpdatedAt = store.SodRetired, old.Version+1, w.By.uid(), w.Now
	if err := w.Tx.SaveSodFunction(&f, old.Version); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "version_conflict", "the function changed; reload it")
	} else if err != nil {
		return nil, err
	}
	if err := w.version(store.SodKindFunction, f.ID, f.Version, functionSnapshot(&f), reason); err != nil {
		return nil, err
	}
	return &f, w.audit("sod.function.retire", append(functionDetail(&f), ojson.KV{Key: "reason", Value: reason}))
}

// ------------------------------------------------------------ rulesets

// RulesetInput is a ruleset's editable content.
type RulesetInput struct {
	Key         string
	Name        string
	Description string
	Enabled     bool
	Note        string
}

func (w *Writer) checkRuleset(in *RulesetInput, selfID string) error {
	in.Name, in.Description, in.Note = clean(in.Name), clean(in.Description), clean(in.Note)
	if err := checkText(in.Name, in.Description, in.Note); err != nil {
		return err
	}
	if other, err := w.Tx.SodRulesetByName(in.Name); err == nil && other.ID != selfID {
		return refuse(409, "name_taken", "a ruleset named %q exists", in.Name)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func rulesetDetail(r *store.SodRuleset) ojson.Object {
	return ojson.Object{{Key: "ruleset_id", Value: r.ID}, {Key: "key", Value: r.Key}, {Key: "name", Value: r.Name},
		{Key: "version", Value: r.Version}, {Key: "enabled", Value: r.Enabled}}
}

// rulesetSnapshot is the full document of the ruleset at this version, so the
// history of a ruleset is the history of everything in it.
func (w *Writer) rulesetSnapshot(r *store.SodRuleset) (map[string]any, error) {
	b, err := BundleOf(w.Tx, r)
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": r.Status, "enabled": r.Enabled, "document": b}, nil
}

// CreateRuleset saves a new, empty ruleset (version 1).
func (w *Writer) CreateRuleset(in RulesetInput) (*store.SodRuleset, error) {
	if in.Key = clean(in.Key); in.Key == "" {
		in.Key = Slug(in.Name)
	}
	if !ValidKey(in.Key) {
		return nil, refuse(422, "invalid_key", "a key of 1 to %d letters, digits, '.', '_', ':' or '-' is required", MaxKey)
	}
	if err := w.checkRuleset(&in, ""); err != nil {
		return nil, err
	}
	if _, err := w.Tx.SodRulesetByKey(in.Key); err == nil {
		return nil, refuse(409, "key_taken", "a ruleset with key %q exists", in.Key)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	r := &store.SodRuleset{ID: uuid.NewString(), Key: in.Key, Name: in.Name, Description: in.Description, Enabled: in.Enabled,
		Status: store.SodActive, Version: 1, CreatedAt: w.Now, UpdatedBy: w.By.uid(), UpdatedAt: w.Now}
	if err := w.Tx.InsertSodRuleset(r); err != nil {
		return nil, err
	}
	snap, err := w.rulesetSnapshot(r)
	if err != nil {
		return nil, err
	}
	if err := w.version(store.SodKindRuleset, r.ID, 1, snap, in.Note); err != nil {
		return nil, err
	}
	return r, w.audit("sod.ruleset.create", rulesetDetail(r))
}

func (w *Writer) loadRuleset(id string, ver int) (*store.SodRuleset, error) {
	old, err := w.Tx.SodRuleset(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "ruleset_not_found", "ruleset not found")
	} else if err != nil {
		return nil, err
	}
	if old.Status != store.SodActive {
		return nil, refuse(409, "ruleset_retired", "%s is retired", old.Name)
	}
	if ver != old.Version {
		return nil, refuse(409, "version_conflict", "the ruleset changed since version %d (now %d); reload it", ver, old.Version)
	}
	return old, nil
}

func (w *Writer) saveRuleset(r *store.SodRuleset, from int, note, action string) (*store.SodRuleset, error) {
	if err := w.Tx.SaveSodRuleset(r, from); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "version_conflict", "the ruleset changed; reload it")
	} else if err != nil {
		return nil, err
	}
	snap, err := w.rulesetSnapshot(r)
	if err != nil {
		return nil, err
	}
	if err := w.version(store.SodKindRuleset, r.ID, r.Version, snap, note); err != nil {
		return nil, err
	}
	return r, w.audit(action, rulesetDetail(r))
}

// UpdateRuleset saves new name, description and enabled flag as the next
// version; ver must be current.
func (w *Writer) UpdateRuleset(id string, ver int, in RulesetInput) (*store.SodRuleset, error) {
	old, err := w.loadRuleset(id, ver)
	if err != nil {
		return nil, err
	}
	if err := w.checkRuleset(&in, id); err != nil {
		return nil, err
	}
	r := *old
	r.Name, r.Description, r.Enabled = in.Name, in.Description, in.Enabled
	r.Version, r.UpdatedBy, r.UpdatedAt = old.Version+1, w.By.uid(), w.Now
	action := "sod.ruleset.update"
	if old.Enabled != in.Enabled {
		action = map[bool]string{true: "sod.ruleset.enable", false: "sod.ruleset.disable"}[in.Enabled]
	}
	return w.saveRuleset(&r, old.Version, in.Note, action)
}

// RetireRuleset retires a ruleset that has no active risks.
func (w *Writer) RetireRuleset(id, reason string) (*store.SodRuleset, error) {
	old, err := w.Tx.SodRuleset(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "ruleset_not_found", "ruleset not found")
	} else if err != nil {
		return nil, err
	}
	reason = clean(reason)
	switch {
	case old.Status != store.SodActive:
		return nil, refuse(409, "ruleset_retired", "%s is already retired", old.Name)
	case reason == "" || len(reason) > MaxNote:
		return nil, refuse(422, "invalid_reason", "a reason of 1 to %d characters is required", MaxNote)
	}
	risks, err := w.Tx.SodRisks()
	if err != nil {
		return nil, err
	}
	for _, rk := range risks {
		if rk.RulesetID == id && rk.Status == store.SodActive {
			return nil, refuse(409, "ruleset_not_empty", "%s still has active risks; retire or move them first", old.Name)
		}
	}
	r := *old
	r.Status, r.Version, r.UpdatedBy, r.UpdatedAt = store.SodRetired, old.Version+1, w.By.uid(), w.Now
	if _, err := w.saveRuleset(&r, old.Version, reason, "sod.ruleset.retire"); err != nil {
		return nil, err
	}
	return &r, nil
}

// touch records that something in the ruleset changed: its version moves on
// and keeps the new document. In a batch it is done once, at the end.
func (w *Writer) touch(rulesetID, note string) error {
	if w.batch {
		if w.dirty == nil {
			w.dirty = map[string]string{}
		}
		if _, ok := w.dirty[rulesetID]; !ok {
			w.dirty[rulesetID] = note
		}
		return nil
	}
	old, err := w.Tx.SodRuleset(rulesetID)
	if err != nil {
		return err
	}
	r := *old
	r.Version, r.UpdatedBy, r.UpdatedAt = old.Version+1, w.By.uid(), w.Now
	if err := w.Tx.SaveSodRuleset(&r, old.Version); err != nil {
		return err
	}
	snap, err := w.rulesetSnapshot(&r)
	if err != nil {
		return err
	}
	return w.version(store.SodKindRuleset, r.ID, r.Version, snap, note)
}

func (w *Writer) flush() error {
	ids := make([]string, 0, len(w.dirty))
	for id := range w.dirty {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	notes := w.dirty
	w.batch, w.dirty = false, nil
	for _, id := range ids {
		if err := w.touch(id, notes[id]); err != nil {
			return err
		}
	}
	return nil
}

// ------------------------------------------------------------ risks

// RiskInput is a risk's editable content. FunctionIDs are two or more distinct
// active functions; RulesetID an active ruleset.
type RiskInput struct {
	Key             string
	Name            string
	Description     string
	Priority        string
	BusinessProcess string
	OwnerID         *int64
	RulesetID       string
	FunctionIDs     []string
	Subjects        Subjects
	Remediation     []string // options offered on a violation; none: all of RemediationOptions
	Note            string
}

func (w *Writer) checkRisk(in *RiskInput, selfID string) error {
	in.Name, in.Description, in.Note = clean(in.Name), clean(in.Description), clean(in.Note)
	in.BusinessProcess = clean(in.BusinessProcess)
	if err := checkText(in.Name, in.Description, in.Note); err != nil {
		return err
	}
	switch {
	case !contains(Priorities, in.Priority):
		return refuse(422, "invalid_priority", "priority is one of %s", strings.Join(Priorities, ", "))
	case len(in.BusinessProcess) > MaxName:
		return refuse(422, "invalid_business_process", "the business process is at most %d characters", MaxName)
	case len(in.FunctionIDs) < 2 || len(in.FunctionIDs) > MaxFunctions:
		return refuse(422, "invalid_functions", "a risk needs 2 to %d conflicting functions", MaxFunctions)
	}
	seen := map[string]bool{}
	for _, id := range in.FunctionIDs {
		if seen[id] {
			return refuse(422, "invalid_functions", "a function cannot conflict with itself; name each function once")
		}
		seen[id] = true
		f, err := w.Tx.SodFunction(id)
		if errors.Is(err, store.ErrNotFound) {
			return refuse(422, "function_not_found", "a function of the risk does not exist")
		} else if err != nil {
			return err
		}
		if f.Status != store.SodActive {
			return refuse(409, "function_retired", "%s is retired", f.Name)
		}
	}
	if err := in.Subjects.validate(); err != nil {
		return err
	}
	opts, err := normalizeOptions(in.Remediation)
	if err != nil {
		return err
	}
	in.Remediation = opts
	rs, err := w.Tx.SodRuleset(in.RulesetID)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(422, "ruleset_not_found", "the ruleset does not exist")
	} else if err != nil {
		return err
	}
	if rs.Status != store.SodActive {
		return refuse(409, "ruleset_retired", "%s is retired", rs.Name)
	}
	if err := w.owner(in.OwnerID); err != nil {
		return err
	}
	if other, err := w.Tx.SodRiskByName(in.Name); err == nil && other.ID != selfID {
		return refuse(409, "name_taken", "a risk named %q exists", in.Name)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func (w *Writer) functionKeys(ids []string) ([]string, error) {
	out := make([]string, len(ids))
	for i, id := range ids {
		f, err := w.Tx.SodFunction(id)
		if err != nil {
			return nil, err
		}
		out[i] = f.Key
	}
	return out, nil
}

func (w *Writer) riskSnapshot(r *store.SodRisk, fnIDs []string, opts []string) (map[string]any, error) {
	keys, err := w.functionKeys(fnIDs)
	if err != nil {
		return nil, err
	}
	rs, err := w.Tx.SodRuleset(r.RulesetID)
	if err != nil {
		return nil, err
	}
	var subj Subjects
	_ = json.Unmarshal([]byte(r.Subjects), &subj)
	return map[string]any{"key": r.Key, "name": r.Name, "description": r.Description, "priority": r.Priority,
		"business_process": r.BusinessProcess, "owner_identity_id": r.OwnerID, "ruleset": rs.Key, "functions": keys,
		"subjects": subj, "remediation": opts, "status": r.Status}, nil
}

func riskDetail(r *store.SodRisk) ojson.Object {
	return ojson.Object{{Key: "risk_id", Value: r.ID}, {Key: "key", Value: r.Key}, {Key: "name", Value: r.Name},
		{Key: "priority", Value: r.Priority}, {Key: "version", Value: r.Version}}
}

// CreateRisk saves a new risk (version 1).
func (w *Writer) CreateRisk(in RiskInput) (*store.SodRisk, error) {
	if in.Key = clean(in.Key); in.Key == "" {
		in.Key = Slug(in.Name)
	}
	if !ValidKey(in.Key) {
		return nil, refuse(422, "invalid_key", "a key of 1 to %d letters, digits, '.', '_', ':' or '-' is required", MaxKey)
	}
	if err := w.checkRisk(&in, ""); err != nil {
		return nil, err
	}
	if _, err := w.Tx.SodRiskByKey(in.Key); err == nil {
		return nil, refuse(409, "key_taken", "a risk with key %q exists", in.Key)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	r := &store.SodRisk{ID: uuid.NewString(), Key: in.Key, Name: in.Name, Description: in.Description, Priority: in.Priority,
		BusinessProcess: in.BusinessProcess, OwnerID: in.OwnerID, RulesetID: in.RulesetID, Subjects: mustJSON(in.Subjects),
		Status: store.SodActive, Version: 1, CreatedAt: w.Now, UpdatedBy: w.By.uid(), UpdatedAt: w.Now}
	if err := w.Tx.InsertSodRisk(r); err != nil {
		return nil, err
	}
	if err := w.Tx.SetSodRiskFunctions(r.ID, in.FunctionIDs); err != nil {
		return nil, err
	}
	if err := w.Tx.SetSodRiskOptions(r.ID, in.Remediation); err != nil {
		return nil, err
	}
	snap, err := w.riskSnapshot(r, in.FunctionIDs, in.Remediation)
	if err != nil {
		return nil, err
	}
	if err := w.version(store.SodKindRisk, r.ID, 1, snap, in.Note); err != nil {
		return nil, err
	}
	if err := w.touch(r.RulesetID, "risk "+r.Key+" added"); err != nil {
		return nil, err
	}
	return r, w.audit("sod.risk.create", riskDetail(r))
}

// UpdateRisk saves new content as the next version; ver must be current.
func (w *Writer) UpdateRisk(id string, ver int, in RiskInput) (*store.SodRisk, error) {
	old, err := w.Tx.SodRisk(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "risk_not_found", "risk not found")
	} else if err != nil {
		return nil, err
	}
	if old.Status != store.SodActive {
		return nil, refuse(409, "risk_retired", "%s is retired", old.Name)
	}
	if ver != old.Version {
		return nil, refuse(409, "version_conflict", "the risk changed since version %d (now %d); reload it", ver, old.Version)
	}
	if err := w.checkRisk(&in, id); err != nil {
		return nil, err
	}
	r := *old
	r.Name, r.Description, r.Priority, r.BusinessProcess = in.Name, in.Description, in.Priority, in.BusinessProcess
	r.OwnerID, r.RulesetID, r.Subjects = in.OwnerID, in.RulesetID, mustJSON(in.Subjects)
	r.Version, r.UpdatedBy, r.UpdatedAt = old.Version+1, w.By.uid(), w.Now
	if err := w.Tx.SaveSodRisk(&r, old.Version); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "version_conflict", "the risk changed; reload it")
	} else if err != nil {
		return nil, err
	}
	if err := w.Tx.SetSodRiskFunctions(r.ID, in.FunctionIDs); err != nil {
		return nil, err
	}
	if err := w.Tx.SetSodRiskOptions(r.ID, in.Remediation); err != nil {
		return nil, err
	}
	snap, err := w.riskSnapshot(&r, in.FunctionIDs, in.Remediation)
	if err != nil {
		return nil, err
	}
	if err := w.version(store.SodKindRisk, r.ID, r.Version, snap, in.Note); err != nil {
		return nil, err
	}
	if err := w.touch(r.RulesetID, "risk "+r.Key+" changed"); err != nil {
		return nil, err
	}
	if old.RulesetID != r.RulesetID {
		if err := w.touch(old.RulesetID, "risk "+r.Key+" moved out"); err != nil {
			return nil, err
		}
	}
	return &r, w.audit("sod.risk.update", riskDetail(&r))
}

// RiskFunctionIDs returns a risk's function ids in order.
func RiskFunctionIDs(tx *store.TenantTx, riskID string) ([]string, error) {
	links, err := tx.SodRiskFunctions()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range links {
		if l.RiskID == riskID {
			out = append(out, l.FunctionID)
		}
	}
	return out, nil
}

// RetireRisk retires a risk; its violations stop being reported.
func (w *Writer) RetireRisk(id, reason string) (*store.SodRisk, error) {
	old, err := w.Tx.SodRisk(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "risk_not_found", "risk not found")
	} else if err != nil {
		return nil, err
	}
	reason = clean(reason)
	switch {
	case old.Status != store.SodActive:
		return nil, refuse(409, "risk_retired", "%s is already retired", old.Name)
	case reason == "" || len(reason) > MaxNote:
		return nil, refuse(422, "invalid_reason", "a reason of 1 to %d characters is required", MaxNote)
	}
	r := *old
	r.Status, r.Version, r.UpdatedBy, r.UpdatedAt = store.SodRetired, old.Version+1, w.By.uid(), w.Now
	if err := w.Tx.SaveSodRisk(&r, old.Version); errors.Is(err, store.ErrNotFound) {
		return nil, refuse(409, "version_conflict", "the risk changed; reload it")
	} else if err != nil {
		return nil, err
	}
	ids, err := RiskFunctionIDs(w.Tx, r.ID)
	if err != nil {
		return nil, err
	}
	opts, err := RiskOptions(w.Tx, r.ID)
	if err != nil {
		return nil, err
	}
	snap, err := w.riskSnapshot(&r, ids, opts)
	if err != nil {
		return nil, err
	}
	if err := w.version(store.SodKindRisk, r.ID, r.Version, snap, reason); err != nil {
		return nil, err
	}
	if err := w.touch(r.RulesetID, "risk "+r.Key+" retired"); err != nil {
		return nil, err
	}
	return &r, w.audit("sod.risk.retire", append(riskDetail(&r), ojson.KV{Key: "reason", Value: reason}))
}

// sortedKeys is the keys of m in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// RiskOptions returns a risk's explicit remediation options (nil: all four).
func RiskOptions(tx *store.TenantTx, riskID string) ([]string, error) {
	all, err := tx.SodRiskOptions()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, o := range all {
		if o.RiskID == riskID {
			out = append(out, o.Option)
		}
	}
	return orderOptions(out), nil
}

// orderOptions puts options in display order (the database lists them alphabetically).
func orderOptions(in []string) []string {
	var out []string
	for _, o := range RemediationOptions {
		if contains(in, o) {
			out = append(out, o)
		}
	}
	return out
}

// Offers reports whether a risk with these explicit options offers option.
func Offers(explicit []string, option string) bool {
	return len(explicit) == 0 || contains(explicit, option)
}
