package sod

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"

	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// SchemaTag names the document format of a ruleset file.
const SchemaTag = "tessera.sod/v1"

// MaxDocument bounds an imported ruleset file.
const MaxDocument = 512 << 10

// Bundle is a ruleset with the functions and risks it needs, the form that is
// exported, kept in git and imported (access as code). Functions and risks are
// named by key; owners by the external id of the identity.
type Bundle struct {
	Schema    string        `json:"schema" yaml:"schema"`
	Ruleset   RulesetDoc    `json:"ruleset" yaml:"ruleset"`
	Functions []FunctionDoc `json:"functions" yaml:"functions"`
	Risks     []RiskDoc     `json:"risks" yaml:"risks"`
}

// RulesetDoc is the ruleset of a Bundle.
type RulesetDoc struct {
	Key         string `json:"key" yaml:"key"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled     bool   `json:"enabled" yaml:"enabled"`
}

// FunctionDoc is a function in a Bundle.
type FunctionDoc struct {
	Key         string     `json:"key" yaml:"key"`
	Name        string     `json:"name" yaml:"name"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Owner       string     `json:"owner,omitempty" yaml:"owner,omitempty"`
	Selectors   []Selector `json:"selectors" yaml:"selectors"`
}

// RiskDoc is a risk in a Bundle; Functions are function keys.
type RiskDoc struct {
	Key             string    `json:"key" yaml:"key"`
	Name            string    `json:"name" yaml:"name"`
	Description     string    `json:"description,omitempty" yaml:"description,omitempty"`
	Priority        string    `json:"priority" yaml:"priority"`
	BusinessProcess string    `json:"business_process,omitempty" yaml:"business_process,omitempty"`
	Owner           string    `json:"owner,omitempty" yaml:"owner,omitempty"`
	Functions       []string  `json:"functions" yaml:"functions"`
	Subjects        *Subjects `json:"subjects,omitempty" yaml:"subjects,omitempty"`
	// Remediation lists the options offered on a violation (revoke, mitigate, accept, escalate); omitted: all.
	Remediation []string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

// MarshalYAML renders the bundle as a YAML file.
func (b *Bundle) MarshalYAML() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

// ParseYAML reads a ruleset file. Unknown fields and trailing documents are
// refused, so a typo is an error and not a silently ignored setting.
func ParseYAML(data []byte) (*Bundle, error) {
	if len(data) == 0 || len(data) > MaxDocument {
		return nil, refuse(422, "invalid_document", "the ruleset file must be 1 to %d bytes", MaxDocument)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, refuse(422, "invalid_document", "the ruleset file is not valid: %v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, refuse(422, "invalid_document", "the ruleset file holds more than one document")
	}
	if b.Schema != "" && b.Schema != SchemaTag {
		return nil, refuse(422, "invalid_document", "schema is %q; this server reads %q", b.Schema, SchemaTag)
	}
	b.Schema = SchemaTag
	return &b, nil
}

// BundleOf is the document of a ruleset: its active risks and the functions
// they use, in key order.
func BundleOf(tx *store.TenantTx, rs *store.SodRuleset) (*Bundle, error) {
	fns, err := tx.SodFunctions()
	if err != nil {
		return nil, err
	}
	risks, err := tx.SodRisks()
	if err != nil {
		return nil, err
	}
	links, err := tx.SodRiskFunctions()
	if err != nil {
		return nil, err
	}
	people, _, err := tx.IdentityMap()
	if err != nil {
		return nil, err
	}
	optRows, err := tx.SodRiskOptions()
	if err != nil {
		return nil, err
	}
	optsOf := map[string][]string{}
	for _, o := range optRows {
		optsOf[o.RiskID] = append(optsOf[o.RiskID], o.Option)
	}
	xid := func(id *int64) string {
		if id == nil {
			return ""
		}
		if p := people[*id]; p != nil {
			return p.ExternalID
		}
		return ""
	}
	fnByID := map[string]*store.SodFunction{}
	for _, f := range fns {
		fnByID[f.ID] = f
	}
	linked := map[string][]string{}
	for _, l := range links {
		linked[l.RiskID] = append(linked[l.RiskID], l.FunctionID)
	}
	b := &Bundle{Schema: SchemaTag, Ruleset: RulesetDoc{Key: rs.Key, Name: rs.Name, Description: rs.Description, Enabled: rs.Enabled},
		Functions: []FunctionDoc{}, Risks: []RiskDoc{}}
	used := map[string]bool{}
	for _, r := range risks {
		if r.RulesetID != rs.ID || r.Status != store.SodActive {
			continue
		}
		doc := RiskDoc{Key: r.Key, Name: r.Name, Description: r.Description, Priority: r.Priority,
			BusinessProcess: r.BusinessProcess, Owner: xid(r.OwnerID), Functions: []string{}, Remediation: orderOptions(optsOf[r.ID])}
		for _, fid := range linked[r.ID] {
			if f := fnByID[fid]; f != nil {
				doc.Functions = append(doc.Functions, f.Key)
				used[fid] = true
			}
		}
		var subj Subjects
		if err := json.Unmarshal([]byte(r.Subjects), &subj); err == nil && !reflect.DeepEqual(subj, Subjects{}) {
			doc.Subjects = &subj
		}
		b.Risks = append(b.Risks, doc)
	}
	for id := range used {
		f := fnByID[id]
		var sels []Selector
		if err := json.Unmarshal([]byte(f.Selectors), &sels); err != nil {
			return nil, fmt.Errorf("sod: stored function %s: %w", f.ID, err)
		}
		b.Functions = append(b.Functions, FunctionDoc{Key: f.Key, Name: f.Name, Description: f.Description, Owner: xid(f.OwnerID),
			Selectors: sels})
	}
	sort.Slice(b.Functions, func(i, j int) bool { return b.Functions[i].Key < b.Functions[j].Key })
	sort.Slice(b.Risks, func(i, j int) bool { return b.Risks[i].Key < b.Risks[j].Key })
	return b, nil
}

// ImportResult says what an import did (or, in a dry run, would do).
type ImportResult struct {
	DryRun  bool     `json:"dry_run"`
	Ruleset string   `json:"ruleset"`
	Created []string `json:"created"`
	Updated []string `json:"updated"`
	Same    []string `json:"unchanged"`
	Retired []string `json:"retired"`
}

// ImportOptions control an import. Prune retires the ruleset's risks that the
// file no longer lists; DryRun validates and reports without writing.
type ImportOptions struct {
	Prune  bool
	DryRun bool
}

func (r *ImportResult) note(list *[]string, kind, key string) { *list = append(*list, kind+" "+key) }

func (w *Writer) ownerByXID(xid string) (*int64, error) {
	if xid == "" {
		return nil, nil
	}
	i, err := w.Tx.IdentityByExternalID(xid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(422, "owner_not_found", "owner %q is not a known identity (use its external id)", xid)
	} else if err != nil {
		return nil, err
	}
	return &i.ID, nil
}

func sameJSON(a, b any) bool {
	x, y := mustJSON(a), mustJSON(b)
	return x == y
}

// Import makes the tenant's ruleset (by key) match the bundle: functions and
// risks are created or updated by key, in one transaction, each change
// versioned and audited, and the ruleset gains one version for the whole
// import. Everything is validated before anything is written.
func (w *Writer) Import(b *Bundle, opt ImportOptions) (*ImportResult, error) {
	if err := validateBundle(b); err != nil {
		return nil, err
	}
	res := &ImportResult{DryRun: opt.DryRun, Ruleset: b.Ruleset.Key, Created: []string{}, Updated: []string{}, Same: []string{}, Retired: []string{}}
	if opt.DryRun {
		return res, w.plan(b, opt, res)
	}
	// resolve and check everything first, so a refusal leaves nothing half-written
	if err := w.plan(b, opt, &ImportResult{}); err != nil {
		return nil, err
	}
	w.batch = true
	defer func() { w.batch, w.dirty = false, nil }()

	rs, err := w.Tx.SodRulesetByKey(b.Ruleset.Key)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if rs, err = w.CreateRuleset(RulesetInput{Key: b.Ruleset.Key, Name: b.Ruleset.Name, Description: b.Ruleset.Description,
			Enabled: b.Ruleset.Enabled, Note: "imported"}); err != nil {
			return nil, err
		}
		res.note(&res.Created, "ruleset", rs.Key)
	case err != nil:
		return nil, err
	case rs.Status != store.SodActive:
		return nil, refuse(409, "ruleset_retired", "%s is retired", rs.Name)
	case rs.Name != b.Ruleset.Name || rs.Description != b.Ruleset.Description || rs.Enabled != b.Ruleset.Enabled:
		if rs, err = w.UpdateRuleset(rs.ID, rs.Version, RulesetInput{Name: b.Ruleset.Name, Description: b.Ruleset.Description,
			Enabled: b.Ruleset.Enabled, Note: "imported"}); err != nil {
			return nil, err
		}
		res.note(&res.Updated, "ruleset", rs.Key)
	}

	fnID := map[string]string{}
	for _, d := range b.Functions {
		owner, err := w.ownerByXID(d.Owner)
		if err != nil {
			return nil, err
		}
		in := FunctionInput{Key: d.Key, Name: d.Name, Description: d.Description, OwnerID: owner, Selectors: d.Selectors, Note: "imported"}
		f, err := w.Tx.SodFunctionByKey(d.Key)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if f, err = w.CreateFunction(in); err != nil {
				return nil, err
			}
			res.note(&res.Created, "function", d.Key)
		case err != nil:
			return nil, err
		default:
			var cur []Selector
			_ = json.Unmarshal([]byte(f.Selectors), &cur)
			if f.Status == store.SodActive && f.Name == d.Name && f.Description == d.Description &&
				sameInt(f.OwnerID, owner) && sameJSON(cur, d.Selectors) {
				res.note(&res.Same, "function", d.Key)
				break
			}
			if f.Status != store.SodActive {
				return nil, refuse(409, "function_retired", "function %s is retired; use another key", d.Key)
			}
			if f, err = w.UpdateFunction(f.ID, f.Version, in); err != nil {
				return nil, err
			}
			res.note(&res.Updated, "function", d.Key)
		}
		fnID[d.Key] = f.ID
	}

	listed := map[string]bool{}
	for _, d := range b.Risks {
		listed[d.Key] = true
		owner, err := w.ownerByXID(d.Owner)
		if err != nil {
			return nil, err
		}
		ids := make([]string, len(d.Functions))
		for i, k := range d.Functions {
			ids[i] = fnID[k]
		}
		var subj Subjects
		if d.Subjects != nil {
			subj = *d.Subjects
		}
		in := RiskInput{Key: d.Key, Name: d.Name, Description: d.Description, Priority: d.Priority,
			BusinessProcess: d.BusinessProcess, OwnerID: owner, RulesetID: rs.ID, FunctionIDs: ids, Subjects: subj,
			Remediation: d.Remediation, Note: "imported"}
		r, err := w.Tx.SodRiskByKey(d.Key)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if _, err = w.CreateRisk(in); err != nil {
				return nil, err
			}
			res.note(&res.Created, "risk", d.Key)
		case err != nil:
			return nil, err
		default:
			cur, err := w.riskDoc(r)
			if err != nil {
				return nil, err
			}
			if r.Status == store.SodActive && r.RulesetID == rs.ID && sameJSON(cur, d) {
				res.note(&res.Same, "risk", d.Key)
				break
			}
			if r.Status != store.SodActive {
				return nil, refuse(409, "risk_retired", "risk %s is retired; use another key", d.Key)
			}
			if _, err = w.UpdateRisk(r.ID, r.Version, in); err != nil {
				return nil, err
			}
			res.note(&res.Updated, "risk", d.Key)
		}
	}
	if opt.Prune {
		risks, err := w.Tx.SodRisks()
		if err != nil {
			return nil, err
		}
		for _, r := range risks {
			if r.RulesetID == rs.ID && r.Status == store.SodActive && !listed[r.Key] {
				if _, err := w.RetireRisk(r.ID, "not in the imported file"); err != nil {
					return nil, err
				}
				res.note(&res.Retired, "risk", r.Key)
			}
		}
	}
	if err := w.flush(); err != nil {
		return nil, err
	}
	return res, w.audit("sod.ruleset.import", ojson.Object{{Key: "ruleset", Value: rs.Key},
		{Key: "created", Value: len(res.Created)}, {Key: "updated", Value: len(res.Updated)},
		{Key: "unchanged", Value: len(res.Same)}, {Key: "retired", Value: len(res.Retired)}})
}

func sameInt(a, b *int64) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

// riskDoc is the stored risk in document form, to compare with an imported one.
func (w *Writer) riskDoc(r *store.SodRisk) (RiskDoc, error) {
	ids, err := RiskFunctionIDs(w.Tx, r.ID)
	if err != nil {
		return RiskDoc{}, err
	}
	keys, err := w.functionKeys(ids)
	if err != nil {
		return RiskDoc{}, err
	}
	opts, err := RiskOptions(w.Tx, r.ID)
	if err != nil {
		return RiskDoc{}, err
	}
	d := RiskDoc{Key: r.Key, Name: r.Name, Description: r.Description, Priority: r.Priority, BusinessProcess: r.BusinessProcess,
		Functions: keys, Remediation: opts}
	if r.OwnerID != nil {
		if i, err := w.Tx.Identity(*r.OwnerID); err == nil {
			d.Owner = i.ExternalID
		}
	}
	var subj Subjects
	if err := json.Unmarshal([]byte(r.Subjects), &subj); err == nil && !reflect.DeepEqual(subj, Subjects{}) {
		d.Subjects = &subj
	}
	if d.Subjects != nil {
		// compare through JSON so a YAML-decoded condition equals a stored one
		d.Subjects = normSubjects(d.Subjects)
	}
	return d, nil
}

func normSubjects(s *Subjects) *Subjects {
	var out Subjects
	_ = json.Unmarshal([]byte(mustJSON(s)), &out)
	return &out
}

// plan fills res for a dry run by comparing the bundle with what is stored,
// after the same resolution checks a real import makes.
func (w *Writer) plan(b *Bundle, opt ImportOptions, res *ImportResult) error {
	rs, err := w.Tx.SodRulesetByKey(b.Ruleset.Key)
	switch {
	case errors.Is(err, store.ErrNotFound):
		res.note(&res.Created, "ruleset", b.Ruleset.Key)
		rs = nil
	case err != nil:
		return err
	case rs.Name != b.Ruleset.Name || rs.Description != b.Ruleset.Description || rs.Enabled != b.Ruleset.Enabled:
		res.note(&res.Updated, "ruleset", rs.Key)
	}
	for _, d := range b.Functions {
		owner, err := w.ownerByXID(d.Owner)
		if err != nil {
			return err
		}
		in := FunctionInput{Name: d.Name, Description: d.Description, OwnerID: owner, Selectors: d.Selectors}
		f, err := w.Tx.SodFunctionByKey(d.Key)
		if errors.Is(err, store.ErrNotFound) {
			if err := w.checkFunction(&in, ""); err != nil {
				return err
			}
			res.note(&res.Created, "function", d.Key)
			continue
		} else if err != nil {
			return err
		}
		if err := w.checkFunction(&in, f.ID); err != nil {
			return err
		}
		var cur []Selector
		_ = json.Unmarshal([]byte(f.Selectors), &cur)
		if f.Name == d.Name && f.Description == d.Description && sameInt(f.OwnerID, owner) && sameJSON(cur, d.Selectors) {
			res.note(&res.Same, "function", d.Key)
		} else {
			res.note(&res.Updated, "function", d.Key)
		}
	}
	listed := map[string]bool{}
	for _, d := range b.Risks {
		listed[d.Key] = true
		if _, err := w.ownerByXID(d.Owner); err != nil {
			return err
		}
		if d.Subjects != nil {
			if err := d.Subjects.validate(); err != nil {
				return err
			}
		}
		r, err := w.Tx.SodRiskByKey(d.Key)
		switch {
		case errors.Is(err, store.ErrNotFound):
			res.note(&res.Created, "risk", d.Key)
		case err != nil:
			return err
		default:
			cur, err := w.riskDoc(r)
			if err != nil {
				return err
			}
			if rs != nil && r.RulesetID == rs.ID && sameJSON(cur, d) {
				res.note(&res.Same, "risk", d.Key)
			} else {
				res.note(&res.Updated, "risk", d.Key)
			}
		}
	}
	if opt.Prune && rs != nil {
		risks, err := w.Tx.SodRisks()
		if err != nil {
			return err
		}
		for _, r := range risks {
			if r.RulesetID == rs.ID && r.Status == store.SodActive && !listed[r.Key] {
				res.note(&res.Retired, "risk", r.Key)
			}
		}
	}
	return nil
}

// validateBundle checks a bundle's structure, with no database: keys, text,
// priorities, selectors, and that every risk names defined functions.
func validateBundle(b *Bundle) error {
	if !ValidKey(b.Ruleset.Key) {
		return refuse(422, "invalid_key", "ruleset.key is 1 to %d letters, digits, '.', '_', ':' or '-'", MaxKey)
	}
	if err := checkText(clean(b.Ruleset.Name), clean(b.Ruleset.Description), ""); err != nil {
		return err
	}
	if len(b.Functions) > 500 || len(b.Risks) > 500 {
		return refuse(422, "invalid_document", "at most 500 functions and 500 risks per ruleset")
	}
	fns := map[string]bool{}
	names := map[string]bool{}
	for _, f := range b.Functions {
		if !ValidKey(f.Key) {
			return refuse(422, "invalid_key", "function key %q is not a valid key", f.Key)
		}
		if fns[f.Key] || names[f.Name] {
			return refuse(422, "invalid_document", "function %q is listed twice", f.Key)
		}
		fns[f.Key], names[f.Name] = true, true
		if err := checkText(clean(f.Name), clean(f.Description), ""); err != nil {
			return wrap("function "+f.Key, err)
		}
		if err := validateSelectors(f.Selectors); err != nil {
			return wrap("function "+f.Key, err)
		}
	}
	risks := map[string]bool{}
	rnames := map[string]bool{}
	for _, r := range b.Risks {
		if !ValidKey(r.Key) {
			return refuse(422, "invalid_key", "risk key %q is not a valid key", r.Key)
		}
		if risks[r.Key] || rnames[r.Name] {
			return refuse(422, "invalid_document", "risk %q is listed twice", r.Key)
		}
		risks[r.Key], rnames[r.Name] = true, true
		if err := checkText(clean(r.Name), clean(r.Description), ""); err != nil {
			return wrap("risk "+r.Key, err)
		}
		if !contains(Priorities, r.Priority) {
			return refuse(422, "invalid_priority", "risk %s: priority is one of %v", r.Key, Priorities)
		}
		if len(r.Functions) < 2 || len(r.Functions) > MaxFunctions {
			return refuse(422, "invalid_functions", "risk %s needs 2 to %d functions", r.Key, MaxFunctions)
		}
		seen := map[string]bool{}
		for _, k := range r.Functions {
			if !fns[k] {
				return refuse(422, "invalid_functions", "risk %s names function %q, which the file does not define", r.Key, k)
			}
			if seen[k] {
				return refuse(422, "invalid_functions", "risk %s names function %q twice", r.Key, k)
			}
			seen[k] = true
		}
		if r.Subjects != nil {
			if err := r.Subjects.validate(); err != nil {
				return wrap("risk "+r.Key, err)
			}
		}
		if _, err := normalizeOptions(r.Remediation); err != nil {
			return wrap("risk "+r.Key, err)
		}
	}
	for i := range b.Risks { // the canonical form: nil means every option
		b.Risks[i].Remediation, _ = normalizeOptions(b.Risks[i].Remediation)
	}
	return nil
}

// wrap prefixes a refusal's message with where in the file it arose.
func wrap(where string, err error) error {
	var rf *Refusal
	if errors.As(err, &rf) {
		return &Refusal{Status: rf.Status, Code: rf.Code, Msg: where + ": " + rf.Msg}
	}
	return err
}
