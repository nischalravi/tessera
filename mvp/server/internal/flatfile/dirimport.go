package flatfile

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/idrules"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Directory CSV import (issue #915). A file for the Directory lists is loaded into a manual source: a
// tenant-scoped system the admin names ("hr-sheet"), never one a connector owns. People and entitlements
// (catalog groups) keep a snapshot in dirimport_records; accounts reuse the flat-file path (mapping, upload
// history, manual tasks), so every target goes through ingest.Import, the correlation and the deletion
// guard the connectors use. A row the next file drops is removed only if the same source imported it.

// Targets of a directory import.
const (
	TargetPeople       = "people"
	TargetAccounts     = "accounts"
	TargetEntitlements = "entitlements"
)

// ValidTarget reports whether t is an import target.
func ValidTarget(t string) bool {
	return t == TargetPeople || t == TargetAccounts || t == TargetEntitlements
}

// Canonical column names of each target.
var (
	PeopleColumns       = []string{"email", "name", "external_id", "department", "title", "manager_email", "status"}
	PeopleRequired      = []string{"email", "name"}
	AccountColumns      = []string{"account_id", "username", "email", "identity_id", "status"}
	AccountRequired     = []string{"account_id", "username"}
	EntitlementColumns  = []string{"name", "external_id", "kind", "privileged", "description"}
	EntitlementRequired = []string{"name"}
)

// Error codes only a directory import raises.
const (
	CodeOwnedElsewhere = "owned_by_other_source"
	CodeEmailInUse     = "email_in_use"
	CodeInvalidKind    = "invalid_kind"
)

// ItemRetireEntitlement is the kind of a held retirement of an entitlement the file no longer lists.
const ItemRetireEntitlement = "entitlement_retire"

// ImportInput is one file for one target of a manual source.
type ImportInput struct {
	System   string
	Name     string // display name of a new source; the system when empty
	Target   string
	Filename string
	Raw      []byte
	By       string
	// ByUser is the platform user id of By, "" when the caller is no user.
	ByUser string
	// Reserved are the systems a configured connector writes to without a connection row (TESSERA_CONNECTORS):
	// an import refuses them as it refuses a connection's system.
	Reserved map[string]bool
}

// importer is who the snapshot names as the last to change a row: the admin's platform user id when known (review
// routing compares it with a reviewer's accounts), else the display name.
func (in ImportInput) importer() string {
	if in.ByUser != "" {
		return in.ByUser
	}
	return in.By
}

// ImportOutcome is what an applied import did.
type ImportOutcome struct {
	Plan   *Plan
	Held   int    // removals the deletion guard held
	HoldID string // the hold they wait in

	HeldRestores  int    // restores of people the source ended that the deletion guard held
	RestoreHoldID string // the hold they wait in
}

// CanonicalMapping is the column mapping of a new manual source's accounts.
func CanonicalMapping(system, name string) *Mapping {
	if strings.TrimSpace(name) == "" {
		name = system
	}
	return &Mapping{System: system, Name: name, Accounts: AccountCols{AccountID: "account_id", Username: "username",
		Email: "email", IdentityID: "identity_id", Status: "status"}}
}

// ManualSource tells what a manual source holds and which columns its files carry.
type ManualSource struct {
	System   string
	Name     string
	People   int
	Accounts int
	Entitle  int
	// AccountColumns are the header names of an accounts file: the mapping's own when the source was set up
	// as a flat-file app, else the canonical ones.
	AccountColumns []string
}

// ManualSources lists the manual sources of the tenant: every flat-file app and every source a people or
// entitlements import wrote to.
func ManualSources(c *store.TenantTx) ([]*ManualSource, error) {
	by := map[string]*ManualSource{}
	get := func(sys string) *ManualSource {
		if by[sys] == nil {
			by[sys] = &ManualSource{System: sys, Name: sys, AccountColumns: AccountColumns}
		}
		return by[sys]
	}
	maps, err := c.FlatMappings()
	if err != nil {
		return nil, err
	}
	for _, ms := range maps {
		m, err := FromStore(ms)
		if err != nil {
			return nil, err
		}
		s := get(ms.System)
		s.Name = ms.Name
		a := m.Accounts
		s.AccountColumns = nonEmpty(a.AccountID, a.Username, a.Email, a.IdentityID, a.Status)
		recs, err := c.FlatRecords(ms.System, KindAccounts)
		if err != nil {
			return nil, err
		}
		s.Accounts = len(recs)
	}
	srcs, err := c.ImportSources()
	if err != nil {
		return nil, err
	}
	for _, x := range srcs {
		s := get(x.System)
		if x.Kind == store.ImportPeople {
			s.People = x.Rows
		} else {
			s.Entitle = x.Rows
		}
	}
	out := make([]*ManualSource, 0, len(by))
	for _, s := range by {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].System < out[j].System })
	return out, nil
}

func nonEmpty(xs ...string) []string {
	var out []string
	for _, x := range xs {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// isManual reports whether the system is already a manual source of this tenant.
func isManual(c *store.TenantTx, system string) (bool, error) {
	if _, err := c.FlatMapping(system); err == nil {
		return true, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	srcs, err := c.ImportSources()
	if err != nil {
		return false, err
	}
	for _, s := range srcs {
		if s.System == system {
			return true, nil
		}
	}
	return false, nil
}

// SystemFree refuses a system a connection or another source owns: a new manual source must not take a
// connector's name or objects.
func SystemFree(c *store.TenantTx, system string) error {
	conns, err := c.Connections()
	if err != nil {
		return err
	}
	for _, x := range conns {
		if x.System == system {
			return &Error{"system_not_manual", "a connection already feeds the system " + system}
		}
	}
	n, err := c.CountSystem(system)
	if err != nil {
		return err
	}
	if n.Accounts+n.Groups+n.Resources+n.Permissions > 0 || system == "tessera" {
		return &Error{"system_not_manual", "the system " + system + " already has data from another source"}
	}
	return nil
}

// checkSource refuses a source an import may not write to: an invalid name, or a system a connector owns.
// reserved are the systems configured connectors write to without a connection row; they are refused on
// every call, also for a source that already exists (one named before the connector's first sync).
func checkSource(c *store.TenantTx, system string, reserved map[string]bool) error {
	if !ValidSystem(system) {
		return &Error{"invalid_system", "name the source with 1 to 63 lower-case letters, digits, '.', '_' or '-'"}
	}
	if reserved[system] {
		return &Error{"system_not_manual", "a connector feeds the system " + system + ": a CSV import never writes to a connector's system"}
	}
	conns, err := c.Connections()
	if err != nil {
		return err
	}
	for _, x := range conns {
		if x.System == system {
			return &Error{"system_not_manual", "a connection already feeds the system " + system + ": a CSV import never writes to a connector's system"}
		}
	}
	manual, err := isManual(c, system)
	if err != nil || manual {
		return err
	}
	return SystemFree(c, system)
}

// PlanImport is the dry run of a directory import: nothing is written.
func PlanImport(c *store.TenantTx, now time.Time, in ImportInput) (*Plan, error) {
	if !ValidTarget(in.Target) {
		return nil, &Error{"invalid_target", "target must be people, accounts or entitlements"}
	}
	if err := checkSource(c, in.System, in.Reserved); err != nil {
		return nil, err
	}
	switch in.Target {
	case TargetAccounts:
		fin, err := accountsInput(c, in)
		if err != nil {
			return nil, err
		}
		return MakePlan(c, now, fin)
	case TargetPeople:
		p, err := preparePeople(c, in)
		if err != nil {
			return nil, err
		}
		return p.plan(c)
	default:
		p, err := prepareEntitlements(c, in)
		if err != nil {
			return nil, err
		}
		return p.plan(c)
	}
}

// accountsInput is the flat-file input of an accounts file: the source's saved mapping, or the canonical
// one for a new source.
func accountsInput(c *store.TenantTx, in ImportInput) (Input, error) {
	fin := Input{System: in.System, Kind: KindAccounts, Filename: in.Filename, Raw: in.Raw, By: in.By, Limits: DirectoryLimits}
	if _, err := c.FlatMapping(in.System); errors.Is(err, store.ErrNotFound) {
		fin.Mapping = CanonicalMapping(in.System, in.Name)
	} else if err != nil {
		return fin, err
	}
	return fin, nil
}

// ApplyImport applies a directory import in the caller's transaction: validates, writes through the ingest
// path, and records the domain event "directory.import". A file with an invalid row changes nothing (the
// plan lists the errors). The caller has checked permission and step-up.
func ApplyImport(c *store.TenantTx, now time.Time, in ImportInput) (*ImportOutcome, error) {
	if !ValidTarget(in.Target) {
		return nil, &Error{"invalid_target", "target must be people, accounts or entitlements"}
	}
	if err := checkSource(c, in.System, in.Reserved); err != nil {
		return nil, err
	}
	out := &ImportOutcome{}
	switch in.Target {
	case TargetAccounts:
		fin, err := accountsInput(c, in)
		if err != nil {
			return nil, err
		}
		pl, err := MakePlan(c, now, fin)
		if err != nil {
			return nil, err
		}
		if out.Plan = pl; len(pl.Errors) > 0 {
			return out, rejected(c, now, in, pl)
		}
		if fin.Mapping != nil {
			row, err := fin.Mapping.ToStore()
			if err != nil {
				return nil, err
			}
			row.UpdatedBy, row.UpdatedAt, row.CreatedBy, row.CreatedAt = in.By, now, in.By, now
			if err := c.PutFlatMapping(row); err != nil {
				return nil, err
			}
			if err := c.Audit(now, in.By, "flatfile.mapping_saved", ojson.Object{{Key: "system", Value: in.System},
				{Key: "name", Value: row.Name}, {Key: "via", Value: "directory_import"}}); err != nil {
				return nil, err
			}
			fin.Mapping = nil // apply with the saved row
		}
		res, err := Apply(c, now, fin)
		if err != nil {
			return nil, err
		}
		out.Held, out.HoldID = res.Upload.Held, res.Upload.HoldID
	case TargetPeople:
		p, err := preparePeople(c, in)
		if err != nil {
			return nil, err
		}
		if out.Plan, err = p.plan(c); err != nil {
			return nil, err
		}
		if len(p.errs) > 0 {
			return out, rejected(c, now, in, out.Plan)
		}
		if out.Held, out.HoldID, err = p.apply(c, now); err != nil {
			return nil, err
		}
		out.HeldRestores, out.RestoreHoldID = p.heldRestores, p.restoreHold
	default:
		p, err := prepareEntitlements(c, in)
		if err != nil {
			return nil, err
		}
		if out.Plan, err = p.plan(c); err != nil {
			return nil, err
		}
		if len(p.errs) > 0 {
			return out, rejected(c, now, in, out.Plan)
		}
		if out.Held, out.HoldID, err = p.applyEntitlements(c, now); err != nil {
			return nil, err
		}
	}
	pl := out.Plan
	keys, truncated := changeKeys(pl.Changes)
	err := c.Audit(now, in.By, "directory.import", ojson.Object{{Key: "system", Value: in.System}, {Key: "target", Value: in.Target},
		{Key: "filename", Value: SafeFilename(in.Filename)}, {Key: "sha256", Value: fileSum(in.Raw)}, {Key: "rows", Value: pl.RowsTotal},
		{Key: "added", Value: pl.Added}, {Key: "changed", Value: pl.Changed}, {Key: "removed", Value: pl.Removed - out.Held},
		{Key: "held", Value: out.Held}, {Key: "keys", Value: keys}, {Key: "keys_truncated", Value: truncated}})
	return out, err
}

// maxAuditKeys bounds the keys of each change type a directory.import event names.
const maxAuditKeys = 100

// changeKeys are the external ids an import added, changed and removed, so the ledger says which people and
// entitlements a file touched (their snapshot keeps only the latest rows).
func changeKeys(chs []Change) (ojson.Object, bool) {
	by := map[string][]string{Added: {}, Changed: {}, Removed: {}}
	truncated := false
	for _, ch := range chs {
		if len(by[ch.Type]) >= maxAuditKeys {
			truncated = true
			continue
		}
		by[ch.Type] = append(by[ch.Type], ch.Key)
	}
	return ojson.Object{{Key: "added", Value: by[Added]}, {Key: "changed", Value: by[Changed]}, {Key: "removed", Value: by[Removed]}}, truncated
}

func fileSum(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// rejected records a refused file: nothing else changed, the attempt is kept in the audit ledger.
func rejected(c *store.TenantTx, now time.Time, in ImportInput, pl *Plan) error {
	_, err := c.RecordAudit(store.AuditRecord{At: now, Action: "directory.import", LegacyActor: in.By, Outcome: store.OutcomeFailure,
		TargetType: "directory_import", TargetID: in.System, Detail: ojson.Object{{Key: "system", Value: in.System},
			{Key: "target", Value: in.Target}, {Key: "filename", Value: SafeFilename(in.Filename)}, {Key: "sha256", Value: fileSum(in.Raw)},
			{Key: "rows", Value: pl.RowsTotal},
			{Key: "errors", Value: len(pl.Errors)}}})
	return err
}

// ---------------------------------------------------------------- shared

// dirPrep is a people or entitlements file read, validated and compared with the snapshot.
type dirPrep struct {
	in    ImportInput
	kind  string // store.ImportPeople | store.ImportEntitlements
	recs  []Record
	errs  []RowError
	total int
	prev  []*store.ImportRecord
	delta Delta

	heldRestores int    // set by reactivate: the restores the guard held
	restoreHold  string // and the hold they wait in
}

func snapshotAsFlat(rows []*store.ImportRecord) []*store.FlatRecord {
	out := make([]*store.FlatRecord, len(rows))
	for i, r := range rows {
		out[i] = &store.FlatRecord{System: r.System, Kind: r.Kind, Key: r.Key, Data: r.Data, Hash: r.Hash}
	}
	return out
}

// header picks the columns of a file: the required ones must be there, the optional ones are read when they are.
func header(t *Table, required, optional []string) (*columns, []RowError) {
	have := map[string]bool{}
	for _, h := range t.Header {
		have[strings.ToLower(h)] = true
	}
	names := append([]string(nil), required...)
	for _, o := range optional {
		if have[o] {
			names = append(names, o)
		}
	}
	cols := resolve(t.Header, names...)
	return cols, cols.errs
}

func rowFail(errs *[]RowError, bad *bool, e *RowError) {
	if e != nil {
		*errs, *bad = append(*errs, *e), true
	}
}

func (d *dirPrep) finish(c *store.TenantTx) error {
	prev, err := c.ImportRecords(d.in.System, d.kind)
	if err != nil {
		return err
	}
	if d.kind == store.ImportPeople {
		if prev, err = reconcilePeople(c, prev); err != nil {
			return err
		}
	}
	d.prev = prev
	if len(d.errs) == 0 {
		d.delta = Diff(d.kind, snapshotAsFlat(prev), d.recs)
		if d.kind == store.ImportPeople {
			d.delta.Removed = stillActive(d.delta.Removed, prev)
		}
	}
	sortErrors(d.errs)
	return nil
}

// endedKey is the snapshot's private note of when this source ended a person: the terminated_at it applied, or
// asked the deletion guard for. It is not a column (no file or form can set it), fieldsOf leaves it out and the
// row hash never covers it. A terminated person is taken back by this source only while their terminated_at is
// still this value: an admin's termination, a leaver plan or any later end writes another time and wins.
const endedKey = "~ended_at"

// ItemReactivatePerson is the kind of a held restore of a person this source ended and its file lists active again.
const ItemReactivatePerson = "person_reactivate"

// endedRecord is a people snapshot row turned to the state an applied removal leaves: the person is terminated.
// The row carries no end note; the caller stamps one when this source did the ending.
func endedRecord(r *store.ImportRecord) *store.ImportRecord {
	f := fieldsOf(r.Data)
	f["status"] = "terminated"
	nr := newRecord(r.Key, f["email"], f)
	out := *r
	out.Data, out.Hash = nr.Data(), nr.Hash
	return &out
}

// endedNote is the end note of a snapshot row, "" when it has none.
func endedNote(data string) string {
	m := map[string]string{}
	_ = json.Unmarshal([]byte(data), &m)
	return m[endedKey]
}

// withEndedNote is r with its end note set to at ("" removes it); the hash is left alone.
func withEndedNote(r *store.ImportRecord, at string) *store.ImportRecord {
	m := map[string]string{}
	_ = json.Unmarshal([]byte(r.Data), &m)
	if at == "" {
		delete(m, endedKey)
	} else {
		m[endedKey] = at
	}
	b, _ := json.Marshal(m)
	out := *r
	out.Data = string(b)
	return &out
}

// endedBySource says whether i's termination is the one this source's snapshot row records: i is terminated and
// its terminated_at is the time the source applied or asked for. Anything else (an admin, a leaver plan, the
// sponsor, another source, a second termination after a rehire) ended the person, and an import never undoes it.
func endedBySource(row *store.ImportRecord, i *store.Identity) bool {
	if row == nil || i == nil || i.Status != "terminated" || i.TerminatedAt == nil {
		return false
	}
	note := endedNote(row.Data)
	return note != "" && note == timeutil.DB(*i.TerminatedAt)
}

// reconcilePeople makes the snapshot say what the directory says for the people this source ended: a row still
// marked active whose person was ended by this source (a removal the deletion guard held and a second admin has
// since released) is read as terminated, so a file that lists the person active again restores them instead of
// reading as unchanged. A person someone else terminated keeps their row as it is: the import does not take
// the termination as its own.
func reconcilePeople(c *store.TenantTx, prev []*store.ImportRecord) ([]*store.ImportRecord, error) {
	if len(prev) == 0 {
		return prev, nil
	}
	all, err := c.Identities()
	if err != nil {
		return nil, err
	}
	byXID := map[string]*store.Identity{}
	for _, i := range all {
		byXID[i.ExternalID] = i
	}
	out := make([]*store.ImportRecord, len(prev))
	for n, r := range prev {
		out[n] = r
		if fieldsOf(r.Data)["status"] != "terminated" && endedBySource(r, byXID[r.Key]) {
			out[n] = withEndedNote(endedRecord(r), endedNote(r.Data))
		}
	}
	return out, nil
}

// stillActive drops the removals of people the snapshot already has as terminated: there is nothing left to end.
func stillActive(removed []Change, prev []*store.ImportRecord) []Change {
	ended := map[string]bool{}
	for _, r := range prev {
		if fieldsOf(r.Data)["status"] == "terminated" {
			ended[r.Key] = true
		}
	}
	out := removed[:0:0]
	for _, r := range removed {
		if !ended[r.Key] {
			out = append(out, r)
		}
	}
	return out
}

func (d *dirPrep) basePlan() *Plan {
	pl := &Plan{System: d.in.System, Kind: d.in.Target, RowsTotal: d.total, Errors: d.errs}
	if len(d.errs) == 0 {
		all := d.delta.All()
		pl.Changes = all
		pl.Added, pl.Changed, pl.Removed, pl.Unchanged = len(d.delta.Added), len(d.delta.Changed), len(d.delta.Removed), d.delta.Unchanged
	}
	return pl
}

// store writes the snapshot. keep are removals the guard held (their rows stay); heldBack are restores the guard
// held (their rows stay terminated, with their end note, until the hold is released or the file asks again).
func (d *dirPrep) store(c *store.TenantTx, now time.Time, keep, heldBack map[string]bool) error {
	for _, r := range d.delta.Removed {
		if keep[r.Key] {
			continue // the guard held it: still this source's, and still to be removed
		}
		if d.kind == store.ImportPeople {
			// the person stays this source's, now terminated: a later file that lists them again is no conflict
			for _, p := range d.prev {
				if p.Key == r.Key {
					e := endedRecord(p)
					e.ImportedBy, e.ImportedAt = d.in.importer(), now
					if err := c.PutImportRecord(e); err != nil {
						return err
					}
				}
			}
			continue
		}
		if err := c.DeleteImportRecord(d.in.System, d.kind, r.Key); err != nil {
			return err
		}
	}
	touched := map[string]bool{}
	for _, r := range d.delta.Added {
		touched[r.Key] = true
	}
	for _, r := range d.delta.Changed {
		touched[r.Key] = true
	}
	for _, r := range d.recs {
		if touched[r.Key] && !heldBack[r.Key] {
			if err := c.PutImportRecord(&store.ImportRecord{System: d.in.System, Kind: d.kind, Key: r.Key, Data: r.Data(), Hash: r.Hash,
				ImportedBy: d.in.importer(), ImportedAt: now}); err != nil {
				return err
			}
		}
	}
	return nil
}

func fieldsOf(data string) map[string]string {
	m := map[string]string{}
	_ = json.Unmarshal([]byte(data), &m) // an unreadable old row is an empty one
	delete(m, endedKey)
	return m
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ---------------------------------------------------------------- people

func preparePeople(c *store.TenantTx, in ImportInput) (*dirPrep, error) {
	d := &dirPrep{in: in, kind: store.ImportPeople}
	tbl, errs := ParseWith(in.Raw, DirectoryLimits)
	if tbl == nil {
		d.errs = errs
		return d, nil
	}
	d.total = tbl.Total
	cols, cerrs := header(tbl, PeopleRequired, PeopleColumns)
	if len(cerrs) > 0 {
		d.errs = cerrs
		return d, nil
	}
	errs = cloneErrors(tbl.Short)
	rowOf := map[string]int{}
	byEmail := map[string]int{}
	for _, row := range tbl.Rows {
		bad := false
		for _, n := range PeopleColumns {
			if _, ok := cols.idx[n]; ok {
				rowFail(&errs, &bad, checkCell(row.Num, n, cols.get(row, n)))
			}
		}
		if bad {
			continue
		}
		email, name := strings.ToLower(cols.get(row, "email")), cols.get(row, "name")
		xid := cols.get(row, "external_id")
		if xid == "" {
			xid = email
		}
		status := strings.ToLower(cols.get(row, "status"))
		mgr := strings.ToLower(cols.get(row, "manager_email"))
		switch {
		case email == "":
			rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "email", Code: CodeRequired, Message: "a value is required"})
		case HasFormulaPrefix(email):
			rowFail(&errs, &bad, checkKey(row.Num, "email", email))
		case !validEmail(email):
			rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "email", Code: CodeInvalidEmail, Message: fmt.Sprintf("%s is not an email address", show(email))})
		}
		if name == "" {
			rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "name", Code: CodeRequired, Message: "a value is required"})
		}
		rowFail(&errs, &bad, checkKey(row.Num, "external_id", xid))
		if mgr != "" && !validEmail(mgr) {
			rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "manager_email", Code: CodeInvalidEmail, Message: fmt.Sprintf("%s is not an email address", show(mgr))})
		}
		switch status {
		case "", "active":
			status = "active"
		case "terminated":
		default:
			rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "status", Code: CodeInvalidStatus,
				Message: fmt.Sprintf("the status %s is not active or terminated", show(status))})
		}
		if !bad {
			if first, dup := rowOf[xid]; dup {
				rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "external_id", Code: CodeDuplicateKey, Message: fmt.Sprintf("the person %s is already in row %d", show(xid), first)})
			} else if first, dup := byEmail[email]; dup {
				rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "email", Code: CodeDuplicateKey, Message: fmt.Sprintf("the email %s is already in row %d", show(email), first)})
			}
		}
		if bad {
			continue
		}
		rowOf[xid], byEmail[email] = row.Num, row.Num
		d.recs = append(d.recs, newRecord(xid, email, map[string]string{"external_id": xid, "email": email, "name": Neutralize(name),
			"department": Neutralize(cols.get(row, "department")), "title": Neutralize(cols.get(row, "title")), "manager_email": mgr, "status": status}))
	}
	d.errs = errs
	if err := d.finish(c); err != nil {
		return nil, err
	}
	if len(d.errs) == 0 {
		d.errs = append(d.errs, peopleConflicts(c, d, rowOf)...)
		if len(d.errs) > 0 {
			sortErrors(d.errs)
			d.delta = Delta{}
		}
	}
	return d, nil
}

// peopleConflicts refuses a row that would take over a person another source owns: the same external id, or
// the same email under another external id, held by an identity this source did not import.
func peopleConflicts(c *store.TenantTx, d *dirPrep, rowOf map[string]int) []RowError {
	ours := map[string]bool{}
	for _, p := range d.prev {
		ours[p.Key] = true
	}
	all, err := c.Identities()
	if err != nil {
		return []RowError{{Code: "internal", Message: "could not read the directory"}}
	}
	byXID, byEmail := map[string]*store.Identity{}, map[string]*store.Identity{}
	for _, i := range all {
		byXID[i.ExternalID] = i
		if i.Email != nil {
			byEmail[strings.ToLower(*i.Email)] = i
		}
	}
	var errs []RowError
	for _, r := range d.recs {
		if i, ok := byXID[r.Key]; ok && !ours[r.Key] {
			errs = append(errs, RowError{Row: rowOf[r.Key], Column: "external_id", Code: CodeOwnedElsewhere,
				Message: fmt.Sprintf("%s is already in the directory from another source; an import does not take over its people", show(i.Name))})
			continue
		}
		if i, ok := byEmail[r.Fields["email"]]; ok && i.ExternalID != r.Key {
			errs = append(errs, RowError{Row: rowOf[r.Key], Column: "email", Code: CodeEmailInUse,
				Message: fmt.Sprintf("the email %s belongs to another person in the directory (%s)", show(r.Fields["email"]), show(i.Name))})
		}
	}
	return errs
}

func (d *dirPrep) plan(c *store.TenantTx) (*Plan, error) {
	pl := d.basePlan()
	if len(d.errs) == 0 && d.kind == store.ImportPeople {
		var err error
		if pl.Claims, err = d.claims(c); err != nil {
			return nil, err
		}
	}
	if len(d.errs) > 0 || pl.Removed == 0 {
		return pl, nil
	}
	return pl, d.guard(c, pl)
}

// claims finds, per person the file adds or changes, the existing accounts in other systems that have no owner
// and carry the person's email (as username or account id): ingest correlates an account to an identity by email
// when the tenant's correlation order has it, so the next sync of that system hands the person those accounts.
func (d *dirPrep) claims(c *store.TenantTx) ([]Claim, error) {
	rules, _, err := idrules.Load(c)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(rules.CorrelationOrder, idrules.KeyEmail) {
		return nil, nil
	}
	touched := map[string]bool{}
	for _, ch := range d.delta.Added {
		touched[ch.Key] = true
	}
	for _, ch := range d.delta.Changed {
		touched[ch.Key] = true
	}
	if len(touched) == 0 {
		return nil, nil
	}
	accts, err := c.Accounts()
	if err != nil {
		return nil, err
	}
	byEmail := map[string]map[string]int{} // email -> system -> accounts
	for _, a := range accts {
		if a.IdentityID != nil || a.System == d.in.System {
			continue
		}
		for _, k := range []string{strings.ToLower(a.Username), strings.ToLower(a.ExternalID)} {
			if !strings.Contains(k, "@") {
				continue
			}
			if byEmail[k] == nil {
				byEmail[k] = map[string]int{}
			}
			byEmail[k][a.System]++
			if k == strings.ToLower(a.Username) {
				break // one account, one claim, though both fields carry the email
			}
		}
	}
	var out []Claim
	for _, r := range d.recs {
		sys := byEmail[r.Fields["email"]]
		if !touched[r.Key] || len(sys) == 0 {
			continue
		}
		cl := Claim{Key: r.Key, Email: r.Fields["email"]}
		for s, n := range sys {
			cl.Accounts += n
			cl.Systems = append(cl.Systems, s)
		}
		sort.Strings(cl.Systems)
		out = append(out, cl)
	}
	return out, nil
}

func (d *dirPrep) guard(c *store.TenantTx, pl *Plan) error {
	switch d.kind {
	case store.ImportPeople:
		// the source's own size is the basis, as ingest judges it (SourceID and Population of apply)
		pop := len(d.prev)
		ref := deleteguard.SourceRef{Kind: deleteguard.SrcConnection, ID: d.in.System}
		gone := 0
		for _, r := range d.delta.Removed {
			if i, err := c.IdentityByExternalID(r.Key); err == nil && i.Status == "active" {
				gone++
			}
		}
		prev, err := deleteguard.PreviousCount(c, ref, deleteguard.CatIdentities, pop)
		if err != nil {
			return err
		}
		sanity, err := deleteguard.CheckFeed(c, ref, deleteguard.CatIdentities, prev, len(d.recs), "")
		if err != nil {
			return err
		}
		pl.Guard, err = previewGuard(c, deleteguard.CatIdentities, gone, pop, sanity)
		return err
	default:
		pl.Guard = nil
		var err error
		pl.Guard, err = previewGuard(c, deleteguard.CatGroups, len(d.delta.Removed), len(d.prev), deleteguard.FeedChecks(len(d.prev), len(d.recs), ""))
		return err
	}
}

// endedAt is when a person ended: the time already recorded for one who is terminated, else now. A re-import
// of a terminated row does not move the date.
func endedAt(c *store.TenantTx, xid string, now time.Time) time.Time {
	if i, err := c.IdentityByExternalID(xid); err == nil && i.Status == "terminated" && i.TerminatedAt != nil {
		return *i.TerminatedAt
	}
	return now
}

// apply writes the people through ingest.Import (identities, the manager reference, the deletion guard's
// vetting of every person turned inactive) and updates the snapshot. It answers how many removals were held.
func (d *dirPrep) apply(c *store.TenantTx, now time.Time) (held int, holdID string, err error) {
	// the source is its own guard key: its removals and feed are judged against its size, not the tenant's
	res := &connectors.DiscoveryResult{System: d.in.System, SourceID: d.in.System, Population: len(d.prev), FeedRecords: len(d.recs)}
	for _, r := range d.recs {
		f := r.Fields
		rec := connectors.IdentityRecord{ExternalID: r.Key, Name: f["name"], Type: "human", Email: strp(f["email"]),
			Department: strp(f["department"]), Title: strp(f["title"]), Status: f["status"]}
		if f["manager_email"] != "" {
			rec.Manager = &connectors.IdentityRef{Email: f["manager_email"]}
		}
		if f["status"] == "terminated" {
			t := endedAt(c, r.Key, now)
			rec.TerminatedAt = &t
		}
		res.Identities = append(res.Identities, rec)
	}
	prevData := map[string]string{}
	for _, p := range d.prev {
		prevData[p.Key] = p.Data
	}
	for _, r := range d.delta.Removed {
		f := fieldsOf(prevData[r.Key])
		t := endedAt(c, r.Key, now)
		res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: r.Key, Name: f["name"], Type: "human",
			Email: strp(f["email"]), Department: strp(f["department"]), Title: strp(f["title"]), Status: "terminated", TerminatedAt: &t})
	}
	// who is active before the import: an end note is only for a person this import itself ends
	wasActive := map[string]bool{}
	for _, rec := range res.Identities {
		if rec.Status == "terminated" {
			if i, err := c.IdentityByExternalID(rec.ExternalID); err == nil && i.Status == "active" {
				wasActive[rec.ExternalID] = true
			} else if err != nil && !errors.Is(err, store.ErrNotFound) {
				return 0, "", err
			}
		}
	}
	// ingest keeps a terminated person terminated; a person this source ended and its file lists active again is
	// taken back here, through the deletion guard (peopleConflicts already refused anyone another source owns)
	heldBack, err := d.reactivate(c, now)
	if err != nil {
		return 0, "", err
	}
	st, err := ingest.Import(c, now, res)
	if err != nil {
		return 0, "", err
	}
	keep := map[string]bool{}
	for _, r := range d.delta.Removed {
		if i, err := c.IdentityByExternalID(r.Key); err == nil && i.Status == "active" {
			held++
			keep[r.Key] = true
		}
	}
	if held > 0 {
		holdID = st.IdentityHoldID
	}
	if err := d.store(c, now, keep, heldBack); err != nil {
		return 0, "", err
	}
	// the end notes: the terminated_at this import applied, or asked the guard for when it held the end
	notes := map[string]string{}
	for _, rec := range res.Identities {
		if rec.Status != "terminated" || !wasActive[rec.ExternalID] {
			continue
		}
		i, err := c.IdentityByExternalID(rec.ExternalID)
		if err != nil {
			return 0, "", err
		}
		switch {
		case i.Status == "terminated" && i.TerminatedAt != nil:
			notes[rec.ExternalID] = timeutil.DB(*i.TerminatedAt)
		case i.Status == "active" && rec.TerminatedAt != nil:
			notes[rec.ExternalID] = timeutil.DB(*rec.TerminatedAt)
		}
	}
	return held, holdID, d.stampEnded(c, notes)
}

// reactivate takes back the people this source ended and its file lists active again. Only a termination the
// source's snapshot records as its own is undone (endedBySource); the deletion guard vets the batch as it vets
// removals, so a file cannot restore people in bulk without a second admin. It answers the people held.
func (d *dirPrep) reactivate(c *store.TenantTx, now time.Time) (map[string]bool, error) {
	prevBy := map[string]*store.ImportRecord{}
	for _, p := range d.prev {
		prevBy[p.Key] = p
	}
	var items []deleteguard.Item
	for _, r := range d.recs {
		row, ok := prevBy[r.Key]
		if !ok || r.Fields["status"] == "terminated" {
			continue
		}
		i, err := c.IdentityByExternalID(r.Key)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !endedBySource(row, i) {
			continue
		}
		ref, err := json.Marshal(reactivateRef{System: d.in.System, ExternalID: r.Key, EndedAt: endedNote(row.Data)})
		if err != nil {
			return nil, err
		}
		items = append(items, deleteguard.Item{Kind: ItemReactivatePerson, Ref: string(ref),
			Label: fmt.Sprintf("%s (%s) made active again by an import of %s", i.Name, r.Key, d.in.System)})
	}
	heldBack := map[string]bool{}
	if len(items) == 0 {
		return heldBack, nil
	}
	dec, err := deleteguard.AdmitWith(c, now, deleteguard.Request{Category: deleteguard.CatIdentities, Source: deleteguard.SourceConnector,
		SourceID: d.in.System, Correlation: "dirimport:reactivate:" + d.in.System, Population: len(d.prev), Items: items})
	if err != nil {
		return nil, err
	}
	for _, it := range dec.Applied {
		var k reactivateRef
		if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
			return nil, err
		}
		if err := reactivatePerson(c, now, d.in.By, k, ""); err != nil {
			return nil, err
		}
	}
	for _, it := range dec.Held {
		var k reactivateRef
		if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
			return nil, err
		}
		heldBack[k.ExternalID] = true
	}
	if len(dec.Held) > 0 {
		d.heldRestores, d.restoreHold = len(dec.Held), dec.HoldID
	}
	return heldBack, nil
}

// reactivateRef is a held restore: the source, the person and the end note the restore undoes.
type reactivateRef struct {
	System     string `json:"system"`
	ExternalID string `json:"external_id"`
	EndedAt    string `json:"ended_at"`
}

// reactivatePerson makes the person active again and records it in the audit ledger.
func reactivatePerson(c *store.TenantTx, now time.Time, by string, k reactivateRef, holdID string) error {
	if err := c.ReactivateIdentity(k.ExternalID); err != nil {
		return err
	}
	detail := ojson.Object{{Key: "system", Value: k.System}, {Key: "external_id", Value: k.ExternalID}, {Key: "ended_at", Value: k.EndedAt}}
	if holdID != "" {
		detail = append(detail, ojson.KV{Key: "hold_id", Value: holdID})
	}
	_, err := c.RecordAudit(store.AuditRecord{At: now, Action: "directory.person_reactivated", LegacyActor: by,
		TargetType: "identity", TargetID: k.ExternalID, Detail: detail})
	return err
}

// ReleaseReactivate applies a held restore if the person is still terminated by the same end of the same source.
func ReleaseReactivate(c *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (outcome, note string, err error) {
	var k reactivateRef
	if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
		return "", "", fmt.Errorf("flatfile: bad held restore: %w", err)
	}
	i, err := c.IdentityByExternalID(k.ExternalID)
	if errors.Is(err, store.ErrNotFound) {
		return deleteguard.ItemGone, "the person no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	if i.Status != "terminated" {
		return deleteguard.ItemGone, "the person is already " + i.Status, nil
	}
	if i.TerminatedAt == nil || timeutil.DB(*i.TerminatedAt) != k.EndedAt {
		return deleteguard.ItemGone, "the person was terminated again since, not by this source", nil
	}
	if src, err := c.ImportRecordSource(store.ImportPeople, k.ExternalID); err != nil {
		return "", "", err
	} else if src != k.System {
		return deleteguard.ItemGone, "the person is no longer in this source", nil
	}
	if err := reactivatePerson(c, now, "deletion_guard", k, it.HoldID); err != nil {
		return "", "", err
	}
	return deleteguard.ItemReleased, "", nil
}

// stampEnded writes the end notes onto the snapshot rows of the people this import ended.
func (d *dirPrep) stampEnded(c *store.TenantTx, notes map[string]string) error {
	if len(notes) == 0 {
		return nil
	}
	rows, err := c.ImportRecords(d.in.System, d.kind)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if at, ok := notes[r.Key]; ok && endedNote(r.Data) != at {
			if err := c.PutImportRecord(withEndedNote(r, at)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- entitlements

var entitlementKinds = map[string]bool{"group": true, "role": true, "team": true, "security_group": true}

func prepareEntitlements(c *store.TenantTx, in ImportInput) (*dirPrep, error) {
	d := &dirPrep{in: in, kind: store.ImportEntitlements}
	tbl, errs := ParseWith(in.Raw, DirectoryLimits)
	if tbl == nil {
		d.errs = errs
		return d, nil
	}
	d.total = tbl.Total
	cols, cerrs := header(tbl, EntitlementRequired, EntitlementColumns)
	if len(cerrs) > 0 {
		d.errs = cerrs
		return d, nil
	}
	errs = cloneErrors(tbl.Short)
	rowOf := map[string]int{}
	for _, row := range tbl.Rows {
		bad := false
		for _, n := range EntitlementColumns {
			if _, ok := cols.idx[n]; ok {
				rowFail(&errs, &bad, checkCell(row.Num, n, cols.get(row, n)))
			}
		}
		if bad {
			continue
		}
		name, xid := cols.get(row, "name"), cols.get(row, "external_id")
		if xid == "" {
			xid = name
		}
		kind := strings.ToLower(cols.get(row, "kind"))
		priv := strings.ToLower(cols.get(row, "privileged"))
		if name == "" {
			rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "name", Code: CodeRequired, Message: "a value is required"})
		}
		rowFail(&errs, &bad, checkKey(row.Num, "external_id", xid))
		if kind == "" {
			kind = "group"
		} else if !entitlementKinds[kind] {
			rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "kind", Code: CodeInvalidKind,
				Message: fmt.Sprintf("the kind %s is not one of group, role, team, security_group", show(kind))})
		}
		switch {
		case trueValues[priv]:
			priv = "true"
		case falseValues[priv]:
			priv = "false"
		default:
			rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "privileged", Code: CodeInvalidValue, Message: fmt.Sprintf("%s is not yes or no", show(priv))})
		}
		if !bad {
			if first, dup := rowOf[xid]; dup {
				rowFail(&errs, &bad, &RowError{Row: row.Num, Column: "external_id", Code: CodeDuplicateKey, Message: fmt.Sprintf("the entitlement %s is already in row %d", show(xid), first)})
			}
		}
		if bad {
			continue
		}
		rowOf[xid] = row.Num
		d.recs = append(d.recs, newRecord(xid, name, map[string]string{"external_id": xid, "name": Neutralize(name), "kind": kind,
			"privileged": priv, "description": Neutralize(cols.get(row, "description"))}))
	}
	d.errs = errs
	if err := d.finish(c); err != nil {
		return nil, err
	}
	if len(d.errs) == 0 {
		conflicts, err := entitlementConflicts(c, d, rowOf)
		if err != nil {
			return nil, err
		}
		if len(conflicts) > 0 {
			d.errs = conflicts
			sortErrors(d.errs)
			d.delta = Delta{}
		}
	}
	return d, nil
}

// entitlementConflicts refuses a row that would take over a group of the system this source did not import:
// one another feed wrote to the same system (a connector that started writing to it after the source was
// named, an agent listing). An import changes and retires only the entitlements it created.
func entitlementConflicts(c *store.TenantTx, d *dirPrep, rowOf map[string]int) ([]RowError, error) {
	ours := map[string]bool{}
	for _, p := range d.prev {
		ours[p.Key] = true
	}
	var errs []RowError
	for _, r := range d.recs {
		if ours[r.Key] {
			continue
		}
		g, err := c.GroupByXID(d.in.System, r.Key)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		errs = append(errs, RowError{Row: rowOf[r.Key], Column: "external_id", Code: CodeOwnedElsewhere,
			Message: fmt.Sprintf("%s is already in the directory from another source; an import does not take over its entitlements", show(g.Name))})
	}
	return errs, nil
}

// ReleaseRetire applies a held retirement: the entitlement stops being requestable. Grants stay, so a review
// still sees who holds it.
func ReleaseRetire(c *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (outcome, note string, err error) {
	var k [2]string
	if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
		return "", "", err
	}
	g, err := c.GroupByXID(k[0], k[1])
	if errors.Is(err, store.ErrNotFound) {
		return deleteguard.ItemGone, "the entitlement no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	if !g.Requestable {
		_ = c.DeleteImportRecord(k[0], store.ImportEntitlements, k[1])
		return deleteguard.ItemGone, "the entitlement is already retired", nil
	}
	if err := retire(c, g); err != nil {
		return "", "", err
	}
	if err := c.DeleteImportRecord(k[0], store.ImportEntitlements, k[1]); err != nil {
		return "", "", err
	}
	return deleteguard.ItemReleased, "", nil
}

func retire(c *store.TenantTx, g *store.Group) error {
	g.Requestable = false
	return c.UpsertGroup(g)
}

// applyEntitlements writes the entitlements as groups of the manual source. A removal retires the entitlement (it is no
// longer requestable; existing grants stay for review) after the deletion guard has admitted it.
func (d *dirPrep) applyEntitlements(c *store.TenantTx, now time.Time) (held int, holdID string, err error) {
	res := &connectors.DiscoveryResult{System: d.in.System}
	for _, r := range d.recs {
		f := r.Fields
		// requestable is set when the entitlement is created only: a catalog admin may have changed it since
		requestable := true
		if g, err := c.GroupByXID(d.in.System, r.Key); err == nil {
			requestable = g.Requestable
		} else if !errors.Is(err, store.ErrNotFound) {
			return 0, "", err
		}
		res.Groups = append(res.Groups, connectors.GroupRecord{System: d.in.System, ExternalID: r.Key, Name: f["name"], Kind: f["kind"],
			Privileged: f["privileged"] == "true", Requestable: requestable, Description: strp(f["description"])})
	}
	if _, err := ingest.Import(c, now, res); err != nil {
		return 0, "", err
	}
	keep := map[string]bool{}
	var items []deleteguard.Item
	live := map[string]*store.Group{}
	for _, r := range d.delta.Removed {
		g, err := c.GroupByXID(d.in.System, r.Key)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return 0, "", err
		}
		if !g.Requestable {
			continue
		}
		ref, err := json.Marshal([2]string{d.in.System, r.Key})
		if err != nil {
			return 0, "", err
		}
		live[string(ref)] = g
		items = append(items, deleteguard.Item{Kind: ItemRetireEntitlement, Ref: string(ref),
			Label: fmt.Sprintf("entitlement %s in %s retired by an import", g.Name, d.in.System)})
	}
	if len(items) > 0 {
		dec, err := deleteguard.AdmitWith(c, now, deleteguard.Request{Category: deleteguard.CatGroups, Source: deleteguard.SourceConnector,
			SourceID: d.in.System, Correlation: "dirimport:" + d.in.System, SourceDriven: true,
			Sanity: deleteguard.FeedChecks(len(d.prev), len(d.recs), ""), PrevCount: len(d.prev), NewCount: len(d.recs), Items: items})
		if err != nil {
			return 0, "", err
		}
		for _, it := range dec.Applied {
			if err := retire(c, live[it.Ref]); err != nil {
				return 0, "", err
			}
		}
		for _, it := range dec.Held {
			var k [2]string
			if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
				return 0, "", err
			}
			keep[k[1]] = true
		}
		held, holdID = len(dec.Held), dec.HoldID
	}
	return held, holdID, d.store(c, now, keep, nil)
}

// ---------------------------------------------------------------- one record (the create and edit forms)

// RecordInput is one object a form creates or edits in a manual source.
type RecordInput struct {
	System string
	Name   string // display name of a new source
	Target string
	// Fields by canonical column name (AccountColumns, PeopleColumns, EntitlementColumns).
	Fields map[string]string
	By     string
	ByUser string // see ImportInput
	// Reserved: see ImportInput.
	Reserved map[string]bool
}

// UpsertRecord adds or replaces one row of a manual source's snapshot and applies the result, the same
// as importing a file that holds every row the source has plus this one. Only rows of a manual source are
// editable: a source a connector owns is refused by checkSource.
func UpsertRecord(c *store.TenantTx, now time.Time, in RecordInput) (*ImportOutcome, error) {
	if !ValidTarget(in.Target) {
		return nil, &Error{"invalid_target", "target must be people, accounts or entitlements"}
	}
	var cols []string
	switch in.Target {
	case TargetPeople:
		cols = PeopleColumns
	case TargetEntitlements:
		cols = EntitlementColumns
	default:
		cols = AccountColumns
	}
	known := map[string]bool{}
	for _, n := range cols {
		known[n] = true
	}
	for k := range in.Fields {
		if !known[k] {
			return nil, &Error{"invalid_field", "unknown field " + show(k)}
		}
	}
	if err := checkSource(c, in.System, in.Reserved); err != nil {
		return nil, err
	}
	colName, rows, err := currentRows(c, in)
	if err != nil {
		return nil, err
	}
	key := recordKey(in.Target, in.Fields)
	replaced := false
	for i, r := range rows {
		if key != "" && recordKey(in.Target, r) == key {
			rows[i], replaced = mergeFields(r, in.Fields), true
		}
	}
	if !replaced {
		rows = append(rows, in.Fields)
	}
	var header []string
	for _, n := range cols {
		if colName[n] != "" {
			header = append(header, n)
		}
	}
	var b strings.Builder
	w := csv.NewWriter(&b)
	names := make([]string, len(header))
	for i, n := range header {
		names[i] = colName[n]
	}
	_ = w.Write(names)
	for _, r := range rows {
		line := make([]string, len(header))
		for i, n := range header {
			line[i] = r[n]
		}
		_ = w.Write(line)
	}
	w.Flush()
	return ApplyImport(c, now, ImportInput{System: in.System, Name: in.Name, Target: in.Target, Filename: "form.csv", Raw: []byte(b.String()), By: in.By, ByUser: in.ByUser,
		Reserved: in.Reserved})
}

func mergeFields(old, upd map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range old {
		out[k] = v
	}
	for k, v := range upd {
		out[k] = v
	}
	return out
}

func recordKey(target string, f map[string]string) string {
	switch target {
	case TargetAccounts:
		return f["account_id"]
	case TargetPeople:
		if f["external_id"] != "" {
			return f["external_id"]
		}
		return strings.ToLower(f["email"])
	}
	if f["external_id"] != "" {
		return f["external_id"]
	}
	return f["name"]
}

// currentRows are the rows the source holds now by canonical field name, and the header name of each field in
// the file the source takes ("" for a field its mapping does not carry).
func currentRows(c *store.TenantTx, in RecordInput) (colName map[string]string, rows []map[string]string, err error) {
	ident := func(cols []string) map[string]string {
		m := map[string]string{}
		for _, n := range cols {
			m[n] = n
		}
		return m
	}
	switch in.Target {
	case TargetPeople:
		recs, err := c.ImportRecords(in.System, store.ImportPeople)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range recs {
			rows = append(rows, fieldsOf(r.Data))
		}
		return ident(PeopleColumns), rows, nil
	case TargetEntitlements:
		recs, err := c.ImportRecords(in.System, store.ImportEntitlements)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range recs {
			f := fieldsOf(r.Data)
			if f["privileged"] == "true" {
				f["privileged"] = "yes"
			} else {
				f["privileged"] = "no"
			}
			rows = append(rows, f)
		}
		return ident(EntitlementColumns), rows, nil
	}
	// accounts: the file header is the mapping's own column names
	m := CanonicalMapping(in.System, in.Name)
	if ms, err := c.FlatMapping(in.System); err == nil {
		if m, err = FromStore(ms); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	a := m.Accounts
	colName = map[string]string{"account_id": a.AccountID, "username": a.Username, "email": a.Email, "identity_id": a.IdentityID, "status": a.Status}
	recs, err := c.FlatRecords(in.System, KindAccounts)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range recs {
		rows = append(rows, fieldsOf(r.Data))
	}
	return colName, rows, nil
}

// RecordFields reads the fields of a stored row, by canonical column name.
func RecordFields(data string) map[string]string { return fieldsOf(data) }
