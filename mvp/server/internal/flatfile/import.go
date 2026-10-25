package flatfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Upload sources. The API takes the file in a request; a later SFTP drop
// calls Apply with the file it fetched and Source "sftp".
const (
	SourceAPI  = "api"
	SourceSFTP = "sftp"
)

// MaxStoredErrors bounds the rejected rows kept per upload; the upload's
// rows_rejected still counts every one.
const MaxStoredErrors = 200

// Input is one file to import.
type Input struct {
	System   string
	Kind     string // accounts | entitlements
	Source   string // api (default) | sftp
	Filename string
	Raw      []byte
	By       string // who uploaded it: the actor of the audit events
}

// Result is what an upload did. An upload with any invalid row is rejected
// whole (Upload.Status "rejected", Errors lists every bad row) and changes
// nothing but the history; the caller still commits, so the attempt is kept.
type Result struct {
	Upload    *store.FlatUpload
	Errors    []RowError // every rejected row (only MaxStoredErrors are stored)
	Changes   []Change
	Confirmed []*store.FlatTask
}

// Apply imports one file for a disconnected app, in the caller's transaction:
// it parses and validates the file with the app's mapping, computes the delta
// against the last applied file of that kind, records the upload (and, for a
// rejected one, each bad row), feeds the accounts and entitlements to the
// graph through the normal ingest path (so they correlate, review and show in
// SoD and orphan reports like any connector's), and confirms the manual tasks
// the file shows done. Every step is audited in the same transaction.
func Apply(c *store.TenantTx, now time.Time, in Input) (*Result, error) {
	if in.Kind != KindAccounts && in.Kind != KindEntitlements {
		return nil, &Error{"invalid_kind", "kind must be accounts or entitlements"}
	}
	ms, err := c.FlatMapping(in.System)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoMapping
	}
	if err != nil {
		return nil, err
	}
	m, err := FromStore(ms)
	if err != nil {
		return nil, err
	}
	if in.Kind == KindEntitlements && m.Entitlements == nil {
		return nil, &Error{"no_entitlement_mapping", "this app's mapping has no entitlement columns"}
	}
	sum := sha256.Sum256(in.Raw)
	up := &store.FlatUpload{ID: store.NewID(), MappingID: ms.ID, System: in.System, Kind: in.Kind, Source: in.Source,
		Filename: SafeFilename(in.Filename), SHA256: hex.EncodeToString(sum[:]), SizeBytes: len(in.Raw), UploadedBy: in.By,
		UploadedAt: now}
	if up.Source == "" {
		up.Source = SourceAPI
	}
	prevAccounts, err := c.FlatRecords(in.System, KindAccounts)
	if err != nil {
		return nil, err
	}
	prevEnts, err := c.FlatRecords(in.System, KindEntitlements)
	if err != nil {
		return nil, err
	}

	var recs []Record
	tbl, errs := Parse(in.Raw)
	if tbl != nil {
		up.RowsTotal = tbl.Total
		if in.Kind == KindAccounts {
			recs, errs = m.AccountRecords(tbl)
		} else {
			known := make(map[string]bool, len(prevAccounts))
			for _, a := range prevAccounts {
				known[a.Key] = true
			}
			recs, errs = m.EntitlementRecords(tbl, known)
		}
	}
	if len(errs) > 0 {
		return reject(c, now, up, errs)
	}

	prev := prevAccounts
	if in.Kind == KindEntitlements {
		prev = prevEnts
	}
	delta := Diff(in.Kind, prev, recs)
	changes := delta.All()

	// Records of the snapshots as this upload leaves them.
	accounts, ents := decode(KindAccounts, prevAccounts), decode(KindEntitlements, prevEnts)
	var cascade []Change
	if in.Kind == KindAccounts {
		accounts = recs
		gone := map[string]bool{}
		for _, r := range delta.Removed {
			gone[r.Key] = true
		}
		kept := ents[:0:0]
		for _, e := range ents {
			if a, _ := SplitEntitlementKey(e.Key); gone[a] {
				cascade = append(cascade, Change{Kind: KindEntitlements, Type: Removed, Key: e.Key, Label: e.Label})
				continue
			}
			kept = append(kept, e)
		}
		ents = kept
		changes = append(changes, cascade...)
	} else {
		ents = recs
	}

	// Manual tasks the new snapshots show done.
	open, err := c.OpenFlatTasks(in.System)
	if err != nil {
		return nil, err
	}
	status := make(map[string]string, len(accounts))
	for _, a := range accounts {
		status[a.Key] = a.Fields["status"]
	}
	entSet := make(map[string]bool, len(ents))
	for _, e := range ents {
		entSet[e.Key] = true
	}
	due := dueTasks(open, in.Kind, status, entSet)
	isDue := map[string]bool{}
	for _, t := range due {
		isDue[t.ID] = true
	}

	up.Held = 0
	// The graph and the removals come before the upload is recorded (the record is append-only and says
	// how many removals the deletion guard held). The snapshot rows below need the upload.
	// The graph. An account whose leaver task is still open stays disabled
	// even though the file still lists it as active: Tessera has decided it
	// goes, and the file has not caught up.
	held := map[string]bool{}
	for _, t := range open {
		if t.Kind == TaskDisableAccount && !isDue[t.ID] {
			held[t.AccountXID] = true
		}
	}
	if _, err := ingest.Import(c, now, discovery(m, accounts, ents, held)); err != nil {
		return nil, err
	}
	feed := feedCheck{}
	if in.Kind == KindAccounts {
		// accounts this file lists are not being dropped: a held drop of one (from an earlier, truncated
		// upload) is withdrawn, so a corrected feed is not undone by releasing the old hold
		listed := make(map[string]bool, len(accounts))
		for _, a := range accounts {
			listed[a.Key] = true
		}
		if _, err := deleteguard.Relist(c, now, deleteguard.CatAccounts, "flatfile:"+in.System, func(it *store.DeletionHoldItem) bool {
			var k [2]string
			return it.Kind == ItemDropAccount && json.Unmarshal([]byte(it.Ref), &k) == nil && k[0] == in.System && listed[k[1]]
		}); err != nil {
			return nil, err
		}
	}
	if in.Kind == KindAccounts && len(delta.Removed) > 0 {
		// the file is the feed: an empty or much shorter one than the last good upload is not trusted to say who is gone
		all, err := c.Accounts()
		if err != nil {
			return nil, err
		}
		for _, a := range all {
			if a.System == in.System && a.Status == "active" {
				feed.prev++
			}
		}
		feed.now = len(accounts)
		feed.sanity = deleteguard.FeedChecks(feed.prev, feed.now, "")
	}
	if in.Kind == KindAccounts {
		// one admission for the whole upload: a hold of n drops costs n rows, not n rewrites of its reason (#486)
		keys := make([]string, len(delta.Removed))
		for i, r := range delta.Removed {
			keys[i] = r.Key
		}
		hid, held, err := dropAccounts(c, now, in.System, keys, feed)
		if err != nil {
			return nil, err
		}
		if held > 0 {
			up.Held += held
			up.HoldID = hid
		}
	} else {
		for _, r := range delta.Removed {
			if err := dropEntitlement(c, now, in.System, r.Key); err != nil {
				return nil, err
			}
		}
	}
	for _, r := range cascade {
		if err := dropEntitlement(c, now, in.System, r.Key); err != nil {
			return nil, err
		}
	}

	up.Status, up.Added, up.Removed, up.Changed, up.Unchanged = store.FlatUploadApplied, len(delta.Added), len(delta.Removed),
		len(delta.Changed), delta.Unchanged
	up.Removed -= up.Held // the removals the guard held did not happen
	up.TasksConfirmed = len(due)
	if err := c.InsertFlatUpload(up); err != nil {
		return nil, err
	}
	for i, ch := range changes {
		if err := c.InsertFlatChange(up.ID, store.FlatChange{Seq: i + 1, Kind: ch.Kind, Change: ch.Type, Label: ch.Label,
			Detail: ch.Detail}); err != nil {
			return nil, err
		}
	}

	// The snapshot: this upload's rows replace the last one's.
	for _, r := range delta.Removed {
		if err := c.DeleteFlatRecord(in.System, in.Kind, r.Key); err != nil {
			return nil, err
		}
	}
	for _, r := range cascade {
		if err := c.DeleteFlatRecord(in.System, KindEntitlements, r.Key); err != nil {
			return nil, err
		}
	}
	touched := map[string]bool{}
	for _, r := range delta.Added {
		touched[r.Key] = true
	}
	for _, r := range delta.Changed {
		touched[r.Key] = true
	}
	for _, r := range recs {
		if touched[r.Key] {
			if err := c.PutFlatRecord(&store.FlatRecord{System: in.System, Kind: in.Kind, Key: r.Key, Data: r.Data(),
				Hash: r.Hash, UploadID: up.ID}); err != nil {
				return nil, err
			}
		}
	}

	res := &Result{Upload: up, Changes: changes}
	for _, t := range due {
		if err := c.CloseFlatTask(t.ID, store.FlatTaskConfirmed, in.By, now, "confirmed by upload "+up.ID, &up.ID); err != nil {
			return nil, err
		}
		if err := c.Audit(now, in.By, "flatfile.task_confirmed", ojson.Object{{Key: "task_id", Value: t.ID},
			{Key: "system", Value: t.System}, {Key: "kind", Value: t.Kind}, {Key: "account", Value: t.AccountXID},
			{Key: "entitlement", Value: t.Entitlement}, {Key: "upload_id", Value: up.ID}}); err != nil {
			return nil, err
		}
		t.Status = store.FlatTaskConfirmed
		res.Confirmed = append(res.Confirmed, t)
	}
	_, err = c.RecordAudit(store.AuditRecord{At: now, Action: "flatfile.upload", LegacyActor: in.By,
		TargetType: "flatfile_upload", TargetID: up.ID, Detail: uploadDetail(up, 0)})
	return res, err
}

// reject records an upload that failed validation: the history row and each
// bad row (up to MaxStoredErrors). Nothing else changes.
func reject(c *store.TenantTx, now time.Time, up *store.FlatUpload, errs []RowError) (*Result, error) {
	rows := map[int]bool{}
	for _, e := range errs {
		if e.Row > 0 {
			rows[e.Row] = true
		}
	}
	up.Status, up.RowsRejected = store.FlatUploadRejected, len(rows)
	if err := c.InsertFlatUpload(up); err != nil {
		return nil, err
	}
	for i, e := range errs {
		if i == MaxStoredErrors {
			break
		}
		if err := c.InsertFlatUploadError(up.ID, store.FlatUploadError{Seq: i + 1, Row: e.Row, Column: e.Column, Code: e.Code,
			Message: e.Message}); err != nil {
			return nil, err
		}
	}
	_, err := c.RecordAudit(store.AuditRecord{At: now, Action: "flatfile.upload", LegacyActor: up.UploadedBy,
		Outcome: store.OutcomeFailure, TargetType: "flatfile_upload", TargetID: up.ID, Detail: uploadDetail(up, len(errs))})
	return &Result{Upload: up, Errors: errs}, err
}

func uploadDetail(up *store.FlatUpload, errCount int) ojson.Object {
	return ojson.Object{{Key: "upload_id", Value: up.ID}, {Key: "system", Value: up.System}, {Key: "kind", Value: up.Kind},
		{Key: "source", Value: up.Source}, {Key: "filename", Value: Neutralize(up.Filename)}, {Key: "sha256", Value: up.SHA256},
		{Key: "status", Value: up.Status}, {Key: "rows", Value: up.RowsTotal}, {Key: "rows_rejected", Value: up.RowsRejected},
		{Key: "errors", Value: errCount}, {Key: "added", Value: up.Added}, {Key: "removed", Value: up.Removed},
		{Key: "held", Value: up.Held}, {Key: "hold_id", Value: up.HoldID},
		{Key: "changed", Value: up.Changed}, {Key: "unchanged", Value: up.Unchanged},
		{Key: "tasks_confirmed", Value: up.TasksConfirmed}}
}

// decode reads stored snapshot rows back as records.
func decode(kind string, rows []*store.FlatRecord) []Record {
	out := make([]Record, 0, len(rows))
	for _, r := range rows {
		f := map[string]string{}
		if err := json.Unmarshal([]byte(r.Data), &f); err != nil {
			f = map[string]string{} // an unreadable row counts as having no fields; the next upload replaces it
		}
		out = append(out, Record{Key: r.Key, Label: labelOf(kind, r.Key), Fields: f, Hash: r.Hash})
	}
	return out
}

// discovery turns the snapshots into the records the ingest path takes: the
// accounts (correlated by the identity's external id, then email), one
// application resource, one permission per entitlement and one edge from
// each account to each of its entitlements. held lists accounts that stay
// disabled whatever the file says.
func discovery(m *Mapping, accounts, ents []Record, held map[string]bool) *connectors.DiscoveryResult {
	res := &connectors.DiscoveryResult{Resources: []connectors.ResourceRecord{{System: m.System, ExternalID: "app",
		Name: Neutralize(m.Name), Kind: "application"}}}
	for _, a := range accounts {
		var ref *connectors.IdentityRef
		if x, e := a.Fields["identity_id"], a.Fields["email"]; x != "" || e != "" {
			ref = &connectors.IdentityRef{ExternalID: x, Email: e}
		}
		status := a.Fields["status"]
		if held[a.Key] {
			status = "disabled"
		}
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: m.System, ExternalID: a.Key,
			Username: a.Fields["username"], Identity: ref, Kind: "user", Status: status})
	}
	priv := map[string]bool{}
	var codes []string
	for _, e := range ents {
		code := e.Fields["entitlement"]
		if _, seen := priv[code]; !seen {
			codes = append(codes, code)
		}
		priv[code] = priv[code] || e.Fields["privileged"] == "true"
	}
	for _, code := range codes {
		res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: m.System, ExternalID: EntitlementPermXID(code),
			Action: code, ResourceExternalID: "app", Privileged: priv[code]})
	}
	for _, e := range ents {
		res.Edges = append(res.Edges, connectors.EdgeRecord{
			Src:      connectors.Ref{Kind: "account", System: m.System, ExternalID: e.Fields["account_id"]},
			Dst:      connectors.Ref{Kind: "perm", System: m.System, ExternalID: EntitlementPermXID(e.Fields["entitlement"])},
			Relation: "direct_grant"})
	}
	return res
}

// Discovery is the graph snapshot of one pair of parsed files (ents may be nil), for a source that
// feeds the ingest path itself, as the SFTP file drop connector does. The records come from
// AccountRecords and EntitlementRecords, so they are validated and normalised.
func Discovery(m *Mapping, accounts, ents []Record) *connectors.DiscoveryResult {
	return discovery(m, accounts, ents, nil)
}

// feedCheck is what Apply knows about the file as a feed: record counts and why it looks broken.
type feedCheck struct {
	prev, now int
	sanity    []string
}

// dropAccounts handles the accounts the file no longer lists: each is disabled, and the grants an import
// made for it go. It is not deleted: reviews and the audit trail still refer to it. The active ones are
// vetted by the guard as one batch. It answers the id of the hold and how many drops it held.
func dropAccounts(c *store.TenantTx, now time.Time, system string, xids []string, feed feedCheck) (holdID string, held int, err error) {
	var items []deleteguard.Item
	active := make(map[string]*store.Account, len(xids))
	for _, xid := range xids {
		a, err := c.AccountByXID(system, xid)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", 0, err
		}
		if a.Status != "active" {
			if err := disableAndDropEdges(c, now, a); err != nil {
				return "", 0, err
			}
			continue
		}
		ref, err := json.Marshal([2]string{system, xid})
		if err != nil {
			return "", 0, err
		}
		active[string(ref)] = a
		items = append(items, deleteguard.Item{Kind: ItemDropAccount, Ref: string(ref),
			Label: fmt.Sprintf("account %s in %s dropped by an import", a.Username, system)})
	}
	if len(items) == 0 {
		return "", 0, nil
	}
	// the deletion guard (internal/deleteguard): an import that drops more accounts than the
	// threshold allows holds the rest; they stay as they are until a second admin releases them
	d, err := deleteguard.AdmitWith(c, now, deleteguard.Request{Category: deleteguard.CatAccounts, Source: deleteguard.SourceConnector,
		SourceID: system, Correlation: "flatfile:" + system, SourceDriven: true, Sanity: feed.sanity, PrevCount: feed.prev, NewCount: feed.now,
		Items: items})
	if err != nil {
		return "", 0, err
	}
	for _, it := range d.Applied {
		if err := disableAndDropEdges(c, now, active[it.Ref]); err != nil {
			return "", 0, err
		}
	}
	return d.HoldID, len(d.Held), nil
}

// ItemDropAccount is the kind of a held drop of an account the file no longer lists.
const ItemDropAccount = "account_drop"

// ReleaseDrop applies a held drop: the account is disabled and its import grants go, if it is
// still active.
func ReleaseDrop(c *store.TenantTx, now time.Time, it *store.DeletionHoldItem) (outcome, note string, err error) {
	var k [2]string
	if err := json.Unmarshal([]byte(it.Ref), &k); err != nil {
		return "", "", fmt.Errorf("flatfile: bad held drop: %w", err)
	}
	// the latest upload decides: an account it lists is not dropped (the feed was corrected since)
	recs, err := c.FlatRecords(k[0], KindAccounts)
	if err != nil {
		return "", "", err
	}
	for _, r := range recs {
		if r.Key == k[1] {
			return deleteguard.ItemGone, "the latest upload lists the account again", nil
		}
	}
	a, err := c.AccountByXID(k[0], k[1])
	if errors.Is(err, store.ErrNotFound) {
		return deleteguard.ItemGone, "the account no longer exists", nil
	}
	if err != nil {
		return "", "", err
	}
	if a.Status != "active" {
		return deleteguard.ItemGone, "the account is already " + a.Status, nil
	}
	if err := disableAndDropEdges(c, now, a); err != nil {
		return "", "", err
	}
	return deleteguard.ItemReleased, "", nil
}

func disableAndDropEdges(c *store.TenantTx, now time.Time, a *store.Account) error {
	if err := c.DisableAccount(a.ID); err != nil {
		return err
	}
	edges, err := c.EdgesFrom(graph.Key("account", a.ID))
	if err != nil {
		return err
	}
	for _, e := range edges {
		if e.Source == "connector" {
			if err := c.DeleteEdge(e.ID, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// dropEntitlement removes the grant of an entitlement record (key: account id
// and entitlement) the file no longer lists.
func dropEntitlement(c *store.TenantTx, now time.Time, system, key string) error {
	xid, code := SplitEntitlementKey(key)
	a, err := c.AccountByXID(system, xid)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	p, err := c.PermissionByXID(system, EntitlementPermXID(code))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	e, err := c.EdgeBetween(graph.Key("account", a.ID), graph.Key("perm", p.ID))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if e.Source == "connector" {
		return c.DeleteEdge(e.ID, now)
	}
	return nil
}

// SafeFilename is a file name fit to store and show: no path, at most 100
// characters of letters, digits and . _ - ( ) and spaces, never starting like
// a spreadsheet formula.
func SafeFilename(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("._-() ", r):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if utf8.RuneCountInString(b.String()) >= 100 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "upload.csv"
	}
	return Neutralize(out)
}
