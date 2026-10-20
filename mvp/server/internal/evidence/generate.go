package evidence

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Input is what a pack is generated from. The period is half-open:
// From <= t < To.
type Input struct {
	ID        string
	Framework Framework
	From, To  time.Time
	Now       time.Time
	By        string // the display name of the generating principal
	Tenant    string // tenant id, for the manifest
}

// FileInfo describes one file of a pack in the manifest.
type FileInfo struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	// Rows is the number of data rows (CSV files); -1 for text files.
	Rows int `json:"rows"`
}

// Manifest is manifest.json. Its own SHA-256 is Result.SHA256.
type Manifest struct {
	Schema      string         `json:"schema"`
	PackID      string         `json:"pack_id"`
	Framework   string         `json:"framework"`
	Name        string         `json:"framework_name"`
	Controls    []Control      `json:"controls"`
	PeriodFrom  string         `json:"period_from"`
	PeriodTo    string         `json:"period_to"`
	GeneratedAt string         `json:"generated_at"`
	GeneratedBy string         `json:"generated_by"`
	Tenant      string         `json:"tenant_id"`
	Files       []FileInfo     `json:"files"`
	SourceRows  map[string]int `json:"user_rows_by_source"`
	Notes       []string       `json:"notes"`
}

// ManifestSchema identifies the manifest layout.
const ManifestSchema = "tessera.evidence-pack/1"

// Result is a generated pack.
type Result struct {
	Manifest Manifest
	// ManifestJSON is manifest.json exactly as it is in the ZIP.
	ManifestJSON []byte
	// SHA256 is the hex SHA-256 of ManifestJSON, which in turn lists the
	// SHA-256 of every other file.
	SHA256 string
	Zip    []byte
}

// maxJMLRows caps the leaver sample; the manifest says when it was reached.
const maxJMLRows = 500

// Generate builds the pack from reads of the transaction's tenant. It writes
// nothing: the caller stores the pack and appends its ledger event.
func Generate(c *store.TenantTx, in Input) (*Result, error) {
	if !in.From.Before(in.To) {
		return nil, errors.New("evidence: empty period")
	}
	people, _, err := c.IdentityMap()
	if err != nil {
		return nil, err
	}
	end := in.To.Add(-time.Microsecond) // the last instant of the period
	g, err := graph.BuildAsOf(c, end)
	if err != nil {
		return nil, err
	}

	type table struct {
		name   string
		header []string
		rows   [][]string
	}
	var tables []table
	notes := append([]string{}, in.Framework.Notes...)

	users, perSource, err := usersTable(c, people, in.To)
	if err != nil {
		return nil, err
	}
	tables = append(tables, table{FileUsers, usersHeader, users})

	jml, truncated, err := jmlTable(c, people, in)
	if err != nil {
		return nil, err
	}
	tables = append(tables, table{FileJML, jmlHeader, jml})
	if truncated {
		notes = append(notes, fmt.Sprintf("%s is capped at %d rows; narrow the period for the rest.", FileJML, maxJMLRows))
	}

	camps, items, err := campaignTables(c, in)
	if err != nil {
		return nil, err
	}
	tables = append(tables, table{FileCampaigns, campaignsHeader, camps}, table{FileItems, itemsHeader, items})

	tables = append(tables, table{FilePrivileged, privHeader, privilegedTable(g, people)})

	rev, err := revocationTable(c, g, in)
	if err != nil {
		return nil, err
	}
	tables = append(tables, table{FileRevoked, revHeader, rev})

	readme := readmeText(in, notes)
	files := []struct {
		name string
		body []byte
		rows int
	}{}
	for _, t := range tables {
		b, err := csvBytes(t.header, t.rows)
		if err != nil {
			return nil, err
		}
		files = append(files, struct {
			name string
			body []byte
			rows int
		}{t.name, b, len(t.rows)})
	}
	files = append(files, struct {
		name string
		body []byte
		rows int
	}{"README.txt", []byte(readme), -1})

	m := Manifest{Schema: ManifestSchema, PackID: in.ID, Framework: in.Framework.ID, Name: in.Framework.Name,
		Controls: in.Framework.Controls, PeriodFrom: timeutil.ISO(in.From), PeriodTo: timeutil.ISO(in.To),
		GeneratedAt: timeutil.ISO(in.Now), GeneratedBy: in.By, Tenant: in.Tenant, SourceRows: perSource, Notes: notes}
	if m.Notes == nil {
		m.Notes = []string{}
	}
	for _, f := range files {
		sum := sha256.Sum256(f.body)
		m.Files = append(m.Files, FileInfo{Name: f.name, SHA256: hex.EncodeToString(sum[:]), Bytes: len(f.body), Rows: f.rows})
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	mj = append(mj, '\n')
	msum := sha256.Sum256(mj)
	manifestHash := hex.EncodeToString(msum[:])

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, body []byte) error {
		// A fixed timestamp makes the ZIP a pure function of the data.
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: in.Now})
		if err != nil {
			return err
		}
		_, err = w.Write(body)
		return err
	}
	for _, f := range files {
		if err := add(f.name, f.body); err != nil {
			return nil, err
		}
	}
	if err := add("manifest.json", mj); err != nil {
		return nil, err
	}
	if err := add("manifest.sha256", []byte(manifestHash+"  manifest.json\n")); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return &Result{Manifest: m, ManifestJSON: mj, SHA256: manifestHash, Zip: buf.Bytes()}, nil
}

func readmeText(in Input, notes []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Tessera evidence pack: %s\n", in.Framework.Name)
	fmt.Fprintf(&b, "Period: %s (inclusive) to %s (exclusive), UTC\n", timeutil.ISO(in.From), timeutil.ISO(in.To))
	fmt.Fprintf(&b, "Generated: %s\n\nControls\n", timeutil.ISO(in.Now))
	for _, c := range in.Framework.Controls {
		fmt.Fprintf(&b, "  %s  %s  [%s]\n", c.ID, c.Title, strings.Join(c.Files, ", "))
	}
	b.WriteString("\nHow to verify\n  manifest.json lists the SHA-256 and row count of every file. " +
		"manifest.sha256 is the SHA-256 of manifest.json, and the same value is recorded in Tessera's audit ledger " +
		"(action evidence.pack_generated).\n")
	b.WriteString("\nScope and limits\n" +
		"  Grants are point-in-time: edge_history says what held at an instant (a grant holds from the instant it was added until the instant it was removed or expired).\n" +
		"  Identities, accounts and their statuses are current records, not point-in-time.\n" +
		"  Revocation verification re-reads Tessera's own graph, not the target system.\n" +
		"  Cells that start with = + - @ are prefixed with an apostrophe so spreadsheets do not run them as formulas.\n")
	for _, n := range notes {
		fmt.Fprintf(&b, "  Note: %s\n", n)
	}
	return b.String()
}

// ---------------------------------------------------------------- csv

// csvCell neutralizes spreadsheet formula injection: a cell that would start
// a formula gets a leading apostrophe.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func csvBytes(header []string, rows [][]string) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(header); err != nil {
		return nil, err
	}
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = csvCell(c)
		}
		if err := w.Write(cells); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func iso(t *time.Time) string {
	if t == nil {
		return ""
	}
	return timeutil.ISO(*t)
}

func sp(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ---------------------------------------------------------------- users

var usersHeader = []string{"source", "account_id", "account_external_id", "username", "account_kind", "account_status",
	"account_created_at", "identity_id", "identity_external_id", "name", "email", "identity_type", "identity_status",
	"department", "hired_at", "terminated_at"}

// usersTable lists every account that existed by the end of the period (an
// account with no created_at is assumed to), one row per account, with its
// source system and identity. perSource counts the rows by source.
func usersTable(c *store.TenantTx, people map[int64]*store.Identity, to time.Time) ([][]string, map[string]int, error) {
	accts, err := c.AccountsBySystemUsername(nil)
	if err != nil {
		return nil, nil, err
	}
	rows := [][]string{}
	per := map[string]int{}
	for _, a := range accts {
		if a.CreatedAt != nil && !a.CreatedAt.Before(to) {
			continue
		}
		row := []string{a.System, id(a.ID), a.ExternalID, a.Username, a.Kind, a.Status, iso(a.CreatedAt),
			"", "", "", "", "", "", "", "", ""}
		if a.IdentityID != nil {
			if p := people[*a.IdentityID]; p != nil {
				row[7], row[8], row[9], row[10] = id(p.ID), p.ExternalID, p.Name, sp(p.Email)
				row[11], row[12], row[13] = p.Type, p.Status, sp(p.Department)
				row[14], row[15] = iso(p.HiredAt), iso(p.TerminatedAt)
			}
		}
		rows = append(rows, row)
		per[a.System]++
	}
	return rows, per, nil
}

func id(n int64) string { return strconv.FormatInt(n, 10) }

// ---------------------------------------------------------------- JML

var jmlHeader = []string{"hr_event_external_id", "identity_id", "identity_external_id", "system", "hr_terminated_at",
	"grants_held_at_termination", "grants_still_held", "last_access_removed_at", "hours_to_last_removal", "result"}

// jmlTable lists, per leaver event effective in the period and per system the
// leaver had an account in, the time from the HR termination to the last
// grant removal. Rows carry ids only. result is "removed" (every grant held at
// termination has ended), "access_remains" (one is still held) or
// "none_held". It reads edge_history, so a removal is timed by the instant
// the edge was removed or expired.
func jmlTable(c *store.TenantTx, people map[int64]*store.Identity, in Input) ([][]string, bool, error) {
	events, err := c.HrisEvents()
	if err != nil {
		return nil, false, err
	}
	var leavers []*store.HrisEvent
	for _, e := range events {
		if e.Type == "leaver" && e.IdentityID != nil && !e.EffectiveAt.Before(in.From) && e.EffectiveAt.Before(in.To) {
			leavers = append(leavers, e)
		}
	}
	rows := [][]string{}
	if len(leavers) == 0 {
		return rows, false, nil
	}
	sort.SliceStable(leavers, func(i, j int) bool { return leavers[i].EffectiveAt.Before(leavers[j].EffectiveAt) })
	earliest := leavers[0].EffectiveAt
	spans, err := c.EdgeSpansSince(earliest)
	if err != nil {
		return nil, false, err
	}
	bySrc := map[string][]*store.EdgeSpan{}
	for _, s := range spans {
		bySrc[s.Src] = append(bySrc[s.Src], s)
	}
	truncated := false
	for _, ev := range leavers {
		ident := people[*ev.IdentityID]
		if ident == nil {
			continue
		}
		accts, err := c.IdentityAccounts(ident.ID)
		if err != nil {
			return nil, false, err
		}
		type agg struct {
			held, remaining int
			last            *time.Time
		}
		bySystem := map[string]*agg{}
		var systems []string
		for _, a := range accts {
			if bySystem[a.System] == nil {
				bySystem[a.System] = &agg{}
				systems = append(systems, a.System)
			}
			x := bySystem[a.System]
			for _, s := range bySrc[graph.Key("account", a.ID)] {
				if !s.HeldAt(ev.EffectiveAt) {
					continue
				}
				x.held++
				// Held at generation time means the access was not removed. A
				// span ending after Now (a future expiry) is still held.
				if e := s.End(); e == nil || e.After(in.Now) {
					x.remaining++
				} else if x.last == nil || e.After(*x.last) {
					t := *e
					x.last = &t
				}
			}
		}
		sort.Strings(systems)
		for _, sys := range systems {
			if len(rows) >= maxJMLRows {
				truncated = true
				break
			}
			x := bySystem[sys]
			result, last, hours := "none_held", "", ""
			switch {
			case x.remaining > 0:
				result = "access_remains"
			case x.held > 0:
				result = "removed"
			}
			if x.last != nil && x.remaining == 0 {
				last = timeutil.ISO(*x.last)
				hours = strconv.FormatFloat(x.last.Sub(ev.EffectiveAt).Hours(), 'f', 2, 64)
			}
			rows = append(rows, []string{ev.ExternalID, id(ident.ID), ident.ExternalID, sys, timeutil.ISO(ev.EffectiveAt),
				strconv.Itoa(x.held), strconv.Itoa(x.remaining), last, hours, result})
		}
	}
	return rows, truncated, nil
}

// ---------------------------------------------------------------- reviews

var campaignsHeader = []string{"campaign_id", "name", "created_at", "status", "unused_days", "total_grants",
	"auto_certified", "items", "decided", "kept", "revoked"}
var itemsHeader = []string{"campaign_id", "item_id", "identity_id", "grant", "reasons", "reviewer_identity_id",
	"decision", "decided_at", "decided_by_user_id", "comment"}

// campaignTables is the review export: the campaigns created in the period and
// their items with the decisions.
func campaignTables(c *store.TenantTx, in Input) (camps, items [][]string, err error) {
	all, err := c.CampaignsNewestFirst()
	if err != nil {
		return nil, nil, err
	}
	camps, items = [][]string{}, [][]string{}
	for i := len(all) - 1; i >= 0; i-- { // oldest first
		cp := all[i]
		if cp.CreatedAt.Before(in.From) || !cp.CreatedAt.Before(in.To) {
			continue
		}
		its, err := c.CampaignItems(cp.ID)
		if err != nil {
			return nil, nil, err
		}
		decided, kept, revoked := 0, 0, 0
		for _, it := range its {
			var by, revID, at, decision string
			if it.DecidedByUserID != nil {
				by = it.DecidedByUserID.String()
			}
			if it.ReviewerID != nil {
				revID = id(*it.ReviewerID)
			}
			if it.Decision != nil {
				decided++
				decision, at = *it.Decision, iso(it.DecidedAt)
				if decision == "keep" {
					kept++
				} else if decision == "revoke" {
					revoked++
				}
			}
			items = append(items, []string{id(cp.ID), id(it.ID), id(it.IdentityID), it.GrantLabel,
				strings.Join(it.Reasons, ";"), revID, decision, at, by, sp(it.Comment)})
		}
		camps = append(camps, []string{id(cp.ID), cp.Name, timeutil.ISO(cp.CreatedAt), cp.Status, strconv.Itoa(cp.UnusedDays),
			strconv.Itoa(cp.TotalGrants), strconv.Itoa(cp.AutoCertified), strconv.Itoa(len(its)), strconv.Itoa(decided),
			strconv.Itoa(kept), strconv.Itoa(revoked)})
	}
	return camps, items, nil
}

// ---------------------------------------------------------------- privileged

var privHeader = []string{"identity_id", "identity_external_id", "identity_type", "identity_status", "permission",
	"resource", "system", "access", "path"}

// privilegedTable lists who held privileged access at the end of the period:
// a privileged permission, or any permission reached through a privileged
// group. One row per identity and permission, with the shortest path.
func privilegedTable(g *graph.Snapshot, people map[int64]*store.Identity) [][]string {
	rows := [][]string{}
	for _, iid := range g.Identities(true) {
		n := g.Node(graph.Key("identity", iid))
		var xid string
		if p := people[iid]; p != nil {
			xid = p.ExternalID
		}
		for _, ep := range g.EffectivePermissions(iid).Values() {
			priv := ep.Privileged
			if len(ep.Paths) > 0 {
				for _, k := range ep.Paths[0] {
					if nd := g.Node(k); nd != nil && nd.Kind == "group" && nd.Privileged {
						priv = true
					}
				}
			}
			if !priv || len(ep.Paths) == 0 {
				continue
			}
			access := "standing"
			if !ep.Standing {
				access = "jit"
			}
			rows = append(rows, []string{id(iid), xid, n.Type, n.Status, ep.Action, ep.ResourceName, ep.System,
				access, g.PathText(ep.Paths[0])})
		}
	}
	return rows
}

// ---------------------------------------------------------------- revocations

var revHeader = []string{"grant_src", "grant_dst", "grant", "reason", "revoked_at", "span_closed_at", "currently_held",
	"verification"}

// revocationTable lists the grants revoked inside Tessera (review, leaver
// plan, least-privilege) in the period, with a verification: the grant is no
// longer in the graph and its history span is closed at the revocation.
// verified is Tessera's own graph state, not a re-read of the target system.
func revocationTable(c *store.TenantTx, g *graph.Snapshot, in Input) ([][]string, error) {
	revoked, err := c.RevokedGrants()
	if err != nil {
		return nil, err
	}
	spans, err := c.EdgeSpansSince(in.From)
	if err != nil {
		return nil, err
	}
	type pair struct{ src, dst string }
	last := map[pair]*store.EdgeSpan{}
	for _, s := range spans {
		k := pair{s.Src, s.Dst}
		if last[k] == nil || s.ValidFrom.After(last[k].ValidFrom) || (s.ValidFrom.Equal(last[k].ValidFrom) && s.ID > last[k].ID) {
			last[k] = s
		}
	}
	rows := [][]string{}
	for _, r := range revoked {
		if r.RevokedAt.Before(in.From) || !r.RevokedAt.Before(in.To) {
			continue
		}
		var closed, verification string
		if s := last[pair{r.Src, r.Dst}]; s != nil && s.ValidTo != nil {
			closed = timeutil.ISO(*s.ValidTo)
		}
		cur, err := c.EdgeBetween(r.Src, r.Dst)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		held := cur != nil
		switch {
		case held:
			verification = "failed: grant is held again"
		case closed != "":
			verification = "verified: grant absent, span closed"
		default:
			verification = "verified: grant absent (no history span)"
		}
		rows = append(rows, []string{r.Src, r.Dst, g.Label(r.Src) + " → " + g.Label(r.Dst), r.Reason, timeutil.ISO(r.RevokedAt),
			closed, strconv.FormatBool(held), verification})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i][4] < rows[j][4] })
	return rows, nil
}
