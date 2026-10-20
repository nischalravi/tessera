package readiness

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Evidence export (design §7.6): a ZIP an auditor can use to reproduce what
// was checked, by whom, and which gaps were accepted. manifest.json lists the
// SHA-256 of every other file, the template pins, and the audit ledger range
// and chain head at generation time. The export is audited in the same
// transaction (readiness.evidence.exported, carrying the manifest hash), so
// the file can be checked against the ledger.
//
// The export holds no sample data beyond object ids: a finding contributes
// its counts and its sample refs, never a sample's name or reason, and a check
// result contributes its numeric and boolean observations, never its message
// or any text.

// EvidenceFormat names the manifest layout.
const EvidenceFormat = "tessera.readiness.evidence/1"

// EventEvidenceExported is the ledger action recorded for every export.
const EventEvidenceExported = "readiness.evidence.exported"

// Scopes of an export.
const (
	EvidenceConnection = "connection"
	EvidenceTenant     = "tenant"
)

// ControlMapping is the text mapping of the export to the controls auditors
// test. It is a mapping, not a claim: Tessera does not assert that the export
// satisfies a control on its own.
var ControlMapping = []ControlRef{
	{Framework: "SOC 2", Controls: "CC6.1, CC6.2, CC6.3",
		Note: "Logical access provisioning and removal: the checklist and reconciliation findings show how the directory connection was verified and which orphaned or dormant accounts were found."},
	{Framework: "ISO/IEC 27001:2022", Controls: "Annex A 5.15, 5.16, 5.17, 5.18",
		Note: "Access control, identity management, authentication information and access rights."},
	{Framework: "SOX ITGC", Controls: "Completeness and accuracy of user listings (IPE)",
		Note: "checks.csv and findings.csv record the population counts, the check run and the configuration hash the listing was produced under."},
	{Framework: "PCI DSS v4.0", Controls: "8.2.6",
		Note: "Inactive user accounts: the dormant-account findings and their acceptance reasons."},
}

// EvidenceDisclaimer is stated in every manifest.
const EvidenceDisclaimer = "This export is evidence to support a control test. Tessera does not claim that it satisfies a control on its own, and it is not an auditor endorsement."

// ControlRef is one control mapping line.
type ControlRef struct {
	Framework string `json:"framework"`
	Controls  string `json:"controls"`
	Note      string `json:"note"`
}

// ManifestFile is one file listed in the manifest.
type ManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

// ManifestTemplate is the template pin and configuration hash a connection's
// evidence is bound to.
type ManifestTemplate struct {
	ConnectionID   string `json:"connection_id"`
	RevisionID     string `json:"revision_id"`
	Template       string `json:"template"`
	Version        string `json:"version"`
	OverlayVersion int    `json:"overlay_version"`
	ConfigHash     string `json:"config_hash"`
}

// ManifestLedger is the audit ledger position at generation time. The export
// event itself is the next event: seq to_seq+1, whose prev_hash is chain_head.
type ManifestLedger struct {
	FromSeq   int64  `json:"from_seq"`
	ToSeq     int64  `json:"to_seq"`
	ChainHead string `json:"chain_head"`
	Verify    string `json:"verify"`
}

// Manifest is manifest.json.
type Manifest struct {
	Format       string             `json:"format"`
	Scope        string             `json:"scope"`
	ConnectionID string             `json:"connection_id,omitempty"`
	GeneratedAt  string             `json:"generated_at"`
	GeneratedBy  string             `json:"generated_by"`
	Files        []ManifestFile     `json:"files"`
	Templates    []ManifestTemplate `json:"templates"`
	Ledger       ManifestLedger     `json:"ledger"`
	Controls     []ControlRef       `json:"control_mapping"`
	Disclaimer   string             `json:"disclaimer"`
}

// EvidenceExport is a built export.
type EvidenceExport struct {
	Filename       string
	Zip            []byte
	Manifest       Manifest
	ManifestSHA256 string
}

// EvidenceOf builds the evidence export of one connection (connID set) or of
// every connection of the tenant, and appends readiness.evidence.exported to
// the ledger in the same write transaction. dash is the tenant dashboard and
// is used only for the tenant scope.
func (s *Service) EvidenceOf(c *store.TenantTx, connID, actor string, now time.Time, dash *Dashboard) (*EvidenceExport, error) {
	scope := EvidenceTenant
	var conns []*store.Connection
	if connID != "" {
		scope = EvidenceConnection
		conn, _, _, err := Revisions(c, connID)
		if err != nil {
			return nil, err
		}
		conns = []*store.Connection{conn}
	} else {
		all, err := c.Connections()
		if err != nil {
			return nil, err
		}
		for _, conn := range all {
			if conn.RetiredAt == nil {
				conns = append(conns, conn)
			}
		}
	}

	var checklist, checks, findings, skipped rows
	checklist.header("connection_id", "revision_id", "item_id", "title", "category", "level", "applicable", "status",
		"reason", "verification", "check_runs", "attester", "attested_at", "attestation_stale")
	checks.header("connection_id", "run_id", "run_kind", "run_status", "run_started_at", "run_finished_at", "config_hash",
		"simulated", "item_id", "check_id", "status", "duration_ms", "observed_counts")
	findings.header("connection_id", "run_id", "finding_id", "code", "variant", "severity", "status", "count",
		"denominator", "percent", "sample_refs", "accepted_by", "acceptance_reason", "acceptance_expires_at",
		"first_seen_at", "last_seen_at")
	skipped.header("connection_id", "revision_id", "item_id", "level", "skipped_by", "reason", "skipped_at", "review_by",
		"review_expired", "template_version")

	type connScore struct {
		ConnectionID string         `json:"connection_id"`
		RevisionID   string         `json:"revision_id"`
		State        string         `json:"state"`
		Breakdown    ScoreBreakdown `json:"breakdown"`
	}
	scores := []connScore{}
	templates := []ManifestTemplate{}
	for _, conn := range conns {
		b, err := s.Current(c, conn.ID, now)
		if err != nil {
			return nil, err
		}
		templates = append(templates, ManifestTemplate{ConnectionID: conn.ID, RevisionID: b.Rev.ID,
			Template: b.Rev.TemplateID, Version: b.Rev.TemplateVersion, OverlayVersion: b.Rev.OverlayVersion,
			ConfigHash: b.ConfigHash})
		scores = append(scores, connScore{conn.ID, b.Rev.ID, b.Rev.State, s.ConnectionScore(b)})
		addChecklist(&checklist, b)
		addChecks(&checks, b)
		if err := addFindings(c, &findings, b); err != nil {
			return nil, err
		}
		addSkips(&skipped, b, now)
	}

	var score any = map[string]any{"connections": scores}
	if scope == EvidenceTenant && dash != nil {
		score = map[string]any{"tenant": dash.Tenant, "connections": scores}
	}
	scoreJSON, err := json.MarshalIndent(score, "", "  ")
	if err != nil {
		return nil, err
	}
	files := []evFile{{"checklist.csv", checklist.bytes()}, {"checks.csv", checks.bytes()},
		{"findings.csv", findings.bytes()}, {"skipped.csv", skipped.bytes()}, {"score.json", append(scoreJSON, '\n')}}

	head, err := c.AuditHead()
	if err != nil {
		return nil, err
	}
	m := Manifest{Format: EvidenceFormat, Scope: scope, GeneratedAt: store.RT(now), GeneratedBy: actor,
		Templates: templates, Controls: ControlMapping, Disclaimer: EvidenceDisclaimer, Files: []ManifestFile{},
		Ledger: ManifestLedger{FromSeq: 1, ToSeq: head.LastSeq, ChainHead: head.LastHash, Verify: "tessera audit verify"}}
	if scope == EvidenceConnection {
		m.ConnectionID = connID
	}
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		m.Files = append(m.Files, ManifestFile{Name: f.name, SHA256: hex.EncodeToString(sum[:]), Bytes: len(f.data)})
	}
	manifestJSON, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	manifestJSON = append(manifestJSON, '\n')
	msum := sha256.Sum256(manifestJSON)
	mhash := hex.EncodeToString(msum[:])

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range append([]evFile{{"manifest.json", manifestJSON}}, files...) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: now.UTC()})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	detail := ojson.Object{{Key: "scope", Value: scope}}
	if connID != "" {
		detail = append(detail, ojson.KV{Key: "connection_id", Value: connID})
	}
	detail = append(detail, ojson.KV{Key: "manifest_sha256", Value: mhash},
		ojson.KV{Key: "files", Value: len(files) + 1}, ojson.KV{Key: "connections", Value: len(conns)},
		ojson.KV{Key: "from_seq", Value: m.Ledger.FromSeq}, ojson.KV{Key: "to_seq", Value: m.Ledger.ToSeq},
		ojson.KV{Key: "chain_head", Value: m.Ledger.ChainHead})
	if err := c.Audit(now, actor, EventEvidenceExported, detail); err != nil {
		return nil, err
	}
	name := "tessera-readiness-evidence-" + now.UTC().Format("20060102T150405Z") + ".zip"
	if connID != "" {
		name = "tessera-readiness-evidence-" + connID + "-" + now.UTC().Format("20060102T150405Z") + ".zip"
	}
	return &EvidenceExport{Filename: name, Zip: buf.Bytes(), Manifest: m, ManifestSHA256: mhash}, nil
}

type evFile struct {
	name string
	data []byte
}

// rows is a CSV under construction.
type rows struct {
	buf bytes.Buffer
	w   *csv.Writer
}

func (r *rows) header(cols ...string) {
	r.w = csv.NewWriter(&r.buf)
	_ = r.w.Write(cols)
}

// add writes one row. A text cell that a spreadsheet would read as a formula
// is prefixed with an apostrophe.
func (r *rows) add(cells ...string) {
	for i, c := range cells {
		if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
			cells[i] = "'" + c
		}
	}
	_ = r.w.Write(cells)
}

func (r *rows) bytes() []byte {
	r.w.Flush()
	return r.buf.Bytes()
}

func ts(t time.Time) string { return store.RT(t) }

func tsp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return store.RT(*t)
}

func addChecklist(out *rows, b *Bundle) {
	for _, it := range b.Eval.Items {
		var kinds, runs []string
		for _, p := range it.Parts {
			k := string(p.Kind)
			if p.Check != "" {
				k += ":" + p.Check
			}
			kinds = append(kinds, k)
			if p.RunID != "" && !slices.Contains(runs, p.RunID) {
				runs = append(runs, p.RunID)
			}
		}
		var by, at, stale string
		if a := it.Attestation; a != nil {
			by, at, stale = a.ActorID, ts(a.AttestedAt), strconv.FormatBool(a.ItemHash != it.ItemHash)
		}
		out.add(b.Conn.ID, b.Rev.ID, it.ID, it.Title, it.Category, string(it.Level), strconv.FormatBool(it.Applicable),
			it.Status, it.Reason, strings.Join(kinds, " "), strings.Join(runs, " "), by, at, stale)
	}
}

// observedCounts keeps only the numeric and boolean observations of a check
// result: counts and fill rates. Text, lists and objects (which could carry
// names or sample data) are dropped.
func observedCounts(o map[string]any) string {
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		switch v := o[k].(type) {
		case bool:
			parts = append(parts, k+"="+strconv.FormatBool(v))
		case float64:
			parts = append(parts, k+"="+strconv.FormatFloat(v, 'f', -1, 64))
		case int:
			parts = append(parts, k+"="+strconv.Itoa(v))
		}
	}
	return strings.Join(parts, " ")
}

func addChecks(out *rows, b *Bundle) {
	emit := func(run *RunInfo, results map[resultKey]*ResultInfo) {
		if run == nil {
			return
		}
		keys := make([]resultKey, 0, len(results))
		for k := range results {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].item != keys[j].item {
				return keys[i].item < keys[j].item
			}
			return keys[i].check < keys[j].check
		})
		for _, k := range keys {
			r := results[k]
			out.add(b.Conn.ID, run.ID, run.Kind, run.Status, ts(run.StartedAt), tsp(run.FinishedAt), run.ConfigHash,
				strconv.FormatBool(r.Simulated), r.ItemID, r.CheckID, r.Status, strconv.Itoa(r.DurationMS),
				observedCounts(r.Observed))
		}
	}
	emit(b.Evidence.LiveRun, b.Evidence.Live)
	emit(b.Evidence.DataRun, b.Evidence.Data)
}

func addFindings(c *store.TenantTx, out *rows, b *Bundle) error {
	if b.Evidence.DataRun == nil {
		return nil
	}
	fs, err := c.RunFindings(b.Evidence.DataRun.ID)
	if err != nil {
		return err
	}
	for _, f := range fs {
		v, err := FindingOf(f)
		if err != nil {
			return err
		}
		refs := make([]string, 0, len(v.Samples))
		for _, sm := range v.Samples {
			refs = append(refs, sm.Ref) // the id only: never the name or reason
		}
		out.add(b.Conn.ID, v.RunID, v.ID, v.Code, v.Variant, v.Severity, v.Status, strconv.Itoa(v.Count),
			strconv.Itoa(v.Denominator), strconv.Itoa(v.Percent), strings.Join(refs, " "), deref(v.AcceptedBy),
			deref(v.Reason), deref(v.ExpiresAt), v.FirstSeenAt, v.LastSeenAt)
	}
	return nil
}

func addSkips(out *rows, b *Bundle, now time.Time) {
	ids := make([]string, 0, len(b.Evidence.Skips))
	for id := range b.Evidence.Skips {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		k := b.Evidence.Skips[id]
		out.add(b.Conn.ID, b.Rev.ID, k.ItemID, k.Level, k.ActorID, k.Reason, ts(k.SkippedAt), ts(k.ReviewBy),
			strconv.FormatBool(!k.ReviewBy.After(now)), k.TemplateVersion)
	}
}
