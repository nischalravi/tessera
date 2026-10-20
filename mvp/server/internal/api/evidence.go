package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/evidence"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Point-in-time access and framework evidence packs (issue #111):
//
//	GET  /api/access/as-of?resource=<id>&date=<date or datetime>
//	GET  /api/evidence/packs
//	POST /api/evidence/packs   {framework, from, to}
//	GET  /api/evidence/packs/{pack_id}
//	GET  /api/evidence/packs/{pack_id}/download
//
// as-of reads edge_history. A pack is generated, stored and recorded in the
// audit ledger (evidence.pack_generated) in one transaction; the ZIP is
// written after it commits.
//
// Evidence routes need audit.read (auditor, tenant admin): generating a pack
// reads existing data and writes only the pack and its ledger event.
func (s *Server) registerEvidenceRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/access/as-of", read, need(auth.PermGraphRead), s.accessAsOf)
	s.handle(G, "/api/evidence/packs", read, need(auth.PermAuditRead), s.listEvidencePacks)
	s.handle(P, "/api/evidence/packs", write, need(auth.PermAuditRead), s.createEvidencePack)
	s.handle(G, "/api/evidence/packs/{pack_id}", read, need(auth.PermAuditRead), s.evidencePack)
	s.handle(G, "/api/evidence/packs/{pack_id}/download", read, need(auth.PermAuditRead), s.evidencePackDownload)
}

// maxPackDays bounds a pack's period.
const maxPackDays = 731

// parseWhen parses a date (YYYY-MM-DD) or an ISO-8601 datetime, as UTC.
func parseWhen(raw string) (t time.Time, dateOnly bool, err error) {
	if len(raw) == len("2006-01-02") {
		t, err = time.Parse("2006-01-02", raw)
		return t.UTC(), true, err
	}
	t, err = timeutil.ParseISO(raw)
	return t, false, err
}

func badQuery(loc, name, msg string, input any) verr {
	return verr{Type: "value_error", Loc: []any{loc, name}, Msg: msg, Input: input}
}

func missingQuery(name string) verr {
	return verr{Type: "missing", Loc: []any{"query", name}, Msg: "Field required", Input: nil}
}

// asOfInstant resolves the "date" of a point-in-time query: a date means the
// end of that day (its last microsecond), a datetime is the instant itself.
// It must not be in the future; today resolves to now.
func asOfInstant(raw string, now time.Time) (time.Time, *verr) {
	t, dateOnly, err := parseWhen(raw)
	if err != nil {
		e := badQuery("query", "date", "Input should be a valid date or datetime", raw)
		return time.Time{}, &e
	}
	if dateOnly {
		if t.After(now) {
			e := badQuery("query", "date", "date must not be in the future", raw)
			return time.Time{}, &e
		}
		t = t.AddDate(0, 0, 1).Add(-time.Microsecond)
		if t.After(now) {
			t = now
		}
		return t, nil
	}
	if t.After(now) {
		e := badQuery("query", "date", "date must not be in the future", raw)
		return time.Time{}, &e
	}
	return t, nil
}

// GET /api/access/as-of: who could reach the resource at the instant, with
// paths. Grants are as edge_history recorded them; identities, accounts and
// the bindings between them are today's (see graph.BuildAsOf).
func (s *Server) accessAsOf(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	resID := p.queryOptInt("resource")
	rawDate := p.queryOptStr("date")
	if resID == nil && len(p.errs) == 0 {
		p.errs = append(p.errs, missingQuery("resource"))
	}
	var at time.Time
	if rawDate == nil {
		p.errs = append(p.errs, missingQuery("date"))
	} else if t, e := asOfInstant(*rawDate, s.clock()); e != nil {
		p.errs = append(p.errs, *e)
	} else {
		at = t
	}
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	res, err := getOrNil(resourceByID(c, *resID))
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, errStatus(http.StatusNotFound, "resource not found")
	}
	g, err := graph.BuildAsOf(c, at)
	if err != nil {
		return nil, err
	}
	people, _, err := c.IdentityMap()
	if err != nil {
		return nil, err
	}
	ids, who := g.WhoCanAccess(res.ID)
	identities := []ojson.Object{}
	for _, iid := range ids {
		ident := people[iid]
		node := g.Node(graph.Key("identity", iid))
		if ident == nil || node == nil {
			continue
		}
		perms := []ojson.Object{}
		for _, ep := range who[iid] {
			paths := []ojson.Object{}
			for k, path := range ep.Paths {
				if k == 3 {
					break
				}
				paths = append(paths, ojson.Object{{Key: "text", Value: g.PathText(path)},
					{Key: "steps", Value: g.DescribePath(path, timeutil.ISOPtr)}})
			}
			perms = append(perms, ojson.Object{{Key: "permission_id", Value: ep.PermID}, {Key: "action", Value: ep.Action},
				{Key: "privileged", Value: ep.Privileged}, {Key: "standing", Value: ep.Standing}, {Key: "paths", Value: paths}})
		}
		identities = append(identities, ojson.Object{
			{Key: "identity", Value: ojson.Object{{Key: "id", Value: ident.ID}, {Key: "name", Value: ident.Name},
				{Key: "type", Value: ident.Type}, {Key: "status", Value: node.Status}, {Key: "department", Value: ident.Department},
				{Key: "title", Value: ident.Title}}},
			{Key: "permissions", Value: perms}})
	}
	return ojson.Object{
		{Key: "resource", Value: ojson.Object{{Key: "id", Value: res.ID}, {Key: "system", Value: res.System},
			{Key: "name", Value: res.Name}, {Key: "kind", Value: res.Kind}, {Key: "environment", Value: res.Environment}}},
		{Key: "date", Value: *rawDate}, {Key: "as_of", Value: timeutil.ISO(at)},
		{Key: "identities", Value: identities}, {Key: "count", Value: len(identities)}}, nil
}

func resourceByID(c *store.TenantTx, id int64) (*store.Resource, error) {
	all, err := c.Resources()
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, store.ErrNotFound
}

// ---------------------------------------------------------------- packs

func packView(p *store.EvidencePack, withManifest bool) (ojson.Object, error) {
	var m evidence.Manifest
	if err := json.Unmarshal(p.Manifest, &m); err != nil {
		return nil, err
	}
	out := ojson.Object{{Key: "id", Value: p.ID}, {Key: "framework", Value: p.Framework}, {Key: "framework_name", Value: m.Name},
		{Key: "period_from", Value: timeutil.ISO(p.PeriodFrom)}, {Key: "period_to", Value: timeutil.ISO(p.PeriodTo)},
		{Key: "generated_at", Value: timeutil.ISO(p.GeneratedAt)}, {Key: "generated_by", Value: p.GeneratedBy},
		{Key: "manifest_sha256", Value: p.ManifestSHA256}, {Key: "size_bytes", Value: p.SizeBytes},
		{Key: "files", Value: len(m.Files)}}
	if withManifest {
		out = append(out, ojson.KV{Key: "manifest", Value: m})
	}
	return out, nil
}

func (s *Server) listEvidencePacks(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	packs, err := store.TxFrom(r.Context()).EvidencePacks()
	if err != nil {
		return nil, err
	}
	out := []ojson.Object{}
	for _, pk := range packs {
		v, err := packView(pk, false)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return ojson.Object{{Key: "packs", Value: out}, {Key: "frameworks", Value: frameworkList()}}, nil
}

func frameworkList() []ojson.Object {
	out := []ojson.Object{}
	for _, f := range evidence.Frameworks() {
		out = append(out, ojson.Object{{Key: "id", Value: f.ID}, {Key: "name", Value: f.Name}, {Key: "controls", Value: f.Controls}})
	}
	return out
}

var packFields = []field{
	{name: "framework", kind: kLiteral, required: true, lits: evidence.IDs()},
	{name: "from", kind: kStr, required: true},
	{name: "to", kind: kStr, required: true},
}

// POST /api/evidence/packs: from and to are dates or datetimes; a date "from"
// is the start of that day and a date "to" includes that day. The period is
// [from, to) and ends no later than now.
func (s *Server) createEvidencePack(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	body, berrs, err := bodyModel(r, packFields, true)
	if err != nil {
		return nil, err
	}
	if len(berrs) > 0 {
		return nil, validated(p, berrs)
	}
	now := s.clock()
	rawFrom, rawTo := body["from"].(string), body["to"].(string)
	from, _, ferr := parseWhen(rawFrom)
	to, toDateOnly, terr := parseWhen(rawTo)
	if ferr != nil {
		berrs = append(berrs, verr{Type: "value_error", Loc: []any{"body", "from"}, Msg: "Input should be a valid date or datetime", Input: rawFrom})
	}
	if terr != nil {
		berrs = append(berrs, verr{Type: "value_error", Loc: []any{"body", "to"}, Msg: "Input should be a valid date or datetime", Input: rawTo})
	}
	if len(berrs) == 0 {
		if toDateOnly {
			to = to.AddDate(0, 0, 1)
		}
		if to.After(now) {
			to = now
		}
		switch {
		case !from.Before(to):
			berrs = append(berrs, verr{Type: "value_error", Loc: []any{"body", "from"}, Msg: "from must be before to, and in the past", Input: rawFrom})
		case to.Sub(from) > maxPackDays*24*time.Hour:
			berrs = append(berrs, verr{Type: "value_error", Loc: []any{"body", "to"},
				Msg: fmt.Sprintf("the period must be at most %d days", maxPackDays), Input: rawTo})
		}
	}
	if err := validated(p, berrs); err != nil {
		return nil, err
	}
	fw, _ := evidence.Lookup(body["framework"].(string))
	pr := principal(r)
	c := store.TxFrom(r.Context())
	id := uuid.NewString()
	res, err := evidence.Generate(c, evidence.Input{ID: id, Framework: fw, From: from, To: to, Now: now,
		By: pr.Display, Tenant: c.Tenant().String()})
	if err != nil {
		return nil, err
	}
	pack := &store.EvidencePack{ID: id, Framework: fw.ID, PeriodFrom: from, PeriodTo: to, GeneratedAt: now,
		GeneratedBy: pr.Display, ManifestSHA256: res.SHA256, Manifest: res.ManifestJSON, SizeBytes: int64(len(res.Zip)),
		Content: res.Zip}
	if err := c.InsertEvidencePack(pack); err != nil {
		return nil, err
	}
	// The ledger event is in this transaction: a pack without its event is not stored.
	if _, err := c.RecordAudit(store.AuditRecord{At: now, Action: "evidence.pack_generated", TargetType: "evidence_pack",
		TargetID: id, Detail: ojson.Object{{Key: "framework", Value: fw.ID}, {Key: "period_from", Value: timeutil.ISO(from)},
			{Key: "period_to", Value: timeutil.ISO(to)}, {Key: "manifest_sha256", Value: res.SHA256},
			{Key: "files", Value: len(res.Manifest.Files)}, {Key: "size_bytes", Value: len(res.Zip)}}}); err != nil {
		return nil, err
	}
	v, err := packView(pack, true)
	if err != nil {
		return nil, err
	}
	return statusBody{status: http.StatusCreated, body: v}, nil
}

func packID(p *params) (string, error) {
	id, err := uuid.Parse(p.path["pack_id"])
	if err != nil {
		return "", errStatus(http.StatusNotFound, "evidence pack not found")
	}
	return id.String(), nil
}

func (s *Server) evidencePack(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := packID(p)
	if err != nil {
		return nil, err
	}
	pk, err := store.TxFrom(r.Context()).EvidencePack(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "evidence pack not found")
	}
	if err != nil {
		return nil, err
	}
	return packView(pk, true)
}

func (s *Server) evidencePackDownload(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := packID(p)
	if err != nil {
		return nil, err
	}
	pk, err := store.TxFrom(r.Context()).EvidencePack(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errStatus(http.StatusNotFound, "evidence pack not found")
	}
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("tessera-evidence-%s-%s-%s.zip", pk.Framework, pk.PeriodFrom.Format("20060102"),
		pk.PeriodTo.Format("20060102"))
	return fileBody{contentType: "application/zip", filename: name, body: pk.Content,
		headers: map[string]string{"X-Tessera-Manifest-SHA256": pk.ManifestSHA256}}, nil
}

// fileBody is a download, written after the request's tenant transaction
// commits (like statusBody). The filename is built from fixed tokens only.
type fileBody struct {
	contentType string
	filename    string
	body        []byte
	headers     map[string]string
}

func writeFile(w http.ResponseWriter, fb fileBody) {
	w.Header().Set("Content-Type", fb.contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+fb.filename+`"`)
	w.Header().Set("Content-Length", fmt.Sprint(len(fb.body)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	for k, v := range fb.headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(fb.body) // #nosec G705 -- an application/zip attachment, never rendered as HTML
}
