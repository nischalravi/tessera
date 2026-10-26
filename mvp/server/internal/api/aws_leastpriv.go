package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/leastpriv"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Unused-access findings with a confidence (issue #645, LP-2). For each
// permission the evaluator says a principal holds, this says whether the usage
// ingest (LP-1) saw it used in the window, and how far "not used" can be
// trusted (internal/leastpriv/confidence.go): high, medium, low or unknown,
// with the reasons. It reads; nothing is changed by it.

func (s *Server) registerAWSLeastPrivRoutes() {
	s.handle(http.MethodGet, "/api/aws/principals/{arn}/least-privilege", read, need(auth.PermGraphRead), s.rd(s.awsLeastPriv))
}

const (
	awsLPDefaultDays = 60
	awsLPMaxDays     = 365
)

type awsLPItem struct {
	Action     string               `json:"action"`
	Resource   string               `json:"resource"`
	Outcome    string               `json:"outcome"`
	Fidelity   string               `json:"fidelity"`
	Used       bool                 `json:"used"`
	LastUsed   *string              `json:"last_used"`
	Confidence leastpriv.Confidence `json:"confidence"`
}

type awsLPView struct {
	Principal  string         `json:"principal"`
	Snapshot   awsSnapshotRef `json:"snapshot"`
	Connector  string         `json:"connector"`
	UnusedDays int            `json:"unused_days"`
	Total      int            `json:"total"`
	Items      []awsLPItem    `json:"items"`
	Next       *string        `json:"next_cursor"`
}

// awsLeastPriv answers GET /api/aws/principals/{arn}/least-privilege
// ?connector=&unused_days=&created=&service=&limit=&cursor=&snapshot=&profile=
//
// connector defaults to the snapshot's own. created (RFC 3339 or YYYY-MM-DD) is
// the identity's creation date; without it the level is capped at medium. A
// permission counts as used when the principal's rows name its action in the
// window, or name its service as a whole (Access Advisor): the finding is then
// "used", never an unused one.
func (s *Server) awsLeastPriv(r *http.Request, p *params) (int, any, error) {
	arn, err := awsName("principal", p.path["arn"], true)
	if err != nil {
		return 0, nil, err
	}
	q := r.URL.Query()
	service := strings.ToLower(q.Get("service"))
	if service != "" && !awsServiceRE.MatchString(service) {
		return 0, nil, badRequest("invalid_service", "service must be a service prefix such as s3")
	}
	days := awsLPDefaultDays
	if v := q.Get("unused_days"); v != "" {
		if days, err = strconv.Atoi(v); err != nil || days < 1 || days > awsLPMaxDays {
			return 0, nil, badRequest("invalid_unused_days", "unused_days must be 1 to "+strconv.Itoa(awsLPMaxDays))
		}
	}
	var created *time.Time
	if v := q.Get("created"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			if t, err = time.Parse("2006-01-02", v); err != nil {
				return 0, nil, badRequest("invalid_created", "created must be RFC 3339 or YYYY-MM-DD")
			}
		}
		created = &t
	}
	limit, cursor, err := awsPage(q)
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	ac, err := s.awsContext(tx, q.Get("snapshot"))
	if err != nil {
		return 0, nil, err
	}
	connector, err := awsName("connector", q.Get("connector"), false)
	if err != nil {
		return 0, nil, err
	}
	if connector == "" {
		connector = ac.hdr.ConnectorID
	}
	if connector == "" {
		return 0, nil, badRequest("invalid_connector", "connector is required: the snapshot has none of its own")
	}
	qr, _, err := s.awsQuerier(ac, q.Get("profile"))
	if err != nil {
		return 0, nil, err
	}
	perms, err := qr.EffectivePermissions(r.Context(), arn)
	if err != nil {
		return 0, nil, awsEvalErr(err)
	}

	now := s.clock()
	today := now.UTC().Truncate(24 * time.Hour)
	since := today.AddDate(0, 0, -(days - 1)).Format("2006-01-02")
	rows, err := tx.AWSUsage(connector, arn, since, 0)
	if err != nil {
		return 0, nil, err
	}
	states, err := tx.AWSUsageStates(connector)
	if err != nil {
		return 0, nil, err
	}
	gaps, err := tx.AWSUsageGaps(connector, 0)
	if err != nil {
		return 0, nil, err
	}
	lastByAction := map[string]string{} // lower-cased action or "svc:*" -> latest day
	var active []string
	seenDay := map[string]bool{}
	for _, u := range rows {
		k := strings.ToLower(u.Action)
		if u.Day > lastByAction[k] {
			lastByAction[k] = u.Day
		}
		if !seenDay[u.Day] {
			seenDay[u.Day] = true
			active = append(active, u.Day)
		}
	}
	ev := leastpriv.AWSEvidence{States: states, Gaps: gaps}
	facts := leastpriv.PrincipalFacts{ARN: arn, Created: created, ActiveDays: active}

	// count the cells before expanding them
	ix := ac.eng.ix
	total := 0
	for _, row := range perms.Rows {
		n := 0
		for _, a := range ix.Actions.MemberNames(row.Action) {
			if service == "" || strings.HasPrefix(strings.ToLower(a), service+":") {
				n++
			}
		}
		total += n * len(ix.Resources.Atoms[row.Resource].Members)
		if total > awsMaxEffectiveCells {
			return 0, nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "too_large",
				Msg: "more than " + strconv.Itoa(awsMaxEffectiveCells) + " permissions: narrow the answer with service="}
		}
	}
	var cells []awsLPCell
	for _, c := range perms.Expand() {
		if service != "" && !strings.HasPrefix(strings.ToLower(c.Action), service+":") {
			continue
		}
		if c.Cell.Outcome != authz.Allow && c.Cell.Outcome != authz.Conditional {
			continue
		}
		cells = append(cells, awsLPCell{c.Action, c.Resource, c.Cell.Outcome.String(), c.Cell.Fidelity.String()})
	}
	if cursor > len(cells) {
		return 0, nil, badRequest("invalid_cursor", "cursor is past the end of the answer")
	}
	end := min(cursor+limit, len(cells))
	items := make([]awsLPItem, 0, end-cursor)
	for _, c := range cells[cursor:end] {
		la, used := lastByAction[strings.ToLower(c.action)]
		if svc, _, ok := strings.Cut(strings.ToLower(c.action), ":"); ok {
			if ls, ok := lastByAction[svc+":*"]; ok {
				used = true
				if ls > la {
					la = ls
				}
			}
		}
		it := awsLPItem{Action: c.action, Resource: c.resource, Outcome: c.outcome, Fidelity: c.fidelity, Used: used,
			Confidence: leastpriv.Assess(now, days, c.action, used, ev, facts)}
		if used {
			it.LastUsed = &la
		}
		items = append(items, it)
	}
	view := &awsLPView{Principal: arn, Snapshot: snapshotRef(ac.hdr), Connector: connector, UnusedDays: days, Total: len(cells), Items: items}
	if end < len(cells) {
		next := strconv.Itoa(end)
		view.Next = &next
	}
	return http.StatusOK, view, nil
}

type awsLPCell struct{ action, resource, outcome, fidelity string }
