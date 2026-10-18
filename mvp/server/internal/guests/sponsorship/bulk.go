package sponsorship

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// MaxBulkRows is the most rows one bulk invitation takes.
const MaxBulkRows = 500

// CSVHeader is the header of a bulk invitation file. A "bundle" column (group
// ids of requestable catalog items, separated by ";") may follow.
var CSVHeader = []string{"email", "given_name", "family_name", "population", "starts_at", "ends_at", "purpose"}

// Row is one parsed line of a bulk file. Err is set when the line itself is
// unusable (a date that does not parse); it fails that row only.
type Row struct {
	Line   int // 1-based line of the file, counting the header as line 1
	Invite Invite
	Code   string
	Msg    string
}

func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("a date is YYYY-MM-DD or RFC 3339")
}

// ParseCSV reads a bulk invitation file: a header (email, given_name,
// family_name, population, starts_at, ends_at, purpose), then up to 500 rows.
// A bad file is refused whole (422); a bad row is returned with its code.
func ParseCSV(raw string) ([]Row, error) {
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(raw, "\ufeff")))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	head, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, refuse(422, "empty_file", "the file has no header")
	} else if err != nil {
		return nil, refuse(422, "invalid_csv", "the file is not valid CSV")
	}
	for i := range head {
		head[i] = strings.ToLower(strings.TrimSpace(head[i]))
	}
	if len(head) < len(CSVHeader) || !slices.Equal(head[:len(CSVHeader)], CSVHeader) || len(head) > len(CSVHeader)+1 ||
		len(head) == len(CSVHeader)+1 && head[len(CSVHeader)] != "bundle" {
		return nil, refuse(422, "invalid_header", "the header is %s", strings.Join(CSVHeader, ","))
	}
	var rows []Row
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				return nil, refuse(422, "invalid_csv", "line %d is not valid CSV", pe.Line)
			}
			return nil, refuse(422, "invalid_csv", "the file is not valid CSV")
		}
		line, _ := r.FieldPos(0)
		if len(rows) >= MaxBulkRows {
			return nil, refuse(422, "too_many_rows", "a file has at most %d rows", MaxBulkRows)
		}
		row := Row{Line: line}
		if len(rec) != len(head) {
			row.Code, row.Msg = "invalid_row", fmt.Sprintf("the row has %d columns, the header %d", len(rec), len(head))
			rows = append(rows, row)
			continue
		}
		in := Invite{Email: rec[0], GivenName: rec[1], FamilyName: rec[2], Population: strings.ToLower(strings.TrimSpace(rec[3])), Purpose: rec[6]}
		var e1, e2 error
		in.StartsAt, e1 = parseTime(rec[4])
		in.EndsAt, e2 = parseTime(rec[5])
		switch {
		case e1 != nil || e2 != nil:
			row.Code, row.Msg = "invalid_dates", "a date is YYYY-MM-DD or RFC 3339"
		case len(head) > len(CSVHeader):
			for _, f := range strings.Split(rec[len(CSVHeader)], ";") {
				if f = strings.TrimSpace(f); f == "" {
					continue
				}
				id, err := strconv.ParseInt(f, 10, 64)
				if err != nil {
					row.Code, row.Msg = "invalid_bundle", "bundle is group ids separated by ;"
					break
				}
				in.Bundle = append(in.Bundle, id)
			}
		}
		row.Invite = in
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, refuse(422, "empty_file", "the file has a header but no rows")
	}
	return rows, nil
}

// Row statuses of a bulk result.
const (
	RowOK            = "ok"             // dry run: would be created
	RowNeedsApproval = "needs_approval" // would be created and wait for a second approver
	RowCreated       = "created"
	RowRefused       = "refused" // the policy or the input says no; nothing was written
)

// RowResult is the outcome of one row. A refusal carries the stable code of
// the rule that said no; PolicyVersion is the policy that decided.
type RowResult struct {
	Row           int      `json:"row"`
	Email         string   `json:"email"`
	Population    string   `json:"population"`
	Status        string   `json:"status"`
	Code          string   `json:"code,omitempty"`
	Message       string   `json:"message,omitempty"`
	NeedsApproval bool     `json:"needs_approval"`
	PolicyVersion string   `json:"policy_version"`
	Rules         []string `json:"rules,omitempty"`
	SponsorshipID string   `json:"sponsorship_id,omitempty"`
}

// BulkResult is a bulk invitation's outcome.
type BulkResult struct {
	DryRun        bool        `json:"dry_run"`
	BatchID       string      `json:"batch_id,omitempty"`
	PolicyVersion string      `json:"policy_version"`
	Rows          []RowResult `json:"rows"`
	Created       int         `json:"created"`
	WouldCreate   int         `json:"would_create"`
	Refused       int         `json:"refused"`
}

// BulkInvite judges every row of a file against the sponsor policy, each as
// the execution would (the rows before it count against the sponsor's
// limits), and, unless dryRun, creates the rows the policy permits. One bad
// row never blocks the others; a dry run writes nothing but its audit event.
func (s *Service) BulkInvite(tx *store.TenantTx, by Actor, rows []Row, dryRun bool, now time.Time) (*BulkResult, error) {
	if len(rows) == 0 || len(rows) > MaxBulkRows {
		return nil, refuse(422, "too_many_rows", "a file has 1 to %d rows", MaxBulkRows)
	}
	res := &BulkResult{DryRun: dryRun, PolicyVersion: s.Policy.Version, Rows: make([]RowResult, 0, len(rows))}
	if !dryRun {
		res.BatchID = uuid.NewString()
	}
	carry, seen := &Carry{}, map[string]bool{}
	for _, row := range rows {
		rr := RowResult{Row: row.Line, Email: strings.TrimSpace(row.Invite.Email), Population: row.Invite.Population, PolicyVersion: s.Policy.Version}
		refused := func(code, msg string, rules []string) {
			rr.Status, rr.Code, rr.Message, rr.Rules = RowRefused, code, msg, rules
			res.Refused++
		}
		norm, nerr := identifiers.Normalize(store.IdentEmail, row.Invite.Email)
		switch {
		case row.Code != "":
			refused(row.Code, row.Msg, nil)
		case nerr == nil && seen[norm]:
			refused("duplicate_in_file", "this email is on an earlier row of the file", nil)
		default:
			if nerr == nil {
				seen[norm] = true
			}
			var c *Carry
			if dryRun {
				c = carry
			}
			p, err := s.Check(tx, by, row.Invite, nil, c, now)
			if err != nil {
				return nil, err
			}
			rr.PolicyVersion, rr.Rules = p.Decision.Version, p.Decision.Rules
			if !p.Decision.Allowed {
				refused(p.Decision.Code, p.Decision.Message, p.Decision.Rules)
				break
			}
			rr.NeedsApproval = p.Decision.NeedsApproval
			rr.Status = RowOK
			if rr.NeedsApproval {
				rr.Status = RowNeedsApproval
			}
			if dryRun {
				carry.bump(p.Population.Key)
				res.WouldCreate++
				break
			}
			out, err := s.writeInvite(tx, by, p, store.ChannelBulkInvite, res.BatchID, now)
			if err != nil {
				return nil, err
			}
			rr.Status, rr.SponsorshipID = RowCreated, out.Sponsorship.ID
			res.Created++
		}
		res.Rows = append(res.Rows, rr)
	}
	action, n := "sponsorship.bulk_invite", res.Created
	if dryRun {
		action, n = "sponsorship.bulk_preview", res.WouldCreate
	}
	d := ojson.Object{{Key: "rows", Value: len(rows)}, {Key: "accepted", Value: n}, {Key: "refused", Value: res.Refused},
		{Key: "policy_version", Value: s.Policy.Version}}
	if res.BatchID != "" {
		d = append(d, ojson.KV{Key: "batch_id", Value: res.BatchID})
	}
	return res, tx.Audit(now, by.Display, action, d)
}
