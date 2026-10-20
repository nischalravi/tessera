package questionnaires

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Need is a questionnaire someone must answer, at the version in force now.
type Need struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Version     int        `json:"version"`
	Questions   []Question `json:"questions"`
}

// need returns the questionnaire attached to a target at its current version (nil: none).
func need(tx *store.TenantTx, kind, target string) (*Need, error) {
	at, err := tx.QuestionnaireAttachmentFor(kind, target)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	q, err := tx.Questionnaire(at.QuestionnaireID)
	if err != nil {
		return nil, err
	}
	if q.Status != "active" {
		return nil, nil
	}
	v, err := tx.QuestionnaireVersion(q.ID, q.Version)
	if err != nil {
		return nil, err
	}
	qs, err := parse(v)
	if err != nil {
		return nil, err
	}
	return &Need{ID: q.ID, Title: q.Title, Description: v.Description, Version: q.Version, Questions: qs}, nil
}

// ForItem is what a request for a catalog item asks: the item's own questionnaire and, when its
// group is privileged, the privileged one.
func ForItem(tx *store.TenantTx, itemID string) ([]Need, error) {
	it, err := tx.CatalogItem(itemID)
	if err != nil {
		return nil, err
	}
	g, err := tx.Group(it.GroupID)
	if err != nil {
		return nil, err
	}
	return gather(tx, store.QTargetCatalogItem, itemID, g.Privileged)
}

// ForRole is what a request for a business role asks: the role's own questionnaire and, for a
// high-risk role (the role flavour of privileged), the privileged one.
func ForRole(tx *store.TenantTx, roleID string) ([]Need, error) {
	r, err := tx.BusinessRole(roleID)
	if err != nil {
		return nil, err
	}
	return gather(tx, store.QTargetBusinessRole, roleID, r.Risk == "high")
}

// ForCampaign is what a reviewer answers with each decision of a campaign.
func ForCampaign(tx *store.TenantTx, campaignID int64) ([]Need, error) {
	return gather(tx, store.QTargetReviewCampaign, fmt.Sprint(campaignID), false)
}

func gather(tx *store.TenantTx, kind, target string, privileged bool) ([]Need, error) {
	var out []Need
	n, err := need(tx, kind, target)
	if err != nil {
		return nil, err
	}
	if n != nil {
		out = append(out, *n)
	}
	if privileged {
		p, err := need(tx, store.QTargetPrivileged, store.QPrivilegedTarget)
		if err != nil {
			return nil, err
		}
		if p != nil {
			out = Union(out, []Need{*p})
		}
	}
	return out, nil
}

// Union merges lists of needs; a questionnaire asked twice is asked once.
func Union(lists ...[]Need) []Need {
	var out []Need
	for _, l := range lists {
		for _, n := range l {
			if !slices.ContainsFunc(out, func(o Need) bool { return o.ID == n.ID }) {
				out = append(out, n)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- answers

// Checked is a validated answer set, normalized (trimmed, unanswered optional questions left
// out), with the hash the audit event carries.
type Checked struct {
	Need    Need
	Answers map[string]any
	Hash    string
}

// Validate checks the answers given (questionnaire id -> question id -> value) against the
// questionnaires needed. A needed questionnaire with a required question must be answered; one
// that was not asked must not be. All problems are refusals with status 422.
func Validate(needs []Need, given map[string]map[string]any) ([]Checked, error) {
	for id := range given {
		if !slices.ContainsFunc(needs, func(n Need) bool { return n.ID == id }) {
			return nil, refuse(422, "unexpected_questionnaire", "questionnaire %s is not asked here", id)
		}
	}
	var out []Checked
	for _, n := range needs {
		a, ok := given[n.ID]
		if !ok && !hasRequired(n) {
			continue
		}
		if !ok {
			return nil, refuse(422, "questionnaire_required", "answer the questionnaire %q", n.Title)
		}
		norm, err := n.check(a)
		if err != nil {
			return nil, err
		}
		if len(norm) == 0 {
			continue
		}
		h, err := hashAnswers(norm)
		if err != nil {
			return nil, err
		}
		out = append(out, Checked{Need: n, Answers: norm, Hash: h})
	}
	return out, nil
}

func hasRequired(n Need) bool {
	return slices.ContainsFunc(n.Questions, func(q Question) bool { return q.Required })
}

// hashAnswers is the SHA-256 of the answers as JSON with the keys sorted (encoding/json sorts
// map keys), so the same answers always hash the same.
func hashAnswers(a map[string]any) (string, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (n Need) check(given map[string]any) (map[string]any, error) {
	byID := make(map[string]Question, len(n.Questions))
	for _, q := range n.Questions {
		byID[q.ID] = q
	}
	for id := range given {
		if _, ok := byID[id]; !ok {
			return nil, refuse(422, "unknown_question", "%q has no question %q", n.Title, id)
		}
	}
	out := map[string]any{}
	for _, q := range n.Questions {
		raw, present := given[q.ID]
		if !present || raw == nil {
			if q.Required {
				return nil, refuse(422, "answer_required", "%q: answer %q", n.Title, q.Text)
			}
			continue
		}
		v, empty, err := q.normalize(raw)
		if err != nil {
			return nil, err
		}
		if empty {
			if q.Required {
				return nil, refuse(422, "answer_required", "%q: answer %q", n.Title, q.Text)
			}
			continue
		}
		out[q.ID] = v
	}
	return out, nil
}

// normalize checks one answer against its question: the value (nil for none) and whether it is empty.
func (q Question) normalize(raw any) (any, bool, error) {
	bad := func(format string, args ...any) error {
		return refuse(422, "invalid_answer", "%q: %s", q.Text, fmt.Sprintf(format, args...))
	}
	switch q.Type {
	case ShortText, LongText:
		s, ok := raw.(string)
		if !ok {
			return nil, false, bad("a text answer is expected")
		}
		s = strings.TrimSpace(s)
		if n := utf8.RuneCountInString(s); n > q.maxLen() {
			return nil, false, bad("at most %d characters (%d given)", q.maxLen(), n)
		}
		return s, s == "", nil
	case SingleChoice:
		s, ok := raw.(string)
		if !ok {
			return nil, false, bad("choose one of the options")
		}
		if s == "" {
			return nil, true, nil
		}
		if !slices.Contains(q.Options, s) {
			return nil, false, bad("%q is not one of the options", s)
		}
		return s, false, nil
	case MultiChoice:
		list, ok := asStrings(raw)
		if !ok {
			return nil, false, bad("choose from the options")
		}
		seen := map[string]bool{}
		for _, s := range list {
			if !slices.Contains(q.Options, s) {
				return nil, false, bad("%q is not one of the options", s)
			}
			if seen[s] {
				return nil, false, bad("%q is chosen twice", s)
			}
			seen[s] = true
		}
		// keep the question's option order, so the same choices always hash the same
		sorted := make([]string, 0, len(list))
		for _, o := range q.Options {
			if seen[o] {
				sorted = append(sorted, o)
			}
		}
		return sorted, len(sorted) == 0, nil
	case YesNo:
		b, ok := raw.(bool)
		if !ok {
			return nil, false, bad("yes or no is expected")
		}
		return b, false, nil
	case Date:
		s, ok := raw.(string)
		if !ok {
			return nil, false, bad("a date as YYYY-MM-DD is expected")
		}
		if s = strings.TrimSpace(s); s == "" {
			return nil, true, nil
		}
		if _, err := time.Parse(DateLayout, s); err != nil {
			return nil, false, bad("%q is not a date (YYYY-MM-DD)", s)
		}
		return s, false, nil
	}
	return nil, false, bad("unsupported question type")
}

func asStrings(raw any) ([]string, bool) {
	switch v := raw.(type) {
	case []string:
		return v, true
	case []any:
		out := make([]string, len(v))
		for i, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, false
			}
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

// FromObject converts a decoded ojson object (question id -> value) to the map Validate takes.
func FromObject(o ojson.Object) map[string]any {
	m := make(map[string]any, len(o))
	for _, kv := range o {
		m[kv.Key] = kv.Value
	}
	return m
}

// Record stores validated answers for a subject (a request line, a role request or a review
// item). Answering a subject again (a review decision retried) replaces the earlier answers.
func Record(tx *store.TenantTx, kind, subject string, checked []Checked, by string, now time.Time) error {
	for _, c := range checked {
		raw, err := json.Marshal(c.Answers)
		if err != nil {
			return err
		}
		if err := tx.PutQuestionnaireAnswer(&store.QuestionnaireAnswer{QuestionnaireID: c.Need.ID, Version: c.Need.Version, SubjectKind: kind,
			SubjectID: subject, Answers: string(raw), Hash: c.Hash, AnsweredBy: by}, now); err != nil {
			return err
		}
	}
	return nil
}

// AuditDetail is the list the audit event of a request or decision carries: each questionnaire
// answered, its version and the hash of the answers (not the answers themselves).
func AuditDetail(checked []Checked) []any {
	out := make([]any, len(checked))
	for i, c := range checked {
		out[i] = ojson.Object{{Key: "questionnaire_id", Value: c.Need.ID}, {Key: "version", Value: c.Need.Version},
			{Key: "answers_hash", Value: c.Hash}}
	}
	return out
}

// AnswerItem is one answered question, with the question as it was asked.
type AnswerItem struct {
	QuestionID string `json:"question_id"`
	Text       string `json:"text"`
	Type       string `json:"type"`
	Answer     any    `json:"answer"`
}

// Answered is what a subject's approver or auditor sees: a questionnaire, the version it was
// answered against, and the answers beside their questions.
type Answered struct {
	QuestionnaireID string       `json:"questionnaire_id"`
	Title           string       `json:"title"`
	Version         int          `json:"version"`
	AnswersHash     string       `json:"answers_hash"`
	AnsweredBy      string       `json:"answered_by"`
	AnsweredAt      time.Time    `json:"answered_at"`
	Items           []AnswerItem `json:"items"`
}

// AnswersFor returns the answers given for a subject, in the version they were given against.
func AnswersFor(tx *store.TenantTx, kind, subject string) ([]Answered, error) {
	rows, err := tx.QuestionnaireAnswersFor(kind, subject)
	if err != nil {
		return nil, err
	}
	out := make([]Answered, 0, len(rows))
	for _, r := range rows {
		v, err := tx.QuestionnaireVersion(r.QuestionnaireID, r.Version)
		if err != nil {
			return nil, err
		}
		qs, err := parse(v)
		if err != nil {
			return nil, err
		}
		var given map[string]any
		if err := json.Unmarshal([]byte(r.Answers), &given); err != nil {
			return nil, err
		}
		a := Answered{QuestionnaireID: r.QuestionnaireID, Title: v.Title, Version: r.Version, AnswersHash: r.Hash, AnsweredBy: r.AnsweredBy,
			AnsweredAt: r.AnsweredAt, Items: []AnswerItem{}}
		for _, q := range qs {
			if val, ok := given[q.ID]; ok {
				a.Items = append(a.Items, AnswerItem{q.ID, q.Text, q.Type, val})
			}
		}
		out = append(out, a)
	}
	return out, nil
}
