// Package questionnaires holds the forms asked of requesters and reviewers (issue #298):
// definitions (versioned, edited only by appending a version), where they are attached,
// the validation of answers against the version asked, and the audit detail of answers.
//
// A questionnaire is attached to a catalog item or business role (the requester answers at
// submit), to the privileged tier (every privileged catalog item and high-risk role) or to a
// review campaign (the reviewer answers with each decision). The server validates every
// answer against the questionnaire version in force, so no client can skip or alter it.
package questionnaires

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Question types.
const (
	ShortText    = "short_text"
	LongText     = "long_text"
	SingleChoice = "single_choice"
	MultiChoice  = "multi_choice"
	YesNo        = "yes_no"
	Date         = "date"
)

// Types lists the question types, in the order the editor offers them.
var Types = []string{ShortText, LongText, SingleChoice, MultiChoice, YesNo, Date}

// Limits.
const (
	MaxQuestions     = 30
	MaxTitle         = 120
	MaxDescription   = 500
	MaxQuestionText  = 300
	MaxHelp          = 300
	MaxOptions       = 20
	MaxOptionText    = 100
	DefaultShortText = 200
	DefaultLongText  = 2000
	CapShortText     = 500
	CapLongText      = 5000
	DateLayout       = "2006-01-02"
)

var questionIDRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// Question is one question of a version. Options is for the choice types, MaxLength for the
// text types (0: the type's default).
type Question struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Text      string   `json:"text"`
	Help      string   `json:"help,omitempty"`
	Required  bool     `json:"required"`
	Options   []string `json:"options,omitempty"`
	MaxLength int      `json:"max_length,omitempty"`
}

// Error is a refusal; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------- definitions

// Spec is what an admin writes: a title, a description and the ordered questions.
type Spec struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Questions   []Question `json:"questions"`
}

// Check validates and normalizes a spec: it trims text, gives a question without an id the
// next free "qN", and refuses what the answer checks could not apply.
func (s Spec) Check() (Spec, error) {
	s.Title, s.Description = strings.TrimSpace(s.Title), strings.TrimSpace(s.Description)
	switch {
	case s.Title == "" || utf8.RuneCountInString(s.Title) > MaxTitle:
		return s, refuse(422, "invalid_title", "a title of 1 to %d characters is required", MaxTitle)
	case utf8.RuneCountInString(s.Description) > MaxDescription:
		return s, refuse(422, "invalid_description", "a description is at most %d characters", MaxDescription)
	case len(s.Questions) == 0 || len(s.Questions) > MaxQuestions:
		return s, refuse(422, "invalid_questions", "a questionnaire has 1 to %d questions", MaxQuestions)
	}
	seen := map[string]bool{}
	for _, q := range s.Questions {
		seen[q.ID] = true
	}
	out := make([]Question, 0, len(s.Questions))
	used := map[string]bool{}
	next := 1
	for i, q := range s.Questions {
		q.ID, q.Text, q.Help = strings.TrimSpace(q.ID), strings.TrimSpace(q.Text), strings.TrimSpace(q.Help)
		if q.ID == "" {
			for {
				q.ID = "q" + strconv.Itoa(next)
				next++
				if !seen[q.ID] && !used[q.ID] {
					break
				}
			}
		}
		n := i + 1
		switch {
		case !questionIDRE.MatchString(q.ID):
			return s, refuse(422, "invalid_question_id", "question %d: an id is lowercase letters, digits and _, starting with a letter (at most 32)", n)
		case used[q.ID]:
			return s, refuse(422, "duplicate_question_id", "question %d: id %q is used twice", n, q.ID)
		case !slices.Contains(Types, q.Type):
			return s, refuse(422, "invalid_question_type", "question %d: type is one of %s", n, strings.Join(Types, ", "))
		case q.Text == "" || utf8.RuneCountInString(q.Text) > MaxQuestionText:
			return s, refuse(422, "invalid_question_text", "question %d: the text is 1 to %d characters", n, MaxQuestionText)
		case utf8.RuneCountInString(q.Help) > MaxHelp:
			return s, refuse(422, "invalid_question_help", "question %d: the help text is at most %d characters", n, MaxHelp)
		}
		used[q.ID] = true
		if err := checkQuestionShape(&q, n); err != nil {
			return s, err
		}
		out = append(out, q)
	}
	s.Questions = out
	return s, nil
}

func checkQuestionShape(q *Question, n int) error {
	isText := q.Type == ShortText || q.Type == LongText
	isChoice := q.Type == SingleChoice || q.Type == MultiChoice
	if !isChoice && len(q.Options) > 0 {
		return refuse(422, "invalid_options", "question %d: only choice questions have options", n)
	}
	if !isText && q.MaxLength != 0 {
		return refuse(422, "invalid_max_length", "question %d: only text questions have a maximum length", n)
	}
	if isText {
		limit := CapShortText
		if q.Type == LongText {
			limit = CapLongText
		}
		if q.MaxLength < 0 || q.MaxLength > limit {
			return refuse(422, "invalid_max_length", "question %d: the maximum length is 1 to %d characters", n, limit)
		}
	}
	if isChoice {
		if len(q.Options) < 2 || len(q.Options) > MaxOptions {
			return refuse(422, "invalid_options", "question %d: a choice question has 2 to %d options", n, MaxOptions)
		}
		seen := map[string]bool{}
		for i, o := range q.Options {
			o = strings.TrimSpace(o)
			if o == "" || utf8.RuneCountInString(o) > MaxOptionText || seen[o] {
				return refuse(422, "invalid_options", "question %d: options are distinct, 1 to %d characters each", n, MaxOptionText)
			}
			seen[o] = true
			q.Options[i] = o
		}
	}
	return nil
}

// maxLen is the longest answer a text question takes.
func (q Question) maxLen() int {
	switch {
	case q.MaxLength > 0:
		return q.MaxLength
	case q.Type == LongText:
		return DefaultLongText
	}
	return DefaultShortText
}

// Target is one place a questionnaire is asked.
type Target struct {
	Kind     string `json:"kind"`
	TargetID string `json:"target_id"`
}

// Definition is a questionnaire at its current version, with where it is attached.
type Definition struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	Version     int        `json:"version"`
	Questions   []Question `json:"questions"`
	Targets     []Target   `json:"targets"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedBy   string     `json:"updated_by"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// parse reads a stored version's questions.
func parse(v *store.QuestionnaireVersion) ([]Question, error) {
	var qs []Question
	if err := json.Unmarshal([]byte(v.Questions), &qs); err != nil {
		return nil, fmt.Errorf("questionnaire %s v%d: %w", v.QuestionnaireID, v.Version, err)
	}
	return qs, nil
}

// Get returns a questionnaire's current version with its targets.
func Get(tx *store.TenantTx, id string) (*Definition, error) {
	q, err := tx.Questionnaire(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "questionnaire_not_found", "questionnaire not found")
	} else if err != nil {
		return nil, err
	}
	ats, err := tx.QuestionnaireAttachments()
	if err != nil {
		return nil, err
	}
	return definition(tx, q, ats)
}

func definition(tx *store.TenantTx, q *store.Questionnaire, ats []*store.QuestionnaireAttachment) (*Definition, error) {
	v, err := tx.QuestionnaireVersion(q.ID, q.Version)
	if err != nil {
		return nil, err
	}
	qs, err := parse(v)
	if err != nil {
		return nil, err
	}
	d := &Definition{ID: q.ID, Title: q.Title, Description: v.Description, Status: q.Status, Version: q.Version, Questions: qs,
		Targets: []Target{}, CreatedAt: q.CreatedAt, UpdatedBy: q.UpdatedBy, UpdatedAt: q.UpdatedAt}
	for _, a := range ats {
		if a.QuestionnaireID == q.ID {
			d.Targets = append(d.Targets, Target{a.Kind, a.TargetID})
		}
	}
	return d, nil
}

// List returns every questionnaire at its current version.
func List(tx *store.TenantTx) ([]*Definition, error) {
	qs, err := tx.Questionnaires()
	if err != nil {
		return nil, err
	}
	ats, err := tx.QuestionnaireAttachments()
	if err != nil {
		return nil, err
	}
	out := make([]*Definition, 0, len(qs))
	for _, q := range qs {
		d, err := definition(tx, q, ats)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// Versions returns every version of a questionnaire, newest first.
func Versions(tx *store.TenantTx, id string) ([]Spec, []int, error) {
	if _, err := Get(tx, id); err != nil {
		return nil, nil, err
	}
	vs, err := tx.QuestionnaireVersions(id)
	if err != nil {
		return nil, nil, err
	}
	specs, nums := make([]Spec, 0, len(vs)), make([]int, 0, len(vs))
	for _, v := range vs {
		qs, err := parse(v)
		if err != nil {
			return nil, nil, err
		}
		specs = append(specs, Spec{Title: v.Title, Description: v.Description, Questions: qs})
		nums = append(nums, v.Version)
	}
	return specs, nums, nil
}

func versionRow(id string, version int, s Spec, by string) (*store.QuestionnaireVersion, error) {
	raw, err := json.Marshal(s.Questions)
	if err != nil {
		return nil, err
	}
	return &store.QuestionnaireVersion{QuestionnaireID: id, Version: version, Title: s.Title, Description: s.Description,
		Questions: string(raw), CreatedBy: by}, nil
}

func titleTaken(tx *store.TenantTx, title, except string) error {
	all, err := tx.Questionnaires()
	if err != nil {
		return err
	}
	for _, q := range all {
		if q.ID != except && strings.EqualFold(q.Title, title) {
			return refuse(409, "title_taken", "a questionnaire titled %q exists", q.Title)
		}
	}
	return nil
}

// Create adds a questionnaire at version 1. The change is audited in the same transaction.
func Create(tx *store.TenantTx, s Spec, by string, now time.Time) (*Definition, error) {
	s, err := s.Check()
	if err != nil {
		return nil, err
	}
	if err := titleTaken(tx, s.Title, ""); err != nil {
		return nil, err
	}
	id := uuid.NewString()
	v, err := versionRow(id, 1, s, by)
	if err != nil {
		return nil, err
	}
	if err := tx.InsertQuestionnaire(id, v, now); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, by, "questionnaire.create", ojson.Object{{Key: "questionnaire_id", Value: id}, {Key: "title", Value: s.Title},
		{Key: "version", Value: 1}, {Key: "questions", Value: len(s.Questions)}}); err != nil {
		return nil, err
	}
	return Get(tx, id)
}

// Edit appends a new version. ver is the version the editor read; a different current version
// is a conflict, so two admins cannot silently overwrite each other.
func Edit(tx *store.TenantTx, id string, ver int, s Spec, by string, now time.Time) (*Definition, error) {
	s, err := s.Check()
	if err != nil {
		return nil, err
	}
	cur, err := Get(tx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case cur.Status != "active":
		return nil, refuse(409, "questionnaire_retired", "a retired questionnaire cannot be edited")
	case cur.Version != ver:
		return nil, refuse(409, "version_conflict", "the questionnaire changed since version %d (now %d); reload it", ver, cur.Version)
	}
	if err := titleTaken(tx, s.Title, id); err != nil {
		return nil, err
	}
	v, err := versionRow(id, ver+1, s, by)
	if err != nil {
		return nil, err
	}
	if ok, err := tx.AddQuestionnaireVersion(v, now); err != nil {
		return nil, err
	} else if !ok {
		return nil, refuse(409, "version_conflict", "the questionnaire changed since version %d; reload it", ver)
	}
	if err := tx.Audit(now, by, "questionnaire.update", ojson.Object{{Key: "questionnaire_id", Value: id}, {Key: "title", Value: s.Title},
		{Key: "version", Value: ver + 1}, {Key: "previous_version", Value: ver}, {Key: "questions", Value: len(s.Questions)}}); err != nil {
		return nil, err
	}
	return Get(tx, id)
}

// Retire stops a questionnaire being asked: its attachments are removed, its answers stay.
func Retire(tx *store.TenantTx, id string, by string, now time.Time) (*Definition, error) {
	cur, err := Get(tx, id)
	if err != nil {
		return nil, err
	}
	if cur.Status != "active" {
		return nil, refuse(409, "questionnaire_retired", "the questionnaire is already retired")
	}
	if _, err := tx.RetireQuestionnaire(id, by, now); err != nil {
		return nil, err
	}
	if err := tx.ReplaceQuestionnaireAttachments(id, nil); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, by, "questionnaire.retire", ojson.Object{{Key: "questionnaire_id", Value: id}, {Key: "title", Value: cur.Title},
		{Key: "version", Value: cur.Version}}); err != nil {
		return nil, err
	}
	return Get(tx, id)
}

// SetTargets replaces where a questionnaire is asked. Each target must exist and be free (one
// questionnaire per target). It is audited with the targets before and after.
func SetTargets(tx *store.TenantTx, id string, targets []Target, by string, now time.Time) (*Definition, error) {
	cur, err := Get(tx, id)
	if err != nil {
		return nil, err
	}
	if cur.Status != "active" {
		return nil, refuse(409, "questionnaire_retired", "a retired questionnaire cannot be attached")
	}
	seen := map[Target]bool{}
	rows := make([]store.QuestionnaireAttachment, 0, len(targets))
	for _, t := range targets {
		t.TargetID = strings.TrimSpace(t.TargetID)
		if seen[t] {
			continue
		}
		seen[t] = true
		if err := checkTarget(tx, t); err != nil {
			return nil, err
		}
		if held, err := tx.QuestionnaireAttachmentFor(t.Kind, t.TargetID); err == nil && held.QuestionnaireID != id {
			return nil, refuse(409, "target_taken", "%s %s already has a questionnaire; detach it there first", t.Kind, t.TargetID)
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		rows = append(rows, store.QuestionnaireAttachment{Kind: t.Kind, TargetID: t.TargetID})
	}
	if err := tx.ReplaceQuestionnaireAttachments(id, rows); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, by, "questionnaire.attach", ojson.Object{{Key: "questionnaire_id", Value: id}, {Key: "title", Value: cur.Title},
		{Key: "targets", Value: targetDetail(rows)}, {Key: "previous", Value: targetDetailOf(cur.Targets)}}); err != nil {
		return nil, err
	}
	return Get(tx, id)
}

func targetDetail(rows []store.QuestionnaireAttachment) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Kind + ":" + r.TargetID
	}
	return out
}

func targetDetailOf(ts []Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Kind + ":" + t.TargetID
	}
	return out
}

func checkTarget(tx *store.TenantTx, t Target) error {
	var err error
	switch t.Kind {
	case store.QTargetPrivileged:
		if t.TargetID != store.QPrivilegedTarget {
			return refuse(422, "invalid_target", "the privileged target is %q", store.QPrivilegedTarget)
		}
		return nil
	case store.QTargetCatalogItem:
		_, err = tx.CatalogItem(t.TargetID)
	case store.QTargetBusinessRole:
		_, err = tx.BusinessRole(t.TargetID)
	case store.QTargetReviewCampaign:
		n, perr := strconv.ParseInt(t.TargetID, 10, 64)
		if perr != nil || n < 1 {
			return refuse(422, "invalid_target", "a review campaign target is its numeric id")
		}
		_, err = tx.Campaign(n)
	default:
		return refuse(422, "invalid_target_kind", "a target is %s, %s, %s or %s", store.QTargetCatalogItem, store.QTargetBusinessRole,
			store.QTargetReviewCampaign, store.QTargetPrivileged)
	}
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "target_not_found", "%s %s not found", t.Kind, t.TargetID)
	}
	return err
}
