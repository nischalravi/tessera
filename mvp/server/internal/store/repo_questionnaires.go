package store

import (
	"database/sql"
	"time"
)

// Questionnaires, their versions, attachments and answers (schema/0450_questionnaires.sql,
// issue #298). The rules (question types, validation, who must answer what) live in
// internal/questionnaires; the store keeps the JSON as given.

// Attachment target kinds.
const (
	QTargetCatalogItem    = "catalog_item"
	QTargetBusinessRole   = "business_role"
	QTargetReviewCampaign = "review_campaign"
	QTargetPrivileged     = "privileged" // target id QPrivilegedTarget
)

// QPrivilegedTarget is the target id of the privileged attachment.
const QPrivilegedTarget = "*"

// Answer subject kinds.
const (
	QSubjectRequestLine = "request_line"
	QSubjectRoleRequest = "role_request"
	QSubjectReviewItem  = "review_item"
)

// Questionnaire is a definition's identity and current version.
type Questionnaire struct {
	ID        string
	Title     string
	Status    string // active | retired
	Version   int
	CreatedAt time.Time
	UpdatedBy string
	UpdatedAt time.Time
}

// QuestionnaireVersion is one immutable version; Questions is a JSON list.
type QuestionnaireVersion struct {
	QuestionnaireID string
	Version         int
	Title           string
	Description     string
	Questions       string
	CreatedBy       string
	CreatedAt       time.Time
}

// QuestionnaireAttachment says where a questionnaire is asked.
type QuestionnaireAttachment struct {
	QuestionnaireID string
	Kind            string
	TargetID        string
}

// QuestionnaireAnswer is one answered questionnaire; Answers is a JSON object keyed by question id.
type QuestionnaireAnswer struct {
	QuestionnaireID string
	Version         int
	SubjectKind     string
	SubjectID       string
	Answers         string
	Hash            string
	AnsweredBy      string
	AnsweredAt      time.Time
}

const (
	qCols  = `q.id, q.title, q.status, q.version, q.created_at, q.updated_by, q.updated_at`
	qvCols = `v.questionnaire_id, v.version, v.title, v.description, v.questions, v.created_by, v.created_at`
	qaCols = `a.questionnaire_id, a.version, a.subject_kind, a.subject_id, a.answers, a.answers_hash, a.answered_by, a.answered_at`
)

var (
	qList = tq("questionnaires.list", `SELECT `+qCols+` FROM questionnaires q WHERE q.tenant_id = @tenant ORDER BY q.title, q.id`)
	qGet  = tq("questionnaires.get", `SELECT `+qCols+` FROM questionnaires q WHERE q.tenant_id = @tenant AND q.id = @id`)
	qIns  = tq("questionnaires.insert", `
		INSERT INTO questionnaires (id, tenant_id, title, status, version, created_at, updated_by, updated_at)
		VALUES (@id, @tenant, @title, 'active', 1, @now, @by, @now)`)
	qBump = tq("questionnaires.bump", `
		UPDATE questionnaires SET title = @title, version = version + 1, updated_by = @by, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND version = @version AND status = 'active'`)
	qRetire = tq("questionnaires.retire", `
		UPDATE questionnaires SET status = 'retired', updated_by = @by, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'active'`)
	qvIns = tq("questionnaire_versions.insert", `
		INSERT INTO questionnaire_versions (tenant_id, questionnaire_id, version, title, description, questions, created_by, created_at)
		VALUES (@tenant, @id, @version, @title, @description, @questions, @by, @now)`)
	qvGet = tq("questionnaire_versions.get", `
		SELECT `+qvCols+` FROM questionnaire_versions v WHERE v.tenant_id = @tenant AND v.questionnaire_id = @id AND v.version = @version`)
	qvList = tq("questionnaire_versions.list", `
		SELECT `+qvCols+` FROM questionnaire_versions v WHERE v.tenant_id = @tenant AND v.questionnaire_id = @id ORDER BY v.version DESC`)
	qatList = tq("questionnaire_attachments.list", `
		SELECT t.questionnaire_id, t.target_kind, t.target_id FROM questionnaire_attachments t
		WHERE t.tenant_id = @tenant ORDER BY t.target_kind, t.target_id`)
	qatFor = tq("questionnaire_attachments.for_target", `
		SELECT t.questionnaire_id, t.target_kind, t.target_id FROM questionnaire_attachments t
		WHERE t.tenant_id = @tenant AND t.target_kind = @kind AND t.target_id = @target`)
	qatClear = tq("questionnaire_attachments.clear", `
		DELETE FROM questionnaire_attachments WHERE tenant_id = @tenant AND questionnaire_id = @id`)
	qatIns = tq("questionnaire_attachments.insert", `
		INSERT INTO questionnaire_attachments (tenant_id, questionnaire_id, target_kind, target_id)
		VALUES (@tenant, @id, @kind, @target)`)
	qaPut = tq("questionnaire_answers.put", `
		INSERT INTO questionnaire_answers (tenant_id, questionnaire_id, version, subject_kind, subject_id, answers, answers_hash,
			answered_by, answered_at)
		VALUES (@tenant, @id, @version, @kind, @subject, @answers, @hash, @by, @now)
		ON CONFLICT (tenant_id, subject_kind, subject_id, questionnaire_id) DO UPDATE SET version = excluded.version,
			answers = excluded.answers, answers_hash = excluded.answers_hash, answered_by = excluded.answered_by,
			answered_at = excluded.answered_at`)
	qaFor = tq("questionnaire_answers.for_subject", `
		SELECT `+qaCols+` FROM questionnaire_answers a
		WHERE a.tenant_id = @tenant AND a.subject_kind = @kind AND a.subject_id = @subject ORDER BY a.questionnaire_id`)
	qaBetween = tq("questionnaire_answers.between", `
		SELECT `+qaCols+`, v.title FROM questionnaire_answers a
		JOIN questionnaire_versions v ON v.tenant_id = a.tenant_id AND v.questionnaire_id = a.questionnaire_id AND v.version = a.version
		WHERE a.tenant_id = @tenant AND v.tenant_id = @tenant AND a.answered_at >= @from AND a.answered_at < @to
		ORDER BY a.answered_at, a.subject_kind, a.subject_id, a.questionnaire_id`)
	qaCount = tq("questionnaire_answers.count_for_questionnaire", `
		SELECT count(*) FROM questionnaire_answers a WHERE a.tenant_id = @tenant AND a.questionnaire_id = @id`)
)

func scanQuestionnaire(s scanner) (*Questionnaire, error) {
	var q Questionnaire
	var created, updated string
	if err := s.Scan(&q.ID, &q.Title, &q.Status, &q.Version, &created, &q.UpdatedBy, &updated); err != nil {
		return nil, err
	}
	var err error
	if q.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	q.UpdatedAt, err = ParseRT(updated)
	return &q, err
}

func scanQuestionnaireVersion(s scanner) (*QuestionnaireVersion, error) {
	var v QuestionnaireVersion
	var at string
	if err := s.Scan(&v.QuestionnaireID, &v.Version, &v.Title, &v.Description, &v.Questions, &v.CreatedBy, &at); err != nil {
		return nil, err
	}
	var err error
	v.CreatedAt, err = ParseRT(at)
	return &v, err
}

func scanQuestionnaireAttachment(s scanner) (*QuestionnaireAttachment, error) {
	var t QuestionnaireAttachment
	err := s.Scan(&t.QuestionnaireID, &t.Kind, &t.TargetID)
	return &t, err
}

func scanQuestionnaireAnswer(s scanner) (*QuestionnaireAnswer, error) {
	var a QuestionnaireAnswer
	var at string
	if err := s.Scan(&a.QuestionnaireID, &a.Version, &a.SubjectKind, &a.SubjectID, &a.Answers, &a.Hash, &a.AnsweredBy, &at); err != nil {
		return nil, err
	}
	var err error
	a.AnsweredAt, err = ParseRT(at)
	return &a, err
}

// Questionnaires lists the tenant's questionnaires by title.
func (tx *TenantTx) Questionnaires() ([]*Questionnaire, error) {
	return collect(tx, scanQuestionnaire, qList)
}

// Questionnaire returns one by id; ErrNotFound if it is not the tenant's.
func (tx *TenantTx) Questionnaire(id string) (*Questionnaire, error) {
	return one(tx, scanQuestionnaire, qGet, sql.Named("id", id))
}

// InsertQuestionnaire creates a questionnaire at version 1 with its first version row.
func (tx *TenantTx) InsertQuestionnaire(id string, v *QuestionnaireVersion, now time.Time) error {
	if _, err := tx.exec(qIns, sql.Named("id", id), sql.Named("title", v.Title), sql.Named("by", v.CreatedBy), sql.Named("now", RT(now))); err != nil {
		return err
	}
	v.QuestionnaireID, v.Version = id, 1
	return tx.insertQuestionnaireVersion(v, now)
}

func (tx *TenantTx) insertQuestionnaireVersion(v *QuestionnaireVersion, now time.Time) error {
	_, err := tx.exec(qvIns, sql.Named("id", v.QuestionnaireID), sql.Named("version", v.Version), sql.Named("title", v.Title),
		sql.Named("description", v.Description), sql.Named("questions", v.Questions), sql.Named("by", v.CreatedBy), sql.Named("now", RT(now)))
	return err
}

// AddQuestionnaireVersion appends version v.Version (the current one plus one) and moves the
// questionnaire on; false means the current version is no longer v.Version-1 (or it is retired).
func (tx *TenantTx) AddQuestionnaireVersion(v *QuestionnaireVersion, now time.Time) (bool, error) {
	res, err := tx.exec(qBump, sql.Named("id", v.QuestionnaireID), sql.Named("title", v.Title), sql.Named("version", v.Version-1),
		sql.Named("by", v.CreatedBy), sql.Named("now", RT(now)))
	if err != nil {
		return false, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return false, err
	}
	return true, tx.insertQuestionnaireVersion(v, now)
}

// RetireQuestionnaire retires an active questionnaire; false if it already was.
func (tx *TenantTx) RetireQuestionnaire(id, by string, now time.Time) (bool, error) {
	res, err := tx.exec(qRetire, sql.Named("id", id), sql.Named("by", by), sql.Named("now", RT(now)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// QuestionnaireVersion returns one version; ErrNotFound if there is none.
func (tx *TenantTx) QuestionnaireVersion(id string, version int) (*QuestionnaireVersion, error) {
	return one(tx, scanQuestionnaireVersion, qvGet, sql.Named("id", id), sql.Named("version", version))
}

// QuestionnaireVersions lists a questionnaire's versions, newest first.
func (tx *TenantTx) QuestionnaireVersions(id string) ([]*QuestionnaireVersion, error) {
	return collect(tx, scanQuestionnaireVersion, qvList, sql.Named("id", id))
}

// QuestionnaireAttachments lists every attachment of the tenant.
func (tx *TenantTx) QuestionnaireAttachments() ([]*QuestionnaireAttachment, error) {
	return collect(tx, scanQuestionnaireAttachment, qatList)
}

// QuestionnaireAttachmentFor returns the attachment of a target; ErrNotFound if it has none.
func (tx *TenantTx) QuestionnaireAttachmentFor(kind, target string) (*QuestionnaireAttachment, error) {
	return one(tx, scanQuestionnaireAttachment, qatFor, sql.Named("kind", kind), sql.Named("target", target))
}

// ReplaceQuestionnaireAttachments sets where a questionnaire is asked. A target another
// questionnaire already holds is a unique-constraint error; the service checks first.
func (tx *TenantTx) ReplaceQuestionnaireAttachments(id string, targets []QuestionnaireAttachment) error {
	if _, err := tx.exec(qatClear, sql.Named("id", id)); err != nil {
		return err
	}
	for _, t := range targets {
		if _, err := tx.exec(qatIns, sql.Named("id", id), sql.Named("kind", t.Kind), sql.Named("target", t.TargetID)); err != nil {
			return err
		}
	}
	return nil
}

// PutQuestionnaireAnswer records (or, for a retried decision, replaces) a subject's answers.
func (tx *TenantTx) PutQuestionnaireAnswer(a *QuestionnaireAnswer, now time.Time) error {
	_, err := tx.exec(qaPut, sql.Named("id", a.QuestionnaireID), sql.Named("version", a.Version), sql.Named("kind", a.SubjectKind),
		sql.Named("subject", a.SubjectID), sql.Named("answers", a.Answers), sql.Named("hash", a.Hash), sql.Named("by", a.AnsweredBy),
		sql.Named("now", RT(now)))
	return err
}

// QuestionnaireAnswersFor lists the answers given for one subject.
func (tx *TenantTx) QuestionnaireAnswersFor(kind, subject string) ([]*QuestionnaireAnswer, error) {
	return collect(tx, scanQuestionnaireAnswer, qaFor, sql.Named("kind", kind), sql.Named("subject", subject))
}

// QuestionnaireAnswerCount is how many answers a questionnaire has received.
func (tx *TenantTx) QuestionnaireAnswerCount(id string) (int, error) {
	return tx.count(qaCount, sql.Named("id", id))
}

// AnsweredQuestionnaire is an answer with the title of the version it was given against.
type AnsweredQuestionnaire struct {
	QuestionnaireAnswer
	Title string
}

// QuestionnaireAnswersBetween lists the answers given in [from, to), oldest first (evidence packs).
func (tx *TenantTx) QuestionnaireAnswersBetween(from, to time.Time) ([]*AnsweredQuestionnaire, error) {
	return collect(tx, func(s scanner) (*AnsweredQuestionnaire, error) {
		var a AnsweredQuestionnaire
		var at string
		if err := s.Scan(&a.QuestionnaireID, &a.Version, &a.SubjectKind, &a.SubjectID, &a.Answers, &a.Hash, &a.AnsweredBy, &at, &a.Title); err != nil {
			return nil, err
		}
		var err error
		a.AnsweredAt, err = ParseRT(at)
		return &a, err
	}, qaBetween, sql.Named("from", RT(from)), sql.Named("to", RT(to)))
}
