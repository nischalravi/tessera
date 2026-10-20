// Package inbox is the groups Inbox: tasks that ask the people who administer
// a folder or group to do something (decide a deprovisioning, look at what a
// rule noticed, attest memberships). Design docs/design/groups-grouper-parity.md
// §10.3 to §10.5; issue #57, GR-14.
//
// A task names the object it is about, not the people who see it: it is shown
// to whoever holds admin (stem_admin on a folder) on that object when it is
// listed, or to the identity it names, so losing the privilege takes the task
// away and nothing is copied at creation time.
package inbox

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/gov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Limits on a task's text.
const (
	MaxTitle  = 300
	MaxDetail = 16 << 10
)

// Input is a task to open.
type Input struct {
	Kind       string
	Title      string
	Detail     any // marshalled to JSON; nil is {}
	ObjectType string
	ObjectID   string
	Subject    *int64
	Assignee   *int64
	// DedupeKey makes opening idempotent: while a task with the key is open, a
	// second Open returns it. "" never dedupes.
	DedupeKey string
	DueAt     *time.Time
}

func (in *Input) check() error {
	switch in.Kind {
	case store.TaskDeprovisioning, store.TaskRule, store.TaskMicroCertification, store.TaskAttestation, store.TaskAttestationOverdue:
	default:
		return gov.Invalid("invalid_kind", "%q is not a task kind", in.Kind)
	}
	if in.ObjectType != string(privs.Folder) && in.ObjectType != string(privs.Group) {
		return gov.Invalid("invalid_object", "a task is about a folder or a group")
	}
	if in.Title == "" || len(in.Title) > MaxTitle {
		return gov.Invalid("invalid_title", "title is 1 to %d characters", MaxTitle)
	}
	return nil
}

// Open creates an open task in tx, with its audit event. When the input has a
// DedupeKey and a task with it is open, that task is returned and nothing is
// written (created is false).
func Open(tx *store.TenantTx, now time.Time, in Input) (t *store.GrpTask, created bool, err error) {
	if err := in.check(); err != nil {
		return nil, false, err
	}
	if in.DedupeKey != "" {
		switch t, err := tx.GrpOpenTaskByKey(in.DedupeKey); {
		case err == nil:
			return t, false, nil
		case !errors.Is(err, store.ErrNotFound):
			return nil, false, err
		}
	}
	detail := "{}"
	if in.Detail != nil {
		b, err := json.Marshal(in.Detail)
		if err != nil {
			return nil, false, err
		}
		if len(b) > MaxDetail {
			return nil, false, gov.Invalid("invalid_detail", "a task's detail is at most %d bytes", MaxDetail)
		}
		detail = string(b)
	}
	t = &store.GrpTask{ID: uuid.NewString(), Kind: in.Kind, Title: in.Title, Detail: detail, ObjectType: in.ObjectType,
		ObjectID: in.ObjectID, Subject: in.Subject, Assignee: in.Assignee, DueAt: in.DueAt, CreatedAt: now}
	if in.DedupeKey != "" {
		t.DedupeKey = &in.DedupeKey
	}
	if err := tx.InsertGrpTask(t); err != nil {
		return nil, false, err
	}
	d := ojson.Object{{Key: "task_id", Value: t.ID}, {Key: "kind", Value: t.Kind}, {Key: "object_type", Value: t.ObjectType},
		{Key: "object_id", Value: t.ObjectID}}
	if t.Subject != nil {
		d = append(d, ojson.KV{Key: "identity_id", Value: *t.Subject})
	}
	_, err = tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.inbox.task_opened", LegacyActor: "groups", TargetType: "task",
		TargetID: t.ID, Detail: d})
	return t, true, err
}

// adminOf is the privilege that administers an object of the type.
func adminOf(objectType string) privs.Privilege {
	if objectType == string(privs.Folder) {
		return privs.StemAdmin
	}
	return privs.Admin
}

// Sees reports whether the checker's subject may see and close the task: it is
// the named assignee, or administers the task's object.
func Sees(ck *privs.Checker, t *store.GrpTask) (bool, error) {
	if t.Assignee != nil && ck.Subject().Identity != nil && *t.Assignee == *ck.Subject().Identity {
		return true, nil
	}
	return ck.Has(privs.Object{Type: privs.ObjectType(t.ObjectType), ID: t.ObjectID}, adminOf(t.ObjectType))
}

// List returns a page of the tasks the subject may see, oldest first. It reads
// the table in chunks and filters, so a page never holds a task the subject
// could not see; total is not reported (it would count what is hidden).
func List(tx *store.TenantTx, ck *privs.Checker, f store.GrpTaskFilter, limit, offset int) ([]*store.GrpTask, error) {
	if limit < 1 {
		limit = 100
	}
	const chunk = 500
	var out []*store.GrpTask
	skip := offset
	for raw := 0; len(out) < limit; raw += chunk {
		f.Limit, f.Offset = chunk, raw
		rows, err := tx.GrpTasks(f)
		if err != nil {
			return nil, err
		}
		for _, t := range rows {
			ok, err := Sees(ck, t)
			if err != nil {
				return nil, err
			}
			switch {
			case !ok:
			case skip > 0:
				skip--
			case len(out) < limit:
				out = append(out, t)
			}
		}
		if len(rows) < chunk {
			break
		}
	}
	return out, nil
}

// Close closes an open task as done or dismissed. A task the subject may not
// see is a privilege error naming the privilege that administers its object.
func Close(tx *store.TenantTx, ck *privs.Checker, now time.Time, id, status, by string) (*store.GrpTask, error) {
	if status != store.TaskDone && status != store.TaskDismissed {
		return nil, gov.Invalid("invalid_status", "status is done or dismissed")
	}
	t, err := tx.GrpTask(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, gov.NotFound("no such task")
	}
	if err != nil {
		return nil, err
	}
	if ok, err := Sees(ck, t); err != nil {
		return nil, err
	} else if !ok {
		return nil, &privs.DeniedError{Object: privs.Object{Type: privs.ObjectType(t.ObjectType), ID: t.ObjectID}, Privilege: adminOf(t.ObjectType)}
	}
	if t.Status != store.TaskOpen {
		return nil, gov.Conflict("task_closed", "the task is already %s", t.Status)
	}
	if err := tx.CloseGrpTask(t.ID, status, now, by); err != nil {
		return nil, err
	}
	t.Status, t.ClosedAt = status, &now
	if by != "" {
		t.ClosedBy = &by
	}
	_, err = tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.inbox.task_closed", LegacyActor: "groups", TargetType: "task",
		TargetID: t.ID, Detail: ojson.Object{{Key: "task_id", Value: t.ID}, {Key: "kind", Value: t.Kind}, {Key: "status", Value: status}}})
	return t, err
}

// CloseSystem closes an open task from a job (no subject): used when the work
// it asked for was done another way. A missing or closed task is not an error.
func CloseSystem(tx *store.TenantTx, now time.Time, id, status, by string) error {
	err := tx.CloseGrpTask(id, status, now, by)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = tx.RecordAudit(store.AuditRecord{At: now, Action: "groups.inbox.task_closed", LegacyActor: "groups", TargetType: "task",
		TargetID: id, Detail: ojson.Object{{Key: "task_id", Value: id}, {Key: "status", Value: status}}})
	return err
}
