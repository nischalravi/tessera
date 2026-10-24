package requests

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Amending a live request (issue #588): while a line is pending, the people involved can add a
// comment, attach metadata about a document, and an approver can add another approver.
//
// Who: the requester, the beneficiary, someone holding requests.decide, and an approver of the
// current stage (Involved). An added approver is another person who must approve after the stages
// already there; only an approver or decider adds one, never the requester or the beneficiary, and
// never the requester or the beneficiary as the new approver. Attachments are metadata only (Tessera
// stores no file): a name, a type, a size up to MaxAttachmentBytes and an optional reference such as a
// ticket link; the tenant's request settings must allow attachments. Each change is audited in the
// caller's transaction. A line that is no longer pending takes none of them.
const (
	MaxComment         = 1000
	MaxCommentsPerLine = 200
	MaxAttachmentName  = 200
	MaxContentType     = 100
	// MaxAttachmentBytes caps the size an attachment may declare (10 MiB).
	MaxAttachmentBytes = 10 << 20
	MaxLineAttachments = 10
	// MaxLineStages caps the approval stages of a line, added approvers included.
	MaxLineStages = 8
)

// Involved reports whether by takes part in the line: its requester or beneficiary, a decider, or an
// approver of its waiting stage.
func Involved(tx *store.TenantTx, l *store.RequestLine, by Actor, now time.Time) (bool, error) {
	if l.RequestedBy == by.id() || (by.IdentityID != nil && *by.IdentityID == l.BeneficiaryID) || by.Decider {
		return true, nil
	}
	return CanDecide(tx, l, by, now)
}

func livePending(tx *store.TenantTx, id string, by Actor, now time.Time) (*store.RequestLine, error) {
	l, err := get(tx, id)
	if err != nil {
		return nil, err
	}
	if ok, err := Involved(tx, l, by, now); err != nil {
		return nil, err
	} else if !ok {
		return nil, refuse(404, "request_not_found", "request not found")
	}
	if l.Status != store.RequestPending {
		return nil, refuse(409, "not_pending", "the request is %s; only a pending request can be amended", l.Status)
	}
	return l, nil
}

func cleanText(s string, max int, code, what string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > max || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return "", refuse(422, code, "%s is 1 to %d characters", what, max)
	}
	return s, nil
}

// AddComment adds a note to a pending line.
func AddComment(tx *store.TenantTx, id string, by Actor, body string, now time.Time) (*store.RequestComment, error) {
	l, err := livePending(tx, id, by, now)
	if err != nil {
		return nil, err
	}
	body, err = cleanText(body, MaxComment, "invalid_comment", "a comment")
	if err != nil {
		return nil, err
	}
	if n, err := tx.RequestCommentCount(l.ID); err != nil {
		return nil, err
	} else if n >= MaxCommentsPerLine {
		return nil, refuse(422, "too_many_comments", "a request has at most %d comments", MaxCommentsPerLine)
	}
	c := &store.RequestComment{ID: uuid.NewString(), LineID: l.ID, AuthorUserID: by.id(), Author: by.Display, Body: body, CreatedAt: now}
	if err := tx.InsertRequestComment(c); err != nil {
		return nil, err
	}
	return c, tx.Audit(now, by.Display, "request.comment.added", ojson.Object{{Key: "line_id", Value: l.ID},
		{Key: "comment_id", Value: c.ID}, {Key: "length", Value: len(body)}})
}

// AttachmentSpec is the metadata of an attachment.
type AttachmentSpec struct {
	Name        string
	ContentType string
	SizeBytes   int64
	Reference   string
}

// AddAttachment records an attachment's metadata on a pending line.
func AddAttachment(tx *store.TenantTx, id string, by Actor, in AttachmentSpec, now time.Time) (*store.RequestAttachment, error) {
	l, err := livePending(tx, id, by, now)
	if err != nil {
		return nil, err
	}
	set, _, err := LoadSettings(tx)
	if err != nil {
		return nil, err
	}
	if !set.AttachmentsAllowed {
		return nil, refuse(422, "attachments_not_allowed", "attachments are turned off for requests")
	}
	name, err := cleanText(in.Name, MaxAttachmentName, "invalid_attachment", "an attachment name")
	if err != nil {
		return nil, err
	}
	in.ContentType, in.Reference = strings.TrimSpace(in.ContentType), strings.TrimSpace(in.Reference)
	switch {
	case in.SizeBytes < 0 || in.SizeBytes > MaxAttachmentBytes:
		return nil, refuse(422, "attachment_too_large", "an attachment is at most %d bytes", MaxAttachmentBytes)
	case len(in.ContentType) > MaxContentType || len(in.Reference) > MaxAttachmentRef ||
		!utf8.ValidString(in.ContentType) || !utf8.ValidString(in.Reference):
		return nil, refuse(422, "invalid_attachment", "the type is at most %d characters and the reference at most %d", MaxContentType, MaxAttachmentRef)
	}
	if n, err := tx.RequestAttachmentCount(l.ID); err != nil {
		return nil, err
	} else if n >= MaxLineAttachments {
		return nil, refuse(422, "too_many_attachments", "a request has at most %d attachments", MaxLineAttachments)
	}
	a := &store.RequestAttachment{ID: uuid.NewString(), LineID: l.ID, Name: name, ContentType: in.ContentType, SizeBytes: in.SizeBytes,
		Reference: in.Reference, AddedBy: by.id(), AddedByName: by.Display, CreatedAt: now}
	if err := tx.InsertRequestAttachment(a); err != nil {
		return nil, err
	}
	return a, tx.Audit(now, by.Display, "request.attachment.added", ojson.Object{{Key: "line_id", Value: l.ID},
		{Key: "attachment_id", Value: a.ID}, {Key: "size_bytes", Value: a.SizeBytes}})
}

// AddApprover appends a stage decided by the given person to a pending line. It opens when the
// stages before it are approved.
func AddApprover(tx *store.TenantTx, id string, by Actor, approverID int64, reason string, now time.Time) (*store.RequestLine, error) {
	l, err := get(tx, id)
	if err != nil {
		return nil, err
	}
	if l.Status != store.RequestPending {
		return nil, refuse(409, "not_pending", "the request is %s; only a pending request can be amended", l.Status)
	}
	if same, err := tx.SameActor(l.RequestedBy, by.id()); err != nil {
		return nil, err
	} else if same || (by.IdentityID != nil && *by.IdentityID == l.BeneficiaryID) {
		return nil, refuse(403, "self_approval", "you cannot change the approvers of a request you made or that grants you access")
	}
	if err := RefuseUnlinked(by); err != nil {
		return nil, err
	}
	if ok, err := CanDecide(tx, l, by, now); err != nil {
		return nil, err
	} else if !ok && !by.Decider {
		return nil, refuse(403, "not_an_approver", "you are not an approver of this request")
	}
	why, err := reasonPtr(reason, true)
	if err != nil {
		return nil, err
	}
	stages, err := tx.RequestStages(l.ID)
	if err != nil {
		return nil, err
	}
	if len(stages) == 0 {
		return nil, refuse(409, "no_stages", "this request has no approval stages to add to")
	}
	if len(stages) >= MaxLineStages {
		return nil, refuse(422, "too_many_stages", "a request has at most %d approval stages", MaxLineStages)
	}
	next := 0
	for _, s := range stages {
		next = max(next, s.Idx+1)
		if s.Status != store.StageApproved && s.Status != store.StageClosed && s.AssigneeID != nil && *s.AssigneeID == approverID {
			return nil, refuse(409, "already_an_approver", "that person already approves this request")
		}
	}
	if approverID == l.BeneficiaryID {
		return nil, refuse(422, "invalid_approver", "the person the access is for cannot approve it")
	}
	ap, err := tx.Identity(approverID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, refuse(422, "invalid_approver", "that person was not found")
		}
		return nil, err
	}
	users, err := tx.UsersLinkedTo(ap.ID)
	if err != nil {
		return nil, err
	}
	if ap.Status != "active" || len(users) == 0 {
		return nil, refuse(422, "invalid_approver", "an approver is an active person who can sign in")
	}
	for _, u := range users {
		if same, err := tx.SameActor(l.RequestedBy, u); err != nil {
			return nil, err
		} else if same {
			return nil, refuse(422, "invalid_approver", "the requester cannot approve their own request")
		}
	}
	st := &store.RequestStage{LineID: l.ID, Idx: next, Kind: store.StageOwner, AssigneeID: &ap.ID, Status: store.StageQueued}
	if err := tx.InsertRequestStage(st); err != nil {
		return nil, err
	}
	return l, tx.Audit(now, by.Display, "request.approver.added", ojson.Object{{Key: "line_id", Value: l.ID},
		{Key: "stage", Value: next}, {Key: "approver_identity_id", Value: ap.ID}, {Key: "reason", Value: *why}})
}
