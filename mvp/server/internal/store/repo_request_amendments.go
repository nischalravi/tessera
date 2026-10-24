package store

import (
	"database/sql"
	"time"
)

// Comments and attachment metadata on a live request line (schema/0911_request_amendments.sql, issue #588).

// RequestComment is a note on a line.
type RequestComment struct {
	ID           string
	LineID       string
	AuthorUserID string
	Author       string
	Body         string
	CreatedAt    time.Time
}

// RequestAttachment is metadata about a file a person attached; Tessera stores no file.
type RequestAttachment struct {
	ID          string
	LineID      string
	Name        string
	ContentType string
	SizeBytes   int64
	Reference   string
	AddedBy     string
	AddedByName string
	CreatedAt   time.Time
}

var (
	reqCommentIns = tq("request_comments.insert", `
		INSERT INTO access_request_comments (id, tenant_id, line_id, author_user_id, author, body, created_at)
		VALUES (@id, @tenant, @line_id, @author_user_id, @author, @body, @created_at)`)
	reqCommentList = tq("request_comments.list", `
		SELECT c.id, c.line_id, c.author_user_id, c.author, c.body, c.created_at FROM access_request_comments c
		WHERE c.tenant_id = @tenant AND c.line_id = @line_id ORDER BY c.created_at, c.id`)
	reqCommentCount = tq("request_comments.count", `
		SELECT COUNT(*) FROM access_request_comments c WHERE c.tenant_id = @tenant AND c.line_id = @line_id`)
	reqAttachIns = tq("request_attachments.insert", `
		INSERT INTO access_request_attachments (id, tenant_id, line_id, name, content_type, size_bytes, reference, added_by,
			added_by_name, created_at)
		VALUES (@id, @tenant, @line_id, @name, @content_type, @size_bytes, @reference, @added_by, @added_by_name, @created_at)`)
	reqAttachList = tq("request_attachments.list", `
		SELECT a.id, a.line_id, a.name, a.content_type, a.size_bytes, a.reference, a.added_by, a.added_by_name, a.created_at
		FROM access_request_attachments a WHERE a.tenant_id = @tenant AND a.line_id = @line_id ORDER BY a.created_at, a.id`)
	reqAttachCount = tq("request_attachments.count", `
		SELECT COUNT(*) FROM access_request_attachments a WHERE a.tenant_id = @tenant AND a.line_id = @line_id`)
)

// InsertRequestComment adds a comment to a line.
func (tx *TenantTx) InsertRequestComment(c *RequestComment) error {
	_, err := tx.exec(reqCommentIns, sql.Named("id", c.ID), sql.Named("line_id", c.LineID), sql.Named("author_user_id", c.AuthorUserID),
		sql.Named("author", c.Author), sql.Named("body", c.Body), sql.Named("created_at", RT(c.CreatedAt)))
	return err
}

// RequestComments lists a line's comments, oldest first.
func (tx *TenantTx) RequestComments(lineID string) ([]*RequestComment, error) {
	return collect(tx, func(s scanner) (*RequestComment, error) {
		var c RequestComment
		var at string
		if err := s.Scan(&c.ID, &c.LineID, &c.AuthorUserID, &c.Author, &c.Body, &at); err != nil {
			return nil, err
		}
		var err error
		c.CreatedAt, err = ParseRT(at)
		return &c, err
	}, reqCommentList, sql.Named("line_id", lineID))
}

// RequestCommentCount is how many comments a line has.
func (tx *TenantTx) RequestCommentCount(lineID string) (n int, err error) {
	err = tx.queryRow(reqCommentCount, sql.Named("line_id", lineID)).Scan(&n)
	return n, err
}

// InsertRequestAttachment records an attachment's metadata on a line.
func (tx *TenantTx) InsertRequestAttachment(a *RequestAttachment) error {
	_, err := tx.exec(reqAttachIns, sql.Named("id", a.ID), sql.Named("line_id", a.LineID), sql.Named("name", a.Name),
		sql.Named("content_type", a.ContentType), sql.Named("size_bytes", a.SizeBytes), sql.Named("reference", a.Reference),
		sql.Named("added_by", a.AddedBy), sql.Named("added_by_name", a.AddedByName), sql.Named("created_at", RT(a.CreatedAt)))
	return err
}

// RequestAttachments lists a line's attachments, oldest first.
func (tx *TenantTx) RequestAttachments(lineID string) ([]*RequestAttachment, error) {
	return collect(tx, func(s scanner) (*RequestAttachment, error) {
		var a RequestAttachment
		var at string
		if err := s.Scan(&a.ID, &a.LineID, &a.Name, &a.ContentType, &a.SizeBytes, &a.Reference, &a.AddedBy, &a.AddedByName, &at); err != nil {
			return nil, err
		}
		var err error
		a.CreatedAt, err = ParseRT(at)
		return &a, err
	}, reqAttachList, sql.Named("line_id", lineID))
}

// RequestAttachmentCount is how many attachments a line has.
func (tx *TenantTx) RequestAttachmentCount(lineID string) (n int, err error) {
	err = tx.queryRow(reqAttachCount, sql.Named("line_id", lineID)).Scan(&n)
	return n, err
}
