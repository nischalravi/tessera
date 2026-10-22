package flatfile

import (
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// The views are what the API answers. Every value that came from a file or
// a person is passed through Neutralize, so an export of any of them is safe
// to open in a spreadsheet (a value stored neutralised is left as it is).

// MappingView is a saved mapping.
type MappingView struct {
	System       string           `json:"system"`
	Name         string           `json:"name"`
	Owner        string           `json:"owner"`
	Accounts     AccountCols      `json:"accounts"`
	Entitlements *EntitlementCols `json:"entitlements"`
	UpdatedBy    string           `json:"updated_by"`
	UpdatedAt    string           `json:"updated_at"`
}

// ViewMapping renders a saved mapping.
func ViewMapping(s *store.FlatMapping) (MappingView, error) {
	m, err := FromStore(s)
	if err != nil {
		return MappingView{}, err
	}
	v := MappingView{System: m.System, Name: Neutralize(m.Name), Owner: Neutralize(m.Owner), UpdatedBy: Neutralize(s.UpdatedBy),
		UpdatedAt: timeutil.ISO(s.UpdatedAt),
		Accounts: AccountCols{AccountID: Neutralize(m.Accounts.AccountID), Username: Neutralize(m.Accounts.Username),
			Email: Neutralize(m.Accounts.Email), IdentityID: Neutralize(m.Accounts.IdentityID), Status: Neutralize(m.Accounts.Status)}}
	if e := m.Entitlements; e != nil {
		v.Entitlements = &EntitlementCols{AccountID: Neutralize(e.AccountID), Entitlement: Neutralize(e.Entitlement),
			Name: Neutralize(e.Name), Privileged: Neutralize(e.Privileged)}
	}
	return v, nil
}

// UploadView is one upload of the history.
type UploadView struct {
	ID             string `json:"id"`
	System         string `json:"system"`
	Kind           string `json:"kind"`
	Source         string `json:"source"`
	Filename       string `json:"filename"`
	SHA256         string `json:"sha256"`
	SizeBytes      int    `json:"size_bytes"`
	Status         string `json:"status"`
	RowsTotal      int    `json:"rows_total"`
	RowsRejected   int    `json:"rows_rejected"`
	Added          int    `json:"added"`
	Removed        int    `json:"removed"` // removals applied; the deletion guard's held ones are in Held
	Held           int    `json:"held,omitempty"`
	HoldID         string `json:"hold_id,omitempty"`
	Changed        int    `json:"changed"`
	Unchanged      int    `json:"unchanged"`
	TasksConfirmed int    `json:"tasks_confirmed"`
	UploadedBy     string `json:"uploaded_by"`
	UploadedAt     string `json:"uploaded_at"`
}

// ViewUpload renders an upload.
func ViewUpload(u *store.FlatUpload) UploadView {
	return UploadView{ID: u.ID, System: u.System, Kind: u.Kind, Source: u.Source, Filename: Neutralize(u.Filename), SHA256: u.SHA256,
		SizeBytes: u.SizeBytes, Status: u.Status, RowsTotal: u.RowsTotal, RowsRejected: u.RowsRejected, Added: u.Added,
		Removed: u.Removed, Held: u.Held, HoldID: u.HoldID, Changed: u.Changed, Unchanged: u.Unchanged, TasksConfirmed: u.TasksConfirmed,
		UploadedBy: Neutralize(u.UploadedBy), UploadedAt: timeutil.ISO(u.UploadedAt)}
}

// UploadDetail is an upload with its per-row errors and its delta.
type UploadDetail struct {
	UploadView
	Errors []RowError `json:"errors"`
	// ErrorsTruncated: more rows were rejected than are listed (rows_rejected
	// counts them all).
	ErrorsTruncated bool     `json:"errors_truncated"`
	Changes         []Change `json:"changes"`
}

// ViewErrors renders rejected rows.
func ViewErrors(in []RowError) []RowError {
	out := make([]RowError, len(in))
	for i, e := range in {
		out[i] = RowError{Row: e.Row, Column: Neutralize(e.Column), Code: e.Code, Message: Neutralize(e.Message)}
	}
	return out
}

// ViewChanges renders a delta's lines.
func ViewChanges(in []Change) []Change {
	out := make([]Change, len(in))
	for i, c := range in {
		out[i] = Change{Kind: c.Kind, Type: c.Type, Label: Neutralize(c.Label), Detail: c.Detail}
	}
	return out
}

// ViewDetail renders an upload with its errors and changes read from the store.
func ViewDetail(c *store.TenantTx, u *store.FlatUpload) (UploadDetail, error) {
	d := UploadDetail{UploadView: ViewUpload(u), Errors: []RowError{}, Changes: []Change{}}
	errs, err := c.FlatUploadErrors(u.ID)
	if err != nil {
		return d, err
	}
	for _, e := range errs {
		d.Errors = append(d.Errors, RowError{Row: e.Row, Column: e.Column, Code: e.Code, Message: e.Message})
	}
	d.Errors = ViewErrors(d.Errors)
	d.ErrorsTruncated = u.RowsRejected > len(d.Errors) && len(d.Errors) >= MaxStoredErrors
	chs, err := c.FlatChanges(u.ID)
	if err != nil {
		return d, err
	}
	for _, ch := range chs {
		d.Changes = append(d.Changes, Change{Kind: ch.Kind, Type: ch.Change, Label: ch.Label, Detail: ch.Detail})
	}
	d.Changes = ViewChanges(d.Changes)
	return d, nil
}

// TaskView is a manual fulfilment task.
type TaskView struct {
	ID             string  `json:"id"`
	System         string  `json:"system"`
	Kind           string  `json:"kind"`
	Account        string  `json:"account"`
	AccountLabel   string  `json:"account_label"`
	Entitlement    string  `json:"entitlement"`
	IdentityID     *int64  `json:"identity_id"`
	Trigger        string  `json:"trigger"`
	Status         string  `json:"status"`
	Instruction    string  `json:"instruction"`
	CreatedBy      string  `json:"created_by"`
	CreatedAt      string  `json:"created_at"`
	ClosedBy       *string `json:"closed_by"`
	ClosedAt       *string `json:"closed_at"`
	CloseReason    string  `json:"close_reason"`
	ClosedUploadID *string `json:"closed_upload_id"`
}

// ViewTask renders a task, with what the person doing it has to do.
func ViewTask(t *store.FlatTask) TaskView {
	label := Neutralize(t.AccountLabel)
	what := fmt.Sprintf("Disable the account %s in %s by hand, then upload the next accounts file to confirm it.", label, t.System)
	if t.Kind == TaskRemoveEntitlement {
		what = fmt.Sprintf("Remove %s from the account %s in %s by hand, then upload the next entitlements file to confirm it.",
			Neutralize(t.Entitlement), label, t.System)
	}
	v := TaskView{ID: t.ID, System: t.System, Kind: t.Kind, Account: Neutralize(t.AccountXID), AccountLabel: label,
		Entitlement: Neutralize(t.Entitlement), IdentityID: t.IdentityID, Trigger: t.Trigger, Status: t.Status, Instruction: what,
		CreatedBy: Neutralize(t.CreatedBy), CreatedAt: timeutil.ISO(t.CreatedAt), CloseReason: Neutralize(t.CloseReason),
		ClosedUploadID: t.ClosedUploadID}
	if t.ClosedBy != nil {
		by := Neutralize(*t.ClosedBy)
		v.ClosedBy = &by
	}
	v.ClosedAt = timeutil.ISOPtr(t.ClosedAt)
	return v
}
