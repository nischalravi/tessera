package connectors

import (
	"context"
	"time"
)

// Contractor statuses a vendor-management system (VMS) reports (issue #304).
const (
	VmsPending = "pending" // approved, not started
	VmsActive  = "active"  // on assignment
	VmsEnded   = "ended"   // assignment completed or terminated
)

// VmsRecord is one contractor assignment as a VMS (Fieldglass, Beeline or a
// generic CSV feed) reports it. System names the feed kind and WorkerID is the
// VMS's own id for the worker, so the pair names the person. EventID is stable
// for one version of the record: the same assignment reported again with the
// same facts has the same id, so a replayed feed changes nothing.
//
// Every contractor needs a sponsor: an employee named by SponsorEmployeeID or
// SponsorEmail. EndsAt drives the contractor's lifecycle, and so the leaver
// plan on that day.
type VmsRecord struct {
	System   string // fieldglass | beeline | csv
	EventID  string
	WorkerID string
	Name     string
	Email    string
	Supplier string // the staffing vendor
	Role     string // job title or role of the assignment

	SponsorEmployeeID string
	SponsorEmail      string

	Status    string
	StartsAt  *time.Time
	EndsAt    *time.Time
	UpdatedAt time.Time
}

// VmsConnector reads contractor assignments from a VMS.
type VmsConnector interface {
	// VmsRecords calls yield for every assignment changed after since (all of
	// them when since is nil), in the order the VMS reports them. It is read-only.
	VmsRecords(ctx context.Context, since *time.Time, yield func(*VmsRecord) error) error
}
