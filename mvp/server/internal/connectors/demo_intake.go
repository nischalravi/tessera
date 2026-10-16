package connectors

import (
	"context"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

// SIS status values a student information system or admissions CRM sends
// (guest design §4.1). Order of a normal path: applied, admitted, deposited,
// matriculated; withdrawn and denied end an application.
const (
	SisApplied      = "applied"
	SisAdmitted     = "admitted"
	SisDeposited    = "deposited"
	SisMatriculated = "matriculated"
	SisWithdrawn    = "withdrawn"
	SisDenied       = "denied"
)

// SisRecord is one status change of an applicant, admit or student. EventID is
// unique per change (a replay of the same change carries the same id).
// Personal data beyond what matching and the portal need (date of birth,
// phone) is not part of this record: the PR that stores them seals them.
type SisRecord struct {
	EventID     string
	ApplicantID string
	StudentID   string // assigned at deposit or matriculation; empty before
	Name        string
	Email       string // personal email, as given on the application
	Program     string
	Term        string
	Status      string
	EffectiveAt time.Time
	// TermStart bounds an admit: the affiliation runs until matriculation
	// plus 30 days. Nil: the population's maximum duration applies.
	TermStart *time.Time
}

// SisConnector is a Connector that also reports applicant status changes.
// Discover returns an empty snapshot: applicants are not directory people
// until intake gives them an identity.
type SisConnector interface {
	Connector
	// SisRecords calls yield for every status change effective after since
	// (all when since is nil). An error from yield stops the stream.
	SisRecords(ctx context.Context, since *time.Time, yield func(*SisRecord) error) error
}

// DemoSIS is a simulated admissions CRM / SIS: three applicants at different
// points of the funnel, so intake has an applicant, an admit, a student and
// a withdrawal to convert. Like the simulated AD it is staged only: neither
// the default "demo" spec nor TESSERA_CONNECTORS selects it, so the seeded
// demo tenant is unchanged.
type DemoSIS struct{ Now time.Time }

// NewDemoSIS builds the simulated SIS relative to now.
func NewDemoSIS(now time.Time) *DemoSIS { return &DemoSIS{Now: now} }

// System implements Connector.
func (*DemoSIS) System() string { return "sis" }

// DisplayName implements Connector.
func (*DemoSIS) DisplayName() string { return "Admissions CRM / SIS - demo" }

// TypeName implements Connector.
func (*DemoSIS) TypeName() string { return "DemoSISConnector" }

// Discover implements Connector.
func (*DemoSIS) Discover(context.Context) (*DiscoveryResult, error) { return &DiscoveryResult{}, nil }

// StreamEvents implements Connector. A SIS sends no usage or HR events.
func (*DemoSIS) StreamEvents(ctx context.Context, _ *time.Time, _ func(Event) error) error {
	return ctx.Err()
}

// Records is the demo feed in the order a SIS would send it.
func (d *DemoSIS) Records() []*SisRecord {
	day := func(n int) time.Time { return d.Now.AddDate(0, 0, n) }
	termStart := day(120)
	return []*SisRecord{
		{EventID: "sis-evt-1001-a", ApplicantID: "A-1001", Name: "Priya Natarajan", Email: "priya.natarajan@mail.example",
			Program: "Computer Science BS", Term: "Fall", Status: SisApplied, EffectiveAt: day(-90)},
		{EventID: "sis-evt-1001-b", ApplicantID: "A-1001", Name: "Priya Natarajan", Email: "priya.natarajan@mail.example",
			Program: "Computer Science BS", Term: "Fall", Status: SisAdmitted, EffectiveAt: day(-45), TermStart: &termStart},
		{EventID: "sis-evt-1002-a", ApplicantID: "A-1002", Name: "Tomas Ekwueme", Email: "tomas.ekwueme@mail.example",
			Program: "Biology MS", Term: "Fall", Status: SisApplied, EffectiveAt: day(-80)},
		{EventID: "sis-evt-1002-b", ApplicantID: "A-1002", Name: "Tomas Ekwueme", Email: "tomas.ekwueme@mail.example",
			Program: "Biology MS", Term: "Fall", Status: SisWithdrawn, EffectiveAt: day(-10)},
		{EventID: "sis-evt-1003-a", ApplicantID: "A-1003", Name: "Mei Lindqvist", Email: "mei.lindqvist@mail.example",
			Program: "Economics BA", Term: "Fall", Status: SisApplied, EffectiveAt: day(-5)},
	}
}

// SisRecords implements SisConnector.
func (d *DemoSIS) SisRecords(ctx context.Context, since *time.Time, yield func(*SisRecord) error) error {
	for _, r := range d.Records() {
		if since != nil && !r.EffectiveAt.After(*since) {
			continue
		}
		if err := yield(r); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// DemoPrehireHRIS is a simulated HR feed of accepted offers: a future-dated
// hire, one whose offer is later rescinded, and one whose start date has
// arrived. It speaks the existing HRIS model (HrisEventRecord, as the demo
// Workday connector does), so a real HRIS connector that emits joiner events
// with the same payload keys feeds the same intake. Staged only, like DemoSIS.
//
// Payload keys the intake reads from a joiner: worker_id, name, personal_email
// (or email), department, title, manager_external_id, position. A leaver for a
// worker who has not started is a rescinded offer.
type DemoPrehireHRIS struct{ Now time.Time }

// NewDemoPrehireHRIS builds the simulated HR feed relative to now.
func NewDemoPrehireHRIS(now time.Time) *DemoPrehireHRIS { return &DemoPrehireHRIS{Now: now} }

// System implements Connector.
func (*DemoPrehireHRIS) System() string { return "hris-prehire" }

// DisplayName implements Connector.
func (*DemoPrehireHRIS) DisplayName() string { return "HRIS accepted offers - demo" }

// TypeName implements Connector.
func (*DemoPrehireHRIS) TypeName() string { return "DemoPrehireHRISConnector" }

// Discover implements Connector.
func (*DemoPrehireHRIS) Discover(context.Context) (*DiscoveryResult, error) {
	return &DiscoveryResult{}, nil
}

// Events is the demo feed in the order an HRIS would send it.
func (d *DemoPrehireHRIS) Events() []*HrisEventRecord {
	day := func(n int) time.Time { return d.Now.AddDate(0, 0, n) }
	joiner := func(evt, worker, name, email, dept string, at time.Time) *HrisEventRecord {
		return &HrisEventRecord{ExternalID: evt, Type: "joiner", EffectiveAt: at, Payload: ojson.Object{
			{Key: "worker_id", Value: worker}, {Key: "name", Value: name}, {Key: "personal_email", Value: email},
			{Key: "department", Value: dept}, {Key: "title", Value: "Analyst"}, {Key: "manager_external_id", Value: "e-0001"}}}
	}
	return []*HrisEventRecord{
		joiner("wd-evt-7001", "W-7001", "Rowan Pelletier", "rowan.pelletier@mail.example", "Finance", day(14)),
		joiner("wd-evt-7002", "W-7002", "Ines Okafor", "ines.okafor@mail.example", "Data", day(10)),
		{ExternalID: "wd-evt-7002-r", Type: "leaver", Identity: &IdentityRef{ExternalID: "W-7002"}, EffectiveAt: d.Now,
			Payload: ojson.Object{{Key: "reason", Value: "Offer rescinded"}}},
		joiner("wd-evt-7003", "W-7003", "Dara Whitfield", "dara.whitfield@mail.example", "Support", day(1)),
	}
}

// StreamEvents implements Connector.
func (d *DemoPrehireHRIS) StreamEvents(ctx context.Context, since *time.Time, yield func(Event) error) error {
	for _, ev := range d.Events() {
		if since != nil && !ev.EffectiveAt.After(*since) {
			continue
		}
		if err := yield(ev); err != nil {
			return err
		}
	}
	return ctx.Err()
}
