// Package vms runs the contractor feeds of a tenant (issue #304): it reads each
// source with its connector (internal/connectors/vms), applies every record
// through internal/intake in its own transaction, and records the outcome on
// the source. The network is read with no transaction open; the source's
// credential is sealed (internal/seal) and opened only to build the connector.
//
// A record that fails to apply does not stop the others, and a sync with a
// failure does not move the source's watermark, so the next run reads the same
// window again (applying a record twice is a no-op).
package vms

import (
	"context"
	"errors"
	"fmt"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	feed "github.com/nischalravi/tessera/mvp/server/internal/connectors/vms"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/intake"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Sync statuses of a report.
const (
	StatusOK      = "ok"
	StatusFailed  = "failed"
	StatusSkipped = "skipped" // paused, or a file source with nothing to fetch
)

// MaxError is the longest error text kept on a source.
const MaxError = 300

// Service syncs contractor sources.
type Service struct {
	DB     *store.DB
	Sealer *seal.Sealer
	HTTP   *http.Client // internal/safehttp
	RT     connsync.Runtime
	Keyer  *identifiers.Keyer
	Clock  timeutil.Clock
	// Build replaces the connector construction (tests).
	Build func(src *store.VmsSource, credential string) (connectors.VmsConnector, error)
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return timeutil.System()
}

// SealCredential seals a source's credential for storage, bound to its row.
func SealCredential(s *seal.Sealer, t tenancy.ID, sourceID, credential string) ([]byte, error) {
	return s.Seal([]byte(credential), seal.AAD(t, "vms_sources", "credential_enc", sourceID))
}

func (s *Service) open(t tenancy.ID, src *store.VmsSource) (string, error) {
	if len(src.CredentialEnc) == 0 {
		return "", nil
	}
	if s.Sealer == nil {
		return "", errors.New("no key is configured to open the credential")
	}
	b, err := s.Sealer.Open(src.CredentialEnc, seal.AAD(t, "vms_sources", "credential_enc", src.ID))
	if err != nil {
		return "", errors.New("the stored credential cannot be opened with the current key")
	}
	return string(b), nil
}

// Report is the result of one source's sync.
type Report struct {
	SourceID string         `json:"source_id"`
	Name     string         `json:"name"`
	Vendor   string         `json:"vendor"`
	Status   string         `json:"status"`
	Records  int            `json:"records"`
	Applied  map[string]int `json:"applied"`
	Failed   int            `json:"failed"`
	Error    string         `json:"error,omitempty"`
}

func (r *Report) count(outcome string) {
	if r.Applied == nil {
		r.Applied = map[string]int{}
	}
	r.Applied[outcome]++
}

// Sync reads the named sources (every active one when none are named).
func (s *Service) Sync(ctx context.Context, tenant tenancy.ID, only ...string) ([]Report, error) {
	var srcs []*store.VmsSource
	if err := s.DB.ReadTenant(ctx, tenant, func(tx *store.TenantTx) error {
		all, err := tx.VmsSources()
		if err != nil {
			return err
		}
		for _, x := range all {
			if len(only) == 0 || contains(only, x.ID) {
				srcs = append(srcs, x)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var out []Report
	for _, src := range srcs {
		rep := s.syncOne(ctx, tenant, src)
		out = append(out, rep)
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
	}
	return out, nil
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// connector builds the reader of a source, or nil when the source has nothing to
// fetch (a CSV source that is uploaded).
func (s *Service) connector(tenant tenancy.ID, src *store.VmsSource) (connectors.VmsConnector, error) {
	cred, err := s.open(tenant, src)
	if err != nil {
		return nil, err
	}
	if s.Build != nil {
		return s.Build(src, cred)
	}
	var set feed.Settings
	if err := unmarshalSettings(src.Settings, &set); err != nil {
		return nil, err
	}
	if src.Vendor == store.VmsCSV {
		if src.BaseURL == "" || set.CSVPath == "" {
			return nil, nil
		}
		base, err := connsync.ParseBaseURL(src.BaseURL, s.RT)
		if err != nil {
			return nil, fmt.Errorf("base URL: %w", err)
		}
		u := *base
		u.Path = set.CSVPath
		return csvConnector{&feed.CSVFetcher{URL: u.String(), Token: connsync.NewSecret(cred), HC: s.HTTP, Settings: set, Now: s.now}}, nil
	}
	return feed.New(feed.Config{Vendor: src.Vendor, BaseURL: src.BaseURL, Settings: set, Credential: cred}, s.RT, s.HTTP, s.now)
}

// csvConnector adapts a fetched CSV file to the connector interface.
type csvConnector struct{ f *feed.CSVFetcher }

func (c csvConnector) VmsRecords(ctx context.Context, _ *time.Time, yield func(*connectors.VmsRecord) error) error {
	res, err := c.f.Fetch(ctx)
	if err != nil {
		return err
	}
	for _, r := range res.Records {
		if err := yield(r); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) syncOne(ctx context.Context, tenant tenancy.ID, src *store.VmsSource) Report {
	rep := Report{SourceID: src.ID, Name: src.Name, Vendor: src.Vendor, Status: StatusOK}
	if src.Status != store.VmsActive {
		rep.Status = StatusSkipped
		return rep
	}
	conn, err := s.connector(tenant, src)
	switch {
	case err != nil:
		return s.finishFailed(ctx, tenant, src, rep, err)
	case conn == nil:
		rep.Status = StatusSkipped
		return rep
	}
	var recs []*connectors.VmsRecord
	if err := conn.VmsRecords(ctx, src.Cursor, func(r *connectors.VmsRecord) error {
		recs = append(recs, r)
		return nil
	}); err != nil {
		return s.finishFailed(ctx, tenant, src, rep, err)
	}
	return s.apply(ctx, tenant, src, rep, recs, true)
}

// Import applies an uploaded CSV file to a CSV source.
func (s *Service) Import(ctx context.Context, tenant tenancy.ID, sourceID string, r io.Reader) (Report, error) {
	var src *store.VmsSource
	if err := s.DB.ReadTenant(ctx, tenant, func(tx *store.TenantTx) (err error) {
		src, err = tx.VmsSource(sourceID)
		return err
	}); err != nil {
		return Report{}, err
	}
	rep := Report{SourceID: src.ID, Name: src.Name, Vendor: src.Vendor, Status: StatusOK}
	if src.Vendor != store.VmsCSV {
		return rep, errors.New("only a CSV source takes an uploaded file")
	}
	var set feed.Settings
	if err := unmarshalSettings(src.Settings, &set); err != nil {
		return rep, err
	}
	res, err := feed.ParseCSV(r, set, s.now())
	if err != nil {
		return rep, err
	}
	rep.Failed = res.BadRows
	// an upload is a whole file, not a window: the watermark does not move
	return s.apply(ctx, tenant, src, rep, res.Records, false), nil
}

// apply puts each record through the intake, then records the result.
func (s *Service) apply(ctx context.Context, tenant tenancy.ID, src *store.VmsSource, rep Report, recs []*connectors.VmsRecord, moveCursor bool) Report {
	rep.Records = len(recs)
	intake.SortVMS(recs)
	var newest *time.Time
	var firstErr error
	for _, r := range recs {
		var res *intake.Result
		err := s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) (err error) {
			// the leavers this feed ends are judged under the feed's own deletion guard settings
			defer deleteguard.ScopeSource(tx, deleteguard.SourceRef{Kind: deleteguard.SrcVMS, ID: src.ID})()
			res, err = intake.ApplyVMS(tx, s.Keyer, r, s.now())
			return err
		})
		if err != nil {
			rep.Failed++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		rep.count(res.Outcome)
		if !r.UpdatedAt.IsZero() && (newest == nil || r.UpdatedAt.After(*newest)) {
			t := r.UpdatedAt
			newest = &t
		}
	}
	if firstErr != nil {
		rep.Status, rep.Error = StatusFailed, fmt.Sprintf("%d records failed; first: %s", rep.Failed, trim(firstErr.Error()))
		newest = nil
	}
	if !moveCursor {
		newest = nil
	}
	s.record(ctx, tenant, src, &rep, newest)
	return rep
}

func (s *Service) finishFailed(ctx context.Context, tenant tenancy.ID, src *store.VmsSource, rep Report, err error) Report {
	rep.Status, rep.Error = StatusFailed, trim(err.Error())
	s.record(ctx, tenant, src, &rep, nil)
	return rep
}

func trim(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > MaxError {
		s = s[:MaxError]
	}
	return strings.ToValidUTF8(s, "")
}

// record stores the outcome on the source and writes the audit event.
func (s *Service) record(ctx context.Context, tenant tenancy.ID, src *store.VmsSource, rep *Report, cursor *time.Time) {
	if err := s.write(ctx, tenant, src, rep, cursor); err != nil {
		rep.Status, rep.Error = StatusFailed, trim("the result could not be recorded: "+err.Error())
	}
}

func (s *Service) write(ctx context.Context, tenant tenancy.ID, src *store.VmsSource, rep *Report, cursor *time.Time) error {
	now := s.now()
	counts := ojson.Object{}
	keys := make([]string, 0, len(rep.Applied))
	for k := range rep.Applied {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		counts = append(counts, ojson.KV{Key: k, Value: rep.Applied[k]})
	}
	raw, _ := store.JSON(counts)
	var msg *string
	result := "ok"
	if rep.Status == StatusFailed {
		result, msg = "failed", &rep.Error
	}
	return s.DB.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		if err := tx.SetVmsResult(src.ID, cursor, now, result, msg, raw); err != nil {
			return err
		}
		d := ojson.Object{{Key: "source_id", Value: src.ID}, {Key: "vendor", Value: src.Vendor}, {Key: "status", Value: rep.Status},
			{Key: "records", Value: rep.Records}, {Key: "failed", Value: rep.Failed}, {Key: "outcomes", Value: counts}}
		_, err := audit.Record(tx.Context(), tx, "vms.sync", d, audit.At(now), audit.Target("vms_source", src.ID))
		return err
	})
}

// ValidBaseURL checks a source's base URL the way a connector will.
func (s *Service) ValidBaseURL(raw string) error {
	if raw == "" {
		return nil
	}
	_, err := connsync.ParseBaseURL(raw, s.RT)
	return err
}
