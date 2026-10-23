package siem

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Streamer is the system actor of what the delivery loop audits.
const Streamer = "siem.streamer"

// Tunables.
var (
	// BatchSize is the most events sent in one request or connection.
	BatchSize = 200
	// BatchesPerTick lets a sink catch up quickly after an outage.
	BatchesPerTick = 20
	// MaxAttempts is how often a rejected batch is retried before it is dead-lettered.
	MaxAttempts = 5
	// FailingAfter is how many consecutive failures mark a sink as failing (audited once).
	FailingAfter = 3
)

// Backoff is the wait before attempt n+1 (n >= 1): 10 s doubling, at most 30 min.
func Backoff(n int) time.Duration {
	d := 10 * time.Second
	for i := 1; i < n && d < 30*time.Minute; i++ {
		d *= 2
	}
	return min(d, 30*time.Minute)
}

// Error is a refused change; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Service delivers every tenant's sinks.
type Service struct {
	DB     *store.DB
	Sealer *seal.Sealer
	// HTTP must come from internal/safehttp.
	HTTP  *http.Client
	Clock func() time.Time
	Log   *slog.Logger
	// Dev allows a loopback syslog collector (as safehttp's loopback exception).
	Dev bool
	// Resolver replaces DNS for syslog (tests).
	Resolver func(ctx context.Context, host string) ([]netip.Addr, error)
	// NewSender replaces the sender a sink gets (tests).
	NewSender func(k *store.SiemSink, token string, tenant string) (Sender, error)
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}

// SecretAAD binds a sink's sealed token to its tenant and row.
func SecretAAD(t tenancy.ID, sinkID string) []byte {
	return seal.AAD(t, "siem_sinks", "secret_sealed", sinkID)
}

func (s *Service) sender(t tenancy.ID, k *store.SiemSink, tenant string) (Sender, error) {
	token := ""
	if len(k.SecretSealed) > 0 {
		if s.Sealer == nil {
			return nil, errors.New("no sealer for the sink token")
		}
		b, err := s.Sealer.Open(k.SecretSealed, SecretAAD(t, k.ID))
		if err != nil {
			return nil, errors.New("the sink token cannot be opened")
		}
		token = string(b)
	}
	if s.NewSender != nil {
		return s.NewSender(k, token, tenant)
	}
	switch k.Kind {
	case "webhook":
		return &Webhook{Client: s.HTTP, URL: k.Target, Flavor: k.Flavor, Token: token, Host: tenant, Format: k.Format}, nil
	case "s3":
		return &S3{Client: s.HTTP, Target: k.Target, Region: k.Region, AccessKeyID: k.AccessKeyID, Secret: token, Tenant: tenant,
			Format: k.Format, Now: s.Clock}, nil
	case "syslog":
		sl := &Syslog{Addr: k.Target, Hostname: tenant, Loopback: s.Dev, Resolver: s.Resolver}
		if k.CAPEM != nil && *k.CAPEM != "" {
			pool, err := ParseCAs(*k.CAPEM)
			if err != nil {
				return nil, err
			}
			sl.RootCAs = pool
		}
		return sl, nil
	}
	return nil, fmt.Errorf("unknown sink kind %q", k.Kind)
}

// Run ticks every interval until ctx is done.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.Tick(ctx); err != nil && ctx.Err() == nil && s.Log != nil {
			s.Log.Error("siem tick failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick delivers what is due for every sink of every active tenant.
func (s *Service) Tick(ctx context.Context) error {
	ctx = audit.WithSystemActor(ctx, Streamer)
	tenants, err := s.DB.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		if err := s.DeliverTenant(ctx, t.ID, t.Slug); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
		}
	}
	return errors.Join(errs...)
}

// DeliverTenant runs each due sink of one tenant.
func (s *Service) DeliverTenant(ctx context.Context, t tenancy.ID, slug string) error {
	ctx = audit.AsSystem(ctx, Streamer)
	now := s.now()
	var due []*store.SiemSink
	if err := s.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		ks, err := tx.SiemSinks()
		for _, k := range ks {
			if k.Enabled && (k.NextAttemptAt == nil || !k.NextAttemptAt.After(now)) {
				due = append(due, k)
			}
		}
		return err
	}); err != nil {
		return err
	}
	var errs []error
	for _, k := range due {
		if err := s.deliverSink(ctx, t, slug, k); err != nil {
			errs = append(errs, fmt.Errorf("sink %s: %w", k.Name, err))
		}
	}
	return errors.Join(errs...)
}

// deliverSink sends batches after the sink's cursor until it is caught up,
// a batch fails or the per-tick budget is spent. Each batch is read, sent
// outside any transaction, and acknowledged; the acknowledgement moves the
// cursor only if it has not moved meanwhile.
func (s *Service) deliverSink(ctx context.Context, t tenancy.ID, slug string, k *store.SiemSink) error {
	snd, err := s.sender(t, k, slug)
	if err != nil {
		return s.fail(ctx, t, k, k.CursorSeq, 0, 0, &SendError{Msg: err.Error()})
	}
	cursor := k.CursorSeq
	for range BatchesPerTick {
		var page []*store.AuditEvent
		if err := s.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
			var err error
			page, err = tx.AuditEventsRange(cursor+1, 0, BatchSize)
			return err
		}); err != nil {
			return err
		}
		if len(page) == 0 {
			return nil
		}
		batch := make([]Record, 0, len(page))
		for _, e := range page {
			if e.Action == "http.request" && !k.IncludeHTTP {
				continue
			}
			if !EventMatches(k.EventFilter, e.Action) {
				continue
			}
			r, err := Encode(k.Format, e, slug)
			if err != nil {
				return err
			}
			batch = append(batch, r)
		}
		last := page[len(page)-1].Seq
		var sendErr error
		if len(batch) > 0 {
			sendErr = snd.Send(ctx, batch)
		}
		if sendErr != nil {
			return s.fail(ctx, t, k, cursor, page[0].Seq, last, sendErr)
		}
		now := s.now()
		recovered := k.Attempts >= FailingAfter
		if err := s.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
			if err := tx.AckSiemBatch(k.ID, cursor, last, len(batch), now); err != nil {
				return err
			}
			if !recovered {
				return nil
			}
			return tx.Audit(now, Streamer, "siem.sink.recovered", ojson.Object{{Key: "sink_id", Value: k.ID},
				{Key: "sink", Value: k.Name}, {Key: "cursor_seq", Value: last}})
		}); errors.Is(err, store.ErrNotFound) {
			return nil // the cursor moved (a reset or another worker); next tick starts from there
		} else if err != nil {
			return err
		}
		k.Attempts = 0
		cursor = last
	}
	return nil
}

// fail records a failed attempt: backoff, the failing transition once, and
// a dead letter for a batch rejected MaxAttempts times.
func (s *Service) fail(ctx context.Context, t tenancy.ID, k *store.SiemSink, cursor, from, to int64, sendErr error) error {
	now := s.now()
	attempts := k.Attempts + 1
	msg := sendErr.Error()
	if len(msg) > 500 {
		msg = msg[:500] + "…"
	}
	var se *SendError
	permanent := errors.As(sendErr, &se) && se.Permanent
	err := s.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		if permanent && attempts >= MaxAttempts && from > 0 {
			d := &store.SiemDeadLetter{ID: uuid.NewString(), SinkID: k.ID, FromSeq: from, ToSeq: to, Events: int(to - from + 1),
				Error: msg, CreatedAt: now}
			if err := tx.DeadLetterSiemBatch(d); err != nil {
				return err
			}
			return tx.Audit(now, Streamer, "siem.sink.dead_letter", ojson.Object{{Key: "sink_id", Value: k.ID},
				{Key: "sink", Value: k.Name}, {Key: "from_seq", Value: from}, {Key: "to_seq", Value: to}, {Key: "error", Value: msg}})
		}
		if err := tx.FailSiemBatch(k.ID, cursor, attempts, now.Add(Backoff(attempts)), msg); err != nil {
			return err
		}
		if attempts != FailingAfter {
			return nil
		}
		return tx.Audit(now, Streamer, "siem.sink.failing", ojson.Object{{Key: "sink_id", Value: k.ID}, {Key: "sink", Value: k.Name},
			{Key: "cursor_seq", Value: cursor}, {Key: "error", Value: msg}})
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// --------------------------------------------------------------- health

// Health is a sink's delivery state.
type Health struct {
	Status string `json:"status"` // healthy | catching_up | degraded | failing | paused
	Lag    int64  `json:"lag"`    // events after the cursor the sink will send
}

// HealthOf reports a sink's state; pending is how many events after its
// cursor it would send (store.SiemPending).
func HealthOf(k *store.SiemSink, pending int64) Health {
	h := Health{Lag: max(pending, 0)}
	switch {
	case !k.Enabled:
		h.Status = "paused"
	case k.Attempts >= FailingAfter:
		h.Status = "failing"
	case k.Attempts > 0:
		h.Status = "degraded"
	case h.Lag > int64(BatchSize):
		h.Status = "catching_up"
	default:
		h.Status = "healthy"
	}
	return h
}

// ------------------------------------------------------------ management

// Actor is the person changing a sink.
type Actor struct {
	UserID  string
	Display string
}

// SinkSpec is a sink's settings.
type SinkSpec struct {
	Name        string
	Kind        string // syslog | webhook (fixed after creation)
	Format      string // json | ocsf
	Target      string
	Flavor      string // webhook: hec | json
	CAPEM       string
	Token       *string // nil: keep (update) / none (create); "" clears. For s3: the secret access key
	IncludeHTTP bool
	// EventFilter limits the sink to some audit actions (see EventMatches); empty: every event.
	EventFilter []string
	// s3: the signing region and the access key id (the secret access key is Token).
	Region      string
	AccessKeyID string
	Enabled     bool
	// Start, on creation: "now" (the current head, the default) or "beginning" (replay the whole ledger).
	Start string
}

func (s *SinkSpec) check(dev bool) error {
	s.Name, s.Target, s.CAPEM = strings.TrimSpace(s.Name), strings.TrimSpace(s.Target), strings.TrimSpace(s.CAPEM)
	s.Region, s.AccessKeyID = strings.TrimSpace(s.Region), strings.TrimSpace(s.AccessKeyID)
	f, err := NormalizeFilter(s.EventFilter)
	if err != nil {
		return err
	}
	s.EventFilter = f
	if s.Name == "" || len(s.Name) > 100 {
		return refuse(422, "invalid_name", "the name is 1 to 100 characters")
	}
	if s.Format != FormatJSON && s.Format != FormatOCSF {
		return refuse(422, "invalid_format", "format is json or ocsf")
	}
	if s.Token != nil && len(*s.Token) > 4096 {
		return refuse(422, "invalid_token", "the token is at most 4096 characters")
	}
	switch s.Kind {
	case "webhook":
		u, err := url.Parse(s.Target)
		if err != nil || u.Host == "" || u.User != nil || len(s.Target) > 2000 {
			return refuse(422, "invalid_target", "the webhook URL must be an absolute https URL without credentials")
		}
		if u.Scheme != "https" && !(dev && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
			return refuse(422, "invalid_target", "the webhook URL must use https")
		}
		if s.Flavor != FlavorHEC && s.Flavor != FlavorJSON {
			return refuse(422, "invalid_flavor", "flavor is hec (Splunk HTTP Event Collector) or json")
		}
		s.CAPEM, s.Region, s.AccessKeyID = "", "", ""
	case "s3":
		u, err := url.Parse(s.Target)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(s.Target) > 2000 {
			return refuse(422, "invalid_target", "the bucket URL must be an absolute https URL (with an optional key prefix) without credentials or a query")
		}
		if u.Scheme != "https" && !(dev && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
			return refuse(422, "invalid_target", "the bucket URL must use https")
		}
		if !regionRe.MatchString(s.Region) {
			return refuse(422, "invalid_region", "the region is the signing region of the bucket, for example eu-west-1 (us-east-1 for most S3-compatible stores)")
		}
		if !accessKeyRe.MatchString(s.AccessKeyID) {
			return refuse(422, "invalid_access_key", "the access key id is 8 to 128 letters and digits")
		}
		s.Flavor, s.CAPEM = "", ""
	case "syslog":
		host, port, err := net.SplitHostPort(s.Target)
		if err != nil {
			host, port = s.Target, DefaultSyslogPort
		}
		n, perr := strconv.Atoi(port)
		if host == "" || perr != nil || n < 1 || n > 65535 || strings.ContainsAny(host, "/@ ") {
			return refuse(422, "invalid_target", "the syslog target is host:port (port 6514 by default)")
		}
		if a, err := netip.ParseAddr(host); err == nil && safehttp.Blocked(a) && !(dev && a.IsLoopback()) {
			return refuse(422, "invalid_target", "the syslog collector address is private or reserved")
		}
		s.Target = net.JoinHostPort(host, port)
		s.Flavor, s.Region, s.AccessKeyID = "", "", ""
		if s.CAPEM != "" {
			if len(s.CAPEM) > 64<<10 {
				return refuse(422, "invalid_ca", "the CA bundle is at most 64 KiB")
			}
			if _, err := ParseCAs(s.CAPEM); err != nil {
				return refuse(422, "invalid_ca", "the CA bundle has no PEM certificates")
			}
		}
	default:
		return refuse(422, "invalid_kind", "kind is syslog, webhook or s3")
	}
	return nil
}

func sealToken(tx *store.TenantTx, sealer *seal.Sealer, k *store.SiemSink, token *string) error {
	if token == nil {
		return nil
	}
	if *token == "" {
		k.SecretSealed = nil
		return nil
	}
	if sealer == nil {
		return errors.New("siem: no sealer for sink tokens")
	}
	sealed, err := sealer.Seal([]byte(*token), SecretAAD(tx.Tenant(), k.ID))
	if err != nil {
		return err
	}
	k.SecretSealed = sealed
	return nil
}

func sinkAudit(k *store.SiemSink, tokenChanged bool) ojson.Object {
	target := k.Target
	if k.Kind == "webhook" || k.Kind == "s3" {
		if u, err := url.Parse(k.Target); err == nil {
			target = u.Scheme + "://" + u.Host
		}
	}
	return ojson.Object{{Key: "sink_id", Value: k.ID}, {Key: "name", Value: k.Name}, {Key: "kind", Value: k.Kind},
		{Key: "format", Value: k.Format}, {Key: "target", Value: target}, {Key: "enabled", Value: k.Enabled},
		{Key: "include_http", Value: k.IncludeHTTP}, {Key: "event_filter", Value: stringsAny(k.EventFilter)}, {Key: "region", Value: k.Region},
		{Key: "access_key_id", Value: k.AccessKeyID}, {Key: "token_changed", Value: tokenChanged}, {Key: "cursor_seq", Value: k.CursorSeq}}
}

// CreateSink adds a sink.
func CreateSink(tx *store.TenantTx, sealer *seal.Sealer, s SinkSpec, dev bool, by Actor, now time.Time) (*store.SiemSink, error) {
	if err := s.check(dev); err != nil {
		return nil, err
	}
	if s.Kind == "webhook" && s.Flavor == FlavorHEC && (s.Token == nil || *s.Token == "") {
		return nil, refuse(422, "token_required", "Splunk HEC needs its token")
	}
	if s.Kind == "s3" && (s.Token == nil || *s.Token == "") {
		return nil, refuse(422, "token_required", "an S3 sink needs its secret access key")
	}
	k := &store.SiemSink{ID: uuid.NewString(), Name: s.Name, Kind: s.Kind, Format: s.Format, Target: s.Target, Flavor: s.Flavor,
		IncludeHTTP: s.IncludeHTTP, EventFilter: s.EventFilter, Region: s.Region, AccessKeyID: s.AccessKeyID, Enabled: s.Enabled,
		CreatedBy: &by.UserID, CreatedAt: now, UpdatedAt: now}
	if s.CAPEM != "" {
		k.CAPEM = &s.CAPEM
	}
	switch s.Start {
	case "", "now":
		head, err := tx.AuditHead()
		if err != nil {
			return nil, err
		}
		k.CursorSeq = head.LastSeq
	case "beginning":
		k.CursorSeq = 0
	default:
		return nil, refuse(422, "invalid_start", "start is now or beginning")
	}
	if err := sealToken(tx, sealer, k, s.Token); err != nil {
		return nil, err
	}
	if err := tx.InsertSiemSink(k); err != nil {
		return nil, err
	}
	return k, tx.Audit(now, by.Display, "siem.sink.created", sinkAudit(k, s.Token != nil))
}

// CheckSink validates a sink's settings as CreateSink would (the checks that
// do not need a token), without storing anything. It returns the settings as
// they would be kept (trimmed, the syslog target with its port).
func CheckSink(s SinkSpec, dev bool) (SinkSpec, error) {
	err := s.check(dev)
	return s, err
}

// ImportSink adds a sink that came in a configuration bundle (internal/transport).
// A bundle never carries a token, so the sink is always added disabled, starts
// at the current head of the ledger and sends nothing until an admin sets its
// token and enables it (UpdateSink then refuses a Splunk HEC sink without one).
// by.UserID may be empty (a machine caller).
func ImportSink(tx *store.TenantTx, s SinkSpec, dev bool, by Actor, bundleHash string, now time.Time) (*store.SiemSink, error) {
	if err := s.check(dev); err != nil {
		return nil, err
	}
	head, err := tx.AuditHead()
	if err != nil {
		return nil, err
	}
	k := &store.SiemSink{ID: uuid.NewString(), Name: s.Name, Kind: s.Kind, Format: s.Format, Target: s.Target, Flavor: s.Flavor,
		IncludeHTTP: s.IncludeHTTP, Enabled: false, CursorSeq: head.LastSeq, CreatedAt: now, UpdatedAt: now}
	if by.UserID != "" {
		k.CreatedBy = &by.UserID
	}
	if s.CAPEM != "" {
		k.CAPEM = &s.CAPEM
	}
	if err := tx.InsertSiemSink(k); err != nil {
		return nil, err
	}
	d := append(sinkAudit(k, false), ojson.KV{Key: "imported_from_bundle", Value: bundleHash})
	return k, tx.Audit(now, by.Display, "siem.sink.created", d)
}

// UpdateSink replaces a sink's settings; its kind cannot change.
func UpdateSink(tx *store.TenantTx, sealer *seal.Sealer, id string, s SinkSpec, dev bool, by Actor, now time.Time) (*store.SiemSink, error) {
	k, err := tx.SiemSink(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "sink_not_found", "sink not found")
	} else if err != nil {
		return nil, err
	}
	if s.Kind == "" {
		s.Kind = k.Kind
	}
	if s.Kind != k.Kind {
		return nil, refuse(422, "invalid_kind", "a sink's kind cannot change")
	}
	if err := s.check(dev); err != nil {
		return nil, err
	}
	// The sealed token is bound to the sink row, not to the destination, so it
	// must never follow the sink to another origin: an edit that moves the
	// target (webhook scheme, host or port; syslog host:port) has to bring a
	// new token or clear it. A path-only change keeps it (#332, as #315).
	from, to := sinkOrigin(k.Kind, k.Target), sinkOrigin(k.Kind, s.Target)
	moved := from != to
	if moved && s.Token == nil && len(k.SecretSealed) > 0 {
		return nil, refuse(422, "credential_required",
			"changing the sink's origin (scheme, host, port) needs a new token; the stored token does not move with it")
	}
	// The secret access key is bound to the key id as well as the origin: a new id needs a new secret.
	if s.Kind == "s3" && s.AccessKeyID != k.AccessKeyID && s.Token == nil && len(k.SecretSealed) > 0 {
		return nil, refuse(422, "credential_required", "changing the access key id needs its secret access key")
	}
	k.Name, k.Format, k.Target, k.Flavor, k.IncludeHTTP, k.Enabled, k.UpdatedAt = s.Name, s.Format, s.Target, s.Flavor,
		s.IncludeHTTP, s.Enabled, now
	k.EventFilter, k.Region, k.AccessKeyID = s.EventFilter, s.Region, s.AccessKeyID
	k.CAPEM = nil
	if s.CAPEM != "" {
		k.CAPEM = &s.CAPEM
	}
	if err := sealToken(tx, sealer, k, s.Token); err != nil {
		return nil, err
	}
	if k.Kind == "webhook" && k.Flavor == FlavorHEC && len(k.SecretSealed) == 0 {
		return nil, refuse(422, "token_required", "Splunk HEC needs its token")
	}
	if k.Kind == "s3" && len(k.SecretSealed) == 0 {
		return nil, refuse(422, "token_required", "an S3 sink needs its secret access key")
	}
	if err := tx.UpdateSiemSink(k); err != nil {
		return nil, err
	}
	d := sinkAudit(k, s.Token != nil)
	if moved {
		d = append(d, ojson.KV{Key: "previous_origin", Value: from}, ojson.KV{Key: "origin", Value: to})
	}
	return k, tx.Audit(now, by.Display, "siem.sink.updated", d)
}

// sinkOrigin is where a sink's token would be sent: scheme://host:port for a
// webhook (default ports filled in, case folded), host:port for syslog. An
// unparsable target is its own origin, so any change to it counts as a move.
func sinkOrigin(kind, target string) string {
	if kind == "syslog" {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return strings.ToLower(target)
		}
		return net.JoinHostPort(strings.ToLower(host), port)
	}
	return safehttp.Origin(target)
}

// Rewind sets a sink's cursor: replay from seq+1 (0: the whole ledger), or
// skip ahead to the head.
func Rewind(tx *store.TenantTx, id string, seq int64, by Actor, now time.Time) (*store.SiemSink, error) {
	k, err := tx.SiemSink(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "sink_not_found", "sink not found")
	} else if err != nil {
		return nil, err
	}
	head, err := tx.AuditHead()
	if err != nil {
		return nil, err
	}
	if seq < 0 || seq > head.LastSeq {
		return nil, refuse(422, "invalid_seq", "the cursor is 0 to %d", head.LastSeq)
	}
	from := k.CursorSeq
	if err := tx.SetSiemCursor(id, seq, now); err != nil {
		return nil, err
	}
	k.CursorSeq, k.Attempts, k.NextAttemptAt, k.LastError = seq, 0, nil, nil
	return k, tx.Audit(now, by.Display, "siem.sink.rewound", ojson.Object{{Key: "sink_id", Value: k.ID}, {Key: "sink", Value: k.Name},
		{Key: "from_seq", Value: from}, {Key: "to_seq", Value: seq}})
}

// TestSink sends one synthetic event to a sink now, outside any transaction.
func (s *Service) TestSink(ctx context.Context, t tenancy.ID, slug string, k *store.SiemSink) error {
	snd, err := s.sender(t, k, slug)
	if err != nil {
		return err
	}
	now := s.now()
	e := &store.AuditEvent{ID: uuid.New(), TenantID: t, Seq: 0, OccurredAt: now, ActorType: store.ActorSystem, Action: "siem.test",
		Outcome: store.OutcomeSuccess, Detail: []byte(`{"test":true}`), SchemaVersion: 1, Hash: "test", PrevHash: "test"}
	r, err := Encode(k.Format, e, slug)
	if err != nil {
		return err
	}
	return snd.Send(ctx, []Record{r})
}

// Kinds and formats, for the API.
var (
	Kinds   = []string{"syslog", "webhook", "s3"}
	Flavors = []string{FlavorHEC, FlavorJSON}
)

var (
	regionRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}$`)
	accessKeyRe = regexp.MustCompile(`^[A-Za-z0-9]{8,128}$`)
	filterRe    = regexp.MustCompile(`^(\*|[a-z0-9_]+(\.[a-z0-9_]+)*(\.\*)?)$`)
)

// MaxFilterEntries is the most patterns a sink's event filter holds.
const MaxFilterEntries = 50

// NormalizeFilter trims, lower-cases and de-duplicates an event filter and
// refuses what is not an audit action or a prefix pattern.
func NormalizeFilter(in []string) ([]string, error) {
	out := []string{}
	for _, e := range in {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || slices.Contains(out, e) {
			continue
		}
		if len(e) > 100 || !filterRe.MatchString(e) {
			return nil, refuse(422, "invalid_filter", "an event filter entry is an audit action such as grant.revoke, or a prefix such as auth.*; %q is neither", e)
		}
		out = append(out, e)
	}
	if len(out) > MaxFilterEntries {
		return nil, refuse(422, "invalid_filter", "an event filter has at most %d entries", MaxFilterEntries)
	}
	return out, nil
}

// alwaysDelivered are the audit actions a sink receives whatever its filter says (issue #511): a change to log
// streaming itself, to the audit ledger, to an admin change request, or to how someone signs in with a privileged
// credential. A filter that hid them would let one admin blind the SIEM and the change that did it.
var alwaysDelivered = []string{"siem.", "audit.", "admin.change.", "auth.break_glass", "breakglass.", "auth.step_up.", "auth.role.",
	"stepup.", "deletion_guard."}

// AlwaysDelivered reports whether a sink receives this action regardless of its event filter.
func AlwaysDelivered(action string) bool {
	for _, p := range alwaysDelivered {
		if strings.HasPrefix(action, p) {
			return true
		}
	}
	return false
}

// Narrows reports whether next lets through fewer events than cur: an empty filter (every event) or "*" narrowed to
// a list, or an entry of cur that no entry of next covers. Widening, clearing and reordering are not narrowing.
func Narrows(cur, next []string) bool {
	all := func(f []string) bool { return len(f) == 0 || slices.Contains(f, "*") }
	if all(next) {
		return false
	}
	if all(cur) {
		return true
	}
	covers := func(g, f string) bool { // does next entry g match every action entry f matches?
		switch {
		case g == f:
			return true
		case strings.HasSuffix(g, ".*"):
			return strings.HasPrefix(strings.TrimSuffix(f, "*"), strings.TrimSuffix(g, "*"))
		}
		return false
	}
	for _, f := range cur {
		if !slices.ContainsFunc(next, func(g string) bool { return covers(g, f) }) {
			return true
		}
	}
	return false
}

// SameFilter reports whether two normalized filters hold the same entries.
func SameFilter(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// SetEventFilter replaces a sink's event filter and audits it (siem.sink.filter_changed, which every sink
// receives). The two-admin change type siem.sink.filter applies a narrowing through it.
func SetEventFilter(tx *store.TenantTx, id string, filter []string, changeID string, now time.Time) (*store.SiemSink, error) {
	k, err := tx.SiemSink(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "sink_not_found", "sink not found")
	} else if err != nil {
		return nil, err
	}
	next, err := NormalizeFilter(filter)
	if err != nil {
		return nil, err
	}
	was := k.EventFilter
	k.EventFilter, k.UpdatedAt = next, now
	if err := tx.UpdateSiemSink(k); err != nil {
		return nil, err
	}
	// in the transaction that applies the change, next to admin.change.applied
	_, err = audit.Record(tx.Context(), tx, "siem.sink.filter_changed", ojson.Object{{Key: "sink_id", Value: k.ID},
		{Key: "name", Value: k.Name}, {Key: "from", Value: stringsAny(was)}, {Key: "to", Value: stringsAny(next)},
		{Key: "narrowed", Value: Narrows(was, next)}, {Key: "change_id", Value: changeID}}, audit.At(now), audit.Target("admin_change", changeID))
	return k, err
}

// EventMatches reports whether a sink with this filter receives an event with
// this audit action. An empty filter receives everything. "*" matches every
// action, "auth.*" every action that starts with "auth.", anything else only
// that action. (A sink still needs include_http to receive http.request.)
func EventMatches(filter []string, action string) bool {
	if len(filter) == 0 || AlwaysDelivered(action) {
		return true
	}
	for _, f := range filter {
		switch {
		case f == "*" || f == action:
			return true
		case strings.HasSuffix(f, ".*") && strings.HasPrefix(action, strings.TrimSuffix(f, "*")):
			return true
		}
	}
	return false
}

func stringsAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
