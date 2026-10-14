package ssf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Service receives, processes and manages SSF streams. HTTP and Sealer are
// needed to fetch keys and to hold secrets; Containment runs the kill switch
// (a nil one makes every actionable event fail with a clear outcome).
type Service struct {
	// HTTP is the outbound client; it must come from internal/safehttp.
	HTTP *http.Client
	// Sealer seals the receiver secret, poll token and API token at rest.
	Sealer      *seal.Sealer
	Clock       timeutil.Clock
	Containment *containment.Service
	// Skew and MaxAge bound a SET's iat (defaults DefaultSkew, DefaultMaxAge).
	Skew, MaxAge time.Duration
	// ContainTimeout bounds the provider calls of one event (default 20s).
	ContainTimeout time.Duration

	jwksMu sync.Mutex
	jwks   map[string]jwksEntry
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return timeutil.System()
}

// ConfigError is a caller error in a transmitter's configuration.
type ConfigError struct{ Msg string }

func (e *ConfigError) Error() string { return e.Msg }

func bad(format string, a ...any) error { return &ConfigError{fmt.Sprintf(format, a...)} }

// ErrNoSuchTransmitter: no such transmitter in this tenant.
var ErrNoSuchTransmitter = &ConfigError{"no such transmitter"}

// ---------------------------------------------------------------- input

// TransmitterInput is a transmitter's configuration as submitted.
type TransmitterInput struct {
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// JWKSURL or JWKS (inline, public keys only) gives the signing keys.
	JWKSURL  string          `json:"jwks_url"`
	JWKS     json.RawMessage `json:"jwks"`
	Delivery string          `json:"delivery"` // push or poll
	PollURL  string          `json:"poll_url"`
	// Secret is the bearer secret the transmitter presents (push), or the
	// bearer token Tessera presents to the transmitter (poll). A push stream
	// without one gets a generated secret, shown once.
	Secret          string `json:"secret"`
	RotateSecret    bool   `json:"rotate_secret"`
	APIToken        string `json:"api_token"` // for verification requests; a poll stream defaults to its token
	VerificationURL string `json:"verification_url"`
	// SubjectSystem is the system (okta, entra, google, ...) the subject
	// resolves against. ConnectionID names a connection and implies it.
	SubjectSystem string `json:"subject_system"`
	ConnectionID  string `json:"connection_id"`
	Status        string `json:"status"` // enabled (default), paused or disabled
	// Discover fetches the transmitter's /.well-known/ssf-configuration and
	// fills the JWKS URL and the verification endpoint when they are blank.
	Discover bool `json:"discover"`
}

var systemRE = regexp.MustCompile(`^[a-z][a-z0-9_]{1,39}$`)

func checkURL(name, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") || len(raw) > 512 {
		return bad("%s must be an https URL", name)
	}
	return nil
}

func printable(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) && r != ' ' {
			return false
		}
	}
	return true
}

func secretAAD(c *store.TenantTx, id, column string) []byte {
	return seal.AAD(c.Tenant(), "ssf_transmitters", column, id)
}

func (s *Service) sealSecret(c *store.TenantTx, id, column, plain string) ([]byte, error) {
	if s.Sealer == nil {
		return nil, bad("sealing is not configured")
	}
	return s.Sealer.Seal([]byte(plain), secretAAD(c, id, column))
}

// open returns a sealed secret ("" when none is set).
func (s *Service) open(tenant tenancy.ID, id, column string, enc []byte) (string, error) {
	if len(enc) == 0 {
		return "", nil
	}
	if s.Sealer == nil {
		return "", errors.New("the stored secret cannot be unsealed: no key is configured")
	}
	plain, err := s.Sealer.Open(enc, seal.AAD(tenant, "ssf_transmitters", column, id))
	if err != nil {
		return "", errors.New("the stored secret cannot be unsealed")
	}
	return string(plain), nil
}

// merged validates in against the existing transmitter (nil on create) and
// returns the transmitter to store and the generated push secret ("" if none).
func (s *Service) merged(c *store.TenantTx, in TransmitterInput, old *store.SSFTransmitter, actor string, now time.Time) (*store.SSFTransmitter, string, error) {
	x := &store.SSFTransmitter{Status: store.SSFEnabled, CreatedBy: actor}
	if old != nil {
		cp := *old
		x = &cp
	} else {
		x.ID = store.NewID()
	}
	in.Name = strings.TrimSpace(in.Name)
	switch {
	case in.Name == "" || len(in.Name) > 100 || !printable(in.Name):
		return nil, "", bad("name is required (1 to 100 characters)")
	case in.Issuer == "" || len(in.Issuer) > 512 || !printable(in.Issuer) || strings.Contains(in.Issuer, " "):
		return nil, "", bad("issuer is required (the transmitter's iss, up to 512 characters)")
	case in.Audience == "" || len(in.Audience) > 256 || !printable(in.Audience):
		return nil, "", bad("audience is required (the aud the transmitter puts in its events)")
	case in.Delivery != store.SSFPush && in.Delivery != store.SSFPoll:
		return nil, "", bad("delivery must be push or poll")
	}
	x.Name, x.Issuer, x.Audience = in.Name, in.Issuer, in.Audience
	for name, v := range map[string]string{"jwks_url": in.JWKSURL, "poll_url": in.PollURL, "verification_url": in.VerificationURL} {
		if err := checkURL(name, v); err != nil {
			return nil, "", err
		}
	}
	// signing keys: replaced when either is submitted, else kept
	if in.JWKSURL != "" || len(in.JWKS) > 0 {
		x.JWKSURL, x.JWKSInline = in.JWKSURL, ""
		if len(in.JWKS) > 0 {
			if len(in.JWKS) > 64<<10 {
				return nil, "", bad("jwks is too large")
			}
			if _, err := ParseJWKS(in.JWKS); err != nil {
				return nil, "", bad("jwks: %v", err)
			}
			x.JWKSInline = string(in.JWKS)
		}
	}
	if x.JWKSURL == "" && x.JWKSInline == "" {
		return nil, "", bad("jwks_url or jwks is required (the transmitter's signing keys)")
	}
	x.VerificationURL = in.VerificationURL
	if in.VerificationURL == "" && old != nil {
		x.VerificationURL = old.VerificationURL
	}
	if in.Status != "" {
		switch in.Status {
		case store.SSFEnabled, store.SSFPaused, store.SSFDisabled:
			x.Status = in.Status
		default:
			return nil, "", bad("status must be enabled, paused or disabled")
		}
	}
	// the delivery method; the secret never carries over to the other method
	if old != nil && old.Delivery != in.Delivery {
		x.SecretEnc = nil
	}
	x.Delivery, x.PollURL = in.Delivery, in.PollURL
	var generated string
	switch {
	case in.Secret != "":
		if len(in.Secret) < 16 || len(in.Secret) > 4096 || !printable(in.Secret) || strings.Contains(in.Secret, " ") {
			return nil, "", bad("secret must be 16 to 4096 printable characters without spaces")
		}
		enc, err := s.sealSecret(c, x.ID, "secret_enc", in.Secret)
		if err != nil {
			return nil, "", err
		}
		x.SecretEnc = enc
	case in.Delivery == store.SSFPush && (len(x.SecretEnc) == 0 || in.RotateSecret):
		generated = seal.RandomSecret(32)
		enc, err := s.sealSecret(c, x.ID, "secret_enc", generated)
		if err != nil {
			return nil, "", err
		}
		x.SecretEnc = enc
	}
	if in.Delivery == store.SSFPoll {
		if in.PollURL == "" {
			return nil, "", bad("poll_url is required for a poll stream")
		}
		if len(x.SecretEnc) == 0 {
			return nil, "", bad("secret (the bearer token for the poll endpoint) is required for a poll stream")
		}
	} else {
		x.PollURL = ""
	}
	if in.APIToken != "" {
		if len(in.APIToken) > 8192 {
			return nil, "", bad("api_token is too long")
		}
		enc, err := s.sealSecret(c, x.ID, "api_token_enc", in.APIToken)
		if err != nil {
			return nil, "", err
		}
		x.APITokenEnc = enc
	}
	// the subject mapping
	x.ConnectionID = nil
	sys := in.SubjectSystem
	if in.ConnectionID != "" {
		conn, err := c.Connection(in.ConnectionID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, "", bad("no such connection")
		}
		if err != nil {
			return nil, "", err
		}
		if conn.RetiredAt != nil {
			return nil, "", bad("the connection is retired")
		}
		if sys != "" && sys != conn.System {
			return nil, "", bad("subject_system %q is not the system of the connection (%q)", sys, conn.System)
		}
		sys = conn.System
		id := conn.ID
		x.ConnectionID = &id
	}
	if !systemRE.MatchString(sys) {
		return nil, "", bad("subject_system is required (the system the subject resolves against, for example okta), or connection_id")
	}
	x.SubjectSystem = sys
	return x, generated, nil
}

func detail(x *store.SSFTransmitter, more ojson.Object) ojson.Object {
	conn := ""
	if x.ConnectionID != nil {
		conn = *x.ConnectionID
	}
	d := ojson.Object{{Key: "transmitter_id", Value: x.ID}, {Key: "name", Value: x.Name}, {Key: "issuer", Value: x.Issuer},
		{Key: "audience", Value: x.Audience}, {Key: "delivery", Value: x.Delivery}, {Key: "subject_system", Value: x.SubjectSystem},
		{Key: "connection_id", Value: conn}, {Key: "status", Value: x.Status}}
	return append(d, more...)
}

// Create adds a transmitter and audits it (never a secret) in the caller's
// transaction. It returns the transmitter and the generated receiver secret
// of a push stream ("" when the caller supplied one).
func (s *Service) Create(c *store.TenantTx, in TransmitterInput, actor string, now time.Time) (*store.SSFTransmitter, string, error) {
	x, generated, err := s.merged(c, in, nil, actor, now)
	if err != nil {
		return nil, "", err
	}
	if err := c.InsertSSFTransmitter(x, now); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return nil, "", bad("a transmitter with that name exists")
		}
		return nil, "", err
	}
	if err := c.Audit(now, actor, "ssf.transmitter_created", detail(x, nil)); err != nil {
		return nil, "", err
	}
	return x, generated, nil
}

// Update replaces a transmitter's configuration. A secret left blank is kept.
func (s *Service) Update(c *store.TenantTx, id string, in TransmitterInput, actor string, now time.Time) (*store.SSFTransmitter, string, error) {
	old, err := c.SSFTransmitter(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", ErrNoSuchTransmitter
	}
	if err != nil {
		return nil, "", err
	}
	x, generated, err := s.merged(c, in, old, actor, now)
	if err != nil {
		return nil, "", err
	}
	if err := c.UpdateSSFTransmitter(x, now); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return nil, "", bad("a transmitter with that name exists")
		}
		return nil, "", err
	}
	more := ojson.Object{{Key: "secret_rotated", Value: generated != "" || in.Secret != ""},
		{Key: "previous_status", Value: old.Status}}
	if err := c.Audit(now, actor, "ssf.transmitter_updated", detail(x, more)); err != nil {
		return nil, "", err
	}
	return x, generated, nil
}

// Delete removes a transmitter and its recorded events (the ledger keeps the history).
func (s *Service) Delete(c *store.TenantTx, id, actor string, now time.Time) error {
	old, err := c.SSFTransmitter(id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNoSuchTransmitter
	}
	if err != nil {
		return err
	}
	if err := c.DeleteSSFTransmitter(id); err != nil {
		return err
	}
	return c.Audit(now, actor, "ssf.transmitter_deleted", detail(old, nil))
}

// ---------------------------------------------------------------- views

// TransmitterView is the API form of a transmitter. It holds no secret.
type TransmitterView struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Issuer          string  `json:"issuer"`
	Audience        string  `json:"audience"`
	JWKSURL         string  `json:"jwks_url"`
	InlineJWKS      bool    `json:"inline_jwks"`
	Delivery        string  `json:"delivery"`
	PollURL         string  `json:"poll_url"`
	VerificationURL string  `json:"verification_url"`
	SubjectSystem   string  `json:"subject_system"`
	ConnectionID    *string `json:"connection_id"`
	// Status is the stream status: enabled, paused or disabled.
	Status              string  `json:"status"`
	SecretSet           bool    `json:"secret_set"`
	APITokenSet         bool    `json:"api_token_set"`
	ReceiverPath        string  `json:"receiver_path,omitempty"` // push: where the transmitter delivers
	LastEventAt         *string `json:"last_event_at"`
	LastError           string  `json:"last_error"`
	LastErrorAt         *string `json:"last_error_at"`
	LastPolledAt        *string `json:"last_polled_at"`
	VerificationPending bool    `json:"verification_pending"`
	VerifiedAt          *string `json:"verified_at"`
	PendingAcks         int     `json:"pending_acks"`
	CreatedBy           string  `json:"created_by"`
	CreatedAt           string  `json:"created_at"`
	UpdatedAt           string  `json:"updated_at"`
}

func isoP(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := timeutil.ISO(*t)
	return &s
}

// ViewTransmitter renders x; slug is the tenant slug of the push URL.
func ViewTransmitter(x *store.SSFTransmitter, slug string) TransmitterView {
	v := TransmitterView{ID: x.ID, Name: x.Name, Issuer: x.Issuer, Audience: x.Audience, JWKSURL: x.JWKSURL,
		InlineJWKS: x.JWKSInline != "", Delivery: x.Delivery, PollURL: x.PollURL, VerificationURL: x.VerificationURL,
		SubjectSystem: x.SubjectSystem, ConnectionID: x.ConnectionID, Status: x.Status, SecretSet: len(x.SecretEnc) > 0,
		APITokenSet: len(x.APITokenEnc) > 0, LastEventAt: isoP(x.LastEventAt), LastError: x.LastError,
		LastErrorAt: isoP(x.LastErrorAt), LastPolledAt: isoP(x.LastPolledAt), VerificationPending: x.VerificationState != "",
		VerifiedAt: isoP(x.VerifiedAt), CreatedBy: x.CreatedBy, CreatedAt: timeutil.ISO(x.CreatedAt), UpdatedAt: timeutil.ISO(x.UpdatedAt)}
	if x.Delivery == store.SSFPush {
		v.ReceiverPath = "/public/t/" + slug + "/ssf/" + x.ID + "/events"
	}
	var acks []string
	if json.Unmarshal([]byte(x.PendingAcks), &acks) == nil {
		v.PendingAcks = len(acks)
	}
	return v
}

// EventView is the API form of a received event.
type EventView struct {
	ID            string  `json:"id"`
	TransmitterID string  `json:"transmitter_id"`
	JTI           string  `json:"jti"`
	Via           string  `json:"via"`
	EventType     string  `json:"event_type"`
	Event         string  `json:"event"` // short name; "unknown" for an event Tessera does not know
	SubjectFormat string  `json:"subject_format"`
	Subject       string  `json:"subject"`
	IdentityID    *int64  `json:"identity_id"`
	Status        string  `json:"status"`
	Outcome       string  `json:"outcome"`
	Steps         int     `json:"steps"`
	StepsFailed   int     `json:"steps_failed"`
	ReceivedAt    string  `json:"received_at"`
	IATAt         string  `json:"iat_at"`
	ActionedAt    *string `json:"actioned_at"`
	LatencyMS     *int64  `json:"latency_ms"`
	IATLatencyMS  *int64  `json:"iat_latency_ms"`
}

// ViewEvent renders e.
func ViewEvent(e *store.SSFEvent) EventView {
	name := EventName(e.EventType)
	if name == "" {
		name = "unknown"
	}
	return EventView{ID: e.ID, TransmitterID: e.TransmitterID, JTI: e.JTI, Via: e.Via, EventType: e.EventType, Event: name,
		SubjectFormat: e.SubjectFormat, Subject: e.Subject, IdentityID: e.IdentityID, Status: e.Status, Outcome: e.Outcome,
		Steps: e.Steps, StepsFailed: e.StepsFailed, ReceivedAt: timeutil.ISO(e.ReceivedAt), IATAt: timeutil.ISO(e.IATAt),
		ActionedAt: isoP(e.ActionedAt), LatencyMS: e.LatencyMS, IATLatencyMS: e.IATLatencyMS}
}

// ReceiverSecret returns the bearer secret a push transmitter must present
// ("" when the transmitter has none), unsealed.
func (s *Service) ReceiverSecret(c *store.TenantTx, x *store.SSFTransmitter) (string, error) {
	return s.open(c.Tenant(), x.ID, "secret_enc", x.SecretEnc)
}
