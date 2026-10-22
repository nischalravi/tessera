// Package vms reads contractor assignments from a vendor-management system
// (issue #304): SAP Fieldglass and Beeline over their REST APIs, and a generic
// CSV feed (uploaded, or fetched over HTTPS). Each reader yields
// connectors.VmsRecord values, which internal/intake maps onto the contractor
// lifecycle: a sponsor and an end date, from which the leaver plan follows.
//
// The readers are read-only: every request is a GET, except the OAuth token
// request. Every call goes through an internal/safehttp client, and a paging
// link must stay on the configured origin.
//
// The Fieldglass and Beeline response shapes below are the documented
// contract of this package, modelled on each vendor's worker and assignment
// listings and exercised against the in-process fakes in vmsfake. No real
// vendor tenant has been used: the endpoint paths are settings so a tenant can
// point them at its own integration, and the first real tenant should confirm
// the field names (see mvp/README.md, "Contractors (VMS)").
//
// SFTP drops are not read here: there is no SFTP client in the module's
// dependencies. A drop lands as a CSV upload (the same parser) until one is added.
package vms

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Settings are a source's non-secret options (stored as JSON).
type Settings struct {
	// WorkersPath is the listing endpoint (Fieldglass default /api/v1/workers,
	// Beeline /api/v2/assignments); TokenPath is the OAuth token endpoint.
	WorkersPath string `json:"workers_path,omitempty"`
	TokenPath   string `json:"token_path,omitempty"`
	// PageSize is the page size asked of the vendor (default 100).
	PageSize int `json:"page_size,omitempty"`
	// Mapping renames CSV columns: canonical field -> the header of the file.
	Mapping map[string]string `json:"mapping,omitempty"`
	// DateFormat is the Go layout of CSV dates (default RFC 3339 or 2006-01-02).
	DateFormat string `json:"date_format,omitempty"`
	// CSVPath is the path under the base URL a CSV source is fetched from.
	CSVPath string `json:"csv_path,omitempty"`
}

var pathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,200}$`)

// Validate checks the settings of a vendor.
func (s *Settings) Validate(vendor string) error {
	for name, p := range map[string]string{"workers_path": s.WorkersPath, "token_path": s.TokenPath, "csv_path": s.CSVPath} {
		if p != "" && (!pathRE.MatchString(p) || strings.Contains(p, "..") || strings.Contains(p, "//")) {
			return fmt.Errorf("%s must be an absolute path of plain characters", name)
		}
	}
	if s.PageSize < 0 || s.PageSize > 1000 {
		return errors.New("page_size must be between 1 and 1000")
	}
	if vendor != store.VmsCSV && (len(s.Mapping) > 0 || s.DateFormat != "" || s.CSVPath != "") {
		return errors.New("mapping, date_format and csv_path apply to CSV sources only")
	}
	if vendor == store.VmsCSV && (s.WorkersPath != "" || s.TokenPath != "") {
		return errors.New("workers_path and token_path apply to Fieldglass and Beeline only")
	}
	if len(s.Mapping) > 0 {
		for k, v := range s.Mapping {
			if !canonical[k] {
				return fmt.Errorf("mapping: %q is not a field", k)
			}
			if strings.TrimSpace(v) == "" || len(v) > 100 {
				return fmt.Errorf("mapping: the column of %q is empty or too long", k)
			}
		}
	}
	if s.DateFormat != "" {
		if len(s.DateFormat) > 40 {
			return errors.New("date_format is too long")
		}
		ref := time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC)
		if back, err := time.Parse(s.DateFormat, ref.Format(s.DateFormat)); err != nil || !back.Equal(ref) {
			return errors.New("date_format is not a Go time layout that round-trips")
		}
	}
	return nil
}

// Credential is the sealed secret of a source: a client id and secret for the
// REST vendors, an optional bearer token for a fetched CSV.
type Credential struct {
	ClientID, ClientSecret connsync.Secret
}

// ParseCredential splits "client_id:client_secret".
func ParseCredential(v string) (id string, secret connsync.Secret, err error) {
	i := strings.IndexByte(v, ':')
	if i <= 0 || i == len(v)-1 || len(v) > 4096 {
		return "", connsync.Secret{}, errors.New("the credential is client_id:client_secret")
	}
	return v[:i], connsync.NewSecret(v[i+1:]), nil
}

// Config builds a connector for one source.
type Config struct {
	Vendor     string
	BaseURL    string
	Settings   Settings
	Credential string // see ParseCredential (REST vendors) or a bearer token (CSV fetch)
}

// New builds the reader of a REST vendor. hc is the server's safehttp client.
func New(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.VmsConnector, error) {
	if hc == nil {
		return nil, errors.New("vms: an internal/safehttp client is required")
	}
	if now == nil {
		now = time.Now
	}
	if err := cfg.Settings.Validate(cfg.Vendor); err != nil {
		return nil, fmt.Errorf("vms: %w", err)
	}
	base, err := connsync.ParseBaseURL(cfg.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("vms: base URL: %w", err)
	}
	if base.Path != "" {
		return nil, errors.New("vms: the base URL is a host without a path (set the paths instead)")
	}
	r := &rest{base: base, set: cfg.Settings, now: now}
	if cfg.Settings.PageSize == 0 {
		r.set.PageSize = 100
	}
	r.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{
		"Accept": {"application/json"}, "User-Agent": {"tessera-connector/vms"}}}
	switch cfg.Vendor {
	case store.VmsFieldglass, store.VmsBeeline:
	default:
		return nil, fmt.Errorf("vms: %q is not a REST vendor", cfg.Vendor)
	}
	id, secret, err := ParseCredential(cfg.Credential)
	if err != nil {
		return nil, fmt.Errorf("vms: %w", err)
	}
	tokenPath := cfg.Settings.TokenPath
	if tokenPath == "" {
		tokenPath = "/api/oauth2/v2.0/token"
	}
	tu := *base
	tu.Path = tokenPath
	r.tok = newTokenSource(id, secret, tu.String(), r.api, now)
	r.api.Authorize = r.tok.authorization
	r.api.OnUnauthorized = r.tok.invalidate
	if cfg.Vendor == store.VmsFieldglass {
		return &Fieldglass{r}, nil
	}
	return &Beeline{r}, nil
}

// rest is what the two REST readers share.
type rest struct {
	base *url.URL
	set  Settings
	api  *connsync.Client
	tok  *tokenSource
	now  func() time.Time
}

func (r *rest) url(path string, q url.Values) string {
	u := *r.base
	u.Path = path
	u.RawQuery = q.Encode()
	return u.String()
}

// eventID is stable for one version of a record: the same facts have the same
// id, a change to any of them a new one.
func eventID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(h[:16])
}

func tstr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// parseTime reads a vendor timestamp or date; empty is nil, junk is nil too (the
// intake then rejects a record that has no end date).
func parseTime(s string, layouts ...string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if len(layouts) == 0 {
		layouts = []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"}
	}
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, s, time.UTC); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// status maps a vendor's status text onto the three statuses Tessera knows. An
// unknown status is returned as is, so the intake rejects the record rather
// than guessing.
func status(s string) string {
	switch strings.ToLower(strings.Join(strings.Fields(s), " ")) {
	case "active", "on assignment", "working", "in progress", "started":
		return connectors.VmsActive
	case "pending", "pending start", "approved", "scheduled", "upcoming", "pending onboarding":
		return connectors.VmsPending
	case "ended", "completed", "complete", "terminated", "closed", "cancelled", "canceled", "offboarded", "expired":
		return connectors.VmsEnded
	}
	return strings.ToLower(strings.TrimSpace(s))
}
