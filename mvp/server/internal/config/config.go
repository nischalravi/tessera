// Package config loads Tessera's typed settings from the environment and
// enforces the production guard rails (design
// docs/design/phase-0-platform-security.md §18.1 and §18.4).
//
// Load never has side effects: it reads variables (and the KEK file, when one
// is named) and returns either a valid *Config or every problem it found,
// joined. With TESSERA_ENV=prod it refuses to start when any of these hold:
// the public URL is not https; COOKIE_SECURE is false; there is no KEK;
// CORS_ORIGINS is not empty (the UI is same-origin in production, so CORS is
// off, §11); OUTBOUND_ALLOW_LOOPBACK is true; TESSERA_SAFEDIAL_ALLOW is set; TESSERA_DEV_IDP_URL is set; the
// audit anchor is not an s3://, azure:// or gs:// URL (missing or file:// included); TESSERA_NOW freezes the clock; a
// trusted-proxy prefix is shorter than /8 (IPv4) or /32 (IPv6); TESSERA_METRICS_ADDR is a wildcard, hostname or public
// address (/metrics is internal only); TESSERA_AUTH_RATE_BURST or TESSERA_ANON_RATE_BURST
// exceeds its production cap. The guard rail on dev_mock IdP connections
// needs the idp_connections table and lands with it (PR6).
package config

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/kekwrap"
	"github.com/nischalravi/tessera/mvp/server/internal/objstore"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Environments. Test is a non-production environment like Dev (the shared
// Test instance and go test): it exposes dev sign-in (§18.4) and is the only
// environment the test-only session helper (internal/auth/authtest) runs in.
const (
	Dev  = "dev"
	Test = "test"
	Prod = "prod"
)

// Upper bounds enforced in every environment (§18.1).
const (
	MaxAccessTokenTTLSeconds = 900
	MaxDeviceCodeTTLSeconds  = 600
)

// Shortest trusted-proxy prefixes accepted with TESSERA_ENV=prod. A broader
// prefix (0.0.0.0/0 above all) would let any client spoof X-Forwarded-For.
const (
	MinProxyPrefixIPv4 = 8
	MinProxyPrefixIPv6 = 32
)

// Config is the typed configuration. The KEK is held behind a pointer so
// printing a Config (even with %#v) never shows key bytes; String and
// LogValue redact it as well.
type Config struct {
	Env                   string // Dev or Prod
	PublicURL             string // issuer base; https in prod
	APIAudience           string // access-token aud
	DB                    string // SQLite path (or sqlite:///path), or a postgres:// DSN (carries a password: never log it)
	DBApp                 string // TESSERA_DB_APP: the application login's postgres:// DSN for request traffic (carries a password: never log it)
	DBAllowPrivilegedApp  bool   // TESSERA_DEV_DB_ALLOW_PRIVILEGED_APP: let the request pool be a privileged login (dev only)
	KEKFile               string // TESSERA_KEK_FILE, when set
	KEKKMS                string // TESSERA_KEK_KMS, when the KEK is wrapped by a cloud key service
	CookieSecure          bool
	CORSOrigins           []string
	TrustedProxies        []netip.Prefix
	OutboundAllowLoopback bool // safehttp may reach 127.0.0.1 / ::1 (dev only)
	// SafedialAllow is TESSERA_SAFEDIAL_ALLOW: comma-separated host:port or
	// CIDR:port entries a dev instance may dial on private addresses (live
	// LDAP checks against a lab directory). Dev only; syntax is checked by
	// safedial.ParseAllow. Production reaches private directories through the
	// Directory Agent instead.
	SafedialAllow string
	// AgentAddr is TESSERA_AGENT_ADDR: the address of the mutual-TLS listener
	// the Directory Agents connect to (DR-11). Empty: no listener, and
	// enrolled agents cannot connect. AgentTLSCert and AgentTLSKey
	// (TESSERA_AGENT_TLS_CERT, TESSERA_AGENT_TLS_KEY) are that listener's
	// certificate and key files, required whenever AgentAddr is set; the CA
	// that signs the certificate is the one the agents pin.
	AgentAddr    string
	AgentTLSCert string
	AgentTLSKey  string
	// ExternalWorkerKinds is TESSERA_EXTERNAL_WORKER_KINDS: the worker kinds
	// (WorkerKinds) that `tessera serve` does not run in-process because
	// `tessera worker` processes do (issue #302). Empty: serve runs them all.
	ExternalWorkerKinds []string
	// ConnectorSyncSchedule is TESSERA_CONNECTOR_SYNC_SCHEDULE: a queue spec
	// ("@every 15m" or five cron fields) that schedules connector_sync for
	// every tenant, run by whichever process runs that kind. Empty: syncs run
	// on demand only. The spec itself is validated where it is registered.
	ConnectorSyncSchedule string
	// RotationFakeAdapters admits the simulated secret-rotation adapter
	// (TESSERA_ROTATION_FAKE_ADAPTERS; dev and test only).
	RotationFakeAdapters bool
	// StepUpAllowWeaker lets a tenant's step-up policy replace the code's own
	// step-up requirements with weaker ones (TESSERA_STEPUP_ALLOW_WEAKER; off by
	// default, a dev convenience for an IdP that cannot do the stronger methods).
	// Without it a policy can only add or strengthen step-up. Refused in prod.
	StepUpAllowWeaker      bool
	AuditAnchor            string
	AuditCheckpointSeconds int
	AuditCheckpointEvents  int
	// AuthRateBurst and AnonRateBurst are the per-IP burst sizes of the
	// /api/auth/* and anonymous request limiters (TESSERA_AUTH_RATE_BURST,
	// TESSERA_ANON_RATE_BURST; defaults 30 and 120). Browser test suites from
	// one address raise them.
	AuthRateBurst int
	AnonRateBurst int
	// AWSCatalogDir (TESSERA_AWS_CATALOG_DIR) is the catalog directory with
	// compiled/<version>.json.gz; empty leaves the AWS evaluator routes
	// unavailable (503). AWSCatalogVersion picks a version (default: newest).
	AWSCatalogDir     string
	AWSCatalogVersion string
	// BackupDir (TESSERA_BACKUP_DIR) turns on scheduled encrypted backups
	// every BackupEveryMinutes, keeping the newest BackupKeep (issue #171).
	BackupDir string
	// ArchiveDir (TESSERA_ARCHIVE_DIR) is where the archival job (issue #298)
	// keeps sealed segments of records past their retention; ArchiveURL
	// (TESSERA_ARCHIVE_URL) is an http(s) object store used instead, reached
	// through internal/safehttp. With neither, ArchiveDirFor falls back to
	// BackupDir/archive, then, outside prod, to var/archive next to the
	// database; in prod an unset archive means nothing is archived or deleted.
	ArchiveDir string
	ArchiveURL string
	// ArchiveTokenSealed (TESSERA_ARCHIVE_TOKEN_SEALED) is the base64 of the
	// object store's bearer token sealed under the KEK (`tessera archive
	// seal-token`). Prod refuses ArchiveURL without it.
	ArchiveTokenSealed string
	// BackupURL (TESSERA_BACKUP_URL) is an s3://, azure:// or gs:// URL each
	// scheduled backup is also copied to. SQLite only, like the backups.
	BackupURL             string
	BackupEveryMinutes    int
	BackupKeep            int
	AccessTokenTTLSeconds int
	DeviceCodeTTLSeconds  int
	DPoPRSNonce           bool
	RPID                  string
	Notify                string
	DevIdPURL             string
	// GroupsSyncBudget is TESSERA_GROUPS_SYNC_BUDGET: the most effective-row
	// operations a group change may do inside its request; more is queued
	// (design groups-grouper-parity.md §6.5).
	GroupsSyncBudget int
	// GroupsRetentionDays is TESSERA_GROUPS_RETENTION_DAYS (`groups.retention_days`):
	// how long group events and point-in-time history are kept, 7 years by
	// default (design §10.2).
	GroupsRetentionDays int
	// FakeTarget is TESSERA_DEV_FAKE_TARGET: cmd/tessera starts an in-process
	// fake SCIM target on a loopback port, so the provisioning screens can be
	// demonstrated without a real system. Refused in prod.
	FakeTarget bool
	// DevOAuthFakeURL is TESSERA_DEV_OAUTH_FAKE_URL (a loopback origin such as
	// http://127.0.0.1:10000): cmd/tessera serves the stateful OAuth app
	// provider fakes there and the dev seed points the provider connections at
	// it, so OAuth apps can be tried end to end. Refused in prod.
	DevOAuthFakeURL string
	// Mail is the notification email delivery (issue #189).
	Mail Mail
	// NotifyMaxAttempts is how many times the dispatcher tries to send one
	// email before it is a dead letter (TESSERA_NOTIFY_MAX_ATTEMPTS).
	NotifyMaxAttempts int
	// NotifyDigestHour is the UTC hour from which the daily digest is built
	// (TESSERA_NOTIFY_DIGEST_HOUR).
	NotifyDigestHour int
	// SoDMaxMitigationDays is the longest a SoD mitigation or acceptance may run
	// (TESSERA_SOD_MAX_MITIGATION_DAYS, default 365); SoDWarnDays is how many days
	// before it ends its owners are warned (TESSERA_SOD_WARN_DAYS, default 14).
	SoDMaxMitigationDays int
	SoDWarnDays          int
	// MetricsAddr is TESSERA_METRICS_ADDR: where the internal /metrics
	// listener binds (host:port). Empty means no metrics listener. Dev and
	// test default to MetricsDefaultAddr (loopback); production defaults to
	// off and, when set, must name a loopback or private IP literal (or the
	// wildcard with TESSERA_METRICS_ALLOW_WILDCARD=true, for a container
	// whose network policy limits the scraper). /metrics is never served on
	// the public listener.
	MetricsAddr string
	// MetricsAddrDefault is true when MetricsAddr is the dev default rather
	// than an operator's choice: a busy port is then a warning, not fatal.
	MetricsAddrDefault bool
	// WorkerMetricsAddr is TESSERA_WORKER_METRICS_ADDR: where `tessera worker`
	// serves /metrics (host:port; empty = no listener, the default). It must be
	// a loopback, private or link-local IP literal unless
	// WorkerMetricsAllowPublic (TESSERA_WORKER_METRICS_ALLOW_PUBLIC) is set; see
	// CheckWorkerMetricsAddr. The API's own /metrics is MetricsAddr.
	WorkerMetricsAddr        string
	WorkerMetricsAllowPublic bool
	// ReadyMaxLoopLagSeconds is how long a background loop may go without a
	// success before /readyz fails (TESSERA_READY_MAX_LOOP_LAG_SECONDS).
	ReadyMaxLoopLagSeconds int
	// ShutdownGrace is TESSERA_SHUTDOWN_GRACE (a Go duration such as 25s, or
	// whole seconds; default 25s, between 1s and 10m): after SIGTERM the server
	// stops accepting, drains in-flight requests and stops its loops within
	// this time. Keep it below the platform's termination grace period.
	ShutdownGrace time.Duration
	// ShutdownDrainDelay is TESSERA_SHUTDOWN_DRAIN_DELAY (same syntax; default
	// 0, at most 2m): how long /readyz reports "unavailable" before the
	// listener stops accepting, so a load balancer stops sending traffic first.
	ShutdownDrainDelay time.Duration
	// LogFormat is TESSERA_LOG_FORMAT: "json" (the default in prod and test) or
	// "text" (the dev default). json goes to stdout, text to stderr.
	LogFormat string
	// LoaderDataDir is TESSERA_LOADER_DATA_DIR: the directory the SQLite files
	// and CSV files of group loaders live in, one subdirectory per tenant
	// (<dir>/<tenant id>/; design groups-grouper-parity.md §9.1). Empty (the default) turns file sources off. It must be absolute and
	// must not contain Tessera's own database.
	LoaderDataDir string
	// GroupsProvSQLDir is TESSERA_GROUPS_PROV_SQL_DIR: the directory of the SQLite
	// files the group provisioning SQL target writes. Empty (the default)
	// disables that target; a tenant chooses only a file name inside it.
	GroupsProvSQLDir string
	// FrozenNow is TESSERA_NOW (tests and demos; refused in prod). The zero
	// time means the wall clock; use Clock.
	FrozenNow time.Time

	kekRef     kekwrap.Ref // TESSERA_KEK_KMS, parsed
	kekWrapped []byte      // TESSERA_KEK_WRAPPED, decoded; cleared once unwrapped
	kek        *secretKey  // decoded TESSERA_KEK or TESSERA_KEK_FILE; nil means "dev auto-generated"
	// outbound is the validated environment and loopback exception, set
	// only by Load. safehttp.ForConfig reads it (Outbound), so neither a
	// hand-built Config nor one whose exported fields were edited after
	// Load can turn the loopback exception on.
	outbound *outboundSettings
}

type outboundSettings struct {
	env           string
	allowLoopback bool
}

// Outbound returns the environment and loopback exception validated by
// Load; ok is false for a Config that Load did not return.
func (c *Config) Outbound() (env string, allowLoopback, ok bool) {
	if c == nil || c.outbound == nil {
		return "", false, false
	}
	return c.outbound.env, c.outbound.allowLoopback, true
}

type secretKey struct{ b []byte }

// Mail modes (TESSERA_NOTIFY_EMAIL).
const (
	MailOff  = "off"  // no email is sent; deliveries are recorded as skipped
	MailDev  = "dev"  // the dev sink: messages are logged and appended to var/dev-mail.jsonl
	MailSMTP = "smtp" // an SMTP relay (TESSERA_SMTP_*)
)

// SMTP TLS modes (TESSERA_SMTP_TLS).
const (
	SMTPStartTLS = "starttls" // upgrade a plain connection (port 587)
	SMTPTLS      = "tls"      // TLS from the first byte (port 465)
	SMTPNoTLS    = "none"     // plain text; dev only
)

// Mail configures the email sender. The SMTP password is never held in
// clear: PasswordSealed is the base64 of seal.Seal(password,
// seal.AAD(tenancy.Platform, "smtp", "password")) under the KEK; produce it
// with `tessera notify seal-password`.
type Mail struct {
	Mode           string // MailOff, MailDev or MailSMTP
	Host           string
	Port           int
	Username       string
	PasswordSealed string // base64; empty for a relay that needs no login
	From           string // an RFC 5322 address
	TLS            string // SMTPStartTLS, SMTPTLS or SMTPNoTLS
}

// String describes the mail settings without the sealed password.
func (m Mail) String() string {
	return fmt.Sprintf("mail{mode=%s host=%s port=%d tls=%s from=%s}", m.Mode, m.Host, m.Port, m.TLS, m.From)
}

// Load reads the configuration through getenv (os.Getenv in production,
// a map in tests) and validates it, including the production guard rails.
func Load(getenv func(string) string) (*Config, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	c := &Config{Env: getenv("TESSERA_ENV")}
	switch c.Env {
	case "":
		c.Env = Dev // design default; serve still requires an explicit TESSERA_ENV=dev
	case Dev, Test, Prod:
	default:
		return nil, fmt.Errorf("config: invalid TESSERA_ENV %q: want TESSERA_ENV=dev, test or prod", c.Env)
	}
	prod := c.Env == Prod
	def := func(devValue, prodValue string) string {
		if prod {
			return prodValue
		}
		return devValue
	}
	str := func(k, devValue, prodValue string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def(devValue, prodValue)
	}
	boolean := func(k string, devValue, prodValue bool) bool {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			if prod {
				return prodValue
			}
			return devValue
		}
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
		bad("%s: %q is not a boolean", k, v)
		return false
	}
	integer := func(k string, d, lo, hi int) int {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			return d
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			bad("%s: %q must be an integer from %d to %d", k, v, lo, hi)
			return d
		}
		return n
	}

	c.PublicURL = strings.TrimRight(str("TESSERA_PUBLIC_URL", "http://localhost:5173", ""), "/")
	c.APIAudience = str("TESSERA_API_AUDIENCE", c.PublicURL+"/api", c.PublicURL+"/api")
	c.DB = dbPath(getenv("TESSERA_DB"))
	c.DBApp = strings.TrimSpace(getenv("TESSERA_DB_APP"))
	c.DBAllowPrivilegedApp = boolean("TESSERA_DEV_DB_ALLOW_PRIVILEGED_APP", false, false)
	c.CookieSecure = boolean("TESSERA_COOKIE_SECURE", true, true)
	c.CORSOrigins = corsOrigins(getenv("TESSERA_CORS_ORIGINS"), getenv("UI_PORT"), prod)
	c.OutboundAllowLoopback = boolean("TESSERA_OUTBOUND_ALLOW_LOOPBACK", true, false)
	c.RotationFakeAdapters = boolean("TESSERA_ROTATION_FAKE_ADAPTERS", true, false)
	c.StepUpAllowWeaker = boolean("TESSERA_STEPUP_ALLOW_WEAKER", false, false)
	// dev default: var/audit-anchors.jsonl next to the database (AnchorURL)
	c.SafedialAllow = strings.TrimSpace(getenv("TESSERA_SAFEDIAL_ALLOW"))
	c.AgentAddr = strings.TrimSpace(getenv("TESSERA_AGENT_ADDR"))
	c.AgentTLSCert = strings.TrimSpace(getenv("TESSERA_AGENT_TLS_CERT"))
	c.AgentTLSKey = strings.TrimSpace(getenv("TESSERA_AGENT_TLS_KEY"))
	if c.AgentAddr != "" && (c.AgentTLSCert == "" || c.AgentTLSKey == "") {
		bad("TESSERA_AGENT_ADDR needs TESSERA_AGENT_TLS_CERT and TESSERA_AGENT_TLS_KEY: the agent channel is mutual TLS only")
	}
	if c.AgentAddr == "" && (c.AgentTLSCert != "" || c.AgentTLSKey != "") {
		bad("TESSERA_AGENT_TLS_CERT and TESSERA_AGENT_TLS_KEY are set without TESSERA_AGENT_ADDR")
	}
	for _, k := range strings.Split(getenv("TESSERA_EXTERNAL_WORKER_KINDS"), ",") {
		if k = strings.TrimSpace(k); k == "" || slices.Contains(c.ExternalWorkerKinds, k) {
			continue
		}
		if !slices.Contains(WorkerKinds, k) {
			bad("TESSERA_EXTERNAL_WORKER_KINDS: unknown kind %q (want %s)", k, strings.Join(WorkerKinds, ", "))
			continue
		}
		c.ExternalWorkerKinds = append(c.ExternalWorkerKinds, k)
	}
	slices.Sort(c.ExternalWorkerKinds)
	c.ConnectorSyncSchedule = strings.TrimSpace(getenv("TESSERA_CONNECTOR_SYNC_SCHEDULE"))
	c.AuditAnchor = str("TESSERA_AUDIT_ANCHOR", "", "")
	if a := c.AuditAnchor; a != "" && !strings.HasPrefix(a, "file://") && !strings.HasPrefix(a, "s3://") && !isCloudAnchor(a) {
		bad("TESSERA_AUDIT_ANCHOR: %q is not a file://, s3://, azure:// or gs:// URL", a)
	} else if isCloudAnchor(a) {
		if err := checkObjectURL(a, prod); err != nil {
			bad("TESSERA_AUDIT_ANCHOR: %v", err)
		}
	}
	c.AuditCheckpointSeconds = integer("TESSERA_AUDIT_CHECKPOINT_SECONDS", 300, 1, 86400)
	c.AuditCheckpointEvents = integer("TESSERA_AUDIT_CHECKPOINT_EVENTS", 1000, 1, 1_000_000)
	c.AuthRateBurst = integer("TESSERA_AUTH_RATE_BURST", 30, 1, 100_000)
	c.AnonRateBurst = integer("TESSERA_ANON_RATE_BURST", 120, 1, 100_000)
	// The wide range is for load tests and the e2e suite; production keeps per-IP throttling of the
	// unauthenticated sign-in and anonymous endpoints meaningful (issue #463).
	if prod && c.AuthRateBurst > MaxProdAuthRateBurst {
		bad("TESSERA_AUTH_RATE_BURST must be at most %d with TESSERA_ENV=prod (got %d)", MaxProdAuthRateBurst, c.AuthRateBurst)
	}
	if prod && c.AnonRateBurst > MaxProdAnonRateBurst {
		bad("TESSERA_ANON_RATE_BURST must be at most %d with TESSERA_ENV=prod (got %d)", MaxProdAnonRateBurst, c.AnonRateBurst)
	}
	c.BackupDir = str("TESSERA_BACKUP_DIR", "", "")
	c.ArchiveDir = str("TESSERA_ARCHIVE_DIR", "", "")
	c.ArchiveURL = str("TESSERA_ARCHIVE_URL", "", "")
	if u := c.ArchiveURL; objstore.IsObjectURL(u) {
		// s3://, azure:// or gs://: credentials come from the workload identity
		if err := checkObjectURL(u, prod); err != nil {
			bad("TESSERA_ARCHIVE_URL: %v", err)
		}
	} else if u != "" {
		pu, err := url.Parse(u)
		switch {
		case err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" || pu.User != nil || pu.RawQuery != "" || pu.Fragment != "":
			bad("TESSERA_ARCHIVE_URL: %q is not an http(s) URL without credentials, query or fragment", u)
		case pu.Scheme != "https" && prod:
			bad("TESSERA_ARCHIVE_URL must be https with TESSERA_ENV=prod")
		}
	}
	c.ArchiveTokenSealed = str("TESSERA_ARCHIVE_TOKEN_SEALED", "", "")
	if c.ArchiveTokenSealed != "" {
		if _, err := base64.StdEncoding.DecodeString(c.ArchiveTokenSealed); err != nil {
			bad("TESSERA_ARCHIVE_TOKEN_SEALED: not valid base64 (seal the token with `tessera archive seal-token`)")
		}
		if c.ArchiveURL == "" {
			bad("TESSERA_ARCHIVE_TOKEN_SEALED needs TESSERA_ARCHIVE_URL")
		}
	}
	if c.ArchiveTokenSealed != "" && objstore.IsObjectURL(c.ArchiveURL) {
		bad("TESSERA_ARCHIVE_TOKEN_SEALED applies to http(s) archive stores only; s3://, azure:// and gs:// use the workload identity")
	}
	c.BackupURL = str("TESSERA_BACKUP_URL", "", "")
	if c.BackupURL != "" {
		switch {
		case !objstore.IsObjectURL(c.BackupURL):
			bad("TESSERA_BACKUP_URL must be an s3://, azure:// or gs:// URL")
		case c.BackupDir == "":
			bad("TESSERA_BACKUP_URL needs TESSERA_BACKUP_DIR (the backup is written there, then copied)")
		default:
			if err := checkObjectURL(c.BackupURL, prod); err != nil {
				bad("TESSERA_BACKUP_URL: %v", err)
			}
		}
	}
	if prod && c.ArchiveURL != "" && !objstore.IsObjectURL(c.ArchiveURL) && c.ArchiveTokenSealed == "" {
		bad("TESSERA_ARCHIVE_URL needs TESSERA_ARCHIVE_TOKEN_SEALED with TESSERA_ENV=prod (an archive store that accepts unauthenticated writes is refused)")
	}
	c.BackupEveryMinutes = integer("TESSERA_BACKUP_EVERY_MINUTES", 360, 5, 7*24*60)
	c.BackupKeep = integer("TESSERA_BACKUP_KEEP", 28, 1, 10_000)
	c.GroupsSyncBudget = integer("TESSERA_GROUPS_SYNC_BUDGET", 5000, 1, 10_000_000)
	c.GroupsRetentionDays = integer("TESSERA_GROUPS_RETENTION_DAYS", 7*365, 30, 36_500)
	if d := strings.TrimSpace(getenv("TESSERA_LOADER_DATA_DIR")); d != "" {
		c.LoaderDataDir = filepath.Clean(d)
		db, err := filepath.Abs(c.DB)
		switch {
		case !filepath.IsAbs(d):
			bad("TESSERA_LOADER_DATA_DIR: %q is not an absolute path", d)
		case err == nil && within(db, c.LoaderDataDir):
			bad("TESSERA_LOADER_DATA_DIR: %q contains the database %q: a loader could read Tessera's own data", d, c.DB)
		}
	}
	c.GroupsProvSQLDir = strings.TrimSpace(getenv("TESSERA_GROUPS_PROV_SQL_DIR"))
	c.AccessTokenTTLSeconds = integer("TESSERA_AT_TTL_SECONDS", 600, 1, MaxAccessTokenTTLSeconds)
	c.DeviceCodeTTLSeconds = integer("TESSERA_DEVICE_CODE_TTL_SECONDS", 300, 1, MaxDeviceCodeTTLSeconds)
	c.DPoPRSNonce = boolean("TESSERA_DPOP_RS_NONCE", false, false)
	c.Notify = str("TESSERA_NOTIFY", "log", "log")
	c.NotifyMaxAttempts = integer("TESSERA_NOTIFY_MAX_ATTEMPTS", 6, 1, 20)
	c.NotifyDigestHour = integer("TESSERA_NOTIFY_DIGEST_HOUR", 8, 0, 23)
	c.SoDMaxMitigationDays = integer("TESSERA_SOD_MAX_MITIGATION_DAYS", 365, 1, 3650)
	c.SoDWarnDays = integer("TESSERA_SOD_WARN_DAYS", 14, 1, 365)
	c.Mail = loadMail(getenv, prod, integer, bad)
	c.ShutdownGrace = loadDuration(getenv, "TESSERA_SHUTDOWN_GRACE", 25*time.Second, time.Second, 10*time.Minute, bad)
	c.ShutdownDrainDelay = loadDuration(getenv, "TESSERA_SHUTDOWN_DRAIN_DELAY", 0, 0, 2*time.Minute, bad)
	c.LogFormat = strings.ToLower(str("TESSERA_LOG_FORMAT", "text", "json"))
	if c.Env == Test && strings.TrimSpace(getenv("TESSERA_LOG_FORMAT")) == "" {
		c.LogFormat = "json"
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		bad("TESSERA_LOG_FORMAT: %q is not json or text", c.LogFormat)
	}
	c.ReadyMaxLoopLagSeconds = integer("TESSERA_READY_MAX_LOOP_LAG_SECONDS", 300, 30, 86400)
	c.MetricsAddr, c.MetricsAddrDefault = loadMetricsAddr(getenv, prod, boolean("TESSERA_METRICS_ALLOW_WILDCARD", false, false), bad)
	c.WorkerMetricsAllowPublic = boolean("TESSERA_WORKER_METRICS_ALLOW_PUBLIC", false, false)
	if a, err := CheckWorkerMetricsAddr(getenv("TESSERA_WORKER_METRICS_ADDR"), c.WorkerMetricsAllowPublic); err != nil {
		bad("TESSERA_WORKER_METRICS_ADDR: %v", err)
	} else {
		c.WorkerMetricsAddr = a
	}
	if c.WorkerMetricsAllowPublic && prod && strings.TrimSpace(getenv("TESSERA_WORKER_METRICS_ADDR")) == "" {
		bad("TESSERA_WORKER_METRICS_ALLOW_PUBLIC=true with no TESSERA_WORKER_METRICS_ADDR: remove it, or name the address")
	}
	if v := strings.TrimSpace(getenv("TESSERA_NOW")); v != "" {
		t, err := timeutil.ParseISO(v)
		switch {
		case err != nil:
			bad("TESSERA_NOW: %v", err)
		case t.IsZero():
			bad("TESSERA_NOW: %q is not a usable time", v)
		default:
			c.FrozenNow = t
		}
	}
	c.AWSCatalogDir = strings.TrimSpace(getenv("TESSERA_AWS_CATALOG_DIR"))
	c.AWSCatalogVersion = strings.TrimSpace(getenv("TESSERA_AWS_CATALOG_VERSION"))
	if v := c.AWSCatalogVersion; v != "" && (len(v) > 40 || strings.Trim(v, "0123456789abcdef-") != "") {
		bad("TESSERA_AWS_CATALOG_VERSION: %q is not a compiled catalog version (<date>-<hex>)", v)
	}
	c.FakeTarget = boolean("TESSERA_DEV_FAKE_TARGET", false, false)
	c.DevOAuthFakeURL = strings.TrimRight(strings.TrimSpace(getenv("TESSERA_DEV_OAUTH_FAKE_URL")), "/")
	c.DevIdPURL = strings.TrimSpace(getenv("TESSERA_DEV_IDP_URL"))
	if c.DevIdPURL == "" && !prod {
		c.DevIdPURL = "http://127.0.0.1:8001"
	}

	pub, err := parsePublicURL(c.PublicURL)
	switch {
	case c.PublicURL == "":
		bad("TESSERA_PUBLIC_URL is required with TESSERA_ENV=prod (an https URL)")
	case err != nil:
		bad("TESSERA_PUBLIC_URL: %v", err)
	case prod && pub.Scheme != "https":
		bad("TESSERA_PUBLIC_URL must be https with TESSERA_ENV=prod (got %s)", pub.Scheme)
	case prod && DevOnlyURL(c.PublicURL) != "":
		bad("TESSERA_PUBLIC_URL must not be %s with TESSERA_ENV=prod", DevOnlyURL(c.PublicURL))
	}
	// §11: the insecure-cookie fallback (Safari on http://localhost) only in
	// dev, and only for a localhost public URL.
	if !c.CookieSecure && !prod {
		if c.Env != Dev || pub == nil || (pub.Hostname() != "localhost" && pub.Hostname() != "127.0.0.1") {
			bad("TESSERA_COOKIE_SECURE=false is allowed only with TESSERA_ENV=dev and a localhost TESSERA_PUBLIC_URL")
		}
	}
	c.RPID = str("TESSERA_RP_ID", "localhost", "")
	if c.RPID == "" && pub != nil {
		c.RPID = pub.Hostname()
	}

	var perr error
	if c.TrustedProxies, perr = parseProxies(str("TESSERA_TRUSTED_PROXIES", "127.0.0.1", "")); perr != nil {
		bad("TESSERA_TRUSTED_PROXIES: %v", perr)
	}

	// KEK: TESSERA_KEK (base64 of 32 bytes) or TESSERA_KEK_FILE (a file
	// holding that base64), never both.
	inline, file := strings.TrimSpace(getenv("TESSERA_KEK")), strings.TrimSpace(getenv("TESSERA_KEK_FILE"))
	wrapped, kms := strings.TrimSpace(getenv("TESSERA_KEK_WRAPPED")), strings.TrimSpace(getenv("TESSERA_KEK_KMS"))
	switch {
	case inline != "" && file != "":
		bad("set only one of TESSERA_KEK and TESSERA_KEK_FILE")
	case (inline != "" || file != "") && (wrapped != "" || kms != ""):
		bad("set only one of TESSERA_KEK, TESSERA_KEK_FILE and TESSERA_KEK_WRAPPED with TESSERA_KEK_KMS")
	case wrapped != "" || kms != "":
		// A KEK wrapped by a cloud key service: validated here, unwrapped once
		// at start by ResolveKEK (Load itself makes no network call).
		switch ref, err := kekwrap.ParseRef(kms); {
		case wrapped == "" || kms == "":
			bad("TESSERA_KEK_WRAPPED and TESSERA_KEK_KMS must be set together")
		case err != nil:
			bad("TESSERA_KEK_KMS: %v", err)
		default:
			w, derr := base64.StdEncoding.DecodeString(wrapped)
			if derr != nil || len(w) == 0 || len(w) > 8192 {
				bad("TESSERA_KEK_WRAPPED: not base64 of a wrapped key (make it with `tessera admin wrap-kek`)")
			} else {
				c.KEKKMS, c.kekRef, c.kekWrapped = kms, ref, w
			}
		}
	case inline != "":
		k, err := decodeKEK(inline)
		if err != nil {
			bad("TESSERA_KEK: %v", err)
		} else {
			c.kek = &secretKey{k}
		}
	case file != "":
		c.KEKFile = file
		k, err := readKEKFile(file)
		if err != nil {
			bad("TESSERA_KEK_FILE: %v", err)
		} else {
			c.kek = &secretKey{k}
		}
	case prod:
		bad("a KEK is required with TESSERA_ENV=prod (set TESSERA_KEK_FILE, TESSERA_KEK, or TESSERA_KEK_WRAPPED with TESSERA_KEK_KMS)")
	}

	if prod {
		if !c.CookieSecure {
			bad("TESSERA_COOKIE_SECURE must be true with TESSERA_ENV=prod")
		}
		if len(c.CORSOrigins) > 0 {
			// §11/§18.1: the production UI is same-origin, so CORS is off.
			// The CSRF Origin check already admits the PUBLIC_URL origin.
			bad("TESSERA_CORS_ORIGINS must be empty with TESSERA_ENV=prod: the UI is same-origin and CORS is off (got %q)",
				strings.Join(c.CORSOrigins, ","))
		}
		if !c.FrozenNow.IsZero() {
			bad("TESSERA_NOW must not be set with TESSERA_ENV=prod (it freezes the clock and stops key rotation)")
		}
		for _, p := range c.TrustedProxies {
			if want := minProxyBits(p); p.Bits() < want {
				bad("TESSERA_TRUSTED_PROXIES: %s is broader than /%d with TESSERA_ENV=prod; list the load balancer CIDRs", p, want)
			}
		}
		if c.OutboundAllowLoopback {
			bad("TESSERA_OUTBOUND_ALLOW_LOOPBACK must be false with TESSERA_ENV=prod")
		}
		if c.RotationFakeAdapters {
			bad("TESSERA_ROTATION_FAKE_ADAPTERS must be false with TESSERA_ENV=prod: the simulated rotation adapter would report success without touching any credential")
		}
		if c.StepUpAllowWeaker {
			bad("TESSERA_STEPUP_ALLOW_WEAKER must be false with TESSERA_ENV=prod: a tenant policy could then weaken the step-up the code requires")
		}
		if c.DevIdPURL != "" {
			bad("TESSERA_DEV_IDP_URL must not be set with TESSERA_ENV=prod")
		}
		if c.DevOAuthFakeURL != "" {
			bad("TESSERA_DEV_OAUTH_FAKE_URL must not be set with TESSERA_ENV=prod (the fake OAuth app providers accept any revoke)")
		}
		if c.FakeTarget {
			bad("TESSERA_DEV_FAKE_TARGET must not be set with TESSERA_ENV=prod (the fake provisioning target accepts any change)")
		}
		if c.DBAllowPrivilegedApp {
			bad("TESSERA_DEV_DB_ALLOW_PRIVILEGED_APP must not be set with TESSERA_ENV=prod (the request pool must never be a privileged database login)")
		}
		if IsPostgresDSN(c.DB) {
			// Never echo the DSN: it carries the password.
			if msg := checkProdPostgres(c.DB); msg != "" {
				bad("TESSERA_DB: %s", msg)
			}
			if msg := checkProdPostgresApp(c.DB, c.DBApp); msg != "" {
				bad("TESSERA_DB_APP: %s", msg)
			}
		}
		if c.SafedialAllow != "" {
			bad("TESSERA_SAFEDIAL_ALLOW must not be set with TESSERA_ENV=prod: private directories are reached through the Directory Agent")
		}
		// s3:// is the only off-host sink so far; a file:// anchor sits on
		// the same host as the ledger it is meant to anchor.
		switch {
		case c.AuditAnchor == "":
			bad("TESSERA_AUDIT_ANCHOR is required with TESSERA_ENV=prod (s3://…)")
		case strings.HasPrefix(strings.ToLower(c.AuditAnchor), "file:"):
			bad("TESSERA_AUDIT_ANCHOR must not be file:// with TESSERA_ENV=prod (use s3://…, azure://… or gs://…)")
		case isCloudAnchor(c.AuditAnchor):
			// azure:// (immutable blob storage) and gs:// (locked bucket retention)
		case !strings.HasPrefix(c.AuditAnchor, "s3://") || len(c.AuditAnchor) == len("s3://"):
			bad("TESSERA_AUDIT_ANCHOR must be an s3://bucket/prefix URL (Object Lock), or azure://account/container/prefix (immutable storage) or gs://bucket/prefix (locked retention), with TESSERA_ENV=prod (got %q)", c.AuditAnchor)
		}
	}
	if len(errs) > 0 {
		if prod {
			return nil, fmt.Errorf("config: refusing to start with TESSERA_ENV=prod: %w", errors.Join(errs...))
		}
		return nil, fmt.Errorf("config: %w", errors.Join(errs...))
	}
	c.outbound = &outboundSettings{env: c.Env, allowLoopback: c.OutboundAllowLoopback}
	return c, nil
}

// isCloudAnchor reports an azure:// or gs:// anchor URL.
func isCloudAnchor(a string) bool {
	return strings.HasPrefix(a, "azure://") || strings.HasPrefix(a, "gs://")
}

// checkObjectURL validates an object-store URL; prod refuses a plain-http endpoint.
func checkObjectURL(raw string, prod bool) error {
	t, err := objstore.ParseURL(raw)
	if err != nil {
		return err
	}
	if prod && strings.HasPrefix(t.Endpoint, "http://") {
		return errors.New("the endpoint option must be https with TESSERA_ENV=prod")
	}
	return nil
}

// ArchiveDirFor is the directory of the local archive store for a database
// path: TESSERA_ARCHIVE_DIR, else BackupDir/archive, else (outside prod) var/archive
// next to the database. Empty: no local archive (prod with none configured).
func (c *Config) ArchiveDirFor(dbPath string) string {
	switch {
	case c.ArchiveDir != "":
		return c.ArchiveDir
	case c.BackupDir != "":
		return filepath.Join(c.BackupDir, "archive")
	case c.IsProd():
		return ""
	}
	return filepath.Join(localDir(dbPath), "var", "archive")
}

// MetricsDefaultAddr is the dev and test /metrics listener (loopback).
const MetricsDefaultAddr = "127.0.0.1:9464"

// WorkerKinds are the queue kinds that can run outside the API process
// (internal/worker.Kinds, which a test keeps equal).
var WorkerKinds = []string{"connector_sync", "provision_push"}

// loadMetricsAddr reads TESSERA_METRICS_ADDR ("off" disables it). Outside
// production the listener must be loopback. In production it is off unless
// set, and then it must be an IP literal that is loopback, private or
// link-local: never a host name (which can resolve anywhere) and never a
// public address. A wildcard bind needs TESSERA_METRICS_ALLOW_WILDCARD=true.
func loadMetricsAddr(getenv func(string) string, prod, wildcardOK bool, bad func(string, ...any)) (addr string, isDefault bool) {
	v := strings.TrimSpace(getenv("TESSERA_METRICS_ADDR"))
	switch strings.ToLower(v) {
	case "off", "none", "false":
		return "", false
	case "":
		if prod {
			return "", false
		}
		return MetricsDefaultAddr, true
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		bad("TESSERA_METRICS_ADDR: %q is not host:port", v)
		return "", false
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		bad("TESSERA_METRICS_ADDR: %q has no usable port", v)
		return "", false
	}
	a, perr := netip.ParseAddr(host)
	wildcard := host == "" || (perr == nil && a.IsUnspecified())
	switch {
	case wildcard && prod && !wildcardOK:
		bad("TESSERA_METRICS_ADDR=%s listens on every interface with TESSERA_ENV=prod: bind a loopback or private address, or set TESSERA_METRICS_ALLOW_WILDCARD=true when a network policy limits the scraper", v)
	case wildcard && !prod:
		bad("TESSERA_METRICS_ADDR=%s: outside production /metrics listens on loopback only", v)
	case wildcard:
	case host == "localhost" && !prod:
	case perr != nil:
		bad("TESSERA_METRICS_ADDR: %q must be an IP literal (a host name can resolve to a public address)", v)
	case prod && !(a.Unmap().IsLoopback() || a.Unmap().IsPrivate() || a.Unmap().IsLinkLocalUnicast()):
		bad("TESSERA_METRICS_ADDR=%s is a public address: /metrics must not be exposed publicly (use a loopback or private address)", v)
	case !prod && !a.Unmap().IsLoopback():
		bad("TESSERA_METRICS_ADDR=%s: outside production /metrics listens on loopback only", v)
	}
	return v, false
}

// loadMail reads TESSERA_NOTIFY_EMAIL and TESSERA_SMTP_*: smtp when a host is
// set, else the dev sink outside production and off in production. Production
// refuses the dev sink and SMTP without TLS.
func loadMail(getenv func(string) string, prod bool, integer func(string, int, int, int) int, bad func(string, ...any)) Mail {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	m := Mail{Host: get("TESSERA_SMTP_HOST"), Username: get("TESSERA_SMTP_USERNAME"),
		PasswordSealed: get("TESSERA_SMTP_PASSWORD_SEALED"), From: get("TESSERA_SMTP_FROM"), TLS: get("TESSERA_SMTP_TLS")}
	m.Port = integer("TESSERA_SMTP_PORT", 587, 1, 65535)
	switch m.Mode = strings.ToLower(get("TESSERA_NOTIFY_EMAIL")); m.Mode {
	case "":
		switch {
		case m.Host != "":
			m.Mode = MailSMTP
		case prod:
			m.Mode = MailOff
		default:
			m.Mode = MailDev
		}
	case MailOff, MailDev, MailSMTP:
	default:
		bad("TESSERA_NOTIFY_EMAIL: %q is not off, dev or smtp", m.Mode)
		m.Mode = MailOff
	}
	if m.TLS == "" {
		m.TLS = SMTPStartTLS
	}
	switch m.TLS {
	case SMTPStartTLS, SMTPTLS, SMTPNoTLS:
	default:
		bad("TESSERA_SMTP_TLS: %q is not starttls, tls or none", m.TLS)
	}
	if prod && m.Mode == MailDev {
		bad("TESSERA_NOTIFY_EMAIL=dev (the dev sink) must not be used with TESSERA_ENV=prod: set TESSERA_SMTP_HOST, or TESSERA_NOTIFY_EMAIL=off")
	}
	if m.Mode == MailSMTP {
		switch {
		case m.Host == "":
			bad("TESSERA_SMTP_HOST is required with TESSERA_NOTIFY_EMAIL=smtp")
		case strings.ContainsAny(m.Host, "/@ \t\r\n"):
			bad("TESSERA_SMTP_HOST must be a host name or address")
		}
		if a, err := mail.ParseAddress(m.From); err != nil || a.Address == "" {
			bad("TESSERA_SMTP_FROM is required with smtp and must be an email address")
		}
		if prod && m.TLS == SMTPNoTLS {
			bad("TESSERA_SMTP_TLS=none must not be used with TESSERA_ENV=prod")
		}
		if m.Username != "" && m.PasswordSealed == "" {
			bad("TESSERA_SMTP_PASSWORD_SEALED is required with TESSERA_SMTP_USERNAME (seal it with `tessera notify seal-password`; the password is never read in clear)")
		}
		if m.PasswordSealed != "" {
			if _, err := base64.StdEncoding.DecodeString(m.PasswordSealed); err != nil {
				bad("TESSERA_SMTP_PASSWORD_SEALED: not valid base64")
			}
		}
	}
	return m
}

// Clock is the clock to run on: TESSERA_NOW when set (dev only), otherwise
// the wall clock.
func (c *Config) Clock() timeutil.Clock {
	if c.FrozenNow.IsZero() {
		return timeutil.System
	}
	return timeutil.Frozen(c.FrozenNow)
}

// MaxProdAuthRateBurst and MaxProdAnonRateBurst cap the per-IP bursts in
// production: above them per-IP throttling of the sign-in and anonymous
// endpoints no longer limits anything (issue #463).
const (
	MaxProdAuthRateBurst = 300
	MaxProdAnonRateBurst = 2000
)

// IsProd reports whether the production guard rails apply.
func (c *Config) IsProd() bool { return c.Env == Prod }

// PublicOrigin is the origin (scheme://host[:port]) of PublicURL, which the
// CSRF Origin check always admits.
func (c *Config) PublicOrigin() string {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// String describes the configuration without the KEK.
func (c *Config) String() string {
	return fmt.Sprintf("config{env=%s public_url=%s kek=%s cors=%v outbound_allow_loopback=%t}",
		c.Env, c.PublicURL, c.kekSource(), c.CORSOrigins, c.OutboundAllowLoopback)
}

// LogValue renders the configuration for slog without the KEK.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(slog.String("env", c.Env), slog.String("public_url", c.PublicURL),
		slog.String("kek", c.kekSource()), slog.Any("cors_origins", c.CORSOrigins),
		slog.Bool("outbound_allow_loopback", c.OutboundAllowLoopback))
}

func (c *Config) kekSource() string {
	switch {
	case c.KEKFile != "":
		return "file:" + c.KEKFile + " (REDACTED)"
	case c.KEKKMS != "":
		return "kms:" + c.KEKKMS + " (REDACTED)"
	case c.kek != nil:
		return "env (REDACTED)"
	}
	return "dev auto-generated"
}

// AnchorURL is the audit anchor sink: TESSERA_AUDIT_ANCHOR, or in dev the
// file var/audit-anchors.jsonl next to the database (server/var for the
// default database). Load refuses a missing or file:// anchor in prod.
func (c *Config) AnchorURL(dbPath string) string {
	if c.AuditAnchor != "" || c.IsProd() {
		return c.AuditAnchor
	}
	return DevAnchorURL(dbPath)
}

// DevAnchorURL is the dev anchor file for a database path.
func DevAnchorURL(dbPath string) string {
	p, err := filepath.Abs(filepath.Join(localDir(dbPath), "var", "audit-anchors.jsonl"))
	if err != nil {
		p = filepath.Join(localDir(dbPath), "var", "audit-anchors.jsonl")
	}
	return "file://" + filepath.ToSlash(p)
}

// DevKEKPath is where a dev KEK is generated: var/dev-kek next to the
// database file (server/var/dev-kek for the default database).
func DevKEKPath(dbPath string) string {
	return filepath.Join(localDir(dbPath), "var", "dev-kek")
}

// localDir is the directory dev files (KEK, anchors) live in: next to a
// SQLite database file, or the working directory for a Postgres DSN.
func localDir(dbPath string) string {
	if IsPostgresDSN(dbPath) {
		return "."
	}
	return filepath.Dir(dbPath)
}

// IsPostgresDSN reports whether a database setting is a postgres:// URL.
func IsPostgresDSN(s string) bool {
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

// checkProdPostgres returns what is wrong with a production Postgres DSN, or
// "". It requires TLS to the server and refuses the retired app_role option
// (the application has its own login, TESSERA_DB_APP; #430).
func checkProdPostgres(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "is not a valid postgres:// URL"
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "is not a valid postgres:// URL"
	}
	var problems []string
	switch q.Get("sslmode") {
	case "require", "verify-ca", "verify-full":
	default:
		problems = append(problems, "sslmode must be require, verify-ca or verify-full with TESSERA_ENV=prod")
	}
	if q.Has("app_role") {
		problems = append(problems, "app_role is no longer supported (SET ROLE can be reversed): give the application its own login in TESSERA_DB_APP")
	}
	return strings.Join(problems, "; ")
}

// checkProdPostgresApp returns what is wrong with the application login's DSN
// next to the owner DSN, or "". Request traffic must connect as its own login
// (never the owner, never SET ROLE) so row-level security binds it (design
// §14.3, #430).
func checkProdPostgresApp(ownerDSN, appDSN string) string {
	if appDSN == "" {
		return "is required with a postgres:// TESSERA_DB and TESSERA_ENV=prod: the application must log in as its own NOSUPERUSER NOBYPASSRLS role (usually tessera_app), not the owner"
	}
	if !IsPostgresDSN(appDSN) {
		return "is not a valid postgres:// URL"
	}
	a, err := url.Parse(appDSN)
	if err != nil {
		return "is not a valid postgres:// URL"
	}
	q, err := url.ParseQuery(a.RawQuery)
	if err != nil {
		return "is not a valid postgres:// URL"
	}
	var problems []string
	switch q.Get("sslmode") {
	case "require", "verify-ca", "verify-full":
	default:
		problems = append(problems, "sslmode must be require, verify-ca or verify-full with TESSERA_ENV=prod")
	}
	if q.Has("app_role") {
		problems = append(problems, "app_role is not supported")
	}
	if a.User == nil || a.User.Username() == "" {
		problems = append(problems, "must name the application login (user) in the URL")
	} else if o, err := url.Parse(ownerDSN); err == nil && o.User != nil && o.User.Username() == a.User.Username() {
		problems = append(problems, "must be a different login from TESSERA_DB's")
	}
	return strings.Join(problems, "; ")
}

// DevMailPath is where the dev mail sink appends: var/dev-mail.jsonl next to
// the database file.
func DevMailPath(dbPath string) string {
	return filepath.Join(localDir(dbPath), "var", "dev-mail.jsonl")
}

// KEKWrapped reports whether the KEK is a wrapped one that ResolveKEK must
// unwrap before Sealer can be used.
func (c *Config) KEKWrapped() bool { return c.kek == nil && len(c.kekWrapped) > 0 }

// ResolveKEK unwraps TESSERA_KEK_WRAPPED with the cloud key service named by
// TESSERA_KEK_KMS, through unwrap (cmd/tessera passes kekwrap.Unwrap bound to
// the safehttp client and the workload identity). It does nothing when the KEK
// is not wrapped. After it, the configuration behaves exactly as with
// TESSERA_KEK. The wrapped value is dropped once opened.
func (c *Config) ResolveKEK(ctx context.Context, unwrap func(ctx context.Context, ref kekwrap.Ref, wrapped []byte) ([]byte, error)) error {
	if !c.KEKWrapped() {
		return nil
	}
	k, err := unwrap(ctx, c.kekRef, c.kekWrapped)
	if err != nil {
		return err
	}
	if len(k) != seal.KeySize {
		return fmt.Errorf("config: the unwrapped KEK is %d bytes, want %d", len(k), seal.KeySize)
	}
	c.kek, c.kekWrapped = &secretKey{k}, nil
	return nil
}

// Sealer returns the KEK sealer. With no KEK configured (dev only; Load
// refuses that in prod) it loads the dev KEK at devKEKPath, generating it
// with mode 0600 on first use.
func (c *Config) Sealer(devKEKPath string) (*seal.Sealer, error) {
	if c.kek != nil {
		return seal.New(c.kek.b)
	}
	if c.KEKWrapped() {
		return nil, errors.New("config: the KEK is wrapped (TESSERA_KEK_WRAPPED): ResolveKEK must run first")
	}
	if c.IsProd() {
		return nil, errors.New("config: no KEK configured")
	}
	k, err := readKEKFile(devKEKPath)
	if errors.Is(err, fs.ErrNotExist) {
		k = seal.RandomBytes(seal.KeySize)
		switch err := writeDevKEK(devKEKPath, k); {
		case errors.Is(err, fs.ErrExist):
			// another process won the race: use its KEK (read once; no
			// retry loop, e.g. on a dangling symlink)
			if k, err = readKEKFile(devKEKPath); err != nil {
				return nil, fmt.Errorf("config: dev KEK %s: %w", devKEKPath, err)
			}
		case err != nil:
			return nil, fmt.Errorf("config: dev KEK: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("config: dev KEK %s: %w", devKEKPath, err)
	}
	return seal.New(k)
}

// writeDevKEK writes k to a mode-0600 temp file in path's directory, syncs
// it, and then links it into place, so path is either absent or holds a
// complete KEK (a crash mid-write leaves only a temp file, never a torn
// KEK). The link is atomic and, unlike rename, never replaces a KEK another
// process placed first (fs.ErrExist).
func writeDevKEK(path string, k []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".dev-kek-*.tmp") // mode 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(k) + "\n")
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- the KEK's own directory
		_ = d.Sync() // persist the new directory entry
		_ = d.Close()
	}
	return nil
}

func decodeKEK(s string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("not valid base64")
	}
	if len(k) != seal.KeySize {
		return nil, fmt.Errorf("must decode to %d bytes (got %d)", seal.KeySize, len(k))
	}
	return k, nil
}

// readKEKFile reads a base64 KEK file. It refuses a file that group or
// other users can access, or that is not a regular file.
func readKEKFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	// A secret volume (Kubernetes, a CSI driver) is mounted 0440 or 0640
	// with the pod's fsGroup, so the group may read it. What is never
	// accepted: any access for others, and write access for the group. The
	// file must also belong to this process or to root (not to another user
	// who could replace it).
	if perm := fi.Mode().Perm(); perm&0o007 != 0 || perm&0o020 != 0 {
		return nil, fmt.Errorf("%s is accessible to other users (mode %04o); chmod 600 it (a mounted secret volume may be 0440 or 0640)", path, perm)
	}
	if err := checkKEKOwner(fi, path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-chosen KEK path
	if err != nil {
		return nil, err
	}
	return decodeKEK(string(b))
}

// DevOnlyURL says why a URL may be used only in development: plain http,
// or a host that is localhost or a loopback, private or link-local
// address. "" means the URL is fine in production. Load applies it to
// TESSERA_PUBLIC_URL, and the configuration import (internal/transport)
// to every URL in a bundle applied to a production server.
func DevOnlyURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme == "http" || u.Scheme == "ws" {
		return "plain " + u.Scheme
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "a localhost address"
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		switch {
		case a.IsLoopback():
			return "a loopback address"
		case a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsUnspecified():
			return "a private or link-local address"
		}
	}
	return ""
}

func parsePublicURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("not a URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("scheme must be https (got %q)", u.Scheme)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("must be scheme://host[:port][/path] with no user info, query or fragment")
	}
	return u, nil
}

func parseProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			pf, err := netip.ParsePrefix(p)
			if err != nil {
				return nil, fmt.Errorf("%q is not an IP or CIDR", p)
			}
			if pf.Bits() == 0 { // every address would be a trusted proxy
				return nil, fmt.Errorf("%q trusts every address; list the proxy CIDRs", p)
			}
			out = append(out, pf.Masked())
			continue
		}
		a, err := netip.ParseAddr(p)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR", p)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// minProxyBits is the shortest prod prefix for p's address family. An
// IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/n) counts as IPv4 at n-96 bits, so
// ::ffff:0:0/96 is refused like 0.0.0.0/0.
func minProxyBits(p netip.Prefix) int {
	switch {
	case p.Addr().Is4():
		return MinProxyPrefixIPv4
	case p.Addr().Is4In6():
		return 96 + MinProxyPrefixIPv4
	}
	return MinProxyPrefixIPv6
}

// dbPath accepts a plain path or the Python backend's sqlite:/// URL form.
func dbPath(v string) string {
	if v == "" {
		return "tessera.db"
	}
	return strings.TrimPrefix(v, "sqlite:///")
}

// within reports whether path is dir or below it (both absolute and clean).
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// corsOrigins: an explicit comma-separated list wins; otherwise dev allows the
// dev UI on localhost and 127.0.0.1 (port UI_PORT or 5173) and prod allows
// none.
func corsOrigins(v, uiPort string, prod bool) []string {
	if v != "" {
		var out []string
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" {
				out = append(out, o)
			}
		}
		return out
	}
	if prod {
		return nil
	}
	if uiPort == "" {
		uiPort = "5173"
	}
	return []string{"http://localhost:" + uiPort, "http://127.0.0.1:" + uiPort}
}

// loadDuration reads a duration setting: a Go duration ("25s", "1m") or whole
// seconds, between min and max.
func loadDuration(getenv func(string) string, key string, def, min, max time.Duration, bad func(string, ...any)) time.Duration {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		n, nerr := strconv.Atoi(v)
		if nerr != nil {
			bad("%s: %q is not a duration (for example 25s)", key, v)
			return def
		}
		d = time.Duration(n) * time.Second
	}
	if d < min || d > max {
		bad("%s: %s is outside %s to %s", key, d, min, max)
		return def
	}
	return d
}
