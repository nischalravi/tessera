package provision

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/certs"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/atlassian"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/erp"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/ldapwrite"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/pam"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/salesforce"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/servicenow"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/sqldb"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/okta"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/scim"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Target kinds.
const (
	KindSCIM = "scim"
	KindOkta = "okta"
	KindFake = "fake"
	// KindREST is the generic REST target (issue #552): any HTTP/JSON system, described by a
	// declarative spec kept in Settings.REST (internal/connectors/restgen).
	KindREST = "rest"

	// Vault targets (issue #304): safe membership in a privileged-access vault.
	KindCyberArk    = "cyberark"
	KindDelinea     = "delinea"
	KindBeyondTrust = "beyondtrust"
	// ERP targets: role assignment in SAP and Oracle (internal/connectors/erp).
	KindSAP    = "sap"
	KindOracle = "oracle"
	// KindSalesforce: user lifecycle and permission-set assignment in a Salesforce org (issue #555).
	KindSalesforce = "salesforce"
	// KindServiceNow: user lifecycle, group membership and role assignment in a ServiceNow instance, or
	// (credential mode "ticket") an incident per change for a person to act on (issue #559).
	KindServiceNow = "servicenow"
	// KindAtlassian: group membership and project role actors of an Atlassian Cloud site (issue #559). Accounts
	// are provisioned through the Atlassian Cloud SCIM preset.
	KindAtlassian = "atlassian"
	// KindSQL is a database (PostgreSQL, MySQL, SQL Server, Oracle): native accounts and roles,
	// or an application's own tables (issue #553, internal/connectors/sqldb). The target's
	// Settings.SQL holds the connection; the credential is the database password.
	KindSQL = "sql"
	// KindLDAP and KindAD: accounts and group membership in an LDAP directory or Active Directory
	// (issue #586, internal/connectors/ldapwrite). Settings.LDAP holds the directory; the credential
	// is the bind password.
	KindLDAP = "ldap"
	KindAD   = "ad"
	// KindAWS: changes of an AWS account's IAM and IAM Identity Center that take access away or put it back, written
	// with a writer role and verified by re-reading with the reader role (issue #660, internal/connectors/awsorg
	// WriteTarget). Settings.AWS names the connector it writes through; the target holds no credential.
	KindAWS = "aws"
)

// ERPKinds are the ERP target kinds; the kind is the system's name in internal/connectors/erp.
var ERPKinds = []string{KindSAP, KindOracle}

// PAMKinds are the vault target kinds; the kind is the vendor's name in internal/connectors/pam.
var PAMKinds = []string{KindCyberArk, KindDelinea, KindBeyondTrust}

// WorkerActor is the system actor of worker events.
const WorkerActor = "provisioning.worker"

// Settings are the target settings kept as JSON.
type Settings struct {
	// Dialect is the SCIM dialect: "standard" or "entra".
	Dialect string `json:"dialect,omitempty"`
	// Preset is the SCIM vendor preset (provision/scim) whose PATCH quirks the client applies.
	Preset string `json:"preset,omitempty"`
	// Fault is the fake target's fault mode (dev only).
	Fault string `json:"fault,omitempty"`
	// OnDeprovision says what happens to a person's account here once the grace
	// period after their last affiliation ended has passed: "disable" (the
	// default: leave it disabled) or "delete" it in the target (issue #74).
	OnDeprovision string `json:"on_deprovision,omitempty"`
	// APIRoot overrides the API path of a vault or ERP target (default: the vendor's).
	APIRoot string `json:"api_root,omitempty"`
	// AgentID, when set, is the Directory Agent that reaches this target: the
	// target is in a private network the server cannot dial. The engine then
	// queues a provision_push job for that agent (internal/agent pull channel)
	// instead of calling the target itself, and the agent's report finishes
	// the operation (issue #302). SCIM and Okta targets only.
	AgentID string `json:"agent_id,omitempty"`
	// SQL is the database connection of a KindSQL target (no secret in it).
	SQL *sqldb.Config `json:"sql,omitempty"`
	// LDAP is the directory of a KindLDAP or KindAD target (no secret in it).
	LDAP *ldapwrite.Config `json:"ldap,omitempty"`
	// REST is the spec of a generic REST target (restgen.Spec as JSON). It holds no secret; the
	// credential is the sealed token. REST targets only.
	REST json.RawMessage `json:"rest,omitempty"`
	// AWS is the connector and writer role of an aws target.
	AWS *AWSSettings `json:"aws,omitempty"`
	// Discovery is the last read of the target's ServiceProviderConfig and
	// ResourceTypes (issue #542). It is informational and never gates provisioning.
	Discovery *DiscoveryRecord `json:"discovery,omitempty"`
}

// AWSSettings are the settings of an aws target.
type AWSSettings struct {
	// ConnectorID is the AWS connector (federated) whose accounts, regions and reader role the target uses.
	ConnectorID string `json:"connector_id"`
	// WriterRole is the name of the writer role in each account ("" for awsorg.DefaultWriterRoleName).
	WriterRole string `json:"writer_role,omitempty"`
}

// scimClient builds the SCIM client of a target: its dialect, the quirks of its
// vendor preset, and the capabilities its last discovery recorded.
func (s Settings) scimClient(hc *http.Client, baseURL, token string) *scim.Client {
	c := &scim.Client{HTTP: hc, BaseURL: baseURL, Token: token, Dialect: s.Dialect}
	if p, ok := scim.PresetByID(s.Preset); ok {
		c.Quirks = p.ClientQuirks()
	}
	if s.Discovery != nil {
		c.SetCapabilities(s.Discovery.Capabilities)
	}
	return c
}

// Engine sends queued operations to their targets and verifies them.
type Engine struct {
	DB     *store.DB
	Sealer *seal.Sealer
	// HTTP must be an internal/safehttp client.
	HTTP  *http.Client
	Clock func() time.Time
	Log   *slog.Logger

	// MaxAttempts is how many times an operation is sent before it fails (5).
	MaxAttempts int
	// MaxVerifies is how many re-reads may disagree before a mismatch (3):
	// a target can take a moment to show a change.
	MaxVerifies int
	// Backoff is the wait after attempt n (n >= 1). Default: 5s doubling to 10 minutes.
	Backoff func(n int) time.Duration
	// Batch is how many operations one pass takes (50).
	Batch int
	// CallTimeout bounds one connector call (30s).
	CallTimeout time.Duration
	// Runtime says whether the dev loopback exception applies to vault and ERP
	// targets (connsync.RuntimeFromConfig). The zero value is the production rules.
	Runtime connsync.Runtime
	// DialAllow is the dev-only private-directory allowlist (TESSERA_SAFEDIAL_ALLOW) of ldap and ad targets.
	DialAllow []safedial.AllowEntry
	// LDAPDialer replaces the safedial dialer of ldap and ad targets (tests).
	LDAPDialer func() (*safedial.Dialer, error)
	// Build creates the connector of a target (tests inject fakes).
	Build func(t *store.ProvTarget, token string) (target.Connector, error)
	// BuildAWS creates the connector of an aws target for a tenant: the AWS connector it writes through, the writer
	// role's name ("" for the default); the server's AWS client (safehttp, limits sized for IAM) is the hook's own
	// (awsorg.Federation.OpenWriteTarget). Nil: an aws target cannot be built.
	BuildAWS func(ctx context.Context, t tenancy.ID, connectorID, writerRole string) (target.Connector, error)
	// Guard, when set, runs every call to a target under that target's
	// limits and circuit breaker (internal/worker.Guard). A call it refuses
	// with a Deferred error is not an attempt: the operation waits and is
	// taken again later.
	Guard Guarder
}

// Guarder runs fn as one call to the target of connection connID, or refuses it.
type Guarder interface {
	Do(ctx context.Context, t tenancy.ID, connID string, fn func(context.Context) error) error
}

// Deferred is an error from a Guarder that says "not now": the call was not
// made, and may be tried again after DeferFor.
type Deferred interface {
	error
	DeferFor() time.Duration
}

// guarded makes one call to a connection's target: under the Guard if there
// is one, with the call timeout either way.
func (e *Engine) guarded(ctx context.Context, t tenancy.ID, connID string, fn func(context.Context) error) error {
	run := func(ctx context.Context) error {
		cctx, cancel := e.call(ctx)
		defer cancel()
		return fn(cctx)
	}
	if e.Guard == nil {
		return run(ctx)
	}
	return e.Guard.Do(ctx, t, connID, run)
}

// Stats counts what one pass did.
type Stats struct {
	Processed int `json:"processed"`
	Verified  int `json:"verified"`
	Mismatch  int `json:"mismatch"`
	Failed    int `json:"failed"`
	Retrying  int `json:"retrying"`
}

func (s *Stats) add(o Stats) {
	s.Processed += o.Processed
	s.Verified += o.Verified
	s.Mismatch += o.Mismatch
	s.Failed += o.Failed
	s.Retrying += o.Retrying
}

const (
	verifyLease = 2 * time.Minute  // a claimed re-read is not taken by another pass for this long
	staleSent   = 10 * time.Minute // a sent operation older than this was abandoned by a stopped worker
)

func (e *Engine) maxAttempts() int { return orInt(e.MaxAttempts, 5) }

// waitStep is the backoff step of an operation waiting for a person (about ten minutes by default).
const waitStep = 8

func (e *Engine) maxVerifies() int { return orInt(e.MaxVerifies, 3) }

func orInt(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

func (e *Engine) backoff(n int) time.Duration {
	if e.Backoff != nil {
		return e.Backoff(n)
	}
	d := 5 * time.Second
	for i := 1; i < n && d < 10*time.Minute; i++ {
		d *= 2
	}
	return min(d, 10*time.Minute)
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

// SealToken seals a target credential for storage.
func SealToken(s *seal.Sealer, t tenancy.ID, targetID, token string) ([]byte, error) {
	return s.Seal([]byte(token), seal.AAD(t, "provisioning_targets", "credential_enc", targetID))
}

// OpenCredential opens a target's stored credential under the KEK ("" when it
// has none). The caller decides where the token goes: into an outbound request
// of this process, or sealed to an agent (internal/seal SealToAgent).
func OpenCredential(s *seal.Sealer, t tenancy.ID, pt *store.ProvTarget) (string, error) {
	if len(pt.CredentialEnc) == 0 {
		return "", nil
	}
	b, err := s.Open(pt.CredentialEnc, seal.AAD(t, "provisioning_targets", "credential_enc", pt.ID))
	if err != nil {
		return "", errors.New("the stored credential cannot be opened with the current key")
	}
	return string(b), nil
}

func (e *Engine) openToken(t tenancy.ID, pt *store.ProvTarget) (string, error) {
	return OpenCredential(e.Sealer, t, pt)
}

func (e *Engine) build(pt *store.ProvTarget, token string) (target.Connector, error) {
	return e.buildWith(e.HTTP, pt, token)
}

// httpFor is the outbound client of a connection's target: the engine's own, or, when the tenant uploaded a
// mutual-TLS certificate for the connection (Admin > Certificates), a copy of it that presents that certificate
// chain and trusts only the uploaded trust anchors, if there are any (issue #498). The key is opened only here,
// for the pass that uses it.
func (e *Engine) httpFor(ctx context.Context, t tenancy.ID, connID string) (*http.Client, error) {
	if e.HTTP == nil || e.Build != nil {
		return e.HTTP, nil
	}
	var c *store.TenantCertificate
	var sealed []byte
	err := e.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		if c, err = tx.ActiveMTLSCertificate(connID); err != nil {
			return err
		}
		sealed, err = tx.CertificateKey(c.ID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return e.HTTP, nil
	}
	if err != nil {
		return nil, err
	}
	if e.Sealer == nil {
		return nil, target.Permanent("the mutual-TLS certificate of this connection cannot be opened: no key-encryption key is configured")
	}
	keyPEM, err := e.Sealer.Open(sealed, certs.KeyAAD(t, c.ID))
	if err != nil {
		return nil, target.Permanent("the mutual-TLS key of this connection cannot be opened")
	}
	pair, err := tls.X509KeyPair([]byte(c.CertPEM), keyPEM)
	if err != nil {
		return nil, target.Permanent("the mutual-TLS certificate of this connection is not usable: %v", err)
	}
	roots, err := certs.TrustPool(c.TrustPEM)
	if err != nil {
		return nil, target.Permanent("the trust anchors of this connection are not usable: %v", err)
	}
	hc, ok := safehttp.WithClientTLS(e.HTTP, []tls.Certificate{pair}, roots)
	if !ok {
		return nil, target.Permanent("a mutual-TLS certificate needs the guarded outbound client")
	}
	return hc, nil
}

func (e *Engine) buildWith(hc *http.Client, pt *store.ProvTarget, token string) (target.Connector, error) {
	if e.Build != nil {
		return e.Build(pt, token)
	}
	if hc == nil {
		return nil, errors.New("no outbound client is configured")
	}
	var s Settings
	if err := json.Unmarshal([]byte(pt.Settings), &s); err != nil {
		return nil, fmt.Errorf("target settings are unreadable: %w", err)
	}
	switch pt.Kind {
	case KindSCIM, KindFake:
		c := s.scimClient(hc, pt.BaseURL, token)
		if pt.Kind == KindFake && s.Fault != "" {
			c.Header = http.Header{"X-Fake-Fault": {s.Fault}}
		}
		return c, nil
	case KindOkta:
		return &okta.Client{HTTP: hc, BaseURL: pt.BaseURL, Token: token}, nil
	case KindREST:
		return buildREST(hc, pt, token, s, e.Runtime)
	case KindCyberArk, KindDelinea, KindBeyondTrust:
		return e.buildVault(hc, pt, token, s)
	case KindSAP, KindOracle:
		return e.buildERP(hc, pt, token, s)
	case KindSalesforce:
		cred, err := salesforce.ParseCredential(token)
		if err != nil {
			return nil, err
		}
		return salesforce.OpenTarget(pt.BaseURL, cred, e.Runtime, hc, e.Clock)
	case KindServiceNow:
		cred, err := servicenow.ParseCredential(token)
		if err != nil {
			return nil, err
		}
		return servicenow.OpenTarget(pt.BaseURL, cred, e.Runtime, hc, e.Clock)
	case KindAtlassian:
		cred, err := atlassian.ParseTargetCredential(token)
		if err != nil {
			return nil, err
		}
		return atlassian.OpenTarget(pt.BaseURL, cred, e.Runtime, hc, e.Clock)
	case KindSQL:
		return e.buildSQL(token, s)
	case KindLDAP, KindAD:
		return e.buildLDAP(pt, token, s)
	case KindAWS:
		return nil, errors.New("an aws target is built for a tenant: it has no dry run")
	}
	return nil, fmt.Errorf("unknown target kind %q", pt.Kind)
}

// buildREST builds the generic REST target. The credential is the secret the spec's auth type uses
// (or a JSON object of secrets); the spec's base URL is the target's base URL.
func buildREST(hc *http.Client, pt *store.ProvTarget, token string, s Settings, rt connsync.Runtime) (target.Connector, error) {
	spec, err := restgen.ParseSpec(s.REST)
	if err != nil {
		return nil, err
	}
	spec.BaseURL = pt.BaseURL
	sec, err := restgen.ParseSecrets(spec.Auth.Type, token)
	if err != nil {
		return nil, err
	}
	return restgen.NewTarget(spec, sec, rt, hc)
}

// buildVault builds the target of a vault. The credential is "user:secret"
// (BeyondTrust: "run-as user:API key").
func (e *Engine) buildVault(hc *http.Client, pt *store.ProvTarget, token string, s Settings) (target.Connector, error) {
	i := strings.IndexByte(token, ':')
	if i <= 0 || i == len(token)-1 {
		return nil, errors.New("the vault credential is user:secret")
	}
	v, err := pam.Open(pam.Config{Vendor: pt.Kind, BaseURL: pt.BaseURL, Username: token[:i], Secret: connsync.NewSecret(token[i+1:]),
		APIRoot: s.APIRoot}, e.Runtime, hc, e.Clock)
	if err != nil {
		return nil, err
	}
	return &pam.Target{V: v}, nil
}

// buildERP builds the target of an ERP. The credential is "client_id:client_secret".
func (e *Engine) buildERP(hc *http.Client, pt *store.ProvTarget, token string, s Settings) (target.Connector, error) {
	i := strings.IndexByte(token, ':')
	if i <= 0 || i == len(token)-1 {
		return nil, errors.New("the ERP credential is client_id:client_secret")
	}
	sys, err := erp.Open(erp.Config{System: pt.Kind, BaseURL: pt.BaseURL, ClientID: token[:i], ClientSecret: connsync.NewSecret(token[i+1:]),
		APIRoot: s.APIRoot}, e.Runtime, hc, e.Clock)
	if err != nil {
		return nil, err
	}
	return &erp.Target{S: sys}, nil
}

// buildSQL builds the target of a database. The credential is the database password; the
// connection dials through the safehttp address policy, not through the HTTP client.
func (e *Engine) buildSQL(token string, s Settings) (target.Connector, error) {
	if s.SQL == nil {
		return nil, errors.New("the database settings are missing")
	}
	// only a dev runtime is dev: any other environment name (the API's "test" included) gets the
	// production rules, and the dialer refuses an environment it does not know
	rt := connsync.Runtime{Env: config.Prod}
	if e.Runtime.Env == config.Dev {
		rt = e.Runtime
	}
	return sqldb.NewTarget(*s.SQL, connsync.NewSecret(token), rt)
}

// buildLDAP builds the target of a directory. The credential is the bind password; the connection
// is made by internal/safedial (the address policy, LDAPS or StartTLS), not by the HTTP client.
func (e *Engine) buildLDAP(pt *store.ProvTarget, token string, s Settings) (target.Connector, error) {
	if s.LDAP == nil {
		return nil, errors.New("the directory settings are missing")
	}
	cfg := *s.LDAP
	cfg.Flavor = pt.Kind
	if cfg.AllowTier0 && e.Runtime.Env != config.Dev {
		return nil, errors.New("allow_tier0 is refused outside a dev environment")
	}
	var roots *x509.CertPool
	if cfg.CACertPEM != "" {
		var err error
		if roots, err = ldapwrite.CAPool(cfg.CACertPEM); err != nil {
			return nil, errors.New("the directory's CA bundle is not usable")
		}
	}
	// only a dev runtime is dev: any other environment name gets the production rules
	env, allow := config.Prod, []safedial.AllowEntry(nil)
	if e.Runtime.Env == config.Dev {
		env, allow = config.Dev, e.DialAllow
	}
	dial := func() (*safedial.Dialer, error) {
		return safedial.New(safedial.Options{Env: env, Allow: allow, RootCAs: roots})
	}
	if e.LDAPDialer != nil {
		dial = e.LDAPDialer
	}
	d, err := dial()
	if err != nil {
		return nil, err
	}
	return ldapwrite.NewTarget(cfg, connsync.NewSecret(token), d)
}

// buildAWS builds the target of an AWS connector through the hook the server wires (internal/connectors/awsorg
// imports this package's dependents, so this package cannot import it).
func (e *Engine) buildAWS(ctx context.Context, t tenancy.ID, pt *store.ProvTarget) (target.Connector, error) {
	var s Settings
	if err := json.Unmarshal([]byte(pt.Settings), &s); err != nil {
		return nil, fmt.Errorf("target settings are unreadable: %w", err)
	}
	switch {
	case s.AWS == nil:
		return nil, errors.New("the AWS settings are missing")
	case e.BuildAWS == nil:
		return nil, errors.New("this server cannot write to AWS")
	}
	return e.BuildAWS(ctx, t, s.AWS.ConnectorID, s.AWS.WriterRole)
}

func (e *Engine) workerCtx(ctx context.Context) context.Context {
	return audit.AsSystem(ctx, WorkerActor)
}

// RunTenant takes the tenant's due operations and drives each as far as it
// goes: sent, then re-read at once. Operations whose target is slow stay
// pending_verification or queued with a next attempt time, to be taken by a
// later pass.
func (e *Engine) RunTenant(ctx context.Context, t tenancy.ID) (Stats, error) {
	ctx = e.workerCtx(ctx)
	now := e.now()
	var due []*store.ProvOp
	err := e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		if _, err := tx.RequeueStaleProvOps(now.Add(-staleSent), now); err != nil {
			return err
		}
		ops, err := tx.DueProvOps(now, orInt(e.Batch, 50))
		if err != nil {
			return err
		}
		for _, op := range ops { // claim: no other pass takes them
			st := store.ProvOpState{Status: op.Status, Attempts: op.Attempts, VerifyAttempts: op.VerifyAttempts,
				NextAttemptAt: now.Add(verifyLease), LastError: op.LastError, Observed: op.Observed}
			if op.Status == Queued {
				st.Status, st.Attempts, st.NextAttemptAt = Sent, op.Attempts+1, now
			} else {
				st.VerifyAttempts++
			}
			if err := tx.SetProvOpState(op.ID, op.Status, st, now); err != nil {
				return err
			}
			op.Status, op.Attempts, op.VerifyAttempts = st.Status, st.Attempts, st.VerifyAttempts
			due = append(due, op)
		}
		return nil
	})
	var stats Stats
	if err != nil {
		return stats, err
	}
	conns, agents := map[string]target.Connector{}, map[string]string{}
	var firstErr error
	for _, op := range due {
		if ctx.Err() != nil {
			break
		}
		s, err := e.process(ctx, t, op, conns, agents)
		stats.add(s)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return stats, firstErr
}

// connector loads the target of a connection and builds its connector.
func (e *Engine) connector(ctx context.Context, t tenancy.ID, connID string, cache map[string]target.Connector) (target.Connector, error) {
	if c, ok := cache[connID]; ok {
		return c, nil
	}
	var pt *store.ProvTarget
	err := e.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		pt, err = tx.ProvTarget(connID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, target.Permanent("the connection no longer has a provisioning target")
	}
	if err != nil {
		return nil, err
	}
	token, err := e.openToken(t, pt)
	if err != nil {
		return nil, target.Permanent("%v", err)
	}
	hc, err := e.httpFor(ctx, t, connID)
	if err != nil {
		return nil, err
	}
	var c target.Connector
	if pt.Kind == KindAWS && e.Build == nil {
		c, err = e.buildAWS(ctx, t, pt)
	} else {
		c, err = e.buildWith(hc, pt, token)
	}
	if err != nil {
		return nil, target.Permanent("%v", err)
	}
	cache[connID] = c
	return c, nil
}

func (e *Engine) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, orDur(e.CallTimeout, 30*time.Second))
}

func orDur(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}

func errText(err error) string { return jobs.ErrorSummary(err) }

func sp(s string) *string { return &s }

// process drives one claimed operation.
func (e *Engine) process(ctx context.Context, t tenancy.ID, op *store.ProvOp, conns map[string]target.Connector, agents map[string]string) (Stats, error) {
	st := Stats{Processed: 1}
	req, err := Request(op)
	if err != nil {
		return st, e.fail(ctx, t, op, err, &st)
	}
	if op.Status == Sent {
		if held, err := e.cancelIfWriteBackOff(ctx, t, op); held || err != nil {
			return st, err
		}
		agentID, err := e.agentOf(ctx, t, op.ConnectionID, agents)
		if err != nil {
			if target.Retryable(err) {
				return st, e.retryLater(ctx, t, op, err, &st)
			}
			return st, e.fail(ctx, t, op, err, &st)
		}
		if agentID != "" {
			return st, e.dispatch(ctx, t, op, agentID, &st)
		}
	}
	conn, err := e.connector(ctx, t, op.ConnectionID, conns)
	if err != nil {
		if target.Retryable(err) {
			return st, e.retryLater(ctx, t, op, err, &st)
		}
		return st, e.fail(ctx, t, op, err, &st)
	}
	if op.Status == Sent {
		err := e.guarded(ctx, t, op.ConnectionID, func(cctx context.Context) error { return conn.Apply(cctx, req) })
		var def Deferred
		if errors.As(err, &def) {
			return st, e.deferOp(ctx, t, op, def, &st)
		}
		if err != nil {
			if target.Retryable(err) && op.Attempts < e.maxAttempts() {
				return st, e.retryLater(ctx, t, op, err, &st)
			}
			return st, e.fail(ctx, t, op, err, &st)
		}
		// The target accepted the change; it is not done until a re-read shows it.
		now := e.now()
		op.VerifyAttempts++
		if err := e.set(ctx, t, op, Sent, store.ProvOpState{Status: PendingVerification, Attempts: op.Attempts,
			VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now}, "provision.sent", nil); err != nil {
			return st, err
		}
		op.Status = PendingVerification
	}
	return st, e.verify(ctx, t, op, conn, req, &st)
}

// cancelIfWriteBackOff stops a claimed operation from being sent when its
// target's write-back is off now, whatever it was when the operation was queued
// (issue #706: disabling is immediate). The target is re-read and the operation
// cancelled in one transaction, with an audit event. Restores of a verified AWS
// change are still sent: they only put back what that change took.
func (e *Engine) cancelIfWriteBackOff(ctx context.Context, t tenancy.ID, op *store.ProvOp) (bool, error) {
	if isAWSRestore(op.Kind) {
		return false, nil
	}
	cancelled := false
	err := e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		pt, err := tx.ProvTarget(op.ConnectionID)
		if errors.Is(err, store.ErrNotFound) {
			return nil // connector() reports a missing target
		}
		if err != nil || pt.WriteBack {
			return err
		}
		now := e.now()
		to := store.ProvOpState{Status: Cancelled, Attempts: max(0, op.Attempts-1), VerifyAttempts: op.VerifyAttempts,
			NextAttemptAt: now, LastError: sp("write_back_disabled: write-back was turned off on the target before this change was sent"),
			CompletedAt: &now}
		if err := tx.SetProvOpState(op.ID, Sent, to, now); err != nil {
			return err
		}
		if _, err := tx.CancelAgentJobsForOp(op.ID, "write-back was turned off", now); err != nil {
			return err
		}
		cancelled = true
		return tx.Audit(now, WorkerActor, "provision.cancelled_write_back_off", ojson.Object{{Key: "op_id", Value: op.ID},
			{Key: "kind", Value: op.Kind}, {Key: "target", Value: op.TargetRef}, {Key: "reason", Value: "write_back_disabled"}})
	})
	if err != nil {
		cancelled = false
	}
	return cancelled, err
}

// isAWSRestore reports whether kind is one of the AWS kinds that undo a revoke.
func isAWSRestore(kind string) bool {
	for _, k := range target.AWSKinds {
		if target.AWSRestoreKind(k) == kind {
			return true
		}
	}
	return false
}

// set moves an operation between statuses in one transaction, with its audit event.
func (e *Engine) set(ctx context.Context, t tenancy.ID, op *store.ProvOp, from string, to store.ProvOpState, action string,
	extra func(tx *store.TenantTx, now time.Time) (ojson.Object, error)) error {
	return e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		now := e.now()
		if err := tx.SetProvOpState(op.ID, from, to, now); err != nil {
			return err
		}
		detail := ojson.Object{{Key: "op_id", Value: op.ID}, {Key: "kind", Value: op.Kind},
			{Key: "target", Value: op.TargetRef}, {Key: "status", Value: to.Status}, {Key: "attempts", Value: to.Attempts}}
		if to.LastError != nil && to.Status == Failed {
			detail = append(detail, ojson.KV{Key: "error", Value: *to.LastError})
		}
		if extra != nil {
			more, err := extra(tx, now)
			if err != nil {
				return err
			}
			detail = append(detail, more...)
		}
		if action == "" {
			return nil
		}
		return tx.Audit(now, WorkerActor, action, detail)
	})
}

// deferOp puts back an operation whose call the target's guard refused (the
// breaker is open, or the rate limit is spent). Nothing was sent, so the
// attempt this pass counted is given back: a target that is down for an hour
// does not fail every operation queued for it.
func (e *Engine) deferOp(ctx context.Context, t tenancy.ID, op *store.ProvOp, d Deferred, st *Stats) error {
	now := e.now()
	st.Retrying++
	next := now.Add(max(d.DeferFor(), time.Second))
	msg := sp("waiting: " + errText(d))
	if op.Status == Sent {
		return e.set(ctx, t, op, Sent, store.ProvOpState{Status: Queued, Attempts: max(0, op.Attempts-1),
			VerifyAttempts: op.VerifyAttempts, NextAttemptAt: next, LastError: msg}, "", nil)
	}
	return e.set(ctx, t, op, op.Status, store.ProvOpState{Status: op.Status, Attempts: op.Attempts,
		VerifyAttempts: max(0, op.VerifyAttempts-1), NextAttemptAt: next, LastError: msg, Observed: op.Observed}, "", nil)
}

// retryLater re-queues an operation whose send failed in a way a later
// attempt may fix.
func (e *Engine) retryLater(ctx context.Context, t tenancy.ID, op *store.ProvOp, cause error, st *Stats) error {
	now := e.now()
	if op.Attempts >= e.maxAttempts() {
		return e.fail(ctx, t, op, cause, st)
	}
	st.Retrying++
	return e.set(ctx, t, op, op.Status, store.ProvOpState{Status: Queued, Attempts: op.Attempts, VerifyAttempts: op.VerifyAttempts,
		NextAttemptAt: now.Add(e.backoff(op.Attempts)), LastError: sp(errText(cause))}, "", nil)
}

// fail ends an operation: its completion never runs, so the item it was for stays open.
func (e *Engine) fail(ctx context.Context, t tenancy.ID, op *store.ProvOp, cause error, st *Stats) error {
	now := e.now()
	st.Failed++
	return e.set(ctx, t, op, op.Status, store.ProvOpState{Status: Failed, Attempts: op.Attempts, VerifyAttempts: op.VerifyAttempts,
		NextAttemptAt: now, LastError: sp(errText(cause)), CompletedAt: &now}, "provision.failed", nil)
}

// verify re-reads the target and settles the operation.
func (e *Engine) verify(ctx context.Context, t tenancy.ID, op *store.ProvOp, conn target.Connector, req target.Request, st *Stats) error {
	var v target.Verdict
	err := e.guarded(ctx, t, op.ConnectionID, func(cctx context.Context) (err error) {
		v, err = conn.Verify(cctx, req)
		return err
	})
	var def Deferred
	if errors.As(err, &def) {
		return e.deferOp(ctx, t, op, def, st)
	}
	now := e.now()
	switch {
	case err != nil:
		// The read itself failed: try again later, and give up after the same
		// number of tries a disagreeing read gets.
		if !target.Retryable(err) || op.VerifyAttempts >= e.maxVerifies() {
			return e.fail(ctx, t, op, fmt.Errorf("could not re-read the target to verify: %w", err), st)
		}
		st.Retrying++
		return e.set(ctx, t, op, PendingVerification, store.ProvOpState{Status: PendingVerification, Attempts: op.Attempts,
			VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now.Add(e.backoff(op.VerifyAttempts)),
			LastError: sp("re-read failed: " + errText(err))}, "", nil)
	case !v.OK && v.Waiting:
		// a person has to act: stay pending, re-read later, and do not spend a verification attempt
		st.Retrying++
		return e.set(ctx, t, op, PendingVerification, store.ProvOpState{Status: PendingVerification, Attempts: op.Attempts,
			VerifyAttempts: max(0, op.VerifyAttempts-1), NextAttemptAt: now.Add(e.backoff(waitStep)),
			LastError: sp("waiting: " + v.Observed), Observed: sp(v.Observed)}, "", nil)
	case !v.OK && op.VerifyAttempts < e.maxVerifies():
		st.Retrying++
		return e.set(ctx, t, op, PendingVerification, store.ProvOpState{Status: PendingVerification, Attempts: op.Attempts,
			VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now.Add(e.backoff(op.VerifyAttempts)),
			LastError: sp("not yet visible in the target: expected " + v.Expected + ", observed " + v.Observed),
			Observed:  sp(v.Observed)}, "", nil)
	case !v.OK:
		st.Mismatch++
		return e.mismatch(ctx, t, op, v)
	}
	// Verified: the completion and the status change commit together.
	err = e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		return FinishVerified(tx, e.now(), op, v.Observed, "")
	})
	if err == nil {
		st.Verified++
		return nil
	}
	// The completion could not be applied (the graph changed under it): the
	// target is right but Tessera is not; retry the re-read, then fail loudly.
	cause := err
	if ce := (*CompletionError)(nil); !errors.As(err, &ce) {
		cause = fmt.Errorf("verified in the target but Tessera could not apply the change: %w", err)
	}
	if op.VerifyAttempts >= e.maxVerifies() {
		return e.fail(ctx, t, op, cause, st)
	}
	st.Retrying++
	return e.set(ctx, t, op, PendingVerification, store.ProvOpState{Status: PendingVerification, Attempts: op.Attempts,
		VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now.Add(e.backoff(op.VerifyAttempts)), LastError: sp(errText(cause))}, "", nil)
}

func runCompletion(tx *store.TenantTx, now time.Time, raw string) error {
	var env completionEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return fmt.Errorf("unreadable completion: %w", err)
	}
	fn, ok := completionFor(env.Name)
	if !ok {
		return fmt.Errorf("no completion %q is registered", env.Name)
	}
	return fn(tx, now, env.Data)
}

// mismatch ends an operation whose re-read never showed the change, and
// raises a finding.
func (e *Engine) mismatch(ctx context.Context, t tenancy.ID, op *store.ProvOp, v target.Verdict) error {
	return e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error { return FinishMismatch(tx, e.now(), op, v, "") })
}

// RunAll runs one pass for every active tenant. A tenant whose pass failed is
// logged and does not stop the others.
func (e *Engine) RunAll(ctx context.Context) {
	tenants, err := e.DB.ActiveTenants(ctx)
	if err != nil {
		if ctx.Err() == nil {
			e.log().Error("provisioning: tenants", "err", err)
		}
		return
	}
	for _, tn := range tenants {
		if ctx.Err() != nil {
			return
		}
		started := e.now()
		stats, err := e.RunTenant(ctx, tn.ID)
		if stats.Processed == 0 && err == nil {
			continue
		}
		if err != nil {
			e.log().Error("provisioning pass failed", "tenant", tn.Slug, "err", err)
		}
		// A failed operation is the operation's own outcome (shown in the
		// provisioning view and audited); the run fails only when the pass broke.
		rec := jobs.Start{Kind: jobs.Provision, Trigger: "schedule", Actor: WorkerActor}
		if rerr := jobs.Record(ctx, e.DB, tn.ID, rec, started, e.now(), stats, err); rerr != nil {
			e.log().Error("provisioning: record run", "tenant", tn.Slug, "err", rerr)
		}
	}
}

// Loop runs RunAll every interval until ctx is done.
func (e *Engine) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		e.RunAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (e *Engine) now() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}
