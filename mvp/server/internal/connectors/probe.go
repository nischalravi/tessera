package connectors

import (
	"context"
	"errors"
	"time"
)

// Prober is the read-only surface readiness checks use against a system
// (design §5.1). Each method is a fixed, read-only operation; there is no
// generic "execute" method and no write method. Real implementations arrive
// per directory (DR-12 to DR-18) behind the Directory Agent or safehttp; the
// demo connectors implement it with scenarios (ScenarioProber).
type Prober interface {
	// Connect opens TCP and TLS and reports the handshake.
	Connect(ctx context.Context) (ConnInfo, error)
	// Authenticate binds or acquires a token and reports what was granted.
	Authenticate(ctx context.Context) (AuthInfo, error)
	// RootInfo reads rootDSE, ServiceProviderConfig or org information.
	RootInfo(ctx context.Context) (RootInfo, error)
	// ObjectExists runs a base-scope read of one object (a DN, a path).
	ObjectExists(ctx context.Context, ref string) (bool, error)
	// Sample reads at most 500 objects and returns counts, never values.
	Sample(ctx context.Context, q SampleQuery) (SampleStats, error)
	// EffectiveRights reads the bound identity's effective rights.
	EffectiveRights(ctx context.Context, ref string) (Rights, error)
	// ChangeFeed reads the incremental-change capability and current cursor.
	ChangeFeed(ctx context.Context) (FeedInfo, error)
	// RateLimits reports the rate-limit headers seen during the run.
	RateLimits(ctx context.Context) (RateInfo, error)
	// Time returns the server clock, where the system exposes one.
	Time(ctx context.Context) (time.Time, error)
}

// ProberOps names every Prober operation (what a recorder may observe).
var ProberOps = []string{"connect", "authenticate", "root_info", "object_exists", "sample", "effective_rights",
	"change_feed", "rate_limits", "time"}

// ErrRateLimited is returned by a prober that saw HTTP 429; the run aborts.
var ErrRateLimited = errors.New("connectors: rate limited")

// ConnInfo is the transport handshake.
type ConnInfo struct {
	Reachable     bool
	TLSVersion    string // "1.2", "1.3"
	ChainValid    bool
	HostnameMatch bool
	NotAfter      time.Time
	Issuer        string
}

// AuthInfo is what authentication granted. It never carries the credential.
type AuthInfo struct {
	OK            bool
	Identity      string     // bound DN, application id or subject
	Mode          string     // simple_bind, sasl, certificate, federation, oauth_private_key_jwt, client_secret, json_key, api_token, bearer_token
	Scopes        []string   // granted scopes (Okta, Google domain-wide delegation)
	Roles         []string   // application roles claim (Entra)
	RefusedScopes []string   // forbidden scopes requested on purpose and refused (Google)
	ExpiresAt     *time.Time // credential or certificate expiry, when reported
	RootIdentity  bool       // LDAP: bound as the root DN
}

// RootInfo is directory or service metadata.
type RootInfo struct {
	Servers           int
	Domains           []string // domains or naming contexts that hold users
	ConfiguredDomains []string // the ones the connection covers
	UnconnectedTrusts []string
	Trusts            []string
	RecycleBin        bool
	Capabilities      []string
	CustomAttributes  int
	OrgUnits          int
	Missing           []string // SCIM: discovery documents that could not be read
}

// SampleQuery is one bounded read. Op selects what is sampled.
type SampleQuery struct {
	Op      string // search, classes, attr, page, range, roles, rules, signin, deprovisioned, members, fields
	Filter  string
	Classes []string
	Attrs   []string
	Limit   int // capped at 500
}

// MaxSample is the most objects a sample may read (§5.2).
const MaxSample = 500

// SampleStats are counts from a sample: no attribute values, no personal data.
type SampleStats struct {
	Objects      int
	PerClass     map[string]int
	AttrFill     map[string]int // objects that carry each attribute
	Missing      []string       // requested attributes never returned
	PagedBeyond  bool           // a page past the server limit was read
	SizeLimitHit bool           // the server returned sizeLimitExceeded
	LargestGroup string
	RangedCount  int
	FullCount    int
	Fields       []string // field names returned (Workday field inventory)
	Available    bool     // the read returned data (roles, rules, sign-in activity...)
	// SCIM paging and members reads: what was inconsistent ("code: detail";
	// empty means consistent), pages read, the server's totalResults and the
	// reverse lookup of group membership through users' groups.
	Findings       []string
	Pages          int
	TotalResults   int
	ReverseChecked bool
	ReverseCount   int
}

// Rights are the bound identity's effective rights, read rather than tried.
type Rights struct {
	Writable       []string // objects or attributes the identity could write
	PrivilegedSIDs []string // privileged groups in tokenGroups
	AdminCount     bool
	Replication    bool     // DS-Replication-Get-Changes-All
	AdminRoles     []string // admin roles of the app or impersonated subject
}

// FeedInfo is the incremental-change capability.
type FeedInfo struct {
	Supported      bool
	Mechanism      string
	DirSyncAllowed bool
}

// RateInfo is the rate-limit headroom observed.
type RateInfo struct {
	Limit, Remaining, Throttled int
	// Retries made after HTTP 429 and the longest Retry-After (seconds) seen.
	Retries, RetryAfterSeconds int
}

// Simulator is implemented by simulated probers: a scenario may override a
// check's result. Results from a simulator are always labelled simulated.
type Simulator interface {
	Override(checkID string) (SimResult, bool)
}

// SimResult is a scenario's result for one check.
type SimResult struct {
	Status   string         `yaml:"status"`
	Message  string         `yaml:"message"`
	Observed map[string]any `yaml:"observed,omitempty"`
	Fixable  bool           `yaml:"fixable,omitempty"`
}
