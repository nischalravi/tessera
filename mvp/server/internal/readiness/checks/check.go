// Package checks is the registry of readiness checks (design §5.1, §5.4).
//
// A live check is a Go function that may call exactly one read-only Prober
// operation, the one the template catalogue declares for it; the runner
// hands it a guard that refuses every other operation. A data check reads
// the staged snapshot of a dry run (§6). No check writes anything, and no
// result carries a secret or a raw attribute value.
package checks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
)

// Result statuses.
const (
	Pass    = "pass"
	Fail    = "fail"
	Warn    = "warn"
	Error   = "error"
	Skipped = "skipped"
	Blocked = "blocked"
)

// Result is one check outcome. Observed holds counts, versions and dates.
type Result struct {
	Status   string
	Observed map[string]any
	Message  string
}

// Params are an item's verify params from the template.
type Params map[string]any

// Float returns a numeric param.
func (p Params) Float(k string, def float64) float64 {
	switch v := p[k].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return def
}

// Int returns an integer param.
func (p Params) Int(k string, def int) int { return int(math.Round(p.Float(k, float64(def)))) }

// String returns a string param.
func (p Params) String(k, def string) string {
	if v, ok := p[k].(string); ok {
		return v
	}
	return def
}

// Strings returns a list param.
func (p Params) Strings(k string) []string {
	var out []string
	switch v := p[k].(type) {
	case []any:
		for _, x := range v {
			out = append(out, fmt.Sprint(x))
		}
	case []string:
		out = v
	}
	return out
}

// Env is what a check may see.
type Env struct {
	Probe         connectors.Prober
	Now           time.Time
	TemplateID    string
	SecretRef     string
	BaseDNs       []string
	Filters       map[string]string // filter name → LDAP filter (empty ones omitted)
	ConfigStrings map[string]string // config field → its text, for secret-shape scanning only
	RequiredAttrs []string          // the template's required user attributes
	WriteScope    []string
	Snapshot      *reconcile.Snapshot // data checks only
}

// Check is a registered check.
type Check struct {
	ID   string
	Kind template.VerifyKind
	Op   string // the single Prober operation a live check may call
	Run  func(ctx context.Context, env Env, p Params) Result
}

var registry = map[string]*Check{}

func register(c *Check) {
	spec, ok := template.Checks[c.ID]
	if !ok {
		panic("checks: " + c.ID + " is not in the template catalogue")
	}
	if spec.Kind != c.Kind || (c.Kind == template.Live && spec.Op != c.Op) {
		panic("checks: " + c.ID + " does not match its catalogue entry")
	}
	if _, dup := registry[c.ID]; dup {
		panic("checks: duplicate " + c.ID)
	}
	registry[c.ID] = c
}

// Get returns a registered check.
func Get(id string) (*Check, bool) {
	c, ok := registry[id]
	return c, ok
}

// IDs lists every registered check id.
func IDs() []string {
	out := make([]string, 0, len(registry))
	for id := range registry {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ErrOpNotAllowed is returned when a check calls a Prober operation other
// than the one it declared.
var ErrOpNotAllowed = errors.New("checks: prober operation not allowed for this check")

// Run executes a check with its operation guard and a panic barrier.
func Run(ctx context.Context, c *Check, env Env, p Params) (r Result) {
	defer func() {
		if x := recover(); x != nil {
			r = Result{Status: Error, Message: "the check failed unexpectedly", Observed: map[string]any{}}
		}
		if r.Observed == nil {
			r.Observed = map[string]any{}
		}
	}()
	if c.Kind == template.Live {
		env.Probe = &guard{p: env.Probe, op: c.Op}
	}
	return c.Run(ctx, env, p)
}

// guard forwards only the declared operation.
type guard struct {
	p  connectors.Prober
	op string
}

func (g *guard) allow(op string) error {
	if g.op != op || g.p == nil {
		return fmt.Errorf("%w: %s", ErrOpNotAllowed, op)
	}
	return nil
}

func (g *guard) Connect(ctx context.Context) (connectors.ConnInfo, error) {
	if err := g.allow(template.OpConnect); err != nil {
		return connectors.ConnInfo{}, err
	}
	return g.p.Connect(ctx)
}

func (g *guard) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	if err := g.allow(template.OpAuthenticate); err != nil {
		return connectors.AuthInfo{}, err
	}
	return g.p.Authenticate(ctx)
}

func (g *guard) RootInfo(ctx context.Context) (connectors.RootInfo, error) {
	if err := g.allow(template.OpRootInfo); err != nil {
		return connectors.RootInfo{}, err
	}
	return g.p.RootInfo(ctx)
}

func (g *guard) ObjectExists(ctx context.Context, ref string) (bool, error) {
	if err := g.allow(template.OpObjectExists); err != nil {
		return false, err
	}
	return g.p.ObjectExists(ctx, ref)
}

func (g *guard) Sample(ctx context.Context, q connectors.SampleQuery) (connectors.SampleStats, error) {
	if err := g.allow(template.OpSample); err != nil {
		return connectors.SampleStats{}, err
	}
	if q.Limit <= 0 || q.Limit > connectors.MaxSample {
		q.Limit = connectors.MaxSample
	}
	return g.p.Sample(ctx, q)
}

func (g *guard) EffectiveRights(ctx context.Context, ref string) (connectors.Rights, error) {
	if err := g.allow(template.OpEffectiveRight); err != nil {
		return connectors.Rights{}, err
	}
	return g.p.EffectiveRights(ctx, ref)
}

func (g *guard) ChangeFeed(ctx context.Context) (connectors.FeedInfo, error) {
	if err := g.allow(template.OpChangeFeed); err != nil {
		return connectors.FeedInfo{}, err
	}
	return g.p.ChangeFeed(ctx)
}

func (g *guard) RateLimits(ctx context.Context) (connectors.RateInfo, error) {
	if err := g.allow(template.OpRateLimits); err != nil {
		return connectors.RateInfo{}, err
	}
	return g.p.RateLimits(ctx)
}

func (g *guard) Time(ctx context.Context) (time.Time, error) {
	if err := g.allow(template.OpTime); err != nil {
		return time.Time{}, err
	}
	return g.p.Time(ctx)
}

// probeErr turns a prober error into a result.
func probeErr(err error) Result {
	switch {
	case errors.Is(err, connectors.ErrRateLimited):
		return Result{Status: Error, Message: "the system rate-limited the check (HTTP 429)", Observed: map[string]any{"rate_limited": true}}
	case errors.Is(err, context.DeadlineExceeded):
		return Result{Status: Error, Message: "the check timed out"}
	case errors.Is(err, connectors.ErrUnsupported):
		return unsupported("this system does not expose it")
	case errors.Is(err, connectors.ErrTargetNotAllowed):
		return Result{Status: Error, Message: "the target is not reachable from this deployment: private directories need the Directory Agent"}
	case errors.Is(err, ErrOpNotAllowed):
		return Result{Status: Error, Message: "the check called a prober operation it did not declare"}
	}
	return Result{Status: Error, Message: "the system did not answer the read-only probe"}
}

// unsupported is the result of a check the system cannot answer: skipped, so
// it never counts as a pass, and the message says what to do.
func unsupported(why string) Result {
	return Result{Status: Skipped, Message: "Not verifiable live: " + why + ". An attestation is required.",
		Observed: map[string]any{"unsupported": true}}
}

func pass(msg string, obs map[string]any) Result {
	return Result{Status: Pass, Message: msg, Observed: obs}
}
func fail(msg string, obs map[string]any) Result {
	return Result{Status: Fail, Message: msg, Observed: obs}
}

func pct(n, d int) string {
	if d == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d%%", 100*n/d) // floor: a fill rate is "at least"
}

func subset(xs, allowed []string) (extra []string) {
	for _, x := range xs {
		if !slices.Contains(allowed, x) {
			extra = append(extra, x)
		}
	}
	return extra
}
