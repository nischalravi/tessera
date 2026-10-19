// Package health answers the orchestrator probes (/livez, /readyz) and builds
// the operator summary behind Admin -> Platform health (issue #303).
//
// Both read the same signals as /metrics. Neither reads tenant data, and
// neither returns error text, hostnames, paths or key material: a failing
// check is the word "fail", the reason is in the server log.
package health

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Check names, in the fixed order /readyz reports them.
const (
	CheckDatabase   = "database"
	CheckAuditChain = "audit_chain"
	CheckKEK        = "kek"
	CheckLoops      = "loops"
)

var checkNames = []string{CheckDatabase, CheckAuditChain, CheckKEK, CheckLoops}

// DefaultMaxLoopLag is how long a gated loop may go without a success before
// /readyz fails (TESSERA_READY_MAX_LOOP_LAG_SECONDS). The loops run every 15
// to 30 seconds.
const DefaultMaxLoopLag = 5 * time.Minute

const (
	checkTimeout = 2 * time.Second
	cacheTTL     = 2 * time.Second // /readyz is unauthenticated: bound the work a caller can cause
)

// Checker evaluates readiness. Create it with New; tests replace the check
// funcs to fail one dependency at a time.
type Checker struct {
	DB         *store.DB
	Sealer     *seal.Sealer
	Loops      *obs.Loops
	MaxLoopLag time.Duration
	Log        *slog.Logger

	// Database, AuditChain and KEK probe one dependency each; nil means the
	// default probe over DB and Sealer.
	Database, AuditChain, KEK func(ctx context.Context) error

	now func() time.Time
	mu  sync.Mutex
	at  time.Time
	res Result
}

// New returns a Checker over the store, the sealer and the loop tracker.
func New(db *store.DB, sealer *seal.Sealer, loops *obs.Loops, maxLag time.Duration, log *slog.Logger) *Checker {
	if loops == nil {
		loops = obs.DefaultLoops
	}
	if maxLag <= 0 {
		maxLag = DefaultMaxLoopLag
	}
	if log == nil {
		log = slog.Default()
	}
	return &Checker{DB: db, Sealer: sealer, Loops: loops, MaxLoopLag: maxLag, Log: log, now: time.Now}
}

// Result is one readiness evaluation. Its JSON shape is constant: the same
// four keys under "checks", each "ok" or "fail".
type Result struct {
	Status string            `json:"status"` // "ok" or "unavailable"
	Checks map[string]string `json:"checks"`
}

// Ready reports whether every check passed.
func (r Result) Ready() bool { return r.Status == "ok" }

// OK reports whether the named check passed.
func (r Result) OK(name string) bool { return r.Checks[name] == "ok" }

// Live is the liveness answer: the process is up and serving. It checks
// nothing else, so a database outage never restarts the pod.
func Live() map[string]string { return map[string]string{"status": "ok"} }

// Ready runs the checks (a result is reused for two seconds) and refreshes
// the tessera_readiness_check_ok gauges.
func (c *Checker) Ready(ctx context.Context) Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && c.now().Sub(c.at) < cacheTTL {
		return c.res
	}
	res := Result{Status: "ok", Checks: map[string]string{}}
	run := func(name string, fn func(context.Context) error) {
		cctx, cancel := context.WithTimeout(ctx, checkTimeout)
		defer cancel()
		err := safely(cctx, fn)
		if err != nil {
			res.Status = "unavailable"
			res.Checks[name] = "fail"
			obs.ReadyCheck.Set(0, name)
			c.Log.Warn("readiness check failed", "check", name, "err", err)
			return
		}
		res.Checks[name] = "ok"
		obs.ReadyCheck.Set(1, name)
	}
	run(CheckDatabase, c.probe(c.Database, c.pingDB))
	run(CheckAuditChain, c.probe(c.AuditChain, c.readChainHead))
	run(CheckKEK, c.probe(c.KEK, c.openKEK))
	run(CheckLoops, c.loopsFresh)
	c.at, c.res = c.now(), res
	return res
}

func (c *Checker) probe(override, def func(context.Context) error) func(context.Context) error {
	if override != nil {
		return override
	}
	return def
}

// safely turns a panic in a probe into a failure: readiness fails closed.
func safely(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = errors.New("check panicked")
		}
	}()
	return fn(ctx)
}

func (c *Checker) pingDB(ctx context.Context) error {
	if c.DB == nil {
		return errors.New("no database")
	}
	return c.DB.ReadSystem(ctx, "readiness probe", func(s *store.SystemTx) error {
		_, err := s.ActiveTenants()
		return err
	})
}

// readChainHead reads the _platform chain head: the ledger's own table is
// reachable and its head row decodes.
func (c *Checker) readChainHead(ctx context.Context) error {
	if c.DB == nil {
		return errors.New("no database")
	}
	return c.DB.ReadTenant(ctx, tenancy.Platform, func(tx *store.TenantTx) error {
		_, err := tx.AuditHead()
		return err
	})
}

var kekProbeAAD = []byte("tessera/readiness/kek-probe")

// openKEK seals and opens a probe value: the KEK is loaded and usable.
func (c *Checker) openKEK(context.Context) error {
	if c.Sealer == nil {
		return errors.New("no KEK loaded")
	}
	sealed, err := c.Sealer.Seal([]byte("probe"), kekProbeAAD)
	if err != nil {
		return err
	}
	pt, err := c.Sealer.Open(sealed, kekProbeAAD)
	if err != nil || string(pt) != "probe" {
		return errors.New("KEK round trip failed")
	}
	return nil
}

func (c *Checker) loopsFresh(context.Context) error {
	if lag := c.Loops.Lagging(c.MaxLoopLag); len(lag) > 0 {
		return errors.New("loops lagging: " + join(lag))
	}
	return nil
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
