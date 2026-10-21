package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// exitError makes main exit with code (the audit verify exit codes).
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

const auditUsage = `usage:
  tessera audit verify     (-tenant slug | -all) [-from-seq N] [-to-seq M] [-anchors file:///path] [-strict] [-json] [-db path]
  tessera audit checkpoint (-tenant slug | -all) [-db path]
  tessera audit export     -tenant slug [-from-seq N] [-to-seq M] [-db path]

verify exit codes: 0 ok, 2 hash mismatch (edited row), 3 seq gap or duplicate
(deleted row) or truncation (the chain ends before its head or its newest
signed checkpoint), 4 checkpoint signature invalid, 5 anchor missing or
mismatched, 6 stale anchoring (only with -strict; otherwise a warning).

Events moved to the archive (issue #298) are checked too when the archive is
configured (TESSERA_ENV, TESSERA_ARCHIVE_DIR or TESSERA_ARCHIVE_URL, and the KEK, as
for the server); otherwise verify warns that the archived range was not checked.

Without -anchors, a database owner who deletes the newest events, their
checkpoint rows and rewinds the head is not detected; with -anchors only the
events after the newest anchored checkpoint (at most one checkpoint interval:
5 min or 1000 events) can be removed unseen.`

// auditCmd runs `tessera audit verify|checkpoint|export` (design §13.7).
func auditCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(stderr, auditUsage)
		return errors.New("audit: missing subcommand")
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("tessera audit "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", dbPath(os.Getenv("TESSERA_DB")), "SQLite database path or postgres:// DSN")
	tenant := fs.String("tenant", "", "tenant slug (_platform for the platform chain)")
	all := fs.Bool("all", false, "every tenant, including _platform")
	from := fs.Int64("from-seq", 0, "first seq (default: the first event)")
	to := fs.Int64("to-seq", 0, "last seq (default: the chain head)")
	anchors := fs.String("anchors", "", "anchor source to check checkpoints against (file:///…/audit-anchors.jsonl)")
	strict := fs.Bool("strict", false, "treat stale anchoring as a failure (exit 6)")
	asJSON := fs.Bool("json", false, "print the reports as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch sub {
	case "verify", "checkpoint", "export":
	default:
		fmt.Fprintln(stderr, auditUsage)
		return fmt.Errorf("audit: unknown subcommand %q", sub)
	}
	if (*tenant == "") == !*all || (sub == "export" && *all) {
		fmt.Fprintln(stderr, auditUsage)
		return errors.New("audit: give exactly one of -tenant or -all (export takes -tenant)")
	}
	if *from < 0 || *to < 0 || (*to > 0 && *to < *from) {
		return errors.New("audit: invalid seq range")
	}
	if _, err := os.Stat(*db); err != nil { // #nosec G703 -- operator-supplied path on the operator's own host
		return fmt.Errorf("audit: database %s: %w", *db, err)
	}
	st, err := store.Open(ctx, *db)
	if err != nil {
		return err
	}
	defer st.Close()
	tenants, err := selectTenants(ctx, st, *tenant)
	if err != nil {
		return err
	}
	switch sub {
	case "verify":
		return auditVerify(ctx, st, tenants, *from, *to, *anchors, *strict, *asJSON, archiveSourceFor(*db, st), stdout)
	case "checkpoint":
		return auditCheckpoint(ctx, st, *db, tenants, stdout)
	default:
		_, err := audit.Export(ctx, st, tenants[0].ID, *from, *to, stdout)
		return err
	}
}

// selectTenants returns the named tenant, or every tenant (with _platform)
// when slug is empty.
func selectTenants(ctx context.Context, st *store.DB, slug string) ([]store.Tenant, error) {
	var out []store.Tenant
	err := st.InSystem(ctx, "tessera audit: tenants", func(s *store.SystemTx) error {
		if slug != "" {
			t, err := s.TenantBySlug(slug)
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("audit: no tenant %q", slug)
			}
			out = []store.Tenant{t}
			return err
		}
		var err error
		out, err = s.Tenants()
		return err
	})
	return out, err
}

func auditVerify(ctx context.Context, st *store.DB, tenants []store.Tenant, from, to int64, anchorURL string,
	strict, asJSON bool, src audit.ArchiveSource, stdout io.Writer) error {
	pub, err := audit.PlatformPublicKeys(ctx, st)
	if err != nil {
		return err
	}
	var anchors *audit.AnchorSet
	if anchorURL != "" {
		path, err := audit.FilePath(anchorURL)
		if err != nil {
			return err
		}
		if anchors, err = audit.ReadAnchors(path); err != nil {
			return &exitError{audit.ExitAnchorMissing, fmt.Sprintf("audit: anchors: %v", err)}
		}
	}
	reports := make([]audit.Report, 0, len(tenants))
	worst := 0
	for _, t := range tenants {
		var rep audit.Report
		if err := st.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			var err error
			rep, err = audit.Verify(tx, t.Slug, audit.VerifyOptions{FromSeq: from, ToSeq: to, Keys: pub,
				Anchors: anchors, Now: time.Now().UTC(), Strict: strict, Archive: src})
			return err
		}); err != nil {
			return fmt.Errorf("audit: verify %s: %w", t.Slug, err)
		}
		reports = append(reports, rep)
		if rep.ExitCode != 0 && (worst == 0 || rep.ExitCode < worst) {
			worst = rep.ExitCode
		}
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return err
		}
	} else {
		for _, r := range reports {
			fmt.Fprintf(stdout, "%-12s %-7s events=%d seq=%d..%d head=%d checkpoints=%d anchored=%d", r.Tenant, r.Result,
				r.Events, r.FirstSeq, r.LastSeq, r.HeadSeq, r.Checkpoints, r.Anchored)
			if r.ArchivedThrough > 0 {
				fmt.Fprintf(stdout, " archived=1..%d (%d events checked)", r.ArchivedThrough, r.ArchivedEvents)
			}
			fmt.Fprintln(stdout)
			for _, p := range r.Problems {
				fmt.Fprintf(stdout, "  [%d] %s seq=%d: %s\n", p.Code, p.Kind, p.Seq, p.Detail)
			}
		}
	}
	if worst != 0 {
		return &exitError{worst, fmt.Sprintf("audit verify failed (exit %d)", worst)}
	}
	return nil
}

func auditCheckpoint(ctx context.Context, st *store.DB, dbFile string, tenants []store.Tenant, stdout io.Writer) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	sealer, err := cfg.Sealer(config.DevKEKPath(dbFile))
	if err != nil {
		return err
	}
	// The s3:// sink's AWS SDK client goes through safehttp like every outbound call.
	outCfg := *cfg
	if outCfg.Env == config.Test {
		outCfg.Env, outCfg.OutboundAllowLoopback = config.Prod, false
	}
	outbound, err := safehttp.ForConfig(&outCfg)
	if err != nil {
		return err
	}
	sink, err := audit.NewSink(cfg.AnchorURL(dbFile), audit.WithHTTPClient(outbound))
	if err != nil {
		return err
	}
	only := map[tenancy.ID]bool{}
	for _, t := range tenants {
		only[t.ID] = true
	}
	ck := &audit.Checkpointer{DB: st, Sealer: sealer, Sink: sink, Clock: timeutil.System, Issuer: cfg.PublicURL,
		Only: func(t store.Tenant) bool { return only[t.ID] }}
	res, err := ck.Run(audit.WithOperatorActor(ctx, operatorName()), true)
	fmt.Fprintf(stdout, "checkpoints created=%d anchored=%d failed=%d\n", res.Created, res.Anchored, res.Failed)
	return err
}

// operatorName names the OS user running the CLI (for the audit actor).
func operatorName() string {
	for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
		if v := os.Getenv(k); v != "" && len(v) <= 64 {
			return v
		}
	}
	return "operator"
}

// archiveSourceFor opens the archive for the chain verification when the
// environment is configured like the server's; nil (a warning in the report)
// when it is not.
func archiveSourceFor(dbFile string, st *store.DB) audit.ArchiveSource {
	if os.Getenv("TESSERA_ENV") == "" {
		return nil
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return nil
	}
	sealer, err := cfg.Sealer(config.DevKEKPath(dbFile))
	if err != nil {
		return nil
	}
	svc, err := newArchive(cfg, dbFile, st, sealer, timeutil.System, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || !svc.Enabled() {
		return nil
	}
	return svc
}
