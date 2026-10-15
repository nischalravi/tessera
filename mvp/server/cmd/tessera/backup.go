package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/backup"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const backupUsage = `usage:
  tessera backup create  [-db path] [-dir backups/] [-keep N] [-upload https://…presigned-PUT-URL] [-json]
  tessera backup verify  -in file.tbak [-anchors file:///…|none] [-json]
  tessera backup restore -in file.tbak [-db target] [-anchors file:///…|none] [-force] [-json]
  tessera backup list    [-dir backups/]

create takes an online snapshot (the server may keep running) sealed under
the KEK. verify and restore decrypt it and check every tenant's audit chain,
checkpoint signatures and, unless -anchors none, the anchors up to the
backup's head. restore installs it only if everything verifies; stop the
server first. The KEK of the instance that took the backup is required.
Exit codes: 0 ok, 1 error, 7 the backup was refused (tampered, wrong KEK or
failed verification).`

// ExitBackupRefused is the exit code of a refused backup.
const ExitBackupRefused = 7

func backupCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(stderr, backupUsage)
		return errors.New("backup: missing subcommand")
	}
	sub, args := args[0], args[1:]
	fset := flag.NewFlagSet("tessera backup "+sub, flag.ContinueOnError)
	fset.SetOutput(stderr)
	db := fset.String("db", dbPath(os.Getenv("TESSERA_DB")), "SQLite database path (restore: the target)")
	dir := fset.String("dir", "", "backup directory (default TESSERA_BACKUP_DIR, else backups/ next to the database)")
	keep := fset.Int("keep", 0, "keep the newest N backups in -dir (default TESSERA_BACKUP_KEEP)")
	upload := fset.String("upload", "", "also PUT the backup to this URL (an object-storage presigned URL)")
	in := fset.String("in", "", "backup file")
	anchors := fset.String("anchors", "", "anchor source to verify against (default: the configured one; none to skip)")
	force := fset.Bool("force", false, "restore over an existing database (kept as .pre-restore-<time>)")
	asJSON := fset.Bool("json", false, "print the result as JSON")
	if err := fset.Parse(args); err != nil {
		return err
	}
	switch sub {
	case "create", "verify", "restore", "list":
	default:
		fmt.Fprintln(stderr, backupUsage)
		return fmt.Errorf("backup: unknown subcommand %q", sub)
	}
	if os.Getenv("TESSERA_ENV") == "" {
		return errors.New("set TESSERA_ENV=dev (run.sh does), TESSERA_ENV=test or TESSERA_ENV=prod")
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	if *dir == "" {
		*dir = cfg.BackupDir
	}
	if *dir == "" {
		*dir = filepath.Join(filepath.Dir(*db), "backups")
	}
	if *keep == 0 {
		*keep = cfg.BackupKeep
	}
	if sub == "list" {
		return backupList(*dir, stdout)
	}
	sealer, err := cfg.Sealer(config.DevKEKPath(*db))
	if err != nil {
		return err
	}
	ctx = audit.WithOperatorActor(ctx, operatorName())
	now := time.Now().UTC()
	if sub == "create" {
		if _, err := os.Stat(*db); err != nil { // #nosec G703 -- operator-supplied path on the operator's own host
			return fmt.Errorf("backup: database %s: %w", *db, err)
		}
		st, err := store.Open(ctx, *db)
		if err != nil {
			return err
		}
		defer st.Close()
		c, err := createBackup(ctx, st, sealer, cfg, *dir, *keep, *upload, now, nil)
		if err != nil {
			return err
		}
		if *asJSON {
			return json.NewEncoder(stdout).Encode(map[string]any{"path": c.Path, "manifest": c.Manifest})
		}
		fmt.Fprintf(stdout, "backup %s written: %s (%d bytes of database, sha256 %s)\n", c.Manifest.ID, c.Path, c.Manifest.Size, c.Manifest.SHA256[:16])
		return nil
	}
	if *in == "" {
		fmt.Fprintln(stderr, backupUsage)
		return errors.New("backup: -in is required")
	}
	opts := backup.RestoreOptions{Force: *force, Now: now}
	if sub == "restore" {
		opts.Target = *db
	}
	if opts.Anchors, err = loadAnchors(*anchors, cfg, *db); err != nil {
		return err
	}
	res, err := backup.Restore(ctx, *in, sealer, opts)
	printRestore(stdout, res, *asJSON)
	var be *backup.Error
	if errors.As(err, &be) {
		return &exitError{ExitBackupRefused, "backup refused: " + be.Error()}
	}
	if err != nil {
		return err
	}
	if sub == "restore" {
		if err := recordRestore(ctx, opts.Target, res); err != nil {
			return fmt.Errorf("backup: restored, but the restore event could not be recorded: %w", err)
		}
		fmt.Fprintf(stdout, "restored backup %s to %s", res.Manifest.ID, res.Target)
		if res.Previous != "" {
			fmt.Fprintf(stdout, " (previous database kept at %s)", res.Previous)
		}
		fmt.Fprintln(stdout)
	} else if !*asJSON {
		fmt.Fprintf(stdout, "backup %s verifies\n", res.Manifest.ID)
	}
	return nil
}

// createBackup writes a backup, prunes old ones, optionally uploads it and
// records platform.backup.created.
func createBackup(ctx context.Context, st *store.DB, sealer *seal.Sealer, cfg *config.Config, dir string, keep int,
	uploadURL string, now time.Time, logger *slog.Logger) (*backup.Created, error) {
	c, err := backup.Create(ctx, st, sealer, backup.CreateOptions{Dir: dir, Env: cfg.Env, Instance: cfg.PublicURL, Now: now})
	if err != nil {
		return nil, err
	}
	detail := c.Detail()
	if uploadURL != "" {
		client, err := safehttp.ForConfig(cfg)
		if err != nil {
			return c, err
		}
		if err := backup.Upload(ctx, client, uploadURL, c.Path); err != nil {
			return c, err
		}
		detail = append(detail, ojson.KV{Key: "uploaded", Value: true})
	}
	if err := backup.RecordEvent(ctx, st, "platform.backup.created", detail); err != nil {
		return c, err
	}
	removed, err := backup.Prune(dir, keep)
	if logger != nil && len(removed) > 0 {
		logger.Info("old backups removed", "count", len(removed))
	}
	return c, err
}

func loadAnchors(flagValue string, cfg *config.Config, db string) (*audit.AnchorSet, error) {
	u := flagValue
	if u == "none" {
		return nil, nil
	}
	if u == "" {
		u = cfg.AnchorURL(db)
	}
	if u == "" {
		return nil, nil
	}
	path, err := audit.FilePath(u)
	if err != nil {
		if flagValue == "" {
			return nil, nil // a non-file anchor sink (s3://) is checked with tessera audit verify
		}
		return nil, err
	}
	a, err := audit.ReadAnchors(path)
	if errors.Is(err, fs.ErrNotExist) && flagValue == "" {
		return nil, nil
	}
	return a, err
}

func recordRestore(ctx context.Context, target string, res *backup.Restored) error {
	st, err := store.Open(ctx, target)
	if err != nil {
		return err
	}
	defer st.Close()
	lost := int64(0)
	for _, t := range res.Tenants {
		lost += t.LostAfterBackup
	}
	return backup.RecordEvent(ctx, st, "platform.backup.restored", ojson.Object{{Key: "backup_id", Value: res.Manifest.ID},
		{Key: "backup_created_at", Value: res.Manifest.CreatedAt.Format(time.RFC3339)}, {Key: "sha256", Value: res.Manifest.SHA256},
		{Key: "tenants", Value: len(res.Tenants)}, {Key: "anchored_events_lost", Value: lost},
		{Key: "sessions_revoked", Value: res.Invalidated.Sessions}, {Key: "login_transactions_deleted", Value: res.Invalidated.LoginTransactions},
		{Key: "bootstrap_invitations_deleted", Value: res.Invalidated.Invitations}, {Key: "signing_keys_revoked", Value: res.Invalidated.SigningKeys}})
}

func printRestore(w io.Writer, res *backup.Restored, asJSON bool) {
	if res == nil {
		return
	}
	if asJSON {
		_ = json.NewEncoder(w).Encode(res)
		return
	}
	fmt.Fprintf(w, "backup %s taken %s (%s), %d tenants\n", res.Manifest.ID, res.Manifest.CreatedAt.Format(time.RFC3339), res.Manifest.Env, len(res.Manifest.Tenants))
	for _, t := range res.Tenants {
		r := t.Report
		fmt.Fprintf(w, "  %-12s %-7s events=%d head=%d checkpoints=%d anchored=%d", t.Slug, r.Result, r.Events, r.HeadSeq, r.Checkpoints, r.Anchored)
		if t.LostAfterBackup > 0 {
			fmt.Fprintf(w, " newer-anchored-events>=%d", t.LostAfterBackup)
		}
		fmt.Fprintln(w)
		for _, p := range r.Problems {
			fmt.Fprintf(w, "    [%d] %s seq=%d: %s\n", p.Code, p.Kind, p.Seq, p.Detail)
		}
	}
	if res.Target != "" {
		in := res.Invalidated
		fmt.Fprintf(w, "credentials revoked: sessions=%d login-transactions=%d bootstrap-invitations=%d signing-keys=%d; users sign in again\n",
			in.Sessions, in.LoginTransactions, in.Invitations, in.SigningKeys)
	}
}

func backupList(dir string, w io.Writer) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(w, "no backups in %s\n", dir)
		return nil
	} else if err != nil {
		return err
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() || filepath.Ext(e.Name()) != backup.Ext {
			continue
		}
		m, err := backup.ReadManifest(filepath.Join(dir, e.Name()))
		if err != nil {
			fmt.Fprintf(w, "%s  unreadable: %v\n", e.Name(), err)
			continue
		}
		n++
		fmt.Fprintf(w, "%s  %s  %s  %d bytes  %d tenants\n", e.Name(), m.CreatedAt.Format(time.RFC3339), m.Env, m.Size, len(m.Tenants))
	}
	if n == 0 {
		fmt.Fprintf(w, "no backups in %s\n", dir)
	}
	return nil
}

// runBackups takes a backup every interval until ctx ends (TESSERA_BACKUP_DIR).
func runBackups(ctx context.Context, st *store.DB, sealer *seal.Sealer, cfg *config.Config, logger *slog.Logger) {
	every := time.Duration(cfg.BackupEveryMinutes) * time.Minute
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sctx := audit.WithSystemActor(ctx, "backup-scheduler")
			if c, err := createBackup(sctx, st, sealer, cfg, cfg.BackupDir, cfg.BackupKeep, "", time.Now().UTC(), logger); err != nil {
				logger.Error("scheduled backup failed", "err", err)
			} else {
				logger.Info("backup written", "path", c.Path, "id", c.Manifest.ID)
			}
		}
	}
}
