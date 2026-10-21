package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/archive"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// newArchive builds the archival service of issue #298: the sealed segments go to
// TESSERA_ARCHIVE_URL (an object store reached through internal/safehttp) or to
// a local directory (TESSERA_ARCHIVE_DIR, BackupDir/archive, or var/archive next
// to a dev database). It returns nil when no archive is configured (prod with
// neither setting), which leaves archiving off: nothing is archived or deleted.
func newArchive(cfg *config.Config, dbFile string, st *store.DB, sealer *seal.Sealer, clock timeutil.Clock, log *slog.Logger) (*archive.Service, error) {
	if sealer == nil {
		return nil, nil
	}
	var blobs archive.BlobStore
	switch {
	case cfg.ArchiveURL != "":
		client, err := safehttp.ForConfigLimits(cfg, 2*time.Minute, archive.MaxBlobBytes+1<<20)
		if err != nil {
			return nil, err
		}
		if blobs, err = archive.NewHTTPStore(cfg.ArchiveURL, client); err != nil {
			return nil, err
		}
	default:
		dir := cfg.ArchiveDirFor(dbFile)
		if dir == "" {
			return nil, nil
		}
		local, err := archive.NewLocalStore(dir)
		if err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
		blobs = local
	}
	return &archive.Service{DB: st, Sealer: sealer, Store: blobs, Clock: clock, Log: log.With("component", "archive")}, nil
}
