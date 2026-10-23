package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/archive"
	"github.com/nischalravi/tessera/mvp/server/internal/cloudcred"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/objstore"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// maxBackupObject bounds a backup copied to an object store (one request,
// held in memory). Larger databases use Postgres tooling or provider snapshots.
const maxBackupObject = 1 << 30

// newObjDeps builds the credential sources and the guarded client the cloud
// object stores use: workload identity (env, IRSA, IMDSv2 / Azure managed
// identity or federation / GCP metadata server or key file). Token exchanges
// go through the SSRF-guarded client; only the fixed metadata addresses go
// through safehttp.MetadataClient.
func newObjDeps(cfg *config.Config) (objstore.Deps, error) {
	client, err := safehttp.ForConfigLimits(cfg, 10*time.Minute, archive.MaxBlobBytes+1<<20)
	if err != nil {
		return objstore.Deps{}, err
	}
	meta := safehttp.MetadataClient()
	return objstore.Deps{HTTP: client,
		AWS:   &cloudcred.AWS{HTTP: client, Meta: meta},
		Azure: &cloudcred.Azure{HTTP: client, Meta: meta},
		GCP:   &cloudcred.GCP{HTTP: client, Meta: meta}}, nil
}

// copyBackupToObjectStore uploads the backup file to TESSERA_BACKUP_URL. The
// backup is already sealed under the KEK; the store sees ciphertext.
func copyBackupToObjectStore(ctx context.Context, cfg *config.Config, path string) error {
	fi, err := os.Stat(path) // #nosec G703 -- the backup this process just wrote
	if err != nil {
		return err
	}
	if fi.Size() > maxBackupObject {
		return fmt.Errorf("backup is %d bytes, over the %d byte limit for an object-store copy", fi.Size(), maxBackupObject)
	}
	deps, err := newObjDeps(cfg)
	if err != nil {
		return err
	}
	st, err := objstore.Open(cfg.BackupURL, deps)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path) // #nosec G304 G703 -- the backup this process just wrote
	if err != nil {
		return err
	}
	if _, err := st.Put(ctx, "backups/"+filepath.Base(path), data, objstore.PutOptions{ContentType: "application/octet-stream"}); err != nil {
		return fmt.Errorf("copy to %s: %w", st.Location(), err)
	}
	return nil
}
