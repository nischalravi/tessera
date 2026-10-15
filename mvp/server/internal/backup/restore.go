package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// RestoreOptions configure a verification or a restore.
type RestoreOptions struct {
	// Target is the database path to restore to. Empty: verify only.
	Target string
	// Anchors is the live anchor source. With it, every checkpoint the
	// backup holds must be anchored with the same JWS, and the report says
	// how many anchored events are newer than the backup (the data a restore
	// loses). Without it, only the chain inside the backup is checked.
	Anchors *audit.AnchorSet
	// Force replaces an existing Target, keeping it as
	// <target>.pre-restore-<timestamp>.
	Force bool
	Now   time.Time
}

// TenantResult is one tenant's verification after decryption.
type TenantResult struct {
	Slug   string       `json:"slug"`
	Report audit.Report `json:"report"`
	// LostAfterBackup is how far the live anchors reach past the backup's
	// head: at least this many events were recorded after the backup and
	// are not in it.
	LostAfterBackup int64 `json:"lost_after_backup"`
}

// Restored is the outcome of a verification or restore.
type Restored struct {
	Manifest Manifest       `json:"manifest"`
	Tenants  []TenantResult `json:"tenants"`
	Target   string         `json:"target,omitempty"`
	Previous string         `json:"previous,omitempty"` // where an existing target was moved
	// Invalidated is what a restore revoked so credentials that were valid at
	// snapshot time do not come back: sessions, pending login transactions,
	// unconsumed bootstrap codes and access-token signing keys, summed over
	// all tenants. It is zero for a verify-only run.
	Invalidated store.CredentialsInvalidated `json:"invalidated"`
}

// InvalidationReason is the revoked_reason of sessions a restore revoked.
const InvalidationReason = "restore"

// Restore decrypts the backup, verifies every tenant's audit chain (hashes,
// links, checkpoint signatures and, with Anchors, the anchors up to the
// backup's head) and that each chain head matches the manifest, and only then
// installs it at opts.Target. A backup that fails any check is refused and
// nothing is changed. The server must not be running on Target.
func Restore(ctx context.Context, path string, sealer *seal.Sealer, opts RestoreOptions) (*Restored, error) {
	dir := os.TempDir()
	if opts.Target != "" {
		dir = filepath.Dir(opts.Target)
		if _, err := os.Stat(opts.Target); err == nil && !opts.Force {
			return nil, refuse("target_exists", "%s exists; stop the server and pass -force to replace it (it is kept as a .pre-restore copy)", opts.Target)
		}
	}
	tmp := filepath.Join(dir, ".restore-"+seal.RandomString(10, "abcdefghijklmnopqrstuvwxyz0123456789")+".db")
	installed := false
	defer func() {
		if !installed {
			removeDB(tmp)
		}
	}()
	m, err := Decrypt(path, tmp, sealer)
	if err != nil {
		return nil, err
	}
	res := &Restored{Manifest: m}
	if err := verifyRestored(ctx, tmp, m, opts, res); err != nil {
		return res, err
	}
	if opts.Target == "" {
		return res, nil
	}
	// Before anything is installed: a failure here leaves the working
	// database in place and the temporary copy is removed.
	if err := invalidateCredentials(ctx, tmp, opts.Now, res); err != nil {
		return res, fmt.Errorf("backup: invalidate credentials in the restored database: %w", err)
	}
	if _, err := os.Stat(opts.Target); err == nil {
		prev := opts.Target + ".pre-restore-" + opts.Now.UTC().Format("20060102T150405Z")
		for _, sfx := range []string{"", "-wal", "-shm"} {
			if err := os.Rename(opts.Target+sfx, prev+sfx); err != nil && !errors.Is(err, os.ErrNotExist) {
				return res, fmt.Errorf("backup: keep the previous database: %w", err)
			}
		}
		res.Previous = prev
	}
	if err := os.Rename(tmp, opts.Target); err != nil {
		return res, err
	}
	installed = true
	res.Target = opts.Target
	return res, nil
}

func verifyRestored(ctx context.Context, path string, m Manifest, opts RestoreOptions, res *Restored) error {
	st, err := store.Open(ctx, path)
	if err != nil {
		return refuse("unreadable_backup", "the restored database does not open: %v", err)
	}
	defer st.Close()
	keys, err := audit.PlatformPublicKeys(ctx, st)
	if err != nil {
		return err
	}
	heads := map[string]int64{}
	for _, t := range m.Tenants {
		heads[t.ID] = t.HeadSeq
	}
	var anchors *audit.AnchorSet
	if opts.Anchors != nil {
		anchors = opts.Anchors.Upto(heads)
	}
	var tenants []store.Tenant
	if err := st.InSystem(ctx, "backup: verify tenants", func(s *store.SystemTx) error {
		var err error
		tenants, err = s.Tenants()
		return err
	}); err != nil {
		return err
	}
	if len(tenants) != len(m.Tenants) {
		return refuse("tampered_backup", "the backup holds %d tenants, its manifest lists %d", len(tenants), len(m.Tenants))
	}
	byID := map[string]TenantHead{}
	for _, h := range m.Tenants {
		byID[h.ID] = h
	}
	var failed []string
	for _, t := range tenants {
		want, ok := byID[t.ID.String()]
		if !ok {
			return refuse("tampered_backup", "tenant %s is not in the manifest", t.Slug)
		}
		var rep audit.Report
		var head store.AuditChainHead
		if err := st.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			var err error
			if head, err = tx.AuditHead(); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			rep, err = audit.Verify(tx, t.Slug, audit.VerifyOptions{Keys: keys, Anchors: anchors, Now: opts.Now})
			return err
		}); err != nil {
			return err
		}
		tr := TenantResult{Slug: t.Slug, Report: rep}
		if opts.Anchors != nil {
			for _, a := range opts.Anchors.ForTenant(t.ID.String()) {
				if d := a.Seq - want.HeadSeq; d > tr.LostAfterBackup {
					tr.LostAfterBackup = d
				}
			}
		}
		res.Tenants = append(res.Tenants, tr)
		if head.LastSeq != want.HeadSeq || head.LastHash != want.HeadHash {
			failed = append(failed, t.Slug+": chain head differs from the manifest")
		}
		if rep.Result == "failed" {
			failed = append(failed, fmt.Sprintf("%s: audit verify failed (exit %d)", t.Slug, rep.ExitCode))
		}
	}
	if len(failed) > 0 {
		return refuse("verification_failed", "the backup does not verify, refusing it: %v", failed)
	}
	return st.Checkpoint(ctx)
}

// invalidateCredentials revokes, in the restored copy at path, every
// credential that could have been revoked, consumed or rotated after the
// snapshot: a restored database cannot remember later revocations, so none of
// its sessions, pending sign-ins, bootstrap codes or access-token keys is
// trusted. Users sign in again; the server mints fresh signing keys on start.
func invalidateCredentials(ctx context.Context, path string, now time.Time, res *Restored) error {
	st, err := store.Open(ctx, path)
	if err != nil {
		return err
	}
	defer st.Close()
	var tenants []store.Tenant
	if err := st.InSystem(ctx, "backup: invalidate credentials", func(s *store.SystemTx) error {
		var err error
		tenants, err = s.Tenants()
		return err
	}); err != nil {
		return err
	}
	var total store.CredentialsInvalidated
	for _, t := range tenants {
		if err := st.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			n, err := tx.InvalidateCredentials(InvalidationReason, now)
			total.Sessions += n.Sessions
			total.LoginTransactions += n.LoginTransactions
			total.Invitations += n.Invitations
			total.SigningKeys += n.SigningKeys
			return err
		}); err != nil {
			return err
		}
	}
	if err := st.Checkpoint(ctx); err != nil {
		return err
	}
	res.Invalidated = total
	return nil
}

// Upload PUTs the backup to url (for example an object-storage presigned
// URL) with the SSRF-guarded client from internal/safehttp.
func Upload(ctx context.Context, client *http.Client, url, path string) error {
	fh, err := os.Open(path) // #nosec G304 -- a backup this process wrote
	if err != nil {
		return err
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, fh)
	if err != nil {
		return err
	}
	req.ContentLength = fi.Size()
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("backup: upload: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("backup: upload: %s", resp.Status)
	}
	return nil
}

// RecordEvent appends action to the platform audit chain of db, with the
// actor from ctx (audit.WithOperatorActor or audit.WithSystemActor).
func RecordEvent(ctx context.Context, db *store.DB, action string, detail ojson.Object) error {
	return db.InTenant(ctx, tenancy.Platform, func(tx *store.TenantTx) error {
		_, err := audit.Record(ctx, tx, action, detail)
		return err
	})
}

// Detail is the audit detail of a created backup (never the KEK check).
func (c *Created) Detail() ojson.Object {
	return ojson.Object{{Key: "backup_id", Value: c.Manifest.ID}, {Key: "file", Value: filepath.Base(c.Path)},
		{Key: "sha256", Value: c.Manifest.SHA256}, {Key: "size", Value: c.Manifest.Size}, {Key: "tenants", Value: len(c.Manifest.Tenants)}}
}
