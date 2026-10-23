package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/archive"
	"github.com/nischalravi/tessera/mvp/server/internal/cloudcred"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/kekwrap"
	"github.com/nischalravi/tessera/mvp/server/internal/objstore"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
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

// kekUnwrapTimeout bounds the unwrap at start.
const kekUnwrapTimeout = 30 * time.Second

// loadSealer is cfg.Sealer after unwrapping a KEK wrapped by a cloud key
// service (TESSERA_KEK_WRAPPED with TESSERA_KEK_KMS), once, with the workload
// identity. After that the KEK behaves exactly like TESSERA_KEK.
func loadSealer(ctx context.Context, cfg *config.Config, devKEKPath string) (*seal.Sealer, error) {
	if cfg.KEKWrapped() {
		uctx, cancel := context.WithTimeout(ctx, kekUnwrapTimeout)
		defer cancel()
		deps, err := newKEKDeps(cfg)
		if err != nil {
			return nil, err
		}
		if err := cfg.ResolveKEK(uctx, func(ctx context.Context, ref kekwrap.Ref, wrapped []byte) ([]byte, error) {
			return kekwrap.Unwrap(ctx, ref, wrapped, deps)
		}); err != nil {
			return nil, fmt.Errorf("TESSERA_KEK_WRAPPED: %w", err)
		}
	}
	return cfg.Sealer(devKEKPath)
}

func kekDepsFor(client *http.Client) kekwrap.Deps {
	meta := safehttp.MetadataClient()
	return kekwrap.Deps{HTTP: client,
		AWS:   &cloudcred.AWS{HTTP: client, Meta: meta},
		Azure: &cloudcred.Azure{HTTP: client, Meta: meta},
		GCP:   &cloudcred.GCP{HTTP: client, Meta: meta}}
}

func newKEKDeps(cfg *config.Config) (kekwrap.Deps, error) {
	client, err := safehttp.ForConfigLimits(cfg, kekUnwrapTimeout, 0)
	if err != nil {
		return kekwrap.Deps{}, err
	}
	return kekDepsFor(client), nil
}

// wrapKEKCmd is `tessera admin wrap-kek -kms <ref> [-generate]`: it wraps a KEK
// (base64 of 32 bytes on stdin, or a fresh random one with -generate) with the
// cloud key service and prints the base64 ciphertext for TESSERA_KEK_WRAPPED.
// It checks the result by unwrapping it. With -generate the plaintext KEK is
// never shown: it exists only inside the key service (and your wrapped copy).
func wrapKEKCmd(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("tessera admin wrap-kek", flag.ContinueOnError)
	fset.SetOutput(stderr)
	kms := fset.String("kms", os.Getenv("TESSERA_KEK_KMS"), "key reference: aws:arn:aws:kms:…, azure:https://<vault>/keys/<name>/<version> or gcp:projects/…/cryptoKeys/<key>")
	generate := fset.Bool("generate", false, "wrap a new random KEK instead of reading one from stdin")
	if err := fset.Parse(args); err != nil {
		return err
	}
	ref, err := kekwrap.ParseRef(*kms)
	if err != nil {
		return fmt.Errorf("-kms: %w", err)
	}
	var kek []byte
	if *generate {
		kek = seal.RandomBytes(seal.KeySize)
	} else {
		raw, err := io.ReadAll(io.LimitReader(stdin, 4096))
		if err != nil {
			return err
		}
		if kek, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err != nil || len(kek) != seal.KeySize {
			return errors.New("stdin must hold a KEK: the base64 of 32 bytes (or use -generate)")
		}
	}
	client, err := safehttp.ForCLI(kekUnwrapTimeout, 0)
	if err != nil {
		return err
	}
	deps := kekDepsFor(client)
	ctx, cancel := context.WithTimeout(ctx, 2*kekUnwrapTimeout)
	defer cancel()
	wrapped, err := kekwrap.Wrap(ctx, ref, kek, deps)
	if err != nil {
		return err
	}
	back, err := kekwrap.Unwrap(ctx, ref, wrapped, deps)
	if err != nil || !bytes.Equal(back, kek) {
		return errors.New("the wrapped KEK does not unwrap to the same key; not printing it")
	}
	fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(wrapped))
	fmt.Fprintf(stderr, "Set TESSERA_KEK_WRAPPED to the value above and TESSERA_KEK_KMS=%s; remove TESSERA_KEK and TESSERA_KEK_FILE.\n", ref)
	if *generate {
		fmt.Fprintln(stderr, "The KEK was generated and is not shown: without this key service (and the wrapped value) the data it seals cannot be opened. Keep the wrapped value in escrow.")
	}
	return nil
}
