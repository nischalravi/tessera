package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/catalog"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const catalogUsage = `usage:
  tessera catalog refresh [-dir catalog/aws] [-date YYYY-MM-DD]
  tessera catalog compile [-dir catalog/aws] [-snapshot YYYY-MM-DD|latest] [-report file.md]

refresh   fetches the AWS Service Reference JSON, the RCP service page and the
          pinned iam-dataset file into <dir>/snapshots/<date> (immutable; an
          existing date is an error). Every file is verified and a manifest
          of SHA-256 digests is written. Nothing is written if any fetch fails.
compile   verifies a snapshot against its manifest, merges the overlays in
          <dir>/overlays and writes <dir>/compiled/<version>.json.gz. It prints
          the version, the PR title and whether anything changed against the
          previous compiled catalog; -report writes the full diff as Markdown.`

// newCatalogFetcher builds the production fetcher: every request goes through
// the SSRF-guarded client. Tests replace it.
var newCatalogFetcher = func() (*catalog.Fetcher, error) {
	c, err := safehttp.New(safehttp.Options{
		Env:          config.Prod, // no loopback or plain http exception
		Timeout:      2 * time.Minute,
		MaxBodyBytes: 32 << 20,
	})
	if err != nil {
		return nil, err
	}
	return &catalog.Fetcher{Client: c}, nil
}

// catalogCmd runs `tessera catalog refresh|compile` (design §10.3).
func catalogCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(stderr, catalogUsage)
		return errors.New("catalog: missing subcommand")
	}
	sub, args := args[0], args[1:]
	fset := flag.NewFlagSet("tessera catalog "+sub, flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", "catalog/aws", "catalog directory")
	switch sub {
	case "refresh":
		date := fset.String("date", "", "snapshot date (default: today, UTC)")
		if err := fset.Parse(args); err != nil {
			return err
		}
		if *date == "" {
			*date = time.Now().UTC().Format("2006-01-02")
		}
		return catalogRefresh(ctx, *dir, *date, stdout)
	case "compile":
		snapshot := fset.String("snapshot", "latest", "snapshot date, or latest")
		report := fset.String("report", "", "write the diff report (Markdown) to this file")
		if err := fset.Parse(args); err != nil {
			return err
		}
		return catalogCompile(*dir, *snapshot, *report, stdout)
	default:
		fmt.Fprintln(stderr, catalogUsage)
		return fmt.Errorf("catalog: unknown subcommand %q (want refresh or compile)", sub)
	}
}

func catalogRefresh(ctx context.Context, dir, date string, stdout io.Writer) error {
	pin, err := catalog.LoadDatasetPin(dir)
	if err != nil {
		return err
	}
	f, err := newCatalogFetcher()
	if err != nil {
		return err
	}
	snap, err := f.Fetch(ctx, date, pin)
	if err != nil {
		return err
	}
	if err := catalog.WriteSnapshot(dir, snap); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "snapshot: %s\nfiles: %d\n", date, len(snap.Files))
	return nil
}

func catalogCompile(dir, snapshot, reportPath string, stdout io.Writer) error {
	if snapshot == "latest" {
		all, err := catalog.ListSnapshots(dir)
		if err != nil {
			return err
		}
		if len(all) == 0 {
			return fmt.Errorf("catalog: no snapshots under %s (run `tessera catalog refresh`)", dir)
		}
		snapshot = all[len(all)-1]
	}
	snap, err := catalog.ReadSnapshot(dir, snapshot)
	if err != nil {
		return err
	}
	ov, err := catalog.LoadOverlays(filepath.Join(dir, "overlays"))
	if err != nil {
		return err
	}
	res, err := catalog.Compile(snap, ov)
	if err != nil {
		return err
	}
	// diff against the newest earlier artifact (a different version)
	existing, err := catalog.ListCompiled(dir)
	if err != nil {
		return err
	}
	var prev *catalog.Compiled
	for i := len(existing) - 1; i >= 0; i-- {
		if existing[i].Version == res.Compiled.Version {
			continue
		}
		if prev, err = catalog.LoadCompiled(catalog.CompiledPath(dir, existing[i].Version)); err != nil {
			return err
		}
		break
	}
	rep := catalog.Diff(prev, res)
	out := catalog.CompiledPath(dir, res.Compiled.Version)
	_, statErr := os.Stat(out) // #nosec G703 -- operator-supplied catalog directory plus a validated version name
	switch {
	case statErr == nil: // same inputs, same version: keep the committed bytes
	case errors.Is(statErr, os.ErrNotExist):
		b, err := catalog.Encode(res.Compiled)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(out, b); err != nil {
			return err
		}
	default:
		return statErr
	}
	if reportPath != "" {
		if err := writeFileAtomic(reportPath, []byte(rep.Markdown())); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "version: %s\ntitle: %s\nchanged: %t\nwarnings: %d\n",
		res.Compiled.Version, rep.Title(), rep.Changed(), len(res.Warnings))
	return nil
}

// writeFileAtomic writes to a temporary file in the same directory and renames it.
func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil { // #nosec G703 -- operator-supplied path on the operator's own host
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after the rename
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path) // #nosec G703 -- operator-supplied path on the operator's own host
}
