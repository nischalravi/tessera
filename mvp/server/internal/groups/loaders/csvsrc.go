package loaders

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
)

// MaxCSVBytes bounds a CSV source; MaxCSVRows its rows.
const (
	MaxCSVBytes = 64 << 20
	MaxCSVRows  = 1_000_000
)

// csvSource reads a header-mapped CSV file (under the loader data directory) or
// an https URL. The file's SHA-256 is recorded on the run. The URL is fetched
// through the SSRF-guarded client; the loader's secret is its bearer token.
type csvSource struct{ noChanges }

func (csvSource) read(ctx context.Context, job LoaderJob, cfg *CSVConfig) ([]byte, error) {
	if cfg.Path != "" {
		path, err := confine(job.Env.DataDir, cfg.Path)
		if err != nil {
			return nil, err
		}
		if err := fileSize(path, MaxCSVBytes); err != nil {
			return nil, err
		}
		b, err := os.ReadFile(path) // #nosec G304 -- confined to the loader data directory by confine
		if err != nil {
			return nil, conflict("source_file_missing", "the source file cannot be read")
		}
		return b, nil
	}
	if job.Env.HTTP == nil {
		return nil, conflict("source_http_unavailable", "no outbound HTTP client is configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.URL, nil)
	if err != nil {
		return nil, invalid("invalid_config", "url is not valid")
	}
	req.Header.Set("Accept", "text/csv, text/plain, */*")
	if len(job.Secret) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(job.Secret))
	}
	resp, err := job.Env.HTTP.Do(req)
	if err != nil {
		// the error names the host the guard refused or could not reach, never the token
		return nil, conflict("source_fetch_failed", "fetching the CSV failed: %v", errors.Unwrap(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, conflict("source_fetch_failed", "fetching the CSV answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxCSVBytes+1))
	if err != nil {
		return nil, conflict("source_fetch_failed", "reading the CSV failed")
	}
	if len(b) > MaxCSVBytes {
		return nil, conflict("source_file_too_large", "the CSV is larger than %d bytes", MaxCSVBytes)
	}
	return b, nil
}

func (s csvSource) Full(ctx context.Context, job LoaderJob) ([]LoadedGroup, error) {
	var cfg CSVConfig
	if err := decodeConfig(job, &cfg); err != nil {
		return nil, err
	}
	data, err := s.read(ctx, job, &cfg)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	job.Stats.Hash = hex.EncodeToString(sum[:])
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	if cfg.Delimiter != "" {
		r.Comma = []rune(cfg.Delimiter)[0]
	}
	header, err := r.Read()
	if err != nil {
		return nil, conflict("source_csv_invalid", "the CSV has no header row")
	}
	subjI := column(header, cfg.SubjectColumn)
	if subjI < 0 {
		return nil, conflict("source_column_missing", "the CSV has no column %q", cfg.SubjectColumn)
	}
	groupI, dispI, srcI := -1, -1, -1
	if cfg.GroupColumn != "" {
		if groupI = column(header, cfg.GroupColumn); groupI < 0 {
			return nil, conflict("source_column_missing", "the CSV has no column %q", cfg.GroupColumn)
		}
	}
	if cfg.DisplayColumn != "" {
		if dispI = column(header, cfg.DisplayColumn); dispI < 0 {
			return nil, conflict("source_column_missing", "the CSV has no column %q", cfg.DisplayColumn)
		}
	}
	if cfg.SourceColumn != "" {
		if srcI = column(header, cfg.SourceColumn); srcI < 0 {
			return nil, conflict("source_column_missing", "the CSV has no column %q", cfg.SourceColumn)
		}
	}
	source := cfg.SubjectSource
	if source == "" {
		source = "identity"
	}
	var out []LoadedGroup
	index := map[string]int{}
	add := func(name string) int {
		if i, ok := index[name]; ok {
			return i
		}
		index[name] = len(out)
		out = append(out, LoadedGroup{Name: name})
		return len(out) - 1
	}
	if cfg.Group != "" {
		add(cfg.Group)
	}
	cell := func(rec []string, i int) string {
		if i < 0 || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	for n := 1; ; n++ {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, conflict("source_csv_invalid", "the CSV is not valid at row %d: %v", n, err)
		}
		if n > MaxCSVRows {
			return nil, conflict("source_row_limit", "the CSV has more than %d rows", MaxCSVRows)
		}
		subject := cell(rec, subjI)
		if subject == "" {
			return nil, conflict("source_empty_subject", "row %d of the CSV has an empty %s", n, cfg.SubjectColumn)
		}
		name := cfg.Group
		if groupI >= 0 {
			if name = cell(rec, groupI); name == "" {
				return nil, conflict("source_empty_group", "row %d of the CSV has an empty %s", n, cfg.GroupColumn)
			}
		}
		ref := SubjectRef{Source: source, Identifier: subject}
		if srcI >= 0 {
			if s := cell(rec, srcI); s != "" {
				ref.Source = s
			}
		}
		g := &out[add(name)]
		g.Members = append(g.Members, ref)
		if dispI >= 0 && g.DisplayName == "" {
			g.DisplayName = cell(rec, dispI)
		}
		job.Stats.Rows++
	}
	return out, nil
}
