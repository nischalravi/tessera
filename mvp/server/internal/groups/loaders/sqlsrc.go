package loaders

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// confine resolves a file name under the loader data directory. The name has
// been validated at save time (no .., no absolute path); this also refuses a
// symbolic link that leads out of the directory, and a missing directory.
func confine(dataDir, rel string) (string, error) {
	if dataDir == "" {
		return "", conflict("loader_data_dir_unset", "no loader data directory is configured (TESSERA_LOADER_DATA_DIR): file sources are off")
	}
	root, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return "", fmt.Errorf("loader data directory: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", err
	}
	full, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return "", conflict("source_file_missing", "the source file %q cannot be opened", rel)
	}
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", conflict("source_file_outside", "the source file %q is outside the loader data directory", rel)
	}
	return full, nil
}

// sqlSource runs the loader's read-only query against a SQLite file under the
// loader data directory.
type sqlSource struct{}

func column(cols []string, name string) int {
	for i, c := range cols {
		if strings.EqualFold(strings.TrimSpace(c), name) {
			return i
		}
	}
	return -1
}

func requireColumns(cols []string, names ...string) ([]int, error) {
	out := make([]int, len(names))
	for i, n := range names {
		if out[i] = column(cols, n); out[i] < 0 {
			return nil, conflict("source_column_missing", "the query returns no column %q (it returns %s)", n, strings.Join(cols, ", "))
		}
	}
	return out, nil
}

func (sqlSource) query(ctx context.Context, job LoaderJob, cfg *SQLConfig, q string, args map[string]string) (*store.ExtResult, error) {
	path, err := confine(job.Env.DataDir, cfg.Database)
	if err != nil {
		return nil, err
	}
	res, err := store.RunExtQuery(ctx, store.ExtQuery{Path: path, SQL: q, Args: args})
	switch {
	case errors.Is(err, store.ErrExtRowLimit):
		return nil, conflict("source_row_limit", "the query returns more than %d rows", store.DefaultExtMaxRows)
	case errors.Is(err, context.DeadlineExceeded):
		return nil, conflict("source_timeout", "the query took longer than %s", store.DefaultExtTimeout)
	case err != nil:
		return nil, conflict("source_query_failed", "the query failed: %v", err)
	}
	return res, nil
}

func (s sqlSource) Full(ctx context.Context, job LoaderJob) ([]LoadedGroup, error) {
	var cfg SQLConfig
	if err := strictDecode(job.Config, &cfg); err != nil {
		return nil, invalid("invalid_config", "config: %v", err)
	}
	res, err := s.query(ctx, job, &cfg, cfg.Query, nil)
	if err != nil {
		return nil, err
	}
	job.Stats.Rows = len(res.Rows)
	list := job.Loader.Type == TypeSQLGroupList
	var gi int
	var ci []int
	if list {
		if ci, err = requireColumns(res.Columns, "group_name", "subject_id"); err != nil {
			return nil, err
		}
		gi = ci[0]
	} else if ci, err = requireColumns(res.Columns, "subject_id"); err != nil {
		return nil, err
	}
	si := ci[len(ci)-1]
	srcI := column(res.Columns, "subject_source")
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
	if !list {
		add(cfg.Group)
	}
	for n, row := range res.Rows {
		subject := strings.TrimSpace(row[si])
		if subject == "" {
			return nil, conflict("source_empty_subject", "row %d of the query has an empty subject_id", n+1)
		}
		name := cfg.Group
		if list {
			if name = strings.TrimSpace(row[gi]); name == "" {
				return nil, conflict("source_empty_group", "row %d of the query has an empty group_name", n+1)
			}
		}
		ref := SubjectRef{Source: "identity", Identifier: subject}
		if srcI >= 0 && strings.TrimSpace(row[srcI]) != "" {
			ref.Source = strings.TrimSpace(row[srcI])
		}
		g := &out[add(name)]
		g.Members = append(g.Members, ref)
	}
	if list && cfg.GroupsQuery != "" {
		gres, err := s.query(ctx, job, &cfg, cfg.GroupsQuery, nil)
		if err != nil {
			return nil, err
		}
		gc, err := requireColumns(gres.Columns, "group_name")
		if err != nil {
			return nil, err
		}
		di, dsc := column(gres.Columns, "display_name"), column(gres.Columns, "description")
		for _, row := range gres.Rows {
			name := strings.TrimSpace(row[gc[0]])
			if name == "" {
				continue
			}
			g := &out[add(name)]
			if di >= 0 {
				g.DisplayName = row[di]
			}
			if dsc >= 0 {
				g.Description = row[dsc]
			}
		}
	}
	return out, nil
}

// Changes reads the incremental query: rows after the cursor, each a group
// name (sql_group_list; sql_simple has one group), a subject, op add or remove,
// and seq. The next cursor is the highest seq seen.
func (s sqlSource) Changes(ctx context.Context, job LoaderJob, cursor string) ([]GroupChange, string, bool, error) {
	var cfg SQLConfig
	if err := strictDecode(job.Config, &cfg); err != nil {
		return nil, "", false, invalid("invalid_config", "config: %v", err)
	}
	if cfg.IncrementalQuery == "" {
		return nil, "", false, nil
	}
	if cursor == "" {
		cursor = "0"
	}
	res, err := s.query(ctx, job, &cfg, cfg.IncrementalQuery, map[string]string{"cursor": cursor})
	if err != nil {
		return nil, "", true, err
	}
	job.Stats.Rows = len(res.Rows)
	ci, err := requireColumns(res.Columns, "subject_id", "op", "seq")
	if err != nil {
		return nil, "", true, err
	}
	gi := column(res.Columns, "group_name")
	list := job.Loader.Type == TypeSQLGroupList
	if list && gi < 0 {
		return nil, "", true, conflict("source_column_missing", "the incremental query returns no column \"group_name\"")
	}
	srcI := column(res.Columns, "subject_source")
	next, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil {
		return nil, "", true, conflict("source_bad_cursor", "the stored cursor %q is not an integer", cursor)
	}
	var out []GroupChange
	for n, row := range res.Rows {
		seq, err := strconv.ParseInt(strings.TrimSpace(row[ci[2]]), 10, 64)
		if err != nil {
			return nil, "", true, conflict("source_bad_seq", "row %d of the incremental query has seq %q, which is not an integer", n+1, row[ci[2]])
		}
		next = max(next, seq)
		var remove bool
		switch strings.ToLower(strings.TrimSpace(row[ci[1]])) {
		case "add":
		case "remove":
			remove = true
		default:
			return nil, "", true, conflict("source_bad_op", "row %d of the incremental query has op %q (want add or remove)", n+1, row[ci[1]])
		}
		subject := strings.TrimSpace(row[ci[0]])
		if subject == "" {
			return nil, "", true, conflict("source_empty_subject", "row %d of the incremental query has an empty subject_id", n+1)
		}
		name := cfg.Group
		if list {
			if name = strings.TrimSpace(row[gi]); name == "" {
				return nil, "", true, conflict("source_empty_group", "row %d of the incremental query has an empty group_name", n+1)
			}
		}
		ref := SubjectRef{Source: "identity", Identifier: subject}
		if srcI >= 0 && strings.TrimSpace(row[srcI]) != "" {
			ref.Source = strings.TrimSpace(row[srcI])
		}
		out = append(out, GroupChange{Group: name, Subject: ref, Remove: remove})
	}
	return out, strconv.FormatInt(next, 10), true, nil
}

// decodeConfig strictly decodes a job's config.
func decodeConfig(job LoaderJob, v any) error {
	if err := strictDecode(json.RawMessage(job.Config), v); err != nil {
		return invalid("invalid_config", "config: %v", err)
	}
	return nil
}

// fileSize guards a file read.
func fileSize(path string, max int64) error {
	st, err := os.Stat(path)
	if err != nil {
		return conflict("source_file_missing", "the source file cannot be opened")
	}
	if !st.Mode().IsRegular() {
		return conflict("source_file_invalid", "the source file is not a regular file")
	}
	if st.Size() > max {
		return conflict("source_file_too_large", "the source file is larger than %d bytes", max)
	}
	return nil
}
