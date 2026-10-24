// Package datasets keeps tenant lookup tables: named sets of distinct string values (allowed
// cost centers, restricted domains) that rules and request forms read by name (issue #588).
// Every change is audited in the caller's transaction; the store holds the rows.
package datasets

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/workflow"
)

// Limits.
const (
	MaxDatasets    = 200
	MaxValues      = 20000
	MaxValueLen    = 200
	MaxNameLen     = 80
	MaxDescription = 500
	// MaxCSVBytes caps an uploaded CSV file.
	MaxCSVBytes = 1 << 20
	// PageSize is the default and largest page of values.
	PageSize    = 100
	MaxPageSize = 500
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$`)

// CheckName validates a dataset name (the name is how rules refer to it).
func CheckName(n string) error {
	if !nameRE.MatchString(n) {
		return cfgerr.Refuse(422, "invalid_name", "a dataset name is 1 to %d letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit", MaxNameLen)
	}
	return nil
}

// CleanValue trims a value and checks it.
func CleanValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > MaxValueLen || !utf8.ValidString(v) || strings.ContainsAny(v, "\x00\r\n") {
		return "", cfgerr.Refuse(422, "invalid_value", "a value is 1 to %d characters on one line", MaxValueLen)
	}
	return v, nil
}

func cleanValues(in []string) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		c, err := CleanValue(v)
		if err != nil {
			return nil, err
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

func notFound() error { return cfgerr.Refuse(404, "dataset_not_found", "dataset not found") }

func conflict() error {
	return cfgerr.Refuse(409, "version_conflict", "the dataset changed since you read it; reload it")
}

// Spec is a dataset to create.
type Spec struct {
	Name        string
	Description string
	Values      []string
}

func checkDescription(d string) (string, error) {
	d = strings.TrimSpace(d)
	if len(d) > MaxDescription || !utf8.ValidString(d) {
		return "", cfgerr.Refuse(422, "invalid_description", "the description is at most %d characters", MaxDescription)
	}
	return d, nil
}

// Create makes a dataset with optional first values.
func Create(tx *store.TenantTx, s Spec, by string, now time.Time) (*store.Dataset, error) {
	if err := CheckName(s.Name); err != nil {
		return nil, err
	}
	desc, err := checkDescription(s.Description)
	if err != nil {
		return nil, err
	}
	vals, err := cleanValues(s.Values)
	if err != nil {
		return nil, err
	}
	if len(vals) > MaxValues {
		return nil, tooMany()
	}
	if n, err := tx.DatasetCount(); err != nil {
		return nil, err
	} else if n >= MaxDatasets {
		return nil, cfgerr.Refuse(422, "too_many_datasets", "a tenant has at most %d datasets", MaxDatasets)
	}
	if _, err := tx.DatasetByName(s.Name); err == nil {
		return nil, cfgerr.Refuse(409, "name_taken", "a dataset with this name exists")
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	id := uuid.NewString()
	if err := tx.InsertDataset(id, s.Name, desc, by, now); err != nil {
		return nil, err
	}
	for _, v := range vals {
		if _, err := tx.AddDatasetValue(id, v); err != nil {
			return nil, err
		}
	}
	if err := tx.Audit(now, by, "dataset.created", ojson.Object{{Key: "dataset_id", Value: id}, {Key: "name", Value: s.Name},
		{Key: "values", Value: len(vals)}}); err != nil {
		return nil, err
	}
	return tx.Dataset(id)
}

func tooMany() error {
	return cfgerr.Refuse(422, "too_many_values", "a dataset holds at most %d values", MaxValues)
}

func load(tx *store.TenantTx, id string) (*store.Dataset, error) {
	d, err := tx.Dataset(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound()
	}
	return d, err
}

// Get returns a dataset.
func Get(tx *store.TenantTx, id string) (*store.Dataset, error) { return load(tx, id) }

// Page lists a page of a dataset's values.
func Page(tx *store.TenantTx, id string, limit, offset int) ([]string, error) {
	if _, err := load(tx, id); err != nil {
		return nil, err
	}
	if limit < 1 || limit > MaxPageSize {
		limit = PageSize
	}
	if offset < 0 {
		offset = 0
	}
	return tx.DatasetValues(id, limit, offset)
}

// Update renames a dataset or changes its description; ver is the version the caller read.
func Update(tx *store.TenantTx, id string, ver int, name, description, by string, now time.Time) (*store.Dataset, error) {
	cur, err := load(tx, id)
	if err != nil {
		return nil, err
	}
	if err := CheckName(name); err != nil {
		return nil, err
	}
	desc, err := checkDescription(description)
	if err != nil {
		return nil, err
	}
	if name != cur.Name {
		if err := inUse(tx, cur.Name); err != nil {
			return nil, err
		}
		if _, err := tx.DatasetByName(name); err == nil {
			return nil, cfgerr.Refuse(409, "name_taken", "a dataset with this name exists")
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	if ok, err := tx.UpdateDataset(id, ver, name, desc, by, now); err != nil {
		return nil, err
	} else if !ok {
		return nil, conflict()
	}
	if err := tx.Audit(now, by, "dataset.updated", ojson.Object{{Key: "dataset_id", Value: id}, {Key: "name", Value: name},
		{Key: "previous_name", Value: cur.Name}, {Key: "version", Value: ver + 1}}); err != nil {
		return nil, err
	}
	return tx.Dataset(id)
}

// inUse refuses a rename or delete of a dataset a live workflow condition names.
func inUse(tx *store.TenantTx, name string) error {
	use, err := workflow.DatasetsInUse(tx)
	if err != nil {
		return err
	}
	if len(use[name]) > 0 {
		return cfgerr.Refuse(409, "dataset_in_use", "an active workflow uses this dataset: change or retire it first")
	}
	return nil
}

// Delete removes a dataset and its values.
func Delete(tx *store.TenantTx, id, by string, now time.Time) error {
	cur, err := load(tx, id)
	if err != nil {
		return err
	}
	if err := inUse(tx, cur.Name); err != nil {
		return err
	}
	if err := tx.DeleteDataset(id); err != nil {
		return err
	}
	return tx.Audit(now, by, "dataset.deleted", ojson.Object{{Key: "dataset_id", Value: id}, {Key: "name", Value: cur.Name},
		{Key: "values", Value: cur.Count}})
}

// Change is the outcome of a change to a dataset's values.
type Change struct {
	Dataset *store.Dataset
	Added   int
	Removed int
}

// Edit adds and removes values in one step (removals first, so a value in both lists ends up present).
func Edit(tx *store.TenantTx, id string, add, remove []string, by string, now time.Time) (*Change, error) {
	cur, err := load(tx, id)
	if err != nil {
		return nil, err
	}
	if len(add) == 0 && len(remove) == 0 {
		return nil, cfgerr.Refuse(422, "nothing_to_change", "name values to add or remove")
	}
	if len(add) > MaxValues || len(remove) > MaxValues {
		return nil, tooMany()
	}
	adds, err := cleanValues(add)
	if err != nil {
		return nil, err
	}
	rems, err := cleanValues(remove)
	if err != nil {
		return nil, err
	}
	ch := &Change{}
	for _, v := range rems {
		if ok, err := tx.RemoveDatasetValue(id, v); err != nil {
			return nil, err
		} else if ok {
			ch.Removed++
		}
	}
	for _, v := range adds {
		if ok, err := tx.AddDatasetValue(id, v); err != nil {
			return nil, err
		} else if ok {
			ch.Added++
		}
	}
	return finish(tx, cur, ch, "dataset.values.changed", by, now)
}

func finish(tx *store.TenantTx, cur *store.Dataset, ch *Change, action, by string, now time.Time) (*Change, error) {
	n, err := tx.DatasetValueCount(cur.ID)
	if err != nil {
		return nil, err
	}
	if n > MaxValues {
		return nil, tooMany() // the caller's transaction rolls back
	}
	if ch.Added > 0 || ch.Removed > 0 {
		if ok, err := tx.TouchDataset(cur.ID, cur.Version, by, now); err != nil {
			return nil, err
		} else if !ok {
			return nil, conflict()
		}
	}
	if err := tx.Audit(now, by, action, ojson.Object{{Key: "dataset_id", Value: cur.ID}, {Key: "name", Value: cur.Name},
		{Key: "added", Value: ch.Added}, {Key: "removed", Value: ch.Removed}, {Key: "values", Value: n}}); err != nil {
		return nil, err
	}
	if ch.Dataset, err = tx.Dataset(cur.ID); err != nil {
		return nil, err
	}
	return ch, nil
}

// ParseCSV reads values from a CSV file: the first column of each row; blank rows are skipped, and
// header drops the first row. The file is refused whole if any value is invalid.
func ParseCSV(raw []byte, header bool) ([]string, error) {
	if len(raw) > MaxCSVBytes {
		return nil, cfgerr.Refuse(413, "file_too_large", "the file is larger than %d bytes", MaxCSVBytes)
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1
	r.ReuseRecord = false
	var out []string
	for row := 0; ; row++ {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, cfgerr.Refuse(422, "invalid_csv", "the file is not valid CSV")
		}
		if row == 0 && header {
			continue
		}
		if len(rec) == 0 || (len(rec) == 1 && strings.TrimSpace(rec[0]) == "") {
			continue
		}
		out = append(out, rec[0])
		if len(out) > MaxValues {
			return nil, tooMany()
		}
	}
	return cleanValues(out)
}

// Upload adds the values of a CSV file to a dataset, or with replace makes them its whole content.
func Upload(tx *store.TenantTx, id string, raw []byte, header, replace bool, by string, now time.Time) (*Change, error) {
	cur, err := load(tx, id)
	if err != nil {
		return nil, err
	}
	vals, err := ParseCSV(raw, header)
	if err != nil {
		return nil, err
	}
	if len(vals) == 0 {
		return nil, cfgerr.Refuse(422, "empty_file", "the file holds no values")
	}
	ch := &Change{}
	if replace {
		old, err := tx.DatasetValues(id, MaxValues, 0)
		if err != nil {
			return nil, err
		}
		was := make(map[string]bool, len(old))
		for _, v := range old {
			was[v] = true
		}
		after := make(map[string]bool, len(vals))
		for _, v := range vals {
			after[v] = true
			if !was[v] {
				ch.Added++
			}
		}
		for _, v := range old {
			if !after[v] {
				ch.Removed++
			}
		}
		if err := tx.ClearDatasetValues(id); err != nil {
			return nil, err
		}
		for _, v := range vals {
			if _, err := tx.AddDatasetValue(id, v); err != nil {
				return nil, err
			}
		}
	} else {
		for _, v := range vals {
			if ok, err := tx.AddDatasetValue(id, v); err != nil {
				return nil, err
			} else if ok {
				ch.Added++
			}
		}
	}
	return finish(tx, cur, ch, "dataset.uploaded", by, now)
}

// Contains reports whether the named dataset holds the value; a missing dataset holds nothing.
func Contains(tx *store.TenantTx, name, value string) (bool, error) {
	d, err := tx.DatasetByName(name)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return tx.DatasetHas(d.ID, strings.TrimSpace(value))
}
