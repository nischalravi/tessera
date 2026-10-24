package datasets_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/datasets"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func code(err error) string {
	var ce *cfgerr.Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

func TestParseCSV(t *testing.T) {
	for name, tc := range map[string]struct {
		in     string
		header bool
		want   []string
		code   string
	}{
		"plain":        {"a\nb\nc\n", false, []string{"a", "b", "c"}, ""},
		"header":       {"value,note\na,x\nb,y\n", true, []string{"a", "b"}, ""},
		"dedupe, trim": {" a \n\nb\na\n", false, []string{"a", "b"}, ""},
		"bom":          {"\xef\xbb\xbfa\nb\n", false, []string{"a", "b"}, ""},
		"quoted comma": {"\"a,b\",x\n", false, []string{"a,b"}, ""},
		"too long":     {strings.Repeat("x", datasets.MaxValueLen+1) + "\n", false, nil, "invalid_value"},
		"bad quote":    {"\"a\nb", false, nil, "invalid_csv"},
		"too big":      {strings.Repeat("a\n", datasets.MaxCSVBytes), false, nil, "file_too_large"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := datasets.ParseCSV([]byte(tc.in), tc.header)
			if code(err) != tc.code {
				t.Fatalf("code = %q (%v), want %q", code(err), err, tc.code)
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDatasetLifecycle(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		for name, bad := range map[string]string{"empty": "", "leading space": " x", "slash": "a/b", "long": strings.Repeat("a", 81)} {
			if _, err := datasets.Create(c, datasets.Spec{Name: bad}, "t", now); code(err) != "invalid_name" {
				t.Errorf("%s name: %v", name, err)
			}
		}
		d, err := datasets.Create(c, datasets.Spec{Name: "Domains", Description: " blocked ", Values: []string{"a.com", " b.com ", "a.com"}}, "t", now)
		if err != nil || d.Count != 2 || d.Description != "blocked" {
			t.Fatalf("create: %+v %v", d, err)
		}
		if _, err := datasets.Create(c, datasets.Spec{Name: "Domains"}, "t", now); code(err) != "name_taken" {
			t.Errorf("duplicate name: %v", err)
		}
		ch, err := datasets.Edit(c, d.ID, []string{"c.com", "a.com"}, []string{"b.com", "zzz.com"}, "t", now)
		if err != nil || ch.Added != 1 || ch.Removed != 1 || ch.Dataset.Count != 2 || ch.Dataset.Version != 2 {
			t.Fatalf("edit: %+v %v", ch, err)
		}
		if _, err := datasets.Edit(c, d.ID, nil, nil, "t", now); code(err) != "nothing_to_change" {
			t.Errorf("empty edit: %v", err)
		}
		if has, _ := datasets.Contains(c, "Domains", " c.com "); !has {
			t.Error("Contains misses a value")
		}
		if has, _ := datasets.Contains(c, "Domains", "b.com"); has {
			t.Error("Contains finds a removed value")
		}
		if has, err := datasets.Contains(c, "Nope", "x"); has || err != nil {
			t.Errorf("a missing dataset: %v %v", has, err)
		}
		// append, then replace
		ch, err = datasets.Upload(c, d.ID, []byte("h\nc.com\nd.com\n"), true, false, "t", now)
		if err != nil || ch.Added != 1 || ch.Removed != 0 || ch.Dataset.Count != 3 {
			t.Fatalf("append: %+v %v", ch, err)
		}
		ch, err = datasets.Upload(c, d.ID, []byte("x.com\nd.com\n"), false, true, "t", now)
		if err != nil || ch.Added != 1 || ch.Removed != 2 || ch.Dataset.Count != 2 {
			t.Fatalf("replace: %+v %v", ch, err)
		}
		if _, err := datasets.Upload(c, d.ID, []byte("\n\n"), false, true, "t", now); code(err) != "empty_file" {
			t.Errorf("empty file: %v", err)
		}
		vals, _ := datasets.Page(c, d.ID, 1, 1)
		if len(vals) != 1 || vals[0] != "x.com" {
			t.Errorf("page: %v", vals)
		}
		// rename: stale version, then ok
		if _, err := datasets.Update(c, d.ID, 1, "Blocked", "", "t", now); code(err) != "version_conflict" {
			t.Errorf("stale rename: %v", err)
		}
		cur, _ := datasets.Get(c, d.ID)
		if u, err := datasets.Update(c, d.ID, cur.Version, "Blocked", "", "t", now); err != nil || u.Name != "Blocked" {
			t.Errorf("rename: %+v %v", u, err)
		}
		if err := datasets.Delete(c, d.ID, "t", now); err != nil {
			t.Errorf("delete: %v", err)
		}
		if _, err := datasets.Get(c, d.ID); code(err) != "dataset_not_found" {
			t.Errorf("after delete: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
