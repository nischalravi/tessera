package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/migration"
)

func TestMigrationAssessment_NoLiveWritesOrNativeReviews(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "live.db")
	sentinel := []byte("existing database and imported decisions must remain untouched")
	if err := os.WriteFile(db, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TESSERA_DB", db)
	t.Setenv("TESSERA_ENV", "prod")
	var out, stderr bytes.Buffer
	reportFile := filepath.Join(dir, "assessment.json")
	args := []string{"migration", "assess", "--tenant", "fixture-tenant", "--product", "saviynt", "--instance", "fixture", "--file", "../../internal/migration/testdata/normalized.json", "--out", reportFile}
	if err := run(context.Background(), args, &out, &stderr); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, sentinel) {
		t.Fatal("live database modified")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatal("database sidecar created")
	}
	var r migration.Report
	reportBytes, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal("report unexpectedly written to stdout")
	}
	if err := json.Unmarshal(reportBytes, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Snapshot.Certifications) != 1 || r.Snapshot.Certifications[0].Decision != "approve" || r.ComparisonStatus != "not_performed" {
		t.Fatal("imported evidence missing or mistaken for live comparison")
	}
}

func TestMigrationOutputRefusesOverwriteAndInputAliases(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.json")
	output := filepath.Join(dir, "report.json")
	b, err := os.ReadFile("../../internal/migration/testdata/normalized.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, b, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"assess", "--tenant", "t", "--product", "saviynt", "--instance", "fixture", "--file", input, "--out", output}
	var stdout, stderr bytes.Buffer
	if err := migrationCmd(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("report permissions")
	}
	if err := migrationCmd(args, &stdout, &stderr); err == nil {
		t.Fatal("overwrote existing output")
	}
	after, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, after) {
		t.Fatal("refused overwrite changed output")
	}
	if err := migrationCmd(append(args, "--force"), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{input, filepath.Join(dir, "symlink"), filepath.Join(dir, "hardlink")} {
		if alias != input {
			if filepath.Base(alias) == "symlink" {
				err = os.Symlink(input, alias)
			} else {
				err = os.Link(input, alias)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		aliased := append([]string{}, args...)
		aliased[len(aliased)-1] = alias
		if err := migrationCmd(append(aliased, "--force"), &stdout, &stderr); err == nil {
			t.Fatal("replaced input alias")
		}
	}
	after, err = os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, b) {
		t.Fatal("input changed")
	}
}

func TestMigrationCommandFailsWithoutWritingPartialReport(t *testing.T) {
	base := []string{"assess", "--product", "saviynt", "--instance", "fixture", "--file", "../../internal/migration/testdata/normalized.json", "--out", filepath.Join(t.TempDir(), "report.json")}
	for _, args := range [][]string{nil, {"apply"}, base, append(append([]string{}, base...), "--tenant", "t", "unexpected"), {"assess", "--tenant", "t", "--file", "missing"}} {
		var out, stderr bytes.Buffer
		if err := migrationCmd(args, &out, &stderr); err == nil {
			t.Fatal("invalid command accepted")
		}
		if out.Len() != 0 {
			t.Fatal("partial report emitted")
		}
	}
}
