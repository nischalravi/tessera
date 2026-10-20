package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/harness"
)

const corpus = "../../testdata/aws/cassettes"

func TestReplayCommandPassesOnTheCorpus(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"replay", "-dir", corpus}, &out, &errb); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "ok    sim-allow-identity") || strings.Contains(out.String(), "FAIL") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestReplayCommandFailsOnABrokenCase(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile(filepath.Join(corpus, "sim-allow-identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip what the simulator said: the engine allows, the recording denies.
	broken := strings.Replace(string(b), "<EvalDecision>allowed</EvalDecision>", "<EvalDecision>implicitDeny</EvalDecision>", 1)
	if broken == string(b) {
		t.Fatal("the fixture changed shape")
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"replay", "-dir", dir}, &out, &errb); code != 1 || !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
}

func TestReplayCommandEdgeCases(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"replay", "-dir", t.TempDir()}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "empty corpus") {
		t.Fatalf("empty corpus: exit %d %s", code, errb.String())
	}
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("no command: exit %d", code)
	}
	if code := run([]string{"nope"}, &out, &errb); code != 2 {
		t.Fatalf("unknown command: exit %d", code)
	}
	if code := run([]string{"gate"}, &out, &errb); code != 2 {
		t.Fatalf("gate without a report: exit %d", code)
	}
}

func TestReplayJSONTriageAndGate(t *testing.T) {
	dir := t.TempDir()
	triage := filepath.Join(dir, "triage.jsonl")
	var out, errb bytes.Buffer
	if code := run([]string{"replay", "-dir", corpus, "-json", "-triage", triage}, &out, &errb); code != 0 {
		t.Fatalf("exit %d %s", code, errb.String())
	}
	var rep harness.ReplayReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || !rep.OK || rep.Metrics == nil {
		t.Fatalf("report: %v", err)
	}
	snap, err := harness.LoadTriage(triage)
	if err != nil || len(snap.Runs) != 1 || len(snap.Divergences) != 0 {
		t.Fatalf("triage %+v %v", snap, err)
	}
	// The replay corpus is far below n = 10,000, so the nightly gate refuses it.
	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(report, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"gate", "-report", report}, &out, &errb); code != 1 || !strings.Contains(out.String(), "need at least") {
		t.Fatalf("gate: exit %d\n%s", code, out.String())
	}
}
