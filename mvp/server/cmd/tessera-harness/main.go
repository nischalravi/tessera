// Command tessera-harness runs the AWS evaluator's differential test harness
// (design §13). This build has the offline subcommands only:
//
//	tessera-harness replay [-dir testdata/aws/cassettes] [-json] [-triage file]
//	tessera-harness gate -report report.json
//
// replay re-runs the recorded corpus through the engine with no AWS credentials
// and no network, and exits 1 unless every case concludes what it expects. gate
// applies the nightly gate (§13.7) to the metrics in a replay or nightly report.
// The nightly subcommand arrives with the sandbox in PR-9.
//
// Only this binary imports internal/aws/harness; the server never links it
// (enforced in internal/archtest).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/harness"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "replay":
		return replay(args[1:], stdout, stderr)
	case "gate":
		return gate(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "tessera-harness: unknown command %q\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: tessera-harness replay [-dir DIR] [-json] [-triage FILE]")
	fmt.Fprintln(w, "       tessera-harness gate -report FILE")
}

func replay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "testdata/aws/cassettes", "directory of replay cases")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	triage := fs.String("triage", "", "append the run and its checks to this triage file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cases, err := harness.LoadDir(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "tessera-harness:", err)
		return 1
	}
	if len(cases) == 0 {
		fmt.Fprintf(stderr, "tessera-harness: no cases in %s; an empty corpus proves nothing\n", *dir)
		return 1
	}
	cat := harness.OfflineCatalog{}
	rep := harness.Replay(context.Background(), cat, cases)

	if *triage != "" {
		if err := writeTriage(*triage, cat.Version(), cases, rep); err != nil {
			fmt.Fprintln(stderr, "tessera-harness:", err)
			return 1
		}
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(stderr, "tessera-harness:", err)
			return 1
		}
	} else {
		printReport(stdout, rep)
	}
	if !rep.OK {
		return 1
	}
	return 0
}

func printReport(w io.Writer, rep *harness.ReplayReport) {
	for _, c := range rep.Cases {
		status := "ok  "
		switch {
		case !c.OK:
			status = "FAIL"
		case c.Known:
			status = "known"
		}
		fmt.Fprintf(w, "%-5s %s", status, c.ID)
		if c.Problem != "" {
			fmt.Fprintf(w, "  %s", c.Problem)
		}
		fmt.Fprintln(w)
	}
	m := rep.Metrics
	fmt.Fprintf(w, "cases=%d counted=%d agree=%d excluded=%v\n", len(rep.Cases), m.M1.Total, m.M1.Agree, m.Excluded)
	if !rep.OK {
		fmt.Fprintln(w, "replay FAILED")
	}
}

func writeTriage(path, catalogVersion string, cases []*harness.Case, rep *harness.ReplayReport) error {
	t, err := harness.OpenTriage(path)
	if err != nil {
		return err
	}
	defer t.Close()
	runID := "replay-" + time.Now().UTC().Format("20060102T150405Z")
	if err := t.AddRun(harness.Run{ID: runID, StartedAt: time.Now().UTC().Format(time.RFC3339), CatalogVersion: catalogVersion, Mode: "replay", Metrics: rep.Metrics}); err != nil {
		return err
	}
	byID := map[string]*harness.Case{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	for _, r := range rep.Cases {
		if r.Check == nil {
			continue
		}
		if err := t.AddCheck(runID, *r.Check); err != nil {
			return err
		}
		if r.Check.Verdict != harness.Disagree {
			continue
		}
		d := harness.Divergence{ID: runID + "/" + r.ID, RunID: runID, SpecID: r.ID, Class: harness.ClassUnclassified, Status: harness.StatusOpen, Check: r.Check}
		if k := byID[r.ID].Known; k != nil {
			d.Class, d.Status, d.Evidence = k.Class, harness.StatusKnown, k.ProbeEvidence
		}
		if err := t.AddDivergence(d); err != nil {
			return err
		}
	}
	return nil
}

func gate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	report := fs.String("report", "", "a JSON report with a metrics object (replay -json output)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *report == "" {
		fmt.Fprintln(stderr, "tessera-harness: gate needs -report")
		return 2
	}
	b, err := os.ReadFile(*report)
	if err != nil {
		fmt.Fprintln(stderr, "tessera-harness:", err)
		return 1
	}
	var rep harness.ReplayReport
	if err := json.Unmarshal(b, &rep); err != nil || rep.Metrics == nil {
		fmt.Fprintln(stderr, "tessera-harness: the report has no metrics object")
		return 1
	}
	res := rep.Metrics.Gate(harness.DefaultGate)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	if !res.Pass {
		return 1
	}
	return 0
}
