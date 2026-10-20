package harness

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
)

// The triage store holds the three tables of §13.1: harness_runs,
// harness_checks and harness_divergences. It is an append-only JSON-lines file,
// not SQLite: the server's store rules (SQL only in internal/store, every
// statement tenant-scoped) are for tenant data, and the harness has no tenant.
// A SQLite schema can replace the file behind the same methods when the nightly
// job needs queries (PR-9); the record shapes are the columns.

// DivergenceClass is the auto-classification of §13.9.
type DivergenceClass string

// Classes of §13.9, plus UNCLASSIFIED for manual triage.
const (
	ClassEngineBug           DivergenceClass = "ENGINE_BUG"
	ClassSimulatorLimitation DivergenceClass = "SIMULATOR_LIMITATION"
	ClassDocAmbiguity        DivergenceClass = "DOC_AMBIGUITY"
	ClassPropagation         DivergenceClass = "PROPAGATION"
	ClassContextMismatch     DivergenceClass = "CONTEXT_MISMATCH"
	ClassCatalogStale        DivergenceClass = "CATALOG_STALE"
	ClassFixtureDrift        DivergenceClass = "FIXTURE_DRIFT"
	ClassUnclassified        DivergenceClass = "UNCLASSIFIED"
)

// DivergenceStatus is the lifecycle of a divergence.
type DivergenceStatus string

// Statuses. An ENGINE_BUG closes only when its reproducer is in the golden or
// replay corpus and passes (§13.9 step 4).
const (
	StatusOpen   DivergenceStatus = "open"
	StatusKnown  DivergenceStatus = "known" // pinned as known_divergence in a cassette
	StatusClosed DivergenceStatus = "closed"
	StatusDrop   DivergenceStatus = "dropped" // PROPAGATION: tracked as a rate only
)

// Run is a row of harness_runs.
type Run struct {
	ID             string   `json:"id"`
	StartedAt      string   `json:"started_at"` // RFC 3339, supplied by the caller
	EngineVersion  string   `json:"engine_version"`
	CatalogVersion string   `json:"catalog_version"`
	FixtureVersion string   `json:"fixture_version"`
	Seed           int64    `json:"seed"`
	Mode           string   `json:"mode"` // "replay" or "nightly"
	Metrics        *Metrics `json:"metrics,omitempty"`
	GatePass       *bool    `json:"gate_pass,omitempty"`
}

// Divergence is a row of harness_divergences.
type Divergence struct {
	ID        string           `json:"id"`
	RunID     string           `json:"run_id"`
	SpecID    string           `json:"spec_id"`
	Class     DivergenceClass  `json:"class"`
	Status    DivergenceStatus `json:"status"`
	Minimized *RequestSpec     `json:"minimized,omitempty"`
	IssueURL  string           `json:"issue_url,omitempty"`
	Evidence  string           `json:"evidence,omitempty"`
	Check     *Check           `json:"check,omitempty"`
}

type triageRecord struct {
	Kind       string      `json:"kind"` // "run", "check" or "divergence"
	Run        *Run        `json:"run,omitempty"`
	RunID      string      `json:"run_id,omitempty"`
	Check      *Check      `json:"check,omitempty"`
	Divergence *Divergence `json:"divergence,omitempty"`
}

// TriageStore is the file-backed triage database. It is safe for concurrent use.
type TriageStore struct {
	mu sync.Mutex
	f  *os.File
}

// OpenTriage opens (creating it if needed) the JSON-lines file at path.
func OpenTriage(path string) (*TriageStore, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- operator-chosen harness output path
	if err != nil {
		return nil, err
	}
	return &TriageStore{f: f}, nil
}

// Close closes the file.
func (t *TriageStore) Close() error { return t.f.Close() }

func (t *TriageStore) append(r triageRecord) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, err = t.f.Write(append(b, '\n'))
	return err
}

// AddRun records a run (a later AddRun with the same id replaces it on load).
func (t *TriageStore) AddRun(r Run) error { return t.append(triageRecord{Kind: "run", Run: &r}) }

// AddCheck records a check under a run.
func (t *TriageStore) AddCheck(runID string, c Check) error {
	return t.append(triageRecord{Kind: "check", RunID: runID, Check: &c})
}

// AddDivergence records a divergence (a later record with the same id replaces
// it on load, which is how a status or issue link is updated).
func (t *TriageStore) AddDivergence(d Divergence) error {
	if d.ID == "" || d.RunID == "" {
		return errors.New("harness: a divergence needs an id and a run id")
	}
	if d.Status == "" {
		d.Status = StatusOpen
	}
	return t.append(triageRecord{Kind: "divergence", Divergence: &d})
}

// TriageSnapshot is the folded content of the file.
type TriageSnapshot struct {
	Runs        []Run
	Checks      map[string][]Check // by run id
	Divergences []Divergence
}

// LoadTriage reads the file at path and folds it: the last record wins per run
// id and per divergence id. Order of first appearance is kept.
func LoadTriage(path string) (*TriageSnapshot, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-chosen harness output path
	if err != nil {
		return nil, err
	}
	out := &TriageSnapshot{Checks: map[string][]Check{}}
	runAt, divAt := map[string]int{}, map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	line := 0
	for sc.Scan() {
		line++
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var r triageRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("harness: triage line %d: %w", line, err)
		}
		switch {
		case r.Kind == "run" && r.Run != nil:
			if i, ok := runAt[r.Run.ID]; ok {
				out.Runs[i] = *r.Run
			} else {
				runAt[r.Run.ID] = len(out.Runs)
				out.Runs = append(out.Runs, *r.Run)
			}
		case r.Kind == "check" && r.Check != nil:
			out.Checks[r.RunID] = append(out.Checks[r.RunID], *r.Check)
		case r.Kind == "divergence" && r.Divergence != nil:
			if i, ok := divAt[r.Divergence.ID]; ok {
				out.Divergences[i] = *r.Divergence
			} else {
				divAt[r.Divergence.ID] = len(out.Divergences)
				out.Divergences = append(out.Divergences, *r.Divergence)
			}
		default:
			return nil, fmt.Errorf("harness: triage line %d: unknown record kind %q", line, r.Kind)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Open returns the divergences still open, sorted by id.
func (s *TriageSnapshot) Open() []Divergence {
	var out []Divergence
	for _, d := range s.Divergences {
		if d.Status == StatusOpen {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
