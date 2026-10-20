package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
)

// The offline replay corpus (§13.1, §13.7 item 3). Each file under
// testdata/aws/cassettes is one case: a spec, the recorded oracle answers and
// what the replay must conclude. Replaying needs no AWS credentials and no
// network; PR CI runs it with `go run ./cmd/tessera-harness replay`.

// Known is a pinned divergence (§13.7): the replay expects the disagreement and
// fails if it disappears, so a stale pin cannot linger.
type Known struct {
	Class         DivergenceClass `json:"class"`
	Justification string          `json:"justification"`
	ProbeEvidence string          `json:"probe_evidence"`
}

// Expect says what a case must conclude. The zero value means "agree".
type Expect struct {
	Verdict   Verdict   `json:"verdict,omitempty"`   // "agree" (default) or "excluded"
	Exclusion Exclusion `json:"exclusion,omitempty"` // required when the verdict is "excluded"
}

// Case is one replay file.
type Case struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	// Synthetic marks a hand-written response rather than a recording. Every
	// case in this PR is synthetic: nothing has been recorded against AWS yet.
	Synthetic bool              `json:"synthetic"`
	Spec      *RequestSpec      `json:"spec"`
	IAM       *awstest.Cassette `json:"iam_cassette,omitempty"`
	Probes    []ProbeResponse   `json:"probe_responses,omitempty"`
	AA        []AAResult        `json:"aa_results,omitempty"`
	Expect    Expect            `json:"expect"`
	Known     *Known            `json:"known_divergence,omitempty"`
}

const maxCaseBytes = 4 << 20

// ExcludedKnown tallies pinned known divergences in Metrics.Excluded.
const ExcludedKnown Exclusion = "known_divergence"

// LoadCase decodes one case strictly.
func LoadCase(b []byte) (*Case, error) {
	var c Case
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("harness: case: %w", err)
	}
	if dec.More() {
		return nil, errors.New("harness: case: trailing data")
	}
	if c.ID == "" || c.Spec == nil {
		return nil, errors.New("harness: case needs an id and a spec")
	}
	if err := c.Spec.Validate(); err != nil {
		return nil, err
	}
	if c.Spec.ID != c.ID {
		return nil, fmt.Errorf("harness: case %s: spec id %q differs", c.ID, c.Spec.ID)
	}
	if c.Expect.Verdict == "" {
		c.Expect.Verdict = Agree
	}
	if c.Expect.Verdict != Agree && c.Expect.Verdict != Excluded {
		return nil, fmt.Errorf("harness: case %s: expect.verdict must be agree or excluded", c.ID)
	}
	if c.Expect.Verdict == Excluded && c.Expect.Exclusion == "" {
		return nil, fmt.Errorf("harness: case %s: an excluded expectation names the exclusion", c.ID)
	}
	if k := c.Known; k != nil {
		if c.Expect.Verdict != Agree {
			return nil, fmt.Errorf("harness: case %s: known_divergence cannot combine with an excluded expectation", c.ID)
		}
		if k.Class != ClassSimulatorLimitation || strings.TrimSpace(k.Justification) == "" || strings.TrimSpace(k.ProbeEvidence) == "" {
			return nil, fmt.Errorf("harness: case %s: known_divergence needs class SIMULATOR_LIMITATION, a justification and probe evidence (§13.7)", c.ID)
		}
	}
	if c.IAM != nil && c.IAM.FixtureVersion != c.Spec.FixtureVersion {
		return nil, fmt.Errorf("harness: case %s: cassette fixture %q differs from the spec's %q", c.ID, c.IAM.FixtureVersion, c.Spec.FixtureVersion)
	}
	return &c, nil
}

// LoadDir loads every *.json case in dir, sorted by file name, and rejects a
// repeated id.
func LoadDir(dir string) ([]*Case, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var out []*Case
	seen := map[string]string{}
	for _, n := range names {
		fi, err := os.Stat(n)
		if err != nil {
			return nil, err
		}
		if fi.Size() > maxCaseBytes {
			return nil, fmt.Errorf("harness: %s is larger than %d bytes", n, maxCaseBytes)
		}
		b, err := os.ReadFile(n) // #nosec G304 -- the corpus directory is the operator's flag
		if err != nil {
			return nil, err
		}
		c, err := LoadCase(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		if prev, dup := seen[c.ID]; dup {
			return nil, fmt.Errorf("%s: case id %s already defined in %s", n, c.ID, prev)
		}
		seen[c.ID] = n
		out = append(out, c)
	}
	return out, nil
}

// oracleFor builds the routed oracle of a case from its recorded answers.
func (c *Case) oracleFor() (Oracle, error) {
	kind := Route(c.Spec)
	switch kind {
	case OracleSimCustom, OracleSimPrincipal:
		if c.IAM == nil {
			return nil, fmt.Errorf("case %s routes to %s but has no iam_cassette", c.ID, kind)
		}
		client := NewIAMClient(awstest.NewReplay(c.IAM), "us-east-1", func() aws.Retryer { return aws.NopRetryer{} })
		bo := Backoff{Base: 1, Max: 8, MaxAttempts: 5} // no Sleep: replay never waits
		if kind == OracleSimCustom {
			return &SimCustom{Client: client, Backoff: bo}, nil
		}
		return &SimPrincipal{Client: client, Backoff: bo}, nil
	case OracleProbe:
		return &ProbeOracle{Client: &RecordedProbe{Responses: c.Probes}, Backoff: Backoff{Base: 1, MaxAttempts: 3}}, nil
	}
	return nil, fmt.Errorf("case %s routes to unsupported oracle %s", c.ID, kind)
}

// CaseResult is the replay verdict on one case.
type CaseResult struct {
	ID      string `json:"id"`
	Check   *Check `json:"check,omitempty"`
	OK      bool   `json:"ok"`
	Known   bool   `json:"known_divergence,omitempty"`
	Problem string `json:"problem,omitempty"`
}

// ReplayReport is the result of replaying a corpus.
type ReplayReport struct {
	Cases   []CaseResult `json:"cases"`
	Metrics *Metrics     `json:"metrics"`
	OK      bool         `json:"ok"`
}

// Replay runs every case offline against cat and holds the corpus at 100%: a
// case must conclude what it expects, and a pinned known divergence must still
// diverge (§13.7).
func Replay(ctx context.Context, cat eval.Catalog, cases []*Case) *ReplayReport {
	rep := &ReplayReport{Metrics: NewMetrics(), OK: true}
	for _, c := range cases {
		res := CaseResult{ID: c.ID}
		fail := func(format string, args ...any) {
			res.Problem = fmt.Sprintf(format, args...)
			rep.OK = false
		}
		o, err := c.oracleFor()
		if err != nil {
			fail("%v", err)
			rep.Cases = append(rep.Cases, res)
			continue
		}
		chk, err := NewRunner(cat, o).Run(ctx, c.Spec.Clone())
		if err != nil {
			fail("run: %v", err)
			rep.Cases = append(rep.Cases, res)
			continue
		}
		res.Check = chk
		if c.Known != nil {
			rep.Metrics.Excluded[ExcludedKnown]++ // pinned: held out of M1, as §13.7 allows
		} else {
			rep.Metrics.Add(*chk)
		}
		switch {
		case c.Known != nil:
			res.Known = true
			if chk.Verdict != Disagree {
				fail("pinned as a known divergence, but the check is now %s (%s); remove the pin", chk.Verdict, chk)
			}
		case c.Expect.Verdict == Excluded:
			if chk.Verdict != Excluded || chk.Exclusion != c.Expect.Exclusion {
				fail("expected exclusion %s, got %s", c.Expect.Exclusion, chk)
			}
		case chk.Verdict != Agree:
			fail("expected agreement, got %s: ours=%s theirs=%s note=%q", chk.Verdict, chk.Ours, chk.Theirs, chk.Note)
		}
		res.OK = res.Problem == ""
		rep.Cases = append(rep.Cases, res)
	}
	return rep
}
