package awsorg

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
)

var testNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

const (
	baseKeyID     = "AKIAEXAMPLEEXAMPLE1"
	baseSecret    = "baseSecretKeyForTestsOnly0123456789abcd"
	sessionKeyID  = "ASIAEXAMPLEEXAMPLE1"
	sessionSecret = "secretsecretsecretsecretsecret0123456789"
	externalID    = "tessera-test-external-id"
)

func baseCreds() sigv4.Credentials {
	return sigv4.Credentials{AccessKeyID: baseKeyID, SecretAccessKey: baseSecret}
}

// newReplay serves the recorded fixtures of testdata/http, verifies every
// signature, and serves the last STS reply (and every other last recording)
// again to later accounts.
func newReplay(t *testing.T) *awstest.Replay {
	t.Helper()
	r := awstest.NewReplay(os.DirFS("testdata/http"))
	r.RepeatLast = true
	r.Verify(baseKeyID, baseSecret).Verify(sessionKeyID, sessionSecret)
	return r
}

// testClient is a client over doer with a frozen clock, no real sleeping and
// no jitter, recording the waits.
func testClient(doer Doer, sleeps *[]time.Duration) *Client {
	now := testNow
	return &Client{HTTP: doer,
		Now: func() time.Time { now = now.Add(time.Second); return now },
		Sleep: func(ctx context.Context, d time.Duration) error {
			if sleeps != nil {
				*sleeps = append(*sleeps, d)
			}
			return ctx.Err()
		},
		Jitter: func(max time.Duration) time.Duration { return max }}
}

// orgConfig is the estate of the fixtures: an organization with a management
// account, one active member account and one suspended one.
func orgConfig() *Config {
	return &Config{Regions: []string{"us-east-1"}, ManagementAccountID: "111111111111", IdentityCenterRegion: "us-east-1"}
}

func newCollector(t *testing.T, r *awstest.Replay, cfg *Config) *Collector {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return &Collector{Client: testClient(r, nil), Config: cfg, Base: baseCreds(), ExternalID: externalID,
		Now: func() time.Time { return testNow }}
}

func collectFixtures(t *testing.T) (*Collection, *awstest.Replay) {
	t.Helper()
	r := newReplay(t)
	col, err := newCollector(t, r, orgConfig()).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if u := r.Unrecorded(); len(u) > 0 {
		t.Fatalf("calls with no recording: %v", u)
	}
	if b := r.BadSignatures(); len(b) > 0 {
		t.Fatalf("bad signatures: %v", b)
	}
	return col, r
}

// fixture reads one recorded response.
func fixture(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "http", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func findFinding(fs Findings, kind, sourceContains string) *Finding {
	for i := range fs {
		if fs[i].Kind == kind && strings.Contains(fs[i].SourceARN, sourceContains) {
			return &fs[i]
		}
	}
	return nil
}
