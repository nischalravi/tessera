package awstest

import (
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func formReq(t *testing.T, host, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "https://"+host+"/", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

type fakeInner struct {
	status int
	body   string
	calls  int
}

func (f *fakeInner) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	b, _ := io.ReadAll(req.Body) // the forwarded body must still be readable
	if len(b) == 0 {
		return nil, errors.New("fakeInner: empty body forwarded")
	}
	h := http.Header{}
	h.Set("Content-Type", "text/xml")
	h.Set("Retry-After", "3")
	h.Set("Authorization", "AWS4-HMAC-SHA256 Credential=SECRET") // must never be stored
	return &http.Response{StatusCode: f.status, Header: h, Body: io.NopCloser(strings.NewReader(f.body))}, nil
}

func TestCanonicalIgnoresParameterOrderAndHostCase(t *testing.T) {
	a := Canonical(formReq(t, "IAM.amazonaws.com", "Action=Simulate&B=2&A=1&A=0"), []byte("Action=Simulate&B=2&A=1&A=0"))
	b := Canonical(formReq(t, "iam.amazonaws.com", "A=0&A=1&B=2&Action=Simulate"), []byte("A=0&A=1&B=2&Action=Simulate"))
	if a != b {
		t.Fatalf("%q != %q", a, b)
	}
	c := Canonical(formReq(t, "iam.amazonaws.com", "Action=Simulate&B=3&A=1&A=0"), []byte("Action=Simulate&B=3&A=1&A=0"))
	if a == c {
		t.Fatal("different values gave the same canonical text")
	}
	if Key("v1", a) == Key("v2", a) {
		t.Fatal("the fixture version is not part of the key")
	}
}

func TestRecordThenReplay(t *testing.T) {
	inner := &fakeInner{status: 200, body: "<ok/>"}
	rec, err := NewRecorder(inner, "fx-1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // the same request twice: two responses under one key
		resp, err := rec.Do(formReq(t, "iam.amazonaws.com", "Action=X&Marker=m"))
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := io.ReadAll(resp.Body); string(b) != "<ok/>" {
			t.Fatalf("body %q", b)
		}
	}
	if _, err := rec.Do(formReq(t, "iam.amazonaws.com", "Action=X")); err != nil {
		t.Fatal(err)
	}
	c := rec.Cassette()
	if len(c.Entries) != 2 || inner.calls != 3 {
		t.Fatalf("%d entries, %d calls", len(c.Entries), inner.calls)
	}
	for _, e := range c.Entries {
		for _, r := range e.Responses {
			if _, ok := r.Headers["Authorization"]; ok {
				t.Fatal("a credential header was recorded")
			}
			if r.Headers["Retry-After"] != "3" {
				t.Fatalf("headers %v", r.Headers)
			}
		}
	}

	path := filepath.Join(t.TempDir(), "c.json")
	if err := rec.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rp := NewReplay(loaded)
	for i := 0; i < 2; i++ {
		resp, err := rp.Do(formReq(t, "iam.amazonaws.com", "Marker=m&Action=X"))
		if err != nil || resp.StatusCode != 200 || resp.Header.Get("Retry-After") != "3" {
			t.Fatalf("%v %v", resp, err)
		}
	}
	// The third ask has nothing left: an error, never a repeat.
	if _, err := rp.Do(formReq(t, "iam.amazonaws.com", "Marker=m&Action=X")); !errors.Is(err, ErrCassetteExhausted) {
		t.Fatalf("err %v", err)
	}
	// An unrecorded request names itself.
	_, err = rp.Do(formReq(t, "iam.amazonaws.com", "Action=Y"))
	if !errors.Is(err, ErrNoRecording) || !strings.Contains(err.Error(), "Action=Y") {
		t.Fatalf("err %v", err)
	}
	// Another fixture version never matches the same cassette entries.
	other := *loaded
	other.FixtureVersion = "fx-2"
	if _, err := NewReplay(&other).Do(formReq(t, "iam.amazonaws.com", "Action=X")); !errors.Is(err, ErrNoRecording) {
		t.Fatalf("err %v", err)
	}
	if _, err := NewRecorder(nil, "x"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("err %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string]string{
		"no version":    `{"entries":[]}`,
		"unknown field": `{"fixture_version":"v","extra":1}`,
		"empty key":     `{"fixture_version":"v","entries":[{"key":"","responses":[{"status":200}]}]}`,
		"dup key":       `{"fixture_version":"v","entries":[{"key":"a","responses":[{"status":200}]},{"key":"a","responses":[{"status":200}]}]}`,
		"no responses":  `{"fixture_version":"v","entries":[{"key":"a","responses":[]}]}`,
		"not json":      `nope`,
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
