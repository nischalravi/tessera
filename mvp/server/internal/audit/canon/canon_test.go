package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

// TestRFC8785Vectors runs the RFC 8785 test vectors (testdata/rfc8785, from
// the reference implementation, Apache-2.0) through the JCS library the
// ledger uses, so a library change that breaks canonicalization fails here.
func TestRFC8785Vectors(t *testing.T) {
	inputs, err := filepath.Glob("testdata/rfc8785/input/*.json")
	if err != nil || len(inputs) < 10 {
		t.Fatalf("vectors: %v (%d)", err, len(inputs))
	}
	for _, in := range inputs {
		name := filepath.Base(in)
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(in) // #nosec G304 -- test vectors
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata/rfc8785/output", name)) // #nosec G304 -- test vectors
			if err != nil {
				t.Fatal(err)
			}
			got, err := jcs.Transform(src)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, bytes.TrimRight(want, "\n")) {
				t.Errorf("JCS mismatch:\n got  %s\n want %s", got, want)
			}
		})
	}
}

func TestGenesis(t *testing.T) {
	g := Genesis("00000000-0000-0000-0000-000000000001")
	if !IsHash(g) || g == Genesis("00000000-0000-0000-0000-000000000002") {
		t.Errorf("genesis %s", g)
	}
	// SHA-256("tessera-audit-genesis-v1:00000000-0000-0000-0000-000000000001"), computed independently
	if g != "d58a7a81f3cc09c22172f10839b405733ded60985757b136536af96e1ad5d309" {
		t.Errorf("genesis %s", g)
	}
}

type stringer struct{}

func (stringer) String() string { return "stringer" }

type report struct {
	Items []string `json:"items"`
	Count int      `json:"count"`
}

type scored struct {
	Score float64 `json:"score"`
}

func TestDetail(t *testing.T) {
	ts := time.Date(2026, 10, 8, 9, 30, 0, 123456789, time.FixedZone("x", 3600))
	ok := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, `{}`},
		{"ordered", ojson.Object{{Key: "b", Value: 1}, {Key: "a", Value: "x"}}, `{"b":1,"a":"x"}`},
		{"map sorted", map[string]any{"b": true, "a": nil}, `{"a":null,"b":true}`},
		{"nested", ojson.Object{{Key: "l", Value: []any{int64(1), "two", ojson.Object{{Key: "k", Value: false}}}}}, `{"l":[1,"two",{"k":false}]}`},
		{"time", ojson.Object{{Key: "t", Value: ts}}, `{"t":"2026-10-08T08:30:00.123456Z"}`},
		{"stringer", ojson.Object{{Key: "s", Value: stringer{}}}, `{"s":"stringer"}`},
		{"struct", ojson.Object{{Key: "r", Value: report{Items: []string{"a"}, Count: 2}}}, `{"r":{"items":["a"],"count":2}}`},
		{"string slice", ojson.Object{{Key: "s", Value: []string{"x", "y"}}}, `{"s":["x","y"]}`},
		{"max safe int", ojson.Object{{Key: "n", Value: int64(MaxSafeInt)}}, `{"n":9007199254740991}`},
		{"json number", ojson.Object{{Key: "n", Value: json.Number("42")}}, `{"n":42}`},
		{"raw", ojson.Object{{Key: "r", Value: json.RawMessage(`{"z":1,"a":[true]}`)}}, `{"r":{"z":1,"a":[true]}}`},
		{"unicode", ojson.Object{{Key: "€", Value: "</script> ö 😂"}}, `{"€":"</script> ö 😂"}`},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Detail(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
			if again, err := DetailJSON(got); err != nil || string(again) != string(got) {
				t.Errorf("not stable: %s %v", again, err)
			}
		})
	}
	bad := []struct {
		name string
		in   any
	}{
		{"float64", ojson.Object{{Key: "f", Value: 1.5}}},
		{"whole float64", ojson.Object{{Key: "f", Value: 2.0}}},
		{"float32", ojson.Object{{Key: "f", Value: float32(1)}}},
		{"ojson float", ojson.Object{{Key: "f", Value: ojson.Float(4)}}},
		{"float in struct", ojson.Object{{Key: "s", Value: scored{Score: 0.5}}}},
		{"fractional json number", ojson.Object{{Key: "n", Value: json.Number("1.0")}}},
		{"too big", ojson.Object{{Key: "n", Value: int64(MaxSafeInt + 1)}}},
		{"too small", ojson.Object{{Key: "n", Value: int64(-MaxSafeInt - 1)}}},
		{"uint64 too big", ojson.Object{{Key: "n", Value: uint64(math.MaxUint64)}}},
		{"not an object", []any{1}},
		{"string", "detail"},
		{"duplicate key", ojson.Object{{Key: "a", Value: 1}, {Key: "a", Value: 2}}},
		{"channel", ojson.Object{{Key: "c", Value: make(chan int)}}},
		{"int keys", ojson.Object{{Key: "m", Value: map[int]string{1: "x"}}}},
		{"oversize", ojson.Object{{Key: "s", Value: strings.Repeat("x", MaxDetailBytes)}}},
	}
	for _, tc := range bad {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			if got, err := Detail(tc.in); !errors.Is(err, ErrDetail) {
				t.Errorf("accepted: %s (%v)", got, err)
			}
		})
	}
	deep := any("leaf")
	for range maxDepth + 2 {
		deep = []any{deep}
	}
	if _, err := Detail(ojson.Object{{Key: "d", Value: deep}}); !errors.Is(err, ErrDetail) {
		t.Errorf("deep nesting accepted: %v", err)
	}
}

func body() Body {
	id := "a"
	return Body{V: Version, TenantID: "t", Seq: 1, ID: "e", OccurredAt: "2026-10-08T09:30:00.000000Z",
		Actor: Actor{Type: "system", ID: &id, Display: &id}, Action: "x", Outcome: "success",
		Detail: json.RawMessage(`{"b":1,"a":2}`), PrevHash: Genesis("t")}
}

// TestHashIgnoresMemberOrderAndWhitespace: the hash is over the JCS form, so
// re-encoding the detail (order, whitespace, escapes) does not change it, and
// every field change does.
func TestHashIgnoresMemberOrderAndWhitespace(t *testing.T) {
	b := body()
	h1, err := Hash(b)
	if err != nil {
		t.Fatal(err)
	}
	b.Detail = json.RawMessage("{ \"a\" : 2,\n \"b\":1 }")
	if h2, _ := Hash(b); h2 != h1 {
		t.Error("member order or whitespace changed the hash")
	}
	b.Detail = json.RawMessage(`{"a":2,"b":1,"c":null}`)
	if h3, _ := Hash(b); h3 == h1 {
		t.Error("an added detail member did not change the hash")
	}
	b = body()
	b.Seq = 2
	if h4, _ := Hash(b); h4 == h1 {
		t.Error("seq is not hashed")
	}
	b = body()
	b.Detail = nil
	if _, err := Hash(b); err == nil {
		t.Error("an empty detail was hashed")
	}
}
