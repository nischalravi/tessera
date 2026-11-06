package ibmi

import (
	"bytes"
	"testing"
)

// FuzzReadFrame: whatever a server sends, the frame decoder never panics,
// never allocates past its cap, and either returns a frame within the cap or
// an error.
func FuzzReadFrame(f *testing.F) {
	for _, s := range [][]byte{{0x81, 0x02, 'h', 'i'}, {0x81, 126, 0, 5, 1, 2, 3, 4, 5}, {0x81, 127, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x88, 0x00}, {0xC1, 0x00}, {0x81, 0x80, 1, 2, 3, 4}, {0x09, 0x00}, {}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, p, err := readFrame(bytes.NewReader(b), 1024)
		if err == nil && len(p) > 1024 {
			t.Fatalf("payload %d over the cap", len(p))
		}
	})
}

// FuzzDecodeReply: the JSON reply decoder and the row mapper never panic and
// never accept a row that is not strings and nulls.
func FuzzDecodeReply(f *testing.F) {
	for _, s := range []string{`{"id":"t2","success":true,"is_done":true,"data":[{"AUTHORIZATION_NAME":"A"}]}`, `{}`, `[]`, `null`,
		`{"id":"t2","success":true,"data":[{"AUTHORIZATION_NAME":1}]}`, `{"id":"t2","success":true,"data":[null]}`, `{"data":{"a":[[[[]]]]}}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := decodeReply([]byte(s), "t2")
		if err != nil {
			return
		}
		for _, row := range r.Data {
			if p, err := profileOf(row); err == nil && p.Name == "" {
				t.Fatalf("a profile without a name was accepted: %q", s)
			}
		}
	})
}
