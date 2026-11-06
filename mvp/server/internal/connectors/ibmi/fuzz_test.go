package ibmi

import (
	"bytes"
	"runtime"
	"strings"
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
// never accept an invalid name or more than pageRows rows.
func FuzzDecodeReply(f *testing.F) {
	for _, s := range []string{`{"id":"t2","success":true,"is_done":true,"data":[{"AUTHORIZATION_NAME":"A"}]}`, `{}`, `[]`, `null`,
		`{"id":"t2","success":true,"data":[{"AUTHORIZATION_NAME":1}]}`, `{"id":"t2","success":true,"data":[null]}`, `{"data":{"a":[[[[]]]]}}`, `{"id":"t2","success":true,"ID":"x"}`, `{"id":"t2","id":"t2","success":true}`, `{"id":"t2","success":true,"data":[{"AUTHORIZATION_NAME":""}]}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := decodeReply([]byte(s), "t2")
		if err != nil {
			return
		}
		for _, p := range r.Data {
			if !nameRE.MatchString(p.Name) {
				t.Fatalf("a profile with an invalid name was accepted: %q", s)
			}
		}
		if len(r.Data) > pageRows {
			t.Fatalf("%d rows", len(r.Data))
		}
	})
}

// TestDecodeReply_BoundedAndExact: the decoder refuses what a rogue endpoint
// can send to cost memory, and matches keys exactly.
func TestDecodeReply_BoundedAndExact(t *testing.T) {
	// A reply of the largest allowed size made of empty rows is refused after
	// pageRows+1 rows, and costs a small, bounded amount of memory.
	big := []byte(`{"id":"t2","success":true,"data":[` + strings.Repeat("{},", maxMessage/3-64) + `{}]}`)
	if len(big) < maxMessage-1024 {
		t.Fatalf("test reply is %d bytes", len(big))
	}
	if _, err := decodeReply(big, "t2"); err != errProtocol && err != errOversize {
		t.Errorf("big reply: %v", err)
	}
	var ms0, ms1 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	_, _ = decodeReply(big, "t2")
	runtime.ReadMemStats(&ms1)
	if used := ms1.TotalAlloc - ms0.TotalAlloc; used > 2<<20 {
		t.Errorf("decoding a %d byte reply allocated %d bytes", len(big), used)
	}
	row := `{"AUTHORIZATION_NAME":"A"}`
	for name, in := range map[string]string{
		"too many rows":     `{"id":"t2","success":true,"data":[` + strings.Repeat(row+",", pageRows) + row + `]}`,
		"empty name":        `{"id":"t2","success":true,"data":[{"AUTHORIZATION_NAME":""}]}`,
		"invalid name":      `{"id":"t2","success":true,"data":[{"AUTHORIZATION_NAME":"1BAD"}]}`,
		"duplicate id":      `{"id":"t2","id":"t2","success":true}`,
		"duplicate success": `{"id":"t2","success":false,"success":true}`,
		"case variant key":  `{"id":"t2","success":true,"Is_Done":true}`,
		"case variant ID":   `{"ID":"t2","success":true}`,
		"duplicate column":  `{"id":"t2","success":true,"data":[{"AUTHORIZATION_NAME":"A","AUTHORIZATION_NAME":"B"}]}`,
		"lower-case column": `{"id":"t2","success":true,"data":[{"AUTHORIZATION_NAME":"A","status":"*ENABLED"}]}`,
		"trailing data":     `{"id":"t2","success":true} {}`,
		"field too long":    `{"id":"t2","success":true,"data":[{"AUTHORIZATION_NAME":"A","TEXT_DESCRIPTION":"` + strings.Repeat("x", maxFieldLen+1) + `"}]}`,
		"non-string column": `{"id":"t2","success":true,"data":[{"AUTHORIZATION_NAME":"A","STATUS":1}]}`,
	} {
		if _, err := decodeReply([]byte(in), "t2"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := `{"id":"t2","success":true,"is_done":true,"error":"x","data":[` + row + `,{"AUTHORIZATION_NAME":"B","extra":[1,{"a":2}],"STATUS":null}]}`
	if r, err := decodeReply([]byte(ok), "t2"); err != nil || len(r.Data) != 2 || !r.IsDone {
		t.Errorf("valid reply: %v %+v", err, r)
	}
}

func TestValidHost(t *testing.T) {
	for h, want := range map[string]bool{"ibmi.corp.example": true, "10.1.2.3": true, "::1": true, "host.": true, "a b": false, "a\r\nX: y": false,
		"a@b": false, "a/b": false, "": false, "-a.b": false, "a:80": false} {
		if got := validHost(h); got != want {
			t.Errorf("validHost(%q) = %v", h, got)
		}
	}
}
