package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// ExportRecord returns the portable form of an event: exactly the hashed body
// (canon.Body) plus "hash". An offline verifier removes "hash", applies RFC
// 8785 to the rest, and checks SHA-256("tessera-audit-v1" 0x00 || that) ==
// hash, and that prev_hash is the previous record's hash (genesis:
// SHA-256("tessera-audit-genesis-v1:" + tenant_id)).
func ExportRecord(e *Event) (ojson.Object, error) {
	raw, err := json.Marshal(e.Body())
	if err != nil {
		return nil, err
	}
	v, err := ojson.Decode(raw)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(ojson.Object)
	if !ok {
		return nil, fmt.Errorf("audit: export: body is %T", v)
	}
	return append(obj, ojson.KV{Key: "hash", Value: e.Hash}), nil
}

// VerifyRecord recomputes the hash of an exported record and compares it with
// the record's "hash" member.
func VerifyRecord(line []byte) (ok bool, hash string, err error) {
	v, err := ojson.Decode(line)
	if err != nil {
		return false, "", err
	}
	obj, isObj := v.(ojson.Object)
	if !isObj {
		return false, "", fmt.Errorf("audit: record is not an object")
	}
	var claimed string
	body := make(ojson.Object, 0, len(obj))
	for _, kv := range obj {
		if kv.Key == "hash" {
			claimed, _ = kv.Value.(string)
			continue
		}
		body = append(body, kv)
	}
	raw, err := ojson.Marshal(body)
	if err != nil {
		return false, "", err
	}
	var b canon.Body
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return false, "", fmt.Errorf("audit: record: %w", err)
	}
	got, err := canon.Hash(b)
	if err != nil {
		return false, "", err
	}
	return got == claimed, got, nil
}

// exportPage is how many events one read transaction streams.
const exportPage = 500

// Export writes the tenant's events with fromSeq <= seq <= toSeq (toSeq 0:
// to the end) as NDJSON, one ExportRecord per line, in seq order. Each page
// is read in its own read-only transaction. It returns the number of events
// written.
func Export(ctx context.Context, db *store.DB, t tenancy.ID, fromSeq, toSeq int64, w io.Writer) (int64, error) {
	if fromSeq < 1 {
		fromSeq = 1
	}
	bw := bufio.NewWriter(w)
	var n int64
	for {
		var page []*Event
		if err := db.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
			var err error
			page, err = tx.AuditEventsRange(fromSeq, toSeq, exportPage)
			return err
		}); err != nil {
			return n, err
		}
		for _, e := range page {
			rec, err := ExportRecord(e)
			if err != nil {
				return n, err
			}
			line, err := ojson.Marshal(rec)
			if err != nil {
				return n, err
			}
			if _, err := bw.Write(append(line, '\n')); err != nil {
				return n, err
			}
			n++
			fromSeq = e.Seq + 1
		}
		if err := bw.Flush(); err != nil {
			return n, err
		}
		if f, ok := w.(interface{ Flush() }); ok {
			f.Flush()
		}
		if len(page) < exportPage {
			return n, nil
		}
		if err := ctx.Err(); err != nil {
			return n, err
		}
	}
}
