package api

import (
	"net/http"
	"testing"
)

// POST /api/connectors/sync?mode=full asks connectors to ignore their
// checkpoints (issue #104); only "incremental" and "full" are accepted.
func TestSyncConnectors_Mode(t *testing.T) {
	c := newRD(t)
	for _, tc := range []struct {
		query string
		code  int
	}{
		{"", http.StatusOK},
		{"?mode=incremental", http.StatusOK},
		{"?mode=full", http.StatusOK},
		{"?mode=FULL", http.StatusUnprocessableEntity},
		{"?mode=everything", http.StatusUnprocessableEntity},
		{"?mode=", http.StatusUnprocessableEntity},
	} {
		if rec := c.do("POST", "/api/connectors/sync"+tc.query, ""); rec.Code != tc.code {
			t.Errorf("POST /api/connectors/sync%s = %d, want %d: %s", tc.query, rec.Code, tc.code, rec.Body)
		}
	}
}
