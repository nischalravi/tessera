package scim

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscover(t *testing.T) {
	big := `{"x":"` + strings.Repeat("a", maxBody+10) + `"}`
	tests := []struct {
		name      string
		spc, rt   string
		spcStatus int
		wantAgent bool
		wantSPC   bool
		wantTypes int
		wantErr   bool
	}{
		{"agent by name", `{"patch":{"supported":true},"extra":1}`, `{"Resources":[{"id":"User","name":"User","x":1},{"id":"Agent","name":"Agent","schema":"` + AgentSchema + `"}]}`, 200, true, true, 2, false},
		{"agent by schema only", `{}`, `[{"name":"Bot","schema":"` + AgentSchema + `"}]`, 200, true, true, 1, false},
		{"no agent", `{}`, `{"Resources":[{"name":"User"},{"name":"Group"}]}`, 200, false, true, 2, false},
		{"spc missing, types ok", ``, `{"Resources":[{"name":"User"}]}`, 404, false, false, 1, true},
		{"types not json", `{}`, `<html>`, 200, false, true, 0, true},
		{"oversized body", big, `{"Resources":[]}`, 200, false, false, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/scim/ServiceProviderConfig":
					w.WriteHeader(tc.spcStatus)
					_, _ = w.Write([]byte(tc.spc))
				case "/scim/ResourceTypes":
					_, _ = w.Write([]byte(tc.rt))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			c := &Client{HTTP: srv.Client(), BaseURL: srv.URL + "/scim"}
			d, err := c.Discover(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if d.AgentAdvertised != tc.wantAgent || d.ServiceProviderConfig != tc.wantSPC || len(d.ResourceTypes) != tc.wantTypes {
				t.Fatalf("got %+v", d)
			}
		})
	}
}
