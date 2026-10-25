package readiness

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
)

// Only the governed templates whose system cannot report the integration's rights may have an
// attestation stand in for the write-scope check. Every other template (SCIM has real write-back
// and answers "unsupported") keeps the live check as the only proof, so least privilege cannot be
// attested past the gate.
func TestWriteScopeAttestationOnlyWhereRightsCannotBeRead(t *testing.T) {
	reg := template.MustDefault()
	attestable := map[string]bool{"erp": true, "awsorg": true, "githubscan": true, "vms": true, "agentcore": true, "azurerbac": true, "gcpiam": true, "unixssh": true, "servicenow": true, "atlassian": true, "mcp": true, "bedrock": true}
	for _, id := range reg.IDs() {
		r, _ := reg.Get(id)
		it, ok := r.Item("base.writeback.scope")
		if !ok {
			t.Fatalf("%s: no base.writeback.scope", id)
		}
		if it.HasLiveAlternative() != attestable[id] {
			t.Errorf("%s: write-scope attestation allowed = %v, want %v", id, it.HasLiveAlternative(), attestable[id])
		}
	}
	// scim_app: the item is live-only, so without a passing live result it stays pending
	st, s := newStore(t), newSvc(t)
	id := createGov(t, s, st, "scim_app", "Payroll", `{"base_url":"https://example.com/scim/v2","write_mode":"scoped","write_scope":["g1"]}`)
	b, err := current(st, s, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	it, ok := b.Eval.Item("base.writeback.scope")
	if !ok || !it.Applicable || it.Status == StatusPass || it.HasKind(template.Attestation) {
		t.Errorf("scim_app write scope without a live result: %+v", it)
	}
}
