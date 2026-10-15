package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

// newStore opens a fresh database with one tenant and returns that tenant's scope.
func newStore(t *testing.T) Scope {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var tn store.Tenant
	if err := db.InSystem(context.Background(), "test", func(s *store.SystemTx) error {
		var err error
		tn, err = s.CreateTenant(store.Tenant{Slug: "larkspur", Name: "Larkspur Labs"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return Scope{DB: db, Tenant: tn.ID}
}

// read runs fn in a read-only transaction of the test tenant.
func read(t *testing.T, st Scope, fn func(c *store.TenantTx) error) {
	t.Helper()
	if err := st.Read(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

// current is Service.Current in a read transaction of the test tenant.
func current(st Scope, s *Service, id string, now time.Time) (b *Bundle, err error) {
	err = st.Read(context.Background(), func(c *store.TenantTx) error {
		var err error
		b, err = s.Current(c, id, now)
		return err
	})
	return b, err
}

func newSvc(t *testing.T) *Service {
	t.Helper()
	return NewService(template.MustDefault(), "")
}

func write(t *testing.T, st Scope, fn func(c *store.TenantTx) error) {
	t.Helper()
	if err := st.Write(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

// fakeEvidence fills passing live and data results (bound to the current
// item hashes) for every item, except those in fail, and lets a test add
// findings. It stands in for validation and dry runs.
type fakeEvidence struct {
	mu       sync.Mutex
	on       bool
	fail     map[string]bool // item ids whose checks fail
	findings []FindingInfo
	runAt    time.Time
}

func (f *fakeEvidence) install(s *Service) {
	s.extraEvidence = func(c *store.TenantTx, rev *store.ConnectionRevision, ev *Evidence) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !f.on {
			return
		}
		conn, err := c.Connection(rev.ConnectionID)
		if err != nil {
			panic(err)
		}
		tmpl, err := s.templateFor(c, rev.TemplateID, rev.TemplateVersion, rev.OverlayVersion)
		if err != nil {
			panic(err)
		}
		cfg, _ := DecodeConfig([]byte(rev.Config))
		in := hashInput(conn, rev, cfg)
		full, _ := in.ConfigHash()
		at := f.runAt
		ev.LiveRun = &RunInfo{ID: "live-1", Kind: "validation", Status: "completed", ConfigHash: full, Simulated: true, StartedAt: at, FinishedAt: &at}
		ev.DataRun = &RunInfo{ID: "data-1", Kind: "dry_run", Status: "completed", ConfigHash: full, Simulated: true, StartedAt: at, FinishedAt: &at}
		for _, it := range tmpl.Items {
			h, _ := in.ItemHash(it.ConfigFields)
			for _, v := range it.Verify {
				st := "pass"
				if f.fail[it.ID] {
					st = "fail"
				}
				r := &ResultInfo{ItemID: it.ID, CheckID: v.Check, Status: st, ItemHash: h, Simulated: true, Message: "simulated"}
				switch v.Kind {
				case template.Live:
					ev.Live[resultKey{it.ID, v.Check}] = r
				case template.Data:
					ev.Data[resultKey{it.ID, v.Check}] = r
				}
			}
		}
		ev.Findings = append(ev.Findings, f.findings...)
	}
}

// adAttestations are the attestations a demo AD connection needs to activate.
var adAttestations = []string{"base.owner", "base.correlation.key", "base.scope.count", "base.stale.threshold",
	"base.schedule", "ad.svc.password", "ad.scope.service_accounts", "ad.groups.privileged", "ad.topo.gc"}

func createAD(t *testing.T, s *Service, st Scope, name string) string {
	t.Helper()
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: name, ConnectorType: "demo-ad", System: strings.ToLower(strings.ReplaceAll(name, " ", "-")),
			Config: json.RawMessage(`{"technical_owner":"Ingrid Lindqvist","business_owner":"Thandiwe Mokoena"}`)}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		_, err = s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/tessera/ad"}, "admin", t0)
		return err
	})
	return id
}

// readyToActivate drives a demo AD connection to dry_run_reconciled.
func readyToActivate(t *testing.T, s *Service, st Scope, id string) {
	t.Helper()
	write(t, st, func(c *store.TenantTx) error {
		for _, item := range adAttestations {
			if _, err := s.Attest(c, id, item, "checked in the console", "admin", t0); err != nil {
				return err
			}
		}
		if _, err := s.Skip(c, id, "ad.tls.signing_cb", "Scheduled for the Q1 domain controller upgrade", nil, "admin", t0); err != nil {
			return err
		}
		if _, err := s.Transition(c, id, store.StateReadyToValidate, "admin", t0); err != nil {
			return err
		}
		b, err := s.Current(c, id, t0)
		if err != nil {
			return err
		}
		if err := s.advanceAfterValidation(c, b, "admin", t0); err != nil {
			return err
		}
		_, err = s.Transition(c, id, store.StateDryRunReconciled, "admin", t0)
		return err
	})
}

func state(t *testing.T, s *Service, st Scope, id string) string {
	t.Helper()
	b, err := current(st, s, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	return b.Rev.State
}

func codeOf(err error) string {
	var re *Error
	if errors.As(err, &re) {
		return re.Code
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return ""
}

func TestStateMachine_AllTransitions(t *testing.T) {
	states := []string{store.StateDraft, store.StateReadyToValidate, store.StateValidated, store.StateDryRunReconciled,
		store.StateActive, store.StateDegraded, store.StateRetired, store.StateSuperseded}
	allowed := map[[2]string]bool{
		{"draft", "ready_to_validate"}: true, {"draft", "retired"}: true,
		{"ready_to_validate", "validated"}: true, {"ready_to_validate", "draft"}: true, {"ready_to_validate", "retired"}: true,
		{"validated", "dry_run_reconciled"}: true, {"validated", "ready_to_validate"}: true, {"validated", "retired"}: true,
		{"dry_run_reconciled", "active"}: true, {"dry_run_reconciled", "validated"}: true, {"dry_run_reconciled", "retired"}: true,
		{"active", "degraded"}: true, {"active", "retired"}: true, {"active", "superseded"}: true,
		{"degraded", "active"}: true, {"degraded", "retired"}: true, {"degraded", "superseded"}: true,
	}
	for _, from := range states {
		for _, to := range states {
			if got := CanTransition(from, to); got != allowed[[2]string{from, to}] {
				t.Errorf("CanTransition(%s, %s) = %v", from, to, got)
			}
		}
	}

	// Every (state, user action) pair against a real revision. Evidence is
	// complete, so only the state decides.
	type action struct {
		name string
		run  func(s *Service, c *store.TenantTx, id string) error
	}
	actions := []action{
		{"to_ready", func(s *Service, c *store.TenantTx, id string) error {
			_, err := s.Transition(c, id, store.StateReadyToValidate, "admin", t0)
			return err
		}},
		{"to_reconciled", func(s *Service, c *store.TenantTx, id string) error {
			_, err := s.Transition(c, id, store.StateDryRunReconciled, "admin", t0)
			return err
		}},
		{"to_active_via_transition", func(s *Service, c *store.TenantTx, id string) error {
			_, err := s.Transition(c, id, store.StateActive, "admin", t0)
			return err
		}},
		{"activate", func(s *Service, c *store.TenantTx, id string) error {
			_, _, err := s.Activate(c, id, "admin", t0)
			return err
		}},
		{"retire", func(s *Service, c *store.TenantTx, id string) error { return s.Retire(c, id, "admin", t0) }},
		{"degrade", func(s *Service, c *store.TenantTx, id string) error { return s.Degrade(c, id, "test", t0) }},
		{"recover", func(s *Service, c *store.TenantTx, id string) error { return s.Recover(c, id, "test", t0) }},
	}
	// want[state][action] is "" (allowed) or the error code.
	want := map[string]map[string]string{
		"draft": {"to_ready": "", "to_reconciled": "transition_blocked", "to_active_via_transition": "invalid_target",
			"activate": "activation_blocked", "retire": "", "degrade": "invalid_transition", "recover": "invalid_transition"},
		"ready_to_validate": {"to_ready": "transition_blocked", "to_reconciled": "transition_blocked", "to_active_via_transition": "invalid_target",
			"activate": "activation_blocked", "retire": "", "degrade": "invalid_transition", "recover": "invalid_transition"},
		"validated": {"to_ready": "transition_blocked", "to_reconciled": "", "to_active_via_transition": "invalid_target",
			"activate": "activation_blocked", "retire": "", "degrade": "invalid_transition", "recover": "invalid_transition"},
		"dry_run_reconciled": {"to_ready": "transition_blocked", "to_reconciled": "transition_blocked", "to_active_via_transition": "invalid_target",
			"activate": "", "retire": "", "degrade": "invalid_transition", "recover": "invalid_transition"},
		"active": {"to_ready": "no_pending_revision", "to_reconciled": "no_pending_revision", "to_active_via_transition": "invalid_target",
			"activate": "no_pending_revision", "retire": "", "degrade": "", "recover": "invalid_transition"},
		"degraded": {"to_ready": "no_pending_revision", "to_reconciled": "no_pending_revision", "to_active_via_transition": "invalid_target",
			"activate": "no_pending_revision", "retire": "", "degrade": "invalid_transition", "recover": ""},
		"retired": {"to_ready": "no_pending_revision", "to_reconciled": "no_pending_revision", "to_active_via_transition": "invalid_target",
			"activate": "connection_retired", "retire": "connection_retired", "degrade": "invalid_transition", "recover": "invalid_transition"},
	}
	// One store for every case; each case drives its own connection.
	st := newStore(t)
	s := newSvc(t)
	fe := &fakeEvidence{on: true, runAt: t0}
	fe.install(s)
	froms := []string{"draft", "ready_to_validate", "validated", "dry_run_reconciled", "active", "degraded", "retired"}
	if raceEnabled {
		froms = []string{"draft", "dry_run_reconciled", "active"}
	}
	for _, from := range froms {
		for _, a := range actions {
			t.Run(from+"/"+a.name, func(t *testing.T) {
				id := createAD(t, s, st, "AD "+from+" "+strings.ReplaceAll(a.name, "_", " "))
				driveTo(t, s, st, id, from)
				err := st.Write(context.Background(), func(c *store.TenantTx) error { return a.run(s, c, id) })
				if got := codeOf(err); got != want[from][a.name] {
					t.Fatalf("%s from %s: got %q, want %q", a.name, from, got, want[from][a.name])
				}
			})
		}
	}
}

// driveTo moves a fresh demo AD connection to state through the real gates.
func driveTo(t *testing.T, s *Service, st Scope, id, target string) {
	t.Helper()
	order := []string{"draft", "ready_to_validate", "validated", "dry_run_reconciled", "active"}
	if target == "degraded" || target == "retired" {
		driveTo(t, s, st, id, "active")
		write(t, st, func(c *store.TenantTx) error {
			if target == "degraded" {
				return s.Degrade(c, id, "test", t0)
			}
			return s.Retire(c, id, "admin", t0)
		})
		return
	}
	n := slices.Index(order, target)
	write(t, st, func(c *store.TenantTx) error {
		for _, item := range adAttestations {
			if _, err := s.Attest(c, id, item, "checked in the console", "admin", t0); err != nil {
				return err
			}
		}
		_, err := s.Skip(c, id, "ad.tls.signing_cb", "Scheduled for the Q1 domain controller upgrade", nil, "admin", t0)
		return err
	})
	for i := 1; i <= n; i++ {
		write(t, st, func(c *store.TenantTx) error {
			switch order[i] {
			case "ready_to_validate":
				_, err := s.Transition(c, id, store.StateReadyToValidate, "admin", t0)
				return err
			case "validated":
				b, err := s.Current(c, id, t0)
				if err != nil {
					return err
				}
				return s.advanceAfterValidation(c, b, "admin", t0)
			case "dry_run_reconciled":
				_, err := s.Transition(c, id, store.StateDryRunReconciled, "admin", t0)
				return err
			default:
				_, _, err := s.Activate(c, id, "admin", t0)
				return err
			}
		})
	}
	if got := state(t, s, st, id); got != target && !(target == "active" && got == "active") {
		t.Fatalf("driveTo %s: at %s", target, got)
	}
}

// passingBundle is an in-memory demo AD revision whose every gate holds.
func passingBundle(t *testing.T) *Bundle {
	t.Helper()
	reg := template.MustDefault()
	tmpl, _ := reg.Get("ad")
	cfg := DefaultConfig("demo-ad", tmpl)
	cfg.TechnicalOwner, cfg.BusinessOwner = "Ingrid", "Thandiwe"
	ref, ver := "vault:kv/ad", "v1"
	conn := &store.Connection{ID: "c1", Name: "AD", ConnectorType: "demo-ad", System: "ad-corp", Role: "account_source"}
	rev := &store.ConnectionRevision{ID: "r1", ConnectionID: "c1", State: store.StateDryRunReconciled, TemplateID: "ad",
		TemplateVersion: "1.0", SecretRef: &ref, SecretVersion: &ver, WriteMode: "off"}
	b := &Bundle{Conn: conn, Rev: rev, Template: tmpl, Config: cfg, Hash: hashInput(conn, rev, cfg), LiveTTL: DefaultLiveTTL}
	b.ConfigHash, _ = b.Hash.ConfigHash()
	at := t0
	b.Evidence = &Evidence{Attestations: map[string]*store.Attestation{}, Skips: map[string]*store.Skip{},
		Live: map[resultKey]*ResultInfo{}, Data: map[resultKey]*ResultInfo{}, TenantTypes: map[string]bool{},
		LiveRun: &RunInfo{ID: "v", Status: "completed", ConfigHash: b.ConfigHash, Simulated: true, FinishedAt: &at},
		DataRun: &RunInfo{ID: "d", Status: "completed", ConfigHash: b.ConfigHash, Simulated: true, FinishedAt: &at}}
	for _, it := range tmpl.Items {
		h, _ := b.Hash.ItemHash(it.ConfigFields)
		for _, v := range it.Verify {
			switch v.Kind {
			case template.Attestation:
				b.Evidence.Attestations[it.ID] = &store.Attestation{ItemID: it.ID, ActorID: "admin", Note: "verified", ItemHash: h}
			case template.Live:
				b.Evidence.Live[resultKey{it.ID, v.Check}] = &ResultInfo{Status: "pass", ItemHash: h, Simulated: true}
			case template.Data:
				b.Evidence.Data[resultKey{it.ID, v.Check}] = &ResultInfo{Status: "pass", ItemHash: h, Simulated: true}
			}
		}
	}
	return b
}

func (b *Bundle) reeval(t *testing.T, now time.Time) *GateReport {
	t.Helper()
	if err := b.Hash.Normalize(); err != nil {
		t.Fatal(err)
	}
	var err error
	if b.ConfigHash, err = b.Hash.ConfigHash(); err != nil {
		t.Fatal(err)
	}
	if b.Eval, err = b.Evaluate(now, b.LiveTTL); err != nil {
		t.Fatal(err)
	}
	return b.Gate(store.StateActive, now)
}

func TestGate_EachConditionBlocks(t *testing.T) {
	if g := passingBundle(t).reeval(t, t0); g.Blocks() {
		t.Fatalf("baseline blocked: %+v", g.Blocking)
	}
	hashOf := func(b *Bundle, id string) string {
		it, _ := b.Template.Item(id)
		h, _ := b.Hash.ItemHash(it.ConfigFields)
		return h
	}
	cases := []struct {
		name    string
		mutate  func(b *Bundle)
		blocker string // item or finding expected among the blockers
		now     time.Time
	}{
		{"required attestation missing", func(b *Bundle) { delete(b.Evidence.Attestations, "base.owner") }, "base.owner", t0},
		{"attestation for an old config", func(b *Bundle) { b.Evidence.Attestations["base.owner"].ItemHash = "old" }, "base.owner", t0},
		{"required live check fails", func(b *Bundle) { b.Evidence.Live[resultKey{"ad.groups.range", "range_retrieval"}].Status = "fail" }, "ad.groups.range", t0},
		{"required live check errors", func(b *Bundle) { b.Evidence.Live[resultKey{"ad.bind", "bind"}].Status = "error" }, "ad.bind", t0},
		{"live result missing", func(b *Bundle) { delete(b.Evidence.Live, resultKey{"ad.tls.chain", "tls_chain"}) }, "ad.tls.chain", t0},
		{"live evidence for an old config", func(b *Bundle) { b.Evidence.Live[resultKey{"ad.bind", "bind"}].ItemHash = "old" }, "ad.bind", t0},
		{"live evidence expired", func(b *Bundle) {}, "validation", t0.Add(25 * time.Hour)},
		{"no validation run", func(b *Bundle) { b.Evidence.LiveRun = nil }, "validation", t0},
		{"required data check fails", func(b *Bundle) { b.Evidence.Data[resultKey{"base.attrs.required", "fill_rate"}].Status = "fail" }, "base.attrs.required", t0},
		{"no dry run", func(b *Bundle) { b.Evidence.DataRun = nil }, "dry_run", t0},
		{"dry run for another config", func(b *Bundle) { b.Evidence.DataRun.ConfigHash = "other" }, "dry_run", t0},
		{"open critical finding", func(b *Bundle) {
			b.Evidence.Findings = []FindingInfo{{Code: "RF-08", Severity: "critical", Status: "open", Title: "Unexpected privileged members"}}
		}, "RF-08", t0},
		{"open high finding", func(b *Bundle) {
			b.Evidence.Findings = []FindingInfo{{Code: "RF-06", Variant: "b", Severity: "high", Status: "open"}}
		}, "RF-06b", t0},
		{"recommended item pending", func(b *Bundle) { delete(b.Evidence.Attestations, "ad.tls.signing_cb") }, "ad.tls.signing_cb", t0},
		{"recommended check fails", func(b *Bundle) { b.Evidence.Data[resultKey{"ad.key.employeeid", "fill_rate"}].Status = "fail" }, "ad.key.employeeid", t0},
		{"expired skip", func(b *Bundle) {
			delete(b.Evidence.Attestations, "ad.tls.signing_cb")
			b.Evidence.Skips["ad.tls.signing_cb"] = &store.Skip{ItemID: "ad.tls.signing_cb", Reason: "Scheduled for the Q1 upgrade", ReviewBy: t0.Add(-time.Hour)}
		}, "ad.tls.signing_cb", t0},
		{"credential missing", func(b *Bundle) { b.Rev.SecretRef = nil }, "credential", t0},
		{"config invalid", func(b *Bundle) { b.Config.Host = "" }, "config.host", t0},
		{"write-back needs a second approver", func(b *Bundle) {
			b.Config.WriteMode = "scoped"
			b.Hash.Config = b.Config
			for _, id := range []string{"base.writeback.scope", "base.writeback.dryrun"} {
				h := hashOf(b, id)
				b.Evidence.Live[resultKey{id, "write_scope"}] = &ResultInfo{Status: "pass", ItemHash: h}
				b.Evidence.Attestations[id] = &store.Attestation{ItemID: id, ItemHash: h}
			}
			// every other item's evidence is bound to the old hash; re-bind it
			for _, it := range b.Template.Items {
				h := hashOf(b, it.ID)
				for k, r := range b.Evidence.Live {
					if k.item == it.ID {
						r.ItemHash = h
					}
				}
				for k, r := range b.Evidence.Data {
					if k.item == it.ID {
						r.ItemHash = h
					}
				}
				if a := b.Evidence.Attestations[it.ID]; a != nil {
					a.ItemHash = h
				}
			}
			full, _ := b.Hash.ConfigHash()
			b.Evidence.LiveRun.ConfigHash, b.Evidence.DataRun.ConfigHash = full, full
		}, "activation.approval", t0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := passingBundle(t)
			tc.mutate(b)
			b.Hash.Config = b.Config
			g := b.reeval(t, tc.now)
			found := false
			for _, x := range g.Blocking {
				if x.Item == tc.blocker || x.Finding == tc.blocker {
					found = true
				}
			}
			if !found {
				t.Fatalf("want blocker %s, got %+v", tc.blocker, g.Blocking)
			}
		})
	}
	// A simulated result never satisfies a gate for a real connector type.
	b := passingBundle(t)
	b.Conn.ConnectorType = "ad"
	g := b.reeval(t, t0)
	if !g.Blocks() {
		t.Fatal("simulated evidence gated a real connector type")
	}
	if it, _ := b.Eval.Item("ad.bind"); it.Status == StatusPass {
		t.Errorf("ad.bind passed on simulated evidence: %+v", it.Parts)
	}
	// An accepted finding does not block.
	b = passingBundle(t)
	b.Evidence.Findings = []FindingInfo{{Code: "RF-08", Severity: "critical", Status: "accepted"}}
	if g := b.reeval(t, t0); g.Blocks() {
		t.Errorf("accepted finding blocks: %+v", g.Blocking)
	}
}

func TestDependencies_BlockAndApplicability(t *testing.T) {
	b := passingBundle(t)
	b.Evidence.Live[resultKey{"ad.tls.ldaps", "tls_handshake"}].Status = "fail"
	b.reeval(t, t0)
	for _, id := range []string{"ad.tls.chain", "ad.bind", "ad.svc.readonly", "ad.groups.range", "ad.sync.deleted"} {
		it, _ := b.Eval.Item(id)
		if it.Status != StatusBlocked || !slices.Contains(it.BlockedBy, "ad.tls.ldaps") {
			t.Errorf("%s: status %s blocked by %v (want blocked by the root cause ad.tls.ldaps)", id, it.Status, it.BlockedBy)
		}
	}
	// 49 items, 46 applicable: write-back is off and there is no Entra connection (§12).
	n, applicable := len(b.Eval.Items), 0
	for _, it := range b.Eval.Items {
		if it.Applicable {
			applicable++
		}
	}
	if n != 49 || applicable != 46 {
		t.Errorf("items %d applicable %d, want 49 and 46", n, applicable)
	}
	b.Evidence.TenantTypes["entra"] = true
	b.reeval(t, t0)
	if it, _ := b.Eval.Item("ad.hybrid.entra"); !it.Applicable {
		t.Error("ad.hybrid.entra should apply with an Entra connection")
	}
}

func TestSkipRules(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	id := createAD(t, s, st, "AD skip")
	err := st.Write(context.Background(), func(c *store.TenantTx) error {
		_, err := s.Skip(c, id, "ad.bind", "We will fix this after go-live, promise", nil, "admin", t0)
		return err
	})
	if codeOf(err) != "required_item_not_skippable" {
		t.Errorf("required skip: %v", err)
	}
	for _, reason := range []string{"", "too short", "nineteen characters"} {
		err = st.Write(context.Background(), func(c *store.TenantTx) error {
			_, err := s.Skip(c, id, "ad.tls.signing_cb", reason, nil, "admin", t0)
			return err
		})
		if codeOf(err) != "reason_too_short" {
			t.Errorf("reason %q: %v", reason, err)
		}
	}
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Skip(c, id, "ad.tls.signing_cb", "twenty characters ok", nil, "admin", t0)
		if err != nil {
			return err
		}
		if it, _ := b.Eval.Item("ad.tls.signing_cb"); it.Status != StatusSkipped {
			t.Errorf("status %s", it.Status)
		}
		log, err := c.AuditLog(5)
		if err != nil {
			return err
		}
		found := false
		for _, e := range log {
			if e.Action == "readiness.item.skipped" && strings.Contains(string(e.Detail), "twenty characters ok") &&
				strings.Contains(string(e.Detail), `"level":"recommended"`) && strings.Contains(string(e.Detail), `"template_version":"1.0.0"`) {
				found = true
			}
		}
		if !found {
			t.Error("skip not audited with item, level, reason and template version")
		}
		_, err = s.Unskip(c, id, "ad.tls.signing_cb", "admin", t0)
		return err
	})
}

func TestConfigEdit_InvalidatesDependentItems(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	id := createAD(t, s, st, "AD edit")
	write(t, st, func(c *store.TenantTx) error {
		for _, item := range []string{"base.owner", "base.schedule", "ad.tls.signing_cb"} {
			if _, err := s.Attest(c, id, item, "checked in the console", "admin", t0); err != nil {
				return err
			}
		}
		_, err := s.Transition(c, id, store.StateReadyToValidate, "admin", t0)
		return err
	})
	patch := func(body string) *ConfigResult {
		var res *ConfigResult
		write(t, st, func(c *store.TenantTx) error {
			var err error
			res, err = s.PatchConfig(c, id, []byte(body), "admin", t0)
			return err
		})
		return res
	}
	// The sync schedule only backs base.schedule.
	res := patch(`{"sync_schedule":"daily 02:00, full weekly"}`)
	if !slices.Equal(res.Invalidated, []string{"base.schedule"}) {
		t.Errorf("schedule edit invalidated %v", res.Invalidated)
	}
	if res.Bundle.Rev.State != store.StateReadyToValidate {
		t.Errorf("state %s", res.Bundle.Rev.State)
	}
	// The host backs the TLS attestation, not the owners.
	res = patch(`{"host":"dc02.corp.larkspur.example"}`)
	if !slices.Equal(res.Invalidated, []string{"ad.tls.signing_cb"}) {
		t.Errorf("host edit invalidated %v", res.Invalidated)
	}
	// Changing an owner invalidates the Required base.owner attestation, so
	// the revision falls back to draft.
	res = patch(`{"technical_owner":"Marcus Bellweather"}`)
	if !slices.Contains(res.Invalidated, "base.owner") || res.Bundle.Rev.State != store.StateDraft {
		t.Errorf("owner edit: invalidated %v, state %s", res.Invalidated, res.Bundle.Rev.State)
	}
	if it, _ := res.Bundle.Eval.Item("base.owner"); it.Status != StatusStale {
		t.Errorf("base.owner status %s", it.Status)
	}
	// Unknown fields (a password, say) are rejected.
	err := st.Write(context.Background(), func(c *store.TenantTx) error {
		_, err := s.PatchConfig(c, id, []byte(`{"password":"hunter2"}`), "admin", t0)
		return err
	})
	if codeOf(err) != "invalid_config" {
		t.Errorf("password field: %v", err)
	}
}

func TestActiveEdit_CreatesRevision(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	fe := &fakeEvidence{on: true, runAt: t0}
	fe.install(s)
	id := createAD(t, s, st, "AD live")
	driveTo(t, s, st, id, "active")
	var live, pending *store.ConnectionRevision
	var err error
	read(t, st, func(c *store.TenantTx) error {
		_, live, pending, err = Revisions(c, id)
		return nil
	})
	if err != nil || live == nil || pending != nil {
		t.Fatalf("live %v pending %v err %v", live, pending, err)
	}
	var res *ConfigResult
	write(t, st, func(c *store.TenantTx) error {
		res, err = s.PatchConfig(c, id, []byte(`{"stale_days":60}`), "admin", t0)
		return err
	})
	if !res.NewRevision || res.Bundle.Rev.Rev != 2 || res.Bundle.Rev.State != store.StateDraft {
		t.Fatalf("new revision: %+v", res.Bundle.Rev)
	}
	var live2, pending2 *store.ConnectionRevision
	read(t, st, func(c *store.TenantTx) error {
		_, live2, pending2, _ = Revisions(c, id)
		return nil
	})
	if live2.ID != live.ID || live2.State != store.StateActive || pending2 == nil || pending2.ID != res.Bundle.Rev.ID {
		t.Fatalf("live revision disturbed: live %+v pending %+v", live2, pending2)
	}
	// The new revision goes through the same gates, then swaps atomically.
	driveTo(t, s, st, id, "active")
	var live3, pending3 *store.ConnectionRevision
	read(t, st, func(c *store.TenantTx) error {
		_, live3, pending3, _ = Revisions(c, id)
		return nil
	})
	if live3.ID != res.Bundle.Rev.ID || pending3 != nil {
		t.Fatalf("swap: live %s pending %v", live3.ID, pending3)
	}
	var old *store.ConnectionRevision
	read(t, st, func(c *store.TenantTx) error {
		old, _ = c.Revision(live.ID)
		return nil
	})
	if old.State != store.StateSuperseded {
		t.Errorf("old revision %s", old.State)
	}
}

func TestActivate_ConcurrentCAS(t *testing.T) {
	for round := 0; round < 5; round++ {
		st, s := newStore(t), newSvc(t)
		fe := &fakeEvidence{on: true, runAt: t0}
		fe.install(s)
		id := createAD(t, s, st, "AD race")
		readyToActivate(t, s, st, id)
		var wg sync.WaitGroup
		errs := make([]error, 3)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = st.Write(context.Background(), func(c *store.TenantTx) error {
					_, _, err := s.Activate(c, id, "admin", t0)
					return err
				})
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[2] = st.Write(context.Background(), func(c *store.TenantTx) error {
				_, err := s.PatchConfig(c, id, []byte(`{"host":"dc09.corp.larkspur.example"}`), "admin", t0)
				return err
			})
		}()
		wg.Wait()
		ok := 0
		for _, err := range errs[:2] {
			if err == nil {
				ok++
			} else if c := codeOf(err); c != "activation_blocked" && c != "no_pending_revision" && c != "state_conflict" {
				t.Fatalf("unexpected activation error: %v", err)
			}
		}
		if ok > 1 {
			t.Fatalf("both activations succeeded")
		}
		var revs []*store.ConnectionRevision
		read(t, st, func(c *store.TenantTx) error {
			revs, _ = c.Revisions(id)
			return nil
		})
		live := 0
		for _, r := range revs {
			if IsLive(r.State) {
				live++
				var g GateReport
				if err := json.Unmarshal([]byte(*r.GateReport), &g); err != nil || g.ConfigHash != r.ConfigHash {
					t.Fatalf("live revision activated against config %s but holds %s", g.ConfigHash, r.ConfigHash)
				}
			}
		}
		if live != ok {
			t.Fatalf("%d live revisions after %d successful activations", live, ok)
		}
	}
}

func TestSimulated_CannotGateRealTypes(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	s.Env = "dev" // even where real types may be activated
	fe := &fakeEvidence{on: true, runAt: t0}
	fe.install(s)
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "Corp AD", ConnectorType: "ad", Config: json.RawMessage(
			`{"host":"dc01.corp.example","base_dns":["DC=corp,DC=example"],"technical_owner":"A","business_owner":"B"}`)}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		if _, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/ad"}, "admin", t0); err != nil {
			return err
		}
		// items whose dependencies need live evidence cannot be attested yet
		for _, item := range []string{"base.owner", "base.correlation.key", "base.stale.threshold", "ad.svc.password"} {
			if _, err := s.Attest(c, id, item, "checked in the console", "admin", t0); err != nil {
				return err
			}
		}
		if _, err := s.Transition(c, id, store.StateReadyToValidate, "admin", t0); err != nil {
			return err
		}
		b, err = s.Current(c, id, t0)
		if err != nil {
			return err
		}
		if err := s.advanceAfterValidation(c, b, "admin", t0); err != nil {
			return err
		}
		if b.Rev.State != store.StateReadyToValidate {
			t.Errorf("simulated evidence validated a real AD connection: %s", b.Rev.State)
		}
		g := b.Gate(store.StateValidated, t0)
		found := false
		for _, x := range g.Blocking {
			if strings.Contains(x.Reason, "simulated") {
				found = true
			}
		}
		if !found {
			t.Errorf("blockers do not explain the simulated evidence: %+v", g.Blocking)
		}
		return nil
	})
	// DR-10 lifted the phase0_required refusal (tenancy, RBAC and step-up
	// exist); outside dev the gate alone still refuses: simulated evidence
	// never satisfies a real type.
	s.Env = ""
	err := st.Write(context.Background(), func(c *store.TenantTx) error {
		_, _, err := s.Activate(c, id, "admin", t0)
		return err
	})
	if codeOf(err) != "activation_blocked" {
		t.Errorf("real type activation: %v", err)
	}
}

func TestOverlay_RaisesLevelForNewRevisions(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	write(t, st, func(c *store.TenantTx) error {
		_, err := s.PutOverlay(c, "ad", []byte(`{"raise_levels":{"ad.svc.no_interactive":"required"},
			"add_items":[{"id":"custom.change_ticket","title":"Change ticket linked","category":"ownership","level":"required",
			"why":"Auditors ask for it.","verify":[{"kind":"attestation"}],"remediation":{"hint":"Link the ticket."}}]}`), "admin", t0)
		return err
	})
	err := st.Write(context.Background(), func(c *store.TenantTx) error {
		_, err := s.PutOverlay(c, "ad", []byte(`{"raise_levels":{"ad.bind":"optional"}}`), "admin", t0)
		return err
	})
	if codeOf(err) != template.CodeDowngrade {
		t.Errorf("downgrade: %v", err)
	}
	id := createAD(t, s, st, "AD overlay")
	b, err := current(st, s, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	if it, _ := b.Eval.Item("ad.svc.no_interactive"); it.Level != template.Required || it.TemplateLevel != template.Optional {
		t.Errorf("raised level not applied: %s (template %s)", it.Level, it.TemplateLevel)
	}
	if _, ok := b.Eval.Item("custom.change_ticket"); !ok || b.Rev.OverlayVersion != 1 {
		t.Errorf("custom item missing; overlay version %d", b.Rev.OverlayVersion)
	}
}

// TestIsolation_ReadinessAuditAndStateScoped: driving a connection to active
// in one tenant (attestations, a skip, activation) writes audit entries
// stamped with that tenant only, and another tenant of the same database
// sees neither the connection nor the entries.
func TestIsolation_ReadinessAuditAndStateScoped(t *testing.T) {
	a, s := newStore(t), newSvc(t)
	var other store.Tenant
	if err := a.DB.InSystem(context.Background(), "test", func(sx *store.SystemTx) error {
		var err error
		other, err = sx.CreateTenant(store.Tenant{Slug: "globex", Name: "Globex"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	b := Scope{DB: a.DB, Tenant: other.ID}
	fe := &fakeEvidence{on: true, runAt: t0}
	fe.install(s)
	id := createAD(t, s, a, "AD tenant A")
	driveTo(t, s, a, id, "active")
	actions := func(sc Scope) map[string]int {
		out := map[string]int{}
		read(t, sc, func(c *store.TenantTx) error {
			log, err := c.AuditLog(-1)
			for _, e := range log {
				out[e.Action]++
			}
			return err
		})
		return out
	}
	got := actions(a)
	for _, want := range []string{"connection.created", "readiness.item.attested", "connection.activated"} {
		if got[want] == 0 {
			t.Errorf("tenant A has no %s audit entry (%v)", want, got)
		}
	}
	if n := len(actions(b)); n != 0 {
		t.Errorf("tenant B's audit log has %d actions from tenant A's readiness work", n)
	}
	read(t, b, func(c *store.TenantTx) error {
		conns, err := c.Connections()
		if len(conns) != 0 {
			t.Errorf("tenant B sees %d connections", len(conns))
		}
		if _, err := c.Connection(id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant A's connection from B: %v", err)
		}
		return err
	})
	if _, err := current(b, s, id, t0); codeOf(err) != "not_found" {
		t.Errorf("readiness view of tenant A's connection from B: %v", err)
	}
	err := b.Write(context.Background(), func(c *store.TenantTx) error {
		_, err := s.Attest(c, id, "base.owner", "attested from tenant B", "admin", t0)
		return err
	})
	if codeOf(err) != "not_found" {
		t.Errorf("attest tenant A's connection from B: %v", err)
	}
}
