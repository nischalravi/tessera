package readiness

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// unsupportedLDAP is a real (non-simulated) LDAP system that cannot answer
// Who Am I or Get Effective Rights, like LLDAP and OpenLDAP. writable turns
// effective rights into an answer that shows write access.
type unsupportedLDAP struct {
	connectors.Prober
	noWhoAmI bool
	rights   string // "unsupported" (default), "readonly" or "writable"
}

func (p unsupportedLDAP) Authenticate(ctx context.Context) (connectors.AuthInfo, error) {
	a, err := p.Prober.Authenticate(ctx)
	a.IdentityUnverified = p.noWhoAmI
	return a, err
}

func (p unsupportedLDAP) EffectiveRights(ctx context.Context, ref string) (connectors.Rights, error) {
	switch p.rights {
	case "readonly":
		return connectors.Rights{}, ctx.Err()
	case "writable":
		return connectors.Rights{Writable: []string{ref}}, ctx.Err()
	}
	return connectors.Rights{}, connectors.ErrUnsupported
}

const (
	itemReadonly = "ldap.svc.readonly"
	itemNoWrite  = "ldap.svc.no_write"
)

var goodAttest = LiveAttestInput{Attester: "Ingrid Lindqvist", Reason: "The directory has no Get Effective Rights control",
	Evidence: "ACL export of the bind DN reviewed in CHG-1043"}

// attestSetup is a real LDAP connection in ready_to_validate whose system has
// no Who Am I and no Get Effective Rights; mode picks what rights answers.
func attestSetup(t *testing.T, rights string) (Scope, *Service, string, *unsupportedLDAP) {
	t.Helper()
	st, s := newStore(t), liveSvc(t)
	id, _ := ldapConn(t, s, st, ldapCfg)
	fake := &unsupportedLDAP{noWhoAmI: true, rights: rights}
	s.Runner.ProberFor = func(b *Bundle, now time.Time) (connectors.Prober, error) {
		p, err := connectors.NewScenarioProber("ldap", "happy", now, b.Config.BaseDNs, nil)
		f := *fake
		f.Prober = p
		return f, err
	}
	write(t, st, func(c *store.TenantTx) error {
		for _, item := range []string{"base.owner", "base.correlation.key", "base.stale.threshold"} {
			if _, err := s.Attest(c, id, item, "checked in the console", "admin", t0); err != nil {
				return err
			}
		}
		_, err := s.Transition(c, id, store.StateReadyToValidate, "admin", t0)
		return err
	})
	return st, s, id, fake
}

func attestInstead(t *testing.T, st Scope, s *Service, id, item string, in LiveAttestInput, now time.Time) error {
	t.Helper()
	return st.Write(context.Background(), func(c *store.TenantTx) error {
		_, err := s.AttestInstead(c, id, item, in, "admin", now)
		return err
	})
}

func part(t *testing.T, b *Bundle, item string) Part {
	t.Helper()
	ie, ok := b.Eval.Item(item)
	if !ok {
		t.Fatalf("no item %s", item)
	}
	for _, p := range ie.Parts {
		if p.Kind == "live" {
			return p
		}
	}
	t.Fatalf("%s has no live part", item)
	return Part{}
}

func blockers(b *Bundle, now time.Time) []string {
	var out []string
	for _, x := range b.Gate(store.StateValidated, now).Blocking {
		out = append(out, x.Item)
	}
	return out
}

func validate(t *testing.T, st Scope, s *Service, id string, now time.Time) *RunView {
	t.Helper()
	v, err := s.Validate(context.Background(), st, id, "admin", clockAt(now))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestLiveAttest_UnsupportedThenAttestedPasses: a live check the system cannot
// answer stays pending and blocks the gate; an attestation in its place passes
// it, and the dependant check then runs.
func TestLiveAttest_UnsupportedThenAttestedPasses(t *testing.T) {
	st, s, id, _ := attestSetup(t, "unsupported")
	v := validate(t, st, s, id, t0)
	if r := resultFor(v, itemReadonly, "bind_identity"); r == nil || r.Status != "skipped" {
		t.Fatalf("bind_identity: %+v", r)
	}
	// the dependant did not run: its dependency is not satisfied yet
	if r := resultFor(v, itemNoWrite, "effective_rights"); r == nil || r.Status != "blocked" {
		t.Fatalf("effective_rights before the first attestation: %+v", r)
	}
	b, err := current(st, s, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	if p := part(t, b, itemReadonly); p.Status != StatusPending || !p.Unsupported {
		t.Fatalf("part before attesting: %+v", p)
	}
	if !slices.Contains(blockers(b, t0), itemReadonly) {
		t.Fatalf("gate does not block on the unsupported item: %v", blockers(b, t0))
	}

	if err := attestInstead(t, st, s, id, itemReadonly, goodAttest, t0); err != nil {
		t.Fatal(err)
	}
	v = validate(t, st, s, id, t0)
	if r := resultFor(v, itemNoWrite, "effective_rights"); r == nil || r.Status != "skipped" {
		t.Fatalf("effective_rights after attesting its dependency: %+v", r)
	}
	if err := attestInstead(t, st, s, id, itemNoWrite, goodAttest, t0); err != nil {
		t.Fatal(err)
	}
	b, err = current(st, s, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []string{itemReadonly, itemNoWrite} {
		ie, _ := b.Eval.Item(item)
		if ie.Status != StatusPass || part(t, b, item).Status != StatusPass {
			t.Errorf("%s: status %s, part %+v", item, ie.Status, part(t, b, item))
		}
		if !strings.Contains(part(t, b, item).Message, "Ingrid Lindqvist") {
			t.Errorf("%s: message %q does not name the attester", item, part(t, b, item).Message)
		}
		if slices.Contains(blockers(b, t0), item) {
			t.Errorf("gate still blocks on %s", item)
		}
	}
	if view := Checklist(b, t0); view == nil {
		t.Fatal("no checklist")
	} else {
		for _, iv := range view.Items {
			if iv.ID == itemNoWrite && (iv.LiveAttestation == nil || iv.LiveAttestation.Stale || iv.LiveAttestation.Evidence == "") {
				t.Errorf("checklist view: %+v", iv.LiveAttestation)
			}
		}
	}
}

// TestLiveAttest_FailCannotBeAttested: only an unsupported result can be
// attested. A failing one is refused, and an attestation made earlier does not
// rescue it once the check fails.
func TestLiveAttest_FailCannotBeAttested(t *testing.T) {
	st, s, id, fake := attestSetup(t, "unsupported")
	fake.noWhoAmI = false // the bind identity is answered and passes
	validate(t, st, s, id, t0)

	// not run yet / passing: no unsupported result to attest
	err := attestInstead(t, st, s, id, itemReadonly, goodAttest, t0)
	var re *Error
	if !errors.As(err, &re) || re.Status != http.StatusUnprocessableEntity || re.Code != "live_check_not_unsupported" {
		t.Fatalf("attesting a passing check: %v", err)
	}

	fake.rights = "writable"
	validate(t, st, s, id, t0)
	b, err := current(st, s, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	if p := part(t, b, itemNoWrite); p.Status != StatusFail || p.Unsupported {
		t.Fatalf("writable bind DN: %+v", p)
	}
	err = attestInstead(t, st, s, id, itemNoWrite, goodAttest, t0)
	if !errors.As(err, &re) || re.Code != "live_check_not_unsupported" {
		t.Fatalf("attesting a failed check: %v", err)
	}

	// an attestation recorded while the system was unsupported does not mask a later fail
	fake.rights = "unsupported"
	validate(t, st, s, id, t0)
	if err := attestInstead(t, st, s, id, itemNoWrite, goodAttest, t0); err != nil {
		t.Fatal(err)
	}
	fake.rights = "writable"
	validate(t, st, s, id, t0)
	b, err = current(st, s, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	if ie, _ := b.Eval.Item(itemNoWrite); ie.Status != StatusFail {
		t.Fatalf("status %s after a fail with an attestation on file", ie.Status)
	}
	if !slices.Contains(blockers(b, t0), itemNoWrite) {
		t.Errorf("gate does not block on the failed item: %v", blockers(b, t0))
	}
}

// TestLiveAttest_Refusals covers the input rules and the items that do not
// take an attestation instead.
func TestLiveAttest_Refusals(t *testing.T) {
	st, s, id, _ := attestSetup(t, "unsupported")
	validate(t, st, s, id, t0)
	cases := []struct {
		name string
		item string
		in   LiveAttestInput
		code string
	}{
		{"no attester", itemReadonly, LiveAttestInput{Reason: goodAttest.Reason, Evidence: goodAttest.Evidence}, "attester_required"},
		{"attester with a newline", itemReadonly, LiveAttestInput{Attester: "a\nb", Reason: goodAttest.Reason, Evidence: goodAttest.Evidence}, "attester_required"},
		{"short reason", itemReadonly, LiveAttestInput{Attester: "Ingrid", Reason: "nineteen characters", Evidence: goodAttest.Evidence}, "reason_too_short"},
		{"no evidence", itemReadonly, LiveAttestInput{Attester: "Ingrid", Reason: goodAttest.Reason}, "evidence_required"},
		{"control character in evidence", itemReadonly, LiveAttestInput{Attester: "Ingrid", Reason: goodAttest.Reason, Evidence: "ok\x00ok ok ok"}, "evidence_required"},
		{"item without the alternative", "ldap.tls.ldaps", goodAttest, "not_attestable_instead"},
		{"attestation-only item", "ldap.svc.ppolicy", goodAttest, "not_attestable_instead"},
		{"unknown item", "ldap.nope", goodAttest, "not_found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := attestInstead(t, st, s, id, tc.item, tc.in, t0)
			var re *Error
			if !errors.As(err, &re) || re.Code != tc.code {
				t.Fatalf("err = %v, want code %s", err, tc.code)
			}
		})
	}
	b, err := current(st, s, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Evidence.LiveAttestations[itemReadonly] != nil {
		t.Error("a refused attestation was stored")
	}
}

// TestLiveAttest_StaleWhenConfigChanges: the attestation is bound to the
// config fields of its item; changing one makes it stale, and so does time.
func TestLiveAttest_StaleWhenConfigChanges(t *testing.T) {
	st, s, id, _ := attestSetup(t, "unsupported")
	validate(t, st, s, id, t0)
	if err := attestInstead(t, st, s, id, itemReadonly, goodAttest, t0); err != nil {
		t.Fatal(err)
	}
	b, _ := current(st, s, id, t0)
	a := b.Evidence.LiveAttestations[itemReadonly]
	if a == nil || a.ConfigHash != b.ConfigHash || a.ItemHash == "" {
		t.Fatalf("attestation not bound to the config: %+v (config %s)", a, b.ConfigHash)
	}

	// host is one of the item's config fields; sync settings are not
	write(t, st, func(c *store.TenantTx) error {
		_, err := s.PatchConfig(c, id, []byte(`{"stale_days":45}`), "admin", t0)
		return err
	})
	b, _ = current(st, s, id, t0)
	if b.Evidence.LiveAttestations[itemReadonly] == nil {
		t.Fatal("attestation lost on an unrelated config change")
	}
	ok, _ := liveAttestationFresh(b.Evidence.LiveAttestations[itemReadonly], mustItem(t, b, itemReadonly).ItemHash, t0, DefaultLiveTTL)
	if !ok {
		t.Error("an unrelated config change made the attestation stale")
	}

	write(t, st, func(c *store.TenantTx) error {
		_, err := s.PatchConfig(c, id, []byte(`{"host":"192.168.1.11"}`), "admin", t0)
		return err
	})
	b, _ = current(st, s, id, t0)
	ie := mustItem(t, b, itemReadonly)
	if ok, why := liveAttestationFresh(b.Evidence.LiveAttestations[itemReadonly], ie.ItemHash, t0, DefaultLiveTTL); ok || !strings.Contains(why, "configuration changed") {
		t.Errorf("after a host change: fresh=%v %q", ok, why)
	}
	// run again: the system is still unsupported, and the old attestation is stale
	st2 := t0.Add(time.Minute)
	validate(t, st, s, id, st2)
	b, _ = current(st, s, id, st2)
	if p := part(t, b, itemReadonly); p.Status != StatusStale || !strings.Contains(p.Reason, "configuration changed") {
		t.Errorf("part after a host change: %+v", p)
	}
	if !slices.Contains(blockers(b, st2), itemReadonly) {
		t.Errorf("gate does not block on the stale attestation: %v", blockers(b, st2))
	}
}

func mustItem(t *testing.T, b *Bundle, id string) *ItemEval {
	t.Helper()
	ie, ok := b.Eval.Item(id)
	if !ok {
		t.Fatalf("no item %s", id)
	}
	return ie
}

// TestLiveAttest_ExpiresLikeLiveResults: an attestation older than the live
// TTL no longer holds.
func TestLiveAttest_ExpiresLikeLiveResults(t *testing.T) {
	a := &store.LiveAttestation{ItemHash: "h", AttestedAt: t0}
	cases := []struct {
		name string
		a    *store.LiveAttestation
		hash string
		now  time.Time
		want bool
	}{
		{"fresh", a, "h", t0.Add(DefaultLiveTTL), true},
		{"expired", a, "h", t0.Add(DefaultLiveTTL + time.Second), false},
		{"other hash", a, "x", t0, false},
		{"none", nil, "h", t0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := liveAttestationFresh(tc.a, tc.hash, tc.now, DefaultLiveTTL); got != tc.want {
				t.Errorf("fresh = %v, want %v", got, tc.want)
			}
		})
	}

	st, s, id, _ := attestSetup(t, "unsupported")
	validate(t, st, s, id, t0)
	if err := attestInstead(t, st, s, id, itemReadonly, goodAttest, t0); err != nil {
		t.Fatal(err)
	}
	late := t0.Add(DefaultLiveTTL + time.Hour)
	b, _ := current(st, s, id, late)
	if p := part(t, b, itemReadonly); p.Status != StatusStale {
		t.Errorf("part after the TTL: %+v", p)
	}
}

// TestLiveAttest_SimulatedNeverPasses: a simulated result for a real
// connector type cannot be attested into a pass.
func TestLiveAttest_SimulatedNeverPasses(t *testing.T) {
	st, s := newStore(t), liveSvc(t)
	id, _ := ldapConn(t, s, st, ldapCfg)
	var b *Bundle
	write(t, st, func(c *store.TenantTx) error {
		var err error
		b, err = s.Current(c, id, t0)
		if err != nil {
			return err
		}
		run := &store.CheckRun{ID: store.NewID(), RevisionID: b.Rev.ID, Kind: "validation", Status: "running", Simulated: true,
			ActorID: "admin", ConfigHash: b.ConfigHash, StartedAt: t0}
		if err := c.InsertCheckRun(run); err != nil {
			return err
		}
		if err := c.FinishCheckRun(run.ID, "completed", t0); err != nil {
			return err
		}
		ie := mustItem(t, b, itemReadonly)
		if err := c.UpsertLiveAttestation(&store.LiveAttestation{RevisionID: b.Rev.ID, ItemID: itemReadonly, ActorID: "admin",
			Attester: "Ingrid", Reason: goodAttest.Reason, Evidence: goodAttest.Evidence, ItemHash: ie.ItemHash,
			ConfigHash: b.ConfigHash, AttestedAt: t0}); err != nil {
			return err
		}
		return c.InsertCheckResult(&store.CheckResult{RunID: run.ID, ItemID: itemReadonly, CheckID: "bind_identity",
			Status: "skipped", Message: "x", Observed: `{"unsupported":true}`, ItemHash: ie.ItemHash, Simulated: true})
	})
	nb, err := current(st, s, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	if p := part(t, nb, itemReadonly); p.Status == StatusPass || p.Unsupported {
		t.Errorf("a simulated result passed through an attestation: %+v", p)
	}
}

// TestLiveAttest_AuditSameTransaction: the audit event is written with the
// attestation, and neither survives a rollback.
func TestLiveAttest_AuditSameTransaction(t *testing.T) {
	st, s, id, _ := attestSetup(t, "unsupported")
	validate(t, st, s, id, t0)
	count := func() (events int, stored bool) {
		read(t, st, func(c *store.TenantTx) error {
			log, err := c.AuditLog(200)
			if err != nil {
				return err
			}
			for _, e := range log {
				if e.Action == "readiness.item.attested_instead" {
					events++
				}
			}
			m, err := c.LiveAttestations(mustRevID(t, c, s, id))
			stored = m[itemReadonly] != nil
			return err
		})
		return
	}

	boom := errors.New("rolled back after the attestation")
	err := st.Write(context.Background(), func(c *store.TenantTx) error {
		if _, err := s.AttestInstead(c, id, itemReadonly, goodAttest, "admin", t0); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if n, stored := count(); n != 0 || stored {
		t.Fatalf("after a rollback: %d audit events, stored=%v", n, stored)
	}

	if err := attestInstead(t, st, s, id, itemReadonly, goodAttest, t0); err != nil {
		t.Fatal(err)
	}
	n, stored := count()
	if n != 1 || !stored {
		t.Fatalf("after commit: %d audit events, stored=%v", n, stored)
	}
	read(t, st, func(c *store.TenantTx) error {
		log, _ := c.AuditLog(200)
		for _, e := range log {
			if e.Action != "readiness.item.attested_instead" {
				continue
			}
			for _, want := range []string{"Ingrid Lindqvist", "ldap.svc.readonly", goodAttest.Reason, goodAttest.Evidence, "config_hash"} {
				if !strings.Contains(string(e.Detail), want) {
					t.Errorf("audit detail lacks %q: %s", want, e.Detail)
				}
			}
		}
		return nil
	})
}

func mustRevID(t *testing.T, c *store.TenantTx, s *Service, id string) string {
	t.Helper()
	b, err := s.Current(c, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	return b.Rev.ID
}
