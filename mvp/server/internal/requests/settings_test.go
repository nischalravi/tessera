package requests_test

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Tenant request settings (issue #298): Submit enforces them, so a client
// cannot bypass them. The tiny world: alice and bob report to carol.

func fp(v float64) *float64 { return &v }

func (w *world) settings(s requests.Settings, ver int) error {
	w.t.Helper()
	var err error
	w.tx(func(c *store.TenantTx) error {
		_, _, err = requests.SaveSettings(c, s, ver, w.pat, w.now)
		return nil
	})
	return err
}

func (w *world) submitWith(by requests.Actor, others bool, sub requests.Submission) ([]*store.RequestLine, error) {
	w.t.Helper()
	var lines []*store.RequestLine
	var err error
	w.tx(func(c *store.TenantTx) error {
		_, lines, err = requests.Submit(c, sub, by, others, w.now)
		return nil
	})
	return lines, err
}

func TestSettings_DefaultsKeepEarlierBehaviour(t *testing.T) {
	d := requests.DefaultSettings()
	if !d.JustificationRequired || d.JustificationMin != 1 || d.DefaultHours != nil || d.MaxHours != nil || d.AttachmentsAllowed ||
		d.HistoryVisibility != requests.HistoryReaders || d.ForOthers != requests.ForOthersPermission {
		t.Errorf("defaults = %+v", d)
	}
	if err := d.Check(); err != nil {
		t.Errorf("defaults do not validate: %v", err)
	}
	w := newWorld(t)
	w.tx(func(c *store.TenantTx) error {
		got, ver, err := requests.LoadSettings(c)
		if err != nil || ver != 0 || got != d {
			t.Errorf("a tenant that never saved: %+v v%d %v", got, ver, err)
		}
		return nil
	})
}

func TestSettings_Validation(t *testing.T) {
	ok := requests.DefaultSettings()
	for name, tc := range map[string]struct {
		mut  func(*requests.Settings)
		want string
	}{
		"min length zero":    {func(s *requests.Settings) { s.JustificationMin = 0 }, "invalid_justification_min"},
		"min length too big": {func(s *requests.Settings) { s.JustificationMin = requests.MaxJustification + 1 }, "invalid_justification_min"},
		"default zero":       {func(s *requests.Settings) { s.DefaultHours = fp(0) }, "invalid_default_hours"},
		"default too long":   {func(s *requests.Settings) { s.DefaultHours = fp(requests.MaxHours + 1) }, "invalid_default_hours"},
		"max negative":       {func(s *requests.Settings) { s.MaxHours = fp(-1) }, "invalid_max_hours"},
		"default above max":  {func(s *requests.Settings) { s.DefaultHours, s.MaxHours = fp(48), fp(24) }, "default_above_max"},
		"unknown history":    {func(s *requests.Settings) { s.HistoryVisibility = "everyone" }, "invalid_history_visibility"},
		"unknown for others": {func(s *requests.Settings) { s.ForOthers = "friends" }, "invalid_for_others"},
	} {
		s := ok
		tc.mut(&s)
		if got := code(s.Check()); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

func TestSettings_SaveIsVersionedAndAudited(t *testing.T) {
	w := newWorld(t)
	s := requests.DefaultSettings()
	s.JustificationMin = 20
	if err := w.settings(s, 1); code(err) != "version_conflict" {
		t.Errorf("saving over a version that does not exist: %v", err)
	}
	if err := w.settings(s, 0); err != nil {
		t.Fatal(err)
	}
	if err := w.settings(s, 0); code(err) != "version_conflict" {
		t.Errorf("a stale save: %v", err)
	}
	s.JustificationMin = 30
	if err := w.settings(s, 1); err != nil {
		t.Fatal(err)
	}
	w.tx(func(c *store.TenantTx) error {
		got, ver, err := requests.LoadSettings(c)
		if err != nil || ver != 2 || got.JustificationMin != 30 {
			t.Errorf("loaded %+v v%d %v", got, ver, err)
		}
		evs, err := c.AuditEvents(store.AuditFilter{})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range evs {
			if e.Action == "request.settings.update" {
				n++
			}
		}
		if n != 2 {
			t.Errorf("%d request.settings.update audit events, want 2", n)
		}
		return nil
	})
}

func TestSettings_Justification(t *testing.T) {
	long := strings.Repeat("x", 25)
	for name, tc := range map[string]struct {
		set  func(*requests.Settings)
		just string
		want string
	}{
		"default needs some text":         {func(*requests.Settings) {}, "  ", "justification_required"},
		"default accepts one character":   {func(*requests.Settings) {}, "x", ""},
		"minimum length refuses a short":  {func(s *requests.Settings) { s.JustificationMin = 20 }, "short one", "justification_required"},
		"minimum length accepts a long":   {func(s *requests.Settings) { s.JustificationMin = 20 }, long, ""},
		"not required accepts none":       {func(s *requests.Settings) { s.JustificationRequired = false }, "", ""},
		"not required still caps length":  {func(s *requests.Settings) { s.JustificationRequired = false }, strings.Repeat("x", requests.MaxJustification+1), "justification_required"},
		"minimum counts after trimming":   {func(s *requests.Settings) { s.JustificationMin = 5 }, "   ab   ", "justification_required"},
		"ignored minimum when not needed": {func(s *requests.Settings) { s.JustificationRequired, s.JustificationMin = false, 50 }, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			s := requests.DefaultSettings()
			tc.set(&s)
			if err := w.settings(s, 0); err != nil {
				t.Fatal(err)
			}
			_, err := w.submitWith(w.alice, false, requests.Submission{Beneficiaries: []int64{w.ids["alice"]},
				Items: []string{w.items["group:okta:platform"]}, Justification: tc.just})
			if got := code(err); got != tc.want {
				t.Errorf("%q: %q, want %q", tc.just, got, tc.want)
			}
		})
	}
}

func TestSettings_Durations(t *testing.T) {
	platform, prod := "group:okta:platform", "group:aws:ProdAdmin" // prod: 8h default, 72h cap
	for name, tc := range map[string]struct {
		set   func(*requests.Settings)
		item  string
		hours *float64
		want  string
		got   *float64 // the duration the line gets, if it is filed
	}{
		"tenant default fills in":     {func(s *requests.Settings) { s.DefaultHours = fp(24) }, platform, nil, "", fp(24)},
		"item default wins":           {func(s *requests.Settings) { s.DefaultHours = fp(24) }, prod, nil, "", fp(8)},
		"asked duration wins":         {func(s *requests.Settings) { s.DefaultHours = fp(24) }, platform, fp(2), "", fp(2)},
		"max refuses a longer ask":    {func(s *requests.Settings) { s.MaxHours = fp(10) }, platform, fp(11), "duration_too_long", nil},
		"max accepts the limit":       {func(s *requests.Settings) { s.MaxHours = fp(10) }, platform, fp(10), "", fp(10)},
		"max refuses until removed":   {func(s *requests.Settings) { s.MaxHours = fp(10) }, platform, nil, "duration_required", nil},
		"max with a default is fine":  {func(s *requests.Settings) { s.DefaultHours, s.MaxHours = fp(4), fp(10) }, platform, nil, "", fp(4)},
		"item cap still applies":      {func(s *requests.Settings) { s.MaxHours = fp(500) }, prod, fp(100), "duration_too_long", nil},
		"max lower than item default": {func(s *requests.Settings) { s.MaxHours = fp(4) }, prod, nil, "duration_too_long", nil},
		"unset leaves until removed":  {func(*requests.Settings) {}, platform, nil, "", nil},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			s := requests.DefaultSettings()
			tc.set(&s)
			if err := w.settings(s, 0); err != nil {
				t.Fatal(err)
			}
			lines, err := w.submit(w.alice, false, []string{"alice"}, []string{tc.item}, tc.hours)
			if got := code(err); got != tc.want {
				t.Fatalf("%q, want %q", got, tc.want)
			}
			if tc.want != "" {
				return
			}
			switch h := lines[0].DurationHours; {
			case tc.got == nil && h != nil, tc.got != nil && (h == nil || *h != *tc.got):
				t.Errorf("duration = %v, want %v", h, tc.got)
			}
		})
	}
}

func TestSettings_Attachments(t *testing.T) {
	for name, tc := range map[string]struct {
		allowed bool
		refs    []string
		want    string
	}{
		"off, none sent":      {false, nil, ""},
		"off, one sent":       {false, []string{"SEC-1"}, "attachments_not_allowed"},
		"on, none sent":       {true, nil, ""},
		"on, two sent":        {true, []string{"SEC-1", "https://wiki.example/x"}, ""},
		"on, too many":        {true, make([]string, requests.MaxAttachments+1), "too_many_attachments"},
		"on, an empty one":    {true, []string{" "}, "invalid_attachment"},
		"on, an overlong one": {true, []string{strings.Repeat("x", requests.MaxAttachmentRef+1)}, "invalid_attachment"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			s := requests.DefaultSettings()
			s.AttachmentsAllowed = tc.allowed
			if err := w.settings(s, 0); err != nil {
				t.Fatal(err)
			}
			_, err := w.submitWith(w.alice, false, requests.Submission{Beneficiaries: []int64{w.ids["alice"]},
				Items: []string{w.items["group:okta:platform"]}, Justification: "project Atlas", Attachments: tc.refs})
			if got := code(err); got != tc.want {
				t.Errorf("%q, want %q", got, tc.want)
			}
		})
	}
}

func TestSettings_ForOthers(t *testing.T) {
	// carol is alice's manager, bob is not; zed holds requests.create_for_others
	for name, tc := range map[string]struct {
		policy string
		by     string // carol, bob or zed
		perm   bool
		target string
		want   string
	}{
		"permission: holder may":          {requests.ForOthersPermission, "zed", true, "alice", ""},
		"permission: others may not":      {requests.ForOthersPermission, "bob", false, "alice", "for_others_not_allowed"},
		"permission: self always":         {requests.ForOthersPermission, "bob", false, "bob", ""},
		"nobody: holder may not":          {requests.ForOthersNobody, "zed", true, "alice", "for_others_not_allowed"},
		"nobody: manager may not":         {requests.ForOthersNobody, "carol", false, "alice", "for_others_not_allowed"},
		"nobody: self still allowed":      {requests.ForOthersNobody, "bob", false, "bob", ""},
		"managers: the manager may":       {requests.ForOthersManagers, "carol", false, "alice", ""},
		"managers: a peer may not":        {requests.ForOthersManagers, "bob", false, "alice", "for_others_not_allowed"},
		"managers: a holder may not":      {requests.ForOthersManagers, "zed", true, "alice", "for_others_not_allowed"},
		"managers: no manager of carol":   {requests.ForOthersManagers, "bob", true, "carol", "for_others_not_allowed"},
		"managers: self still allowed":    {requests.ForOthersManagers, "bob", false, "bob", ""},
		"managers: user without a person": {requests.ForOthersManagers, "zed", false, "alice", "for_others_not_allowed"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRouted(t)
			s := requests.DefaultSettings()
			s.ForOthers = tc.policy
			if err := r.settings(s, 0); err != nil {
				t.Fatal(err)
			}
			by := map[string]requests.Actor{"carol": r.carol, "bob": r.bob, "zed": r.zed}[tc.by]
			_, err := r.submitWith(by, tc.perm, requests.Submission{Beneficiaries: []int64{r.ids[tc.target]},
				Items: []string{r.item}, Justification: "project Atlas"})
			if got := code(err); got != tc.want {
				t.Errorf("%q, want %q", got, tc.want)
			}
		})
	}
}
