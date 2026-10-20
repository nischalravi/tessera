package benchgen

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/provisioning"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Result is one measured target of design section 6.7.
type Result struct {
	// Name is a stable key, Design the row of the table it measures.
	Name   string `json:"name"`
	Design string `json:"design"`
	// Stat is what Value is: p95, p99, or total.
	Stat string `json:"stat"`
	// Limit is the target, in Unit. Zero means the design states no number:
	// the value is reported, not asserted.
	Limit   float64 `json:"limit"`
	Unit    string  `json:"unit"`
	Value   float64 `json:"value"`
	Samples int     `json:"samples"`
	Pass    bool    `json:"pass"`
	Note    string  `json:"note,omitempty"`
}

// Report is everything one run measured.
type Report struct {
	Percent float64   `json:"percent"`
	Backend string    `json:"backend"`
	Stats   string    `json:"tenant"`
	Started time.Time `json:"started"`
	Results []Result  `json:"results"`
}

// Failed returns the results that missed their target.
func (r *Report) Failed() []Result {
	var out []Result
	for _, x := range r.Results {
		if !x.Pass {
			out = append(out, x)
		}
	}
	return out
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	return s[int(float64(len(s)-1)*p)]
}

// latency builds a Result from samples; limit is in milliseconds.
func latency(name, design, stat string, p, limit float64, ds []time.Duration, note string) Result {
	v := ms(percentile(ds, p))
	return Result{Name: name, Design: design, Stat: stat, Limit: limit, Unit: "ms", Value: v, Samples: len(ds), Pass: limit == 0 || v <= limit, Note: note}
}

// Latency builds a Result from samples for a caller that measures elsewhere
// (the REST gate in internal/api): p is the percentile, limit is in milliseconds.
func Latency(name, design, stat string, p, limit float64, ds []time.Duration, note string) Result {
	return latency(name, design, stat, p, limit, ds, note)
}

// Total builds a Result from one duration (limit zero: reported, not asserted).
func Total(name, design string, limit, d time.Duration, note string) Result {
	return total(name, design, limit, d, note)
}

// total builds a Result from one duration; limit is a duration (zero: report only).
func total(name, design string, limit, d time.Duration, note string) Result {
	return Result{Name: name, Design: design, Stat: "total", Limit: limit.Seconds(), Unit: "s", Value: d.Seconds(), Samples: 1,
		Pass: limit == 0 || d <= limit, Note: note}
}

func sample(n int, fn func(i int) error) ([]time.Duration, error) {
	out := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if err := fn(i); err != nil {
			return nil, err
		}
		out = append(out, time.Since(start))
	}
	return out, nil
}

// Measure runs the operations of the design's section 6.7 table against a
// generated tenant, in the order that leaves each measurement a fair tenant:
// reads first, then single changes, the loader, provisioning, the nesting of the
// reference group, verification and the term rollover. It changes the tenant
// (and leaves it in the shape it found it, but for rows the rollover adds).
func Measure(ctx context.Context, t *Tenant) (*Report, error) {
	spec := t.Spec
	rep := &Report{Percent: spec.Percent, Stats: t.Stats.String(), Started: time.Now().UTC(), Backend: "sqlite"}
	rng := rand.New(rand.NewSource(spec.Seed + 1)) // #nosec G404 -- sample choice, not a secret
	add := func(rs ...Result) { rep.Results = append(rep.Results, rs...) }
	n := spec.Samples
	list := store.MembersListID(t.ID)
	heavy := max(10, n/10) // a page of a large group is much slower than a key lookup

	// hasMember(group, identity): p99 <= 5 ms, a read transaction each, like the API
	spec.logf("measure: hasMember")
	groups := []store.GroupID{t.Leaf, t.Levels[1][rng.Intn(len(t.Levels[1]))], t.Levels[2][rng.Intn(len(t.Levels[2]))], t.Top, t.Ref}
	ds, err := sample(n, func(i int) error {
		return t.read(ctx, func(e model.Env) error {
			_, err := e.IsMember(groups[i%len(groups)], t.Idents[rng.Intn(len(t.Idents))])
			return err
		})
	})
	if err != nil {
		return nil, fmt.Errorf("hasMember: %w", err)
	}
	add(latency("has_member", "hasMember(group, identity)", "p99", 0.99, 5, ds, ""))

	// first page of a group's members, sorted by name: p95 <= 100 ms
	spec.logf("measure: member pages")
	for _, g := range []struct {
		name  string
		group store.GroupID
	}{{"members_first_page_reference_group", t.Ref}, {"members_first_page_nested_group", t.Top}} {
		var total int
		ds, err := sample(heavy, func(int) error {
			return t.read(ctx, func(e model.Env) error {
				_, tot, _, err := e.EffectiveMembers(g.group, model.MemberQuery{Sort: "name", Limit: 100})
				total = tot
				return err
			})
		})
		if err != nil {
			return nil, fmt.Errorf("member page: %w", err)
		}
		add(latency(g.name, "List members of a group, first page of 100, sorted by name", "p95", 0.95, 100, ds, fmt.Sprintf("%d effective members", total)))
	}

	// all groups of an identity: p95 <= 80 ms
	spec.logf("measure: groups of an identity")
	var most int
	ds, err = sample(n, func(int) error {
		return t.read(ctx, func(e model.Env) error {
			gs, err := e.Tx.GrpGroupsOfIdentity(t.Idents[rng.Intn(len(t.Idents))], list, "effective", e.Now, 500, 0)
			most = max(most, len(gs))
			return err
		})
	})
	if err != nil {
		return nil, fmt.Errorf("groups of an identity: %w", err)
	}
	add(latency("identity_groups", "List all groups of an identity (effective)", "p95", 0.95, 80, ds, fmt.Sprintf("at most %d groups in the sample", most)))

	// folder browser: a folder with Browse children: p95 <= 300 ms
	spec.logf("measure: folder browser")
	ds, err = sample(heavy, func(int) error {
		return t.read(ctx, func(e model.Env) error {
			_, err := e.ListGroups(model.GroupQuery{Folder: t.BrowseFolder, Limit: 100})
			return err
		})
	})
	if err != nil {
		return nil, fmt.Errorf("folder browser: %w", err)
	}
	add(latency("folder_browser", "Folder browser: list a folder with 5,000 children the user can VIEW", "p95", 0.95, 300, ds,
		fmt.Sprintf("%d children, first page of 100, model layer without the privilege filter (the REST gate adds it)", t.Stats.Counts.Browse)))

	// members as of T for the reference group: <= 2 s
	spec.logf("measure: point in time")
	at := t.Now()
	var seen int
	start := time.Now()
	if err := t.read(ctx, func(e model.Env) error {
		for off := 0; ; off += 2000 {
			rows, tot, err := pit.MembersAt(e.Tx, t.Ref, list, at, 2000, off)
			if err != nil {
				return err
			}
			seen = tot
			if off+len(rows) >= tot || len(rows) == 0 {
				return nil
			}
		}
	}); err != nil {
		return nil, fmt.Errorf("members as of: %w", err)
	}
	add(total("pit_members_as_of", `PIT "members as of T" for a 45,000-member group`, 2*time.Second, time.Since(start),
		fmt.Sprintf("all %d members, paged by 2,000", seen)))

	// single direct add and remove, effective state on return: p95 <= 75 ms
	spec.logf("measure: single change")
	var adds, removes []time.Duration
	for i := 0; i < n; i++ {
		ident := t.Idents[i%len(t.Idents)]
		start := time.Now()
		if err := t.write(ctx, t.Eng, func(e model.Env) error {
			_, err := e.AddMember(t.Tail, model.MemberInput{Identity: &ident})
			return err
		}); err != nil {
			return nil, fmt.Errorf("single add: %w", err)
		}
		adds = append(adds, time.Since(start))
		start = time.Now()
		if err := t.write(ctx, t.Eng, func(e model.Env) error {
			_, err := e.RemoveMember(t.Tail, strconv.FormatInt(ident, 10))
			return err
		}); err != nil {
			return nil, fmt.Errorf("single remove: %w", err)
		}
		removes = append(removes, time.Since(start))
	}
	const chainNote = "at the bottom of a chain of 12 groups"
	add(latency("single_add", "Single direct add, <= 50 ancestors, effective state visible on response", "p95", 0.95, 75, adds, chainNote),
		latency("single_remove", "Single direct remove, <= 50 ancestors, effective state visible on response", "p95", 0.95, 75, removes, chainNote))

	// loader: Loader changes, engine complete: <= 60 s
	spec.logf("measure: loader of %d changes", spec.Loader)
	loader, err := t.loader(ctx, rng)
	if err != nil {
		return nil, fmt.Errorf("loader: %w", err)
	}
	add(loader)

	// provisioning, the nesting of the reference group and verification
	rs, err := t.provisioning(ctx, rng)
	if err != nil {
		return nil, fmt.Errorf("provisioning: %w", err)
	}
	add(rs...)

	// nightly verification: <= 45 min, with the reference group nested (the heaviest state)
	spec.logf("measure: verification")
	start = time.Now()
	var vr *engine.VerifyReport
	if err := t.write(ctx, t.Eng, func(e model.Env) (err error) { vr, err = t.Eng.Verify(e.Tx, e.Now); return }); err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	add(total("verify", "Nightly full verification of the reference tenant", 45*time.Minute, time.Since(start),
		fmt.Sprintf("%d groups, %d checks, in one transaction on this database", vr.Groups, vr.Checked)))
	add(Result{Name: "verify_clean", Design: "A difference is a bug (section 6.6)", Stat: "repairs", Unit: "rows", Value: float64(vr.RepairCount),
		Samples: 1, Pass: vr.RepairCount == 0})

	// storage: what the effective rows took, extrapolated to the reference tenant
	if spec.DBPath != "" {
		full := float64(max(0, t.EffectiveBytes)) / (spec.Percent / 100) / (1 << 30)
		add(Result{Name: "storage", Design: "Storage: grp_effective and its index", Stat: "extrapolated", Limit: 4, Unit: "GB", Value: full, Samples: 1, Pass: full <= 4,
			Note: fmt.Sprintf("the database file grew %d MB for %d effective rows (%d bytes a row) while they were written; scaled to 100%%",
				t.EffectiveBytes>>20, t.Stats.Effective, t.EffectiveBytes/max(1, t.Stats.Effective))})
	}

	// term rollover: no number in the design (question 9), reported
	spec.logf("measure: term rollover")
	rs, err = t.rollover(ctx, rng)
	if err != nil {
		return nil, fmt.Errorf("term rollover: %w", err)
	}
	add(rs...)
	return rep, nil
}

// loader applies Loader membership changes (half adds, then the same rows
// removed) in transactions of 500, as a batch loader would, then lets the
// engine finish whatever it queued.
func (t *Tenant) loader(ctx context.Context, rng *rand.Rand) (Result, error) {
	leaves := t.Levels[0]
	type change struct {
		g     store.GroupID
		ident int64
	}
	adds := make([]change, max(1, t.Spec.Loader/2))
	for i := range adds {
		adds[i] = change{leaves[rng.Intn(len(leaves))], t.Idents[rng.Intn(len(t.Idents))]}
	}
	start := time.Now()
	have := map[change]bool{}
	for _, phase := range []string{"add", "remove"} {
		if err := t.chunks(ctx, t.Eng, len(adds), 500, func(e model.Env, lo, hi int) error {
			for _, c := range adds[lo:hi] {
				switch phase {
				case "add":
					res, err := e.AddMember(c.g, model.MemberInput{Identity: &c.ident})
					if err != nil {
						return err
					}
					if res.Created {
						have[c] = true
					}
				default:
					if !have[c] { // it was a member before the load: leave it
						continue
					}
					if _, err := e.RemoveMember(c.g, strconv.FormatInt(c.ident, 10)); err != nil {
						return err
					}
					delete(have, c)
				}
			}
			return nil
		}); err != nil {
			return Result{}, err
		}
	}
	chunks, err := t.drain(ctx)
	if err != nil {
		return Result{}, err
	}
	changes := 2 * len(adds)
	note := fmt.Sprintf("%d changes (half adds, half removes), %d queued chunks drained", changes, chunks)
	// a shorter run than the design's 50,000 changes gets a proportional limit
	limit := time.Duration(float64(60*time.Second) * float64(changes) / 50000)
	if changes < 50000 {
		note += fmt.Sprintf("; fewer than 50,000, so the limit is scaled to %s", limit.Round(time.Millisecond))
	}
	return total("loader", "Loader run with 50,000 membership changes: engine complete", min(limit, 60*time.Second), time.Since(start), note), nil
}

// drain runs the engine queue to empty and returns the number of chunks.
func (t *Tenant) drain(ctx context.Context) (int, error) {
	chunks := 0
	for {
		var did bool
		if err := t.write(ctx, t.Eng, func(e model.Env) (err error) { did, err = t.Eng.Drain(e.Tx, e.Now); return }); err != nil {
			return chunks, err
		}
		if !did {
			return chunks, nil
		}
		chunks++
	}
}

// provConfig is a SCIM target configuration that validates; the in-memory target
// replaces the connection, so only the common part is used.
func provConfig() json.RawMessage {
	b, _ := json.Marshal(map[string]any{"account_system": "dir", "member_ref": "{{.Username}}",
		"group_name": `{{.Name | replace ":" "-"}}`, "target": map[string]any{"base_url": "https://scim.example.com/scim/v2"}})
	return b
}

// provisioning measures the incremental path (event to op applied), then the
// nesting of the reference group into the group 400 policy groups use: the time
// until the engine is complete and until the first provisioning ops are applied.
func (t *Tenant) provisioning(ctx context.Context, rng *rand.Rand) ([]Result, error) {
	spec := t.Spec
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		return nil, err
	}
	target := NewMemTarget()
	svc := &provisioning.Service{DB: t.DB, Sealer: sealer, Clock: t.Now, Sleep: func(context.Context, time.Duration) {},
		Open: func(context.Context, provisioning.TargetSpec) (provisioning.Provisioner, error) { return target, nil }}
	var prov *store.Provisioner
	if err := t.write(ctx, t.Eng, func(e model.Env) (err error) {
		prov, err = svc.Create(e.Tx, e.Now, "benchgen", provisioning.CreateInput{Name: "bench", TargetType: provisioning.TypeSCIM2,
			Config: provConfig(), Secret: map[string]string{"token": "bench-token"}, Failsafe: json.RawMessage(`{}`)})
		if err != nil {
			return err
		}
		_, err = svc.SetMark(e.Tx, e.Now, "benchgen", prov.ID, provisioning.MarkInput{ObjectType: "folder", ObjectID: string(t.PolicyFolder),
			Scope: "sub", Include: true})
		return err
	}); err != nil {
		return nil, fmt.Errorf("create: %w", err)
	}
	run := func(kind string) (*provisioning.Report, error) {
		return svc.Run(ctx, t.ID, prov.ID, provisioning.RunOptions{Kind: kind})
	}
	// review the first run (adopt mode), then go active and sync in full
	spec.logf("measure: provisioning, first full sync of %d policy groups", len(t.Policy))
	if _, err := run(store.RunFull); err != nil {
		return nil, fmt.Errorf("adopt run: %w", err)
	}
	active := store.ProvModeActive
	if err := t.write(ctx, t.Eng, func(e model.Env) error {
		p, err := e.Tx.Provisioner(prov.ID)
		if err != nil {
			return err
		}
		_, err = svc.Update(e.Tx, e.Now, "benchgen", prov.ID, provisioning.UpdateInput{Version: p.Version, Mode: &active})
		return err
	}); err != nil {
		return nil, fmt.Errorf("activate: %w", err)
	}
	start := time.Now()
	if _, err := run(store.RunFull); err != nil {
		return nil, fmt.Errorf("full sync: %w", err)
	}
	var out []Result
	_, ops, _, _ := target.Counts()
	out = append(out, total("provision_full_sync", "First full sync of the policy groups (no target in the design)", 0, time.Since(start),
		fmt.Sprintf("%d policy groups, %d target ops", len(t.Policy), ops)))

	// effective change -> provisioning op applied (p95 <= 60 s, target latency excluded)
	spec.logf("measure: provisioning, incremental")
	ns := min(spec.Samples, 40)
	idle := 0
	ds, err := sample(ns, func(i int) error {
		k := rng.Intn(len(t.Policy))
		ident := t.Idents[rng.Intn(len(t.Idents))]
		if err := t.write(ctx, t.Eng, func(e model.Env) error {
			_, err := e.AddMember(t.PolicyLeaf[k], model.MemberInput{Identity: &ident})
			return err
		}); err != nil {
			return err
		}
		rep, err := run(store.RunIncremental)
		if err != nil {
			return err
		}
		if rep.Idle {
			idle++
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("incremental: %w", err)
	}
	note := "one direct add into a leaf a policy group uses, then one incremental run, against an in-memory target"
	if idle > 0 {
		note += fmt.Sprintf("; %d runs found nothing to do", idle)
	}
	out = append(out, latency("provision_incremental", "Effective-change event to provisioning operation applied (incremental)", "p95", 0.95, 60000, ds, note))

	// nest the reference group into the group every policy group uses
	spec.logf("measure: nesting the reference group (%d members) into a group used by %d policy groups", t.Stats.Counts.Ref, len(t.Policy))
	target.Reset()
	start = time.Now()
	var queued bool
	if err := t.write(ctx, t.Eng, func(e model.Env) error {
		res, err := e.AddMember(t.Target, model.MemberInput{Group: t.Ref})
		queued = res != nil && res.Outcome.Queued
		return err
	}); err != nil {
		return nil, fmt.Errorf("nest: %w", err)
	}
	// The engine drains in chunks; the provisioner follows the effective changes
	// as they commit, so it runs after each chunk until it has written something.
	// complete counts the engine's time only (the request and its chunks).
	engineTime := time.Since(start)
	var first time.Duration
	var trace []string
	chunks := 0
	for {
		begin := time.Now()
		var did bool
		if err := t.write(ctx, t.Eng, func(e model.Env) (err error) { did, err = t.Eng.Drain(e.Tx, e.Now); return }); err != nil {
			return nil, fmt.Errorf("drain: %w", err)
		}
		if !did {
			break
		}
		engineTime += time.Since(begin)
		chunks++
		if first == 0 {
			begin = time.Now()
			if _, err := run(store.RunIncremental); err != nil {
				return nil, fmt.Errorf("incremental during drain: %w", err)
			}
			if f := target.FirstApply(); !f.IsZero() {
				first = f.Sub(start)
			}
			trace = append(trace, fmt.Sprintf("chunk %d done at %s, the run after it took %s", chunks, engineTime.Round(time.Millisecond), time.Since(begin).Round(time.Millisecond)))
		}
	}
	complete := engineTime
	if first == 0 {
		if _, err := run(store.RunIncremental); err != nil {
			return nil, fmt.Errorf("incremental after drain: %w", err)
		}
		if f := target.FirstApply(); !f.IsZero() {
			first = f.Sub(start)
		}
	}
	mode := fmt.Sprintf("queued, %d chunks", chunks)
	if !queued {
		mode = "inside the budget, applied in the request"
	}
	out = append(out, total("nest_reference_complete", "Add a 45,000-member group into a group used by 400 policy groups: complete", 5*time.Minute, complete,
		fmt.Sprintf("%d members, %d policy groups, %s; engine time only", t.Stats.Counts.Ref, len(t.Policy), mode)))
	r := total("nest_reference_first_ops", "Add a 45,000-member group into a group used by 400 policy groups: first provisioning ops start", 30*time.Second, first,
		"from the request until the first Apply on the target; "+strings.Join(trace, "; "))
	r.Pass = first > 0 && first <= 30*time.Second
	out = append(out, r)
	// catch the provisioner up (reported: the design has no number for it)
	start = time.Now()
	for i := 0; i < 1000; i++ {
		rep, err := run(store.RunIncremental)
		if err != nil {
			return nil, fmt.Errorf("catch up: %w", err)
		}
		if rep.Idle {
			break
		}
	}
	_, ops, adds, _ := target.Counts()
	out = append(out, total("provision_catch_up", "Provisioner caught up after the nesting (no target in the design)", 0, time.Since(start),
		fmt.Sprintf("%d ops, %d member adds on the target", ops, adds)))
	return out, nil
}

// rollover builds one term of course rosters (small groups, a handful of
// members each) and rolls it over: the old term's groups are deleted and the
// next term's are created. The design leaves this open (question 9) and asks for
// the benchmark to include it.
func (t *Tenant) rollover(ctx context.Context, rng *rand.Rand) ([]Result, error) {
	n := t.Stats.Counts.Roster
	const members = 10
	var term [2][]store.GroupID
	mkTerm := func(label string) (store.FolderID, error) {
		var id store.FolderID
		err := t.write(ctx, t.Eng, func(e model.Env) error {
			f, err := e.CreateFolder(model.CreateFolderInput{Parent: t.Root, Extension: "roster" + label})
			if err == nil {
				id = f.ID
			}
			return err
		})
		return id, err
	}
	build := func(i int, folder store.FolderID) error {
		return t.chunks(ctx, t.Eng, n, 100, func(e model.Env, lo, hi int) error {
			for c := lo; c < hi; c++ {
				g, err := e.CreateGroup(model.CreateGroupInput{Folder: folder, Extension: "course" + strconv.Itoa(c)})
				if err != nil {
					return err
				}
				term[i] = append(term[i], g.ID)
				for _, k := range rng.Perm(len(t.Idents))[:min(members, len(t.Idents))] {
					if _, err := e.AddMember(g.ID, model.MemberInput{Identity: &t.Idents[k]}); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
	f0, err := mkTerm("fall")
	if err != nil {
		return nil, err
	}
	start := time.Now()
	if err := build(0, f0); err != nil {
		return nil, err
	}
	built := time.Since(start)
	f1, err := mkTerm("spring")
	if err != nil {
		return nil, err
	}
	start = time.Now()
	if err := t.chunks(ctx, t.Eng, len(term[0]), 100, func(e model.Env, lo, hi int) error {
		for _, g := range term[0][lo:hi] {
			if err := e.DeleteGroup(g); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	archived := time.Since(start)
	start = time.Now()
	if err := build(1, f1); err != nil {
		return nil, err
	}
	next := time.Since(start)
	note := fmt.Sprintf("%d roster groups of %d members", n, members)
	return []Result{
		total("rollover_build_term", "Term rollover: create a term's roster groups (design question 9)", 0, built, note),
		total("rollover_archive_term", "Term rollover: delete the old term's roster groups", 0, archived, note),
		total("rollover_next_term", "Term rollover: create the next term's roster groups", 0, next, note),
	}, nil
}
