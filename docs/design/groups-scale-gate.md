# Groups scale gate (GR-17, issue #60)

Companion to `groups-grouper-parity.md` section 6.7. That table gives the performance targets for the
reference tenant ("large university"); this note says how they are measured, what was measured, and
what is still open. The numbers are real runs, not estimates. A target that was missed stays in the
table as a miss.

## What was built

| Piece | Where | What it does |
|---|---|---|
| Generator | `internal/groups/benchgen` (`Generate`) | Loads a tenant of the reference shape at `Percent` of its size through the store and the membership engine, in bounded transactions: identities with an account each, a folder tree (depth 6), four levels of nested basic groups plus a chain of 12, direct rows, a reference group (`ref:student:enrolled`, loaded through the model so it has events and PIT rows), the group every policy group uses, composite policy groups, a folder with N children, and materialized effective memberships. |
| Measurements | `benchgen.Measure` | Every row of the section 6.7 table, in an order that leaves each measurement a fair tenant. Returns `Result`s (value, limit, pass) and renders Markdown or JSON. |
| In-memory target | `benchgen.MemTarget` | A provisioning target with no latency, so provisioning numbers are Tessera's own time ("excluding target API latency"). |
| Command | `cmd/tessera-bench groups` | `-percent`, `-samples`, `-loader`, `-seed`, `-db`, `-md`, `-json`, `-enforce` (exit 1 on a miss). |
| REST gate | `internal/api/groups_scale_test.go` | The same tenant read and written through the HTTP handler as an administrator (routing, authorization, audit, JSON in the numbers; the network is not). |
| Entry point | `./run.sh bench groups [flags]` | Runs the command, then the REST gate at the same percentage. |
| Smoke tests | `benchgen_test.go`, `TestGroupsScaleGate_RESTSmall` | Run in every `go test`, on a tenant of 0.05 to 0.1%: shape, every target measured, incremental engine equals full recompute (`verify_clean`). They assert no timings. |
| Heavy gates | `TestScaleGate`, `TestGroupsScaleGate_REST` | Skipped unless `TESSERA_GROUPS_SCALE_GATE=1`; they fail the test on a miss. |

Tenant counts at `Percent` p (with small floors): groups 150,000 p, folders 25,000 p, identities
600,000 p, direct rows 3,000,000 p, reference group 45,000 p, policy groups 400 p, folder children
5,000 p, roster groups 20,000 p. The loader run is always 50,000 changes. The shape (90/6/3/1% of
groups on four levels, fan-in 10/5/5) gives about 17.6 million effective rows per 100%, close to the
design's 20 million.

## What was measured

Backend: SQLite (the design's SQLite numbers apply to tenants up to 10%), 10% tenant: 15,000 groups,
2,500 folders, 60,000 identities, 300,000 direct rows, 1,758,117 effective rows, a reference group of
4,500, 40 policy groups, 500 browse children. Generation takes 12 minutes. One developer machine, other
work running; treat the numbers as indicative, repeat them on the CI runner. The limits are the
design's, unscaled.

| Target | Limit | Measured | |
|---|---|---|---|
| `hasMember` p99 (engine / REST) | 5 ms | 0.6 ms / 4.2 ms | pass (REST is close) |
| Members, first page of 100 by name, p95 (reference group / nested group / REST) | 100 ms | 5.9 / 15.6 / 18.3 ms | pass |
| Groups of an identity, p95 (engine / REST) | 80 ms | 1.4 / 2.8 ms | pass |
| Folder browser, 500 children, p95 (engine / REST as admin) | 300 ms | 1.5 / 4.8 ms | pass |
| Single add p95 at the bottom of a chain of 12 (engine / REST) | 75 ms | 48.7 / 53.4 ms | pass |
| Single remove p95 (engine / REST) | 75 ms | 46.0 / 50.3 ms | pass |
| PIT members as of T, all 4,500 members (engine / REST) | 2 s | 0.011 / 0.108 s | pass |
| Incremental event to provisioning op applied, p95 | 60 s | 0.37 s | pass |
| Nest the reference group into the 40-policy group: engine complete | 300 s | 30.7 s | pass |
| Same: first provisioning op applied | 30 s | 31.6 s | **fail** |
| Nightly full verification (1.95 million checks) | 45 min | 60.6 s | pass, 0 repairs |
| **Loader, 50,000 membership changes, engine complete** | 60 s | **864 s** | **fail** |
| **Storage of `grp_effective`, scaled to 100%** | 4 GB | **20 GB** | **fail** |
| Term rollover, 2,000 roster groups of 10 members: build / archive / next term | no number | 75 / 11 / 77 s | reported |

### The misses

- **Loader: 864 s against 60 s (14 times too slow).** 50,000 single changes (25,000 adds then the
  same rows removed) through `AddMember`/`RemoveMember` in transactions of 500, 17 ms a change. The
  cost per change grows with the tenant (3.8 ms at a 1% tenant, 17 ms at 10%): each change updates
  `grp_effective` for every ancestor and writes an event and PIT rows. A batch loader needs a bulk path
  that coalesces changes per group (one recompute of the affected identities per group per chunk,
  events written in bulk) instead of N single-change propagations; GR-6 (loader) is the place. This is
  the largest gap.
- **First provisioning op: 31.6 s against 30 s at 10%, and growing with the tenant.** The incremental
  run after every engine chunk applied nothing until the last chunk: provisioning defers groups whose
  `recompute_state` is not `clean` (`desired.go`, `deferred_groups`), so the first op waits for the
  engine job. The target therefore cannot be met by a faster provisioner; either provisioning must
  work from the committed part of a recompute (the effective events are already emitted per chunk) or
  the target must be read as "engine complete plus one run". Decision for a human. At 100% (45,000
  members, 400 policy groups) the engine job is the 5-minute budget, so 30 s is out of reach as built.
- **Storage: 1,220 bytes per effective row, 20 GB at 100% against 4 GB.** Measured as the growth of the
  SQLite file (and its WAL) while the effective rows were written, so it includes pages the repeated
  updates of ancestor rows left free, and the indexes. It is an upper bound for `grp_effective` alone,
  but a row is `tenant_id`, `group_id`, `list_id` (three 36-character text values), the identity, the
  support count and a timestamp, stored twice: in the `WITHOUT ROWID` primary key
  `(tenant_id, group_id, list_id, identity_id)` and in `grp_eff_identity`
  `(tenant_id, identity_id, list_id, group_id)`. That is about 250 bytes before page overhead, so the
  real figure is several hundred bytes a row, not 1,220. Narrower keys (a small integer for the tenant,
  the list and the group in the two indexes) are the way to 4 GB. A precise per-table figure needs
  `dbstat` or `pg_total_relation_size`, which the store layer does not expose (every statement binds
  `@tenant`).

## What is not measured, and why

- **Postgres and the 100% tenant.** The groups tables (`grp_*`, schema `0280` to `0286`) have no
  Postgres dialect: `internal/store/schema/postgres` stops at the tables that existed when #18 was
  written, and the schema parity test skips `grp_*` (`pgPending`). `tessera-bench` refuses a Postgres
  `-db`. The 100% tenant is a Postgres target (generation alone would take hours on SQLite), so the
  nightly run on Postgres is blocked on a Postgres port of those migrations, their RLS policies
  (`tessera admin gen-rls`) and a pass over the engine's SQL for the translator. Until then the gate
  runs on SQLite at 10%.
- **The nightly CI job.** It needs a workflow under `.github/`, which the agent may not change. The
  command for it is `./run.sh bench groups -percent 10 -enforce -md groups-scale.md -json groups-scale.json`
  (about 35 minutes), uploading both files; the Markdown is the dashboard of the section 6.7 targets.
  Until the loader and storage misses are fixed the job fails, which is the point of a gate; start it
  as non-blocking.
- **Network and target latency.** REST numbers use the HTTP handler in process; provisioning uses the
  in-memory target.
- **`hasMember` on REST is at 4.2 ms of 5 ms** on this machine; it is the target to watch when the
  audit or authorization path grows.

## Running it

```
cd mvp
./run.sh bench groups                         # 10% tenant, then the REST gate; tens of minutes
./run.sh bench groups -percent 1 -samples 100 # a quick look, about two minutes
cd server && TESSERA_GROUPS_SCALE_GATE=1 go test -run TestScaleGate -timeout 2h ./internal/groups/benchgen
```
