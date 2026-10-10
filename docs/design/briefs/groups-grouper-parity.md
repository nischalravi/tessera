[Full doc: groups-grouper-parity.md](../groups-grouper-parity.md) · Checked 2026-10-10 against origin/dev d9a42f3

# Brief: native groups with Grouper parity (GR-1..GR-20)

Goal: the Grouper connector is import and coexistence only. Paths are relative to `mvp/server/` unless `frontend/`.

## Rules and invariants (non-negotiable)
- K2 one engine. Stored inputs: direct memberships, nesting/factor edges (`grp_deps`), composite defs. `grp_effective` is materialized with support counts; per-identity delta propagation in ascending `grp_levels.level` order. Only identities are stored in `grp_effective`.
- I1: `grp_effective` row exists iff semantics say member; basic-group `support` = active direct identity row (0/1) + active direct group rows whose child contains the identity. I2: `grp_closure` = transitive closure of `grp_deps`; `level(g)=1+max(child)`, leaves 0.
- Composites: n-ary union/intersection, binary complement (left minus right); no direct members (API refuses). Dependency graph acyclic: refuse edge if parent is already a descendant, `409 {"error":"cycle","path":[...]}`.
- Disabled/deleted group = empty set. `IsMember` re-checks the direct row's dates even if the time wheel lags (30 s tick; p99 lag ≤ 60 s).
- Sync budget `TESSERA_GROUPS_SYNC_BUDGET` (default 5,000 row ops): under budget propagate in the API tx with the audit event; over budget commit direct change, enqueue `grp_engine_queue`, `recompute_state='pending'`, return 202 + op id, chunks of 2,000. One engine writer per tenant (Postgres `pg_advisory_xact_lock`); `grp_events.seq` gap-free.
- K5 privileges: Grouper's names, lower-cased; dynamic inheritance (folder row with `scope` one|sub applied at check time, never copied). `everyone` holder needs `tenant_admin`. `tenant_admin` implies all; `auditor` read/view; `viewer` view.
- K6 no arbitrary code: no JEXL, GSH, in-process hooks. Rules: closed vocabulary; privilege check at save AND fire time.  Email rule actions off by default.
- K4 policy groups: restricted Cedar fragment (`permit`/`forbid` on `Tessera::Action::"member"`; only `principal in Group`, attribute ==/in/contains/has, `&&`,`||`,`!`; no context/resource attrs/arithmetic). `E = ⋃permit − ⋃forbid`. Compiled to hash-consed composites (`_allow`, `_deny`, `_n<hash>`); `sys:attr:*` groups for attributes.
- K7 loader failsafe trips => run `held`, nothing applied, Inbox task with downstream impact; unresolved subjects never silently dropped. K8/README rule 4: provisioning op `done` only after targeted re-read (`verified`); 3 failed attempts => `drift` + Inbox task; first run is `adopt` mode (changes nothing).
- K9 every change writes `grp_events` in the same tx; PIT derived from events; daily Merkle digest (RFC 8785 canonical JSON) appended to the audit ledger.
- K11 Grouper connector read-only; each folder has one writer: `mirror` | `shadow` | `native`; mirrored/shadow folders refuse writes `409 folder_mirrored`.
- Phase 0 conventions: every table has `tenant_id`; unique constraints start with `tenant_id`; all SQL only in `internal/store` (archtest `TestIsolation_NoRawSQLOutsideStore` enforces); tenant tables reached through `*store.TenantTx`; UUID text PKs; `identities.id` referenced as INTEGER.

## Security properties
- Loader create/change needs `groups.loader.admin`, fresh phishing-resistant step-up, and a second approver for SQL loaders (GRP-6311). SQL loaders: SELECT/WITH only, read-only tx, timeout 120 s, row limit. LDAPS/StartTLS only; SFTP host keys pinned.
- Rules cannot escalate (GRP-7359). Visualization and browse filtered by VIEW (GRP-7387). Writes accept `Idempotency-Key`; batches ≤ 1,000 ops, atomic by default. Every route audited; every group route privilege-checked (403 test per route).
- No act-as header; no Grouper basic-auth store (compat API uses machine clients).

## Layout
Designed: migrations `internal/store/schema/0101_groups.sql`, `0102_group_privs`, `0103_group_events`, `0104_group_attrs`, `0105_group_loaders`, `0106_group_prov`, `0107_group_gov`; `internal/groups/{naming,model,engine,privs,attrs,policygroups,loaders,provisioning,events,pit,rules,attest,deprov,reports,api,plan,benchgen,grouperconn}`; `internal/api/groups_folders.go` (GR-1); CLI `cmd/tessera-cli`; `frontend/src/features/directory/groups/`.
Actual now: none of the groups code exists (no `internal/groups`, no `grp_*`, no `0101..0107`). Existing: `internal/store/schema/{0001_tenancy,0003_keys,0004_audit,0201..0203}.sql`; `internal/{api,audit,store,tenancy,keys,seal,safehttp,connectors,reviews,archtest,devidp}`; `cmd/{tessera,tessera-devidp}`; frontend `src/features/directory/{Lists,ObjectPages,Panels,IdentityPage,shared}.tsx`, `src/api.ts`.
Clash: existing `groups` table (integer id, connected-system groups, served by `GET /api/groups`, listed in `Lists.tsx`) is NOT the native model; native = `grp_*` + graph node `system='tessera'`.

## Key types and names
`store.{FolderID,GroupID,ListID,Folder,Group,DirectMembership,EffectiveMembership}`; enums GroupKind group|role, Definition basic|composite|policy, CompositeOp, ManagedBy ui|policy_repo|loader|grouper_mirror|connector, MemberType identity|group. Tables: `grp_folders, grp_name_aliases, grp_groups, grp_composite_factors, grp_lists, grp_direct_memberships, grp_deps, grp_closure, grp_levels, grp_effective, grp_engine_queue, grp_privileges, grp_events, grp_event_cursors, grp_pit_{objects,direct,effective,privileges,digests}, grp_loaders, grp_loader_runs, grp_loader_unresolved, grp_provisioners, grp_provisionable, grp_sync_groups, grp_sync_ops, grp_rules`. Engine: `Engine.Apply(ctx, tx, []seed)`, `seed{group,list,identity,delta}`. Interfaces: `loaders.GroupSource{Full,Changes}`, `provisioning.Provisioner{Capabilities,ReadAll,Read,Apply}`. Routes: `/api/groups/...` (§10.11), `/scim/v2/{Groups,Users}` read-only, `/grouper-ws/servicesRest/v2_6_000/` read-only.

## Tests and commands
- `./run.sh test` (go vet + go test ./...), `./run.sh build` (Go + `npm run build` = tsc + vite). CI also runs gofmt, `go test -race -timeout 25m ./...`, govulncheck and gosec (security-scan). Run `go test -race ./...` in `mvp/server` before a PR.
- Named tests by PR: GR-1 `TestIsolation_GroupsTables`; GR-2 `TestEngine_MatchesOracle` (fuzz), `_CycleVeto`, `_SyncBudgetFallsBackToQueue`, `TestTimewheel_DisableWithin60s`, `TestIsMember_IgnoresExpiredRowsWhenWheelLags`, `TestVerify_DetectsAndRepairsInjectedCorruption`; GR-3 `TestPIT_*`; GR-4 `TestPrivs_*`, per-route 403; GR-5 `TestBatch_AtomicAndIdempotent`; GR-9 `TestPolicyGroups_PDPAgreesWithEngine`. Others: §13.

## PR plan (all open, none started; issue = state per issues.txt)
| PR | Issue | Scope | Depends |
|---|---|---|---|
| GR-1 | #44 | store, folder/group CRUD, `tenant_admin` guard | #5,#7,#9 |
| GR-2 | #45 | membership engine | GR-1 |
| GR-3 | #46 | events + PIT + digest | GR-2,#7 |
| GR-4 | #47 | privilege model, `platform_users.identity_id` | GR-2,#9 |
| GR-5 | #48 | REST API, SCIM server, simulate | GR-3,GR-4 |
| GR-6 | #49 | CLI + declarative plans | GR-5,#14 |
| GR-7 | #50 | attribute framework, object types | GR-4 |
| GR-8 | #51 | Directory → Groups UI | GR-5,GR-7 |
| GR-9 | #52 | policy groups as Cedar | GR-2,GR-7 |
| GR-10 | #53 | loaders | GR-5,#16 |
| GR-11 | #54 | provisioning framework (LDAP/AD, SCIM, SQL, webhook) | GR-3 |
| GR-12 | #55 | Entra/Google/Okta (needs-human) | GR-11 |
| GR-13 | #56 | rules, constraints | GR-3,GR-4 |
| GR-14 | #57 | attestation, deprov, reports | GR-3,4,13 |
| GR-15 | #58 | Grouper import, mirror (needs-human) | GR-5,7,10 |
| GR-16 | #59 | shadow, cut-over, WS read API (needs-human) | GR-15,11 |
| GR-17 | #60 | scale gate | GR-2,5,11,#18 |
| GR-18 | #61 | SQS/RabbitMQ/Kafka sinks | GR-3 |
| GR-19 | #62 | permissions and limits (Phase 3) | GR-7,9,15 |
| GR-20 | #63 | long-tail provisioners (Phase 3) | GR-11 |

## Which sections to read
- Schema/store (GR-1..4): §5, §4. Engine: §6. Privileges: §7. API/CLI/UI: §10.11–10.13, §12. Events/PIT: §10.1–10.2, §5.3.
- Policy groups: §8. Loaders/provisioning: §9. Rules/attestation/deprov/reports: §10.3–10.7. Attributes: §10.9. Permissions: §10.10.
- Grouper connector: §11, §3 (inventory), §15. Preconditions, per-PR files/tests: §13. Risks: §14. Capability to PR mapping: §12.

## Known deviations and gaps (verified against code)
- Preconditions unmet: #9 (auth core) is open. Only Phase 0 PR1–PR4 (#5–#8) are merged. No `platform_users` table, no principals/RBAC enforcement; `tenant_admin` appears only in dev IdP config. GR-1 and GR-4 depend on #9; check how roles land before coding guards.
- Doc says `./run.sh test` is `go test -race ./...`; actual `./run.sh test` is vet + `go test ./...` without `-race` (CI uses `-race`). Doc says CI runs staticcheck; no staticcheck anywhere in CI or `run.sh` (gofmt, vet, govulncheck, gosec exist).
- New tables must also be added to the `tables` slice in `internal/store/db.go` (drop order) and satisfy `TestIsolation_EveryTableScopedOrAllowlisted`; the doc does not mention this.
- No `cmd/tessera-cli`; binaries are `cmd/tessera`, `cmd/tessera-devidp`. Whether CLI subcommands will live in `cmd/tessera` is undecided.
- Doc cites `ui-redesign` branch and `features/directory/Lists.tsx`; Lists.tsx is on dev and `features/directory/groups/` does not exist. Frontend has no test runner (no vitest/Playwright in `package.json`); GR-8's component and Playwright tests need that added.
- Doc internal inconsistency: K5/§7.1 say 22 privileges and "9 on attribute definitions", but the tables list 8 attr-def privileges (8+5+8=21; the `grp_privileges` CHECK has 21 values). Resolve before GR-4.
