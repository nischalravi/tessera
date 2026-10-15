Brief of [deployment-readiness.md](../deployment-readiness.md). Checked 2026-10-10 against origin/dev d9a42f3.

## Purpose
Connections to customer directories (AD, LDAP, Entra, Okta, Google, Workday, SCIM) are governed objects: checklist, gated state machine, read-only validation, dry-run reconciliation, health score. Requirement: a connection cannot reach `active` unless every applicable Required item passes.

## Non-negotiable rules
- Connection = `connections` row + `connection_revisions`; state lives on the revision. States: `draft > ready_to_validate > validated > dry_run_reconciled > active`; plus `degraded` (from active), `retired`.
- ONLY `internal/readiness` changes revision state. Test `TestOnlyReadinessWritesConnectionState` (go/parser scan) enforces it. Never add another writer.
- `readiness.ActiveConnection` has unexported fields; only `readiness` constructs it. `ingest.SyncActive` takes it; dry runs use `ingest.Stage` (writes `stg_*` only, never the live graph).
- Required items are never skippable (422 `required_item_not_skippable`). Recommended skip needs a reason of 20+ chars. Customer overlays add items or raise levels, never lower (422).
- Refused transitions return 409 with the gate report (`error: activation_blocked`, `blocking[]`). Activate re-evaluates the gate in one tx with compare-and-set on (state, config_hash, gate_version).
- Evidence is bound to `config_hash` (SHA-256 of JCS non-secret config + secret version + template@version + overlay); change makes results stale. Live results expire after 24 h.
- Correlation: tier 1 exact HR id; tier 2 immutable cross-system link; tier 3 (email/UPN) only proposes to the review queue, never auto-links.
- Template vocabulary is closed (no expression language). Simulated (demo) results can never satisfy gates for real connector types.
- Every table: `tenant_id TEXT NOT NULL REFERENCES tenants(id)`, no default; unique constraints start with `tenant_id`; SQL only in `internal/store`.

## Security properties
- Live checks are read-only by construction: `connectors.Prober` has no write method. Least privilege is checked by reading effective rights, never by attempting writes. Test `TestProbers_ReadOnly` uses a recorder.
- Bounds: 10 s per check, 120 s per run, at most 500 samples per class, concurrency 2, abort on first 429, one run per revision at a time (409), 6 runs/connection/h, 1 dry run in flight per tenant.
- No secrets in results (tests scan serialised output for secret bytes). Samples hold fill counts, or ids and names only, capped at 10, expire after 30 days.
- HTTP probes use `safehttp` plus per-template host allowlists. Private directories only via the Directory Agent (local allowlist, outbound mTLS, typed ops only; DR-11, not built). Credential endpoint is write-only.
- Planned, not built: step-up, RBAC permissions (`connections.read|manage|activate`), two-person activation for `write_mode != off` (DR-10); ledger evidence events and export (DR-8).

## Layout (as built, mvp/server)
| Path | Contents |
|---|---|
| `internal/readiness/` | `state.go` (Service: Transition, Activate, Retire, Degrade, Recover, CanWrite, ActiveConnections), `gate.go`, `eval.go`, `confighash.go`, `config.go` (`IsDemoType`), `runner.go`, `runs.go`, `dryrun.go`, `dryrun_view.go`, `score.go`, `attention.go`, `scope.go`, `view.go`, `demo.go`, `errors.go`, `service.go` (`Bundle`) |
| `internal/readiness/template/` | `types.go` (Level: required/recommended/optional), `load.go`, `lint.go`, `overlay.go`, `catalog.go`, `testdata/counts.golden` |
| `internal/readiness/templates/` | `base,ad,ldap,entra,okta,google,workday,scim_app.yaml`, `embed.go` |
| `internal/readiness/checks/` | `check.go`, `live.go`, `data.go` |
| `internal/reconcile/` | `snapshot,prepare,correlate,findings,rules(.go/.yaml),impact,cause.go` |
| `internal/connectors/` | `probe.go` (Prober), `demo_ad.go`, `scenario.go`, `demo_readiness/{happy,gaps}.yaml` |
| `internal/ingest/stage.go` | `Stage`, `SyncActive` |
| `internal/store/` | `model_readiness.go`, `repo_connections.go`, `repo_readiness.go`, `repo_staging.go`, `repo_scores.go`; `schema/0201_connections.sql`, `0202_readiness.sql`, `0203_staging.sql` |
| `internal/api/` | `connections.go`, `validations.go`, `dryruns.go`, `deployment_health.go`, `openapi_readiness.{go,json}` |
| `cmd/tessera/readiness.go` | `readiness lint` |

Frontend (mvp/frontend/src): `features/admin/connections/{ConnectionsList,Wizard,ValidationResults,ReconReport,FindingDrawer,shared,index}`, `components/{Checklist,Stepper}.tsx`, `features/insights/DeploymentHealth.tsx`, `features/home/Home.tsx`, `features/inbox/`, `app/nav.ts`, `app/CommandPalette.tsx`, `api.ts`.

DR-9 (#90, on branch `agent/90-readiness-drift`): `readiness/drift.go` (baseline, `Compare`, `Monitor`, `DegradeReasons`, `RequireWrite`, template upgrade grace, `Tasks`), `readiness/schedule.go` (`Scheduler`, `JobHook`), `store/repo_baselines.go`, `schema/0209_readiness_baselines.sql`, `template.Registry.Archive`, `cmd/tessera/readiness_jobs.go`.

Not yet existing: `readiness/evidence.go`, `internal/safedial`, `internal/agent`, `cmd/tessera-agent`, per-directory `internal/connectors/{ad,ldap,entra,...}/probe.go`.

## Key names
- Score: `levelWeight` required 5, recommended 2, optional 0; `severityPenalty` critical 15, high 8, medium 3, low 1; `PenaltyCap` 40; `RequiredCap` 49 (cap below 50 while a Required item fails); bands healthy, needs_attention, at_risk, not_ready.
- Template counts (template + base = total): ad 36+13=49, ldap 23+13=36, entra 17+13=30, okta 14+13=27, google 15+13=28, workday 15+13=28, scim_app 13+13=26. Regenerate golden: `go test ./internal/readiness/template -run TestTemplates_Counts -update`.
- Findings RF-01..RF-12; audit events `connection.{created,state_changed,activated,degraded,recovered,retired}`, `readiness.{validation.*,dryrun.completed,item.skipped,item.unskipped,finding.accepted}`.

## Tests
- Run: `cd mvp && ./run.sh test` (go vet + `go test ./...`, includes API parity replay); `./run.sh build` (Go build + frontend type-check). Race tests exist (`race_test.go`); CI runs race Go tests with a 25m timeout.
- Existing: `TestStateMachine_AllTransitions`, `TestGate_EachConditionBlocks`, `TestActivate_ConcurrentCAS`, `TestSimulated_CannotGateRealTypes`, `TestOnlyReadinessWritesConnectionState`, `TestIsolation_ReadinessAuditAndStateScoped`, api `isolation_readiness_test.go` and `health_test.go`, store `isolation_readiness_test.go`.
- New routes must be in `openapi_readiness.json`, in the isolation route-coverage test, and tenant-scoped. New tables need isolation tests with sentinel data in tenant B. Demo seed must not change default `demo` output (parity fixtures).

## PR plan (issue)
| PR | Scope | Issue | State |
|---|---|---|---|
| DR-1..DR-7 | templates; connections+gating; check framework; staging+recon; score+API; wizard UI; Insights/Home UI | #82-#88 | merged (#120) |
| DR-8 | evidence export, ledger events (needs Phase 0 PR3 #7, merged) | #89 | open |
| DR-9 | drift, Degraded, scheduled re-runs, template upgrades | #90 | open |
| DR-10 | tenancy finish, RBAC, step-up, two-person activation (needs #9, #12, #16) | #91 | open |
| DR-11 | Directory agent, `safedial` (needs #6, merged) | #92 | open |
| DR-12..17 | live checks: AD, OpenLDAP/389-DS, Entra, Okta, Google, Workday (needs-human) | #93-#98 | open |
| DR-18 | generic SCIM live checks | #99 | open |

## Read which section
| Task | Sections |
|---|---|
| Template/item YAML, new checks | 3.1-3.6, then the directory's 3.7-3.13; 3.14 counts |
| State machine, gates, activation | 4.1-4.5 |
| Live checks, prober, safe network | 5.1-5.4 |
| Reconciliation, findings RF-xx, causes | 6 |
| Score, attention, drift, evidence | 7 |
| Structs, DDL, packages | 8.2-8.4 |
| Routes, permissions | 9 |
| UI | 10 |
| Threat model | 11 |
| Slice scope, demo walkthrough | 12 |
| PR files and tests | 13 (DR-n heading) |

## Known deviations (doc vs code)
- Tables are tenant-scoped (no default tenant id); the doc's "before PR1" default-tenant text was updated. Readiness routes run under `DevDefaultTenant` (larkspur) until auth (PR5, #9) lands (server.go).
- Demo seed creates the Okta (demo) connection for `larkspur` only; `globex` starts with none; `TESSERA_READINESS_DEMO=off` skips it.
- State setter is the store query `connection_revisions.set_state`, not a `SetRevisionState` method; `ingest.SyncActive`, not `ingest.Sync`.
- OpenAPI for readiness is a separate `openapi_readiness.json` served at `/api/readiness/openapi.json`, not merged into `openapi.json`.
- Audit uses the current `c.Audit(...)` helper; routes have no step-up or RBAC (DR-10), so no 403 `phase0_required` was found in code (unverified whether gating by `TESSERA_ENV` exists; `IsDemoType` and the simulated-result rule exist).
- Routes `validate` and `dry-run` are "phased": each run commits in several transactions.
- Missing from the section 9 table (unverified, not found in route list): evidence routes (DR-8), `/api/connections/{id}/readiness/evidence`.
