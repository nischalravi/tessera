[Issue #298](https://github.com/nischalravi/tessera/issues/298) (gap vs Saviynt) · Paths relative to `mvp/server/` unless `frontend/`.

# Brief: SoD functions, risks, rulesets and mitigating controls

## Model (PR 1, `agent/298-sod-functions`)
- Function = named set of entitlements (selectors: system + permission id | action pattern, optional resource attribute). Risk = priority, business process, owner, two or more functions, optional `subjects`. Ruleset = named group of risks, enabled per tenant. Schema `0300_sod.sql`: `sod_functions`, `sod_rulesets`, `sod_risks`, `sod_risk_functions`, `sod_versions` (append-only, one table for all three kinds).
- Violation = identity holds a distinct entitlement of each of two of a risk's functions via any graph path. Key `<risk key>:<identity id>` (suffix `:<f1>+<f2>` only for risks of 3+ functions).
- `internal/sod` holds model, validation, versioned audited changes (`Writer`), YAML (`Bundle`, `tessera.sod/v1`) and detection. It must not import `internal/policy`; policy imports it (`policy/sod.go`): each risk becomes a `sod_risk` policy, so simulate, reviews and leaver plans need no second path. `policy.Effective` swaps the file SoD policies for risks.
- Legacy `separation_of_duties` files: `policy.LegacyBundle` converts them (risk key = policy id, so keys and messages are unchanged). Tenant with no stored ruleset: `sod.Load` compiles the legacy bundle in memory. Seed and `POST /api/sod/import-legacy` persist it. Equivalence tests: `internal/policy/sod_test.go`.

## Rules
- Reads `graph.read`; writes `sod.manage` (policy admin) + step-up; simulate `requests.create`. Every mutation audits in the same transaction; seed is `Quiet`.
- A ruleset version snapshots the whole document and moves on whenever a risk or function in it changes (batched in imports).
- Import validates everything first (`plan`), then writes; `prune` retires risks the file drops.

## PR 2 (`agent/298-mitigating-controls`, on PR 1)
- Schema `0301_sod_controls.sql`: `sod_controls`, `sod_mitigations` (partial unique index: one pending or active per risk x identity), `sod_risk_options` (no rows: all four options), `sod_escalations`.
- Four-eyes is enforced in `internal/sod/mitigation.go` (`DecideMitigation`: decider != `requested_by`), not only in the route table. `sod.mitigate` requests and escalates; `sod.approve` decides (approve needs step-up). Early end: risk owner or `sod.approve`, step-up checked in the handler.
- `sod.Covers` gives each violation its status (open, mitigation_pending, mitigated, accepted); a mitigation whose end date has passed stops covering immediately, the sweeper (`sod.Sweep`, in `RunSweeper`) then closes it, warns (`notify.Expiring`) and alerts. `analysis.withoutMitigated` takes covered SoD violations out of `/api/violations` and counts; `/api/sod/violations` keeps them with `open`.
- Revoke option reuses `revokeEdge` (the least-privilege revoke); review items get SoD context from `/api/sod/review-context` (a new endpoint, so the review parity fixtures are unchanged).
- Config: `TESSERA_SOD_MAX_MITIGATION_DAYS` (365), `TESSERA_SOD_WARN_DAYS` (14).

## Part 2 (`agent/298-sod-remediation-request-settings`)
- Schema `0381_sod_remediation.sql`: `sod_ruleset_remediation` (ruleset default options as a JSON list, escalation approver). Effective options: the risk's own `sod_risk_options` rows, else its ruleset's, else all four (`sod.LoadRemediation`, `Remediation.Target`). `PUT /api/sod/rulesets/{id}/remediation` (`sod.manage` + step-up).
- Escalation goes to the ruleset approver, else the risk owner, as a notification (inbox item). Approving an accept or control mitigation queues `sod_mitigation_expire` at the end date in the same transaction (`Writer.OnActivate`); `sod.ExpireOne` re-opens the violation, the sweeper stays the backstop.
- Request settings, schema `0380_request_settings.sql` (`request_settings`, one row per tenant): `internal/requests/settings.go`, enforced in `requests.Submit`; `GET|PUT /api/request-settings` (PUT `catalog.manage` + step-up); Admin page `/admin/request-settings`.

## Read when changing this
`internal/sod/{model,detect,service,bundle,compile}.go`, `internal/policy/sod.go`, `internal/api/sod.go`, `frontend/src/features/governance/{SodModel.tsx,sodModel.ts}`, `frontend/src/features/insights/SodConflicts.tsx`, `internal/sod/{controls,mitigation}.go`, `internal/api/sod_controls.go`, `frontend/src/features/governance/{Mitigations,MitigateDrawers}.tsx`, `frontend/tests/sod.test.ts`.
