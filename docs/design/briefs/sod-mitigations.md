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
See the PR description: control library, four-eyes mitigations with mandatory end date, remediation options per risk, expiry sweep, review context, evidence export, UI.

## Read when changing this
`internal/sod/{model,detect,service,bundle,compile}.go`, `internal/policy/sod.go`, `internal/api/sod.go`, `frontend/src/features/governance/{SodModel.tsx,sodModel.ts}`, `frontend/src/features/insights/SodConflicts.tsx`, `frontend/tests/sod.test.ts`.
