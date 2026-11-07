[Full design: azure-rbac-evaluator.md](../azure-rbac-evaluator.md) | Checked 2026-11-07 against origin/dev 7fd5019 | **Status: draft, awaiting human approval**

# Brief: Azure RBAC evaluator

Goal: pure-Go engine answering "can principal P perform action A at scope S, and why", exact vs real Azure (nightly sandbox agreement: Wilson 95% lower bound >= 99.5%, n >= 10,000, every stratum >= 99%, 14 green nights). Second exit criterion: a role-assignment or custom-role PR shows exactly who gains or loses what. Model: the AWS evaluator; this design states only what differs. Issue #667 (AZ-0); then AZ-1..AZ-6.

## Non-negotiable rules
- Decision = `authz.Decision`: `ALLOW | DENY | CONDITIONAL(residual)` + fidelity `EXACT | APPROXIMATE | UNSUPPORTED` with reason codes. "Unknown" is CONDITIONAL (needs context) or UNSUPPORTED (layer not modelled). A wrong confident answer is worse than CONDITIONAL.
- Order (§4.1, §7.1): deny assignments first (DENY explicit), then role assignments (union; `Actions - NotActions`, `DataActions - NotDataActions` per permission block), then the matching assignment's condition, then resource locks (DENY guardrail). All stages run for the trace.
- `NotActions` is not a deny; a second role can grant. Conditions never deny and only filter their own assignment. `Actions: *` never grants a data action.
- Inheritance: `/` -> management groups -> subscription -> resource group -> resource -> nested child resources. Deny assignments skip children when `DoNotApplyToChildScopes`. `assignableScopes` is ignored at evaluation (lint only).
- Deny matching: All Principals (zero GUID, `SystemDefined`) or P/any group of P in `Principals`, and nobody of P's set in `ExcludePrincipals` (transitive: AZ-A5).
- Groups: transitive Entra membership in the snapshot. PIM eligible never grants now; potential mode gives `CONDITIONAL(pim.activate(id))`.
- Case: actions, scopes, GUIDs ASCII case-insensitive; condition strings case-sensitive unless `IgnoreCase`.
- Ambiguity: permissive default, `AMBIGUITY:AZ-A<n>`, probe (§4.10, AZ-A1..A10). Never skip an unparseable object: `UNSUPPORTED POLICY_UNPARSEABLE`.
- Out of scope: classic administrators (retired; converted to Owner assignments, which are covered), Azure Policy, Entra directory roles. UNSUPPORTED: non-RBAC data planes, Lighthouse, unknown condition attributes, deny assignments with a condition, unread root scope.

## Security properties
- Untrusted input: strict JSON parse, condition grammar with size/depth/set caps, linear-time glob (shared with AWS, moved to `internal/authz/glob`), fuzzing, per-evaluation deadline.
- Purity: `internal/azure/{model,cond,eval,snapshot,index,query}` do no I/O, no clock, no map-order dependence; traces byte-identical.
- Collector read-only, federated (workload identity federation, no stored secret; secret/cert mode only behind a flag prod refuses), all HTTP via `safehttp`, no Azure SDK. `azure_*` tables tenant-scoped, isolation-tested, both dialects.
- `/api/azure/*` read-only (except connector settings), tenant-scoped, RBAC-declared, audited.

## Key types and names (planned)
- `internal/azure/model`: `Snapshot`, `ScopeTree`, `RoleDef{Blocks []PermBlock}`, `Assignment{Source direct|pim_active|pim_eligible}`, `DenyAssignment`, `Lock`, `Principal`, `Closure`.
- `internal/azure/cond`: v2.0 parser and three-valued evaluator. `eval.Request` implements `authz.Request`, `Platform() == "azure"`.
- New `authz.Stage`: `azure_deny`, `azure_role`, `azure_pim`, `azure_lock`. Reason codes in §3.2-3.3 (`LOCK_EFFECT_UNVERIFIED`, `NON_RBAC_AUTHZ_LAYER`, `CROSS_TENANT_DELEGATION`, `CONDITION_UNSUPPORTED`, `DENY_CONDITION_UNSUPPORTED`, `ROOT_SCOPE_UNREAD`, ...).

## Layout, under mvp/server (planned)
- `internal/azure/{model,cond,scope,catalog,eval,snapshot,index,query,render,harness,azreplay}`; shared harness core `internal/harnesscore` (Wilson, minimizer, triage) extracted from AWS without behaviour change.
- Collector: extend `internal/connectors/azurerbac` (ARM, Microsoft.Authorization 2022-04-01, PIM 2020-10-01) and `internal/connectors/entra` (Graph transitive membership, custom security attributes).
- `catalog/azure/`: provider operations (`isDataAction`), `attributes.yaml`, data-plane model table. Schema `0NNN_azure_snapshots.sql` + Postgres variant. Golden `testdata/azure/golden/` with ids **AZG-nn** (not GC-nn).

## Honest status
- Nothing built. `azurerbac` today emits one permission per (scope, role), ignoring NotActions, deny assignments, conditions and inheritance; it authenticates with a client secret or certificate.
- No Microsoft API decides access for an arbitrary principal that we could confirm (Q2). The oracle is real calls by probe principals; `Permissions - List For Resource` is a caller-only cross-check.

## Oracle and gate
- O1 real calls in a sandbox tenant (canary resources, deployment stacks for deny assignments, PIM schedules, locks); O2 `Permissions - List For Resource` cross-check (never counted). Strata §10.2. Gate = AWS §13.7.

## PR plan (after human approval)
- AZ-1 types + parsers (condition language, scope IDs, glob move). AZ-2 collector + catalog + persistence + federated credentials. AZ-3 evaluator. AZ-4 golden corpus (AZG-01..34+) + ambiguity register doc. AZ-5 harness + sandbox + nightly (`.github/`, infra: `needs-human`). AZ-6 indexes, queries, `/api/azure/*`, PR comment, UI.
- Critical path AZ-1 -> AZ-3 -> AZ-4 -> AZ-5. Depends on EP-4 for the stratified generator.

## Which sections to read
- Semantics: §4 (order §4.1, scopes §4.2, actions §4.3, deny §4.4, groups §4.5, PIM §4.6, locks §4.8). Condition language: §5. Scope cut and reason codes: §3. Algorithm: §7.1. Collector, reader permissions, credentials: §9. Harness and sandbox: §10. Golden cases: §11. PR scope: §12. Open questions Q1-Q8: §15. Sources: §16.

## Open questions (summary)
- Q1 sandbox ownership (dedicated tenant) and budget; Q2 any checkAccess-style oracle; Q3 root-scope visibility without elevation; Q4 Resource Graph for bulk reads; Q5 Terraform vs Bicep; Q6 Entra directory roles later; Q7 PIM eligibility in reviews; Q8 shared explanations route.
