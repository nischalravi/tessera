[Full design: access-as-code-repo.md](../access-as-code-repo.md) | Issue #646 (AC-0) | Checked 2026-10-26 against origin/dev 4e7f774 · Paths relative to `mvp/server/`.

# Brief: the access-as-code policy repo (Cedar schema)

**Status: Draft — needs human approval.** Nothing of AC-1..AC-11 is built; `cedar-go` is not in `go.mod`.

## Non-negotiable rules
- Objects are data (YAML → Cedar entities: `Role`, `JitEligibility`, SoD as `tessera.sod/v1`); rules are Cedar policies (`BirthrightRule`, `AgentScope`, `Invariant`). One generated schema (`schema/tessera.cedarschema`) validates all.
- Invariants are `forbid` over facts with an implicit permit; fact shapes are actions `reach` (identity × effective permission), `exist` (identity), `hold_credential` (credential). SoD stays in `internal/sod` (pairwise).
- A non-EXACT `reach` fact never blocks; it is a low-fidelity finding.
- Apply = validate all → plan (writers in dry run, canonical JSON, `plan_sha256`) → apply in ONE `DB.InTenant` transaction with every domain event and `policy.bundle.applied` in it; stale plan → 409; same digest → no-op.
- `full` retires (never deletes) repo-managed objects absent from the bundle; `partial` only upserts. UI objects need `adopt` first. Repo-managed objects refuse other writers with 409 `policy_managed`.
- Grant removals count against the deletion guard; over threshold → refused (atomic), not half-held. Step ceiling → 413.
- Two-person: change type `policy_bundle.apply` in `admin_change_requests`; approver ≠ requester, step-up, echoes payload hash; approval re-plans.
- Bundle never governs Tessera's own RBAC, IdP trust, connectors or write modes.

## Security properties
256 KiB/file, 4 MiB and 2,000 files/bundle, Cedar depth ≤ 32, ≤ 10,000 entities, fuzzed loader; no network in validate. Apply bound to commit SHA + `bundle_sha256`; after AC-10 Tessera fetches the commit itself via `safehttp`. `tessera.yaml` `tenant` must equal the session tenant; references by external key resolved in-tenant only. Perms: `policy.read`, `policy.plan`, `policy.apply` (request), `admin.change.approve` + step-up. Fail closed: bundle unreadable → embedded YAML invariants; JIT with eligibility on → deny.

## Existing code to reuse
`roles.Create/Update/Retire/Reconcile(…, dryRun)` → `Plan`; `roles.Rule` (department/type/title + `abac_policies` id); `jit.CreateRequest`/`Approve` (eligibility today = `groups.requestable`, `MaxHours = 72`); `sod.Writer.Import(b, {Prune, DryRun})`; `policy.Evaluators` (7 types: forbidden_access, no_standing_access, separation_of_duties, terminated_with_access, secret_max_age, nhi_ownership, mfa_required) and `policy.Effective`; `policygroups.Applier` (origin, commit, full, `policy_ref`) is the pattern; `admin.Service.Submit/Approve`; `simulate.Run`, `policy.DiffViolations`.

## Layout (designed)
Repo: `tessera.yaml`, `schema/`, `roles/`, `birthright/`, `jit/`, `sod/`, `agents/`, `invariants/`, `groups/` (GR-9), `tests/`. Server: `internal/cedarx` (AC-1), `internal/policyrepo` (loader, plan, apply, `BlastRadius` hook), `internal/agentscope` (AC-7), `internal/admin/change_policy.go`.

## Key names
Tables: `business_roles.key`/`managed_by`, `business_role_versions.policy_ref` (AC-4); `jit_eligibility`, `jit_eligibility_groups`, `jit_eligibility_versions`, `jit_settings` (AC-5); `sod_rulesets.managed_by` (AC-6); `agent_scopes` (AC-7); `policy_sources`, `policy_versions` (AC-3); `policy_applies`. Routes: `POST /api/policy/{validate,diff,apply}`, `GET /api/policy/applies`. Errors: `invalid_bundle` 422, `stale_plan` 409, `policy_managed` 409, `deletion_guard` 409, `plan_too_large` 413.

## Tests
Isolation test per new table; both dialects (Postgres schema + `gen-rls`); `/api/policies` and `/api/violations` parity fixtures unchanged by AC-3; round-trip import/export (AC-4, AC-6); a plan equals a UI-made change; cross-tenant bundle refused; fuzz the loader.

## PR plan
AC-1 #647 cedarx · AC-2 #648 bundle + CLI · AC-3 #649 invariants · AC-4 #650 roles + birthright · AC-5 #651 JIT eligibility · AC-6 #652 SoD · AC-7 #653 agent scopes · AC-8 #654 blast radius · AC-9 #655 Terraform · AC-10 #656 GitHub App · AC-11 #657 merge sync. Base for two-person: #569.

## Which sections to read
Schema and object formats §3; mapping §5; apply §6; two-person §7; blast hook §8; security §9; open questions §10.

## Open questions (human)
Two-person for every apply vs tighten-only single; approver ≠ PR author; one or many birthright rules per role; refuse vs override large/removal-heavy applies; unscoped agents; invariants on APPROXIMATE facts; signed commits; YAML vs Cedar entity JSON; `business_roles.key`.
