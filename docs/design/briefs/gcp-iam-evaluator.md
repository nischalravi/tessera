[Full design: gcp-iam-evaluator.md](../gcp-iam-evaluator.md) | Checked 2026-11-07 against origin/dev 7fd5019 | **Status: draft, awaiting human approval**

# Brief: GCP IAM evaluator

Goal: pure-Go engine answering "can principal P use permission X on resource R, and why", exact vs real GCP (nightly sandbox agreement: Wilson 95% lower bound >= 99.5%, n >= 10,000, every stratum >= 99%, 14 green nights). Second exit criterion: a policy PR (allow binding, custom role, deny or PAB change) shows exactly who gains or loses what. Model: the AWS evaluator and the Azure design. Issue #668 (GC-0); then GC-1..GC-6.

## Non-negotiable rules
- Decision = `authz.Decision`: `ALLOW | DENY | CONDITIONAL(residual)` + fidelity with reason codes. "Unknown" is CONDITIONAL or UNSUPPORTED.
- Order (§4.1, §7.1): PAB (not eligible -> DENY guardrail), deny (DENY explicit), allow (none -> DENY implicit); then Org Policy overlay guardrail and VPC-SC flag. All stages run for the trace. Only allow policies grant.
- Hierarchy: org -> nested folders -> project -> resource. Allow policies union down the chain; deny policies attach at org/folder/project and flow down; PAB rules name org/folder/project (covering descendants: GC-A1).
- Deny: permission matches `deniedPermissions` minus `exceptionPermissions` (v2 names, only `RESOURCE.*`, `*.*`, `*.VERB` groups), principal in `deniedPrincipals` minus `exceptionPrincipals` (sets and groups), condition true **or not evaluable** (documented fail-closed). Non-deniable permissions are never denied.
- PAB: relevant if bound to a set containing P and binding condition not false (unevaluable -> enforced); blocks only permissions in the policy's enforcement version; errors fail closed.
- Roles expand to `includedPermissions` at the pinned catalog. Conditional bindings do not override unconditional ones. No conditions on basic roles or `allUsers`/`allAuthenticatedUsers`. `allAuthenticatedUsers` excludes federated identities and anonymous.
- Ambiguity: permissive default `AMBIGUITY:GC-A<n>` with a probe (GC-A1..A10), never against a documented fail-closed rule. Never skip an unparseable or unread policy: UNSUPPORTED.
- Decided (§3.4, human to confirm Q3/Q4): VPC-SC not modelled, IAM allows in a perimeter are APPROXIMATE `VPCSC_PERIMETER`. Org Policy not modelled except member-restriction constraints in the simulate/PR path and a curated boolean overlay as guardrail (`ORG_POLICY_CONSTRAINT`).

## Security properties
- Untrusted input: strict parsers for v1/v2/v3 policies and all identifier syntaxes; a hand-written CEL subset (no general CEL runtime), size/depth caps, fuzzing, per-evaluation deadline.
- Purity of `internal/gcp/{model,policy,cel,principal,eval,snapshot,index,query}`; immutable snapshots; byte-identical traces.
- Collector read-only, federated (workload identity federation + reader SA impersonation, no stored key; key mode only behind a flag prod refuses), `safehttp`, no Google SDK. `gcp_*` tables tenant-scoped, isolation-tested, both dialects.
- `/api/gcp/*` read-only (except connector settings), tenant-scoped, RBAC-declared, audited.

## Key types and names (planned)
- `internal/gcp/model`: `Snapshot`, `ResourceTree`, `AllowPolicy{Bindings}`, `DenyPolicy{Rules}`, `PABPolicy`, `PABBinding`, `Role{Stage, Deleted, Permissions}`, canonical `Principal{Kind, ID}`.
- `eval.Request` implements `authz.Request`, `Platform() == "gcp"`. New `authz.Stage`: `gcp_pab`, `gcp_deny`, `gcp_allow`, `gcp_guardrail`. Reason codes §3.2-3.3 (`VPCSC_PERIMETER`, `ORG_POLICY_CONSTRAINT`, `PAB_VERSION_LATEST`, `NON_IAM_AUTHZ_LAYER`, `EVENTARC_ACCESS_POLICY`, `POLICY_UNREAD`, `GROUPS_UNREAD`, ...).

## Layout, under mvp/server (planned)
- `internal/gcp/{model,policy,cel,principal,catalog,eval,snapshot,index,query,render,harness,gcpreplay}`; harness core shared via `internal/harnesscore`.
- Collector: extend `internal/connectors/gcpiam` (CRM v3, IAM v1/v2/v3, Cloud Asset Inventory) and `internal/connectors/google` (Cloud Identity transitive groups).
- `catalog/gcp/`: roles/permissions, v1<->v2 names, `deny_supported.yaml`, `pab_versions.yaml`, `orgpolicy_overlay.yaml`, `resource_names.yaml`. Schema `0NNN_gcp_snapshots.sql` + Postgres. Golden `testdata/gcp/golden/` ids **GCG-nn** (not GC-nn: AWS corpus and PR prefix).

## Honest status
- Nothing built. `gcpiam` emits one permission per (resource, role), with no inheritance, role expansion, conditions, deny or PAB; it authenticates with a service-account key.
- Policy Troubleshooter is Pre-GA; PAB is only in v3beta; it cannot take groups, domains or federated identities as principals and ignores Storage ACLs, VPC-SC and Pub/Sub resource policies.

## Oracle and gate
- O1 Policy Troubleshooter `iam:troubleshoot` (v3 allow+deny, v3beta +PAB); O2 `testIamPermissions` as probe (caller-only, no wildcards; 5% cross-check); O3 real calls by probe SAs for the rest. VPC-SC stratum reported, not gated. Gate = AWS §13.7.

## PR plan (after human approval)
- GC-1 types + parsers (policies, identifiers, CEL subset). GC-2 collector + catalog + persistence + federated credentials. GC-3 evaluator. GC-4 golden corpus (GCG-01..36+) + ambiguity register doc. GC-5 harness + sandbox org + nightly (`.github/`, infra: `needs-human`). GC-6 indexes, queries, impersonation edges, `/api/gcp/*`, PR comment, UI.
- Critical path GC-1 -> GC-3 -> GC-4 -> GC-5. Depends on EP-4.

## Which sections to read
- Semantics: §4 (order §4.1, hierarchy §4.2, roles §4.3, deny §4.4, PAB §4.5, principals §4.6, impersonation §4.7, PAM §4.8). VPC-SC and Org Policy decision: §3.4. CEL subset: §5. Algorithm: §7.1. Collector and reader roles: §9. Harness: §10. Golden: §11. PRs: §12. Open questions Q1-Q7: §15. Sources: §16.

## Open questions (summary)
- Q1 sandbox organization ownership and budget; Q2 Pre-GA Troubleshooter as oracle; Q3 confirm VPC-SC flag-only; Q4 confirm Org Policy narrow scope; Q5 Cloud Identity groups read at customers; Q6 full SA authentication-role edges; Q7 shared explanations route.
