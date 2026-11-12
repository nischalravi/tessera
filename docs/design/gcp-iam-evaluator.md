# Design: Exact GCP IAM evaluator, with explanations and a differential test harness

| | |
|---|---|
| **Status** | Draft, awaiting human approval. Implementation (GC-1…GC-6) starts only after a human approves this doc and its brief, and `iam-authz-expert` has reviewed §4–§8. |
| **Plan item** | GC-0 (#668) in [`differentiators-plan.md`](differentiators-plan.md) §1. Depends on EP-4 (stratified generator). GC-1…GC-6 follow, with the same ≥ 99.5 % gate as AWS. |
| **Authors** | iam-architect, with iam-authz-expert (semantics) and iam-pam-nhi-expert (service accounts, impersonation, workload identity) |
| **Reviewers needed** | iam-authz-expert: §4–§8 and the golden corpus (§11). iam-pam-nhi-expert: §4.6–§4.7 and §9.3. iam-governance-expert: §7.4 evidence fields. |
| **Date** | 2026-11-07. Google Cloud docs re-read on 2026-11-07; every GCP claim cites a source in §16. |
| **Model** | [`aws-effective-permission-evaluator.md`](aws-effective-permission-evaluator.md) (the "AWS design") and its sibling [`azure-rbac-evaluator.md`](azure-rbac-evaluator.md). This doc reuses their decision model, fidelity rules, harness metrics and gate, and states only what differs. |

---

## 0. Summary of key decisions

| # | Decision | Why |
|---|---|---|
| D1 | A **pure-Go evaluator** in `mvp/server/internal/gcp/` over an immutable snapshot, no I/O, sharing `internal/authz` with AWS and Azure. | One decision and explanation contract across clouds. |
| D2 | `ALLOW`, `DENY`, `CONDITIONAL(residual)` plus fidelity `EXACT`/`APPROXIMATE`/`UNSUPPORTED` (AWS D2). The issue's "unknown" maps to `CONDITIONAL` (a CEL condition needs context) or `UNSUPPORTED`. | Same contract. |
| D3 | Order is Google's: **principal access boundary (PAB) → deny → allow**, all evaluated, results compiled [GC1]. PAB and deny only remove access; only allow policies grant [GC1][GC3]. | Documented model. |
| D4 | Ambiguities default to the **more permissive** reading, flagged `AMBIGUITY:GC-A<n>`, each with a probe (§4.10). **Except** where Google documents fail-closed behaviour (deny conditions and PAB binding conditions that cannot be evaluated *apply* [GC2][GC3]); there the engine follows the documented rule exactly. | Same rule as AWS D3, but never against a documented rule. |
| D5 | The permission catalog is **role definitions plus `queryTestablePermissions`**, snapshotted and pinned (§6.3). Deny-supported permissions and PAB enforcement versions are separate catalog tables. | First-party and machine-readable. |
| D6 | Oracles: **Policy Troubleshooter** `iam:troubleshoot` (v3 for allow + deny; v3beta adds PAB) for any principal, **`testIamPermissions`** as the probe principal, and **real calls** for what neither decides (§10). | The issue names these oracles; Troubleshooter can decide for arbitrary principals. |
| D7 | Gate identical to AWS: **Wilson 95 % lower bound ≥ 99.5 %, n ≥ 10,000**, per stratum ≥ 99 %, zero confident-wrong verdicts, 14 green nights. | One bar for "exact". |
| D8 | **VPC Service Controls: out of scope for the verdict, flagged.** **Organization Policy: out of scope for the verdict**, with two narrow exceptions modelled (§3.4). | Both are separate control layers, not IAM: VPC-SC is "an extra layer … independent of IAM" based on request context [GC9]; Org Policy "focuses on *what*" (configuration), IAM on *who* [GC8]. |
| D9 | The collector **extends `internal/connectors/gcpiam` and `internal/connectors/google`** (read-only, safehttp, no Google SDK) and moves to **federated credentials** (workload identity federation, no stored key), mirroring EP-2 (§9). | Reuse; prod must not hold a service-account key. |

**Scope in one line:** resource hierarchy (organization, nested folders, project, resource) with inherited allow policies; basic, predefined and custom roles expanded to permissions; IAM Conditions (the CEL subset of §5) on allow bindings; deny policies with exception principals, exception permissions and tag-based denial conditions; PAB policies with enforcement versions and principal-based binding conditions; every principal form (users, service accounts, groups with nested membership, domains, `allUsers`, `allAuthenticatedUsers`, workforce and workload identity pools, service-account principal sets, service agents); service-account impersonation as exact per-hop decisions — **exact**. VPC-SC perimeters, Org Policy constraints in general, Cloud Storage ACLs, and service-internal models — **flagged** (§3).

---

## 1. Problem and users

As AWS design §1, for Google Cloud. Today `gcpiam` emits one permission per (resource, role) and leaves inheritance, role expansion, conditions, deny and PAB to the reader. It cannot say "this binding is blocked by an org-level deny policy" or "this service account's PAB makes the project ineligible".

## 2. Goals and non-goals

**Goals.** (G1) Exact decisions for §3.1, ≥ 99.5 % agreement with real GCP on a sandbox organization. (G2) A trace naming the decisive binding (resource, role, member, condition), deny rule or PAB policy. (G3) Effective permissions, who-can and diff at the AWS SLOs. (G4) A policy PR (allow binding, custom role, deny policy, PAB policy or binding) shows who gains or loses which permission where; additionally, the PR linter flags bindings an Org Policy member-restriction constraint would reject (§3.4).

**Non-goals (Phase 1).** Authorization inside services (BigQuery row and column security, GKE Kubernetes RBAC, Cloud SQL users); network reachability; any write to the customer organization.

---

## 3. Scope cut

Fidelity propagation as AWS §7.9 (outcome-sensitive reasons only).

### 3.1 Exact

| Area | Covered |
|---|---|
| Hierarchy | Organization → folders (nested) → project → resource, and parent resources inside services where the resource name nests (for example a bucket and its objects). An allow policy "is inherited by that resource's descendants" [GC1]. |
| Allow policies | Bindings `{role, members, condition}` on any resource that has a policy (organization, folder, project, and service resources such as buckets, topics, secrets, keys, service accounts). Union across the resource and its ancestors [GC1]. Policy versions 1 and 3. |
| Roles | Basic (`roles/owner`, `roles/editor`, `roles/viewer`), predefined, custom (organization- and project-level). Expanded to `includedPermissions` at the pinned catalog version. Custom role `stage` and `deleted` states (§4.3). |
| IAM Conditions | The CEL subset of §5 on allow bindings [GC4]. |
| Deny policies | Rules `{deniedPrincipals, exceptionPrincipals, deniedPermissions, exceptionPermissions, denialCondition}`, attached at organization, folder or project, inherited downward; v2 permission names with the three wildcard group forms; denial conditions with tag functions [GC2]. |
| PAB policies | Rules of eligible Resource Manager resources (effect `ALLOW` only), bindings to principal sets with `principal.type`/`principal.subject` conditions, enforcement versions, fail-closed on errors [GC3]. |
| Principals | Every allow-, deny- and PAB-policy identifier form on [GC5] (§4.6), nested group membership, domain membership by customer ID [GC6]. |
| Impersonation | Each hop of a service-account chain is an exact permission decision on the service-account resource (`iam.serviceAccounts.getAccessToken` and the related permissions) [GC7]. Chains are composed in the query layer (§7.2). |
| Org Policy, narrow | (a) the member-restriction constraints at policy-write time (linter only); (b) a curated overlay of boolean constraints that block named permissions (§3.4). |

### 3.2 Approximated (`APPROXIMATE`)

| Area | Approximation | Reason code |
|---|---|---|
| VPC Service Controls | When the snapshot shows the project inside a perimeter that restricts the requested service and the request does not state its network origin and access level, an IAM `ALLOW` is returned `APPROXIMATE` (the perimeter can still block). A `DENY` is unaffected. | `VPCSC_PERIMETER` |
| Org Policy overlay | A boolean constraint from the overlay (§3.4b) that is enforced on an ancestor blocks the listed permissions as a guardrail; the mapping is hand-curated until probed. | `ORG_POLICY_CONSTRAINT` |
| Condition attribute support | An attribute (for example `resource.name`) that the requested permission's service may not supply: treated as the documented default for that service, approximate until probed. | `ATTRIBUTE_SUPPORT_UNVERIFIED` |
| PAB `latest` enforcement version | We resolve `latest` to the version in the pinned catalog; Google changes the default with up to 4 weeks' notice [GC3]. | `PAB_VERSION_LATEST` |
| Ambiguity defaults | Any decision that depends on an unsettled §4.10 entry. | `AMBIGUITY:GC-A<n>` |
| Snapshot freshness | IAM changes are eventually consistent [GC2]. | `SNAPSHOT_STALENESS` |

### 3.3 Unsupported (`UNSUPPORTED`)

| Area | Reason code |
|---|---|
| Cloud Storage fine-grained ACLs (bucket without uniform bucket-level access); BigQuery dataset ACL semantics beyond IAM; GKE Kubernetes RBAC; Cloud SQL and other in-database users | `NON_IAM_AUTHZ_LAYER` |
| Eventarc access policies (Google evaluates them in the deny and allow stages and ignores them on evaluation failure [GC1]) | `EVENTARC_ACCESS_POLICY` |
| Custom Org Policy constraints whose resource types match the request's method | `ORG_POLICY_CUSTOM` |
| A condition using an attribute or function outside §5, or IAP context (`request.auth.access_levels`, `destination.*`) when the request does not supply it in concrete mode | `CONDITION_UNSUPPORTED` |
| Permission missing from the pinned catalog | `CATALOG_MISS` |
| A stored policy, role or binding that fails to parse | `POLICY_UNPARSEABLE` (fail-closed, AWS §3.3) |
| A resource whose allow policy the reader could not read, on the request's ancestor chain | `POLICY_UNREAD` |
| Group membership not readable (customer withheld Cloud Identity read, Q5) and a group binding could decide | `GROUPS_UNREAD` |

### 3.4 Decision on VPC-SC and Org Policy (requested by the issue)

**VPC Service Controls — not modelled in the verdict; flagged.** VPC-SC is a context-based perimeter "independent of IAM", decided on network origin, access levels and ingress/egress rules [GC9]. Those inputs are properties of the request's network path, which an IAM question ("can P use permission X on R") does not have, and Google's own Troubleshooter "does not diagnose VPC Service Controls issues" [GC10]. Modelling perimeters exactly would need Access Context Manager policies plus the caller's network context: a separate design. Phase 1 reads perimeter membership (Access Context Manager read) only to raise `VPCSC_PERIMETER` on outcome-sensitive allows (§3.2). Least privilege and auto-revoke never act on those.

**Organization Policy — not modelled in general; two narrow parts modelled.** Org Policy restricts resource *configuration* ("what"), not identity ("who") [GC8]; most constraints (allowed locations, VM external IPs, uniform bucket access) decide whether a specific create or update payload is acceptable, which is not a property of (principal, permission, resource). They are out of the verdict. We model:

- **(a) Member restriction at policy-write time.** `iam.allowedPolicyMemberDomains` and `iam.managed.allowedPolicyMembers` decide which members an allow policy may contain (new organizations block `allUsers`/`allAuthenticatedUsers` by default through the latter [GC6]). The simulate/PR path (§7.3) evaluates them with Org Policy's hierarchy rules (inherit, merge for legacy list constraints, override for managed constraints [GC8]) and reports "this binding would be rejected". They never change an evaluation verdict, because they do not apply retroactively [GC8].
- **(b) A curated overlay of boolean constraints that block specific permissions outright** (for example disabling service-account key creation blocks `iam.serviceAccountKeys.create`). `catalog/gcp/orgpolicy_overlay.yaml` maps constraint → permissions, each entry with a source URL and a probe; enforced constraints on the ancestor chain act as a guardrail (`DenyKind = Guardrail`, `ORG_POLICY_CONSTRAINT`, APPROXIMATE until its probe passes). Dry-run policies never block [GC8].

The "org-policy hierarchy" in the issue's scope is therefore covered in two senses: the **resource hierarchy** (organization/folder/project inheritance of allow, deny and PAB) is exact; the **Org Policy hierarchy** evaluation is implemented for the constraints in (a) and (b) only.

---

## 4. Verified GCP IAM semantics

### 4.1 Order and combination [GC1]

IAM "evaluates all policy types simultaneously, then compiles the results", conceptually:

1. **PAB:** if the principal is subject to PAB policies and is not eligible for the resource, access is blocked; if eligible, or not subject to any PAB, continue.
2. **Deny:** if any relevant deny policy denies the permission, access is blocked.
3. **Allow:** access is granted only if a relevant allow policy grants a role containing the permission. Relevant allow policies are those on the resource and those inherited.

The engine computes all three for the trace and combines them in this order: `PAB blocks → DENY Guardrail`; `deny applies → DENY Explicit`; `no allow → DENY Implicit`; else `ALLOW`. Three-valued parts combine with `authz.Tri`/`Residual`.

### 4.2 Hierarchy

- Allow policies attach to one resource and are inherited by all descendants [GC1]. The effective allow set for `(P, perm, R)` is the union of bindings on R and every ancestor.
- Deny policies attach only at organization, folder or project (attachment points `cloudresourcemanager.googleapis.com/{organizations|folders|projects}/ID`) and flow down to all descendants; a higher-level deny applies even if lower levels are more permissive [GC2].
- PAB rules name organizations, folders or projects as eligible resources; a rule's resource covers its descendants (GC-A1, default yes, probe).
- The collector records each resource's full ancestor path; a moved project changes its ancestry in the next snapshot.

### 4.3 Roles and permissions

- Permission names in allow-policy roles: `service.resource.verb` (v1). Deny policies use v2 names `SERVICE_FQDN/RESOURCE.ACTION`, for example `iam.googleapis.com/roles.create` [GC2]. The catalog keeps a bijection; a deny rule naming a permission that has no v1 equivalent is kept verbatim and can only match itself.
- Role expansion: a binding grants exactly the role's `includedPermissions` at evaluation time. Basic roles are expanded like any role. Custom roles: a `DISABLED` stage or a deleted role grants nothing (GC-A2, default: a deleted role's binding grants nothing, a `DISABLED` one grants nothing; probe both).
- Permission matching in allow policies is exact string equality (roles hold no wildcards). Requests name one permission (Google checks permissions, not API methods); method → permission mapping is out of scope for the evaluator and in scope for the harness (§10.4).

### 4.4 Deny policies [GC2]

- A rule denies `perm` to `P` on `R` iff: the rule is in a deny policy attached at R's project, a folder above it or the organization; `perm` matches `deniedPermissions` and not `exceptionPermissions`; P matches `deniedPrincipals` (directly or by set membership, including group membership) and does not match `exceptionPrincipals` ("exempt … even if they're denied or belong to a denied group"); and `denialCondition` is true **or cannot be evaluated**.
- Wildcards are only the three permission-group forms `SERVICE_FQDN/RESOURCE.*`, `SERVICE_FQDN/*.*`, `SERVICE_FQDN/*.VERB`; they include future permissions [GC2]. Matcher: split `RESOURCE.ACTION` and compare components; no free-form glob.
- **Deniable permissions.** Only supported permissions can be denied [GC2]; the Troubleshooter reports a `permissionDeniable` flag [GC10]. A deny rule naming a non-deniable permission has no effect; the catalog table `deny_supported.yaml` (from Google's list) decides, and a permission not on it in a rule that would otherwise match is `AMBIGUITY:GC-A3` (default: not denied, the permissive reading).
- Denial conditions recognise only resource tag functions such as `resource.matchTag(...)` [GC2][GC4]. In symbolic mode an unknown tag value yields a residual; an expression the engine cannot evaluate makes the rule **apply** (documented fail-closed), recorded in the trace.
- Exception principals in deny policies can be principal sets (groups, domains, pools); exception by group membership is transitive (GC-A4, default transitive, probe).
- Limits: up to 500 deny policies and 500 rules per resource [GC2] (validated at ingest, not semantics).

### 4.5 Principal access boundary policies [GC3]

- A PAB policy restricts, never grants. It takes effect only when bound to a principal set by a policy binding. Up to 10 policies per principal set, 500 rules and 500 resources per policy.
- **Relevance:** a PAB policy is relevant to P when a binding attaches it to a principal set containing P and the binding's condition is not false. Binding conditions use only `principal.type` and `principal.subject` with `&&`, `||`, `!`, ≤ 10 operators; **true or not evaluable ⇒ enforced**.
- **Decision:** not blocked if P has no relevant PAB policy, or the permission is not in the policy's **enforcement version**, or some relevant policy lists an eligible resource covering R; blocked if P has ≥ 1 relevant policy and none makes R eligible. Errors are fail-closed.
- Enforcement version: per policy; each version's blockable set includes earlier ones. `catalog/gcp/pab_versions.yaml` holds the blockable permissions per version; `latest` → §3.2.
- Supported principal sets: workforce pool, workload pool, Workspace domain, project/folder/organization principal sets (service accounts, workload pools and agent identities in that container), agent identities in a trust domain [GC3][GC5]. Folder and organization sets include descendants' principals.
- Cross-organization bindings are periodically deleted [GC3]; the collector ignores any it sees and records an anomaly.
- Cached public resources (for example public Cloud Storage objects): PAB cannot stop viewing but still blocks modification and deletion [GC3]; the engine treats reads of resources with an `allUsers` grant as not PAB-blockable for the read permissions in the catalog's "cached" list (GC-A5, probe).

### 4.6 Principals and principal sets [GC5][GC6]

Canonical principal model `Principal{Kind, ID}` with kinds: user (Google Account), service account, service agent, group, domain (Cloud Identity customer ID), `allUsers`, `allAuthenticatedUsers`, workforce identity (pool + subject, with group and attribute values from the snapshot), workload identity (project number + pool + subject, likewise), agent identity, and GKE pod sets. Allow (v1), deny (v2) and PAB (v3) identifier syntaxes all parse into this model.

- `allAuthenticatedUsers`: all service accounts and all Google Account users, **excluding** federated workforce and workload identities and anonymous callers; not supported in deny or PAB [GC6].
- `allUsers`: anyone including anonymous; in deny it is `principalSet://goog/public:all`; not supported in PAB [GC6].
- `domain:`: matched by customer ID, not domain name; secondary domains are rewritten to the primary [GC6].
- Conditions cannot be attached to bindings of basic roles or of `allUsers`/`allAuthenticatedUsers` [GC4]; the parser flags such a stored binding as an anomaly and evaluates it unconditionally (what Google would have to do if it existed), `AMBIGUITY:GC-A6`.
- **Groups:** a member inherits the roles of the group [GC6]. Nested groups are honoured transitively (Cloud Identity transitive memberships); GC-A7 (default transitive, permissive) until probed. Group membership is read from Cloud Identity at snapshot time; the Troubleshooter also checks membership "at the time of the query" [GC10].
- `deleted:` principals grant nothing.
- **Workload/workforce attribute sets** (`principalSet://…/attribute.X/V`): the snapshot cannot know which external subjects exist, so who-can returns the set itself as a principal; `can` for a concrete federated identity takes its attributes from the request (absent ⇒ `UNKNOWN` ⇒ `CONDITIONAL` in symbolic mode).

### 4.7 Service-account impersonation [GC7]

Impersonating a service account needs `iam.serviceAccounts.getAccessToken` on it; the Service Account Token Creator role holds it [GC7]. The evaluator answers each hop exactly as a normal permission check on the service-account resource (which inherits project, folder and organization policies). The query layer (§7.2) builds `can_impersonate` edges for `getAccessToken`, `signBlob`, `signJwt`, `getOpenIdToken`, `implicitDelegation` and `actAs`, and composes chains; each edge carries its own explanation. The exact permission list per edge kind is confirmed in GC-1 against Google's "roles for service account authentication" page (Q6).

### 4.8 Privileged Access Manager

PAM grants are temporary **conditional bindings** with `request.time` conditions [GC4], so active grants are exact under §5. Entitlements a principal may request but has not been granted are "potential access", reported like Azure PIM eligibility (residual atom `pam.request(<entitlement>)`) when `?include=eligible` is set.

### 4.9 What the existing code and knowledge base get wrong

`gcpiam` does not expand inheritance or roles, ignores deny and PAB, and labels conditional bindings without evaluating them. GC-6 replaces its role-on-resource permissions with evaluator-confirmed edges, as AWS PR-11 did.

### 4.10 Ambiguity register

Living doc `docs/knowledge/gcp-evaluation-ambiguities.md` (GC-4).

| Id | Question | Default | Probe |
|---|---|---|---|
| GC-A1 | A PAB rule's resource covers its descendants | Yes | PAB naming a folder; access a project under it |
| GC-A2 | Bindings of `DISABLED` and deleted custom roles | Grant nothing | Disable a custom role, then undelete within the window |
| GC-A3 | Deny rule names a permission not on the deniable list | Not denied | Troubleshooter `permissionDeniable` plus a real call |
| GC-A4 | Exception by nested-group membership | Transitive | Exception group containing a group containing the probe SA |
| GC-A5 | Which read permissions on public cached resources PAB cannot block | Catalog list | Public object read by a PAB-bound SA |
| GC-A6 | Stored conditional binding on a basic role or `allUsers` | Unconditional | Not creatable; recorded if ever seen |
| GC-A7 | Nested group membership in allow policies | Transitive | Role on a parent group, member of a nested group |
| GC-A8 | `resource.name`/`resource.type` absent for a service or a list permission | Comparison false, so the conditional binding does not grant; `!` of it true (permissive) | Conditional binding with `resource.name.startsWith` on list vs get |
| GC-A9 | `testIamPermissions` reflects deny and PAB | Yes | Probe SA with a deny rule; compare with Troubleshooter |
| GC-A10 | Case of e-mail addresses in member identifiers | Case-insensitive | Binding with mixed-case `user:` e-mail |

---

## 5. The IAM Conditions subset (CEL)

Parser `internal/gcp/cel` (GC-1): a hand-written parser for the documented subset, not a general CEL runtime [GC4].

- **Syntax:** literals (string, int, bool, timestamp via `timestamp("…")`, duration), `&&`, `||`, `!`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `in` on literal lists, parentheses, member access, and these functions: `startsWith`, `endsWith`, `extract`, `matchTag`, `matchTagId`, `hasTagKey`, `hasTagKeyId`, `getAttribute` (on `api`), `getHours`, `getMinutes`, `getSeconds`, `getDayOfWeek`, `getDayOfMonth`, `getDayOfYear`, `getMonth`, `getFullYear`, `getDate` (with optional IANA time zone). The exact function list is pinned from [GC4]'s attribute reference in GC-1; anything else is `CONDITION_UNSUPPORTED`.
- **Attributes by policy type** [GC4]: allow — `resource.type`, `resource.name`, `resource.service`, resource tags, `request.time`, `api.getAttribute(…)` (for example `iam.googleapis.com/modifiedGrantsByRole` in delegated `setIamPolicy`), `request.auth.access_levels` and `destination.ip|port` (IAP only); deny — resource tag functions only; PAB bindings — `principal.type`, `principal.subject`.
- **Semantics:** CEL's commutative `&&`/`||` with error absorption (an error operand does not decide if the other operand decides); a top-level error or unknown: **allow binding does not grant**, **deny rule applies**, **PAB binding is enforced** [GC2][GC3]. In symbolic mode unknown attributes become residual atoms.
- **Limits:** expression size and operator count bounded at Google's documented limits (pinned in GC-1) plus our own caps (8 KiB, depth 32); violations are `POLICY_UNPARSEABLE`.
- `resource.name` format differs per service (for example buckets vs objects); `catalog/gcp/resource_names.yaml` holds the format per resource type, each with a source URL.

---

## 6. Data model

### 6.1 Engine types (`internal/gcp/model`, GC-1)

- `Snapshot{ID, OrgID, AsOf, Nodes ResourceTree, AllowPolicies map[ResourceName]*AllowPolicy, DenyPolicies map[AttachPoint][]*DenyPolicy, PABPolicies map[string]*PABPolicy, PABBindings []*PABBinding, Roles map[string]*Role, Groups Closure, Principals, Perimeters, OrgPolicies, CatalogVersion, Anomalies}`, immutable after `Build()`.
- `AllowPolicy{Resource, Version, Etag, Bindings []Binding{Role, Members []PrincipalRef, Condition *cel.Expr}}`.
- `DenyPolicy{Name, AttachPoint, Rules []DenyRule{Denied, Except []PrincipalRef, Perms, ExceptPerms []PermPattern, Condition *cel.Expr}}`.
- `PABPolicy{Name, EnforcementVersion, Rules []{Resources []ResourceName, Effect}}`, `PABBinding{Policy, Target PrincipalSet, Condition *cel.Expr}`.
- `Role{Name, Stage, Deleted, Permissions sorted []string}`.
- Request: `eval.Request{Principal, Permission, Resource, Attributes, Mode, IncludeEligible, At}`, `Platform() == "gcp"`.

### 6.2 Persistence (GC-2)

`internal/store/schema/0NNN_gcp_snapshots.sql` + `schema/postgres/` variant + regenerated `rls.sql`: `gcp_connectors`, `gcp_snapshots`, `gcp_snapshot_blobs` (raw policy JSON verbatim), `gcp_ingest_anomalies`, `gcp_explanations`. `tenant_id`, triggers, isolation tests, SQL only in `internal/store` (`repo_gcp.go`).

### 6.3 Catalogs (`catalog/gcp/`)

- **Roles and permissions:** predefined roles with `includedPermissions` (IAM `roles.list` view FULL), custom roles from the organization and projects, and the permission universe from `queryTestablePermissions` (which also gives custom-role support levels). `tessera catalog refresh|compile --cloud gcp`; deterministic artifact as AWS PR-2.
- **v1 ↔ v2 permission names**, `deny_supported.yaml`, `pab_versions.yaml`, `orgpolicy_overlay.yaml`, `resource_names.yaml`, each with source URLs and a refresh job that opens a PR on change.

---

## 7. The evaluation algorithm

### 7.1 Pipeline

```
Eval(snap, req):
  chain := snap.Nodes.AncestorsOrSelf(req.Resource)            # resource → project → folders → org
  S     := Expand(req.Principal)                               # groups (transitive), domain, allAuthenticatedUsers if eligible,
                                                               # allUsers, pool sets, SA principal sets, service-agent sets
  if req.Permission ∉ catalog: UNSUPPORTED CATALOG_MISS
  # Stage 1: PAB (StageGCPPAB)
  rel := {pol | b in bindings, b.Target ∋ req.Principal, cond(b) != False, pol = b.Policy,
           req.Permission ∈ blockable(pol.EnforcementVersion)}
  pab := True if rel = ∅ else AnyOf(eligible(pol, req.Resource) for pol in rel)   # cond unknown ⇒ enforced
  # Stage 2: deny (StageGCPDeny)
  deny := AnyOf(applies(rule) for rule in deny policies at org/folder/project in chain)
          where applies = permMatch ∧ ¬exceptPerm ∧ princMatch(S) ∧ ¬exceptPrinc(S) ∧ condOrTrueOnError(rule)
  # Stage 3: allow (StageGCPAllow)
  allow := AnyOf(cond(b) for node in chain, b in allow[node].Bindings
                 if b.Role grants req.Permission and b.Members ∩ S ≠ ∅)
  if req.IncludeEligible: allow := Or(allow, PAM entitlements …)
  # Guardrails (StageGCPGuardrail): Org Policy overlay; VPC-SC flag
  result := And(pab, Not(deny), allow, Not(overlayBlocks))
  outcome/deny kind from the first stage that is definitely False: PAB → Guardrail, deny → Explicit,
  allow → Implicit, overlay → Guardrail; else ALLOW or CONDITIONAL(result)
```

All stages run for the trace. Fidelity accumulates per AWS §7.9.

### 7.2 Effective permissions, who-can and impersonation edges

Atoms over the permission universe (permissions partitioned by the set of roles and deny patterns that mention them); inverted indexes from resource to inherited bindings and from principal to expanded sets. `WhoCan(perm, R)` returns principal sets as well as individuals (a domain or a pool attribute set is an answer, not something to enumerate). Impersonation edges (§4.7) feed the graph's NHI view, as AWS trust edges do.

### 7.3 Simulation

`snapshot.Apply` supports allow-binding add/remove/condition change, custom role change, deny policy and rule change, PAB policy, rule and binding change, and group membership change. `query.Diff` gives gained/lost (principal, permission, resource) triples; the PR comment also lists Org Policy member-restriction rejections (§3.4a).

### 7.4 The explanation

New `authz.Stage` constants `gcp_pab`, `gcp_deny`, `gcp_allow`, `gcp_guardrail`. `StmtRef`: `PolicyID` = policy name or resource name for allow, `PolicyKind` = `allow_binding|deny_rule|pab_policy|pab_binding|org_policy`, `SourceARN` = full resource name (`//cloudresourcemanager.googleapis.com/projects/…`), `StatementIndex` = binding or rule index, `AttachmentPath` = `[member or set matched, role, resource]`, `OrgLevel` = node kind. Condition atoms are recorded in `CondTrace`. Same `explanation_id` scheme and version fields as AWS.

---

## 8. Matching and case rules

| Item | Rule |
|---|---|
| v1 permissions, role names | Exact, case-sensitive |
| v2 deny permission patterns | Three group forms only, component-wise |
| Member identifiers | Prefix (`user:`, `group:` …) case-sensitive; e-mail addresses compared case-insensitively (GC-A10 pending, default insensitive, permissive) |
| Resource names | Exact, case-sensitive full resource names; project ID vs number normalized to number at ingest |
| CEL strings | Case-sensitive unless the function says otherwise |

---

## 9. Integration: collector, credentials, API, UI

### 9.1 Collector (GC-2)

Extends `internal/connectors/gcpiam` and `internal/connectors/google`, plain HTTP through `safehttp`, read-only (GET plus the read-only `getIamPolicy`/`searchAllIamPolicies` POSTs), paginated, bounded.

| Data | API |
|---|---|
| Hierarchy and org/folder/project allow policies | Cloud Resource Manager v3 (`folders`, `projects` search, `getIamPolicy` with `requestedPolicyVersion=3`) |
| Resource-level allow policies | Cloud Asset Inventory `searchAllIamPolicies` (or `exportAssets` with `IAM_POLICY`), organization scope |
| Deny policies | IAM v2 `policies.listPolicies` per attachment point (URL-encoded) [GC2] |
| PAB policies and bindings | IAM v3 principal access boundary policies and policy bindings on organization, folders and projects [GC3] |
| Roles and permissions | IAM v1 `roles.list` (predefined, view FULL), `organizations.roles.list`, `projects.roles.list`, `permissions.queryTestablePermissions` |
| Groups | Cloud Identity groups and transitive memberships |
| Service accounts, workload/workforce pools | IAM v1 lists |
| Perimeters (flag only) | Access Context Manager service perimeters (read) |
| Org Policy (overlay and member constraints only) | Org Policy v2 effective policies for the overlay constraints |

Fail-closed: an unreadable policy on any ancestor chain is an anomaly and every decision it could affect is `UNSUPPORTED` (`POLICY_UNREAD` or `POLICY_UNPARSEABLE`).

### 9.2 Reader permissions

Organization-level roles: Security Reviewer (`roles/iam.securityReviewer`), Deny Reviewer (`roles/iam.denyReviewer`), Principal Access Boundary Policy Viewer (`roles/iam.principalAccessBoundaryViewer`), Browser, Cloud Asset Viewer, Organization Policy Viewer, Access Context Manager Reader, plus Cloud Identity group read (Admin API `groups.read` privilege) — the same set the Troubleshooter itself requires [GC10], minus admin roles. `gcpiam.ReaderPermissions()` lists them and a test checks every permission is a read verb against the catalog.

### 9.3 Credentials

Workload identity federation: a workload identity pool provider in the customer's organization trusts a Tessera-issued JWT (`internal/keys`); STS token exchange, then service-account impersonation of the reader SA, all through `safehttp`. No service-account key stored. Key-file mode stays only behind a flag that prod refuses, mirroring EP-2. Reviewed by `iam-pam-nhi-expert` and `iam-protocols-expert`.

### 9.4 API and UI (GC-6)

`GET /api/gcp/can`, `/principals/{id}/effective`, `/who-can?resource=&permission=`, `/explanations/{id}`, `POST /api/gcp/simulate-change`, connector and snapshot routes. Read-only except connector settings, tenant-scoped, RBAC-declared, audited (fail closed). UI via `src/api.ts`, lazy-loaded, reusing EP-7 badges and trace viewer.

---

## 10. The differential test harness

### 10.1 Oracles and routing

| Tier | Oracle | Decides | Limits |
|---|---|---|---|
| O1 | **Policy Troubleshooter** `iam:troubleshoot`: v3 (allow + deny), v3beta (allow + deny + PAB) [GC10] | Any user or service account (and SA principal sets, agent identities) × permission × resource; per-policy explanations; `permissionDeniable` | Pre-GA. Groups, domains and federated identities are not supported as principals; Cloud Storage ACLs ignored; VPC-SC not diagnosed; Pub/Sub resource allow policies not evaluated; non-tag conditions need context supplied; tags not fetched for regional resources; unreadable policy ⇒ `Unknown` [GC10]. |
| O2 | **`testIamPermissions`** as a probe principal | The probe's own permissions on a resource (CRM v3 projects and service resources) | Caller only; no wildcards [GC11]; deny/PAB reflection is GC-A9. |
| O3 | **Real calls** by probe service accounts (impersonated in the sandbox) | Anything O1/O2 cannot: federated identities, Pub/Sub resource policies, conditions with `request.time`/IAP context, Org Policy overlay, VPC-SC (as a separate stratum, outside the gate) | Harmless reads; writes only on canaries. |

Routing (as AWS §13.3): O1 for every check it supports; O2 to cross-check O1 nightly on a 5 % sample; O3 for the rest. A check where O1 returns `Unknown` because of a supplied-context condition is re-run with context; still unknown ⇒ routed to O3.

### 10.2 Strata

Hierarchy depth (org, folder×k, project, resource); role kinds (basic, predefined, custom, disabled/deleted custom); conditions (resource name, type, tags, time, `api.getAttribute`); deny (org/folder/project, wildcard groups, exception principal, exception permission, tag condition); PAB (no policy, eligible, not eligible, binding condition on type/subject, enforcement version boundary); principals (user, SA, nested group, domain, allUsers, allAuthenticatedUsers, workload and workforce pool sets, SA principal set, service agent); impersonation hops; overlay constraints; VPC-SC (reported, not gated).

### 10.3 Sandbox organization (GC-5; described here, applied only after human sign-off)

`infra/sandbox/gcp/` (Terraform): a dedicated sandbox organization (Q1) with 3 folder levels, 4 projects, canary buckets (uniform access), topics, secrets, service accounts; custom roles; deny policies at each level; PAB policies bound to project and folder principal sets; Cloud Identity groups nested to 3 levels; a workload identity pool for federated probes; a perimeter in dry-run and enforced mode for the VPC-SC stratum; overlay constraints enforced on one folder.

### 10.4 Comparing

Permission ↔ method mapping for O3 calls lives in `internal/gcp/harness/methods.yaml` (which API call exercises which permission), validated by the harness against Troubleshooter results for the same check. Eventual consistency: poll O1 until the scenario's expected policy etag is visible before counting. Cassettes at the safehttp layer (`internal/gcp/gcpreplay`).

### 10.5 Gate

Identical to AWS §13.7 and the plan: 100 % golden and replay on every PR; nightly Wilson 95 % lower bound ≥ 99.5 % at n ≥ 10,000, coverage ≥ 97 %, every stratum ≥ 99 % (VPC-SC stratum excluded and reported), zero confident-wrong verdicts, 14 green nights; weekly re-run of every GC-A probe.

---

## 11. Offline golden corpus

`testdata/gcp/golden/*.yaml`, `TestGolden` in `internal/gcp/eval`, AWS §14.1 format. Case ids **GCG-nn** (not GC-nn, which is the AWS corpus's prefix and also this plan's PR prefix).

| Id | Case | Expected |
|---|---|---|
| GCG-01 | `roles/viewer` on org, `storage.buckets.get` on a bucket in a nested folder | ALLOW (inheritance) |
| GCG-02 | Predefined role on project, permission not in role | DENY implicit |
| GCG-03 | Custom role on folder, granted permission | ALLOW |
| GCG-04 | Disabled custom role | DENY implicit (`AMBIGUITY:GC-A2` until probed) |
| GCG-05 | Bucket-level binding only, access another bucket | DENY implicit |
| GCG-06 | Group binding, member via nested group | ALLOW (GC-A7) |
| GCG-07 | `domain:` binding, user in secondary domain | ALLOW |
| GCG-08 | `allAuthenticatedUsers`, workload identity | DENY implicit |
| GCG-09 | `allUsers`, anonymous read of public object | ALLOW |
| GCG-10 | Condition `resource.name.startsWith(…)` match / no match | ALLOW / DENY |
| GCG-11 | Condition on `request.time`, symbolic mode | CONDITIONAL |
| GCG-12 | Condition on resource tag | ALLOW / DENY by tag |
| GCG-13 | Conditional and unconditional binding of the same role | ALLOW (conditional does not override) |
| GCG-14 | Deny at org, Owner on project | DENY explicit |
| GCG-15 | Deny with `exceptionPrincipals` containing the SA | ALLOW |
| GCG-16 | Deny with `exceptionPermissions` carve-out from `RESOURCE.*` | ALLOW for the carved permission |
| GCG-17 | Deny `SERVICE/*.delete` vs `get` | DENY delete, ALLOW get |
| GCG-18 | Deny with tag condition true / false / not evaluable | DENY / ALLOW / DENY |
| GCG-19 | Deny on a non-deniable permission | ALLOW (`AMBIGUITY:GC-A3`) |
| GCG-20 | Deny to `principalSet://goog/public:all` | DENY for every principal |
| GCG-21 | Deny to group, user via nested group, excepted by another group | ALLOW (GC-A4) |
| GCG-22 | PAB: SA in project set, resource eligible | ALLOW |
| GCG-23 | PAB: resource not eligible | DENY guardrail |
| GCG-24 | PAB: permission outside enforcement version | ALLOW |
| GCG-25 | PAB binding condition `principal.type` excludes SA | ALLOW |
| GCG-26 | PAB binding condition not evaluable | DENY guardrail (fail-closed) |
| GCG-27 | PAB on folder set, SA in descendant project | DENY guardrail |
| GCG-28 | Impersonation: Token Creator on SA → `getAccessToken` | ALLOW; chain edge emitted |
| GCG-29 | Impersonation hop blocked by org deny on `iam.googleapis.com/serviceAccounts.getAccessToken` | DENY explicit |
| GCG-30 | PAM active grant inside / after window | ALLOW / DENY |
| GCG-31 | Overlay: SA key creation disabled on folder | DENY guardrail, `ORG_POLICY_CONSTRAINT` |
| GCG-32 | Project in enforced VPC-SC perimeter, IAM allows | ALLOW, APPROXIMATE `VPCSC_PERIMETER` |
| GCG-33 | Bucket with fine-grained ACLs, object read | UNSUPPORTED `NON_IAM_AUTHZ_LAYER` |
| GCG-34 | Unreadable allow policy on an ancestor | UNSUPPORTED `POLICY_UNREAD` |
| GCG-35 | Unparseable CEL on relevant binding | UNSUPPORTED `POLICY_UNPARSEABLE` |
| GCG-36 | Simulate adding `allUsers` where `iam.managed.allowedPolicyMembers` forbids | Diff + "binding would be rejected" |

---

## 12. Implementation plan (GC-1…GC-6)

Each PR keeps the race suite, both SQL dialects, archtest purity and parity fixtures green. Paths under `mvp/server/`.

| PR | Scope | Files | Tests | Deps |
|---|---|---|---|---|
| **GC-1** Types and parsers | `internal/gcp/model`; strict parsers for allow (v1/v3), deny (v2) and PAB (v3) policies and bindings; principal identifier parser for all three syntaxes into one model; CEL subset parser (§5); v1↔v2 permission mapping; additive `authz.Stage` constants | `internal/gcp/{model,policy,cel,principal}/` | Table tests per identifier form and CEL function; `FuzzParseCEL`, `FuzzParsePrincipal`, `FuzzParsePolicy`; round-trip; limits | GC-0 approved |
| **GC-2** Collector, catalog and persistence | §9.1 reads, federated credentials (§9.3), fail-closed anomalies, `ReaderPermissions()`, catalog refresh/compile (roles, permissions, deny-supported, PAB versions, overlay), `gcp_*` tables (SQLite + Postgres + RLS) | `internal/connectors/{gcpiam,google}`, `internal/gcp/catalog/`, `internal/store/{model_gcp,repo_gcp}.go`, schema files | Recorded-HTTP replay incl. pagination, 403 per resource, quota errors; isolation test; content-hash stability; prod refuses key mode; schema parity and Postgres translation tests | GC-1 |
| **GC-3** Evaluator | §7.1 pipeline, PAB, deny, allow, conditions (Tri/Residual), PAM, overlay and VPC-SC flags, fidelity, explanation | `internal/gcp/{eval,snapshot}/` | Purity archtest; determinism; no-mutation under `-race`; symbolic soundness (rapid) | GC-1 |
| **GC-4** Golden corpus and ambiguity register | GCG-01…GCG-36 and more until every §3.1 row is covered; `docs/knowledge/gcp-evaluation-ambiguities.md` | `testdata/gcp/golden/`, `internal/gcp/eval/golden_test.go`, docs | Golden 100 %; coverage matrix | GC-3 |
| **GC-5** Harness and sandbox | Oracle clients O1–O3, routing, `gcpreplay` cassettes, comparator, strata (EP-4), Wilson gate via `internal/harnesscore` (shared with AZ-5); `infra/sandbox/gcp/` and nightly workflow (**touches `.github/` and infra: `needs-human`**) | `internal/gcp/harness/`, `cmd/tessera-harness --cloud gcp`, `infra/sandbox/gcp/` | Replay of recorded Troubleshooter and `testIamPermissions` responses (each access state, `Unknown`, pagination); method-map validation; archtest | GC-2, GC-4, EP-4 |
| **GC-6** Indexes, queries and integration | Atoms, `EffectivePermissions`, `WhoCan`, `Diff`, impersonation edges; `/api/gcp/*`; evaluator-confirmed edges replace `gcpiam` role-on-resource permissions; PR comment incl. Org Policy member rejections; UI page | `internal/gcp/{index,query,render}/`, `internal/api/gcp*.go`, frontend, `mvp/README.md` | Atoms ≡ brute force; perf at 2× target (`-tags slow`); API tests; exit-criterion-2 test; parity fixtures unchanged or explained | GC-3, GC-2 |

Critical path: GC-1 → GC-3 → GC-4 → GC-5. If AZ-5 lands first, GC-5 reuses `internal/harnesscore`; otherwise GC-5 extracts it.

---

## 13. Risks

| Risk | Mitigation |
|---|---|
| Troubleshooter is Pre-GA and its PAB support is v3beta only [GC10] | Pin API versions in cassettes; O3 real calls remain the ground truth for disputed checks; Q2 |
| Troubleshooter cannot take groups, domains or federated identities as principals | Probe SAs that are members of the groups under test; O3 for federated identities |
| Permission catalog churn (new permissions, deniable list, PAB versions) | Nightly refresh PR; `CATALOG_MISS` instead of guessing; decisions pin the catalog version |
| `resource.name` formats differ by service | Per-type table with sources; unknown type ⇒ `ATTRIBUTE_SUPPORT_UNVERIFIED` |
| Large organizations (Asset Inventory volume) | CAI search with paging; incremental snapshots by asset change feed later |
| Eventual consistency | Poll for the expected etag before probing |

## 14. Security properties

As AWS and Azure: untrusted inputs parsed strictly with limits and fuzzing; no general CEL runtime (no reflection, no macros beyond the subset, bounded evaluation); pure evaluator packages; immutable snapshots; raw policies stored verbatim; all outbound calls via `safehttp`; read-only reader checked by test; tenant isolation; harness never linked into the server.

## 15. Open questions for the human

| # | Question | Proposed answer | Owner |
|---|---|---|---|
| Q1 | Who owns the GCP sandbox organization (a dedicated organization is needed for deny and PAB at org level), its budget and the probe-credential sign-off? | Dedicated organization; security engineering; same Phase 0 sign-off as #28 | Security lead, founder |
| Q2 | Is it acceptable that O1 (Troubleshooter) is Pre-GA, with PAB only on v3beta? | Yes for the harness (not the product); disputed checks settle with O3 | iam-authz-expert |
| Q3 | Confirm the VPC-SC decision: flag only (`VPCSC_PERIMETER`), no perimeter modelling in Phase 1 | Yes; separate design if customers ask | Founder |
| Q4 | Confirm the Org Policy decision: member-restriction constraints in the simulate path, curated boolean overlay as guardrail, everything else out | Yes | Founder |
| Q5 | Customer-side reader: may we ask for Cloud Identity groups read (Admin API privilege), which some customers resist? | Yes, with a degraded mode: without it, group-based decisions are `UNSUPPORTED` (`GROUPS_UNREAD`) | Product + security |
| Q6 | Model the full service-account "authentication roles" set (actAs, signBlob, implicitDelegation) as impersonation edges in GC-6, or only `getAccessToken` first? | All, confirmed against Google's roles page in GC-1 | iam-pam-nhi-expert |
| Q7 | One shared `/api/explanations/{id}` across clouds | Same as Azure Q8; decide before AZ-6/GC-6 | iam-architect |

---

## 16. Sources (Google Cloud docs, read 2026-11-07)

- **[GC1]** "IAM policy types" (simultaneous evaluation, PAB → deny → allow, allow inheritance, Eventarc access policies): https://cloud.google.com/iam/docs/policy-types
- **[GC2]** "Deny policies" overview (structure, v2 permission format, wildcard groups, attachment points, inheritance, denial conditions with tag functions, true-or-unevaluable applies, limits): https://cloud.google.com/iam/docs/deny-overview
- **[GC3]** "Principal access boundary policies" (restrict only, bindings, principal sets, enforcement versions, binding conditions, fail-closed, limits, cached public resources): https://cloud.google.com/iam/docs/principal-access-boundary-policies
- **[GC4]** "Overview of IAM Conditions" (CEL subset, attributes by policy type, unsupported basic roles and allUsers/allAuthenticatedUsers, conditional bindings do not override unconditional ones): https://cloud.google.com/iam/docs/conditions-overview
- **[GC5]** "Principal identifiers" (allow v1, deny v2 and PAB v3 identifier forms): https://cloud.google.com/iam/docs/principal-identifiers
- **[GC6]** "Principals" overview (allAuthenticatedUsers and allUsers definitions, groups, domains by customer ID, service agents, workforce and workload pools, default organization restriction): https://cloud.google.com/iam/docs/principals-overview
- **[GC7]** "Service account impersonation" (`iam.serviceAccounts.getAccessToken`, Service Account Token Creator): https://cloud.google.com/iam/docs/service-account-impersonation
- **[GC8]** "Introduction to the Organization Policy Service" (what vs who, inheritance, merge for legacy managed constraints, dry run, list and boolean constraints, not retroactive): https://cloud.google.com/resource-manager/docs/organization-policy/overview
- **[GC9]** "Overview of VPC Service Controls" (extra layer independent of IAM, context-based perimeter): https://cloud.google.com/vpc-service-controls/docs/overview
- **[GC10]** "Troubleshoot IAM permissions" (Policy Troubleshooter: what it evaluates, v3 and v3beta, required roles, limitations, access states, `permissionDeniable`): https://cloud.google.com/policy-intelligence/docs/troubleshoot-access
- **[GC11]** Resource Manager v3 `projects.testIamPermissions` (caller's permissions, wildcards not allowed): https://cloud.google.com/resource-manager/reference/rest/v3/projects/testIamPermissions

Pages fetched through their current `docs.cloud.google.com` redirects; the canonical `cloud.google.com` URLs are listed.
