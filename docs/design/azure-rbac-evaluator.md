# Design: Exact Azure RBAC evaluator, with explanations and a differential test harness

| | |
|---|---|
| **Status** | Draft, awaiting human approval. Implementation (AZ-1…AZ-6) starts only after a human approves this doc and its brief, and `iam-authz-expert` has reviewed §4–§8. |
| **Plan item** | AZ-0 (#667) in [`differentiators-plan.md`](differentiators-plan.md) §1. Depends on EP-4 (stratified generator). AZ-1…AZ-6 follow, with the same ≥ 99.5 % gate as AWS. |
| **Authors** | iam-architect, with iam-authz-expert (semantics) and iam-pam-nhi-expert (PIM, managed identities) |
| **Reviewers needed** | iam-authz-expert: §4–§8 and the golden corpus (§11). iam-pam-nhi-expert: §4.6 (PIM) and §9 (credentials). iam-governance-expert: the evidence fields in §7.4. |
| **Date** | 2026-11-07. Microsoft Learn pages re-read on 2026-11-07; every Azure claim cites a source in §16. |
| **Model** | [`aws-effective-permission-evaluator.md`](aws-effective-permission-evaluator.md) (the "AWS design"). This doc reuses its decision model, fidelity rules, harness metrics and gate, and states only what differs. |

---

## 0. Summary of key decisions

| # | Decision | Why |
|---|---|---|
| D1 | A **pure-Go evaluator** in `mvp/server/internal/azure/` over an immutable snapshot, with no I/O, sharing `internal/authz` (`Decision`, `Outcome`, `Fidelity`, `Residual`, `ExplanationStep`) with the AWS engine. | One decision and explanation contract across clouds; the UI, least privilege and evidence code stay cloud-neutral. |
| D2 | Decisions are `ALLOW`, `DENY` or `CONDITIONAL(residual)` plus fidelity `EXACT`, `APPROXIMATE` or `UNSUPPORTED` (AWS design D2). What the issue calls "unknown" is `CONDITIONAL` (a condition needs request context we do not have) or `UNSUPPORTED` (we cannot model the layer). | A wrong confident answer is worse than an honest "it depends". |
| D3 | Evaluation order is Microsoft's documented order (§4.1): **deny assignments first**, then role assignments (Actions − NotActions, DataActions − NotDataActions), then **conditions** on the matching assignment. Resource locks are a separate guardrail stage (§4.8). | [AZ1] steps 3–9. |
| D4 | Ambiguities default to the **more permissive** reading, flagged `AMBIGUITY:AZ-A<n>`, each with a probe in the sandbox (§4.10). | Same rule as AWS D3: missing a real grant is worse than flagging a possible one. |
| D5 | The action catalog comes from ARM's **provider operations** API (`isDataAction` per operation), snapshotted and pinned per decision (§6.3). | First-party, machine-readable, classifies control vs data actions. |
| D6 | **Oracle = real calls** by probe service principals in a sandbox tenant (§10). `Permissions - List For Resource` is a secondary cross-check only: it returns the caller's permission blocks, not a decision. | Azure has no public "simulate for any principal" API that we could confirm (Q2). |
| D7 | The gate is the AWS gate unchanged: **Wilson 95 % lower bound ≥ 99.5 %, n ≥ 10,000**, every stratum ≥ 99 %, zero confident-wrong verdicts, 14 green nights (§10.5). | One bar for "exact" across clouds. |
| D8 | Group membership comes from **Microsoft Graph transitive membership** (nested groups), captured in the snapshot (§4.5). PIM **eligible** assignments never count as access held now; they appear in "potential access" (§4.6). | [AZ1] "role assignments are transitive for groups"; eligibility is not access. |
| D9 | The collector **extends `internal/connectors/azurerbac` and `internal/connectors/entra`** (already read-only, safehttp) and adds **federated credentials** (workload identity federation, no stored secret), mirroring EP-2 (§9). | Reuse; prod must not hold a client secret. |

**Scope in one line:** role assignments at root, management group, subscription, resource group and resource scope, with inheritance; custom and built-in role definitions (all four action lists, wildcards, case rules); deny assignments (including All Principals, `ExcludePrincipals`, `DoNotApplyToChildScopes`); ABAC conditions v2.0 for the documented actions and attributes; PIM active and eligible assignments; nested Entra groups; resource locks — **exact**. Service data-plane models that bypass RBAC (storage keys and SAS, Key Vault access policies, Kubernetes RBAC, SQL logins), Azure Lighthouse delegations, Entra directory roles and Azure Policy — **unsupported, flagged**. Classic administrators — **out of scope** (retired, §3.4).

---

## 1. Problem and users

Same as AWS design §1: an access reviewer, an auditor and a platform engineer need "can principal P perform action A on scope S, and why" for Azure, plus "who can do A on S" and "who gains or loses what if this role-assignment PR merges". Today `azurerbac` emits one Tessera permission per (scope, role) and leaves inheritance, NotActions, deny assignments and conditions to the reader. That over-reports access (Contributor's NotActions ignored, deny assignments ignored) and under-reports it (management-group inheritance, nested groups).

## 2. Goals and non-goals

**Goals.** (G1) Exact decisions for the scope in §0 and §3.1, ≥ 99.5 % agreement with real Azure on a sandbox tenant. (G2) A trace that names the decisive assignment, role definition, permission block, matching action pattern and condition atoms. (G3) "Effective permissions", "who can" and "diff" queries at the AWS SLOs (AWS design §12.1). (G4) A role-assignment or custom-role PR shows who gains or loses which action at which scope.

**Non-goals (Phase 1).** Authorization inside services that keep their own model (§3.3); Entra ID directory roles and app roles (Microsoft Graph authorization); Azure Policy `deny` effects (configuration, not identity); any write to the customer tenant.

---

## 3. Scope cut: exact, approximated, unsupported

Fidelity follows AWS design §3 and §7.9: a decision is only as exact as the least-exact component that **could have changed the outcome**.

### 3.1 Exact

| Area | Covered |
|---|---|
| Scope hierarchy | `/` (root), tenant root management group, nested management groups, subscription, resource group, resource, and nested child resources (for example `…/storageAccounts/a/blobServices/default/containers/c`). Inheritance downward at every level [AZ1][AZ4]. |
| Role assignments | Any principal type (user, group, service principal, managed identity, `ForeignGroup` is §3.3), any scope above or at the target. Assignment `condition` + `conditionVersion` 2.0. |
| Role definitions | Built-in and custom. `permissions[]` blocks, each with `actions`, `notActions`, `dataActions`, `notDataActions`, and the role-level `condition` of built-in roles (for example Key Vault Data Access Administrator) [AZ2][AZ6]. |
| Deny assignments | Actions/NotActions/DataActions/NotDataActions, `Principals` (including All Principals, the zero GUID with type `SystemDefined`), `ExcludePrincipals`, `DoNotApplyToChildScopes`, scope inheritance [AZ3]. |
| Conditions | The v2.0 grammar (§5) with `ActionMatches`, `SubOperationMatches`, `Exists`, AND/OR/NOT, every documented comparison and cross-product operator, attribute sources `@Resource`, `@Request`, `@Principal`, `@Environment`, for the actions where Microsoft documents conditions: Blob and Queue storage data actions and `Microsoft.Authorization/roleAssignments/write|delete` (constrained delegation) [AZ5][AZ6][AZ7]. |
| PIM | Active (`Assigned` and `Activated`) schedule instances count as assignments, inside their schedule window. Eligible schedule instances never grant now (§4.6) [AZ8]. |
| Groups | Transitive (nested) membership of security groups from Microsoft Graph [AZ1]. |
| Resource locks | `CanNotDelete` and `ReadOnly`, inherited, control plane only (§4.8) [AZ9]. |

### 3.2 Approximated (`APPROXIMATE`, with a reason code)

| Area | Approximation | Reason code |
|---|---|---|
| `ReadOnly` lock on POST actions | Microsoft documents that a `ReadOnly` lock blocks POST operations (for example `listKeys`, VM restart) as well as writes and deletes, but gives no complete list. We block every non-`read` control-plane action under a `ReadOnly` lock and mark the decision approximate until a probe settles each action family. | `LOCK_EFFECT_UNVERIFIED` |
| Ambiguity defaults | A decision whose outcome depends on an unsettled register entry (§4.10). | `AMBIGUITY:AZ-A<n>` |
| Condition attribute support | An attribute that the attribute catalog (§6.3) does not list for the requested action is treated as absent, as for AWS keys, and marked approximate until probed. | `ATTRIBUTE_SUPPORT_UNVERIFIED` |
| Snapshot freshness | Role-assignment changes can take minutes to apply; we evaluate the snapshot. | `SNAPSHOT_STALENESS` |

### 3.3 Unsupported (`UNSUPPORTED`; best-effort answer, excluded from "exact" metrics)

| Area | Reason code |
|---|---|
| Data planes with their own authorization: storage shared keys and SAS, Key Vault vaults using the access-policy model (`enableRbacAuthorization=false`), Cosmos DB key or native RBAC, AKS Kubernetes RBAC, SQL logins | `NON_RBAC_AUTHZ_LAYER` |
| Azure Lighthouse (assignments held in the managing tenant are not listed in the customer tenant) and `ForeignGroup` principals | `CROSS_TENANT_DELEGATION` |
| A condition that uses an attribute, function or action outside §5 (the parser accepts the grammar, the catalog lacks the attribute) | `CONDITION_UNSUPPORTED` |
| A deny assignment that carries a non-empty `condition` (the field exists in the API; Microsoft documents no semantics for it) | `DENY_CONDITION_UNSUPPORTED` |
| An action missing from the pinned catalog | `CATALOG_MISS` |
| A stored role definition, assignment or condition that fails to parse | `POLICY_UNPARSEABLE` (fail-closed, as AWS §3.3: never skipped; every decision it could affect is UNSUPPORTED) |
| Root-scope (`/`) assignments not readable by the reader identity (§9.2) | `ROOT_SCOPE_UNREAD` |

### 3.4 Out of scope

- **Classic administrators** (Service Administrator, Co-Administrator). Retired on 31 August 2024; from December 2025 Azure converted remaining ones to Owner role assignments at subscription scope, and as of May 2026 they are fully retired [AZ10]. The converted Owner assignments are ordinary role assignments and are covered. The collector does not call the classic-administrator API.
- **Azure Policy** (`deny`, `denyAction`, `modify` effects). These constrain resource configuration, not who may act; they are not part of RBAC's documented evaluation [AZ1]. Recorded as a known source of disagreement on writes (§10.4 excludes write probes whose payload an assigned policy could deny).
- **Entra ID roles** (Global Administrator and others) except their one Azure effect, `elevateAccess`, which appears as a User Access Administrator assignment at `/` and is covered.

---

## 4. Verified Azure RBAC semantics

### 4.1 The documented order [AZ1]

1. The caller's token carries its group memberships, including transitive ones.
2. ARM retrieves all role assignments and deny assignments that apply to the resource.
3. **If a deny assignment applies, access is blocked.**
4. ARM narrows the role assignments to the user and its groups.
5. The action must be in some assigned role: `Actions − NotActions` (management) or `DataActions − NotDataActions` (data).
6. If no role has the action at the requested scope, access is denied.
7. If the matching assignment has a condition, it is evaluated; allow only if it is met.

The model is **additive**: effective permissions are the union of all role assignments [AZ1]. `NotActions` is **not a deny**: a second role that grants the action allows it [AZ2]. A condition **cannot deny**: it only filters the permissions of its own assignment [AZ5].

### 4.2 Scopes and inheritance

- Four assignable levels (management group, subscription, resource group, resource), parent to child; lower levels inherit from higher ones [AZ4]. `/` (root) sits above the tenant root group and is assignable (built-in roles' `assignableScopes` is `/` [AZ2]).
- Scope strings are resource IDs. A role assignment is an extension resource whose scope is the ID it extends [AZ4]. A nested child resource (`…/blobServices/default/containers/c`) is a scope, and every prefix that is itself a resource ID is an ancestor scope.
- **Case.** ARM resource IDs and resource-group names are case-insensitive ([AZ12] marks `resourceGroupName` "case insensitive"). The engine compares scopes with ASCII case folding and keeps the original spelling for display. Ambiguity AZ-A1 (non-ASCII names) defaults to Unicode simple case folding.
- `assignableScopes` restricts where a role can be *assigned*; it does not restrict evaluation. "Ultimately, the level of access is determined by the custom role assignment" [AZ2]. The engine ignores it at evaluation and the linter flags an assignment outside its role's assignable scopes.

### 4.3 Role definitions and action matching

- Action strings: `{Company}.{ProviderName}/{resourceType}/{action}`; `*` is a wildcard [AZ2]. Examples that fix the matcher: `*/read` (any provider), `Microsoft.Compute/*` (all actions of all types in a provider), `Microsoft.Network/*/read`, `Microsoft.Authorization/*/Delete` (in Contributor's NotActions).
- **Matching** is case-insensitive (ASCII) and `*` matches any sequence including `/` (the `Microsoft.Compute/*` example only works that way). Implemented with the AWS linear-time glob (`internal/aws/glob`, moved to a cloud-neutral package in AZ-1, §12), with `?` treated as a literal because Azure documents no `?` in actions. Ambiguity AZ-A2: whether `*` inside a segment (`Microsoft.Storage/storageAccounts/*Services/read`) is honoured; default yes (permissive), probe.
- A role grants action `a` iff **some permission block** has `a ∈ match(actions) ∧ a ∉ match(notActions)`, and likewise for data actions with `dataActions`/`notDataActions`. Subtraction is per block (the API shape is `permissions[]`); ambiguity AZ-A3 covers multi-block custom roles, default per block (permissive), probe.
- **Control and data are separate namespaces.** `Actions: ["*"]` (Owner, Contributor) never grants a data action; only `dataActions` does [AZ2]. The catalog (§6.3) classifies the requested action by `isDataAction`; a request whose action is not in the catalog is `CATALOG_MISS`.
- Built-in roles may carry a role-level `condition` (v2.0), for example the constrained delegation in Key Vault Data Access Administrator [AZ7]. It is ANDed with any assignment condition (AZ-A4; default AND, which is less permissive, so it is registered with an over-approximating fallback: if a probe has not settled it, a decision that depends on it is APPROXIMATE).

### 4.4 Deny assignments [AZ3]

- Properties: `Permissions.{Actions,NotActions,DataActions,NotDataActions}`, `Scope`, `DoNotApplyToChildScopes` (default false), `Principals[]`, `ExcludePrincipals[]`, `IsSystemProtected`.
- **All Principals**: `Principals` id `00000000-0000-0000-0000-000000000000` with type `SystemDefined`; allowed only in `Principals`, never in `ExcludePrincipals`.
- **Who creates them.** Customers cannot create deny assignments directly; Azure creates them, notably for **deployment stacks** with deny settings (and managed applications). Customer-managed deny assignments are in private preview as of 2026-10-06 [AZ3]. The engine handles any deny assignment it reads, whatever created it.
- **Applicability to a request (P, a, S):** the deny assignment's scope D is S, or an ancestor of S and `DoNotApplyToChildScopes` is false; `a` matches `Actions − NotActions` (or the data pair); P or any group of P is in `Principals` (or `Principals` is All Principals); and neither P nor any group of P is in `ExcludePrincipals`. Group matching in `ExcludePrincipals` is transitive by default (AZ-A5, permissive: an exclusion through a nested group excludes; probe with a deployment stack whose excluded principal is a group).
- **Precedence.** A matching deny assignment blocks access whatever role assignments grant [AZ1 step 4]. It applies to classic administrator assignments too [AZ3] (moot after §3.4).

### 4.5 Principals and group expansion

- Principals are Entra object IDs: users (members and B2B guests), groups, service principals and managed identities (service principals) [AZ1].
- Role assignments are **transitive for groups** [AZ1]. The snapshot holds, for each principal, the closure of its group memberships from Microsoft Graph `transitiveMemberOf`, restricted to groups ARM honours. Ambiguity AZ-A6: whether Microsoft 365 (non-security) groups and mail-enabled security groups count; default: count any group that holds an assignment (permissive), probe.
- Dynamic groups are taken as Graph reports their current membership. PIM for Groups: active group membership counts; eligible membership is an eligibility path (§4.6).
- Token group overage (users in very many groups) is ARM's problem, not ours: ARM documents that it evaluates transitive membership, and we model the membership, not the token. Any disagreement that traces to overage is triaged as AZ-A7.

### 4.6 PIM: eligible vs active [AZ8][AZ5]

- **Active**: `roleAssignmentScheduleInstances` with `assignmentType` `Assigned` or `Activated`, and plain `roleAssignments`. An activated eligibility appears as an active instance; the collector de-duplicates instance and assignment by `(principal, role, scope, condition)` and keeps the earliest end time.
- Schedules have start and end times. Concrete mode evaluates them against the request time; the snapshot's `as_of` is the default.
- **Eligible**: `roleEligibilityScheduleInstances` ("schedule instances only include assignments that are active at the current time") [AZ8]. An eligibility **grants nothing now**. It is reported in the trace as a non-decisive `pim_eligible` step and, in **potential mode** (`?include=eligible`), turns a would-be implicit deny into `CONDITIONAL` with residual atom `pim.activate(<eligibility id>)`. Conditions on eligible assignments are carried into the residual [AZ5].
- PIM activation policy (MFA, approval, justification) is not evaluated; it affects whether activation is possible, not what activation grants.

### 4.7 Conditions

See §5 for the language. Semantics [AZ5]: a condition on an assignment is evaluated only when the assignment's role grants the requested action; each `(!(ActionMatches{…}) OR (expr))` clause is true for actions it does not target, so only targeted actions are filtered. Conditions never deny on their own and never affect other assignments.

### 4.8 Resource locks [AZ9]

Locks "override any user permissions" and apply "across all users and roles". `CanNotDelete` blocks deletes; `ReadOnly` blocks deletes and updates and also POST operations. Locks apply to the control plane only, inherit to child scopes and extension resources, and the most restrictive lock wins; management groups cannot be locked. The engine runs locks as a **guardrail stage after a role decision of ALLOW**, with `DenyKind = Guardrail`. Delete actions (`*/delete`) under either lock are exact; non-read, non-delete actions under `ReadOnly` are `LOCK_EFFECT_UNVERIFIED` until probed (§3.2).

### 4.9 What the existing code and knowledge base get wrong

- `azurerbac` maps "role at scope" to one permission and marks privilege from `*`, ignoring `NotActions` (Contributor reads as able to write role assignments) and deny assignments. AZ-6 replaces those edges with evaluator-confirmed ones, as AWS PR-11 did.
- Group membership comes from the `entra` connector at graph level only; the evaluator needs the transitive closure in the snapshot (AZ-2).

### 4.10 Ambiguity register

Kept as a living doc in `docs/knowledge/azure-evaluation-ambiguities.md` (AZ-4), like the AWS one. Each entry: question, default (permissive), probe, status.

| Id | Question | Default | Probe |
|---|---|---|---|
| AZ-A1 | Case folding of non-ASCII scope names | Unicode simple folding | Resource group with a non-ASCII name, assignment at differently cased ID |
| AZ-A2 | `*` inside a segment in Actions | Honoured | Custom role with `Microsoft.Storage/storageAccounts/*Services/read` |
| AZ-A3 | NotActions subtraction per permission block | Per block | Custom role with two blocks (if ARM accepts it) |
| AZ-A4 | Role-level and assignment-level condition combine with AND | AND, decision APPROXIMATE until probed | Key Vault Data Access Administrator plus an assignment condition |
| AZ-A5 | Transitive group match in `ExcludePrincipals` | Transitive | Deployment stack excluding a parent group |
| AZ-A6 | Which group types ARM honours | All | M365 group and mail-enabled security group assignments |
| AZ-A7 | Group overage (> 200 groups in token) | Model membership | Probe user in 250 groups |
| AZ-A8 | Missing attribute in a comparison (not `Exists`) | Comparison false, so the clause fails (blob without tag `Project` fails `StringEquals 'x'`); `StringNotEquals` on a missing attribute is **true** (permissive) | Blob with and without the tag under each operator family |
| AZ-A9 | `SubOperationMatches` when the request has no sub-operation | false | Blob read with and without list |
| AZ-A10 | Deny assignment at a management group applies to its subscriptions | Yes | Deployment stack at management-group scope |

---

## 5. The condition language (v2.0)

**Grammar** (parser in `internal/azure/cond`, AZ-1), from [AZ6]:

```
condition   := clause ( ("AND"|"&&") clause )*
clause      := "(" "(" actionGuard ")" ("OR"|"||") "(" expr ")" ")"  | "(" expr ")"
actionGuard := "!" "(" actionTerm ")" ( ("AND"|"&&") "!" "(" actionTerm ")" )*
actionTerm  := "ActionMatches{" str "}" [ ("AND"|"&&") ["NOT"|"!"] "SubOperationMatches{" str "}" ]
expr        := term ( ("AND"|"&&"|"OR"|"||") term )*      -- mixed AND/OR without parentheses is rejected
term        := ["NOT"|"!"] ( "(" expr ")" | "Exists" attr | attr op value | value op value )
attr        := "@" ("Resource"|"Request"|"Principal"|"Environment") "[" name "]"
op          := BoolEquals|BoolNotEquals|String[Not]Equals[IgnoreCase]|String[Not]StartsWith[IgnoreCase]
             | String[Not]Like[IgnoreCase]|Numeric{Equals,NotEquals,GreaterThan[Equals],LessThan[Equals]}
             | DateTime{Equals,NotEquals,GreaterThan[Equals],LessThan[Equals]}|Guid[Not]Equals
             | ("ForAnyOfAnyValues"|"ForAllOfAnyValues"|"ForAnyOfAllValues"|"ForAllOfAllValues") ":" baseOp
value       := str | number | bool | "{" value ("," value)* "}"
```

`conditionVersion` must be `2.0` ("the only supported version" [AZ2]); anything else is `POLICY_UNPARSEABLE`.

**Operator semantics** [AZ6]: `StringLike` uses `*` and `?` with `\*`, `\?` escapes (same glob, case-sensitive unless `IgnoreCase`); numeric comparison is integers only; DateTime uses full precision `yyyy-mm-ddThh:mm:ss.fffffffZ`; GUID comparison is case-insensitive; the cross-product operators follow the four any/all definitions on [AZ6]. `ActionMatches` uses the action glob of §4.3.

**Attributes supported in Phase 1** (attribute catalog `catalog/azure/attributes.yaml`, AZ-1): Blob and Queue storage attributes as listed on the storage ABAC attribute pages (container name, blob path and prefix, blob index tags with `<$key_case_sensitive$>`, version ID, snapshot, encryption scope, is-current-version, HNS enabled, account name) [AZ5][AZ6]; `@Request`/`@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId|PrincipalId|PrincipalType]` [AZ7]; `@Environment[isPrivateLink|Microsoft.Network/privateEndpoints|Microsoft.Network/virtualNetworks/subnets|UtcNow]` [AZ6]; `@Principal[<attributeSet>_<attribute>]` custom security attributes [AZ6].

**Three-valued evaluation.** As AWS design §9.4: in concrete mode every attribute is present or absent; in "can ever" mode an attribute the request does not fix is `UNKNOWN`, and the clause becomes a residual atom. `@Environment[UtcNow]` defaults to the request time; private-link and subnet attributes default to `UNKNOWN`, so "can X read this blob" under a private-link condition is `CONDITIONAL(isPrivateLink == true)`.

**Limits** (untrusted input): condition ≤ 8 KiB, nesting depth ≤ 32, values per set ≤ 256, linear-time glob; violations are `POLICY_UNPARSEABLE`. Microsoft's visual editor limit of 5 expressions [AZ5] is not a grammar limit and is not enforced.

---

## 6. Data model

### 6.1 Engine types (`internal/azure/model`, AZ-1)

- `Snapshot{ID, TenantID, AsOf, Scopes ScopeTree, RoleDefs map[GUID]*RoleDef, Assignments []*Assignment, Eligibilities []*Assignment, Denies []*DenyAssignment, Locks []*Lock, Principals map[OID]*Principal, Groups Closure, CatalogVersion, Anomalies []IngestAnomaly}`; immutable after `Builder.Build()`.
- `ScopeTree`: nodes `{ID (canonical, original spelling kept), Kind (root|mg|subscription|rg|resource), Parent}`; `Ancestors(scope)` is O(depth), depth ≤ 6 management-group levels plus subscription, group and resource path.
- `RoleDef{ID, Name, BuiltIn, Blocks []PermBlock{Actions, NotActions, DataActions, NotDataActions PatternSet}, Condition *cond.Expr, AssignableScopes}`.
- `Assignment{ID, PrincipalID, PrincipalType, RoleDefID, Scope, Condition *cond.Expr, Source (direct|pim_active|pim_eligible), Start, End}`.
- `DenyAssignment{ID, Scope, Blocks PermBlock, Principals []PrincipalRef, AllPrincipals bool, Exclude []PrincipalRef, NoChildren bool, SystemProtected bool, Creator string}`.
- `Lock{Scope, Level (CanNotDelete|ReadOnly)}`; `Principal{OID, Type, CustomSecurityAttributes map[string][]string}`; `Closure` maps an OID to its sorted transitive group set.
- Requests: `eval.Request{Principal OID, Action string, Scope string, SubOperation string, Attributes map[string]Value, Mode (concrete|symbolic), IncludeEligible bool, At time.Time}`; it implements `authz.Request` with `Platform() == "azure"`.

### 6.2 Persistence (AZ-2)

Schema `internal/store/schema/0NNN_azure_snapshots.sql` plus `schema/postgres/0NNN_azure_snapshots.sql` with composite `(tenant_id, id)` foreign keys and regenerated `rls.sql`. Tables: `azure_connectors`, `azure_snapshots` (content hash, as_of, catalog version, status), `azure_snapshot_blobs` (canonical JSON of each source object, stored verbatim), `azure_ingest_anomalies`, `azure_explanations`. Every table has `tenant_id`, cross-tenant triggers and an isolation test; all SQL lives in `internal/store` (`repo_azure.go`) behind `TenantTx`.

### 6.3 Catalogs (`catalog/azure/`)

- **Operations**: `GET /providers/Microsoft.Authorization/providerOperations?$expand=resourceTypes` gives each operation's name and `isDataAction`. `tessera catalog refresh --cloud azure` snapshots it, `compile` writes a versioned artifact (same shape and determinism test as AWS PR-2).
- **Attributes**: `attributes.yaml`, hand-curated from [AZ5][AZ6][AZ7] with source URLs; which actions supply which attributes.
- **Data-plane model table**: which resource types can bypass RBAC and the property that says so (`enableRbacAuthorization`, `allowSharedKeyAccess`, `disableLocalAuth`) for `NON_RBAC_AUTHZ_LAYER`.

---

## 7. The evaluation algorithm

### 7.1 Pipeline

```
Eval(snap, req):
  P      := {req.Principal} ∪ snap.Groups[req.Principal]
  chain  := snap.Scopes.AncestorsOrSelf(req.Scope)          # target first, root last
  kind   := catalog.Kind(req.Action)                         # control | data | miss → UNSUPPORTED CATALOG_MISS
  # Stage 1: deny assignments (StageAzureDeny)
  for d in denies at scopes in chain:
      if d.Scope != req.Scope and d.NoChildren: skip (trace not_applicable)
      if not matchBlock(d.Blocks, kind, req.Action): skip
      if not (d.AllPrincipals or P ∩ d.Principals ≠ ∅): skip
      if P ∩ d.Exclude ≠ ∅: trace "excluded"; skip
      → DENY Explicit, decisive = d   (later stages still run for the trace)
  # Stage 2: role assignments (StageAzureRole)
  grants := []
  for a in active assignments at scopes in chain with a.Principal ∈ P and active at req.At:
      r := snap.RoleDefs[a.RoleDefID]
      if not grantsAction(r, kind, req.Action): continue
      c := And(evalCond(r.Condition), evalCond(a.Condition))       # Tri / Residual
      grants += (a, c)
  allow := AnyOf(c for (a, c) in grants)                            # additive model
  # Stage 3: PIM eligibility, only if allow is not True and req.IncludeEligible
  for e in eligibilities matching as in stage 2: allow := Or(allow, And(Atom(pim.activate(e)), cond(e)))
  # Stage 4: locks (StageAzureLock), only if allow is not False and kind == control
  lock := strictest lock at scopes in chain
  if lock blocks req.Action: → DENY Guardrail (exact for delete, else LOCK_EFFECT_UNVERIFIED)
  # Final
  denied by stage 1 → DENY Explicit; allow == True → ALLOW; allow == False → DENY Implicit; else CONDITIONAL(allow)
```

Deny-assignment matching is evaluated even when the role stage would deny, so the trace always shows both. Fidelity is accumulated per AWS §7.9 (outcome-sensitive reasons only).

### 7.2 Effective permissions and who-can

Same structure as AWS PR-10: atoms over the operations catalog (actions partitioned by the set of patterns that match them), envelopes per role definition, an inverted index from scope to assignments and from principal to closure. `EffectivePermissions(P, S)` and `WhoCan(a, S)` are exact over the catalog; wildcard actions in a role expand to the catalog's operations at the pinned version, and the result names the catalog version.

### 7.3 Simulation

`snapshot.Apply(PolicyChange)` supports add/remove role assignment, add/remove/modify custom role definition, add/remove group membership, and assignment condition changes. `query.Diff` gives who gains or loses which action at which scope; `render` produces the PR comment (shared renderer with AWS, AZ-6).

### 7.4 The explanation

`authz.ExplanationStep` with new stages `azure_deny`, `azure_role`, `azure_pim`, `azure_lock` (additive constants in `internal/authz`). `StmtRef` maps as: `PolicyID` = assignment or deny-assignment ID, `PolicyKind` = `role_assignment|deny_assignment|role_definition|lock`, `SourceARN` = the full resource ID, `StatementIndex` = permission block index, `AttachmentPath` = `[principal or group OID, role name, scope]`, `OrgLevel` = the scope kind. `MatchedOn` records the matching pattern and the excluding `NotActions` pattern if any. `explanation_id` = hash of canonical JSON, with `engine_version`, `catalog_version` and `snapshot_id`, as AWS.

---

## 8. Matching and case rules (summary)

| Item | Rule |
|---|---|
| Actions and data actions | ASCII case-insensitive, `*` matches any sequence including `/`; linear-time glob |
| Scopes | ASCII case-insensitive resource-ID comparison after canonicalization (trailing `/` removed, duplicate `/` rejected, `resourcegroups` and `resourceGroups` equal) |
| Principal and role IDs | GUIDs, case-insensitive |
| Condition string operators | Case-sensitive unless `…IgnoreCase`; tag keys written `<$key_case_sensitive$>` are case-sensitive keys |
| `ActionMatches` patterns | Same as actions |

---

## 9. Integration: collector, credentials, API, UI

### 9.1 Collector (AZ-2)

Extends `internal/connectors/azurerbac` (ARM) and `internal/connectors/entra` (Graph), plain HTTP through `safehttp`, no Azure SDK, read-only, paginated with `nextLink`, bounded like the existing connectors. ARM reads (api-version `2022-04-01` for Microsoft.Authorization, as the connector already uses):

| Data | Call |
|---|---|
| Management groups and subscriptions | Management-group descendants of the tenant root group; subscriptions list |
| Resource groups and resources | Per subscription list calls (or Resource Graph, Q4) |
| Role assignments | `{scope}/providers/Microsoft.Authorization/roleAssignments` per management group and subscription (lists at, above and below) |
| Role definitions | `{scope}/providers/Microsoft.Authorization/roleDefinitions` at each assignable scope |
| Deny assignments | `{scope}/providers/Microsoft.Authorization/denyAssignments` (no filter lists at, above and below) [AZ3] |
| PIM | `roleAssignmentScheduleInstances`, `roleEligibilityScheduleInstances` (`2020-10-01`) [AZ8] |
| Locks | `{scope}/providers/Microsoft.Authorization/locks` |
| Data-plane mode | `Microsoft.Storage/storageAccounts`, `Microsoft.KeyVault/vaults` properties |
| Operations catalog | `providers/Microsoft.Authorization/providerOperations` |

Graph reads: users, service principals and groups (IDs and types), `transitiveMemberOf` per principal that is in or under any assigned group, custom security attributes used by any condition, and PIM-for-Groups eligibility.

Fail-closed: an unreadable scope or an unparseable object is an `IngestAnomaly`; affected decisions are UNSUPPORTED (§3.3). An unchanged estate writes nothing (content hash).

### 9.2 Reader permissions

- ARM: **Reader** at the tenant root management group. Reader includes `*/read`, which covers `Microsoft.Authorization/roleAssignments/read`, `denyAssignments/read` [AZ3], `locks/read` and the PIM schedule reads [AZ8]. Assignments at `/` are only listable with elevated access [AZ3]; we do not elevate (Q3), so decisions that a root assignment could change carry `ROOT_SCOPE_UNREAD` unless the tenant attests there are none.
- Graph (application permissions, least set, verified in AZ-2 against Microsoft's permission reference): read users, groups and members, service principals; read custom security attribute assignments; read PIM-for-Groups eligibility. `internal/connectors/azurerbac` gains a `ReaderPermissions()` list that a test checks for read-only verbs, like `awsorg.ReaderPolicy`.

### 9.3 Credentials

Workload identity federation: an Entra app registration with a federated identity credential trusting a Tessera-issued JWT (`internal/keys`), exchanged at the Entra token endpoint; no stored secret. Client-secret and certificate modes stay only behind a flag that prod refuses (config guardrail), mirroring EP-2. Reviewed by `iam-pam-nhi-expert` and `iam-protocols-expert`.

### 9.4 API and UI (AZ-6)

`GET /api/azure/can`, `GET /api/azure/principals/{oid}/effective`, `GET /api/azure/who-can?scope=&action=`, `GET /api/azure/explanations/{id}`, `POST /api/azure/simulate-change`, connector and snapshot routes like `/api/aws/*`. All read-only except connector settings, tenant-scoped, RBAC-declared, audited (reads fail closed on audit). UI through `src/api.ts` only, lazy-loaded, reusing the EP-7 fidelity badges and trace viewer. Parity fixtures unchanged unless explained in their README.

---

## 10. The differential test harness

### 10.1 Oracles

| Tier | Oracle | Decides | Notes |
|---|---|---|---|
| O1 | **Real calls** by probe service principals (federated credentials) in the sandbox tenant | Everything in §3.1 | Control plane: harmless reads; writes and deletes only on canary resources; `POST` actions only on canaries. Data plane: blob/queue read, write, delete on canary containers. Outcome = 2xx/404 vs `AuthorizationFailed` (ARM) or the data-plane authorization error, classified by an error-code table recorded in cassettes. |
| O2 | `Permissions - List For Resource` as the probe principal [AZ12] | The union of permission blocks the caller holds at a resource | A cross-check of role union and inheritance only: it returns `actions/notActions/dataActions/notDataActions` "the caller has", with no conditions or deny assignments in the response. Disagreement with O1 is triaged, never counted. |
| O3 | `checkAccess`-style API, if Microsoft documents one we may call for arbitrary principals (Q2) | TBD | Not used until confirmed. |

### 10.2 Strata (EP-4 generator)

Scope depth (mg×k, sub, rg, resource, nested child); NotActions carve-outs; wildcards (provider, `*/read`, mid-segment); data vs control; multi-role union; deny assignment (scope, child scopes off, All Principals, excluded user, excluded group); conditions (blob tag, path, prefix, version, private link, UtcNow, constrained delegation, principal attribute); groups (nested 1–4 levels, dynamic, PIM for Groups); PIM (active window, expired, eligible); locks (CanNotDelete, ReadOnly × delete, write, POST). Sampling and sizes as AWS §13.4.

### 10.3 Sandbox tenant (AZ-5; described here, applied only after human sign-off)

`infra/sandbox/azure/` (Bicep or Terraform, Q5): a dedicated Entra tenant or a sandbox management group with 3 levels, 2 subscriptions, resource groups with canary storage accounts, queues, VMs (deallocated), Key Vaults in both models; custom roles covering the strata; deployment stacks with `denyDelete` and `denyWriteAndDelete` and excluded principals to create deny assignments; locks; probe service principals with federated credentials; PIM eligible and active schedules. Budget and owner: Q1.

### 10.4 Running and comparing

Propagation: role-assignment and lock changes are applied by scenario, then the harness waits and polls with an O1 canary call until the expected state is observed (bounded). Write probes exclude scopes with Azure Policy assignments that could deny the payload. Cassettes record raw HTTP at the safehttp layer (`internal/azure/azreplay`), the same pattern as `awsreplay`.

### 10.5 Gate

Exactly AWS §13.7 and the plan's success metric: every PR passes the golden corpus and replay at 100 %; nightly, Wilson 95 % lower bound ≥ 99.5 % at n ≥ 10,000, coverage ≥ 97 %, every stratum ≥ 99 %, zero S1 (confident-wrong) disagreements; 14 consecutive green nights for the exit criterion; weekly re-run of every AZ-A probe. The Wilson, minimizer and triage code is shared with AWS (§12).

---

## 11. Offline golden corpus

`testdata/azure/golden/*.yaml`, run by `TestGolden` in `internal/azure/eval`, same YAML format as AWS §14.1. Case ids are **AZG-nn** (not GC-nn, which the AWS corpus uses). Initial cases (AZ-4 completes them to cover every §3.1 row):

| Id | Case | Expected |
|---|---|---|
| AZG-01 | Reader at subscription, read VM in an RG | ALLOW |
| AZG-02 | Reader, VM restart (POST) | DENY implicit |
| AZG-03 | Contributor at MG two levels up, write storage account | ALLOW (inheritance) |
| AZG-04 | Contributor, `roleAssignments/write` | DENY implicit (NotActions) |
| AZG-05 | Contributor + User Access Administrator, `roleAssignments/write` | ALLOW (NotActions is not deny) |
| AZG-06 | Owner, blob read (data action) | DENY implicit (control ≠ data) |
| AZG-07 | Storage Blob Data Reader at container, blob read | ALLOW |
| AZG-08 | Custom role `Microsoft.Network/*/read`, read NSG | ALLOW; write NSG DENY |
| AZG-09 | Action case variant `microsoft.web/sites/restart/Action` | ALLOW |
| AZG-10 | Deny assignment `*/delete` at resource, Owner deletes | DENY explicit |
| AZG-11 | Same, principal in `ExcludePrincipals` | ALLOW |
| AZG-12 | Deny at RG with `DoNotApplyToChildScopes`, delete child resource | ALLOW |
| AZG-13 | Deny with All Principals, user via nested group | DENY explicit |
| AZG-14 | Deny excludes a parent group of the user | ALLOW, `AMBIGUITY:AZ-A5` until probed |
| AZG-15 | Assignment via group nested 3 deep | ALLOW |
| AZG-16 | Blob tag condition, tag matches | ALLOW |
| AZG-17 | Blob tag condition, tag absent | DENY implicit (AZ-A8) |
| AZG-18 | Blob tag condition, symbolic mode | CONDITIONAL(tag == 'Cascade') |
| AZG-19 | Condition targets read only; write allowed unconditionally | ALLOW write |
| AZG-20 | `SubOperationMatches{'Blob.List'}` exclusion | List ALLOW, read gated |
| AZG-21 | Private-link condition, concrete false | DENY implicit |
| AZG-22 | Constrained delegation: assign allowed role to a group | ALLOW; assign Owner DENY |
| AZG-23 | Principal custom security attribute equals blob tag | ALLOW / DENY by value |
| AZG-24 | PIM eligible Owner, concrete | DENY implicit, `pim_eligible` step |
| AZG-25 | Same, potential mode | CONDITIONAL(pim.activate) |
| AZG-26 | PIM activated, inside window / after end | ALLOW / DENY |
| AZG-27 | CanNotDelete lock at RG, Owner deletes resource | DENY guardrail |
| AZG-28 | ReadOnly lock, `listKeys` | DENY guardrail, `LOCK_EFFECT_UNVERIFIED` |
| AZG-29 | Lock, blob delete (data plane) | ALLOW (locks are control plane only) |
| AZG-30 | Key Vault in access-policy mode, secret get | UNSUPPORTED `NON_RBAC_AUTHZ_LAYER` |
| AZG-31 | Unparseable condition on a relevant assignment | UNSUPPORTED `POLICY_UNPARSEABLE` |
| AZG-32 | Action missing from catalog | UNSUPPORTED `CATALOG_MISS` |
| AZG-33 | Scope compared with different casing | ALLOW |
| AZG-34 | Two roles, one with condition false, one without condition | ALLOW (additive) |

---

## 12. Implementation plan (AZ-1…AZ-6)

Mirrors the plan's row "Parser, collector, evaluator, golden corpus, harness and integration". Each PR keeps `go test -race ./...`, both SQL dialects, archtest purity rules and the parity fixtures green. Paths are under `mvp/server/` unless noted.

| PR | Scope | Files | Tests | Deps |
|---|---|---|---|---|
| **AZ-1** Types and parsers | `internal/azure/model`; strict parsers for role definitions, assignments, deny assignments (JSON from ARM) and the v2.0 condition language (§5) with limits; scope-ID canonicalizer; move the AWS glob to `internal/authz/glob` (no behaviour change, AWS tests unchanged); attribute catalog skeleton; additive `authz.Stage` constants | `internal/azure/{model,cond,scope}/`, `internal/authz/glob/`, `catalog/azure/attributes.yaml` | Table tests per grammar rule and operator; `FuzzParseCondition`, `FuzzScopeCanonical`; round-trip; ReDoS worst case | AZ-0 approved |
| **AZ-2** Collector, catalog and persistence | ARM and Graph reads of §9.1, federated credentials (§9.3), fail-closed anomalies, `ReaderPermissions()`, provider-operations catalog refresh/compile, `azure_*` tables (SQLite + Postgres + RLS) | `internal/connectors/{azurerbac,entra}`, `internal/azure/catalog/`, `internal/store/{model_azure,repo_azure}.go`, schema files | Recorded-HTTP replay of every call incl. pagination, 403 per scope, throttling (`Retry-After`); isolation test for `azure_*`; content-hash stability; config guardrail test (prod refuses secret mode); `TestSchemaParity_*`, `TestPostgresStatementsTranslate` | AZ-1 |
| **AZ-3** Evaluator | §7.1 pipeline, conditions (Tri/Residual), PIM, locks, fidelity, explanation | `internal/azure/{eval,snapshot}/` | Purity archtest; determinism (shuffled inputs, byte-identical traces); `TestEvalDoesNotMutateSnapshot`; symbolic soundness (rapid) | AZ-1 |
| **AZ-4** Golden corpus and ambiguity register | AZG-01…AZG-34 plus cases until every §3.1 row is covered; `docs/knowledge/azure-evaluation-ambiguities.md` | `testdata/azure/golden/`, `internal/azure/eval/golden_test.go`, docs | Golden at 100 %; generated rule-coverage matrix | AZ-3 |
| **AZ-5** Harness and sandbox | Oracle clients O1/O2, cassettes and `azreplay`, comparator, strata generator (from EP-4), Wilson gate; extract provider-neutral `metrics.go`, `minimize.go`, triage into `internal/harnesscore` (AWS unchanged); `infra/sandbox/azure/` and the nightly workflow (**touches `.github/` and infra: `needs-human`**, applied only after sign-off) | `internal/azure/harness/`, `internal/harnesscore/`, `cmd/tessera-harness` (`--cloud azure`), `infra/sandbox/azure/` | Replay of recorded oracle responses; error-code classification table tests; archtest: server never imports the harness | AZ-2, AZ-4, EP-4 |
| **AZ-6** Indexes, queries and integration | Atoms, `EffectivePermissions`, `WhoCan`, `Diff`; `/api/azure/*`; evaluator-confirmed edges replace `azurerbac`'s role-at-scope permissions; PR comment; UI page through `src/api.ts` with fidelity badges | `internal/azure/{index,query,render}/`, `internal/api/azure*.go`, `mvp/frontend/src/features/insights/`, `mvp/README.md` | Atoms ≡ brute force (rapid); perf at 2× target scale (`-tags slow`); API tests via `httptest`; exit-criterion-2 test (a role-assignment PR gives an exact gained/lost list); parity fixtures unchanged or explained | AZ-3, AZ-2 |

Critical path: AZ-1 → AZ-3 → AZ-4 → AZ-5 (first nightly). AZ-2 runs beside AZ-3; AZ-6 after AZ-3 and AZ-2.

---

## 13. Risks

| Risk | Mitigation |
|---|---|
| No first-party decision oracle for arbitrary principals (unlike AWS's simulator) | O1 real calls with designed probe principals; strata sized so each needs few principals; Q2 tracks a Microsoft API |
| Propagation delay makes nightly runs flaky | Poll-until-observed per scenario; quarantine and re-run before counting a disagreement |
| Error-code drift in ARM and data planes | Error classification table in cassettes; unknown codes are "invalid", never "deny" |
| ABAC attribute list grows per service | Attribute catalog with source URLs; unknown attribute ⇒ `CONDITION_UNSUPPORTED`, never a guess |
| Customer-managed deny assignments leave preview and gain conditions | `DENY_CONDITION_UNSUPPORTED` today; re-read [AZ3] in the weekly probe run |
| Tenant-wide Graph reads are large | Read only principals in or under assigned groups; incremental by delta query later |

## 14. Security properties

As AWS brief: inputs are untrusted (strict parse, limits, fuzzing, linear glob, per-evaluation deadline); evaluator packages are pure (archtest); snapshots immutable; raw source objects stored verbatim; every outbound call through `safehttp`; read-only reader identity checked by test; tenant isolation for every `azure_*` table; harness never linked into the server.

## 15. Open questions for the human

| # | Question | Proposed answer | Owner |
|---|---|---|---|
| Q1 | Who owns the sandbox (dedicated Entra tenant vs a sandbox management group in an existing tenant), its budget, and sign-off for probe credentials? | Dedicated tenant (deny assignments, root scope and Graph permissions are tenant-wide); security engineering owns it; same Phase 0 sign-off as #28 | Security lead, founder |
| Q2 | Is there a Microsoft API that decides access for an arbitrary principal (a "checkAccess") that we may use as an oracle? | Ask Microsoft through the partner channel; until then O1 only | iam-architect |
| Q3 | May the reader see root-scope (`/`) assignments, which need elevated access? | No elevation; ask the customer to attest, else `ROOT_SCOPE_UNREAD` | Security lead |
| Q4 | Use Azure Resource Graph (`authorizationresources`) for bulk collection instead of per-scope REST? | Yes for scale after AZ-2 ships with REST; REST stays the reference | iam-architect |
| Q5 | Bicep or Terraform for `infra/sandbox/azure`? | Terraform, to match `infra/sandbox` for AWS | Platform |
| Q6 | Model Entra directory roles (Graph authorization) as a later "AZ-7"? | Later; separate design | Product |
| Q7 | Should potential mode include PIM eligibility by default in the access-review UI? | Yes, as a separate column, never merged with active access | iam-governance-expert |
| Q8 | One shared `/api/explanations/{id}` route across clouds instead of per-cloud routes? | Yes, decide before AZ-6 and GC-6 | iam-architect |

---

## 16. Sources (Microsoft Learn, read 2026-11-07)

- **[AZ1]** "What is Azure role-based access control (Azure RBAC)?" (scopes, groups transitive, additive model, "How Azure RBAC determines if a user has access to a resource"): https://learn.microsoft.com/en-us/azure/role-based-access-control/overview
- **[AZ2]** "Understand Azure role definitions" (properties, Actions/NotActions/DataActions/NotDataActions, wildcard examples, NotActions is not a deny, AssignableScopes, conditionVersion 2.0): https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions
- **[AZ3]** "List Azure deny assignments" (properties, All Principals, ExcludePrincipals, DoNotApplyToChildScopes, deployment stacks, private preview of customer-managed deny assignments, REST filters, required permission): https://learn.microsoft.com/en-us/azure/role-based-access-control/deny-assignments
- **[AZ4]** "Understand scope for Azure RBAC": https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview
- **[AZ5]** "What is Azure attribute-based access control (Azure ABAC)?" (where conditions apply, conditions cannot deny, status table, PIM with conditions): https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-overview
- **[AZ6]** "Azure role assignment condition format and syntax" (grammar, operators, attribute sources, environment attributes): https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-format
- **[AZ7]** "Delegate Azure access management to others" (conditions on `roleAssignments/write|delete`, `RoleDefinitionId`, `PrincipalType`, built-in roles with conditions): https://learn.microsoft.com/en-us/azure/role-based-access-control/delegate-role-assignments-overview
- **[AZ8]** "Manage eligible access to Azure resources through PIM using REST API" (`roleEligibilitySchedules`, schedule instances, filters): https://learn.microsoft.com/en-us/rest/api/authorization/privileged-role-eligibility-rest-sample
- **[AZ9]** "Lock your Azure resources" (lock levels, override all permissions, inheritance, control plane only, POST blocked): https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources
- **[AZ10]** "Azure classic subscription administrators" (retirement 2024-08-31, Owner conversion December 2025, fully retired May 2026): https://learn.microsoft.com/en-us/azure/role-based-access-control/classic-administrators
- **[AZ11]** Storage ABAC attributes (blob and queue), linked from [AZ6]: https://learn.microsoft.com/en-us/azure/storage/blobs/storage-auth-abac-attributes and https://learn.microsoft.com/en-us/azure/storage/queues/queues-auth-abac-attributes (to be read in full in AZ-1 when the attribute catalog is built)
- **[AZ12]** REST "Permissions - List For Resource" (2022-04-01; "Gets all permissions the caller has for a resource"): https://learn.microsoft.com/en-us/rest/api/authorization/permissions/list-for-resource
