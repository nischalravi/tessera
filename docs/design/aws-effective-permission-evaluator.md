# Design: Exact AWS effective-permission evaluator, with explanations and a differential test harness

| | |
|---|---|
| **Status** | Draft for review. Implementation-ready once open questions Q1–Q4 are answered. |
| **Phase / item** | Phase 1, step 1 (`docs/knowledge/README.md`, capability map A, rows 2–3; D3·M1, D3·M2, D5·M2) |
| **Authors** | iam-architect, with iam-authz-expert (evaluation semantics) and iam-pam-nhi-expert (NHI, trust and escalation angle) |
| **Reviewers needed** | iam-authz-expert: §5–§9 and the golden corpus (§14). iam-pam-nhi-expert: §11.4 and trust edges. iam-governance-expert: the evidence fields in §7.11. |
| **Date** | 2026-10-08. AWS docs re-read on that date. Every AWS claim cites a source in §18. |
| **Exit criteria served** | (1) On a sandbox AWS org, the evaluator agrees with AWS on **≥ 99.5 %** of sampled checks. (2) A policy PR shows exactly **who gains or loses which permission**. |

---

## 0. Summary of key decisions

| # | Decision | Why |
|---|---|---|
| D1 | Build the evaluator as a **pure-Python reference implementation** in `mvp/backend/tessera/aws/`. Its inputs are immutable snapshots and it has no I/O. The Rust Effective-Permission Engine (spec §5, §6) will later be a port of it and is differentially tested against it. | The MVP is Python. Correctness comes before speed in Phase 1. A readable reference becomes the oracle for every later implementation, which is the same approach Cedar took (a Lean model checked against Rust; see §2.3). |
| D2 | Every decision has **three values**: `ALLOW`, `DENY` or `CONDITIONAL`. A `CONDITIONAL` decision carries a residual predicate. Each decision also carries a **fidelity flag**: `EXACT`, `APPROXIMATE` or `UNSUPPORTED`, with reasons. | "Can X ever do Y" questions have context we cannot know. A wrong confident answer is worse than an honest "it depends" (D3·§8.2). |
| D3 | When the AWS docs are ambiguous, **over-approximate access**: report the more permissive reading, mark it `APPROXIMATE`, and register a probe that settles it against live AWS (§4.3). | For a security product, missing a real grant is worse than flagging one that might exist. Probes convert approximations into `EXACT` over time. |
| D4 | The action, resource and condition-key catalog comes from **AWS's official Service Reference JSON** (`servicereference.us-east-1.amazonaws.com`). It is snapshotted, versioned and pinned per decision. **iam-dataset (MIT)** is a supplementary source. We take **no AGPL code or data** (PMapper, iam-simulate). | It is first-party, machine-readable and updated within 24 hours. The licences are compatible with ours. |
| D5 | The harness uses **four oracles in tiers**: SimulateCustomPolicy, SimulatePrincipalPolicy, **live probes** (real, harmless API calls made with real sessions in the sandbox), and Access Analyzer custom checks. Each check type is routed to the oracle that can actually decide it (§13.3). | The simulator cannot evaluate RCPs, session policies, trust policies, KMS grants, ACLs or Block Public Access (§13.2). Live probes are the only oracle for those. |
| D6 | The CI gate is the **Wilson 95 % lower bound** of agreement, which must be ≥ 99.5 %. This needs n ≥ 10,000 decided checks a night, which tolerates ≤ 38 disagreements. Coverage is reported separately so that `UNSUPPORTED` cannot be used to game the number. Every PR must pass 100 % of the offline golden and replay corpus. | A raw percentage over a small sample would let the gate pass by luck. |
| D7 | Performance comes from **equivalence-class ("atom") partitioning** of actions and resources, compiled statements, and inverted indexes by service prefix. Recompute is incremental from policy deltas. | Full recompute for every PR does not scale. The atom approach is how Zelkova-style tools keep universal questions tractable. |
| D8 | Integration keeps the MVP contract. The AWS connector stops emitting hand-picked `Permission` rows and emits **evaluator-confirmed** ones, each with an `explanation_id`. `simulate()` gains a policy-document change type, and that is what produces the "who gains or loses" PR comment. | This reuses `GraphSnapshot`, `diff_effective` and the least-privilege code unchanged where possible. |

**Phase-1 scope in one line:** identity, resource, boundary, SCP (per OU level), RCP, session and explicit deny are **exact**. So are trust policies and AssumeRole edges, KMS key policies and grants, S3 bucket policies with ACLs, Object Ownership and Block Public Access, NotAction/NotResource/NotPrincipal, every condition operator and policy variables. **Approximated** (flagged): VPC endpoint policies, access points, service-specific keys that the request cannot supply, and RAM shares. **Unsupported** (flagged): Identity Center ABAC attribute sourcing, S3 Access Grants, Lake Formation, data-plane ACL systems other than S3, and EC2 multi-resource authorization.

---

## 1. Problem and users

Tessera's wedge is access-as-code with a pre-merge blast-radius diff (spec D1). The diff is only worth something if the effective permissions under it match what AWS enforces. Knowledge doc 03 §1 says "A blast-radius number that disagrees with the cloud's real decision is worse than having no number." Today the MVP does not evaluate AWS at all. `connectors/demo_company.py` hard-codes `(action, resource)` permission rows on roles, and `graph.py` treats any reachable `perm` node as granted. There are no denies, guardrails, conditions or resource policies.

Users and their questions:
- **Marcus (platform engineer):** "If I merge this PR, who gains or loses `s3:GetObject` on `prod-pii`?"
- **Priya (head of security):** "Who can decrypt with the PII KMS key, and why?"
- **Auditor:** "Show me the statement, policy version and OU path that justified this access on 2026-09-30."
- **NHI owner (iam-pam-nhi-expert):** "Which humans and workloads can become `CIDeployRole`, through which trust chain?"
- **Least-privilege engine:** "Is this used-only policy equivalent to the old one for every observed call, and strictly smaller otherwise?"

---

## 2. Goals and non-goals

### 2.1 Goals
1. **G1 — Point decisions.** Given a concrete request (principal, action, resource, context), return the decision AWS would make, with the deny kind (explicit, implicit or guardrail), for every policy type in scope.
2. **G2 — Explanations.** Every decision carries a structured trace. It names every statement that allowed, denied, failed to match or gated the request, with the policy's ARN and version, the attachment path (user → group → policy; account → OU → root for SCPs), and the condition evaluation.
3. **G3 — Partial-context ("can ever") decisions.** When context is unknown, return `CONDITIONAL` with a minimal residual predicate, for example `aws:MultiFactorAuthPresent = true ∧ aws:SourceIp ∈ 10.0.0.0/8`.
4. **G4 — Set queries.** "All effective permissions of principal X" and "who can do action Y on resource Z", at the scale in §12.
5. **G5 — Change diffs.** Given a policy change (a PR), list the (principal, action, resource-class) tuples whose decision changes, each with before and after explanations.
6. **G6 — Measured fidelity.** A differential harness against AWS reports agreement nightly. The evaluator is never released below the gate.
7. **G7 — Assume-role reachability.** Trust edges, including sts:AssumeRole, AssumeRoleWithWebIdentity and AssumeRoleWithSAML, plus role chains, so that "effective permissions of a human" includes the roles they can become. This feeds NHI exposure and the Phase 2 escalation analysis.

### 2.2 Non-goals for Phase 1
- **Enforcement.** Tessera does not sit on the request path.
- **Full privilege-escalation analysis.** That is Phase 2 and uses pathfinding.cloud. Phase 1 builds only the AssumeRole and PassRole edges it needs.
- **Azure and GCP evaluators** (Phase 3). The interfaces in §6 must not be AWS-specific in their names.
- **SMT-based universal proofs.** Phase 1 gives exact point and enumeration answers plus syntactic residuals. Z3/cvc5 encoding is a Phase 2 item (Q5). The data model leaves room for it.
- **Cedar ↔ IAM compilation.** That is a separate Phase 1 item. This evaluator is what checks the compiled output.
- **Service-specific authorization outside IAM policy language**, such as Lake Formation, S3 Access Grants, RDS IAM DB auth token scoping, or Cognito.

### 2.3 Prior art we learn from (verified 2026-10-08)

| Project | Licence | Maintenance | Use for us |
|---|---|---|---|
| **AWS Service Reference JSON** (`servicereference.us-east-1.amazonaws.com/v1/<svc>/<svc>.json`) | AWS site terms (first-party data) | Live; changes appear within 24 h | **Primary catalog.** Fields: `Actions[].Name`, `ActionConditionKeys`, `Resources[].Name`, `Annotations.Properties` (`IsList`, `IsWrite`, `IsPermissionManagement`, `IsTaggingOnly`), `Resources[].ARNFormats`, `ConditionKeys[].Types`, `Operations[].AuthorizedActions` plus SDK method mapping, `Version`. It has no dependent-actions field. |
| **iam-dataset** (iann0036) | MIT | Pushed 2026-10-08 (daily automation) | **Supplementary.** Dependent actions, SDK-to-action `map.json`, access-level strings. |
| **policy_sentry** (Salesforce) | MIT | 0.15.2, 2026-04-14; database refreshed monthly by scraping HTML | Cross-check only. Its access-level overrides are useful. |
| **Parliament** (Duo Labs) | BSD-3-Clause | 1.6.4, 2025-04; data last refreshed 2025-02 (stale) | Learn from its `is_arn_match` segment logic and lint fixtures. Do not use its data. |
| **policyuniverse** (Netflix) | Apache-2.0 | Dormant since 2024 | Its "internet accessible" heuristics give us edge-case ideas. Its data is stale. |
| **cloudsplaining** (Salesforce) | BSD-3-Clause | 0.9.1, 2026-06 | Not an evaluator: it only does pattern risk. It now consumes pathfinding.cloud. |
| **PMapper** (NCC Group) | **AGPL-3.0** | Last release 2022 | **Read only, copy nothing.** Its check order (`local_check_authorization_full`) is a useful checklist. Known bugs to avoid: it case-folds ARNs, does incomplete regex escaping, has no RCPs, bypasses boundaries for every same-account resource-policy match whatever the principal type, and treats a statement with no `Resource` as matching everything. |
| **iamlive** | MIT | v1.1.28, 2026-04 | Its SDK-call-to-action map helps the harness build realistic requests. |
| **pathfinding.cloud** (Datadog) | **Apache-2.0** (repo verified) | Pushed 2026-10-08 | Phase 2 escalation catalog. Phase 1 uses it only to choose which actions the harness samples more heavily. |
| **iam-simulate** (cloud-copilot, now `act-security-labs/iam-simulate`) | **AGPL-3.0-or-later** | Active (npm 0.1.173) | The closest OSS competitor: it covers identity, resource, boundary, SCP, RCP and session policies with a trace. **Do not copy code or test data.** We may compare black-box outputs only if counsel agrees (Q7). |
| **iamspy** (Datadog, Z3-based) | [unverified] | [unverified] | Possible reference for the Phase 2 SMT encoding. |
| **Zelkova** (Backes et al., FMCAD 2018); **Stratified Abstraction** (Backes et al., CAV 2020); **Block Public Access** (Bouchet et al., ESEC/FSE 2020) | Papers | — | Encode ARNs as strings with glob-to-regex. Model key presence as a separate boolean (this is what makes IfExists and Null exact). Use condition-key equivalence classes for "public". The atoms idea in §12 comes from here. |
| **Cedar** (Cutler et al., OOPSLA 2024); **How We Built Cedar** (Disselkoen et al., FSE 2024 Companion) | Papers | — | Verification-guided development: a readable reference model, differential random testing of the production engine against it, and type-directed generators. That is the method for D1 and §13.4. |
| **Chakarov et al., "Formally Verified Cloud-Scale Authorization"** (ICSE 2025) [details unverified] | Paper | — | AWS rebuilt its IAM authorizer in Dafny and shadow-tested it. This is the strongest public evidence that differential testing at scale finds corner cases. |

**No permissively licensed, neutral IAM evaluation corpus exists.** The corpus in §14 is our own, and every case is labelled with the source that justifies it.

---

## 3. Scope cut: exact, approximated, unsupported

Every `Decision` has a `fidelity` of `EXACT`, `APPROXIMATE` or `UNSUPPORTED`, plus `fidelity_reasons: list[FidelityReason]`. A decision is only as exact as the least-exact component that **could have changed the outcome**. Components that were evaluated but could not flip the result do not downgrade it. For example, an approximated VPC endpoint policy cannot downgrade a request that is already explicitly denied by an identity policy (§7.9).

### 3.1 Exact (`EXACT`)

| Area | Covered |
|---|---|
| Identity policies | User inline and managed policies, group policies (via the user's groups), role inline and managed policies, default policy version only, and `Version` 2008 vs 2012 (2008 makes policy variables literal text). |
| Permissions boundaries | Users and roles. Implicit deny limits the identity path and role-ARN or parent-user resource grants. Explicit deny always applies. |
| Session policies | Inline plus up to 10 managed ARNs, for AssumeRole*, GetFederationToken and Identity Center sessions (the permission set's inline policy is identity, not session). Direct session-ARN grants are not limited by them. |
| SCPs | Per-level intersection from root through OUs to the account. Full IAM language since Sept 2025: Allow with `Condition`, resource ARNs, `NotAction`, `NotResource`, and wildcards anywhere in actions. Management account exempt. Service-linked roles exempt. External principals are not subject to the resource account's SCPs. |
| RCPs | Per-level intersection on the **resource account**. Deny-only customer RCPs; `RCPFullAWSAccess`; `Principal: "*"` only. Supported-service list from §10.3. Management-account resources exempt. SLR callers exempt. AWS-managed KMS keys exempt. `kms:RetireGrant` exempt. |
| Resource-based policies | S3 bucket, SQS, SNS, Secrets Manager, Lambda function, ECR repository, KMS key policy, IAM role trust policy, and any service whose resource policy the connector collects. The same-account principal-type matrix (§7.4). Cross-account dual evaluation. |
| Role trust and AssumeRole | sts:AssumeRole, AssumeRoleWithWebIdentity, AssumeRoleWithSAML, sts:TagSession, sts:SetSourceIdentity. Explicit allow required in the trust policy. ExternalId and OIDC `aud`/`sub` conditions. Role-chain edges. |
| KMS | Key policy is mandatory. Account-principal delegation enables IAM policies. Grants (allow only; operations; EncryptionContextEquals/Subset; SourceArn constraint). Cross-account operation allowlist. |
| S3 | Bucket policy; bucket and object ACLs when Object Ownership ≠ BucketOwnerEnforced; Block Public Access (org, account, bucket) with the "is public" test; RestrictPublicBuckets; bucket-owner explicit deny on objects owned by another account. |
| Policy grammar | Action/NotAction, Resource/NotResource, Principal/NotPrincipal, wildcards (`*`, `?`), case rules (§8.1), and statement/policy OR semantics. |
| Conditions | Every operator family, `…IfExists`, `Null`, `ForAllValues`/`ForAnyValue`, policy variables (including defaults and `${*}`/`${?}`/`${$}`), multi-key AND, multi-value OR, and type coercion (§9). |
| Principals | IAM user, role session (AssumeRole, web identity, SAML, EC2 instance profile, Identity Center), STS federated user, account root (including `aws:AssumedRoot`), service principal, anonymous, and service-linked-role session. |

### 3.2 Approximated (`APPROXIMATE`, with a reason code)

| Area | Approximation | Reason code |
|---|---|---|
| VPC endpoint policies | Evaluated only when the request says it came through a known endpoint (`aws:SourceVpce` is set and the snapshot has that endpoint's policy). Otherwise the endpoint is assumed to allow. | `VPCE_POLICY_UNKNOWN` |
| S3 access points and multi-Region access points | The access point policy is evaluated as a second resource policy that must also allow, plus the bucket's delegation. Doc ambiguity A13. | `S3_ACCESS_POINT` |
| Service-specific condition keys | Correct when the caller supplies the value. Absent from a "can ever" query means `UNKNOWN`, which produces `CONDITIONAL`, not an approximation. A key that the catalog does not list for the action is treated as **absent**, which is AWS's behaviour, but only `APPROXIMATE` until probes confirm it. | `KEY_SUPPORT_UNVERIFIED` |
| Same-account resource policies for services other than IAM and KMS that may require an explicit RBP allow | A per-service table (§7.4.3). Services missing from the table use the default union rule. | `SERVICE_RBP_RULE_UNVERIFIED` |
| Doc-ambiguity defaults | Any decision whose outcome depends on an entry in the ambiguity register (§4.3) that has not yet been settled by a probe. | `AMBIGUITY:<id>` |
| AWS RAM shares | Treated as a synthetic resource policy built from the RAM managed permission. | `RAM_SHARE` |
| Policy-size and propagation state | We evaluate the snapshot. Eventual consistency (IAM: seconds; KMS grants: up to ~5 min; RCP changes in Access Analyzer: up to 24 h) is outside the model. | `SNAPSHOT_STALENESS` (when the snapshot is older than its freshness SLO) |

### 3.3 Unsupported (`UNSUPPORTED`; the decision is still returned as best effort and excluded from "exact" metrics)

| Area | Reason code |
|---|---|
| EC2 multi-resource authorization (RunInstances checks image, subnet, SG, volume…) beyond a single target ARN | `MULTI_RESOURCE_ACTION` |
| Lake Formation, S3 Access Grants, OpenSearch fine-grained access control, EKS RBAC, Redshift and RDS database grants | `NON_IAM_AUTHZ_LAYER` |
| Identity Center ABAC attributes (`aws:PrincipalTag` sourced from the IdP at sign-in) unless the session context supplies them | `IDC_ABAC_SOURCE` |
| Forward access sessions and `aws:CalledVia` chains that the request does not state | `FAS_CHAIN` |
| Declarative policies (EC2 and others), backup, tag and AI opt-out policies | `DECLARATIVE_POLICY` |
| Actions missing from the pinned catalog (new services) | `CATALOG_MISS` |

The UI shows exact results with no badge, approximate results with an amber badge and the reason, and unsupported results with a grey badge. Neither least privilege nor auto-revoke ever acts on `APPROXIMATE` or `UNSUPPORTED` evidence (spec R2).

---

## 4. Verified AWS evaluation semantics

This section is the normative semantic source for the implementation. Where it differs from `docs/knowledge/03-authorization-and-policy.md` §4.5, it supersedes it. §4.4 lists the corrections to make in the knowledge doc.

### 4.1 The facts the algorithm depends on (each traceable to §18)

1. **Default and deny.** All requests are implicitly denied except those from the account root user. "An explicit deny overrides an explicit allow." The enforcement code looks for applicable `Deny` statements across SCPs, RCPs, resource policies, identity policies, boundaries and session policies **first** [S1].
2. **Order on the documented single-account path** [S1]: explicit deny → RCPs (some allow must exist; `RCPFullAWSAccess` cannot be detached) → SCPs → resource-based policies (principal-type dependent) → identity-based policies → permissions boundary → session policy → allow.
3. **Principal-type matrix for same-account resource-policy grants** [S1, S2, S6]:
   - **IAM user ARN**: not limited by an implicit deny in identity policies or the boundary.
   - **Role session ARN** (assumed-role): granted directly to the session. Not limited by an implicit deny in identity, boundary or session policies.
   - **STS federated-user ARN**: same as a role session. A grant to the **IAM user who federated** is limited by the boundary and session policy.
   - **IAM role ARN** (in `Principal` or in `aws:PrincipalArn`): limited by an implicit deny in the boundary or session policy. Not limited by the identity policy.
   - **Wildcard principal plus an `aws:PrincipalArn` condition**: boundaries and session policies do **not** limit it unless an identity-based policy contains an explicit deny.
   - **Account principal** (`arn:aws:iam::ID:root` or `"ID"`): delegates to the account. It "does not limit permissions to only the root user", and identity policies must still allow [S5].
   - The session-policy page states the role-ARN case as a formula: session permissions = (session ∩ RBP) ∪ (session ∩ identity) [S6].
4. **Explicit allow required in the resource policy.** "IAM role trust policies and KMS key policies are exceptions… they must explicitly allow access for principals." Other services "may also require" it [S1].
5. **Cross-account.** "AWS performs two evaluations… The request is allowed only if both evaluations return Allow." The trusted (principal) account evaluates identity plus its limiters (boundary, session, SCP). The trusting (resource) account evaluates the resource policy plus its limiters (RCP) [S3]. ACLs "cannot grant permissions to entities within the same account" [S6].
6. **SCPs** [S4, S4a, S4b]:
   - An explicit `Allow` must exist "at every level from the root through each OU in the direct path to the account (including the target account itself)". A deny at any level wins.
   - SCPs do not affect users or roles in the management account. They do apply to delegated-admin member accounts and to member-account root users.
   - SCPs do not affect any service-linked role.
   - They "don't affect users or roles from accounts outside the organization": an external principal using your bucket is not subject to your SCPs.
   - Full IAM language support (Sept 2025): Allow with `Condition`, resource ARNs, `NotAction` and `NotResource`, and wildcards anywhere in actions. `Principal` and `NotPrincipal` are unsupported.
7. **RCPs** [S5a, S5b]:
   - They apply to resources in member accounts for the listed services only (62 prefixes on 2026-10-08, §10.3).
   - They apply "regardless of whether the principals belong to the same organizations or not", including root users.
   - They do not apply to service-linked-role callers, to management-account resources, to AWS-managed KMS keys, or to `kms:RetireGrant`.
   - Customer RCPs are Deny-only and must use `"Principal": "*"`. `NotPrincipal` and `NotAction` are unsupported. `"*"` alone as an Action is not allowed.
   - The RCP that applies is the one belonging to the account that owns the resource listed in the action's "Resource type" column.
8. **NotPrincipal** [S7]:
   - Deny only. It is not allowed in identity or trust policies, SCPs or RCPs.
   - "Will always deny any IAM principal that has a permissions boundary policy attached, regardless of the values specified."
   - You must list the account ARN as well, because "AWS might validate the account first, then the role, and then the assumed-role user".
9. **Conditions** [S8, S9]:
   - Missing key → no match → false. The exception is **negated** operators (`StringNotEquals`, `StringNotLike`, `ArnNotLike`, `NotIpAddress`…), which evaluate **true** when the key is missing.
   - `…IfExists` → true when the key is missing.
   - `Null:true` means absent.
   - `ForAllValues` → **true when the key is missing or empty**. `ForAnyValue` → false when the key is missing.
   - Multiple keys in one operator, and multiple operators, combine with AND. Multiple values for one key combine with OR.
   - `ArnLike`/`ArnEquals` are identical: case-sensitive and matched per segment across the six colon-delimited components.
   - `StringLike` supports `*`/`?`. Numeric, Date, Bool (via variables only), Binary, IP and Null do not support wildcards. Policy variables are allowed only in String and ARN operators, and in the resource part of `Resource` (after the fifth colon).
10. **Policy variables** [S10]:
   - Key names are case-insensitive.
   - Only single-valued keys can be used.
   - Missing value → "effectively null": positive operators do not match, negated operators match, and a `Resource`/`NotResource` entry containing it matches nothing.
   - Defaults are written `${key, 'default'}`. Escapes are `${*}`, `${?}`, `${$}`.
   - Variables are literal text unless `Version` is `2012-10-17`.
11. **Resource wildcards** [S11]:
   - `*`/`?` work within ARN segments.
   - "If the `*` wildcard is the last character of a resource ARN segment, it can expand to match beyond the colon boundaries."
   - `*` crosses `/` freely. No wildcard is allowed in the service segment.
   - User names in `Resource` and `Principal` are case-sensitive.
   - Partial-ARN wildcards are not allowed in `Principal` [S5].
12. **Actions** are case-insensitive [S4b]. SCP `Action`/`NotAction` "are case-insensitive".
13. **NotAction/NotResource** match everything not listed, including actions and services that do not exist yet. `Resource` still scopes which actions are applicable [S12].
14. **KMS** [S13–S15]:
   - The key policy is required. The account-principal statement "allows the account to use IAM policies… Without this permission, IAM policies that allow access to the key are ineffective, although IAM policies that deny access to the key are still effective."
   - Grants only allow and never deny. They can have a cross-account grantee. Constraints are EncryptionContextEquals/Subset and SourceArn. Grants are eventually consistent, typically seconds and sometimes up to about 5 minutes.
   - External users "cannot use the KMS key until you attach IAM policies that delegate those permissions, **or use grants**".
   - Cross-account use works only for the cryptographic operations, CreateGrant, DescribeKey, GetKeyRotationStatus, GetPublicKey, ListGrants, RetireGrant and RevokeGrant.
15. **S3** [S16, S17]:
   - Authorization runs in three contexts: user, bucket and object. The bucket owner's explicit deny applies even to objects it does not own.
   - With Object Ownership `BucketOwnerEnforced`, ACLs are disabled.
   - Block Public Access has four settings plus org-level policies. The most restrictive setting wins.
   - `IgnorePublicAcls` ignores public ACLs at evaluation time. `BlockPublicAcls` and `BlockPublicPolicy` only affect PUTs.
   - `RestrictPublicBuckets` restricts a bucket with a **public** policy "to only AWS service principals and authorized users within the bucket owner's account". That also blocks non-public cross-account statements in the same policy.
   - "Public" means that some Allow statement is not limited to fixed values of a principal, `aws:SourceIp` (no broader than /8 for IPv4, /32 for IPv6, excluding RFC 1918 ranges), `aws:SourceArn`, `aws:SourceVpc`, `aws:SourceVpce`, `aws:SourceOwner`, `aws:SourceAccount`, `aws:userid` (except the `AROLEID:*` pattern), `aws:PrincipalOrgID`, `s3:DataAccessPointArn` or `s3:DataAccessPointAccount`.
16. **Root user.** No identity policies or boundary can apply to it. It is subject to SCPs and RCPs in member accounts [S6].
17. **Roles.** A role ARN in a trust policy is stored as its unique principal ID, so deleting and recreating the role breaks the trust. `aws:PrincipalArn` conditions are **not** converted to IDs [S5]. Role chaining caps the session at 1 h [S18].

### 4.2 How the knowledge doc's §4.5 pseudocode is wrong or incomplete

| # | knowledge doc 03 §4.5 says | Correction |
|---|---|---|
| K1 | "SCPs: at EVERY level of the principal account's OU chain… else DENY" applies to all requests. | It applies only when the principal is an IAM user, role or root **in a member account** and is not a service-linked role. External principals and management-account principals skip SCPs. |
| K2 | Step 5 "Resource-based policy… can produce ALLOW" before identity policies, with no account caveat. | A same-account grant to the **account principal** produces no direct allow: it delegates. A same-account grant to a **role ARN** is still capped by the boundary and session policy. |
| K3 | Cross-account: "the identity policy plus its limiters". | Correct. Add that the **resource account's RCPs** apply even to external principals, and the **resource account's SCPs do not**. |
| K4 | Not mentioned. | NotPrincipal plus Deny always denies principals that have a boundary. |
| K5 | Not mentioned. | `ForAllValues` with a missing key is true. Negated operators with a missing key are true. Both are among the most common causes of over-grant. |
| K6 | "SCPs still don't apply to the management account or to service-linked roles." | Also: RCPs don't apply to management-account **resources**, to SLR callers, to AWS-managed KMS keys, or to `kms:RetireGrant`. |

### 4.3 Ambiguity register

Each entry gives the doc conflict, our default (chosen under D3), and the live probe that settles it (§13.5). A decision whose outcome depends on an unsettled entry is flagged `AMBIGUITY:<id>`.

| ID | Ambiguity | Default | Probe |
|---|---|---|---|
| **A1** | Resource wildcard: "trailing `*` in a segment can expand beyond the colon boundaries". Which segments, and does a non-trailing `*` ever cross a colon? | Segments 1–5 (`arn`, partition, service, region, account) are matched one by one. The 6th segment is the **rest of the string, colons included**, matched as one glob. A `*` that is the **last character of segments 3–5** matches the remainder of the ARN (for example `arn:aws:s3:*` matches every S3 ARN). A non-trailing `*` never crosses a colon. | Policies with `arn:aws:sqs:us-east-1:*`, `arn:aws:sqs:*:queue`, `arn:aws:logs:*:*:log-group:a*` against resources whose names contain colons. |
| **A2** | The SCP syntax page's table allows `Resource`/`NotResource`/`Condition` with Allow, but its prose says Allow may only use `"*"` in Resource. | Follow the Sept 2025 announcement: full language. | SCP Allow scoped to one bucket ARN; access to another bucket. |
| **A3** | Same-account **trust policy naming a specific user or role ARN**: does the caller also need `sts:AssumeRole` in its identity policy? The docs state the explicit-allow requirement and the general same-account union rule, but never this case. | No identity allow needed, applying the same matrix as other resource policies. A role-ARN caller is still capped by its boundary and session policy. | User with no identity policies assumes a role whose trust names the user's ARN. |
| **A4** | NotPrincipal layering for sessions: must you list the account, the role **and** the session ARN, or are the account and role enough? | Exempt only if the account ARN **and** (role ARN **or** session ARN) are listed. Users: account ARN and user ARN. Otherwise the Deny applies. | Three bucket policies (account+role; account+session; role+session) × an assumed-role caller. |
| **A5** | `ForAnyValue:` combined with a **negated** operator and a missing key. The general rule makes negated-plus-missing true; the set-operator page makes ForAnyValue-plus-missing false. | **false** (the set-operator rule is more specific). | Allow with `ForAnyValue:StringNotEquals aws:TagKeys` and no tags in the request. |
| **A6** | Unresolved policy variable: "might cause the entire statement to be invalid", versus "inverted operators… do match against a null value". | Per-occurrence semantics, not statement drop. Positive operator: false. Negated: true. Resource entry: no match. | Deny with `StringNotEquals s3:ExistingObjectTag/Team: ${aws:PrincipalTag/Team}` and an untagged caller (the docs' own example, which says denied). |
| **A7** | A single-valued operator with no set qualifier used on a **multivalued** key. Behaviour is not documented ("require a set operator"). | Positive operators: true if **any** request value matches. Negated: true if **no** request value matches. Flag `APPROXIMATE`. | `StringEquals aws:TagKeys` with two tags. |
| **A8** | A set qualifier on a single-valued key ("can lead to overly permissive policies"). | Treat the value as a one-element set. A missing key follows the set-operator rule. | `ForAllValues:StringEquals aws:PrincipalTag/team` with an untagged principal. |
| **A9** | Wildcard `Principal: "*"` **without** an `aws:PrincipalArn` condition in a same-account policy. Is it limited by the boundary or session policy? The docs say "no other permissions are required" and describe the PrincipalArn exception, but never this plain case. | Treated as a direct grant to the requester (not limited by an implicit deny). | Role with a boundary that excludes S3; bucket policy `Principal:"*"` allows GetObject. |
| **A10** | Services other than IAM and KMS that "may also require an explicit Allow" in their resource policy for the same account. | Per-service table (§7.4.3), initially empty apart from IAM and KMS. Unknown services use the union rule and are flagged. | For each RBP service in the sandbox: identity allow only, no RBP statement. |
| **A11** | The session-policy branch of the deny/allow page is garbled ("checks whether the principal is a role session… Otherwise… Deny"). | A role session with no session policy: no limit. A federated-user session always has a session policy (GetFederationToken requires one). | GetFederationToken with a narrow policy; an action outside it. |
| **A12** | KMS **grant** to a cross-account grantee: is an IAM allow needed in the grantee's account? The docs say "IAM policies… **or** use grants". | No: the grant suffices on both sides. SCPs, RCPs and explicit denies still apply. | Grant to a role in account B; the role has no KMS identity permission. |
| **A12b** | Is a same-account KMS grant to a **role ARN** capped by the role's boundary? | Yes, with the same matrix as a role-ARN RBP grant. Over-approximation would say no, but the matrix rule is more specific. Flag until probed. | Role with a boundary excluding `kms:*`, plus a grant on Decrypt. |
| **A13** | Access-point delegation versus double evaluation. | Both the access-point policy and the bucket policy (or its delegation to access points) must allow. | Sandbox access point with and without delegation. |
| **A14** | Do RCP statements naming services outside the supported list get rejected at attach time, or silently ignored? | Silently ignored for evaluation. | Attach `Deny lambda:InvokeFunction` as an RCP. |
| **A15** | Does the simulator apply SCPs to management-account principals and to service-linked roles the way live enforcement does? | Trust live probes over the simulator for these strata. | Simulator versus probe on the management account and an SLR. |
| **A16** | Org-level S3 BPA in "all or none" mode versus account-level partial settings. | The most restrictive of org, account, bucket and access point. | Toggling in the sandbox (management account only). |
| **A17** | IP conditions: `aws:SourceIp` is absent behind a VPC endpoint, so an allow conditioned on `IpAddress` fails, while a deny with `NotIpAddress` **applies** (negated plus missing). | As stated; this is documented, but probe because it is a frequent incident cause. | Request through a VPCE against both policies. |

### 4.4 Knowledge-base corrections to make in the same PR series
- Fix `03-authorization-and-policy.md` §4.5 with K1–K6.
- Update the RCP service list. The doc says "a third-party vendor counts 44"; the official list had **62 prefixes** on 2026-10-08, including `s3`, `sts`, `kms`, `sqs`, `secretsmanager`, `dynamodb`, `logs`, `cognito-idp`, `ecr`, `events` and `codebuild`. Lambda and SNS are still absent.
- Add the new simulator capabilities and limits from §13.2. The simulator now takes ordered SCP levels (`OrderedOrganizationPolicyInputList`), a `PolicyExclusionList`, and returns per-action aggregation.
- Fix the Stratified Abstraction citation: it is Backes et al., CAV 2020. "Block Public Access" is Bouchet et al., ESEC/FSE 2020.

---

## 5. Architecture

```
            ┌───────────────────────── tessera/aws/ ─────────────────────────────┐
 connector  │  ingest/        model.py          catalog/            eval/          │
 (read-only)│  aws_org.py ──► Snapshot (frozen) ◄── Catalog(v=2026-10-08) ──► engine.py│
  AWS APIs ─┼► aws_iam.py      PolicyDoc/Stmt     servicereference                 │ │
            │  aws_res.py      Principal/OrgNode  + iam-dataset                    ▼ │
            │                  TrustEdge/Grant                     match.py  cond.py│
            │                                                     (action/res/princ)│
            │  index/ (atoms, inverted idx) ◄────────────────────── explain.py      │
            │  query.py  : can(), effective_permissions(), who_can(), diff()       │
            └──────────────┬──────────────────────────┬──────────────────────────────┘
                           │ EvaluatedGrant rows       │ Decision + Explanation
                           ▼                           ▼
             tessera/graph.py (GraphSnapshot)     api/app.py  /api/aws/*
             simulate.py / leastpriv.py / nhi.py   PR comment renderer
                           ▲
 harness/  (separate package `tessera_harness/`, never imported by the server)
   sampler ─► request gen ─► oracle router ─► {SimCustom, SimPrincipal, Probe, AA}
          └──────────────► engine ──────────► comparator ─► triage DB ─► metrics/CI
```

Design rules:
- **Purity.** `eval/` functions take `(Snapshot, Catalog, EvaluationRequest)` and return `Decision`. They do no I/O and read no clock (time arrives in the request context). This makes caching, replay and differential testing trivial.
- **Determinism.** Iteration orders are sorted. Explanations come out in a stable order, so traces can be diffed between versions.
- **Versioning.** Every `Decision` records `engine_version`, `catalog_version` and `snapshot_id` (a content hash). This meets design rule 2 in the README ("every decision records the policy version it used").
- **Platform-neutral core.** `Decision`, `ExplanationStep`, `Tri` and `Residual` live in `tessera/authz/core.py`, so the Azure and GCP evaluators (Phase 3) can reuse them.

---

## 6. Data model

There are two layers:
- **(a) Frozen in-memory dataclasses** that the engine evaluates over (`tessera/aws/model.py`).
- **(b) SQLAlchemy tables** that persist raw native documents and computed results (`tessera/models_aws.py`). They are added next to `models.py`, which is not modified.

Raw policy JSON is always stored verbatim alongside its normalized form, so the evidence is the exact bytes AWS holds.

### 6.1 Engine dataclasses

```python
# tessera/authz/core.py  (platform-neutral)
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Union

class Outcome(str, Enum):
    ALLOW = "allow"; DENY = "deny"; CONDITIONAL = "conditional"

class DenyKind(str, Enum):
    EXPLICIT = "explicit"            # a Deny statement matched
    IMPLICIT = "implicit"            # nothing allowed, or a required layer had no Allow
    GUARDRAIL = "guardrail"          # non-policy control: S3 BPA, KMS cross-account op allowlist

class Fidelity(str, Enum):
    EXACT = "exact"; APPROXIMATE = "approximate"; UNSUPPORTED = "unsupported"

@dataclass(frozen=True)
class FidelityReason:
    code: str                        # e.g. "AMBIGUITY:A3", "VPCE_POLICY_UNKNOWN"
    detail: str
    outcome_sensitive: bool          # True if flipping this assumption could flip the decision

# Residual predicates (three-valued logic, §9.4)
@dataclass(frozen=True)
class Atom:                          # one (operator, key, values) test, after variable substitution
    op: str                          # canonical operator, e.g. "StringLike", "IpAddress", "Null"
    key: str                         # lower-cased context key, e.g. "aws:sourceip"
    values: tuple[str, ...]
    qualifier: Literal["", "ForAllValues", "ForAnyValue"] = ""
    if_exists: bool = False
    negated: bool = False            # derived from the operator family; kept explicit for rendering
    source: "StmtRef | None" = None  # which statement contributed it

@dataclass(frozen=True)
class And: terms: tuple["Residual", ...]
@dataclass(frozen=True)
class Or:  terms: tuple["Residual", ...]
@dataclass(frozen=True)
class Not: term: "Residual"
Residual = Union[bool, And, Or, Not, Atom]
```

```python
# tessera/aws/model.py
PrincipalKind = Literal[
    "iam_user", "iam_role",                 # entities (a role never makes a request itself)
    "role_session",                         # AssumeRole / WebIdentity / SAML / EC2 / Identity Center sessions
    "federated_user_session",               # GetFederationToken
    "root",                                 # account root user (including AssumeRoot sessions)
    "service",                              # service principal, e.g. "s3.amazonaws.com"
    "anonymous",
]

@dataclass(frozen=True)
class Principal:
    arn: str                                 # requester ARN (the session ARN for sessions)
    kind: PrincipalKind
    account_id: str | None                   # None for service and anonymous
    entity_arn: str | None                   # role ARN for role sessions; the IAM user's ARN for federated sessions
    unique_id: str | None                    # AIDA…/AROA…, for trust-policy principal-ID matching
    path: str = "/"
    is_service_linked: bool = False          # role path /aws-service-role/
    tags: dict[str, str] = field(default_factory=dict)          # entity tags
    session_tags: dict[str, str] = field(default_factory=dict)  # override entity tags with the same key
    transitive_tag_keys: frozenset[str] = frozenset()
    session_policy_ids: tuple[str, ...] = ()                    # PolicyDoc ids (inline + PolicyArns)
    source_identity: str | None = None
    group_arns: tuple[str, ...] = ()                            # users only
    boundary_policy_id: str | None = None
    identity_policy_ids: tuple[str, ...] = ()                   # resolved attachments (user + groups, or role)
    federated_provider: str | None = None                       # OIDC/SAML provider ARN
    chain: tuple[str, ...] = ()                                 # role-chain ARNs, oldest first

class PolicyKind(str, Enum):
    IDENTITY = "identity"; BOUNDARY = "boundary"; SESSION = "session"
    SCP = "scp"; RCP = "rcp"; RESOURCE = "resource"; TRUST = "trust"; KMS_KEY = "kms_key_policy"
    VPCE = "vpc_endpoint"; S3_ACCESS_POINT = "s3_access_point"; RAM = "ram_synthetic"

@dataclass(frozen=True)
class PolicyDoc:
    id: str                                  # stable: sha256(kind | source_arn | version_id | raw bytes)
    kind: PolicyKind
    source_arn: str                          # policy ARN, "<resource-arn>#policy" or "<role-arn>#trust"
    version_id: str | None                   # managed-policy default version, or SCP/RCP content hash
    language_version: Literal["2012-10-17", "2008-10-17"] | None   # anything but 2012-10-17 → variables are literal
    raw_json: str                            # verbatim bytes as fetched
    statements: tuple["Statement", ...]
    aws_managed: bool = False
    fetched_at: str = ""                     # ISO 8601, for staleness

@dataclass(frozen=True)
class Statement:
    policy_id: str
    index: int                               # 0-based position in the Statement array
    sid: str | None
    effect: Literal["Allow", "Deny"]
    actions: "PatternSet | None"             # exactly one of actions / not_actions (validated at parse)
    not_actions: "PatternSet | None"
    resources: "PatternSet | None"           # both None in a resource policy ⇒ implied "this resource"
    not_resources: "PatternSet | None"
    principals: "PrincipalSet | None"        # resource policies only
    not_principals: "PrincipalSet | None"
    condition: tuple[Atom, ...]              # conjunction; variables still unresolved (resolved per request)
    span: tuple[int, int, int, int] | None   # (start_line, start_col, end_line, end_col) in raw_json

@dataclass(frozen=True)
class PolicyAttachment:
    policy_id: str
    target_arn: str                          # user / group / role / OU / account / root / resource
    via: tuple[str, ...]                     # provenance path, e.g. ("user/alice", "group/eng")
    attachment_type: Literal["inline", "managed", "boundary", "scp", "rcp", "resource", "session", "trust"]

@dataclass(frozen=True)
class OrgNode:
    id: str                                  # r-xxxx / ou-xxxx / 123456789012
    kind: Literal["root", "ou", "account"]
    parent_id: str | None
    name: str
    scp_ids: tuple[str, ...]                 # SCPs attached at THIS level
    rcp_ids: tuple[str, ...]                 # RCPs attached at THIS level

@dataclass(frozen=True)
class Organization:
    org_id: str
    management_account_id: str
    nodes: dict[str, OrgNode]
    scp_enabled: bool
    rcp_enabled: bool
    def path_to(self, account_id: str) -> tuple[OrgNode, ...]: ...   # root → … → account

@dataclass(frozen=True)
class Boundary:                               # convenience view; a boundary is a PolicyDoc plus an attachment
    entity_arn: str
    policy_id: str

@dataclass(frozen=True)
class ResourcePolicy:
    resource_arn: str
    kind: PolicyKind                         # RESOURCE / TRUST / KMS_KEY / S3_ACCESS_POINT / VPCE
    policy_id: str
    requires_explicit_allow: bool            # trust policies, KMS key policies, and the §7.4.3 table

@dataclass(frozen=True)
class KmsGrant:
    key_arn: str; grant_id: str
    grantee_principal: str | None; grantee_service_principal: str | None
    operations: frozenset[str]               # "Decrypt", "GenerateDataKey", ...
    constraints_ec_equals: dict[str, str] | None
    constraints_ec_subset: dict[str, str] | None
    constraint_source_arn: str | None
    retiring_principal: str | None
    created_at: str

@dataclass(frozen=True)
class S3BucketState:
    bucket_arn: str; owner_account: str
    object_ownership: Literal["BucketOwnerEnforced", "BucketOwnerPreferred", "ObjectWriter"]
    bucket_acl: tuple["AclGrant", ...]
    bpa_bucket: "Bpa"; bpa_account: "Bpa"; bpa_org: bool | None     # org level is all-or-none
    policy_is_public: bool                   # computed per §7.6.2

@dataclass(frozen=True)
class TrustEdge:                              # materialized "who can become role R" (§11.4)
    from_principal_arn: str                  # user / role / provider / service / account root
    to_role_arn: str
    mechanism: Literal["AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML", "service", "PassRole"]
    decision: Outcome                        # ALLOW or CONDITIONAL
    residual: Residual                       # e.g. sts:ExternalId == "x", or token sub like "repo:org/*"
    explanation_id: str

@dataclass(frozen=True)
class Snapshot:
    id: str                                  # content hash
    taken_at: str
    org: Organization | None
    principals: dict[str, Principal]         # entities plus synthetic session templates
    policies: dict[str, PolicyDoc]
    attachments: tuple[PolicyAttachment, ...]
    resource_policies: dict[str, tuple[ResourcePolicy, ...]]   # by resource ARN
    kms_grants: dict[str, tuple[KmsGrant, ...]]
    s3: dict[str, S3BucketState]
    resources: dict[str, "Resource"]         # arn → type, account, region, tags
    vpce_policies: dict[str, str]            # VPC endpoint id → PolicyDoc id
    canonical_ids: dict[str, str]            # S3 canonical user id → account id
```

```python
# tessera/aws/eval/request.py
@dataclass(frozen=True)
class ContextValue:
    state: Literal["present", "absent", "unknown"]   # unknown ⇒ symbolic (§9.4)
    values: tuple[str, ...] = ()
    type: Literal["String", "ARN", "Numeric", "Date", "Bool", "IP", "Binary"] = "String"
    multivalued: bool = False

@dataclass(frozen=True)
class EvaluationRequest:
    principal_arn: str                        # requester (the session ARN for sessions)
    action: str                               # "s3:GetObject"
    resource_arn: str | None                  # None or "*" for actions with no resource-level support
    context: dict[str, ContextValue]          # keys lower-cased
    mode: Literal["concrete", "symbolic"] = "concrete"
    session: "SessionSpec | None" = None      # hypothetical sessions: session policies, tags, source identity
    via_vpce: str | None = None
    s3_object_owner: str | None = None        # when the object owner differs from the bucket owner
    assume: "AssumeSpec | None" = None        # sts:AssumeRole* requests: target role, ExternalId, token claims
```

```python
# tessera/authz/core.py (continued)
@dataclass(frozen=True)
class StmtRef:
    policy_id: str; policy_kind: str; source_arn: str; version_id: str | None
    statement_index: int; sid: str | None; span: tuple[int, int, int, int] | None
    attachment_path: tuple[str, ...]          # e.g. ("role/Ci", "managed:arn:aws:iam::aws:policy/ReadOnlyAccess")
    org_level: str | None = None              # "r-abcd" | "ou-…" | account id, for SCPs and RCPs

@dataclass(frozen=True)
class CondTrace:
    atom: Atom
    request_state: Literal["present", "absent", "unknown"]
    request_values: tuple[str, ...]
    result: Literal["true", "false", "unknown"]

@dataclass(frozen=True)
class ExplanationStep:
    stage: Literal["parse", "context", "explicit_deny", "rcp", "scp", "resource_policy",
                   "identity", "boundary", "session", "kms_grant", "s3_acl", "s3_bpa",
                   "vpce", "cross_account", "special_rule", "final"]
    result: Literal["allow", "deny", "no_match", "not_applicable", "pass", "fail", "conditional"]
    statement: StmtRef | None                 # None for stage summaries
    matched_on: dict[str, str]                # {"action": "s3:Get*", "resource": "arn:…/*", "principal": "PARENT"}
    condition_trace: tuple[CondTrace, ...]
    residual: Residual | None
    note: str                                 # human sentence, generated from a template, never free text
    decisive: bool                            # part of the minimal justification set

@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    deny_kind: DenyKind | None
    residual: Residual                        # True for ALLOW, False for DENY, a formula for CONDITIONAL
    fidelity: Fidelity
    fidelity_reasons: tuple[FidelityReason, ...]
    steps: tuple[ExplanationStep, ...]
    decisive: tuple[StmtRef, ...]             # minimal set of statements that justify the outcome
    request: "EvaluationRequest"
    engine_version: str; catalog_version: str; snapshot_id: str
    def aws_eval_decision(self) -> Literal["allowed", "explicitDeny", "implicitDeny"] | None: ...
```

### 6.2 Persistence (SQLAlchemy sketch, new file `tessera/models_aws.py`)

```python
class AwsSnapshot(Base):
    __tablename__ = "aws_snapshots"
    id: Mapped[str] = mapped_column(String, primary_key=True)           # content hash
    taken_at: Mapped[datetime]; org_id: Mapped[str | None]
    account_ids: Mapped[list] = mapped_column(JSON)
    catalog_version: Mapped[str]
    source: Mapped[str]                                                 # connector | pr-sim | harness

class AwsPolicyDocument(Base):            # immutable, content-addressed
    __tablename__ = "aws_policy_documents"
    id: Mapped[str] = mapped_column(String, primary_key=True)           # PolicyDoc.id
    kind: Mapped[str]; source_arn: Mapped[str] = mapped_column(index=True)
    version_id: Mapped[str | None]; raw_json: Mapped[str] = mapped_column(Text)
    normalized: Mapped[dict] = mapped_column(JSON); fetched_at: Mapped[datetime]

class AwsPolicyAttachment(Base):
    __tablename__ = "aws_policy_attachments"
    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("aws_snapshots.id"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("aws_policy_documents.id"))
    target_arn: Mapped[str] = mapped_column(index=True)
    attachment_type: Mapped[str]; via: Mapped[list] = mapped_column(JSON)

class AwsOrgNode(Base):
    __tablename__ = "aws_org_nodes"
    snapshot_id: Mapped[str] = mapped_column(primary_key=True)
    id: Mapped[str] = mapped_column(primary_key=True)
    kind: Mapped[str]; parent_id: Mapped[str | None]; name: Mapped[str]

class AwsTrustEdge(Base):
    __tablename__ = "aws_trust_edges"
    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(index=True)
    from_arn: Mapped[str] = mapped_column(index=True); to_role_arn: Mapped[str] = mapped_column(index=True)
    mechanism: Mapped[str]; outcome: Mapped[str]
    residual: Mapped[dict] = mapped_column(JSON); explanation_id: Mapped[str]

class AwsEffectivePermission(Base):       # materialized, scope-compressed (§12.4)
    __tablename__ = "aws_effective_permissions"
    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(index=True)
    principal_arn: Mapped[str] = mapped_column(index=True)
    action_atom: Mapped[int] = mapped_column(index=True)
    resource_atom: Mapped[int] = mapped_column(index=True)              # atom ids (§12.2)
    outcome: Mapped[str]; residual: Mapped[dict | None] = mapped_column(JSON)
    fidelity: Mapped[str]; explanation_id: Mapped[str]
    engine_version: Mapped[str]; catalog_version: Mapped[str]

class AwsExplanation(Base):               # content-addressed, deduplicated traces
    __tablename__ = "aws_explanations"
    id: Mapped[str] = mapped_column(String, primary_key=True)          # sha256 of the canonical trace
    trace: Mapped[dict] = mapped_column(JSON)
```

The tables are snapshot-scoped and append-only. Old snapshots are kept for the evidence-retention period (Q8), which lets an auditor ask "why could X do Y on date D?" and get the same answer every time.

---

## 7. The evaluation algorithm

### 7.1 Notation and three-valued primitives

`Tri` values are `T`, `F`, or `U(φ)`, where φ is a residual. The operations are Kleene logic that also builds the formula:
`T ∧ x = x`, `F ∧ x = F`, `U(φ) ∧ U(ψ) = U(φ∧ψ)`; `T ∨ x = T`, `F ∨ x = x`, `U(φ) ∨ U(ψ) = U(φ∨ψ)`; `¬T = F`, `¬U(φ) = U(¬φ)`.
`any(stmts)` is the `∨` of the statements' match values. `all(levels)` is the `∧`. In `concrete` mode no `U` ever occurs (§9.4).

`stmt_match(s, req, ctx)` returns a `Tri`. It is the `∧` of:
1. `action_match(s)`: §8.2
2. `resource_match(s)`: §8.3
3. `principal_match(s)`: resource-policy kinds only; §8.4. It also returns how the principal matched: `SELF`, `PARENT`, `ACCOUNT`, `WILDCARD`, `WILDCARD_PRINCIPALARN` or `SERVICE`.
4. `cond(s)`: §9

If one statement matches the principal in several ways, `principal_match` keeps the most direct kind, in this order: `SELF` > `WILDCARD_PRINCIPALARN` > `WILDCARD` > `PARENT` > `ACCOUNT`.

### 7.2 Top-level algorithm (the order of checks)

```text
function EVALUATE(req, snap, cat) -> Decision:
    T := new Trace(); F := new FidelityAccumulator()

    # ---- 0. Normalize -----------------------------------------------------------------
    a   := cat.canonical_action(req.action)                # case-folds; verifies prefix and name
    if a is None: F.add("CATALOG_MISS", outcome_sensitive=True); a := lower(req.action)
    P   := resolve_principal(req.principal_arn, req.session, snap)          # §7.3
    R   := resolve_resource(req.resource_arn, a, snap, cat)                 # type, owner account, region, tags
    ctx := build_context(req, P, R, snap, cat)                             # §9.1
    root_default_allow := (P.kind == "root" and P.account_id == R.account_id)

    # ---- 1. Collect the applicable policy sets ----------------------------------------
    ID   := identity_statements(P, snap)          # [] for root, service, anonymous
    PB   := boundary_statements(P, snap)          # None if no boundary
    SP   := session_statements(P, req, snap)      # None if not a session or no session policy
    SCPL := scp_levels(P, snap)                   # None if not applicable (§7.5); else list of levels
    RCPL := rcp_levels(a, R, P, snap, cat)        # None if not applicable (§7.5)
    RBP  := resource_statements(R, a, snap)       # bucket / queue / key / trust ... (+ access point, §3.2)
    VPCE := vpce_statements(req, snap, F)         # None if no endpoint; flagged if the endpoint is unknown
    cross := is_cross_account(P, R)               # §7.7

    # ---- 2. Explicit deny across EVERY policy type ---------------------------------------
    D := F
    for s in Deny statements of (ID ∪ PB ∪ SP ∪ flatten(SCPL) ∪ flatten(RCPL) ∪ RBP ∪ VPCE):
        m := stmt_match(s, req, ctx)              # the NotPrincipal rule (§8.4.3) lives here
        T.record("explicit_deny", s, m)
        D := D ∨ m
    if D == T: return finish(DENY, EXPLICIT, T, F)

    # ---- 3. Organization gates: a conjunction over org levels, each needing an Allow ---------
    RCP_OK := T if RCPL is None else ∧_{lvl ∈ RCPL} any(Allow stmts at lvl match)
    SCP_OK := T if SCPL is None else ∧_{lvl ∈ SCPL} any(Allow stmts at lvl match)
    T.record("rcp", RCP_OK, per_level=True); T.record("scp", SCP_OK, per_level=True)

    # ---- 4. Grant paths ------------------------------------------------------------------
    ID_ALLOW := any(Allow stmts in ID match)
    PB_OK    := T if PB is None else any(Allow stmts in PB match)
    SP_OK    := session_gate(P, SP)                                  # §7.4.2
    RB       := classify_rbp_allows(RBP, req, ctx)                   # match kind → Tri (∨ within a kind)
    SPECIAL  := special_resource_grants(a, R, P, req, ctx, snap)     # KMS grants, S3 ACLs (§7.6)

    if   P.kind == "service":    GRANT := RB[SERVICE] ∨ RB[WILDCARD]                        # §7.8
    elif P.kind == "anonymous":  GRANT := RB[WILDCARD] ∨ SPECIAL.acl_public                 # §7.8
    elif not cross:              GRANT := same_account_grant(P, R, ID_ALLOW, PB_OK, SP_OK, RB, SPECIAL)   # §7.4
    else:                        GRANT := cross_account_grant(P, R, ID_ALLOW, PB_OK, SP_OK, RB, SPECIAL)  # §7.7
    if root_default_allow and not R.requires_explicit_rbp_allow: GRANT := T                 # §7.4 note

    # ---- 5. Non-policy guardrails ------------------------------------------------------------
    G := s3_bpa_gate(a, R, P, RBP, snap)              # §7.6.2; T unless an S3 setting blocks
       ∧ kms_cross_account_op_gate(a, R, P)           # §7.6.1
       ∧ vpce_gate(VPCE)                              # any(Allow) when the endpoint policy is known, else T (flagged)

    # ---- 6. Combine ------------------------------------------------------------------------
    A := GRANT ∧ RCP_OK ∧ SCP_OK ∧ G ∧ ¬D               # D can still be U(φ) in symbolic mode
    A := simplify(A, ctx, cat)                          # §9.5: unsatisfiable ⇒ F, valid ⇒ T
    if A == T: return finish(ALLOW, None, T, F)
    if A == F: return finish(DENY, deny_kind(T), T, F)      # §7.10 chooses IMPLICIT or GUARDRAIL
    return finish(CONDITIONAL, None, T, F, residual=A.φ)
```

The order of checks is **observably** AWS's: explicit deny, then the RCP and SCP gates, then the grant paths, then the boundary and session limits. By default the engine still evaluates every stage after a decisive one, so the trace can say "this would also have failed at the SCP" for explanation and triage. `fast=True` stops at the first decisive outcome and is used for bulk enumeration (§12).

### 7.3 Resolving the principal

```text
resolve_principal(arn, session_spec, snap):
  arn:aws:iam::A:user/path/name            → iam_user (entity_arn = arn; groups resolved)
  arn:aws:iam::A:root                      → root
  arn:aws:sts::A:assumed-role/Role/Sess    → role_session (entity_arn = the role ARN, path taken from the snapshot;
                                              is_service_linked if the role path starts with /aws-service-role/)
  arn:aws:sts::A:federated-user/Name       → federated_user_session (entity_arn = the IAM user that called
                                              GetFederationToken; a session policy is required, A11)
  "<svc>.amazonaws.com"                    → service
  "*" / "anonymous"                        → anonymous
  arn:aws:iam::A:role/R (an entity, not a requester)
       → synthesize the session template "arn:aws:sts::A:assumed-role/R/*" with no session policy
         unless session_spec says otherwise. Every role-level answer is the answer for a session
         that has no session policy.
Tags: principal tags = entity tags overlaid by session tags (session wins on a key collision), plus transitive
      tags inherited along the chain.
```

### 7.4 Same-account grants (the principal-type matrix)

```text
same_account_grant(P, R, ID_ALLOW, PB_OK, SP_OK, RB, SPECIAL):
    # Identity path: identity ∧ boundary ∧ session
    IDP := ID_ALLOW ∧ PB_OK ∧ SP_OK

    # Direct grants to the requester itself: NOT limited by an implicit deny in identity, boundary or session
    DIRECT := RB[SELF] ∨ RB[WILDCARD_PRINCIPALARN] ∨ RB[WILDCARD]          # WILDCARD per A9

    # Grants to the parent entity (role ARN for a role session; IAM user ARN for a federated session):
    # limited by the boundary and session policy, NOT by the identity policy
    PARENT := RB[PARENT] ∧ PB_OK ∧ SP_OK

    # Account-principal statements delegate. They enable the identity path but grant nothing alone.
    if R.requires_explicit_rbp_allow:                    # trust policies, KMS key policies, the §7.4.3 table
        IDP := IDP ∧ RB[ACCOUNT]
    # Otherwise the union rule holds: the identity path alone suffices and RB[ACCOUNT] adds nothing.

    KG := SPECIAL.kms_grant_self ∨ (SPECIAL.kms_grant_parent ∧ PB_OK ∧ SP_OK)          # A12b
    # S3 ACLs cannot grant within the same account (§4.1 fact 5), so they are not part of this union.
    return IDP ∨ DIRECT ∨ PARENT ∨ KG
```

**Notes on callers:**
- **IAM user.** `SELF` means a match on the user's ARN, and `SP_OK = T`.
- **Root.** Root has no identity policies, so the account's default allow is applied in step 4 (`root_default_allow`). In member accounts root is still subject to SCPs, RCPs and explicit denies. Trust policies and KMS key policies still gate root: `R.requires_explicit_rbp_allow` stops the default allow there, and root then needs an `ACCOUNT` or `SELF` match. The step is recorded as `special_rule`.

#### 7.4.1 Role trust policies (`sts:AssumeRole*`)

A request whose action is `sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity`, `sts:AssumeRoleWithSAML`, `sts:TagSession` or `sts:SetSourceIdentity` has the **target role** as its resource. Its resource policy is the role's trust policy, with `requires_explicit_allow = True`.

- **Same account.** The trust policy must allow. If it names the caller (`SELF` or `PARENT`), no identity policy is needed (A3, flagged until probed). If it names only the account, the identity policy must allow `sts:AssumeRole` on that role ARN.
- **Cross-account.** The trust policy must allow (any match kind), the caller's identity policy must allow, and so must the caller's boundary, session policy and SCPs. The RCPs of the role's account apply, because STS supports RCPs.
- **Web identity and SAML.** The caller is the identity provider: `Principal.Federated` must equal the provider ARN. Conditions are evaluated over token claims supplied as context (`token.actions.githubusercontent.com:sub`, `:aud`, `SAML:aud`…). In "can ever" mode they are `unknown`, so the result is `CONDITIONAL` with the claim predicate as its residual. No identity policy exists, so the trust policy alone decides, subject to RCPs.
- **Session tags and source identity.** Passing tags requires `sts:TagSession`; setting a source identity requires `sts:SetSourceIdentity`. Each is evaluated as its own request against the same trust policy. `aws:RequestTag/*` and `aws:TagKeys` apply.
- **Principal stored as an ID.** If the snapshot shows a trust principal as a bare `AROA…`/`AIDA…` because the role or user was deleted, it matches only the principal with that `unique_id`. A recreated principal with the same name does **not** match. The trace explains this.
- **Role chaining.** Each hop is its own evaluated edge (§11.4). A chained session's maximum duration is 1 h. That affects session lifetime, not authorization, so it is recorded as an annotation only.

#### 7.4.2 Session gate

```text
session_gate(P, SP):
   if P.kind not in {role_session, federated_user_session}: return T
   if P.kind == role_session and SP is None: return T            # no session policy was passed
   if P.kind == federated_user_session and SP is None: return F  # A11: should not exist; ingest anomaly
   return any(Allow stmts in SP match)
```

#### 7.4.3 Services whose resource policy must explicitly allow (same account)

This is a curated table, `catalog/aws/rbp_rules.yaml`. It starts with `iam` (trust policies) and `kms` (key policies); every other service uses the union rule. Each entry cites the doc page or probe that justifies it. Probes from A10 add entries. Decisions that depend on a service no probe has covered carry `SERVICE_RBP_RULE_UNVERIFIED`.

### 7.5 When SCPs and RCPs apply

```text
scp_levels(P, snap):
    if snap.org is None or not snap.org.scp_enabled:              return None
    if P.kind in {service, anonymous}:                            return None
    if P.account_id not in org accounts:                          return None   # external principal
    if P.account_id == snap.org.management_account_id:            return None   # management account exempt
    if P.is_service_linked:                                       return None   # SLR exempt
    return [SCP statements attached at node] for node in org.path_to(P.account_id)   # root → OUs → account

rcp_levels(a, R, P, snap, cat):
    if snap.org is None or not snap.org.rcp_enabled:              return None
    if R is None or R.account_id not in org accounts:             return None
    if R.account_id == snap.org.management_account_id:            return None
    if service_prefix(a) not in cat.rcp_supported_services:       return None   # §10.3
    if P.is_service_linked:                                       return None
    if a == "kms:retiregrant":                                    return None
    if R.type == "kms:key" and R.is_aws_managed_key:              return None
    return [RCP statements attached at node] for node in org.path_to(R.account_id)
```

An SCP or RCP level with no matching Allow makes its gate `F`. The trace names the **level** that blocked, by OU id and name, for example "blocked at OU Workloads/Prod (ou-ab12-…), whose SCPs allow only ec2:*". That is the explanation customers most often need, and AWS's own messages and simulator do not give it (the simulator hides SCP statements; §13.2).

### 7.6 Resource-specific rules

#### 7.6.1 KMS
- **Key policy.** It is the resource policy, with `requires_explicit_allow`. IAM policies count only if the key policy allows the **account principal** (`RB[ACCOUNT]`) for that action. An identity-policy **deny** is always effective, because step 2 sees it.
- **Grants.** `SPECIAL.kms_grant_self` / `kms_grant_parent` is true if some grant on the key meets all of these:
  - **Grantee.** It is the requester (`self`) or the requester's parent role or user (`parent`). If the grantee is the account root, the grant is treated as a delegation that needs the identity allow, and is flagged.
  - **Operation.** The requested operation is in the grant's operations. `kms:ReEncrypt*` maps to `ReEncryptFrom` and `ReEncryptTo`.
  - **Constraints.**
    - `EncryptionContextEquals` must equal the request's `kms:EncryptionContext:*` map exactly.
    - `EncryptionContextSubset`: the grant's map must be a subset of the request's map.
    - `SourceArn` must equal `aws:SourceArn`.

  Grants count on both sides of a cross-account evaluation (A12).
- **Cross-account operation allowlist.** If the principal's account is not the key's account and the action is not a cryptographic operation, CreateGrant, DescribeKey, GetKeyRotationStatus, GetPublicKey, ListGrants, RetireGrant or RevokeGrant, the result is `DENY/GUARDRAIL` whatever the policies say.
- **Exemptions.** AWS-managed keys skip RCPs. `kms:RetireGrant` by the grant's retiring principal is allowed by the grant itself and skips RCPs.
- **Key state.** A disabled key or one pending deletion is not an authorization question. When it is known, it is shown as an annotation, `NON_IAM_AUTHZ_LAYER`.

#### 7.6.2 S3

```text
special_resource_grants (S3 part):
  eff := effective_bpa(org, account, bucket, access point)          # most restrictive
  if bucket.object_ownership != "BucketOwnerEnforced":
      ACL grants come from the bucket ACL (bucket operations) or the object ACL (object operations; only if known)
      grantee kinds: canonical user (→ account via snapshot.canonical_ids), AllUsers, AuthenticatedUsers, LogDelivery
      permission → actions: READ → s3:ListBucket (bucket) / s3:GetObject* (object); WRITE; READ_ACP; WRITE_ACP;
                            FULL_CONTROL = all four
      if eff.IgnorePublicAcls: drop grants to AllUsers and AuthenticatedUsers
      ACL grants count only cross-account or for anonymous callers (§4.1 fact 5)
      SPECIAL.acl_public := remaining AllUsers grants (anonymous) or AuthenticatedUsers grants (any signed caller)
      SPECIAL.acl_grant_to_account := remaining canonical-user grants whose account == P.account_id

s3_bpa_gate(a, R, P, RBP, snap):
  if R is not an S3 resource: return T
  eff := effective_bpa(...)
  if eff.RestrictPublicBuckets and policy_is_public(bucket policy or access point policy):
       allowed := P.kind == service  or  P.account_id == bucket owner account
       if not allowed: return F                    # GUARDRAIL; the trace names RestrictPublicBuckets
  if a in {s3:PutBucketPolicy}      and eff.BlockPublicPolicy and policy_is_public(context "tessera:requestedpolicy"): return F
  if a in {s3:PutBucketAcl, s3:PutObjectAcl, s3:PutObject} and eff.BlockPublicAcls and request ACL is public:      return F
  return T

policy_is_public(doc):     # S3 "meaning of public" [S17]; Bouchet et al. 2020
  public := some Allow statement whose principal set includes "*" (or AWS:"*") and whose conditions do NOT pin,
            through a positive operator with a fixed value (no wildcard, no variable), at least one of:
            aws:PrincipalArn, aws:PrincipalAccount, aws:PrincipalOrgID, aws:userid (not "AROLEID:*"),
            aws:SourceIp (no broader than /8 for IPv4 or /32 for IPv6, RFC 1918 ranges excepted), aws:SourceArn,
            aws:SourceVpc, aws:SourceVpce, aws:SourceOwner, aws:SourceAccount,
            s3:DataAccessPointArn (account fixed; for bucket policies only), s3:DataAccessPointAccount
  Actions unknown to S3 inside such a statement still make the policy public (S3 checks that actions exist).
```

**Object context.** When the object owner differs from the bucket owner (only possible when ownership is not BucketOwnerEnforced), two extra checks run:
- **Bucket context:** the bucket owner's policies may explicitly deny the request (already covered by step 2).
- **Object context:** the object owner's grants, meaning the object ACL, must allow the request.

Tessera does not inventory objects. For object actions on buckets without BucketOwnerEnforced, the default assumption is that the object owner is the bucket owner. Those decisions carry `S3_OBJECT_OWNER_UNKNOWN` (`APPROXIMATE`) unless `req.s3_object_owner` is supplied.

### 7.7 Cross-account

```text
cross_account_grant(P, R, ID_ALLOW, PB_OK, SP_OK, RB, SPECIAL):
    KG := SPECIAL.kms_grant_self ∨ SPECIAL.kms_grant_parent                              # A12
    PRINCIPAL_SIDE := (ID_ALLOW ∧ PB_OK ∧ SP_OK) ∨ KG        # the SCPs of P's account are applied in step 6
    RESOURCE_SIDE  := RB[SELF] ∨ RB[PARENT] ∨ RB[ACCOUNT] ∨ RB[WILDCARD] ∨ RB[WILDCARD_PRINCIPALARN]
                      ∨ SPECIAL.acl_grant_to_account ∨ SPECIAL.acl_public ∨ KG
                                                              # the RCPs of R's account are applied in step 6
    return PRINCIPAL_SIDE ∧ RESOURCE_SIDE
```

`is_cross_account(P, R)` compares the principal's account with the account that owns the resource. For S3 objects that is the bucket owner, with the object context added when the owners differ. Actions with no resource (`"*"`) are same-account by definition. A caller in account B that names a resource in account A only through an access point also uses this path, with the access point's account as the resource side (A13).

### 7.8 Service principals and anonymous callers

- **Service principals** (for example `s3.amazonaws.com` sending to an SQS queue): only resource policies can grant. Identity, boundary, session and SCP policies do not apply. RCPs apply to the resource, and AWS's own RCP examples rely on `aws:PrincipalIsAWSService` to exempt services. `aws:SourceArn`, `aws:SourceAccount` and `aws:SourceOrgID` come from the request context; in "can ever" mode they are `unknown`. For cross-region calls from opt-in regions, the principal name is regionalized (`s3.ap-east-1.amazonaws.com`); the catalog lists those regions.
- **Anonymous**: only `Principal: "*"` statements and public ACLs grant, subject to Block Public Access and RCPs. `aws:PrincipalAccount` and `aws:userid` are both `anonymous`.

### 7.9 Fidelity propagation

A fidelity reason is **outcome-sensitive** if replacing the approximated component with its opposite assumption changes the final outcome. "Opposite" means allow↔deny for a gate, and match↔no-match for a statement. The engine finds out by re-running steps 2–6 with each flagged component flipped, which costs O(number of flagged components), typically 0–2. Only outcome-sensitive reasons lower `fidelity`. This keeps `APPROXIMATE` meaningful instead of noisy.

### 7.10 Deny kind and decisive statements

- **`EXPLICIT`** if `D` is `T`. The decisive statement is the first matching Deny, ordered by policy type (SCP, RCP, VPCE, resource, boundary, session, identity) and then by document order. Every other matching Deny is still listed in the trace.
- **`GUARDRAIL`** if `G` is `F` while the policy result was `T`.
- **`IMPLICIT`** otherwise. The decisive item is the **failing gate**, worded like AWS's AccessDenied messages so the two can be compared mechanically (§13.6). Examples: "no service control policy allows s3:GetObject (level ou-prod)", "no identity-based policy allows", "no permissions boundary allows", "no session policy allows", "no resource-based policy allows" (trust and KMS).
- **For `ALLOW`**, the decisive set is a **minimal justification**: one matching Allow per required layer. That means the grant path used, every SCP and RCP level, the boundary and the session policy. The engine chooses the first statement in a stable sort order so traces diff cleanly between versions.

### 7.11 The explanation model (the "why" trace)

An explanation is the ordered tuple `Decision.steps` plus the `decisive` set. **Every statement the engine looked at that could have affected the outcome appears exactly once**, under the stage where it was evaluated, with one of these results:

| Result | Meaning |
|---|---|
| `allow` / `deny` | The statement matched and contributed its effect |
| `no_match` | It did not match, with the first failing element: `action`, `resource`, `principal` or `condition:<key>` |
| `not_applicable` | Its policy type did not apply to this request, with the reason, e.g. "SCPs do not apply to the management account" or "RCPs do not cover lambda" |
| `pass` / `fail` | A gate summary for one SCP or RCP level, the boundary, the session policy, BPA, the KMS cross-account allowlist, or the VPCE |
| `conditional` | It matched only under a residual |

**Provenance** (`StmtRef`) identifies each statement precisely enough to find it in the console and in Git:
- policy ARN, or `<resource-arn>#policy`;
- the managed policy's **default version id**, or the SCP/RCP content hash;
- statement index, Sid, and line/column span in the raw JSON;
- the **attachment path**:
  - user → group → policy, for group-inherited policies;
  - role → permission set → Identity Center instance, for `AWSReservedSSO_*` roles;
  - the org level (root, OU id and name, or account), for SCPs and RCPs;
  - the resource ARN, for resource policies, plus the grant id for KMS grants.

**Condition trace.** For every atom: the key, the request state (`present`, `absent` or `unknown`), the values compared, which variant applied (IfExists, qualifier), and the result. This is what lets a reviewer see why, for example, "`StringNotEquals` on a missing key evaluated true".

**Rendering.** Three views come from one structure:
1. **One-line summary**, in the AWS AccessDenied style: `DENY (implicit): no service control policy allows s3:PutObject — blocked at OU Workloads/Prod (ou-ab12) [SCP AllowEC2Only#0 does not match action]`.
2. **Ordered narrative** for the UI and the PR comment: each stage, with the decisive statements in bold and links to the policy versions.
3. **Machine JSON**, the canonical serialization hashed to `explanation_id`. It is stored deduplicated (§6.2) and used for evidence exports and the harness comparator.

**Evidence guarantees** for the auditor story (iam-governance-expert to confirm):
- Explanations are content-addressed and tied to `snapshot_id` + `engine_version` + `catalog_version`.
- Replaying the same triple reproduces the identical trace bytes, which is checked in CI.
- Raw policy bytes are retained, so a trace can be re-verified years later without trusting Tessera's normalization.

---

## 8. Matching semantics

### 8.1 Case rules

| Element | Case |
|---|---|
| Service prefix and action name | Insensitive |
| Condition **key names**, including `${…}` variable names | Insensitive. A tag-key suffix such as `aws:PrincipalTag/Team` is looked up case-insensitively. `aws:TagKeys` **values** are compared by the operator, so `ForAnyValue:StringEquals` is case-sensitive. |
| Condition **values** | Decided by the operator. `StringEquals`, `StringLike` and `Arn*` are sensitive. `…IgnoreCase` is insensitive. `Bool` accepts `true`/`false` in any case [verify: probe P-BOOLCASE]. |
| Resource ARNs | Sensitive in every segment, including IAM user and role names. |
| Principal ARNs | Sensitive. Service principal names are lower-case. |

### 8.2 Action matching

```text
action_match(stmt, a):
  pats := stmt.actions if stmt.actions is not None else stmt.not_actions
  hit  := any(glob_ci(p, a) for p in pats)        # "*" matches everything; "s3:*"; "s3:Get*Object"; "?" = one character
  return hit if stmt.actions is not None else not hit
glob_ci(p, a): an anchored, case-insensitive regex in which '*' → '.*' and '?' → '.', with every other
               character escaped. Wildcards may appear anywhere, including the service prefix (SCPs allow "*:Describe*").
```

The catalog is used to **pre-expand** wildcards for indexing only (§12). Evaluation always matches the raw pattern, so actions launched after the catalog snapshot still match. This matters for `NotAction` with `Allow`, which grants future actions.

### 8.3 Resource matching

```text
resource_match(stmt, R, ctx):
  if stmt belongs to a resource policy and both resources and not_resources are None: return T    # implied
  pats := stmt.resources if stmt.resources is not None else stmt.not_resources
  pats := [substitute_variables(p, ctx) for p in pats]       # §9.3; a pattern with a null variable is dropped
  if R is None or R.arn == "*":                              # action without resource-level permissions
      hit := any(p == "*" for p in pats)
  else:
      hit := any(arn_glob(p, R.arn) for p in pats)
  return hit if stmt.resources is not None else not hit
  # So Resource "arn:aws:s3:::x" does not match an action without resource-level support, while
  # NotResource "arn:aws:s3:::x" does match it.

arn_glob(pattern, arn):                                      # default for ambiguity A1
  if pattern == "*": return True
  split pattern and arn on their first five ':' into six parts (the 6th keeps any further ':')
  for i in 0..4:
      if pattern part i ends in '*' and every later pattern part is empty or '*':
          return prefix_glob(part_i minus '*', arn part i) and arn has at least i+1 parts   # crosses ':'
      if not glob_cs(pattern part i, arn part i): return False    # '*' and '?' stay within the segment
  return glob_cs(pattern part 5, arn part 5)                  # in the resource part '*' crosses '/' and ':'
```

The regex compiler escapes **every** regex metacharacter apart from our `*` and `?`. PMapper escapes only `.`, `$` and `^`; real resource names contain `+`, `(`, `[` and `{`.

### 8.4 Principal matching (resource policies)

#### 8.4.1 Normalizing the policy's `Principal`
- `"*"` and `{"AWS": "*"}` become `WILDCARD`. If the statement also conditions on `aws:PrincipalArn` (any operator), the kind is `WILDCARD_PRINCIPALARN`.
- `{"AWS": "123456789012"}` and `{"AWS": "arn:aws:iam::123456789012:root"}` become the account principal.
- User, role, assumed-role and federated-user ARNs are kept. A bare unique ID (`AIDA…`, `AROA…`) is kept as an ID.
- `{"Service": [...]}` and `{"Federated": ...}` are kept as they are. `{"CanonicalUser": ...}` is mapped to its account through `snapshot.canonical_ids`.

#### 8.4.2 Match kinds for a requester P

| Policy principal | Requester kind | Match kind |
|---|---|---|
| User ARN == P.arn | iam_user | `SELF` |
| Session ARN == P.arn | role_session, federated_user_session | `SELF` |
| Role ARN == P.entity_arn, or role unique ID == P.unique_id | role_session | `PARENT` |
| User ARN == P.entity_arn | federated_user_session | `PARENT` |
| Account principal == P.account_id | any IAM principal | `ACCOUNT` (for **root** this behaves as `SELF`, because root holds every permission of its account) |
| `*` | any, including anonymous | `WILDCARD` or `WILDCARD_PRINCIPALARN` |
| Service == P.arn | service | `SERVICE` |
| Federated == the provider in the AssumeRoleWith* request | web identity, SAML | `SELF` (trust policies only) |

#### 8.4.3 NotPrincipal (Deny only)

```text
notprincipal_deny_applies(stmt, P):            # True ⇒ the Deny applies to P
  if P has a permissions boundary: return True # documented: always denies, whatever is listed
  L := normalized NotPrincipal list
  exempt :=  account principal of P ∈ L
         and (  (P.kind == iam_user               and P.arn ∈ L)
             or (P.kind in {role_session, federated_user_session} and (P.entity_arn ∈ L or P.arn ∈ L))   # A4
             or  P.kind == root )
  return not exempt
```

`NotPrincipal` with `Allow` is invalid, and AWS refuses to save it. If one appears in a snapshot, ingest records an anomaly, ignores the statement and adds a lint finding.

---

## 9. Condition evaluation

### 9.1 The request-context model

`build_context` produces a `dict[key → ContextValue]` with lower-cased keys. Each key is in one of three states:

| State | Meaning | Where it comes from |
|---|---|---|
| `present(values, type)` | AWS would put the key in the request context with these values | (1) **Derived** from the snapshot (§9.2); (2) supplied by the **caller** (a concrete request, a CloudTrail replay, or a harness case) |
| `absent` | AWS would **not** put this key in the context | The derivation rules know the key can't exist for this principal or request. Example: `aws:MultiFactorAuthPresent` for long-term access keys, `aws:SourceIp` through a VPC endpoint, `aws:username` for a role session, or a service-specific key the catalog doesn't list for this action. |
| `unknown` | It could be present with any value, or absent | Symbolic mode, for keys that depend on runtime: `aws:SourceIp`, `aws:CurrentTime`, `aws:MultiFactorAuthPresent` for temporary credentials, `aws:RequestTag/*`, `s3:prefix`, token claims and so on |

**Concrete mode** requires every key that a relevant statement references to be `present` or `absent`. A key left `unknown` is a **request error** (`MissingContext`), mirroring the simulator's `MissingContextValues`. **Symbolic mode** (§9.4) allows `unknown`.

Each catalog key has a declared type: String, ARN, Numeric, Date, Bool, IP, Binary, or ArrayOf\*. Whether a key is multivalued comes from the catalog (`ArrayOf…`) or from the global-key table.

### 9.2 Derived global keys

`tessera/aws/eval/context.py` implements one function per key family, covering availability rules from the AWS global condition key reference [S19]:

| Key | Derivation |
|---|---|
| `aws:PrincipalArn` | The **role ARN** for role sessions (not the session ARN), the user ARN, the root ARN, or the federated-user ARN. Absent for anonymous callers. |
| `aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths` | From the snapshot's org. Org keys are absent when the account is not in an org. Anonymous: absent (account = `anonymous`). |
| `aws:PrincipalTag/k` | Entity tags overlaid by session tags. Absent if the tag isn't set. |
| `aws:PrincipalType` | `User`, `AssumedRole`, `FederatedUser`, `Account` or `Anonymous` |
| `aws:userid`, `aws:username` | `aws:userid` follows the IAM variables table (`AROA…:session`, `AIDA…`, the account id for root, `anonymous`). `aws:username` exists for IAM users only. |
| `aws:PrincipalIsAWSService`, `aws:PrincipalServiceName`, `aws:PrincipalServiceNamesList` | True, or present, only for service-principal callers. Absent for unsigned requests. |
| `aws:ResourceAccount`, `aws:ResourceOrgID`, `aws:ResourceOrgPaths`, `aws:ResourceTag/k` | From the resource. Tag keys are absent if the tag isn't set on the resource, or if the service doesn't support `aws:ResourceTag` for that action (catalog). |
| `aws:TokenIssueTime`, `aws:MultiFactorAuthPresent`, `aws:MultiFactorAuthAge` | Absent for long-term credentials (IAM users signing with access keys, root keys). For sessions they are `unknown` in symbolic mode. |
| `aws:SourceIdentity`, `aws:FederatedProvider`, `aws:AssumedRoot`, `aws:Ec2InstanceSourceVpc` | Present only when the session has them |
| `aws:SourceIp`, `aws:SourceVpc`, `aws:SourceVpce`, `aws:VpceAccount` | Mutually exclusive by path. Through a VPC endpoint, `SourceIp` is absent and the VPC keys are present; otherwise the reverse. Symbolic mode keeps the **path** itself as an unknown boolean, so the residual can say "allowed if called via vpce-123 OR from 10.0.0.0/8". |
| `aws:CurrentTime`, `aws:EpochTime`, `aws:SecureTransport`, `aws:RequestedRegion`, `aws:CalledVia*`, `aws:ViaAWSService` | Caller-supplied. `unknown` in symbolic mode. `aws:ViaAWSService` and `aws:CalledVia` are absent for direct calls. |

### 9.3 Operators and policy variables

**Normalization at parse time.** `{"StringLikeIfExists": {"k": ["a", "b"]}}` becomes `Atom(op="StringLike", key="k", values=("a", "b"), if_exists=True)`. Qualifiers are parsed out of names such as `ForAllValues:StringEquals`. Policy values of any JSON scalar type are stored as strings; `Bool` values accept JSON booleans too.

**Atom evaluation for a `present` key with values V (one or more) and policy values W:**

| Op family | Single-valued key, no qualifier | Notes |
|---|---|---|
| `StringEquals` / `StringNotEquals` | ∃w ∈ W: v == w (negated: ¬∃) | Case-sensitive |
| `StringEqualsIgnoreCase` / `StringNotEqualsIgnoreCase` | Unicode case-fold comparison | |
| `StringLike` / `StringNotLike` | Glob with `*`/`?`; `${*}`, `${?}` and `${$}` are literal characters | Case-sensitive |
| `NumericEquals`, `…NotEquals`, `…LessThan`, `…LessThanEquals`, `…GreaterThan`, `…GreaterThanEquals` | Decimal comparison. If either side fails to parse, the atom is false. | No variables |
| `DateEquals` … `DateGreaterThanEquals` | Parse ISO 8601 (W3C profiles) or epoch seconds, normalize to UTC, compare | No variables |
| `Bool` | Case-insensitive compare against `true`/`false` | Variables allowed |
| `BinaryEquals` | Byte comparison of base64-decoded values | |
| `IpAddress` / `NotIpAddress` | CIDR containment for IPv4/IPv6. A bare address means /32 or /128. | |
| `ArnEquals` ≡ `ArnLike`, `ArnNotEquals` ≡ `ArnNotLike` | Six-segment, case-sensitive, per-segment glob (the same `arn_glob` rule as §8.3, default A1) | Variables allowed |
| `Null` | `"true"` ⇒ the key is absent; `"false"` ⇒ the key is present | No variables; IfExists not allowed |

**Missing keys, qualifiers and IfExists.** This is the core truth table. Here `pos` means the operator is not negated:

| Key state | No qualifier | `…IfExists` | `ForAllValues:` | `ForAnyValue:` |
|---|---|---|---|---|
| present | per-op (A7 for a multivalued key) | per-op | ∀v ∈ V: op(v, W) (`pos`); for negated ops, ∀v: ¬∃w match | ∃v ∈ V: op(v, W) (`pos`); for negated ops, ∃v: ¬∃w match |
| present but empty set (`[]` or `""`) | false (`pos`) / true (negated) | same as present | **true** | false |
| absent | **false (`pos`) / true (negated)** | **true** | **true** | **false** (A5, including negated ops) |
| unknown | `U(atom)` | `U(atom)` | `U(atom)` | `U(atom)` |

**Combining.** Inside one operator block, the keys AND and the values for one key OR (OR is built into the atom). Operator blocks AND. A statement whose condition has no blocks is `T`.

**Policy variables.**
- **Allowed in:** the resource part of `Resource`/`NotResource`, and String, ARN and Bool condition **values**.
- **Not allowed in:** keys, `Action` or `Principal`. A variable there is literal text.
- **When they are substituted.** Only when `language_version == "2012-10-17"`; any other version leaves them literal.
- **Grammar:** `${key}`, `${key, 'default'}`, `${*}`, `${?}`, `${$}`. A default is used when the key is absent.
- **Absent with no default:** in a resource pattern, the pattern is dropped (it matches nothing). In a condition, the value becomes the null marker: positive operators are false and negated operators true (A6).
- **Unknown:** in symbolic mode the variable stays symbolic. The atom becomes `U(atom with ${key} inside)`, and the residual renderer shows it, for example "resource suffix equals aws:PrincipalTag/team".
- **Multivalued keys** cannot be variables. If one is used, the policy is invalid; ingest records an anomaly and the evaluator treats the pattern as literal [verify P-MVVAR].

**Type mismatches.** A context value that fails to parse for the operator family (a non-IP value for `IpAddress`, for example) makes a positive operator false and a negated operator true. This matches the "no match" semantics [verify P-TYPEMISMATCH].

### 9.4 Three-valued reasoning: concrete requests versus "can X ever do Y"

The two query modes differ only in how `unknown` is introduced:

| | Concrete (`mode="concrete"`) | Symbolic (`mode="symbolic"`) |
|---|---|---|
| Used by | The harness, CloudTrail replay ("why was this call allowed?"), point checks in the UI | Effective-permission enumeration, who-can, PR diffs, least privilege |
| Runtime keys | Must be supplied or derivably absent | `unknown` unless pinned by the query's **assumption profile** |
| Outcomes | ALLOW / DENY only. `CONDITIONAL` cannot occur; if it does, that is an engine bug. | ALLOW / DENY / CONDITIONAL(φ) |

**Assumption profiles** let users ask realistic questions without enumerating context. A profile is a named partial context:
- `any-network`: SourceIp, SourceVpc and SourceVpce `unknown`.
- `corp-network`: SourceIp ∈ the configured corporate CIDRs.
- `mfa-session`: MultiFactorAuthPresent = true.
- `now`: CurrentTime = evaluation time.
- `tls`: SecureTransport = true.

The default profile for effective permissions is `{now, tls}`, with everything else unknown. The profile used is stored with every materialized row.

**Soundness invariant.** For any total context c consistent with the partial context: `eval_concrete(c) == ALLOW ⇔ φ(c) == true`. Property-based tests enforce it (§15, PR-5): random total contexts are drawn, symbolic and concrete evaluation are both run, and their results must agree.

**Interpreting deny-side unknowns.** If a Deny statement's condition is `U(ψ)`, the final residual contains `¬ψ`. The result is "allowed unless ψ", which is reported as `CONDITIONAL`, not `ALLOW`. Example: a Deny conditioned on `aws:RequestedRegion ∉ {eu-west-1}` yields "allowed only in eu-west-1".

### 9.5 Simplification and satisfiability (Phase 1)

`simplify(φ)` keeps residuals small and decides the obvious cases without a solver:
1. Constant folding and flattening, then deduplication of identical atoms (by canonical form).
2. **Per-key consistency.** Atoms on the same key and type are grouped and checked with a small domain solver:
   - **String equality:** a set intersection or exclusion; `StringLike` against `StringEquals` literals is checked by glob matching.
   - **Numeric and date:** interval arithmetic.
   - **IP:** CIDR set algebra with `ipaddress` collapse.
   - **Bool:** two values.
   - **Presence:** `Null`, IfExists and `ForAllValues`-vacuity are expressed through a presence boolean per key (the Zelkova trick).
3. If a conjunction is inconsistent on any key, it is `F`. If a disjunction contains a key-complete cover (for example `Bool k true ∨ Bool k false ∨ Null k true`), it is `T`.
4. Anything the domain solver cannot decide, such as two independent `StringLike` patterns on one key, is left as a residual. The decision is still sound: a residual that is actually unsatisfiable is reported `CONDITIONAL` instead of `DENY`, and gets the `RESIDUAL_UNDECIDED` hint. Phase 2 swaps in Z3 or cvc5 (Q5) to decide such residuals exactly.

**Rendering.** Residuals are rendered in DNF, with at most 4 disjuncts shown and the rest collapsed. Each atom links to its source statement. Example:
`CONDITIONAL — allowed if (aws:MultiFactorAuthPresent = true) AND (aws:SourceIp in 10.0.0.0/8 OR via vpce-0abc) [identity: DevPolicy#2, SCP ou-prod: RegionGuard#0]`

---

## 10. The action, resource and condition-key catalog

### 10.1 Sources, in priority order
1. **AWS Service Reference JSON** (primary). The index is at `https://servicereference.us-east-1.amazonaws.com/`, and per-service files are at `…/v1/<svc>/<svc>.json`. They provide actions, action condition keys, resource types per action, ARN formats, key types, `Annotations.Properties`, and Operation → AuthorizedActions/SDK mappings. AWS documents that changes can take 24 h to appear.
2. **iam-dataset (MIT).** Used for **dependent actions** and the access-level string where the Service Reference has only booleans. Licence notices are recorded in `THIRD_PARTY_NOTICES`.
3. **Curated overlays** in `catalog/aws/overlays/*.yaml`, maintained by Tessera:
   - the RCP-supported service list (§10.3), scraped from the Organizations user guide;
   - the SCP/RCP exemption rules;
   - the KMS cross-account operation allowlist;
   - S3 ACL permission → action mapping;
   - the global-key availability table (§9.2);
   - the `rbp_rules.yaml` explicit-allow table (§7.4.3);
   - regionalized service principals for opt-in regions;
   - the S3 "public" fixed-value key list.

### 10.2 Shape and versioning

```text
catalog/aws/
  snapshots/2026-10-08/            # immutable; content hash = catalog_version
     index.json                    # service list as fetched
     services/<svc>.json           # verbatim Service Reference files
     iam-dataset.lock              # commit SHA of the supplementary data
  overlays/*.yaml                  # reviewed by iam-authz-expert (CODEOWNERS)
  compiled/<catalog_version>.msgpack   # action ids, per-service bitsets, key types; built in CI
tessera/aws/catalog/loader.py      # load(version) -> Catalog
```

`Catalog` API:
- `canonical_action(str) -> str | None`
- `expand(pattern) -> frozenset[ActionId]`
- `resource_types(action) -> tuple[ResourceType]`
- `supports_resource_level(action) -> bool`
- `condition_keys(action, resource_type) -> set[str]`
- `key_type(key) -> KeyType`
- `is_multivalued(key) -> bool`
- `rcp_supported(service) -> bool`
- `access_level(action) -> {List, Read, Write, PermissionsManagement, Tagging}`
- `arn_formats(resource_type) -> list[str]`, `match_resource_type(arn) -> ResourceType | None`

### 10.3 Keeping the catalog current
- **Nightly job** (`.github/workflows/catalog-refresh.yml`):
  1. Fetch the index and every service file, plus the RCP services page.
  2. Normalize.
  3. Diff against the latest snapshot.
  4. If anything changed, open a PR titled "catalog: 2026-10-09 (+12 actions, +1 RCP service)". The PR has a human-readable diff and runs the golden corpus and the replay corpus against the new catalog.
- **Review gate.** Changes to overlays and to the RCP list need iam-authz-expert review. Pure Service Reference additions auto-merge if the tests pass.
- **Pinning.** A tenant's materialized results record `catalog_version`. When a new catalog lands, re-materialization is scheduled. An expanded wildcard that gains actions changes effective permissions, and those changes are reported as a **"catalog-driven change"** in the drift feed rather than as a policy change.
- **Unknown actions at evaluation time.** Matching still works on the raw pattern (§8.2). Only indexing and expansion degrade. The decision carries `CATALOG_MISS` and a metric alarms on it.
- **RCP list.** On 2026-10-08 the official list has 62 service prefixes. It is held in `overlays/rcp_services.yaml` with its fetch date. The nightly job diffs it against the Organizations guide page.

---

## 11. Integration with the existing MVP

The MVP (`mvp/backend/tessera/`) has a networkx `GraphSnapshot` over `identity → account → group → perm → resource`. Effective permission there is plain reachability; `simulate.py` copies the graph, mutates edges and diffs; `leastpriv.py` and `nhi.py` read `EffectivePermission` objects. The goal is to make AWS correct **without breaking that contract**.

### 11.1 Connector: `tessera/connectors/aws_org.py` (replaces `DemoAWSConnector` for real tenants)

It is read-only, assumes a Tessera role through OIDC/WIF federation (no stored keys, per D5 §8.4's strategic note), and collects one snapshot per run. It needs no write permissions anywhere.

| API calls | Feeds |
|---|---|
| `organizations:DescribeOrganization`, `ListRoots`, `ListOrganizationalUnitsForParent`, `ListAccountsForParent`, `ListPolicies(SCP, RCP)`, `DescribePolicy`, `ListTargetsForPolicy` | `Organization`, `OrgNode`, SCP/RCP `PolicyDoc` |
| `iam:GetAccountAuthorizationDetails` (per account) | Users, groups, roles (with trust policies, boundaries and tags), inline and managed policies (all versions; only the default is evaluated) |
| `s3:ListAllMyBuckets`, `GetBucketPolicy`, `GetBucketAcl`, `GetBucketOwnershipControls`, `GetBucketPublicAccessBlock`; `s3control:GetPublicAccessBlock`, `ListAccessPoints`, `GetAccessPointPolicy`; the org-level S3 policy | `S3BucketState`, access-point policies |
| `kms:ListKeys`, `DescribeKey`, `GetKeyPolicy`, `ListGrants` | KMS key policies and `KmsGrant` |
| `sqs:GetQueueAttributes(Policy)`, `sns:GetTopicAttributes`, `secretsmanager:GetResourcePolicy`, `lambda:GetPolicy`, `ecr:GetRepositoryPolicy`, `ec2:DescribeVpcEndpoints` (PolicyDocument) | Other resource policies, VPCE policies |
| `sso-admin:ListPermissionSets`, `DescribePermissionSet`, `GetInlinePolicyForPermissionSet`, `ListAccountAssignments`; `identitystore:*` reads | Identity Center: maps `AWSReservedSSO_*` roles to permission sets and IdP groups (the `maps_to` edges the demo connector fakes) |
| CloudTrail Lake or trail S3 (optional; Phase 1 least-privilege usage) | Usage events and replay requests (§13.4, stratum S5) |

The connector writes the `aws_*` tables (§6.2) and also emits the MVP's normalized records, so the existing graph keeps working:
- **`AccountRecord`** for each IAM user, each role, and each Identity Center user-in-account. `kind` is `user` or `service`. Roles are `service` accounts unless an Identity Center or SAML mapping links them to a human `IdentityRecord`.
- **`GroupRecord`** for IAM groups and for roles seen as groups (`kind="role"`), so `maps_to` from Okta groups still works.
- **`ResourceRecord`** for each resource in the snapshot, with environment and tags taken from resource tags.
- **`PermissionRecord`** rows: **only evaluator-confirmed ALLOW or CONDITIONAL tuples**, at the granularity of an action atom × resource atom (§12.2), labelled with representative names such as "s3:GetObject on prod-pii/\*".
- **`EdgeRecord`** `grants` from the role or user to each permission it is effectively allowed. The `edge.source` field is set to `evaluator`. A new optional field, `explanation_id`, is added to `EdgeRecord` and `GrantEdge` (nullable, so backward compatible).

**Effect:** `GraphSnapshot.effective_permissions()` now returns AWS permissions that already respect denies, SCPs, boundaries and resource policies. `leastpriv`, `policies`, `reviews` and `nhi` work unchanged. Their output simply becomes correct.

### 11.2 Model changes (additive only)
- `GrantEdge.explanation_id: str | None`, `GrantEdge.outcome: str | None` (`allow`/`conditional`), and `GrantEdge.fidelity: str | None`.
- `graph.EffectivePermission` gains `conditional: bool`, `fidelity: str` and `explanation_ids: list[str]`, all with defaults. API responses gain the same fields.
- New API endpoints:
  - `GET /api/aws/can?principal=&action=&resource=&profile=` → `Decision` with trace
  - `GET /api/aws/principals/{arn}/effective?service=&profile=` → paged effective set (§12.3)
  - `GET /api/aws/resources/{arn}/who-can?action=` → principals plus decisions
  - `POST /api/aws/simulate-policy-change` → diff (§11.3)
  - `GET /api/aws/explanations/{id}`

  All are read-only and tenant-scoped, and every call is audited (Phase 0 ledger).

### 11.3 Simulation: "a policy PR shows exactly who gains or loses which permission"

`simulate.py` today supports `remove_edge_ids`, `add_edges` and `disable_account_ids`. The design adds a new change type, `policy_changes: list[PolicyChange]`:

```python
@dataclass
class PolicyChange:
    op: Literal["put_policy_version", "attach", "detach", "put_inline", "delete_inline",
                "put_boundary", "delete_boundary", "put_resource_policy", "put_trust_policy",
                "attach_scp", "detach_scp", "put_scp", "attach_rcp", "detach_rcp", "put_rcp",
                "move_account", "create_grant", "retire_grant", "put_bpa", "put_ownership_controls"]
    target_arn: str
    document: str | None          # raw JSON for puts
    policy_arn: str | None
```

**Pipeline:**
1. Build `snap' = apply(changes, snap)`. The result is a new frozen Snapshot sharing structure with the old one.
2. Compute the affected set with the reverse indexes (§12.5), for example: an SCP change → every principal in the subtree; a bucket policy change → the principals indexed for that bucket's resource atoms plus every principal in the policy's principal set.
3. Recompute only the affected (principal, action-atom, resource-atom) cells under both snapshots.
4. Diff the cells. Output records are `{principal, action_atom → concrete actions, resource_atom → concrete resources, before: Decision, after: Decision, change: gained|lost|conditional_changed|fidelity_changed}`.
5. Join with the usage index (`usage.py`), so a "lost" record shows whether it was used in the last 30 or 90 days. This is what the existing simulate UI already shows.
6. Hand the result to the existing `diff_effective`-shaped response, plus the PR comment renderer.

**Example PR comment:**
```
Tessera access diff — snapshot 7f3a… → PR head (catalog 2026-10-08, engine 1.0.0)
 + 3 principals GAIN s3:GetObject on arn:aws:s3:::prod-pii/*   [EXACT]
     role/DataEngineer (sessions)  via bucket policy prod-pii#Statement[2] (PARENT; boundary DataBoundary#0 allows)
     ...
 − 1 principal LOSES kms:Decrypt on key/9f… (used 3 days ago)   [EXACT]
 ~ 2 principals become CONDITIONAL (aws:SourceVpce = vpce-0abc) on sqs:SendMessage ...
 ! 1 result APPROXIMATE (AMBIGUITY:A3 — same-account trust naming user ARN)
```

**Exactness claim.** For in-scope policy types, the diff is exact over the resources and principals in the snapshot, and over every action in the catalog version.

### 11.4 Trust edges, NHI and the human view (iam-pam-nhi-expert)

- **Trust-edge materialization.** For every role R and every candidate caller C, the engine evaluates `sts:AssumeRole` (and the WithWebIdentity/WithSAML variants for provider principals) in symbolic mode and stores a `TrustEdge(C → R)` if the outcome is ALLOW or CONDITIONAL. Candidate callers are the principals named in R's trust policy, plus every principal of the trusted account when the trust names the account, plus every principal of any account when it names `*`.
- **Graph edges.** Trust edges become graph edges with `relation="can_assume"`; `graph.py` needs a single new `GRANT_RELATIONS` member. A human's effective permissions then include those of every role reachable through `can_assume`. Each hop is annotated so that role chaining, with its 1 h cap, is visible.
- **NHI findings this enables in Phase 1**, feeding `nhi.py` flags:
  - an OIDC trust with a wildcard `sub` (residual contains `StringLike …:sub "repo:org/*"`) → `wildcard_oidc_trust`;
  - a cross-account trust without `sts:ExternalId` to a non-org account → `missing_external_id`;
  - `Principal: "*"` trust with weak conditions → `public_trust`;
  - an NHI whose effective set includes permission-management actions (catalog `IsPermissionManagement`) → `privileged`.
- **PassRole edges.** `iam:PassRole` is evaluated with `iam:PassedToService` set to `unknown`, and the edges are stored for Phase 2 escalation analysis.

### 11.5 Least privilege
- **Usage → actions.** CloudTrail `eventSource` + `eventName` are mapped to IAM actions through the catalog's `Operations[].AuthorizedActions`, with the iamlive and iam-dataset map as a fallback.
- **Producing a recommendation:**
  1. Compute the used set U(principal) of (action, resource) pairs over the observation window.
  2. Build a candidate policy.
  3. Evaluate it under the snapshot.
  4. **Verify** that every element of U is still ALLOW, and that the new effective set is a subset of the old one.

  Both checks are evaluator queries, so the PR states "this change removes N permissions, none used in 90 days, and keeps all 41 observed calls" with an exact basis.
- **Safety.** Recommendations are only generated from rows whose fidelity is `EXACT`, and they are never auto-applied when `CONDITIONAL` rows are involved (spec R2).

---

## 12. Performance: precomputation, indexing and caching

### 12.1 Target scale and SLOs (Phase 1 design target, "large tenant")

| Dimension | Target |
|---|---|
| Accounts in org | 500 |
| IAM users + roles (+ Identity Center session templates) | 50,000 |
| Distinct policy documents / statements | 30,000 / 400,000 |
| Resources inventoried (buckets, keys, queues, topics, secrets, functions, repos; **not** S3 objects) | 2,000,000, of which 50,000 have resource policies |
| Catalog | ~450 service prefixes, ~18,000 actions [approximate; measured per catalog version] |

| Query | SLO (warm, single tenant, 16 vCPU worker) |
|---|---|
| Point decision with full trace | p99 < 20 ms |
| All effective permissions of one principal (compressed) | p95 < 3 s |
| Who can do action Y on resource Z | p95 < 2 s |
| PR diff, single identity or resource policy change | p95 < 60 s |
| PR diff, SCP or RCP change at root (worst case) | < 15 min, streamed progressively; the PR check reports "partial" until done |
| Full tenant materialization | < 60 min |

### 12.2 Equivalence classes (atoms)

Evaluating every (principal × action × resource) cell is impossible at this scale (50k × 18k × 2M). It is also unnecessary, because policies can only distinguish what their patterns mention. This is the same insight behind Zelkova and Stratified Abstraction.

- **Action atoms.**
  1. Collect every action pattern in the tenant (Action/NotAction across all statements of every type).
  2. Give each catalog action a signature: the set of patterns that match it.
  3. Actions with equal signatures form one atom.

  No policy can tell them apart, so one evaluation covers all of them. (Condition keys differ per action, so the signature also includes the action's key set restricted to the keys actually referenced.) Expected size: a few thousand atoms. A sentinel "future action of service s" atom per service represents actions not yet in the catalog. It matches only `*`, `s:*` and NotAction patterns.
- **Resource atoms.** Each resource's signature is (service, resource type, account, region, the set of Resource/NotResource patterns matching its ARN, resource-policy id, KMS grant set id, S3 ownership/ACL/BPA state, and the values of the tag keys referenced in any `aws:ResourceTag/*` condition).
- **Principal atoms.** Each principal's signature is (identity-policy set, boundary, session template, account → SCP path id, values of referenced `aws:PrincipalTag/*` keys, org membership, SLR flag, and **every resource-policy principal pattern that matches it**). For example, 3,000 Identity Center sessions collapse to the ~40 permission-set atoms.

Atoms are computed by hashing, in O(total patterns × items) with compiled matchers. Matching on the 6th ARN segment is grouped by literal prefix, so most patterns are tested against a sorted range of ARNs rather than against every ARN.

### 12.3 Pruning with envelopes and inverted indexes

- **Compiled statements.** Each statement compiles to:
  - an **action bitset** over catalog action ids (roaring bitmap; NotAction is a complement), plus a `matches_future` flag;
  - a resource matcher;
  - a principal matcher;
  - an atom closure for its conditions.
- **Per-principal action envelope.**
  `env(P) = (⋃ Allow bitsets of ID ∪ RBP-statements-naming-P ∪ grants) ∩ (⋂ over boundary, session and each SCP level of that layer's ⋃ Allow bitsets) \ (⋃ unconditional, resource-independent Deny bitsets)`.
  Only action atoms inside `env(P)` are evaluated for P. The envelope is sound: a condition can only remove access, never add it.
- **Inverted indexes:**
  - `service_prefix → statements`;
  - `action_atom → Allow statements whose bitset contains it`;
  - `principal arn | account | "*" → resource-policy statements naming it`, for resource-side candidates;
  - `resource_atom → resource policies, grants and ACL grants`.
- **"All effective permissions of X":** for each action atom in `env(atom(X))`, take the resource atoms reachable through matching Resource patterns or through resource policies naming X, and evaluate in fast mode. The result is stored compressed: one row per (action atom, resource atom), and expanded to concrete names only in the API layer, paged by service.
- **"Who can do Y on Z":**
  1. Find `ra = atom(Z)` and `aa = atom(Y)`.
  2. The candidates are the principal atoms whose envelope contains `aa`, plus the principals named in Z's resource policy, grants or ACLs. Account and wildcard principals are expanded to every in-snapshot principal of that account, plus a synthetic **external** row "any principal in account N (subject to that account's own policies)". A wildcard adds a synthetic "anyone" row, including anonymous where relevant.
  3. Evaluate each candidate atom, then expand atoms to principals.

### 12.4 Caching and storage
- **Decision memo.** Keyed by `(principal_atom_sig, action_atom_sig, resource_atom_sig, profile_id, relevant_policy_hash)`. `relevant_policy_hash` hashes only the policy documents the evaluation actually consulted, so cached cells survive snapshot changes that don't touch them. This is what makes PR diffs cheap.
- **Materialization.** `aws_effective_permissions` stores scope-compressed rows (spec §6.3) at atom granularity, with an atom → members table. A "who can access R" query joins through the resource atom.
- **Explanation dedupe.** Many cells share a trace. They are content-addressed, and a full trace is materialized only for decisive rows and on demand (point queries recompute with the full trace, which is cheap).

### 12.5 Incremental recompute

The dependency index maps:
- `policy_id → principal atoms` (identity, boundary, session) or `→ resource atoms` (resource policies, grants);
- `org_node → accounts → principal atoms` (SCP) or `→ resource atoms` (RCP);
- `pattern → atoms`.

On a delta, which is either a connector change or a PR's `PolicyChange`:
1. If the delta adds new patterns, **refine** only the atoms the new pattern splits. The split is local. Atoms are merged back lazily in the nightly full recompute.
2. Mark the affected cells and recompute them under the old and new snapshots. The memo makes the "old" side free.
3. If more than 25 % of principal atoms are affected (typically a root SCP), switch to a partitioned full recompute per account and stream results.

### 12.6 Implementation notes
- **Python 3.12.** Use `pyroaring` for bitsets, precompiled `re` patterns (anchored, with `re.ASCII` where safe), `ipaddress`, and `msgspec` for snapshot (de)serialization. `multiprocessing` with fork-shared, read-only compiled snapshots, sharded by principal atom.
- **Expected cost:** 500 principal atoms × ~300 envelope-pruned action atoms × ~50 resource atoms on average ≈ 7.5 M cells. At ~20 µs per fast-mode cell that is about 150 core-seconds, comfortably inside the 60-minute materialization SLO. This is validated in PR-11 with a synthetic generator at 2× target scale.
- **Rust port.** The spec's Rust EPE ports `eval/` 1:1 later. It must reproduce this engine's output on the golden corpus, the replay corpus and a 10⁷-request random corpus before it replaces it.

---

## 13. The differential test harness

### 13.1 Architecture

```
 infra/sandbox (Terraform, applied by CI only)          mvp/harness/ (package tessera_harness; never imported by the server)
 ┌───────────────────────────────────────┐   outputs  ┌───────────────────────────────────────────────────────────────┐
 │ org, OUs, SCPs, RCPs, accounts,        │──────────►│ manifest.json (scenarios, principals, resources, canaries)     │
 │ scenario modules (tsr-<id>-*)          │           │                                                                 │
 └───────────────────────────────────────┘           │ snapshotter ── uses tessera/connectors/aws_org.py (same code)  │
                                                       │     │                                                           │
                                                       │ sampler (strata S1–S6) ─► RequestSpec[]                        │
                                                       │     │                                                           │
                                                       │     ├─► tessera engine (concrete mode)  ─► Decision             │
                                                       │     └─► oracle router ─► SimCustom | SimPrincipal | Probe | AA  │
                                                       │                    │       (with cassette recorder)             │
                                                       │ comparator ─► agreement / divergence ─► minimizer ─► triage DB  │
                                                       │ metrics (Wilson LB, coverage, per-stratum) ─► CI status + report│
                                                       └───────────────────────────────────────────────────────────────┘
```

- **Language and package.** Python, using `boto3` pinned to a version whose IAM model includes `OrderedOrganizationPolicyInputList` and `PolicyExclusionList`. CI asserts that pin (§13.2).
- **Cassettes.** Every oracle response is recorded, keyed by a canonical request hash plus the fixture version. Recorded cassettes become the **offline replay corpus**: PR CI re-runs every past divergence and a 2,000-check stratified sample with no AWS credentials.
- **Storage.** Tables `harness_runs`, `harness_checks` (request, our decision, oracle answer, stratum, oracle type, latency) and `harness_divergences` (class, minimized reproducer, issue link, status).

### 13.2 What AWS's oracles can and cannot decide (verified 2026-10-08)

**IAM policy simulator** (`SimulatePrincipalPolicy`, `SimulateCustomPolicy`) [S20–S24]:
- **Evaluates:** identity policies, permissions boundaries (one, `PermissionsBoundaryPolicyInputList`), and **SCPs including conditions and resource scoping**:
  - Principal mode uses the account's real SCPs.
  - Custom mode takes `OrderedOrganizationPolicyInputList`, up to 7 levels root → account, "evaluates SCPs in the order that you provide, consistent with how Organizations enforces SCPs".
  - It also takes one `ResourcePolicy` with `ResourceOwner` and `CallerArn` for cross-account checks.
- **Does not evaluate** (documented):
  - **RCPs**: "does not support resource control policies". `PolicyExclusionList` also ignores RCP identifiers.
  - **Session policies**: Custom `PolicyInputList` "cannot be 'scope-down' policies".
  - **Assumed-role, federated-user or service-principal callers**: `CallerArn` cannot be one of those.
  - **Resource policies on IAM roles**: "Simulation of resource-based policies isn't supported for IAM roles", so trust policies and sts:AssumeRole can't be simulated.
  - **VPC endpoint policies, role chaining, and multiple resource-based policies on one resource**.
- **Not mentioned at all**, so treated as unsupported: KMS grants, S3 ACLs, Block Public Access, access-point delegation, NotPrincipal-with-boundary.
- **Context.** It auto-fills only `aws:PrincipalAccount`, `PrincipalId`, `PrincipalType`, `Type`, `UserId`, `UserName`, `PrincipalOrgID`, `PrincipalOrgMasterAccountId` and `PrincipalOrgPaths`. **Every other key, including `aws:PrincipalArn` and `aws:PrincipalTag/*`, must be passed** in `ContextEntries`, or the result is an implicit deny with the key in `MissingContextValues`. Keys referenced only by SCPs are hidden from `MissingContextValues`.
- **Service-awareness.** It does **not** know which services support which global keys for identity and resource policies. SCPs are evaluated "with service-aware logic". This is a known source of false divergences, so the harness must pass the same context to both sides.
- **Response shape.**
  - It now returns **one `EvaluationResult` per action**. The top level aggregates to the most restrictive result, so **per-resource decisions must be read from `ResourceSpecificResults[].EvalResourceDecision`**.
  - SCP statements are never in `MatchedStatements`.
  - `EvalDecisionDetails` is populated only for cross-account checks and is absent when an SCP denies.
  - The `SourcePolicyType` enum in the docs disagrees with the example strings: accept both `resource` and `"Resource Policy"`.
  - Pagination: `MaxItems` up to 1000, and you must loop on `IsTruncated`.
- **Other API facts.** `ActionNames` in Custom mode take no wildcards. `ResourceHandlingOption` only covers the EC2 scenarios. AWS says plainly that "the policy simulator results can differ from your live AWS environment". No TPS limit is documented, so the harness uses adaptive backoff.

**IAM Access Analyzer** [S25–S28]:
- **Custom policy checks** (`CheckAccessNotGranted`, `CheckNoNewAccess`, `CheckNoPublicAccess`).
  - They are Zelkova-based, operate on a **single policy** with no environment (no SCPs, RCPs or org context), and are designed to minimize false negatives.
  - **PASS is trustworthy; FAIL may be a false positive.**
  - Cost: $0.002 per call.
  - `CheckNoPublicAccess` resource types include `AWS::S3::Bucket`, `AWS::KMS::Key`, `AWS::IAM::AssumeRolePolicyDocument`, `AWS::SQS::Queue` and `AWS::SecretsManager::Secret`.
- **Internal access analyzer** (`ORGANIZATION_INTERNAL_ACCESS`).
  - It evaluates identity, resource, boundary, SCP and RCP policies for S3, S3 directory buckets, RDS snapshots and DynamoDB tables and streams.
  - Findings come from `ListFindingsV2`/`GetFindingV2` (`findingType = InternalAccess`), with `serviceControlPolicyRestriction` and `resourceControlPolicyRestriction` = `APPLIED` only when the zone of trust is the organization.
  - Cost: $9 per resource per month. It is not available above 70,000 principals.
- **External access analyzer.**
  - It considers S3 ACLs, Block Public Access and access points, and KMS key policies **and grants**.
  - It does **not** apply RCPs: the docs say "APPLIED… not currently available for external access findings".
  - It considers only conditions that external users can't influence.
  - It updates within 30 min, and within 24 h for RCP changes.
- **There is no general "check access for (P, A, R)" API** in Access Analyzer.

**Live probes.** These are real API calls made in the sandbox with real sessions. They are the **only** oracle for RCPs, session policies, trust and AssumeRole, KMS grants, ACLs, Block Public Access, NotPrincipal layering, VPC endpoints and every ambiguity probe. Their cost is IAM propagation delay (re-check after a settle period) and a constrained action set (§13.5).

**AccessDenied messages** (CloudTrail `errorMessage` and probe errors) [S29]:
- They name the policy type for explicit and implicit denies: SCP, RCP (explicit only), VPC endpoint, permissions boundary, session, resource-based, role trust, identity-based.
- Explicit denies sometimes include the policy ARN.
- Only **one** policy type is named even when several deny, and some services do not use the format.
- The harness uses them to check our `deny_kind` and decisive stage, as a secondary metric.

### 13.3 Oracle routing

| Check category (by the policy types our trace touches) | Primary oracle | Secondary |
|---|---|---|
| Identity / boundary / SCP, same account, IAM user or role (no session policy) | SimulatePrincipalPolicy (deployed) or SimulateCustomPolicy (fuzz) | Probe sample (10 %) |
| + one resource policy (S3, SQS, SNS, Secrets, Lambda, ECR), same or cross account, caller is a user or role ARN | SimulateCustomPolicy with `ResourcePolicy`, `ResourceOwner`, `CallerArn` | Probe sample (10 %) |
| Anything involving **RCPs, session policies, assumed-role callers granted by session-ARN statements, trust policies or AssumeRole, KMS key policies or grants, S3 ACLs, BPA, access points, VPCE, NotPrincipal, management account, SLR** | **Live probe** | Simulator where partially applicable, recorded but not counted |
| Universal claims ("policy P never allows A on R") | Access Analyzer `CheckAccessNotGranted` (counted only if AA says PASS and we say ALLOW, or AA says FAIL with a reason statement that we say matches nothing; anything else goes to manual triage) | — |
| Who-can for S3 and DynamoDB in the org | Internal access findings (set comparison per resource) | Probes on a sample of the differing principals |
| External exposure | External access findings (set comparison; RCP-blocked findings excluded because AA doesn't apply RCPs) | Probes |
| Observed traffic | CloudTrail replay (S5) | — |

Only checks whose primary oracle is **authoritative for every policy type in the trace** count toward the gate metric. Everything else is still recorded and triaged.

### 13.4 Sampling strategy (nightly)

| Stratum | What | Volume per night | Oracle |
|---|---|---|---|
| **S1 Golden-deployed** | Every §14 case that is deployable is instantiated as a scenario module and run in full | ~60 checks (100 %) | Per routing |
| **S2 Grammar fuzz** | Type-directed random policy sets, with Cedar-style generators (FSE 2024): identity + boundary + up to 4 SCP levels + one resource policy. Weighted toward NotAction/NotResource, mid-string wildcards, `?`, IfExists, set operators, Null, negated operators on missing keys, variables with and without defaults, Version 2008, case variants of actions and ARNs, `ArnLike` per segment, and IP edge CIDRs. Requests are generated to land near the boundary: for each generated policy set, a request that matches one statement is mutated by one field. | 6,000 | SimulateCustomPolicy |
| **S3 Deployed config** | Sandbox principals × catalog actions × sandbox resources. Stratified by service (the top 25 services in proportion to CloudTrail frequency, plus a random tail), by principal kind and by our predicted outcome (allow and deny balanced 50/50 by importance sampling). Context taken from the profile and passed explicitly. | 3,000 | SimulatePrincipalPolicy, or SimulateCustomPolicy for cross-account |
| **S4 Probes** | The categories the simulator can't decide (above), covering every RCP-supported service in the sandbox, every BPA combination, every KMS grant constraint, trust variants and session-policy variants, plus every open ambiguity probe (A1–A17) | 1,500 | Live probe |
| **S5 CloudTrail replay** | Sandbox harness traffic and synthetic workloads replayed from CloudTrail Lake events (with `requestContext`), success versus AccessDenied | 500 | Observed outcome |
| **S6 Set checks** | AA custom checks on all sandbox identity and resource policies; internal and external findings comparison | ~200 calls | Access Analyzer |

In total that is ≥ 10,000 gate-eligible checks a night (S1–S5), which is enough for the Wilson bound in §13.7. Sampling is seeded, and the seed is logged so a run can be reproduced.

### 13.5 Calling the oracles

**SimulateCustomPolicy** (fuzz and cross-account):

```python
resp = iam.simulate_custom_policy(
    PolicyInputList=[json.dumps(p) for p in identity_policies],
    PermissionsBoundaryPolicyInputList=[json.dumps(boundary)] if boundary else [],
    OrderedOrganizationPolicyInputList=[            # root → OU(s) → account, ≤ 7 levels
        {"ServiceControlPolicyInputList": [json.dumps(s) for s in level]} for level in scp_levels
    ] if scp_levels else [],
    ActionNames=[action],                           # concrete; no wildcards in Custom mode
    ResourceArns=[resource_arn] if resource_arn else ["*"],
    ResourcePolicy=json.dumps(resource_policy) if resource_policy else None,
    ResourceOwner=f"arn:aws:iam::{resource_account}:root" if resource_policy else None,
    CallerArn=caller_user_or_role_arn,              # never a session ARN (API restriction)
    ContextEntries=[{"ContextKeyName": k, "ContextKeyValues": vals, "ContextKeyType": sim_type(k)}
                    for k, vals in explicit_context.items()],   # string|stringList|numeric|…|ip|date|boolean…
    MaxItems=1000,
)
# Loop while resp["IsTruncated"]. For each EvaluationResult, read ResourceSpecificResults[*].EvalResourceDecision
# when present, else EvalDecision. Record MatchedStatements, MissingContextValues,
# OrganizationsDecisionDetail.AllowedByOrganizations, PermissionsBoundaryDecisionDetail, EvalDecisionDetails.
# A non-empty MissingContextValues ⇒ the check is INVALID (harness bug), not a divergence.
```

**SimulatePrincipalPolicy** (deployed config): `PolicySourceArn=<user/role ARN>`, `ActionNames`, `ResourceArns`, `ContextEntries`. A `ResourcePolicy` is passed only when one is needed: the API never fetches resource policies, so the harness supplies the deployed policy text. `PolicyExclusionList` is used for ablation runs, for example excluding SCPs to isolate whether a divergence is in the SCP stage. The harness role needs `iam:SimulatePrincipalPolicy`, `iam:SimulateCustomPolicy`, `iam:GetContextKeysFor*` and read-only org access.

**Access Analyzer:** `accessanalyzer.check_access_not_granted(policyDocument=…, policyType="IDENTITY_POLICY"|"RESOURCE_POLICY", access=[{"actions": [...], "resources": [...]}])`, and `list_findings_v2(analyzerArn=<org internal analyzer>, filter={"findingType": {"eq": ["InternalAccess"]}})` followed by `get_finding_v2`. Honour `ThrottlingException.retryAfterSeconds`.

**Live probes.** A probe runs as a real principal from the manifest:
- **Role sessions:** the harness assumes the role, passing the scenario's session policy and tags where relevant.
- **IAM users:** probe-only users whose access keys live in the harness account's Secrets Manager. They are rotated daily, and the users exist only in sandbox accounts.

It then makes a **safe call**, and the result is classified by response:

| Action family | Safe call | Allowed if | Denied if |
|---|---|---|---|
| EC2 mutating | Same API with `DryRun=True` | `DryRunOperation` | `UnauthorizedOperation` |
| S3 object read | `GetObject` / `HeadObject` on a **canary object that exists** | 200 | 403 AccessDenied (never use a missing key: without ListBucket S3 returns 403 for a missing object) |
| S3 object write | `PutObject` to `canary/<run-id>` in a sandbox bucket, deleted by lifecycle after 1 day | 200 | 403 |
| SQS / SNS | `SendMessage` / `Publish` to a canary queue or topic, which a lifecycle-free consumer drains | 200 | AccessDenied / AuthorizationError |
| KMS | `Encrypt` (and `Decrypt` of the probe's own ciphertext) with a canary key; `DescribeKey` | 200 | AccessDeniedException |
| STS | `AssumeRole` / `AssumeRoleWithWebIdentity` with a JWT minted by the sandbox test OIDC issuer (§13.8) | Credentials returned | AccessDenied |
| Secrets Manager | `GetSecretValue` on a canary secret | 200 | AccessDeniedException |
| IAM / Organizations reads | `Get*` / `List*` | 200 | AccessDenied |
| Anything else | Only if the action is in the curated `probe_catalog.yaml` with a declared safe call; otherwise the check is not probed | | |

Any other error (throttling, NoSuchEntity, validation) makes the probe **INCONCLUSIVE**. It is retried, and never counted as a deny. Every disagreement is re-probed after a **10-minute settle** to filter out IAM and KMS eventual consistency. The probe path **never** changes IAM, Organizations, policies or grants. Fixture changes go only through Terraform applies, or through harness setup steps that run before sampling starts. Probe roles carry a dedicated session tag (`tessera-harness=true`), and the sandbox's SCPs deny mutating calls outside the `tsr-*` resource prefix for that tag.

### 13.6 Comparing results

For each check, our `Decision` is normalized into `{allowed | explicitDeny | implicitDeny}`. `GUARDRAIL` maps to `implicitDeny` for simulator comparison and to `denied` for probes. `CONDITIONAL` in concrete mode is an engine bug and counts as a disagreement. `UNSUPPORTED` excludes the check from the gate metric and is counted in coverage.

| Metric | Definition | Use |
|---|---|---|
| **M1 decision agreement** | agree / gate-eligible checks (allow versus deny) | **The gate** |
| M2 deny-kind agreement | Explicit versus implicit, where the oracle states it (simulator, AccessDenied text) | Tracked; any drop opens an issue |
| M3 statement agreement | The simulator's `MatchedStatements` (identity and resource) ⊆ our decisive and matching statements, with positions mapped through spans | Tracked; checks explanation quality |
| M4 stage agreement | The policy type named in the AccessDenied message equals our decisive stage | Tracked |
| C coverage | Gate-eligible checks whose fidelity is EXACT or APPROXIMATE / all sampled checks | Must be ≥ 97 %, so `UNSUPPORTED` can't game M1 |
| Per-stratum and per-service M1 | | Any stratum with point agreement < 99 % opens a P1 issue |

### 13.7 The gate (CI)

- **Every PR.** These run offline with no AWS credentials:
  1. Unit tests.
  2. The §14 golden corpus at **100 %**.
  3. The replay corpus (cassettes) at **100 %**, apart from entries pinned as `known_divergence` with a `SIMULATOR_LIMITATION` justification and probe evidence.
  4. Property tests: symbolic/concrete soundness (§9.4), determinism of traces, and parse → serialize round-trip.
  5. A coverage report for the golden corpus over the §3.1 rule list. Every rule must be hit by at least one case.
- **Nightly**, against the sandbox: the full harness. The **gate** is green when all of these hold:
  - the Wilson 95 % lower bound of M1 is ≥ 99.5 % with n ≥ 10,000 (at n = 10,000 that tolerates ≤ 38 disagreements; at n = 5,000, ≤ 16);
  - coverage C is ≥ 97 %;
  - there are zero S1 disagreements.

  The results are published to the dashboard and the README badge.
- **Release.** An evaluator release, or a catalog with overlay changes, requires **3 consecutive green nights** on the release-candidate build. A red night blocks releases and auto-assigns the on-call evaluator owner.
- **Weekly.** All ambiguity probes (A1–A17) are re-run. A changed outcome means AWS changed behaviour: P1 issue plus an update to §4.3.
- **Exit-criterion evidence.** The Phase 1 exit report attaches the last 7 nightly runs (n, M1 and its Wilson bound, C, per-stratum tables), the list of open divergences with classes, and the probe evidence for every closed ambiguity.

### 13.8 Sandbox AWS org (Terraform, described here, not applied)

`infra/sandbox/` holds the root modules. The state lives in the harness account's S3 backend with locking. Only CI applies it, through an OIDC role in the management account. No human has standing access; break-glass goes through the Phase 0 audit ledger.

```
Organization o-sbx (all features; SCP + RCP policy types enabled; S3 org BPA policy available but not attached by default)
└── Root r-sbx            SCPs: FullAWSAccess, SbxGuardrails (deny non-tsr-* mutations by harness-tagged sessions,
│                                deny regions ∉ {us-east-1, eu-west-1} except global services, deny leaving org)
│                         RCPs: RCPFullAWSAccess
├── mgmt (management acct)   — SCP-exemption and RCP-exemption probes; mgmt-account resources (tsr-mgmt-*)
├── OU Workloads             SCP: FullAWSAccess
│   ├── OU Prod              SCP: FullAWSAccess, DenyS3DeleteProd, RegionLock(eu-west-1) [Allow-with-Condition variant]
│   │   └── acct prod-a
│   └── OU Dev               SCP: FullAWSAccess
│       └── acct dev-a
├── OU AllowlistTest         SCP: AllowEC2SQSOnly (FullAWSAccess DETACHED at this OU)    → per-level intersection tests
│   └── acct allowlist-a     SCP (account level): FullAWSAccess, NotActionAllowVariant (full-language test)
├── OU RCPTest               RCP: DenyExternalS3 (aws:PrincipalOrgID), RequireTLS (BoolIfExists SecureTransport),
│   │                             DenyNonOrgKMS, DenySTSUnlessOrg
│   └── acct rcp-a
└── OU Harness               SCP: FullAWSAccess
    └── acct harness         Access Analyzer org analyzers (delegated admin: external + ORGANIZATION_INTERNAL_ACCESS),
                             harness runner role (OIDC from CI), probe-user key secrets, test OIDC issuer
                             (S3 + CloudFront static discovery doc + JWKS; private key in KMS, used by the harness to
                             mint JWTs), CloudTrail Lake event data store (org trail incl. requestContext)
External (non-org) accounts: ext-solo (no org) and ext-org (in a separate tiny org o-ext) — for cross-org/PrincipalOrgID cases
```

**Scenario modules** live at `infra/sandbox/scenarios/<case-id>/`. Each is small, isolated and named `tsr-<id>-*`. It creates exactly what one or more golden cases need:
- **IAM:** users (no console, no keys unless `probe_user = true`); roles with trust policies, boundaries and tags; managed and inline policies; groups.
- **S3:** buckets in each Object Ownership mode, ACL variants, BPA combinations, public and non-public bucket policies, access points (VPC and internet origin), and canary objects.
- **KMS:** keys with and without the root delegation statement; `aws_kms_grant` with EncryptionContext and SourceArn constraints.
- **Other resources:** SQS queues and SNS topics with policies; Secrets Manager secrets with resource policies; a Lambda function with a resource policy (an RCP-unsupported service); an ECR repository.
- **Networking:** one VPC with an S3 gateway endpoint and STS/KMS interface endpoints, each with endpoint policies, plus a probe runner (Lambda in the VPC) so probes can travel the VPCE path.

Every module outputs a manifest fragment: case id, principals, resources, canaries, and the expected golden ids. The harness gathers the fragments into `manifest.json`.

**Cost envelope (estimate):**

| Item | Approximate monthly cost |
|---|---|
| ~40 KMS keys | $40 |
| 3 interface endpoints × 2 AZs | ~$45 |
| Access Analyzer internal access, capped at 15 monitored resources | ~$135 |
| CloudTrail Lake | ~$50 |
| Custom checks (~6,000 calls) | ~$12 |
| Simulator | Free |
| **Total** | **≈ $300/month** |

**Safety:**
- Public buckets hold only canary bytes.
- Budget alarm at $500.
- `SbxGuardrails` keeps harness sessions inside `tsr-*` resources.
- No production data or identities ever enter the sandbox.
- The test OIDC issuer trusts only sandbox roles.

### 13.9 Triage of divergences

1. **Minimize.** Delta-debug the policy set (drop statements, then values, then condition blocks) and the context until the divergence disappears. Keep the minimal reproducer. For probe divergences, minimization runs through SimulateCustomPolicy when it applies, or else through a re-deployed minimal scenario.
2. **Auto-classify**, using the rules below together with an ablation run (`PolicyExclusionList`) and an alternate oracle:

   | Class | Signal | Action |
   |---|---|---|
   | `ENGINE_BUG` | Probe or simulator agree with each other and disagree with us | P1. Fix, and add a golden case from the reproducer |
   | `SIMULATOR_LIMITATION` | The simulator disagrees with both the probe and us | Add to the cassette `known_divergence` list with the probe evidence. Document it in §13.2. Optionally report to AWS. |
   | `DOC_AMBIGUITY` | Touches a §4.3 entry, or reveals a new one | Update the register; the probe result sets the default |
   | `PROPAGATION` | Agreement after the settle re-probe | Drop; track the rate |
   | `CONTEXT_MISMATCH` | The oracle used different context (for example an auto-filled key) | Harness bug; fix the request builder |
   | `CATALOG_STALE` | The action or key is missing from the pinned catalog | Refresh the catalog; check the overlay |
   | `FIXTURE_DRIFT` | The snapshot differs from the Terraform manifest | Re-apply; alert on infrastructure drift |

3. **File.** An issue is opened automatically with the reproducer, both traces, the oracle response and the cassette. Owners: the evaluator team for ENGINE_BUG, the harness team for CONTEXT_MISMATCH and FIXTURE_DRIFT. SLA: an ENGINE_BUG is fixed or hidden behind a fidelity downgrade within 5 business days. A downgrade means the affected pattern is marked `APPROXIMATE` with a reason code.
4. **Close.** An ENGINE_BUG closes only when its reproducer is in the golden or replay corpus and passes.

---

## 14. Offline golden corpus

### 14.1 Format and conventions

The corpus lives at `mvp/backend/tests/aws_eval/golden/*.yaml`, one file per area. `tests/aws_eval/test_golden.py` runs it with **no AWS credentials**. Every case gives the snapshot fragment, the request and the expected decision, and cites the rule that justifies the expectation. A case has `verified: doc` (it follows directly from a cited AWS doc sentence) or `verified: pending-probe:<A-id>` (it depends on an ambiguity default). A case flips to `verified: probe:<run-id>` once the harness confirms it in the sandbox. Every deployable case is also a scenario module (§13.8, stratum S1).

```yaml
# Defaults for every case unless overridden
accounts: {A: "111111111111", B: "222222222222", MGMT: "999999999999", X: "333333333333"}  # X: account in ANOTHER org (o-ext)
org: null                  # Organizations absent unless the case sets org
policy_version: "2012-10-17"
mode: concrete             # context keys not listed are ABSENT unless §9.2 derives them
s3: {object_ownership: BucketOwnerEnforced, bpa: {account: none, bucket: none}}
expect: {outcome: ALLOW|DENY|CONDITIONAL, deny_kind: explicit|implicit|guardrail, stage: <decisive stage>, fidelity: exact}
```

Shared org fixture **O1** (used where `org: O1`):
```yaml
O1:
  management_account: "999999999999"
  scp_enabled: true
  rcp_enabled: true
  root r-1:          {scp: [FullAWSAccess], rcp: [RCPFullAWSAccess]}
  ou-prod (in r-1):  {scp: [FullAWSAccess], rcp: [RCPFullAWSAccess]}  → account 111111111111 {scp: [FullAWSAccess], rcp: [RCPFullAWSAccess]}
  ou-allow (in r-1): {scp: [AllowEC2Only], rcp: [RCPFullAWSAccess]}   → account 222222222222 {scp: [FullAWSAccess], rcp: [RCPFullAWSAccess]}
  account 999999999999 (management) directly under r-1
  AllowEC2Only = {"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}
```

`Allow*` means the identity policy `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`. `BKT` is `arn:aws:s3:::tsr-bkt`. User ARN `U` = `arn:aws:iam::111111111111:user/alice`. Role ARN `R` = `arn:aws:iam::111111111111:role/app`, session `RS` = `arn:aws:sts::111111111111:assumed-role/app/s1`.

### 14.2 Cases

**Basics and the grammar**

```yaml
- id: GC-01  title: Implicit deny with no policies
  principal: U   identity: []
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a.txt"}
  expect: {outcome: DENY, deny_kind: implicit, stage: identity}
  why: "All requests are implicitly denied by default except root [S1]."  verified: doc

- id: GC-02  title: Identity allow
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a.txt"}
  expect: {outcome: ALLOW}   why: "Identity allow; no limiters [S1]."  verified: doc

- id: GC-03  title: Explicit deny overrides allow
  principal: U
  identity: [{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},
                           {"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::*log*"}]}]
  request: {action: s3:PutObject, resource: "arn:aws:s3:::tsr-applog/x"}
  expect: {outcome: DENY, deny_kind: explicit, stage: explicit_deny, decisive: "identity#1"}
  why: "Deny matches 'arn:aws:s3:::*log*' ('*' spans '/' in the resource part); explicit deny wins [S1][S11]."  verified: doc

- id: GC-04  title: Action names are case-insensitive
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"S3:getobject","Resource":"*"}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: ALLOW}   why: "Actions are case-insensitive [S4b]."  verified: doc

- id: GC-05  title: Resource ARNs are case-sensitive
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::TSR-BKT/*"}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: DENY, deny_kind: implicit, stage: identity}  why: "Resource matching is case-sensitive [S11]."  verified: doc

- id: GC-06  title: '*' crosses '/' inside the resource segment
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*/test/*"}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/1/2/test/object.jpg"}
  expect: {outcome: ALLOW}   why: "AWS's own example list includes 1/2/test/object.jpg [S11]."  verified: doc

- id: GC-07  title: The same pattern needs the literal '/test/'
  principal: U   identity: "as GC-06"
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/test/object.jpg"}
  expect: {outcome: DENY, deny_kind: implicit, stage: identity}  why: "Listed as a non-match [S11]."  verified: doc

- id: GC-08  title: '?' matches exactly one character
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:111111111111:q?"}]}]
  requests:
    - {action: sqs:SendMessage, resource: "arn:aws:sqs:us-east-1:111111111111:q1"}   → ALLOW
    - {action: sqs:SendMessage, resource: "arn:aws:sqs:us-east-1:111111111111:q10"}  → DENY implicit
  why: "'?' is a single-character wildcard [S11]."  verified: doc

- id: GC-09  title: NotAction with Allow and Resource '*' grants everything else
  principal: U   identity: [{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}]
  requests:
    - {action: ec2:DescribeInstances, resource: "*"}                                  → ALLOW
    - {action: iam:CreateUser, resource: "arn:aws:iam::111111111111:user/bob"}        → DENY implicit
  why: "NotAction with Allow matches every unlisted action [S12]."  verified: doc

- id: GC-10  title: NotAction with Allow scoped by Resource does not reach other services
  principal: U   identity: [{"Statement":[{"Effect":"Allow","NotAction":"s3:DeleteBucket","Resource":"arn:aws:s3:::*"}]}]
  request: {action: ec2:DescribeInstances, resource: "*"}
  expect: {outcome: DENY, deny_kind: implicit, stage: identity}
  why: "Other services' actions aren't applicable to S3 resources [S12]; a Resource that isn't '*' does not match an action without resource-level permissions (§8.3)."  verified: doc

- id: GC-11  title: NotResource with Deny denies everything outside the listed resources
  principal: U
  identity: [{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},
                           {"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::hr/Payroll","arn:aws:s3:::hr/Payroll/*"]}]}]
  requests:
    - {action: s3:GetObject, resource: "arn:aws:s3:::other/x"}       → DENY explicit (identity#1)
    - {action: s3:GetObject, resource: "arn:aws:s3:::hr/Payroll/p1"} → ALLOW
  why: "[S12] NotResource example."  verified: doc

- id: GC-12  title: Deny NotAction plus BoolIfExists on MFA, with long-term keys
  principal: U (access keys, so aws:MultiFactorAuthPresent is ABSENT)
  identity: [{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},
                           {"Effect":"Deny","NotAction":"iam:*","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}]
  requests:
    - {action: ec2:DescribeInstances, resource: "*"}                       → DENY explicit
    - {action: iam:GetUser, resource: "arn:aws:iam::111111111111:user/alice"} → ALLOW
  why: "IfExists with a missing key is true, so the Deny applies [S8]; the MFA key is absent for long-term credentials [S19]."  verified: doc
```

**Conditions**

```yaml
- id: GC-13  title: A positive operator on a missing key does not match
  principal: U (no tags)
  identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"data"}}}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: DENY, deny_kind: implicit}   why: "[S8] missing key ⇒ no match."  verified: doc

- id: GC-14  title: A negated operator on a missing key matches (over-grant pitfall)
  principal: U (no tags)
  identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalTag/team":"contractor"}}}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: ALLOW}   why: "[S8] 'If the policy condition requires that the key is not matched… and the key is not present, the condition is true.'"  verified: doc

- id: GC-15  title: A negated operator on a missing key in a Deny applies the Deny
  principal: U (no tags)
  identity: [Allow*, {"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalTag/team":"data"}}}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: DENY, deny_kind: explicit}   why: "[S8]."  verified: doc

- id: GC-16  title: StringLikeIfExists with a missing key
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*","Condition":{"StringLikeIfExists":{"ec2:InstanceType":["t3.*"]}}}]}]
  request: {action: ec2:RunInstances, resource: "arn:aws:ec2:us-east-1:111111111111:security-group/sg-1"}   # no InstanceType key
  expect: {outcome: ALLOW}   why: "[S8] IfExists ⇒ true when the key is absent."  verified: doc

- id: GC-17  title: ForAllValues with a missing key is vacuously true
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"ec2:CreateTags","Resource":"*","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["env","cost-center"]}}}]}]
  request: {action: ec2:CreateTags, resource: "arn:aws:ec2:us-east-1:111111111111:instance/i-1"}   # aws:TagKeys absent
  expect: {outcome: ALLOW}   why: "[S9] ForAllValues 'returns true if there are no context keys in the request'."  verified: doc

- id: GC-18  title: ForAllValues plus Null:false closes the gap
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"ec2:CreateTags","Resource":"*","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["env"]},"Null":{"aws:TagKeys":"false"}}}]}]
  request: "as GC-17"
  expect: {outcome: DENY, deny_kind: implicit}   why: "[S9] example table, last row: No match."  verified: doc

- id: GC-19  title: ForAnyValue with a missing key is false
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"ec2:DeleteTags","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":["env"]}}}]}]
  request: {action: ec2:DeleteTags, resource: "arn:aws:ec2:us-east-1:111111111111:instance/i-1"}
  expect: {outcome: DENY, deny_kind: implicit}   why: "[S9]."  verified: doc

- id: GC-20  title: Values OR within a key; keys and operators AND
  principal: U
  identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{
              "StringEquals":{"aws:PrincipalTag/team":["data","ml"],"aws:RequestedRegion":"eu-west-1"}}}]}]
  principal_tags: {team: ml}
  requests:
    - {context: {aws:RequestedRegion: eu-west-1}} → ALLOW
    - {context: {aws:RequestedRegion: us-east-1}} → DENY implicit
  why: "[S8] multiple values OR; multiple keys AND."  verified: doc

- id: GC-21  title: Null:true allows only when the key is absent
  principal: U (long-term keys)
  identity: [{"Statement":[{"Effect":"Allow","Action":"sqs:ListQueues","Resource":"*","Condition":{"Null":{"aws:TokenIssueTime":"true"}}}]}]
  request: {action: sqs:ListQueues, resource: "*"}
  expect: {outcome: ALLOW}   why: "TokenIssueTime is absent for long-term credentials [S8][S19]."  verified: doc

- id: GC-22  title: An IpAddress allow fails through a VPC endpoint
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a", context: {aws:SourceVpce: vpce-1}}   # SourceIp absent
  expect: {outcome: DENY, deny_kind: implicit}   why: "aws:SourceIp is absent via a VPCE [S8][S19]."  verified: doc

- id: GC-23  title: A NotIpAddress deny applies through a VPC endpoint
  principal: U   identity: [Allow*, {"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}]
  request: "as GC-22"
  expect: {outcome: DENY, deny_kind: explicit}   why: "Negated operator with a missing key ⇒ true [S8] (A17)."  verified: pending-probe:A17

- id: GC-24  title: A policy variable resolves for an IAM user
  principal: U (aws:username=alice)
  identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-home/${aws:username}/*"}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-home/alice/notes.txt"}
  expect: {outcome: ALLOW}   why: "[S10]."  verified: doc

- id: GC-25  title: The same variable is null for a role session
  principal: RS   identity(role app): "as GC-24"
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-home/app/notes.txt"}
  expect: {outcome: DENY, deny_kind: implicit}
  why: "aws:username is not present for roles [S10]; a Resource entry with a null variable matches nothing [S10]."  verified: doc

- id: GC-26  title: A default value applies when the tag is absent
  principal: U (no team tag)
  identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-team-${aws:PrincipalTag/team, 'company-wide'}/*"}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-team-company-wide/x"}
  expect: {outcome: ALLOW}   why: "[S10] default values."  verified: doc

- id: GC-27  title: Version 2008-10-17 makes variables literal text
  principal: U (aws:username=alice)
  identity: [{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-home/${aws:username}/*"}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-home/alice/notes.txt"}
  expect: {outcome: DENY, deny_kind: implicit}   why: "[S10] variables are literal strings without Version 2012-10-17."  verified: doc

- id: GC-28  title: Date condition on aws:CurrentTime
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":"2026-10-01T00:00:00Z"}}}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a", context: {aws:CurrentTime: "2026-10-08T12:00:00Z"}}
  expect: {outcome: DENY, deny_kind: implicit}   why: "[S8] date operators."  verified: doc

- id: GC-29  title: StringEqualsIgnoreCase
  principal: U (tag dept=Finance)
  identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEqualsIgnoreCase":{"aws:PrincipalTag/dept":"finance"}}}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: ALLOW}   why: "[S8]."  verified: doc

- id: GC-30  title: A service principal with an ArnEquals aws:SourceArn guard
  principal: "sns.amazonaws.com"
  resource_policy (queue arn:aws:sqs:us-east-1:111111111111:tsr-q):
    {"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage",
      "Resource":"arn:aws:sqs:us-east-1:111111111111:tsr-q","Condition":{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:111111111111:tsr-topic"}}}]}
  requests:
    - {context: {aws:SourceArn: "arn:aws:sns:us-east-1:111111111111:tsr-topic"}} → ALLOW
    - {context: {aws:SourceArn: "arn:aws:sns:us-east-1:777788889999:tsr-topic"}} → DENY implicit
  why: "[S8] ARN operator example."  verified: doc
```

**Boundaries, session policies and the principal-type matrix** (same account: bucket `tsr-bkt` owned by 111111111111)

```yaml
- id: GC-31  title: An identity allow capped by a boundary
  principal: U   identity: [Allow*]
  boundary: {"Statement":[{"Effect":"Allow","Action":["ec2:*"],"Resource":"*"}]}
  request: {action: iam:CreateUser, resource: "arn:aws:iam::111111111111:user/x"}
  expect: {outcome: DENY, deny_kind: implicit, stage: boundary}   why: "[S2] Shirley example."  verified: doc

- id: GC-32  title: A bucket policy granting the user ARN bypasses an implicit deny in the boundary and identity
  principal: U   identity: []   boundary: {"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}
  bucket_policy: {"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/alice"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: ALLOW, stage: resource_policy, match_kind: SELF}
  why: "[S1][S2] a same-account RBP grant to an IAM user ARN is not limited by an implicit deny in identity or boundary."  verified: doc

- id: GC-33  title: An explicit deny in the boundary still wins over a user-ARN grant
  "as GC-32, but the boundary also has": {"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::tsr-bkt/*"}
  expect: {outcome: DENY, deny_kind: explicit, stage: explicit_deny}   why: "[S2][S6] 'an explicit deny in the permission boundary is effective'."  verified: doc

- id: GC-34  title: A bucket policy granting the role ARN, with no identity policy and no boundary
  principal: RS   role identity: []
  bucket_policy: {"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/app"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: ALLOW, match_kind: PARENT}   why: "[S1] the role-ARN grant is limited only by boundary and session policy, not by identity."  verified: doc

- id: GC-35  title: A role-ARN grant is capped by the role's boundary
  "as GC-34, with role boundary": {"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}
  expect: {outcome: DENY, deny_kind: implicit, stage: boundary}
  why: "[S1][S6] 'if you specify a role ARN… an explicit allow in the permission boundary is required'."  verified: doc

- id: GC-36  title: A session-ARN grant is not capped by the boundary
  "as GC-35, but Principal": {"AWS":"arn:aws:sts::111111111111:assumed-role/app/s1"}
  expect: {outcome: ALLOW, match_kind: SELF}   why: "[S1][S2] grants to the session are not limited by identity, boundary or session policy."  verified: doc

- id: GC-37  title: A role-ARN grant is capped by a session policy
  "as GC-34, with session policy on RS": {"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}
  expect: {outcome: DENY, deny_kind: implicit, stage: session}
  why: "[S6] (session ∩ RBP) ∪ (session ∩ identity)."  verified: doc

- id: GC-38  title: Wildcard principal plus aws:PrincipalArn is not capped by the boundary
  principal: RS   role identity: []   role boundary: {"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}
  bucket_policy: {"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*",
                  "Condition":{"ArnEquals":{"aws:PrincipalArn":"arn:aws:iam::111111111111:role/app"}}}]}
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: ALLOW, match_kind: WILDCARD_PRINCIPALARN}
  why: "[S1][S5] 'Permissions boundaries and session policies do not limit permissions granted using aws:PrincipalArn with a wildcard (*) in Principal, unless the identity-based policies contain an explicit deny.'"  verified: doc
  note: "A policy-public check would also apply if BPA RestrictPublicBuckets were on; it is off here."

- id: GC-39  title: A same-account grant to the account principal delegates; identity is still needed
  principal: U   identity: []
  bucket_policy: {"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: DENY, deny_kind: implicit, stage: identity}
  why: "[S5] the account principal 'delegates authority to the account… does not limit permissions to only the root user'."  verified: doc

- id: GC-40  title: A session policy intersects the identity policy
  principal: RS   role identity: [{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}]
  session_policy: {"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}
  request: {action: s3:PutObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: DENY, deny_kind: implicit, stage: session}   why: "[S6]."  verified: doc

- id: GC-41  title: A federated-user session granted directly by ARN
  principal: "arn:aws:sts::111111111111:federated-user/bob"  (parent user bob; session policy allows only ec2:*)
  bucket_policy: {"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:sts::111111111111:federated-user/bob"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: ALLOW, match_kind: SELF}   why: "[S1][S2] federated-user ARN grants are direct to the session."  verified: doc
```

**SCPs** (`org: O1`)

```yaml
- id: GC-42  title: SCPs intersect per level; an OU allowlist without FullAWSAccess blocks S3
  principal: "arn:aws:iam::222222222222:user/carol"   identity: [Allow*]
  request: {action: s3:ListAllMyBuckets, resource: "*"}
  expect: {outcome: DENY, deny_kind: implicit, stage: scp, blocking_level: ou-allow}
  why: "[S4] an Allow must exist at every level; ou-allow has only ec2:*."  verified: doc

- id: GC-43  title: An SCP deny at the OU overrides allows at the root and the account
  org: "O1 + ou-prod gets SCP {\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"s3:DeleteBucket\",\"Resource\":\"*\"}]}"
  principal: U   identity: [Allow*]
  request: {action: s3:DeleteBucket, resource: "arn:aws:s3:::tsr-bkt"}
  expect: {outcome: DENY, deny_kind: explicit, stage: explicit_deny, decisive_level: ou-prod}  why: "[S4]."  verified: doc

- id: GC-44  title: The management account is exempt from SCPs
  org: "O1 + root gets SCP Deny s3:*"
  principal: "arn:aws:iam::999999999999:user/admin"   identity: [Allow*]
  request: {action: s3:ListAllMyBuckets, resource: "*"}
  expect: {outcome: ALLOW, scp: not_applicable}   why: "[S4a] SCPs don't affect users or roles in the management account."  verified: doc

- id: GC-45  title: Service-linked roles are exempt from SCPs
  org: "O1 + root gets SCP Deny s3:*"
  principal: "arn:aws:sts::111111111111:assumed-role/AWSServiceRoleForExample/svc" (role path /aws-service-role/)
  identity(role): [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: ALLOW, scp: not_applicable}   why: "[S4a] SCPs do not affect any service-linked role."  verified: doc

- id: GC-46  title: A member account's root user is subject to SCPs
  org: "O1 + ou-prod gets SCP Deny s3:DeleteBucket"
  principal: "arn:aws:iam::111111111111:root"
  request: {action: s3:DeleteBucket, resource: "arn:aws:s3:::tsr-bkt"}
  expect: {outcome: DENY, deny_kind: explicit}   why: "[S4a] SCPs affect the member account's root user."  verified: doc

- id: GC-47  title: An external principal is not subject to the resource account's SCPs
  org: "O1 + ou-prod gets SCP Deny s3:GetObject"     # bucket tsr-bkt is in 111111111111 (ou-prod)
  principal: "arn:aws:iam::333333333333:role/partner" session "…assumed-role/partner/s"   identity: [Allow*]
  bucket_policy: {"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::333333333333:role/partner"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: ALLOW}
  why: "[S4a] SCPs 'don't affect users or roles from accounts outside the organization'; no RCP restricts it."  verified: doc

- id: GC-48  title: An SCP Allow with a Condition (full IAM language, Sept 2025)
  org: "O1 with ou-allow's AllowEC2Only replaced by {\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:RequestedRegion\":\"eu-west-1\"}}}]}"
  principal: "arn:aws:iam::222222222222:user/carol"   identity: [Allow*]
  requests:
    - {action: sqs:ListQueues, resource: "*", context: {aws:RequestedRegion: us-east-1}} → DENY implicit (scp, ou-allow)
    - {action: sqs:ListQueues, resource: "*", context: {aws:RequestedRegion: eu-west-1}} → ALLOW
  why: "[S4b][S30] conditions allowed in SCP Allow statements."  verified: pending-probe:A2
```

**RCPs** (`org: O1`, RCPs enabled)

```yaml
- id: GC-49  title: An RCP blocks principals outside the org, despite the bucket policy
  org: "O1 + ou-prod gets RCP {\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",
        \"Condition\":{\"StringNotEqualsIfExists\":{\"aws:PrincipalOrgID\":\"o-sbx\"},\"BoolIfExists\":{\"aws:PrincipalIsAWSService\":\"false\"}}}]}"
  principal: "…assumed-role/partner/s" in 333333333333 (org o-ext ⇒ aws:PrincipalOrgID = o-ext)   identity: [Allow*]
  bucket_policy: "as GC-47 (without the SCP)"
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: DENY, deny_kind: explicit, stage: explicit_deny, policy_kind: rcp}
  why: "[S5a] RCPs apply to resources in member accounts regardless of the principal's org."  verified: doc

- id: GC-50  title: RCPs do not apply to resources in the management account
  org: "O1 + root gets the RCP from GC-49"
  bucket: "arn:aws:s3:::tsr-mgmt-bkt" owned by 999999999999, with a bucket policy allowing the partner role
  principal: "as GC-49"
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-mgmt-bkt/a"}
  expect: {outcome: ALLOW, rcp: not_applicable}   why: "[S5a] RCPs don't affect resources in the management account."  verified: doc

- id: GC-51  title: An RCP naming a service that does not support RCPs has no effect
  org: "O1 + ou-prod gets RCP {\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"*\"}]}"
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}]}]
  request: {action: lambda:InvokeFunction, resource: "arn:aws:lambda:us-east-1:111111111111:function:tsr-fn"}
  expect: {outcome: ALLOW, fidelity: approximate, reasons: ["AMBIGUITY:A14"]}
  why: "[S5a] Lambda is not in the RCP service list; attach-time behaviour unverified."  verified: pending-probe:A14
```

**Cross-account**

```yaml
- id: GC-52  title: Cross-account allow needs both sides
  principal: "arn:aws:sts::222222222222:assumed-role/Demo/s"   identity(Demo): [{"Statement":[{"Effect":"Allow","Action":"s3:*Object*","Resource":"arn:aws:s3:::tsr-prod/*"}]}]
  bucket tsr-prod owned by 111111111111, policy: {"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:role/Demo"},"Action":["s3:GetObject*","s3:PutObject*"],"Resource":"arn:aws:s3:::tsr-prod/*"}]}
  requests:
    - {action: s3:PutObject, resource: "arn:aws:s3:::tsr-prod/x"}    → ALLOW
    - {action: s3:DeleteObject, resource: "arn:aws:s3:::tsr-prod/x"} → DENY implicit (stage: resource_policy)
  why: "[S3] AWS's own cross-account example."  verified: doc

- id: GC-53  title: Cross-account with the bucket allowing but no identity allow
  "as GC-52 with Demo identity": []
  request: {action: s3:PutObject, resource: "arn:aws:s3:::tsr-prod/x"}
  expect: {outcome: DENY, deny_kind: implicit, stage: identity}   why: "[S3][S6] both evaluations must allow."  verified: doc

- id: GC-54  title: Cross-account where the bucket names the account principal
  "as GC-52, with bucket Principal": {"AWS":"222222222222"}
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-prod/x"}
  expect: {outcome: ALLOW}   why: "[S5][S6] the account delegates; Demo's identity policy allows."  verified: doc
```

**Role trust and AssumeRole**

```yaml
- id: GC-55  title: Cross-account AssumeRole needs an identity allow when the trust names the account
  role: "arn:aws:iam::111111111111:role/tsr-x" trust {"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"sts:AssumeRole"}]}
  principal: "arn:aws:iam::222222222222:user/dave"   identity: []
  request: {action: sts:AssumeRole, resource: "arn:aws:iam::111111111111:role/tsr-x"}
  expect: {outcome: DENY, deny_kind: implicit, stage: identity}   why: "[S18][S31] the trusted account must grant sts:AssumeRole."  verified: doc

- id: GC-56  title: An ExternalId condition with no ExternalId supplied
  role trust: {"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"tsr-42"}}}]}
  principal: "as GC-55"   identity: [{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}]
  request: {action: sts:AssumeRole, resource: "arn:aws:iam::111111111111:role/tsr-x"}   # sts:ExternalId absent
  expect: {outcome: DENY, deny_kind: implicit, stage: resource_policy}   why: "[S8] missing key ⇒ no match."  verified: doc

- id: GC-57  title: A same-account trust that names the user ARN, with no identity policy
  role trust: {"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/alice"},"Action":"sts:AssumeRole"}]}
  principal: U   identity: []
  request: {action: sts:AssumeRole, resource: "arn:aws:iam::111111111111:role/tsr-x"}
  expect: {outcome: ALLOW, fidelity: approximate, reasons: ["AMBIGUITY:A3"]}
  why: "The same-account RBP matrix applied to trust policies; not stated explicitly in the docs."  verified: pending-probe:A3

- id: GC-58  title: An identity allow alone cannot assume a role whose trust doesn't name the caller
  role trust: {"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
  principal: U   identity: [Allow*]
  request: {action: sts:AssumeRole, resource: "arn:aws:iam::111111111111:role/tsr-x"}
  expect: {outcome: DENY, deny_kind: implicit, stage: resource_policy}
  why: "[S1] role trust policies must explicitly allow the principal."  verified: doc

- id: GC-59  title: GitHub OIDC trust with a wildcard sub, symbolic and concrete
  role trust: {"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
     "Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
     "StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}]}
  requests:
    - {mode: symbolic, action: sts:AssumeRoleWithWebIdentity, caller: provider}
      → CONDITIONAL, residual: "…:aud = sts.amazonaws.com ∧ …:sub like repo:acme/*", nhi_flag: wildcard_oidc_trust
    - {mode: concrete, context: {…:aud: sts.amazonaws.com, …:sub: "repo:acme/web:ref:refs/heads/main"}} → ALLOW
    - {mode: concrete, context: {…:aud: sts.amazonaws.com, …:sub: "repo:evil/web:ref:refs/heads/main"}} → DENY implicit
  why: "[S5] OIDC federated principals; [S8] string operators."  verified: doc
```

**KMS** (key `K` = `arn:aws:kms:us-east-1:111111111111:key/k1`)

```yaml
- id: GC-60  title: Without the root-delegation statement, IAM policies are ineffective
  key_policy: {"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/kadmin"},"Action":"kms:*","Resource":"*"}]}
  principal: U   identity: [{"Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}]}]
  request: {action: kms:Decrypt, resource: K}
  expect: {outcome: DENY, deny_kind: implicit, stage: resource_policy}
  why: "[S13] 'Without this permission, IAM policies that allow access to the key are ineffective.'"  verified: doc

- id: GC-61  title: With the root-delegation statement, IAM policies work
  key_policy: {"Statement":[{"Sid":"Enable IAM User Permissions","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"kms:*","Resource":"*"}]}
  principal: "as GC-60"
  expect: {outcome: ALLOW}   why: "[S13]."  verified: doc

- id: GC-62  title: A grant with an encryption-context constraint
  key_policy: "as GC-60 (no delegation)"
  grant: {grantee: "arn:aws:iam::111111111111:role/app", operations: [Decrypt], constraints: {EncryptionContextEquals: {dept: "fin"}}}
  principal: RS   identity: []
  requests:
    - {action: kms:Decrypt, resource: K, context: {"kms:EncryptionContext:dept": fin}} → ALLOW (stage: kms_grant)
    - {action: kms:Decrypt, resource: K, context: {"kms:EncryptionContext:dept": hr}}  → DENY implicit
  expect_fidelity: exact
  why: "[S14] grants allow the listed operations under their constraints. A12b (whether a boundary caps a role-ARN grantee) is evaluated but not outcome-sensitive here, because the role has no boundary (§7.9)."  verified: doc

- id: GC-63  title: An identity-policy explicit deny overrides a grant
  "as GC-62 first request, with role identity": [{"Statement":[{"Effect":"Deny","Action":"kms:Decrypt","Resource":"*"}]}]
  expect: {outcome: DENY, deny_kind: explicit}   why: "[S14] grants cannot override a deny; [S13] IAM denies are always effective."  verified: doc

- id: GC-64  title: A cross-account non-cryptographic KMS operation is blocked whatever the policies say
  key_policy: {"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"kms:*","Resource":"*"}]}
  principal: "arn:aws:iam::222222222222:user/dave"   identity: [Allow*]
  request: {action: kms:ScheduleKeyDeletion, resource: K}
  expect: {outcome: DENY, deny_kind: guardrail, stage: special_rule}
  why: "[S15] cross-account permission is effective only for cryptographic operations, CreateGrant, DescribeKey, … ScheduleKeyDeletion 'still fails'."  verified: doc
```

**S3 ACLs, Object Ownership and Block Public Access**

```yaml
- id: GC-65  title: IgnorePublicAcls neutralizes a public-read ACL for anonymous callers
  bucket: {object_ownership: ObjectWriter, bpa: {bucket: {IgnorePublicAcls: true}}, object_acl(a.txt): [{grantee: AllUsers, perm: READ}]}
  principal: anonymous
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a.txt"}
  expect: {outcome: DENY, deny_kind: implicit, stage: s3_acl}   why: "[S17] IgnorePublicAcls ignores all public ACLs."  verified: doc

- id: GC-66  title: RestrictPublicBuckets blocks a cross-account statement inside a public policy
  bucket: {bpa: {bucket: {RestrictPublicBuckets: true}}}
  bucket_policy: {"Statement":[
     {"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"},
     {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}
  principal: "arn:aws:iam::222222222222:user/dave"   identity: [Allow*]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: DENY, deny_kind: guardrail, stage: s3_bpa}
  why: "[S17] statement 3 makes the policy public, so RestrictPublicBuckets disables Account-2's access (AWS's own example)."  verified: doc

- id: GC-67  title: BucketOwnerEnforced disables ACL grants
  bucket: {object_ownership: BucketOwnerEnforced, bucket_acl: [{grantee: canonical(222222222222), perm: READ}]}   # no bucket policy
  principal: "arn:aws:iam::222222222222:user/dave"   identity: [Allow*]
  request: {action: s3:ListBucket, resource: "arn:aws:s3:::tsr-bkt"}
  expect: {outcome: DENY, deny_kind: implicit, stage: resource_policy}   why: "[S16] ACLs disabled; no resource-side allow."  verified: doc

- id: GC-68  title: An anonymous public bucket policy works with BPA off
  bucket_policy: {"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}
  principal: anonymous
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: ALLOW}   why: "[S5] '*' with Allow grants public access."  verified: doc
```

**NotPrincipal**

```yaml
- id: GC-69  title: Listing only the role ARN in NotPrincipal still denies its sessions (account missing)
  principal: RS   role identity: [Allow*]
  bucket_policy: {"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111111111111:role/app"},"Action":"s3:*","Resource":["arn:aws:s3:::tsr-bkt","arn:aws:s3:::tsr-bkt/*"]}]}
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: DENY, deny_kind: explicit}
  why: "[S7] you must also list the account ARN; AWS may validate the account first."  verified: doc

- id: GC-70  title: NotPrincipal with Deny always denies a principal that has a boundary
  "as GC-69 with NotPrincipal": {"AWS":["arn:aws:iam::111111111111:root","arn:aws:iam::111111111111:role/app","arn:aws:sts::111111111111:assumed-role/app/s1"]}
  role boundary: [Allow*]
  expect: {outcome: DENY, deny_kind: explicit}   why: "[S7][S2] 'will always deny any IAM principal that has a permissions boundary'."  verified: doc

- id: GC-71  title: NotPrincipal listing the account and the role exempts the session (no boundary)
  "as GC-69 with NotPrincipal": {"AWS":["arn:aws:iam::111111111111:root","arn:aws:iam::111111111111:role/app"]}
  expect: {outcome: ALLOW, fidelity: approximate, reasons: ["AMBIGUITY:A4"]}
  why: "[S7] recommends listing the role and the account; whether the session ARN is also needed is unverified."  verified: pending-probe:A4
```

**Symbolic ("can ever") decisions**

```yaml
- id: GC-72  title: An MFA-conditioned allow gives a residual
  principal: RS (role app; template session)   mode: symbolic   profile: {}
  identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: CONDITIONAL, residual: "aws:MultiFactorAuthPresent = true"}
  why: "§9.4: the key is unknown for sessions."  verified: doc

- id: GC-73  title: A region deny becomes a residual under symbolic context
  principal: RS   mode: symbolic   identity: [Allow*,
     {"Statement":[{"Effect":"Deny","NotAction":["iam:*","sts:*"],"Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-west-1"]}}}]}]
  request: {action: sqs:SendMessage, resource: "arn:aws:sqs:eu-west-1:111111111111:tsr-q"}
  expect: {outcome: CONDITIONAL, residual: "aws:RequestedRegion present ∧ aws:RequestedRegion = eu-west-1"}
  why: "§9.4: RequestedRegion is unknown in symbolic mode, so the Deny's condition ψ stays symbolic and the result is Allow ∧ ¬ψ. If the key were absent, the negated operator would be true and the Deny would apply, which is why presence appears in the residual. The renderer drops the presence clause for keys the global-key table marks as always present."  verified: doc

- id: GC-74  title: A symbolic residual that simplifies to a constant
  principal: RS   mode: symbolic
  identity: [{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}},
                           {"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}]
  request: {action: s3:GetObject, resource: "arn:aws:s3:::tsr-bkt/a"}
  expect: {outcome: DENY, deny_kind: null}
  why: "§9.5: allow ∧ ¬deny = (x ∧ ¬x) on the same atom is unsatisfiable, so the result is DENY, not CONDITIONAL. deny_kind is null because it depends on context: a concrete request gives EXPLICIT when SecureTransport is true and IMPLICIT when it is false."  verified: doc
```

**Coverage.** These 74 cases (several of them with 2–3 requests each, so 85 assertions) cover every rule in §3.1. CI fails if a rule loses all of its cases. The rule ↔ case matrix is generated into `tests/aws_eval/golden/COVERAGE.md`. **Pending-probe cases** are A2 (GC-48), A3 (GC-57), A4 (GC-71), A14 (GC-51) and A17 (GC-23). They are run in the sandbox in the first harness night. If the probe disagrees, the default **and** the case are updated together in one PR.

---

## 15. Implementation plan: ordered, independently mergeable PRs

Every PR keeps `pytest` green for the existing MVP tests (`tests/test_graph.py`, `test_least_privilege.py` and others) and adds no behaviour change until PR-11 switches the AWS connector. Paths are relative to `mvp/backend/` unless they start with `infra/` or `mvp/harness/`.

| PR | Scope | Files | Tests | Depends on |
|---|---|---|---|---|
| **PR-1** | Core types and the policy parser: string-or-list normalization, the `Version` rule, every `Principal` form, condition parsing with qualifiers and IfExists, statement spans, validation and ingest anomalies (NotPrincipal+Allow, an invalid element mix, a multivalued variable). Hard limits on policy size and nesting; JSON parsed strictly. | `tessera/authz/core.py`, `tessera/aws/model.py`, `tessera/aws/policy/parse.py`, `tessera/aws/policy/lint.py` | `tests/aws_eval/test_parse.py`: round-trip, malformed input, a Hypothesis fuzz that never raises, span accuracy | — |
| **PR-2** | Catalog: the snapshot fetcher, compiler and loader; overlays (`rcp_services.yaml` with 62 prefixes, `kms_xacct_ops.yaml`, `global_keys.yaml`, `s3_acl_map.yaml`, `rbp_rules.yaml`, `opt_in_regions.yaml`, `s3_public_fixed_keys.yaml`); `THIRD_PARTY_NOTICES` for iam-dataset; the nightly refresh workflow that opens a PR | `catalog/aws/**`, `tessera/aws/catalog/{fetch,compile,loader}.py`, `.github/workflows/catalog-refresh.yml` | Loader and expansion tests; RCP list membership; offline fixtures for the diff report; a determinism test that the same inputs give the same compiled hash | — |
| **PR-3** | Matching: a **linear-time glob** (no backtracking regex, so it is safe against ReDoS), action matching, `arn_glob` with the A1 default, principal normalization and match kinds, NotPrincipal layering | `tessera/aws/eval/match.py`, `tessera/aws/eval/glob.py` | Table tests for each §8 rule; a property test that glob agrees with a reference regex on safe patterns; a worst-case pattern performance test; GC-04–GC-11 at the matcher level | PR-1 |
| **PR-4** | Conditions, context and residuals: operator families, the missing-key truth table, qualifiers, variables with defaults and escapes, type coercion, global-key derivation, Tri/Residual, the per-key domain simplifier, the renderer | `tessera/aws/eval/{cond,context,variables}.py`, `tessera/authz/residual.py` | Operator truth tables; GC-12–GC-30 at the condition level; a **soundness property test** (symbolic vs concrete over random total contexts); simplifier unit tests | PR-1, PR-2 |
| **PR-5** | The engine: the §7.2 pipeline, the principal-type matrix, SCP/RCP applicability per level, sessions, trust policies, cross-account, deny-kind selection, decisive sets, fidelity accumulation with outcome-sensitivity, the explanation builder and its three renderings | `tessera/aws/eval/{engine,explain,fidelity}.py`, `tests/aws_eval/golden/{basics,conditions,matrix,scp,rcp,xacct,trust,notprincipal,symbolic}.yaml`, `tests/aws_eval/test_golden.py` | **Golden corpus GC-01–GC-59 and GC-69–GC-74 at 100 %**; trace determinism (byte-identical JSON); generated rule-coverage matrix | PR-3, PR-4 |
| **PR-6** | KMS and S3: key-policy delegation, grants with constraints, the cross-account op allowlist, ACLs by ownership mode, effective BPA, `policy_is_public`, RestrictPublicBuckets, PUT-time BPA checks, object context | `tessera/aws/eval/{kms,s3}.py`, `tests/aws_eval/golden/{kms,s3}.yaml` | GC-60–GC-68; `policy_is_public` tests against the S3 doc examples and the Bouchet et al. categories | PR-5 |
| **PR-7** | Read-only AWS connector and persistence: an org/IAM/S3/KMS/SQS/SNS/Secrets/Lambda/ECR/VPCE/Identity Center collector producing a `Snapshot`; `aws_*` tables; registry entry `aws` (not the default); federated credentials only | `tessera/connectors/aws_org.py`, `tessera/models_aws.py`, `tessera/aws/snapshot.py`, `tessera/connectors/registry.py` (one line) | Connector tests with `moto` (collection only; moto does not enforce IAM) and botocore Stubber for the APIs moto lacks; snapshot content-hash stability; a least-privilege check of the connector's own IAM policy (it must contain only read actions, verified by our own catalog `Annotations`) | PR-1, PR-2 |
| **PR-8** | Harness foundation, offline: request specs, oracle clients (SimCustom, SimPrincipal, AA, probe), cassette record and replay, the comparator, M1–M4 and C, the Wilson-bound gate, the triage DB, a delta-debug minimizer, the CI replay job | `mvp/harness/tessera_harness/**`, `mvp/harness/tests/**`, `.github/workflows/harness-replay.yml` | Stubbed AWS responses: pagination, the `ResourceSpecificResults` aggregation trap, the `SourcePolicyType` enum mismatch, `MissingContextValues` ⇒ INVALID, throttling backoff; Wilson math; minimizer convergence | PR-5 |
| **PR-9** | Sandbox Terraform and the nightly harness: org, OUs, SCP/RCP fixtures, accounts, the test OIDC issuer, CloudTrail Lake, org analyzers, a scenario module per deployable GC case, the manifest, `probe_catalog.yaml`, the nightly workflow (manual approval for applies) | `infra/sandbox/**`, `mvp/harness/probe_catalog.yaml`, `.github/workflows/harness-nightly.yml` | `terraform validate`, `tflint`, `checkov`, and a policy test that every probe action is read-only, DryRun or confined to canaries. **Not applied until Phase 0 security sign-off (Q3).** | PR-8 |
| **PR-10** | Indexes and queries: action, resource and principal atoms; envelopes; inverted indexes; the memo; `effective_permissions()`, `who_can()`, `diff()`; incremental refinement; a synthetic scale generator | `tessera/aws/index/{atoms,envelope,inverted,memo}.py`, `tessera/aws/query.py`, `tests/aws_eval/test_query.py`, `tests/aws_eval/perf/` | Equivalence test: atom-based results equal brute force on small random snapshots. Perf test at 2× target scale (marked `slow`, run nightly) against the §12.1 SLOs | PR-5, PR-6 |
| **PR-11** | MVP integration: additive fields on `GrantEdge` and `EffectivePermission`; the connector emits evaluator-confirmed permissions and `can_assume` trust edges; `simulate()` gains `policy_changes`; leastpriv verification; NHI trust flags; `/api/aws/*` endpoints; the PR comment renderer | `tessera/models.py` (additive columns), `tessera/graph.py` (one relation), `tessera/simulate.py`, `tessera/leastpriv.py`, `tessera/nhi.py`, `tessera/api/app.py`, `tessera/aws/render/pr_comment.py` | All existing tests unchanged and green. New: an **exit-criterion-2 test** where a golden fixture plus a policy PR gives an exact gained/lost list with traces; API tests; a test that a least-privilege recommendation preserves the used set | PR-7, PR-10 |
| **PR-12** | Knowledge-base corrections (§4.4) and the ambiguity register as a living doc | `docs/knowledge/03-authorization-and-policy.md`, `docs/knowledge/aws-evaluation-ambiguities.md` | Docs only | can merge first |

The **critical path** is PR-1 → PR-3/PR-4 → PR-5 → PR-8 → PR-9 (first nightly). PR-6, PR-7 and PR-10 run in parallel after PR-5. Exit criterion 1 is first measurable after PR-9. Exit criterion 2 is demonstrable after PR-11.

Rough sizing, two engineers: PR-1 to PR-6 take about 4 weeks, PR-7 to PR-9 about 3 weeks, and PR-10 to PR-11 about 3 weeks. That fits Phase 1's 10 weeks, with probe-driven fixes overlapping.

---

## 16. Risks

Ranked by severity. Platform-security risks are listed first.

| # | Risk | Scenario | Mitigation |
|---|---|---|---|
| R1 | **Tessera's AWS reader is a crown jewel** | The read-only connector can read every policy in the org. Stolen, it maps the whole estate for an attacker. | Federated (OIDC/WIF) per-tenant role, no stored keys, read-only actions verified by our own catalog in CI (PR-7), Phase 0 audit ledger for every snapshot, bulk revocation path. iam-pam-nhi-expert to review. |
| R2 | **Policy JSON is untrusted input** | A crafted policy with a pathological wildcard (`*a*a*a…`) makes a backtracking regex hang the evaluator (ReDoS); a deep or oversized document exhausts memory. | Linear-time glob (PR-3), strict JSON parsing with size and depth caps above AWS's own limits, per-evaluation time budget, fuzzing (PR-1). |
| R3 | **Harness credentials and public fixtures** | Probe-user access keys leak; a public test bucket is abused. | Keys only in the sandbox, rotated daily, in Secrets Manager, never in CI logs; `SbxGuardrails` SCP; canary-only public data; budget alarms; no customer data in the sandbox. Blocked on Phase 0 sign-off. |
| R4 | **Undocumented AWS behaviour** | An ambiguity default is wrong, so a whole class of decisions is wrong. | The register (§4.3), outcome-sensitive `APPROXIMATE` flags, first-night probes, weekly re-probes to detect AWS changes. |
| R5 | **The oracle is wrong** | The simulator disagrees with live enforcement (AWS says results "can differ") and we "fix" the engine to match the simulator. | Probe-first routing for every category the simulator doesn't cover; a `known_divergence` entry requires probe evidence; ENGINE_BUG classification needs two concurring oracles. |
| R6 | **Sandbox not representative** | 99.5 % on fixtures, lower on real estates (odd services, huge policies, Identity Center ABAC). | Stratum S3 weighted by real CloudTrail frequencies; later, opt-in design-partner CloudTrail replay ("observed success that we predict as deny" = P1, as spec §6.2 says); per-service agreement published. |
| R7 | **Metric gaming or bias** | Flagging hard cases `UNSUPPORTED` raises M1. | Coverage floor C ≥ 97 %, per-stratum floors, unsupported volume reported next to M1. |
| R8 | **AWS changes semantics** | New policy types or language extensions (like the Sept 2025 SCP change) silently break the engine. | Nightly catalog diff, an RSS watch on What's New for IAM, Organizations and S3 tags, weekly ambiguity probes, engine version pinned per decision. |
| R9 | **Performance in Python** | Atoms explode under tag-heavy ABAC (many distinct `aws:ResourceTag` values). | Cap tag-value cardinality per key in signatures (fall back to symbolic tag predicates), shard by account, the Rust port as a planned step (spec EPE). |
| R10 | **Licence contamination** | Copying from PMapper or iam-simulate (AGPL) taints the product. | Clean-room rule in CONTRIBUTING, dependency licence scan in CI, no AGPL test data; iam-dataset and policy_sentry (MIT) data only with notices. |
| R11 | **Eventual consistency** | IAM, KMS grant or RCP propagation makes the harness report false divergences, and the product shows stale decisions. | Settle-and-reprobe; snapshot freshness SLO with a `SNAPSHOT_STALENESS` flag; the UI shows "as of" times. |
| R12 | **Explanations misread by auditors** | A long trace is taken as proof of something it doesn't say. | Templated wording reviewed by iam-governance-expert; the decisive set shown first; raw policy bytes attached. |

---

## 17. Open questions

| # | Question | Proposed answer | Owner |
|---|---|---|---|
| Q1 | The spec puts the EPE in Rust. Is a Python reference engine first acceptable? | Yes. The Python engine becomes the oracle that the Rust port must match (D1). | iam-architect, eng lead |
| Q2 | Gate thresholds: coverage floor 97 %? Do `APPROXIMATE` decisions count in M1? | Count them (they are our answer), and report the exact-only M1 separately. | Product + iam-authz-expert |
| Q3 | Who owns the sandbox org, its budget (≈ $300/month) and Phase 0 sign-off for harness credentials? | Security engineering owns it; Phase 0 must ship the audit ledger first. | Security lead |
| Q4 | Default assumption profile for effective-permission views. | `{now, tls}`, everything else symbolic. Show the profile chip in the UI. | UX + iam-authz-expert |
| Q5 | Phase 2 SMT backend (Z3, MIT, vs cvc5, BSD), and whether to reuse Cedar symcc's encoding ideas for IAM residuals. | Prototype both on residuals left `RESIDUAL_UNDECIDED`. | iam-authz-expert |
| Q6 | Model VPC endpoint policies exactly in Phase 1? | No. Approximate unless the request names the endpoint (§3.2). Revisit when network-path data exists. | iam-architect |
| Q7 | May we use AGPL iam-simulate as an additional black-box oracle (its outputs only, no code or data)? | Ask counsel. Until then, no. | Legal |
| Q8 | Retention period for snapshots and explanations (evidence). | Align with the governance doc (D4·M22): 7 years for SOX tenants, configurable. | iam-governance-expert |
| Q9 | CloudTrail replay in customer tenants (privacy, cost). | Opt-in, aggregated, read from the customer's CloudTrail Lake. | Product + privacy |
| Q10 | Identity Center ABAC (attributes from the IdP as principal tags): Phase 1 or later? | Phase 1 models permission sets; ABAC attributes come only from session context (`UNSUPPORTED` otherwise). | iam-authn-expert |
| Q11 | Report confirmed simulator and doc discrepancies to AWS? | Yes, through a partner channel. It builds credibility and shrinks the ambiguity register. | iam-architect |

---

## 18. Sources (AWS docs read 2026-10-08 unless noted)

- **[S1]** IAM, "How AWS enforcement code logic evaluates requests to allow or deny access": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html
- **[S2]** IAM, "Permissions boundaries for IAM entities": https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
- **[S3]** IAM, "Cross-account policy evaluation logic": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html. See also "Cross account resource access in IAM": https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html
- **[S4]** Organizations, "SCP evaluation": https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html
- **[S4a]** Organizations, "Service control policies": https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- **[S4b]** Organizations, "SCP syntax": https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html
- **[S5]** IAM, "AWS JSON policy elements: Principal": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
- **[S5a]** Organizations, "Resource control policies": https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
- **[S5b]** Organizations, "RCP syntax": https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_syntax.html
- **[S6]** IAM, "Policies and permissions" (policy types, session policies, root user): https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html, plus https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html and https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html
- **[S7]** IAM, "NotPrincipal": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html
- **[S8]** IAM, "Condition operators": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
- **[S9]** IAM, "Single-valued vs. multivalued context keys": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
- **[S10]** IAM, "Policy variables and tags": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
- **[S11]** IAM, "Resource": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html
- **[S12]** IAM, "NotAction": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html, and "NotResource": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html
- **[S13]** KMS, "Default key policy": https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html
- **[S14]** KMS, "Grants in AWS KMS": https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
- **[S15]** KMS, "Allowing users in other accounts to use a KMS key": https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying-external-accounts.html
- **[S16]** S3, "How Amazon S3 authorizes a request": https://docs.aws.amazon.com/AmazonS3/latest/userguide/how-s3-evaluates-access-control.html
- **[S17]** S3, "Blocking public access to your Amazon S3 storage": https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- **[S18]** IAM, "IAM roles: terms and concepts" (role chaining): https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html
- **[S19]** IAM, "AWS global condition context keys": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
- **[S20]** IAM API, `SimulatePrincipalPolicy`: https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html
- **[S21]** IAM API, `SimulateCustomPolicy`: https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html
- **[S22]** IAM API, `EvaluationResult` / `ResourceSpecificResult` / `ContextEntry` / `Statement`: https://docs.aws.amazon.com/IAM/latest/APIReference/API_EvaluationResult.html, https://docs.aws.amazon.com/IAM/latest/APIReference/API_ResourceSpecificResult.html, https://docs.aws.amazon.com/IAM/latest/APIReference/API_ContextEntry.html
- **[S23]** IAM API, `OrderedOrganizationPolicyType` / `PolicyIdentifier`: https://docs.aws.amazon.com/IAM/latest/APIReference/API_OrderedOrganizationPolicyType.html, https://docs.aws.amazon.com/IAM/latest/APIReference/API_PolicyIdentifier.html
- **[S24]** IAM, "Testing IAM policies with the IAM policy simulator": https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html
- **[S25]** Access Analyzer API: `CheckAccessNotGranted`, `CheckNoNewAccess`, `CheckNoPublicAccess`, `ValidatePolicy`: https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckAccessNotGranted.html (and siblings)
- **[S26]** "IAM Access Analyzer custom policy checks": https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-checks-validating-policies.html
- **[S27]** Access Analyzer resources and concepts: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html, pricing https://aws.amazon.com/iam/access-analyzer/pricing/
- **[S28]** Access Analyzer API `ExternalAccessDetails` / `InternalAccessDetails`: https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ExternalAccessDetails.html, https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_InternalAccessDetails.html
- **[S29]** IAM, "Troubleshoot access denied error messages": https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html
- **[S30]** AWS What's New (2025-09-19), "AWS Organizations supports full IAM policy language for SCPs": https://aws.amazon.com/about-aws/whats-new/2025/09/aws-organizations-iam-language-service-control-policies
- **[S31]** IAM, "Grant a user permissions to switch roles": https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_permissions-to-switch.html
- **[S32]** Service Authorization Reference, "Simplified AWS service information for programmatic access": https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html
- **OSS (repositories and licences checked 2026-10-08 via the GitHub API or npm):**
  - salesforce/cloudsplaining (BSD-3-Clause)
  - duo-labs/parliament (BSD-3-Clause)
  - Netflix-Skunkworks/policyuniverse (Apache-2.0)
  - nccgroup/PMapper (AGPL-3.0)
  - iann0036/iamlive (MIT)
  - iann0036/iam-dataset (MIT)
  - salesforce/policy_sentry (MIT)
  - DataDog/pathfinding.cloud (Apache-2.0)
  - act-security-labs/iam-simulate (formerly cloud-copilot; AGPL-3.0-or-later)
  - DataDog/iamspy (not verified)
- **Papers** (DOIs as recorded by the research agent, not independently re-verified):
  - Backes et al., "Semantic-based Automated Reasoning for AWS Access Policies using SMT", FMCAD 2018
  - Backes et al., "Stratified Abstraction of Access Control Policies", CAV 2020
  - Bouchet et al., "Block Public Access: Trust Safety Verification of Access Control Policies", ESEC/FSE 2020
  - Cutler et al., "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization", OOPSLA 2024
  - Disselkoen et al., "How We Built Cedar: A Verification-Guided Approach", FSE 2024 Companion
  - Chakarov et al., "Formally Verified Cloud-Scale Authorization", ICSE 2025
