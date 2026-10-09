# 03 — Authorization Models, Policy Languages and Zero Trust

*Tessera knowledge base. Research as of 2026-10-08. Where a claim could not be confirmed against a primary source it is marked **[unverified]**. Vendor claims are labelled as such.*

---

## 1. Scope and why it matters

Authorization is the question "may this principal perform this action on this resource, in this context, right now?" Authentication proves who a principal is. Authorization decides what that principal is allowed to do. For Tessera this is the core domain. The product positioning (entitlements as Cedar policy in Git, blast-radius simulation, usage-based least privilege) assumes Tessera can do three hard things:

1. **Represent** entitlements across heterogeneous systems (AWS, Azure, GCP, Kubernetes, Snowflake, Databricks, BigQuery, SaaS, in-house apps) in one model that people can review.
2. **Compute effective permissions** exactly the way each target system's own enforcement code does, including denies, guardrails, boundaries, conditions, inheritance and session scoping. A blast-radius number that disagrees with the cloud's real decision is worse than having no number.
3. **Change entitlements safely** through a policy-as-code workflow: diff, test, prove properties, simulate, approve, deploy and detect drift.

This document covers the theory (DAC/MAC/RBAC/ABAC/ReBAC/PBAC), the standards (NIST RBAC, NIST SP 800-162, XACML, Zanzibar, AuthZEN, NIST SP 800-207, CISA ZTMM), the engines (Cedar, OPA, Topaz, Cerbos, Oso, Casbin, OpenFGA, SpiceDB and others), and the exact evaluation logic of AWS, Azure and GCP plus the main data platforms. It ends with concrete requirements for Tessera.

Market context as of late 2025 and 2026: the authorization layer is consolidating and standardizing.
- Cedar joined the CNCF Sandbox (October 2025).
- OpenFGA moved to CNCF Incubating (October 2025).
- OpenID AuthZEN Authorization API 1.0 became a Final Specification (January 2026).
- OPA's core maintainers moved to Apple (August 2025), and Styra's commercial products are being open-sourced.
- Permify was acquired by FusionAuth (November 2025).
- Aserto shut its SaaS (May 2025), and Topaz continues as open source.
- Warrant became WorkOS FGA (2024).

The result is a "standard PDP API plus a few dominant open languages" market. That favours a platform that sits above engines rather than competing with them.

---

## 2. Core concepts (precise definitions)

**Subject / principal.** The entity requesting access: a human user, group, service account, workload identity, role session or AI agent. In cloud IAM the *principal* that makes the request is often a derived session (for example an AWS assumed-role session), not the underlying role.

**Resource / object.** The thing being accessed, such as an S3 bucket, a Snowflake table, a document or a Kubernetes namespace.

**Action / permission / privilege.** An operation on a resource, such as `s3:GetObject`, `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`, `bigquery.tables.getData` or Snowflake `SELECT`.

**Entitlement.** A durable grant that links a subject to a permission set on a scope. Examples are a role assignment, an IAM policy attachment, a group membership that implies a role, or a Snowflake `GRANT`. Entitlements are what IGA systems certify. Permissions are what enforcement points evaluate.

**Effective permission.** The set of (action, resource, condition) tuples a principal can actually exercise after every grant, deny, guardrail, boundary, condition, inheritance rule and session restriction has been applied. This is the central computed artifact for Tessera.

**PEP / PDP / PIP / PAP** (from XACML and NIST SP 800-162):
- *Policy Enforcement Point (PEP)*: intercepts the request and enforces the decision.
- *Policy Decision Point (PDP)*: evaluates policy and returns permit or deny (plus obligations or advice).
- *Policy Information Point (PIP)*: supplies attributes or relationship data to the PDP.
- *Policy Administration Point (PAP)*: where policies are authored and managed.

**Discretionary Access Control (DAC).** Owners of objects decide who else gets access. Examples are Unix permission bits, file-share ACLs and Snowflake object ownership. DAC is flexible, but rights propagate without central control.

**Mandatory Access Control (MAC).** A central authority assigns security labels, and the system enforces rules that users cannot override. Classic examples are Bell–LaPadula (no read up, no write down, for confidentiality) and Biba (integrity). Modern equivalents include SELinux type enforcement and data-classification-driven masking.

**Access Control List (ACL).** A per-object list of (subject, rights) pairs. It answers "who can access this object?" cheaply and "what can this subject access?" expensively.

**Capability.** An unforgeable token held by the subject that names an object and rights, for example a signed URL, a macaroon or an OAuth access token with a narrow scope. It answers "what can I access?" cheaply. Revocation is hard.

**Role-Based Access Control (RBAC).** Permissions are assigned to roles, and users are assigned to roles. NIST RBAC defines Core RBAC, Hierarchical RBAC (role inheritance), Static Separation of Duty (SSD, constraints on assignment) and Dynamic Separation of Duty (DSD, constraints on which roles can be activated together in one session).

**Role explosion.** RBAC's failure mode. Encoding context (region, tenant, project, data sensitivity) into role names multiplies roles combinatorially. Microsoft's Azure ABAC documentation gives an example where a per-customer container layout would need about 256,000 role assignments but can be replaced by one condition.

**Attribute-Based Access Control (ABAC).** Decisions are computed from attributes of the subject, resource, action and environment, evaluated against policy (NIST SP 800-162). It removes role explosion but makes "who can access X?" harder to answer without attribute inventory.

**Relationship-Based Access Control (ReBAC).** Access derives from a graph of relationships, for example "user is editor of doc", "doc is in folder" and "editors of a folder are editors of its docs". This is popularised by Google Zanzibar. It is natural for collaborative apps, hierarchies and multi-tenant SaaS.

**Policy-Based Access Control (PBAC).** An umbrella term, used mostly by vendors and analysts, for authorization expressed as centrally managed, versioned policies, usually in a policy language and usually combining RBAC, ABAC and ReBAC. In practice "PBAC" and "policy-as-code authorization" mean the same thing.

**Next Generation Access Control (NGAC).** A NIST graph-based ABAC model (standardized as ANSI INCITS 499/525/526 family). It is relevant mainly as prior art for graph-plus-attribute models.

**Explicit deny / implicit deny.** Implicit deny is the default outcome when nothing grants. Explicit deny is a policy statement that forbids and overrides any allow.

**Guardrail / boundary.** A policy that cannot grant, only cap. Examples are AWS SCPs, RCPs and permissions boundaries, GCP principal access boundaries, and the effect of Azure deny assignments. Effective permission is the intersection of grants and guardrails.

**Least privilege.** Each principal holds only the permissions needed for its task, for only as long as needed.

**Standing vs just-in-time (JIT) access.** Standing access persists until it is removed. JIT access is granted on demand, usually with approval, and expires automatically. **Zero Standing Privilege (ZSP)** is the target state where privileged permissions exist only during an active, approved session.

**Zero Trust (ZT).** NIST SP 800-207 defines it as a set of principles that remove implicit trust based on network location and evaluate each access request per session, using dynamic policy over identity, device and context.

**Consistency token / zookie.** In Zanzibar, an opaque token encoding a snapshot timestamp. Clients pass it so that a check is evaluated against data at least as fresh as a given write. This prevents the "new enemy" problem.

**Policy drift.** Divergence between the intended policy (in Git) and the deployed or effective state. Causes include out-of-band changes, ClickOps, emergency access left in place and provider-side changes to managed policies.

---

## 3. Standards, models and specifications

| Name | Body | Version / status (as of Oct 2026) | Link |
|---|---|---|---|
| RBAC standard | ANSI/INCITS (from NIST model by Sandhu, Ferraiolo, Kuhn) | INCITS 359-2004, revised INCITS 359-2012 [revision year from memory, unverified] | https://csrc.nist.gov/projects/role-based-access-control |
| NIST SP 800-162, *Guide to ABAC Definition and Considerations* | NIST | Published Jan 2014 (with later updates) | https://csrc.nist.gov/pubs/sp/800/162/upd2/final |
| NIST SP 800-178 (comparison of XACML and NGAC) | NIST | Final, 2016 | https://csrc.nist.gov/pubs/sp/800/178/final |
| XACML 3.0 | OASIS | OASIS Standard (2013, errata later). Mature, with low new adoption | https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html |
| NGAC | INCITS | Standards 499 / 525 / 526 [unverified exact numbers] | https://csrc.nist.gov/projects/policy-machine |
| Google Zanzibar paper | USENIX ATC 2019 | Published paper (not a standard) | https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/ |
| OpenID AuthZEN Authorization API 1.0 | OpenID Foundation, AuthZEN WG | **Final Specification**, approved and announced 12 Jan 2026 (81 for, 1 against, 25 abstain) | https://openid.net/specs/authorization-api-1_0-final.html |
| AuthZEN Authorization Claims | IETF individual draft (Gazitt) | draft-gazitt-oauth-authzen-claims-01 (Sep 2026). Individual submission, not WG | https://www.ietf.org/archive/id/draft-gazitt-oauth-authzen-claims-01.html |
| Cedar language and spec | AWS-originated, now CNCF | CNCF **Sandbox** since 8 Oct 2025. Language reference v4.5. SDK crates 4.1x | https://www.cncf.io/projects/cedar/ |
| Open Policy Agent / Rego | CNCF | **Graduated** (since 2021). OPA 1.x with Rego v1 default since OPA 1.0 (Dec 2024). Latest 1.20.x reported [patch level unverified] | https://www.openpolicyagent.org/ |
| OpenFGA | CNCF | **Incubating** since 28 Oct 2025 | https://www.cncf.io/projects/openfga/ |
| NIST SP 800-207, *Zero Trust Architecture* | NIST | Final, Aug 2020 | https://csrc.nist.gov/pubs/sp/800/207/final |
| NIST SP 800-207A, *ZTA Model for Access Control in Cloud-Native Apps in Multi-Location Environments* | NIST | Final, Sep 2023 | https://csrc.nist.gov/pubs/sp/800/207/a/final |
| CISA Zero Trust Maturity Model | CISA | v2.0, Apr 2023 | https://www.cisa.gov/zero-trust-maturity-model |
| BeyondCorp | Google (papers 2014–2018) | Industry reference architecture | https://cloud.google.com/beyondcorp |
| OAuth 2.0 Rich Authorization Requests | IETF | RFC 9396 (2023) | https://www.rfc-editor.org/rfc/rfc9396 |
| SPIFFE / SPIRE (workload identity used in 800-207A) | CNCF | Graduated | https://spiffe.io/ |

### Notes on the key standards

**NIST RBAC (INCITS 359).** It has four components:
- *Core*: USERS, ROLES, PERMS, OPS, OBS, user assignment (UA), permission assignment (PA) and sessions.
- *Hierarchical*: either a general partial order or a limited (tree) hierarchy. Senior roles inherit junior roles' permissions.
- *SSD*: mutually exclusive role assignments.
- *DSD*: mutually exclusive role activations within a session.

Sessions matter because the permissions a user *can* activate are not the same as the permissions active *now*. AWS role sessions and Snowflake primary and secondary roles are real-world examples.

**NIST SP 800-162 (ABAC).** It defines ABAC as access decisions made by evaluating subject, object, operation and environment attributes against policy. It separates the enterprise concerns of attribute governance, attribute authority and trust from the mechanism. Its main lesson for Tessera: ABAC is only as good as the provenance and freshness of attributes.

**XACML 3.0.** It introduced the PAP/PDP/PEP/PIP architecture. Its policy structure is PolicySet → Policy → Rule, each with Target, Condition, Effect, Obligations and Advice. Combining algorithms resolve conflicts: deny-overrides, permit-overrides, first-applicable, only-one-applicable, deny-unless-permit and permit-unless-deny. XACML's XML syntax is widely considered unergonomic. Its architecture vocabulary survives in AuthZEN and every modern engine.

**AuthZEN Authorization API 1.0 (Final).** It standardizes the PEP→PDP wire protocol, not the policy language. Contents:
- *Information model*: Subject `{type, id, properties}`, Resource `{type, id, properties}`, Action `{name, properties}` and free-form Context. The Decision is a boolean plus optional context.
- *Endpoints*:
  - `POST /access/v1/evaluation` for a single decision.
  - `POST /access/v1/evaluations` for batched ("boxcarred") decisions, with semantics `execute_all` (default), `deny_on_first_deny` and `permit_on_first_permit`.
  - Search endpoints under `/access/v1/search/` for subject search, resource search and action search.
  - PDP metadata discovery at `/.well-known/authzen-configuration`.
- *Binding*: HTTPS/JSON. A denial is HTTP 200 with `"decision": false`.

Interop demonstrations have included Topaz, Cerbos, OpenFGA-based PDPs, Axiomatics, PingAuthorize and others [the exact interop roster is unverified]. AuthZEN is the natural integration surface for Tessera's application-authorization ambitions.

**Zanzibar (2019).** Google's global authorization system for Drive, YouTube, Cloud and others:
- *Data*: relation tuples `object#relation@user`, where the user can be a userset `object#relation`.
- *Schema*: namespace configs with userset rewrites (union, intersection, exclusion, `computed_userset` and `tuple_to_userset`).
- *APIs*: Check, Read, Write, Watch and Expand.
- *Consistency*: zookies, built on Spanner's TrueTime. Clients store a zookie with content on writes and pass it on checks, so ACL changes and content changes are ordered (avoiding the "new enemy" problem).
- *Performance*: the Leopard indexing system flattens deeply nested group membership. The paper reports trillions of tuples and millions of checks per second at low latency.

**NIST SP 800-207.** It describes the logical components:
- *Policy Engine (PE)* plus *Policy Administrator (PA)*, which together form the Policy Decision Point.
- *Policy Enforcement Point (PEP)*.
- Inputs: CDM system, industry compliance, threat intelligence, activity logs, data access policy, PKI, ID management and SIEM.

It lists seven tenets. Among them: all data sources and services are resources; all communication is secured regardless of location; access is granted per session; access is determined by dynamic policy; asset posture is monitored; authentication and authorization are dynamic and strictly enforced; and telemetry is collected to improve posture. Deployment variants include enhanced identity governance, micro-segmentation and network/SDP. **SP 800-207A** (2023) applies this to cloud-native and multi-cloud apps. It defines policies at a network tier and an identity tier, enforced through gateways, service mesh sidecars and SPIFFE-style workload identities.

**CISA ZTMM v2.0 (April 2023).**
- *Five pillars*: Identity, Devices, Networks, Applications & Workloads, Data.
- *Three cross-cutting capabilities*: Visibility & Analytics, Automation & Orchestration, Governance.
- *Four maturity stages*: Traditional, Initial (new in v2), Advanced, Optimal.

For Tessera, the Identity pillar's "Optimal" stage (continuous validation, automated JIT and least-privilege access) and the Applications & Workloads and Data pillars' fine-grained, policy-based authorization are what the product must map to.

**BeyondCorp.** Google's model removes the privileged network: access-aware proxies, a device inventory and trust tiers, decided per request. Commercial descendants include Google BeyondCorp Enterprise / Chrome Enterprise Premium, Cloudflare Access and Zscaler Private Access.

---

## 4. How it works

### 4.1 Generic decision flow

```
 Request ──► PEP ──(AuthZEN: subject, action, resource, context)──► PDP
                                                                    │
                                     ┌──────────────────────────────┤
                                     ▼                              ▼
                              Policy store (PAP)        PIP: attributes / relationship graph
                                     │                              │
                                     └────────► evaluate ◄──────────┘
                                                  │
                     decision {permit|deny, obligations, reasons} ──► PEP enforces + logs
```

Engines differ on four axes:
- **Where the data lives.** Stateless engines (Cedar, OPA, Cerbos) receive entities and attributes with the request or from a cache. Stateful engines (Zanzibar-style) own a relationship store.
- **Conflict resolution.** Deny-overrides is the most common. Ordered or first-applicable resolution is rarer.
- **Expressiveness vs analyzability.** Rego is Datalog-like and very expressive. Cedar is deliberately restricted so it can be compiled to SMT.
- **Query modes.** Engines support some subset of check, list-objects (what can X access?), list-subjects (who can access Y?) and partial evaluation / query plans (turning policy into a SQL WHERE clause).

### 4.2 Cedar evaluation semantics

- A policy is `permit` or `forbid`, with a scope (`principal`, `action`, `resource`, including `in` hierarchy constraints) plus `when` and `unless` conditions.
- **Decision rule.** If any `forbid` is satisfied, the result is Deny. Otherwise, if any `permit` is satisfied, the result is Allow. Otherwise the result is Deny (implicit). Policy order is irrelevant.
- **Errors.** A policy whose condition errors is skipped, so it neither permits nor forbids. The schema validator is intended to rule such errors out ahead of time.
- **Data model.** Entities with a UID (`Type::"id"`), attributes, parent entities (forming a DAG for `in`) and, since language 4.1, *entity tags* (key-value maps accessed with `hasTag` / `getTag`). Templates (`?principal`, `?resource`) support per-grant instantiation, which is effectively ReBAC-style tuples as policies.
- **Analyzability.** The language is not Turing-complete: no loops and no user-defined recursion. Validation is schema-based typechecking. The authorizer and validator are modelled in Lean, with proofs of properties such as "forbid trumps permit" and type soundness, and the Rust implementation is checked against the Lean model by differential random testing. The team reports finding and fixing 4 validator bugs through proofs and 21 more bugs through differential and property-based testing.
- **Symbolic analysis.** The `cedar-policy-symcc` crate compiles policies to SMT (it uses cvc5) and decides:
  - policy-set equivalence
  - subsumption ("does the new policy set allow strictly less?")
  - disjointness
  - always-allows / always-denies

  It returns concrete counterexample requests and entity stores. AWS says the symbolic encoding is proved correct, and its 2026 SymCert paper verifies five analyses used in an AWS Cedar analysis service. The Cedar Analysis CLI demonstrates policy-set comparison and redundancy detection.

### 4.3 OPA / Rego evaluation semantics

- Rego is a Datalog-derived query language. Policies define rules (for example `allow if { ... }`) over `input` (the request) and `data` (loaded documents).
- There is no built-in deny-override. Combination is whatever the author encodes, typically `default allow := false` plus `deny contains msg if ...`.
- OPA 1.0 (Dec 2024) made Rego v1 the default. `if` and `contains` are required, `input` and `data` are reserved, and the server binds to localhost by default.
- Strengths: general-purpose (Kubernetes admission via Gatekeeper, Terraform plans via conftest, Envoy external authorization, CI checks) and partial evaluation for data filtering. Weaknesses: there is no formal decidable analysis comparable to Cedar's, so policy equivalence and "who can access X" are not answerable in general, and authorization data has to be pushed in through bundles.

### 4.4 Zanzibar-style evaluation

- **Check** walks the userset-rewrite graph from `object#relation` to the user. It handles union, intersection and exclusion, and `tuple_to_userset` hops (for example, a doc's parent folder's viewers).
- **Consistency.**
  - *Zanzibar*: zookies. Clients default to roughly ~5 s stale snapshots for cache hit rates, or "at least as fresh as zookie Z".
  - *SpiceDB*: ZedTokens with the modes `minimize_latency`, `at_least_as_fresh`, `at_exact_snapshot` and `fully_consistent`.
  - *OpenFGA*: a `consistency` preference of `MINIMIZE_LATENCY` or `HIGHER_CONSISTENCY`, with no client-held snapshot token [current absence of a zookie equivalent unverified].
  - *Permify*: "snap tokens".
- **Reverse queries.** Zanzibar engines offer ListObjects / LookupResources and ListUsers / LookupSubjects. Pre-computation (Google's Leopard; AuthZed Materialize, reportedly GA for Dedicated Cloud in Sep 2026 [third-party source]) is how they stay fast at scale.

### 4.5 AWS IAM effective-permission logic (precise)

**Policy types:**
- identity-based policies (managed and inline, on users, groups and roles)
- resource-based policies (bucket, KMS key, role trust, SQS and others)
- permissions boundaries (on users and roles)
- Organizations **SCPs** (cap principals in member accounts)
- Organizations **RCPs** (cap resources in member accounts)
- session policies (passed at AssumeRole or GetFederationToken)
- ACLs (legacy: S3 and others)
- VPC endpoint policies

**Single-account algorithm** (paraphrasing AWS's documented logic):

```
0. Default: implicit DENY (except the account root user).
1. Collect ALL applicable policies: SCPs, RCPs, resource-based, identity-based,
   permissions boundary, session policy (and endpoint policies where relevant).
2. If ANY applicable statement is an explicit Deny        → DENY (final).
3. RCPs: if none of the RCPs in the resource account's
   OU chain Allows the action                             → DENY.
   (RCPFullAWSAccess is auto-attached and undetachable, so this is
   effectively "deny unless an RCP Deny matched".)
4. SCPs: at EVERY level of the principal account's OU chain
   (root → OUs → account), some SCP must Allow             else DENY.
5. Resource-based policy: if it Allows the request principal, it can
   produce ALLOW even with no identity-policy allow, subject to the
   principal-type rules below.
6. Identity-based policies: if none Allow (and step 5 did not already
   decide)                                                 → DENY.
7. Permissions boundary (if set): must Allow              else DENY.
8. Session policy (if a session principal passed one): must Allow else DENY.
9.                                                          → ALLOW.
```

**Principal-type rules for same-account resource-policy grants.** These are subtle and essential for a correct engine:
- Granted to an **IAM user ARN**: not limited by an implicit deny in identity policies or the permissions boundary.
- Granted to an **assumed-role session ARN** or an **STS federated-user session ARN**: granted directly to the session. Not limited by an implicit deny in identity policy, boundary or session policy.
- Granted to an **IAM role ARN** (in `Principal` or via `aws:PrincipalArn`): the requester is actually the role session, so the grant *is* limited by an implicit deny in the permissions boundary or session policy. An exception is documented for a wildcard Principal with an `aws:PrincipalArn` condition.
- **Role trust policies and KMS key policies** must explicitly allow the principal even in the same account. An identity-policy allow alone is insufficient.

**Cross-account.** AWS evaluates the trusted (principal) account and the trusting (resource) account separately, and both must return Allow:
- the identity policy plus its limiters in the principal's account (SCPs, boundary, session)
- the resource policy plus its limiters in the resource's account (RCPs)

An explicit deny anywhere wins. AWS RAM policy fragments add another layer.

**Recent changes Tessera must model:**
- **RCPs** launched November 2024. Initial services were S3, STS, KMS, SQS and Secrets Manager. Cognito and CloudWatch Logs were added January 2026 and DynamoDB February 2026. A third-party vendor counts 44 service entries as of August 2026 [unverified]. Lambda, RDS, SNS, API Gateway and Bedrock reportedly lack RCP support [third-party, unverified].
- **SCPs support the full IAM policy language** (September 2025): conditions, individual resource ARNs, `NotAction` with Allow, `NotResource`, and wildcards anywhere in action strings. SCPs still don't apply to the management account or to service-linked roles.
  - The SCP syntax page still says that an SCP `Allow` statement may use only `"Resource": "*"`, not individual ARNs. That sentence predates the September 2025 launch and conflicts with it; Tessera follows the launch and lints the case as a warning (design ambiguity A2). Every SCP and RCP must have `"Version": "2012-10-17"`, and an RCP's `Principal` must be the bare string `"*"` (not `{"AWS": "*"}`).
- **Incomplete resource ARNs.** In identity-based policies AWS completes an ARN with fewer than six fields by adding `*` to every missing field: `arn:aws:sqs` means `arn:aws:sqs:*:*:*`, every SQS resource in every Region and account. Session policies passed to `AssumeRole*` reject incomplete ARNs (`MalformedPolicyDocumentException`). SCP behaviour is undocumented; Tessera completes them the same way and flags the result (design ambiguity A21).
- **IAM Access Analyzer**:
  - *External access* findings, from Zelkova automated reasoning over resource policies.
  - *Unused access* findings, from last-accessed data, plus recommendations to refine unused permissions (June 2024).
  - *Internal access* findings (June 2025). These cover S3, DynamoDB and RDS and use automated reasoning over identity policies, resource policies, SCPs and RCPs to list which in-org users and roles can reach critical resources. They are evaluated daily, and an error is raised past 3,000 principals.
  - *Custom policy checks*: CheckNoNewAccess, CheckAccessNotGranted and CheckNoPublicAccess, suited to CI.
- **Zelkova** translates IAM policies into SMT formulas and checks properties such as "is this bucket public?". It underpins Access Analyzer and S3 Block Public Access reasoning.

### 4.6 Azure RBAC + ABAC + deny assignments (precise)

**Model.** A role assignment is (security principal, role definition, scope). Principals are users, groups (transitive membership counts), service principals and managed identities. Scopes form a hierarchy: management group → subscription → resource group → resource. Assignments inherit downward. A role definition holds `Actions`, `NotActions`, `DataActions` and `NotDataActions`, plus `AssignableScopes`. Azure RBAC is **additive**: effective permissions are the union of all applicable assignments.

**Evaluation** (Azure Resource Manager and data planes integrated with Azure RBAC):
```
1. Principal obtains token (includes transitive group memberships*).
2. ARM gathers all role assignments AND deny assignments applicable to the resource
   (at its scope and all ancestor scopes).
3. If any deny assignment applies to the principal + action      → DENY.
4. Filter role assignments to this principal (direct or via group).
5. Effective = (Actions − NotActions) for management plane;
               (DataActions − NotDataActions) for data plane.
   NotActions is subtraction, NOT a deny: another role can re-grant.
6. If no role grants the action at this scope                     → DENY.
7. If the granting assignment(s) carry conditions (ABAC), evaluate;
   access granted if at least one granting assignment's conditions pass.
8.                                                                → ALLOW.
```
\* Group overage for large memberships is handled by Entra ID through a graph lookup.

**Azure ABAC conditions** are expressions on role assignments over `@Request`, `@Resource`, `@Environment` and `@Principal` attributes. Principal attributes are Entra *custom security attributes*. Conditions are GA for Blob Storage, ADLS Gen2 and Queues, both standard and premium, with some attributes still in preview. Principal attributes in conditions have been GA since November 2023. Conditions do not apply to management actions through the storage resource provider. Conditions are also used to **constrain delegation**, by limiting which roles a delegate may assign and to whom [GA date unverified].

**Deny assignments.** Historically, customers cannot create them directly. They are created by Azure, for example for Managed Applications and **Deployment Stacks `denySettings`**. A deny assignment can exclude principals. API and SDK tooling (`2024-07-01-preview`) exposes create and delete of *user-assigned* deny assignments, but in at least one May 2026 report this was gated per subscription [general availability unverified].

**Separate planes to model:**
- *Microsoft Entra roles*: directory roles, a different RBAC system with administrative units.
- *Azure Policy*: configuration compliance and `deny` / `denyAction` effects on resource operations. It is not identity authorization, but it blocks operations.
- *Data-plane systems with their own ACLs*: ADLS POSIX ACLs (evaluated after RBAC: if RBAC grants, ACLs are not checked), Key Vault access policies (legacy) vs RBAC, SQL database permissions and Cosmos DB data-plane RBAC.
- *Privileged Identity Management (PIM)*: eligible vs active assignments, time-bound activation and approval.

### 4.7 GCP IAM (precise)

**Policy types:**
- **Allow policies (IAM policies)** attached to resources across the hierarchy: organization → folders → project → resource. Bindings are (role, members, optional condition). Inheritance is the union of ancestors' allow policies, and a child cannot remove an inherited grant.
- **Deny policies** (IAM v2 API) attached to an organization, folder or project. Deny rules name denied principals, exception principals, denied permissions (in `service.googleapis.com/resource.verb` format), exception permissions and an optional condition. Deny conditions support only resource-tag functions. **If a deny condition evaluates true or cannot be evaluated, the deny applies** (fail closed).
- **Principal Access Boundary (PAB) policies** (IAM v3 API) are bound to *principal sets*: workforce or workload identity pools, Workspace domains, projects, folders, organizations and agent identities. They define which resources a principal is *eligible* to access. They can only block permissions covered by their *enforcement version*, and they fail closed on evaluation error. Limits are 500 rules per policy, 1,000 policies per organization and 10 policies per principal set.
- **Access policies** (newer; currently for Eventarc) can ALLOW or DENY.
- **IAM Conditions**: CEL expressions on allow-policy role bindings, using request time, resource name and type, tags and others. They are supported only on some resource types, and basic roles cannot be conditioned.

**Evaluation** (Google describes it as simultaneous evaluation, explained as stages):
```
1. PAB: if principal is subject to ≥1 PAB policy and NONE makes it eligible for the
   resource (for a permission in the enforcement version)        → DENY.
2. Deny policies on the resource's ancestry (org, folders, project): if any rule
   denies the permission to the principal (not excepted; condition true or
   unevaluable)                                                  → DENY.
3. Allow policies on resource + all ancestors: if some binding grants a role
   containing the permission to the principal (directly or via group /
   domain / principalSet) with condition true                    → ALLOW, else DENY.
```

**Orthogonal controls that also block requests:** VPC Service Controls perimeters (context and network-based), Organization Policy constraints (for example domain-restricted sharing, which limits who *can be granted*), and service-specific ACLs (legacy GCS ACLs, BigQuery dataset ACLs). The Policy Troubleshooter (v3) explains allow, deny and PAB decisions. Policy Simulator and the PAB simulator support pre-change simulation. Privileged Access Manager (PAM) provides JIT grants.

**Key escalation primitive in GCP:** `iam.serviceAccounts.actAs` (implicit in deploying compute as a service account), `getAccessToken`, `signBlob`/`signJwt`, `setIamPolicy` on anything, and service account key creation.

### 4.8 Data-platform authorization

**Snowflake.** It combines DAC (every object is *owned* by a role, and the owner can grant), RBAC (privileges granted to roles, roles granted to roles to form a hierarchy, roles granted to users) and user-based access (privileges granted directly to users are considered only when secondary roles are ALL).
- *System roles*: ORGADMIN, ACCOUNTADMIN, SECURITYADMIN, USERADMIN, SYSADMIN and PUBLIC.
- *Database roles* are scoped to a database and cannot be activated directly. They must be granted to account roles.
- *Sessions*: a session has one *primary* role (which owns created objects) plus *secondary* roles. Since BCR 2024_08, an unset `DEFAULT_SECONDARY_ROLES` became `('ALL')`, so by default a user's effective privileges are the union of **all granted roles**. That materially widens effective access and makes "role in use" analysis less informative.
- *Other features*: managed access schemas (centralise grant authority in the schema owner), future grants, and row access policies and masking policies (including tag-based masking) as ABAC-like controls.

Effective-permission computation needs the transitive closure of role-to-role grants, the ownership chain, future grants and policy attachments.

**Databricks Unity Catalog.**
- *Securables*: metastore → catalog → schema → table/view/volume/function/model, plus external locations, storage credentials and connections.
- *Privileges* (SELECT, MODIFY, USE CATALOG, USE SCHEMA, BROWSE, MANAGE, EXECUTE and others) inherit downward. Owners have full control. Workspace-catalog bindings restrict where catalogs can be used.
- *ABAC policies*: row-filter and column-mask policies driven by **governed tags** and automated data classification, attached at catalog, schema or table level and backed by UDFs. Databricks announced these as GA [exact GA date unverified]. ABAC "GRANT" policies remain Beta (currently EXECUTE on models). They require DBR 16.4+ or serverless.

**BigQuery.** It uses GCP IAM at the organization, folder, project, dataset, table and view levels, plus:
- authorized views, routines and datasets
- **row-level access policies** (filter expression plus grantees; admins do not bypass them and must be added to a `TRUE` filter)
- **column-level security** via Data Catalog policy tags, with optional dynamic masking

Newer *data governance tags*, based on Resource Manager tags, were introduced in preview in July 2026.

### 4.9 Least privilege, JIT and zero standing privilege (ZSP)

- **Usage-based right-sizing.** Compare granted permissions with observed usage (CloudTrail and last-accessed data, Azure Activity and sign-in logs, GCP Audit Logs and IAM Recommender, Snowflake `ACCESS_HISTORY`, Databricks system tables), then propose minimised policies. AWS Access Analyzer policy generation and unused-access recommendations, GCP IAM Recommender and role insights, and Entra access reviews are the native baselines.
- **JIT mechanisms**: Entra PIM (eligible assignments), GCP Privileged Access Manager, AWS IAM Identity Center with temporary elevation (for example the AWS TEAM sample solution), and Snowflake or Databricks grants scheduled through workflow tools.
- **ZSP** requires break-glass design, approval SLAs, auto-revocation and audit evidence. The CISA ZTMM "Optimal" identity stage expects automated JIT and just-enough access.

### 4.10 Fine-grained authorization for AI and RAG

Problem: a retriever pulls chunks from a vector index built over documents with heterogeneous ACLs (SharePoint, Google Drive, Confluence, Snowflake). The LLM must only see chunks the *end user* may read, and agents acting for users must not exceed the user's rights. That is a confused-deputy risk.

Patterns:
1. **Pre-filtering.** Compute the user's authorized object IDs or ACL tags (ReBAC LookupResources / ListObjects, or a Cerbos/Oso query plan compiled to a metadata filter) and pass them into the vector query.
2. **Post-filtering.** Retrieve top-k, then batch-check each document (AuthZEN `evaluations`, OpenFGA BatchCheck, Auth0 FGA retriever filters). This can starve recall.
3. **Hybrid.** Coarse metadata filtering plus a fine check.

Supporting requirements:
- **ACL ingestion** from source systems, with low-latency sync. Stale ACLs are a leakage vector.
- **Agent identity and delegation.** On-behalf-of tokens and capability-scoped tokens (RFC 9396 RAR, token exchange) so the effective permission is the intersection of agent and user.

Auth0 FGA (built on OpenFGA) ships RAG retriever helpers for LangChain and LangGraph. SpiceDB, Cerbos, Oso and Permit.io publish similar patterns.

---

## 5. How the market implements it

### 5.1 Policy-engine comparison

| Engine | Model / language | State | Analysis / verification | Reverse queries / filtering | Governance & status (Oct 2026) | Notes |
|---|---|---|---|---|---|---|
| **Cedar** | Own language. RBAC + ABAC + entity hierarchy (light ReBAC), templates, entity tags | Stateless (entities passed in) | **Strongest**: schema validation, Lean-verified semantics, SMT symbolic compiler (equivalence, subsumption, counterexamples) | Partial evaluation (experimental) [unverified current status]. No native list-objects | CNCF Sandbox (Oct 2025). Rust core, Go (StrongDM-donated), Java/JS/Python bindings maturing | Managed: **Amazon Verified Permissions** ($5/M single requests after a 97% cut in June 2025; policy-store aliases and named policies Apr 2026). Used in AWS (Verified Access, Bedrock AgentCore policy [unverified]) and by Cloudflare, MongoDB and StrongDM |
| **OPA / Rego** | General-purpose Datalog-like | Stateless (bundles and data pushed) | Unit testing (`opa test`), coverage, Regal linter. No decidable equivalence | Partial evaluation → SQL / filters | CNCF Graduated. Core maintainers moved to Apple (Aug 2025). Styra's EOPA, OPA Control Plane and Regal open-sourced. Styra DAS sunset | De facto for Kubernetes admission (Gatekeeper), Terraform (conftest), Envoy. Permit.io, OPAL |
| **Topaz** | OPA/Rego plus built-in Zanzibar-style directory | Stateful directory + stateless policy | Rego tests | Directory graph queries. AuthZEN | Aserto SaaS shut down May 2025. OSS maintained by maintainers | Early AuthZEN implementer |
| **Cerbos** | YAML resource/principal/role policies with CEL conditions | Stateless PDP | Policy test suites in CI. Cerbos Hub for distribution and audit | **PlanResources** query plans → ORM filters. AuthZEN | Apache-2.0 PDP. Commercial Hub. Funding last public 2023 (~$11M total) | Developer-friendly. Embedded/WASM PDP |
| **Oso** | Polar (logic language) + facts | Oso Cloud (hosted facts) or "local authorization" against your DB | Tests. No formal proofs | `list` and `list_local` (returns SQL WHERE) | Commercial SaaS. Legacy OSS libraries deprecated [date unverified] | Strong on app-level ReBAC/RBAC modelling |
| **Casbin** | PERM metamodel (Request, Policy, Effect, Matchers) via config | Library with adapters | Minimal | Filtered policy loading | Apache-2.0. Many languages | Simple, embedded. Weak for central governance |
| **OpenFGA** | Zanzibar DSL (types, relations, conditions via CEL) | Stateful tuple store | Model tests (`fga model test`) | ListObjects, ListUsers, BatchCheck | CNCF Incubating (Oct 2025). Okta/Auth0 origin. Auth0 FGA is the managed version | Grafana Labs, GitPod maintainers. 37+ public production adopters (CNCF) |
| **SpiceDB** | Zanzibar schema language, caveats (CEL) | Stateful (Postgres, CockroachDB, Spanner, MySQL) | Schema validation, assertions, playground | LookupResources / LookupSubjects. Materialize (precomputed) | Apache-2.0. AuthZed Cloud, Dedicated, Enterprise | Most faithful Zanzibar (ZedTokens) |
| **Ory Keto** | Zanzibar + Ory Permission Language (TS-like) | Stateful | Limited | Expand / list | Apache-2.0. Ory Network | Part of Ory stack |
| **Permify** | Zanzibar-style DSL with attributes | Stateful | Schema tests | Lookup entity / subject | Acquired by **FusionAuth** (Nov 2025). Stays open source | Snap tokens |
| **WorkOS FGA** (ex-Warrant) | Zanzibar-style | Hosted | — | Query API | WorkOS acquired Warrant Apr 2024. OSS repo remains | Bundled with WorkOS AuthKit |
| **XACML engines** (Axiomatics, AuthzForce) / **ALFA** | XACML / ALFA | Stateless | Some analysis tooling | Reverse query (Axiomatics) | Mature enterprise | Axiomatics active in AuthZEN [unverified] |
| **PingAuthorize, PlainID, Permit.io, Styra-successors** | PBAC platforms over OPA/Cedar/own | Varies | Varies | Varies | Commercial | PlainID and Permit.io target "authorization management" |

### 5.2 Cloud-entitlement and identity-security vendors (Tessera's competitive frame)

- **CIEM / CNAPP:** Wiz, Palo Alto Prisma Cloud, Microsoft Defender for Cloud (which absorbed CloudKnox / Entra Permissions Management; Microsoft announced Permissions Management's retirement [retirement date unverified]), Orca, Tenable Cloud Security (ex-Ermetic), CrowdStrike, Sonrai (cloud permissions firewall), Datadog. These compute effective permissions and escalation paths, but mostly read-only. Remediation is ticket- or bot-driven, not Git-native.
- **Privileged / JIT access:** CyberArk (Secure Cloud Access / ZSP), Britive, Apono, Entitle (acquired by BeyondTrust 2024), ConductorOne, Opal, Indent, StrongDM (Cedar-based), Teleport.
- **Data access governance:** Immuta, Privacera, Cyral, Satori, Okera (acquired by Databricks), Veza (authorization graph across cloud, data and SaaS; arguably the closest to Tessera's "unified access graph").
- **IGA:** SailPoint, Saviynt, Okta Identity Governance, Microsoft Entra ID Governance. Strong on certification and joiner-mover-leaver, weak on fine-grained cloud and data effective permissions.
- **Native:** AWS IAM Access Analyzer, GCP Policy Intelligence (Recommender, Troubleshooter, Simulator), Azure (Entra access reviews, PIM).

**Notable differences:** CIEMs model the graph. Policy engines model decisions. Almost nobody combines a *source-of-truth policy language*, *Git workflow*, *formally checked diffs* and *exact multi-cloud effective-permission evaluation*. That combination is Tessera's wedge.

---

## 6. Threats, attacks and failure modes

### 6.1 Privilege-escalation paths in cloud IAM

**AWS.** Datadog's **pathfinding.cloud** (December 2025) catalogs 60+ (later reported as 65) escalation paths in machine-readable YAML/JSON. It builds on Rhino Security's 2018 list of 21. Reportedly, 42% of the paths were not detected by any OSS tool evaluated. Classes:
- *Policy self-modification*: `iam:CreatePolicyVersion`, `SetDefaultPolicyVersion`, `PutUserPolicy`/`PutRolePolicy`/`PutGroupPolicy`, `AttachUser/Role/GroupPolicy`, and adding yourself to a group.
- *Credential minting*: `iam:CreateAccessKey`, `CreateLoginProfile`/`UpdateLoginProfile` on another user.
- *Trust manipulation*: `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole`.
- *PassRole to compute*: `iam:PassRole` + `ec2:RunInstances`, `lambda:CreateFunction`+`InvokeFunction`, `glue:CreateDevEndpoint`, `cloudformation:CreateStack`, `ecs:RunTask`, `sagemaker:CreateNotebookInstance`, `codebuild`, `datapipeline` and others.
- *Code injection into existing privileged compute*: `lambda:UpdateFunctionCode`, `ssm:SendCommand`/`StartSession`, `ec2-instance-connect`.
- *Boundary bypass*: `iam:DeleteRolePermissionsBoundary` / `PutRolePermissionsBoundary`.
- *Organization-level*: management-account compromise (SCPs don't apply to it) and delegated-admin abuse.

**Azure:**
- `Microsoft.Authorization/roleAssignments/write` (Owner, User Access Administrator, RBAC Administrator without conditions).
- Managed identity abuse through VM Run Command, Automation runbooks, Logic Apps and Function code deploy.
- Key Vault access-policy write.
- Entra app/service-principal credential addition (Application Administrator, Cloud Application Administrator → app with high Graph permissions).
- Privileged Role Administrator.
- Dynamic group rule manipulation through user attributes.
- Elevation of a Global Administrator to User Access Administrator at root scope ("elevate access").

**GCP:**
- `iam.serviceAccounts.actAs` with compute or deploy permissions (Compute, Cloud Functions, Cloud Run, Cloud Build, Composer, Dataflow, Deployment Manager).
- `iam.serviceAccounts.getAccessToken` / `signJwt` / `signBlob` / `implicitDelegation`.
- `iam.serviceAccountKeys.create`.
- `*.setIamPolicy` on a project, folder or service account.
- `iam.roles.update` on custom roles in use.
- `orgpolicy.policy.set` to lift constraints.
- The default compute service account historically holding Editor.

**Data platforms:**
- *Snowflake*: OWNERSHIP transfer, MANAGE GRANTS, SECURITYADMIN and USERADMIN chains, plus the default secondary roles ALL widening blast radius.
- *Databricks*: MANAGE on a catalog, ownership of a storage credential or external location, and cluster policies that let users bypass Unity Catalog through no-isolation clusters.
- *BigQuery*: `bigquery.rowAccessPolicies.*` and dataset `setIamPolicy`.

**Implication.** An effective-permission engine must evaluate *transitive* reachability (principal → can modify policy, mint creds, assume, pass or deploy → principal′), not just direct grants. Blast radius = everything reachable in the escalation graph.

### 6.2 Confused deputy

A privileged service is tricked into using its authority for a less-privileged caller.

- **AWS cross-service:** a service principal such as `s3.amazonaws.com` or `sns.amazonaws.com` acts on a resource on behalf of an attacker's account. Mitigate with `aws:SourceArn` / `aws:SourceAccount` / `aws:SourceOrgID` conditions in resource policies. RCPs can enforce these org-wide.
- **Third-party SaaS role assumption:** mitigated with `sts:ExternalId`. Vendors must generate per-tenant external IDs.
- **AI agents and RAG:** an agent with broad service credentials answers a user who should not see the data. Mitigate by evaluating with the user's identity, using delegated or attenuated tokens and intersecting agent and user permissions.

### 6.3 Policy and decision failure modes

- **Policy drift.** Console or CLI changes outside Git, emergency grants never revoked, AWS-managed policies changing under you (AWS edits managed policies regularly), Snowflake future grants silently applying to new objects, and inherited grants from newly created parent folders or OUs.
- **Semantic mistakes.** `NotAction` with Allow granting far more than intended. Wildcard principals in resource policies. Azure `NotActions` mistaken for a deny. GCP deny conditions failing closed (good) while IAM allow conditions fail open-to-deny. Cedar errors skipping a `forbid` policy (mitigated by validation).
- **Translation fidelity.** Compiling a high-level policy (Cedar) into native IAM can be lossy. Some cloud semantics (session-scoped resource grants, KMS key-policy requirements, ADLS ACL precedence) have no direct Cedar analogue, and reverse-lifting native to Cedar can over- or under-approximate.
- **Consistency.** The ReBAC "new enemy" problem: a check against stale tuples after revocation. Cloud IAM is eventually consistent (AWS IAM propagation takes seconds), so a "revoked" change in Tessera is not instantaneous enforcement.
- **Attribute integrity.** ABAC trusts tags. Anyone who can `TagResource` or edit Entra custom security attributes can change access. Tag-mutation permissions must be treated as privileged.
- **Availability.** A PDP outage forces a fail-open vs fail-closed decision. External PDPs on the hot path add latency, which is why sidecars, embedded engines and caching are used.
- **Scale limits.** Access Analyzer internal-access errors past 3,000 principals. PAB limits. AWS policy size limits (managed policy 6,144 characters; SCP 5,120) push teams to wildcards, which defeats least privilege.

---

## 7. Expert and authoritative sources

- **NIST CSRC**: RBAC project (David Ferraiolo, Rick Kuhn), ABAC SP 800-162 (Vincent Hu et al.), NGAC/Policy Machine, SP 800-207 (Scott Rose, Oliver Borchert, Stu Mitchell, Sean Connelly), SP 800-207A (Ramaswamy Chandramouli, Zack Butcher).
- **Ravi Sandhu**: foundational RBAC (RBAC96) and ABAC (ABAC-alpha) papers.
- **Google**: the Zanzibar paper (Pang, Caceres et al., USENIX ATC 2019) and the BeyondCorp papers (Ward, Beyer et al.).
- **AWS Automated Reasoning Group**: Zelkova (Backes et al., FMCAD 2018), the Cedar papers ("Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization", OOPSLA 2024; "How We Built Cedar: A Verification-Guided Approach", FSE 2024) and SymCert (2026). Key people: Byron Cook, Emina Torlak, Mike Hicks, Neha Rungta.
- **OpenID AuthZEN WG**: co-chairs Omri Gazitt (Aserto/Topaz) and David Brossard (Axiomatics) [current co-chairs unverified]. Alex Babeanu and Atul Tulshibagwale were active contributors [unverified].
- **OPA**: Torin Sandall, Tim Hinrichs, Teemu Koponen (now at Apple). **SpiceDB/AuthZed**: Jake Moshenko, Joey Schorr, Jimmy Zelinskie. **OpenFGA**: Andrés Aguiar (Okta).
- **Cloud IAM research**: Datadog Security Labs (pathfinding.cloud, Nick Frichette's Hacking the Cloud), Rhino Security Labs (Spencer Gietzen, Pacu), Wiz Research, Ian Mckay (iann0036 IAM dataset), Kinnaird McQuade (Cloudsplaining), Duo Labs' CloudMapper / NCC Group PMapper, Andy Robbins and SpecterOps (BloodHound, AzureHound), Dirk-jan Mollema (Entra attacks).
- **Analysts**: KuppingerCole (Policy-Based Access Management / Dynamic Authorization Management Leadership Compass), Gartner (CIEM, ITDR, "Externalized Authorization Management" research).
- **CISA**: Zero Trust Maturity Model v2.0. **DoD**: Zero Trust Reference Architecture and Strategy (2022) with 7 pillars.

---

## 8. Implications for Tessera

### 8.1 Required capabilities

1. **MUST — Exact per-cloud effective-permission evaluators.** Implement AWS (§4.5 including principal-type resource-policy rules, cross-account dual evaluation, SCP per-OU-level intersection, RCPs, boundaries, session policies, trust and KMS key-policy explicit-allow requirements, condition keys), Azure (§4.6 deny assignments → union of role assignments → `Actions−NotActions` / `DataActions−NotDataActions` → conditions, plus PIM eligibility, Entra roles and ADLS ACLs) and GCP (§4.7 PAB → deny → inherited allow with IAM Conditions, plus VPC-SC and Org Policy as annotated blockers). Each evaluator must return the decision *and* the provenance chain (which statements, which assignments).
2. **MUST — Differential test harness against the real clouds.** Continuously validate Tessera's evaluator against the AWS IAM policy simulator / Access Analyzer, the GCP Policy Troubleshooter and Azure "check access" in sandbox accounts. Track divergence as a quality SLO.
3. **MUST — Canonical entitlement graph.** Principals, groups, roles, policies, statements, assignments, resources, hierarchy, sessions and trust edges for AWS, Azure, GCP, Kubernetes, Snowflake, Databricks and BigQuery, ingested incrementally from APIs and audit logs.
4. **MUST — Privilege-escalation and blast-radius analysis.** Transitive reachability over escalation primitives (seeded from pathfinding.cloud's machine-readable catalog for AWS, plus equivalent curated catalogs for Azure, GCP and data platforms). "Blast radius" = the set of (resource, action) reachable from a principal, *including* escalation hops, under current *and* proposed policy.
5. **MUST — Cedar-in-Git source of truth with schema.** A Tessera Cedar schema (entity types per platform), policy validation in CI, and compilation from Cedar intent to native artifacts (IAM JSON, SCP/RCP, Azure role assignments and conditions, GCP bindings and deny policies, Snowflake/Databricks GRANTs). Every compile must be *checked*, re-lifting the native output and proving equivalence or subsumption against intent.
6. **MUST — Change simulation and formal diff on every PR.** Use Cedar symbolic analysis (`symcc`: equivalence, subsumption, "never allows public", "never grants iam:*") plus effective-permission diffs ("these 14 principals gain s3:GetObject on prod-pii") posted as PR comments. Gate merges on invariant checks.
7. **MUST — Drift detection and reconciliation.** Detect out-of-band changes (CloudTrail, Azure Activity Log, GCP Admin Activity, Snowflake `QUERY_HISTORY` for GRANT statements). Classify each change (emergency, ClickOps, provider-managed). Offer "adopt into Git" or "revert".
8. **MUST — Usage-based least-privilege recommendations.** Join grants with observed usage (CloudTrail, last-accessed data, GCP audit logs and Recommender, Azure sign-in and activity logs, Snowflake `ACCESS_HISTORY`, Databricks system tables) to propose minimised policies as PRs, with confidence and observation windows.
9. **MUST — Explicit-deny and guardrail awareness.** Model SCPs, RCPs, PAB, GCP deny policies and Azure deny assignments as first-class objects that the simulator respects, including SCP non-application to the management account and service-linked roles.
10. **SHOULD — JIT / ZSP workflows.** Time-bound grants expressed as Cedar policy with expiry (`context.now < expiry` or template instances with TTL), executed natively (PIM, GCP PAM, temporary IAM Identity Center assignments, Snowflake grants with scheduled revoke) and auto-revoked with evidence.
11. **SHOULD — AuthZEN-compliant PDP and PEP interfaces.** Expose `/access/v1/evaluation(s)` and the search endpoints over the Tessera graph, so apps and AI gateways can query "can X do Y" and "what can X access" in a standard way. Consume AuthZEN PDPs (Cerbos, Topaz, OpenFGA-based) as sources.
12. **SHOULD — Data-platform depth.** Snowflake role-hierarchy closure (including ownership, future grants, database roles and secondary roles ALL), Unity Catalog privilege inheritance plus ABAC policies and governed tags, BigQuery IAM plus row and column policies.
13. **SHOULD — Confused-deputy linting.** Flag resource policies granting to service principals without `aws:SourceArn`/`SourceAccount`/`SourceOrgID`, and third-party roles without `sts:ExternalId`. Generate RCPs to enforce these org-wide.
14. **SHOULD — Attribute and tag governance.** Treat tag-write, custom-security-attribute-write and governed-tag-write permissions as privileged edges in the escalation graph.
15. **SHOULD — Access review and certification export.** Attach effective-permission evidence to IGA campaigns (SailPoint, Okta, Entra) and to auditors (SOC 2, ISO 27001, FedRAMP AC-2/AC-6 control evidence).
16. **COULD — ReBAC application authorization.** Offer a Zanzibar-compatible store (or integrate OpenFGA or SpiceDB) for customer apps, unified with infrastructure entitlements in one graph.
17. **COULD — AI/RAG authorization service.** Ingest source-system ACLs (Google Drive, SharePoint, Confluence, Snowflake) and expose pre-filter (resource search) and post-filter (batch evaluation) APIs for retrievers, with agent-on-behalf-of-user intersection semantics.
18. **COULD — Kubernetes RBAC and admission.** Effective-permission evaluation for Kubernetes RBAC (ClusterRoleBindings, aggregated roles, escalate/bind/impersonate verbs) and Cedar-for-Kubernetes or Gatekeeper policy generation.
19. **COULD — Zero-trust posture mapping.** Score customers against the CISA ZTMM v2 Identity, Applications and Data pillars using Tessera's telemetry.

### 8.2 How the effective-permission engine must model each cloud

**Architecture.** One core engine with a *platform-semantics plug-in* per target. The core provides:
- A normalized request: (principal, action, resource, context) plus a session descriptor.
- A **three-valued decision with provenance**: Allow / ExplicitDeny / ImplicitDeny, plus `NotApplicable` per policy and a reason trace.
- An **SMT encoding layer**, Zelkova-style, so the engine answers *universal* questions such as "can *any* principal outside the org read this bucket?" and "does this PR expand access?", not only point checks. Practical approach: encode each platform's evaluation as formulas over symbolic request variables (action, resource ARN string constraints, condition keys) and solve with cvc5 or Z3. Pair this with a *concrete* graph engine for enumeration (who-can-access lists).

**AWS plug-in:**
- Ordered pipeline: explicit deny → RCP (per OU level, resource account) → SCP (per OU level, principal account; skip for management account and service-linked roles) → resource policy, with the principal-type matrix (user ARN, role ARN, role-session ARN, federated user) → identity policies → boundary → session policy.
- Cross-account: dual evaluation, both must allow.
- Special resources: role trust policies (explicit allow required), KMS key policies plus grants, S3 ACLs and Object Ownership, S3 Block Public Access, VPC endpoint policies.
- A full condition-key semantics library: string and ARN operators, `IfExists`, `ForAllValues`/`ForAnyValue` (including the empty-set pitfalls) and global keys (`aws:PrincipalOrgID`, `aws:SourceIp`, `aws:SourceVpce`, `aws:PrincipalTag`, `aws:ResourceTag`, `aws:RequestedRegion`, `aws:MultiFactorAuthPresent`, `aws:SourceArn`).
- Treat unknown runtime context symbolically: "allowed if MFA" and "allowed from VPCE x".
- Per-service action and resource-type metadata from the AWS Service Authorization Reference, versioned.

**Azure plug-in:**
- Scope tree (management groups → subscriptions → resource groups → resources).
- Transitive group expansion from Entra.
- Deny assignments with exclusions first.
- Union of role assignments, with wildcard `Actions` matching then `NotActions` subtraction per role (not across roles).
- Separate management and data planes.
- ABAC conditions as symbolic predicates over `@Resource`/`@Request`/`@Principal`/`@Environment`.
- PIM: eligible vs active. Report both "can activate" and "currently has".
- Entra directory roles as a separate graph with escalation edges into Azure (Global Admin elevate access).
- Data-plane overlays: ADLS ACLs (checked only if RBAC denies), Key Vault access policies, SQL and Cosmos data-plane RBAC.

**GCP plug-in:**
- Resource hierarchy with union of inherited allow bindings.
- Principal expansion: users, groups (nested), domains, `allUsers`/`allAuthenticatedUsers`, workforce and workload identity `principalSet://`, service agents.
- Role → permission expansion (predefined role definitions change over time, so version them).
- IAM Conditions (CEL subset) evaluated symbolically.
- Deny policies on the ancestry, with exception principals and permissions, and conditions that fail closed.
- PAB: principal-set bindings, enforcement versions and eligibility rules.
- Overlays: VPC-SC perimeters and Org Policy constraints (as "would be blocked by" annotations), and service ACLs (GCS legacy ACLs, BigQuery dataset ACLs, row and column policies).

**Snowflake / Databricks / BigQuery plug-ins:**
- *Snowflake*: role DAG closure, ownership, future grants, database roles via account roles, session semantics (primary role vs secondary ALL), managed-access schemas, row access and masking policies as conditional or attenuated access.
- *Unity Catalog*: securable tree inheritance, ownership, workspace bindings, ABAC policies keyed on governed tags.

### 8.3 Data-model entities and fields

| Entity | Key fields |
|---|---|
| `Platform` | id, kind (aws/azure/gcp/k8s/snowflake/databricks/bigquery/saas/app), semantics_version |
| `Tenant/Scope` | id, platform, kind (org, OU, account, mgmt group, subscription, RG, folder, project, Snowflake account, metastore/catalog/schema), parent_id, path, tags |
| `Principal` | id, platform, kind (human, group, role, role_session, service_account, managed_identity, workload_identity, agent, federated), native_id/ARN, display, idp_link (to the workforce identity), attributes/tags, owner, lifecycle (active, disabled, orphaned), last_used_at |
| `Membership` | member_id, group_id, source (direct, dynamic, nested), valid_from/to |
| `Resource` | id, platform, type, native_id/ARN, scope_id, parent_id, tags/classification (PII, prod), data_sensitivity, public_exposure |
| `Action/Permission` | platform, name, service, access_level (read/write/list/permissions-mgmt/tagging), resource_types, is_privilege_escalation_primitive, plane (mgmt/data) |
| `Role/PermissionSet` | id, platform, kind (managed, custom, built-in, Snowflake role, database role), permissions (actions, not_actions, data_actions …), assignable_scopes, version |
| `Policy` | id, platform, kind (identity, resource, trust, SCP, RCP, boundary, session, deny_policy, PAB, deny_assignment, azure_condition, row_access, masking, abac_policy, cedar), document (raw), normalized_statements, attached_to, version_hash, source (git/native/drift) |
| `Statement` | policy_id, effect (allow/deny/permit/forbid), principals, not_principals, actions, not_actions, resources, not_resources, condition (AST) |
| `Assignment/Grant` | id, principal_id, role_or_policy_id, scope_id, condition, eligibility (eligible/active), start/expiry, justification, ticket, granted_by, origin (git PR / JIT / out-of-band) |
| `TrustEdge` | from_principal, to_principal/role, mechanism (AssumeRole, actAs, impersonation, federation, PassRole, OBO), conditions (ExternalId, SourceArn) |
| `EffectivePermission` (materialized) | principal_id, action, resource_id or pattern, decision, conditions_residual, provenance[], via_escalation_path_id, computed_at, model_version |
| `EscalationPath` | id, start_principal, steps[] (primitive, edge), end_capability, severity |
| `UsageEvent` (aggregated) | principal_id, action, resource_id, count, first/last_seen, source_log |
| `Recommendation` | id, target (policy/assignment), proposed_change (Cedar diff + native diff), evidence (usage window), risk_delta, status |
| `ChangeSet/PR` | id, git_ref, cedar_diff, native_plan, symbolic_findings, blast_radius_delta, approvals, deploy_status |
| `DriftEvent` | id, object_ref, observed_at, actor, classification, resolution |
| `Invariant` | id, Cedar/SMT property ("no public S3", "no non-break-glass admin"), scope, severity |

### 8.4 Cedar vs OPA recommendation

**Use Cedar as Tessera's canonical entitlement language. Support OPA/Rego as a guardrail and integration surface, not as the source of truth.**

Rationale:
- **Analyzability is the product.** Blast-radius simulation and "prove this PR only removes access" need decidable equivalence and subsumption with counterexamples. Cedar provides this, with a verified SMT encoding. Rego, being general-purpose, cannot provide it in general.
- **Semantics fit entitlements.** Default-deny, forbid-overrides-permit, order independence, schemas and principal/action/resource scoping mirror cloud IAM concepts. Templates map to grants. Entity hierarchies map to OUs, folders, resource groups and role DAGs.
- **Ecosystem momentum.** CNCF Sandbox (Oct 2025), AWS Verified Permissions, StrongDM, Cloudflare, MongoDB and a Go implementation all support it. Vendor-neutral governance reduces "AWS lock-in" objections.
- **Where OPA wins:** Kubernetes admission (Gatekeeper is entrenched), Terraform plan checks (conftest) and Envoy external authorization. Many customers already have Rego. OPA's governance is stable under the CNCF despite the Apple acqui-hire, but commercial support thinned after Styra's wind-down. Tessera should **import and lint existing Rego** and optionally **emit Rego guardrails** for CI, without making Rego the model.

Caveats to plan for:
- Cedar has no native list-objects or reverse query. Tessera's graph engine supplies that.
- Cedar cannot express every cloud nuance (string-pattern ARNs with `NotResource`, `IfExists` semantics). Keep *native* policy as an evaluable artifact alongside Cedar intent, and prove consistency rather than assuming it.
- Cedar language versions (4.x) and SDK versions differ. Pin both.

### 8.5 Build vs integrate

| Component | Recommendation | Why |
|---|---|---|
| Policy language and evaluator | **Integrate** Cedar (Rust crate, embedded) | Verified, fast, Apache-2.0. Contributing upstream builds credibility |
| Symbolic analysis | **Integrate** `cedar-policy-symcc` + cvc5. **Build** Tessera-specific invariants and diff UX | The core analysis is available; the product value is in the UX |
| Cloud effective-permission evaluators (AWS/Azure/GCP) | **Build** (core IP), validated against native simulators | No OSS evaluator is exact across all three. This is the moat |
| Escalation catalogs | **Integrate** pathfinding.cloud (AWS); **build** Azure, GCP and data-platform catalogs | Public data for AWS; gaps elsewhere |
| Graph store | **Build on** a proven DB (Postgres plus a graph layer, or a dedicated graph DB). Consider SpiceDB or OpenFGA only for app-ReBAC | Infrastructure graph queries (paths, closures) differ from Zanzibar checks |
| App-level ReBAC (COULD) | **Integrate** OpenFGA or SpiceDB first; expose via AuthZEN | Mature, CNCF-governed; avoid rebuilding Zanzibar early |
| PDP API | **Build** AuthZEN 1.0 endpoints | The standard is Final; cheap to implement and a differentiator |
| JIT executors | **Integrate** native PIM, GCP PAM and IAM Identity Center; **build** orchestration | Use native enforcement and own the policy and workflow |
| Rego support | **Integrate** OPA (library) for import, test and guardrail emission | Meets customers where they are |
| IGA and certifications | **Integrate** (SailPoint, Okta, Entra via SCIM and APIs) | Not the wedge; supply evidence to them |

---

## 9. Glossary

- **ABAC**: Attribute-Based Access Control.
- **ACL**: Access Control List.
- **actAs**: GCP permission to run resources as a service account.
- **AuthZEN**: OpenID Foundation working group and its Authorization API (PEP↔PDP protocol). 1.0 Final, January 2026.
- **AVP**: Amazon Verified Permissions, AWS's managed Cedar PDP.
- **Blast radius**: everything a principal (or a compromised credential) can reach, including through escalation.
- **Boxcarring**: batching multiple evaluations in one AuthZEN request.
- **Capability**: an unforgeable token conferring rights.
- **CEL**: Common Expression Language, used by GCP IAM Conditions, OpenFGA and SpiceDB caveats, Cerbos and Kubernetes.
- **CIEM**: Cloud Infrastructure Entitlement Management.
- **Confused deputy**: a privileged component misused on behalf of a less-privileged caller.
- **DAC / MAC**: Discretionary / Mandatory Access Control.
- **Deny assignment**: Azure object that blocks actions regardless of role assignments.
- **DSD / SSD**: Dynamic / Static Separation of Duty.
- **Effective permission**: net access after all policies are evaluated.
- **Entity tags**: Cedar 4.1+ key-value maps on entities.
- **External ID**: AWS STS condition that mitigates confused deputy for third parties.
- **JIT**: just-in-time access.
- **NGAC**: Next Generation Access Control (NIST).
- **PAB**: GCP Principal Access Boundary policy.
- **PAP/PDP/PEP/PIP**: Policy Administration / Decision / Enforcement / Information Point.
- **PassRole**: AWS permission to hand a role to a service. A classic escalation primitive.
- **PBAC**: Policy-Based Access Control.
- **PERM**: Casbin metamodel (Policy, Effect, Request, Matchers).
- **PIM**: Microsoft Entra Privileged Identity Management.
- **Polar**: Oso's logic policy language.
- **RCP**: AWS Organizations Resource Control Policy (caps resources).
- **ReBAC**: Relationship-Based Access Control.
- **Rego**: OPA's policy language.
- **Role explosion**: combinatorial growth of roles when RBAC encodes context.
- **SCP**: AWS Organizations Service Control Policy (caps principals).
- **Session policy**: AWS inline policy passed when creating temporary credentials. It caps the session.
- **SMT**: Satisfiability Modulo Theories, the solver technology behind Zelkova and Cedar analysis.
- **Tuple**: Zanzibar relationship record `object#relation@subject`.
- **userset rewrite**: Zanzibar rule deriving a relation from others.
- **XACML**: eXtensible Access Control Markup Language (OASIS).
- **Zelkova**: AWS SMT-based IAM policy reasoning engine.
- **ZedToken / zookie / snap token**: consistency tokens in SpiceDB / Zanzibar / Permify.
- **ZSP**: Zero Standing Privilege.
- **ZTA / ZTMM**: Zero Trust Architecture / Zero Trust Maturity Model.

---

## 10. Sources

Standards and specifications
- NIST RBAC project: https://csrc.nist.gov/projects/role-based-access-control
- NIST SP 800-162: https://csrc.nist.gov/pubs/sp/800/162/upd2/final
- NIST SP 800-178: https://csrc.nist.gov/pubs/sp/800/178/final
- NIST SP 800-207: https://csrc.nist.gov/pubs/sp/800/207/final
- NIST SP 800-207A announcement: https://csrc.nist.gov/News/2023/nist-publishes-sp-800-207a
- CISA ZTMM v2.0: https://www.cisa.gov/zero-trust-maturity-model ; overview: https://learn.microsoft.com/en-us/security/zero-trust/cisa-zero-trust-maturity-model-intro
- OASIS XACML 3.0: https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html
- AuthZEN Authorization API 1.0 Final: https://openid.net/specs/authorization-api-1_0-final.html
- AuthZEN final approval announcement: https://openid.net/authorization-api-1-0-final-specification-approved/
- AuthZEN claims draft: https://www.ietf.org/archive/id/draft-gazitt-oauth-authzen-claims-01.html
- Zanzibar paper: https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/

Cedar / Verified Permissions
- CNCF Cedar project page: https://www.cncf.io/projects/cedar/
- AWS: Cedar joins CNCF: https://aws.amazon.com/blogs/opensource/cedar-joins-cncf-as-a-sandbox-project
- InfoQ: https://infoq.com/news/2026/01/cedar-joins-cncf-sandbox/
- Cedar docs and history: https://docs.cedarpolicy.com/ ; https://docs.cedarpolicy.com/other/doc-history.html
- Cedar analysis tools: https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies
- Cedar paper: https://arxiv.org/abs/2403.04651 ; verification-guided development: https://arxiv.org/pdf/2407.01688
- Lean use case: https://lean-lang.org/use-cases/cedar/
- SymCert: https://www.amazon.science/publications/symcert-verifying-smt-based-policy-analyses
- AVP Cedar 4 FAQ: https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/cedar4-faq.html
- AVP price reduction: https://aws.amazon.com/about-aws/whats-new/2025/06/amazon-verified-permissions-reduces-price/
- AVP aliases and named policies: https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-verified-permissions-policy-store

OPA and other engines
- OPA 1.0 docs: https://openpolicyagent.org/docs/edge/opa-1
- OPA maintainers join Apple: https://cloudnativenow.com/features/apple-buys-styra-brains-opa-remains-open/ ; https://heise.de/-10574287 ; Oso commentary: https://osohq.com/post/opa-maintainers-join-apple-oss-community-to-maintain-styra-products
- OpenFGA incubation: https://www.cncf.io/blog/2025/11/11/openfga-becomes-a-cncf-incubating-project/ ; https://openfga.dev/blog/incubation-announcement
- Aserto final chapter / Topaz: https://www.aserto.com/blog/the-final-chapter-for-aserto
- FusionAuth acquires Permify: https://www.einpresswire.com/article/868633639/fusionauth-acquires-permify-unifying-authn-authz-in-a-single-deploy-anywhere-platform
- WorkOS acquires Warrant: https://workos.com/blog/workos-acquires-warrant
- Oso list filtering: https://www.osohq.com/docs/develop/enforce/list-filtering
- AuthZed Series A: https://securityweek.com/authzed-raises-12-million-for-permissions-management-technology
- Cerbos funding: https://www.securityweek.com/cerbos-raises-7-5-million-for-authorization-platform/

AWS
- Policy evaluation logic: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html
- Cross-account evaluation: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html
- RCPs: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html ; DynamoDB support: https://aws.amazon.com/about-aws/whats-new/2026/02/aws-expands-resource-control-policies-amazon/ ; third-party coverage list: https://www.native.security/cloud-docs/aws-rcp-by-service
- SCP full IAM language: https://aws.amazon.com/about-aws/whats-new/2025/09/aws-organizations-iam-language-service-control-policies ; https://aws.amazon.com/blogs/security/unlock-new-possibilities-aws-organizations-service-control-policy-now-supports-full-iam-language
- Access Analyzer internal access: https://aws.amazon.com/about-aws/whats-new/2025/06/iam-access-analyzer-aws-organization-access-resources ; https://aws.amazon.com/blogs/aws/verify-internal-access-to-critical-aws-resources-with-new-iam-access-analyzer-capabilities
- Access Analyzer findings: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html
- Unused permissions (Amazon Science): https://www.amazon.science/blog/new-aws-tool-recommends-removal-of-unused-permissions
- pathfinding.cloud: https://securitylabs.datadoghq.com/articles/introducing-pathfinding.cloud/ ; https://github.com/DataDog/pathfinding.cloud ; Pathfinding Labs: https://securitylabs.datadoghq.com/articles/introducing-pathfinding-labs/
- Scanner benchmark (author-biased): https://haitmg.pl/blog/aws-iam-privesc-scanners-benchmark/

Azure
- Azure RBAC overview and evaluation: https://learn.microsoft.com/en-us/azure/role-based-access-control/overview
- Azure ABAC conditions: https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-overview
- Storage ABAC: https://learn.microsoft.com/azure/storage/blobs/storage-auth-abac ; GA: https://azure.microsoft.com/en-us/updates/azure-storage-abac-ga/
- Custom security attributes example: https://learn.microsoft.com/en-ca/Azure/role-based-access-control/conditions-custom-security-attributes-example
- Deny assignments: https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/role-based-access-control/deny-assignments.md
- Az.Resources 9.1.0 (deny assignment cmdlets): https://www.powershellgallery.com/packages/Az.Resources/9.1.0

GCP and BigQuery
- IAM policy types and evaluation: https://docs.cloud.google.com/iam/docs/policy-types
- Principal access boundary: https://docs.cloud.google.com/iam/docs/principal-access-boundary-policies
- Deny policies: https://docs.cloud.google.com/iam/docs/deny-overview
- PAB simulator: https://docs.cloud.google.com/policy-intelligence/docs/pab-simulator-overview
- Deny + Org Policy defense in depth: https://cloud.google.com/blog/products/identity-security/just-say-no-build-defense-in-depth-with-iam-deny-and-org-policies/
- BigQuery column-level security: https://docs.cloud.google.com/bigquery/docs/column-level-security-intro
- BigQuery governance tags preview: https://itbrief.co.uk/story/google-cloud-adds-bigquery-governance-tags-in-preview

Data platforms
- Snowflake access control: https://docs.snowflake.com/en/user-guide/security-access-control-overview
- Snowflake default secondary roles BCR: https://docs.snowflake.com/en/release-notes/bcr-bundles/2024_08/bcr-1692
- Databricks ABAC GA blog: https://www.databricks.com/blog/abac-row-filtering-and-column-masking-policies-governed-tags-and-data-classification-are-now
- Databricks ABAC policies docs: https://docs.databricks.com/aws/data-governance/unity-catalog/abac/policies

AI / RAG authorization
- Auth0 authorization for RAG: https://auth0.com/ai/docs/intro/authorization-for-rag
- Secure RAG with LangChain and OpenFGA: https://auth0.com/blog/building-a-secure-rag-with-python-langchain-and-openfga/
- Couchbase, securing agentic RAG: https://www.couchbase.com/blog/securing-agentic-rag-pipelines/
- PyCon DE 2025, RAG FGA talk: https://pycon.de/archive/2025/talks/securing-rag-pipelines-with-fine-grained-authorization/
