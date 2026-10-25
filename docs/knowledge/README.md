# Tessera IAM knowledge base and capability map

This folder is Tessera's working knowledge of identity and access management. It is meant to grow with the product. The six domain documents were researched from primary sources (standards bodies, RFCs, vendor docs, incident reports) as of October 2026. Claims that could not be verified are marked `[unverified]` inline.

This README turns those documents into one map. It lists every IAM capability Tessera needs, where the MVP stands today, whether to build or integrate, and the order to build in.

## The domain documents

| # | Document | Covers | Expert agent |
|---|---|---|---|
| 01 | [Authentication and identity proofing](01-authentication-and-identity-proofing.md) | NIST 800-63-4, passkeys/WebAuthn, MFA, sessions, recovery, CIAM, ITDR | `iam-authn-expert` |
| 02 | [Federation and protocols](02-federation-and-protocols.md) | SAML, OAuth 2.1, OIDC, DPoP/mTLS, token exchange, SCIM, SSF/CAEP, SPIFFE, VCs | `iam-protocols-expert` |
| 03 | [Authorization and policy](03-authorization-and-policy.md) | RBAC/ABAC/ReBAC, Cedar, OPA, AuthZEN, AWS/Azure/GCP/Snowflake evaluation logic, zero trust | `iam-authz-expert` |
| 04 | [Identity governance and compliance](04-identity-governance-and-compliance.md) | JML, provisioning, requests, certifications, SoD, SOX/SOC 2/ISO/PCI/HIPAA/DORA evidence | `iam-governance-expert` |
| 05 | [Privileged, cloud and machine identity](05-privileged-cloud-and-machine-identity.md) | PAM, JIT/ZSP, CIEM, secrets, NHI, OAuth grants, attack paths, real incidents | `iam-pam-nhi-expert` |
| 06 | [AI agents and IAM architecture](06-ai-agents-and-iam-architecture.md) | Agent delegation, MCP authorization, agentic threats, reference architecture, KPIs | `iam-agent-identity-expert` |

Companion register: [AWS evaluation ambiguities](aws-evaluation-ambiguities.md), the open questions in AWS's own IAM documentation, each with Tessera's default and the probe that would settle it.

The expert agents live in [`.claude/agents/`](../../.claude/agents/). `iam-architect` plans capabilities end to end and pulls in the domain experts. In Claude Code, ask for one by name, for example *"use iam-authz-expert to review the AWS evaluator"*.

References below use the form **D3·M1**: document 03, requirement 1 in its section 8.

## What the research agrees on

Every domain arrived at the same handful of principles independently. These are the platform's design rules.

1. **Integrate with identity providers, vaults and proxies; don't rebuild them.** Okta, Entra, Ping and Google own login. Vault and cloud secret managers own secrets. Teleport and Boundary own session proxying. Entra Agent ID and Okta for AI Agents own agent login. Tessera governs what all of them grant. (D1·build-vs-integrate, D5·M11/C13/C14, D6·S12)
2. **Policy is code in Git, and every decision records the policy version it used.** Cedar is the source language, validated in CI, diffed formally on every PR, and compiled to native cloud artifacts. (D3·M5–M6, D4·M6, D5·M8, D6·M6)
3. **Effective permissions must be exact and explainable.** "Why can X do Y" has to match what the cloud actually enforces, including SCPs, RCPs, boundaries, deny policies and session policies, and the engine must be continuously tested against the clouds' own simulators. (D3·M1–M2, D5·M2)
4. **Nothing counts as done until Tessera has re-read the system to confirm it.** That applies to provisioning, revocation and remediation. (D4·M8, M9, M14)
5. **Standing access is the exception.** Token exchange (RFC 8693) is the brokering primitive for just-in-time access, through each cloud's own mechanism, and credentials are short-lived, audience-bound and sender-constrained. (D2·M10, D5·M9, D6·M2–M4)
6. **Every non-human identity has a human owner.** That covers service accounts, keys, OAuth apps and AI agents. When an owner leaves, ownership must be reassigned. (D4·M4, D5·M3/M16, D6·M1)
7. **Revocation propagates in real time.** Tessera consumes SSF/CAEP/RISC events and, later, emits them. Logout, termination and risk events kill downstream credentials. (D1·M5–M6, D2·M4, D6·M8)
8. **Evidence is a product feature.** An append-only ledger and frozen, reproducible review populations, exportable per framework. (D4·M13, M22; D1·M9; D6·M7)
9. **Tessera must meet the bar it sells.** Phishing-resistant admin sign-in, hardened recovery, sender-constrained tokens, and a full audit trail of itself. (D1·M4, M10; D2·M7–M9)

## Corrections to our earlier assumptions

The research changed two things in the product plan.

- **Exception-only certification is not auditor-endorsed.** No standards body or audit firm explicitly accepts it. Auditors do accept risk-based scoping that is documented, tested and agreed with them in advance, with sampled human QA of auto-decisions. Tessera will ship auto-decisions with exportable rule logic and sampling, and will not market reviews as "auditor-approved". Usage-based *revocation* is far easier to defend than usage-based *approval*, so it stays a headline feature. (D4·§8.2, S16)
- **AI agent identity is a must-have in its own domain, but not the wedge.** D6 lists the MCP authorization server as a MUST to be credible in the agent space. The competitive analysis shows that space is crowded and platform-bundled. Agents are therefore Phase 4, built on the Phase 1–3 primitives (token exchange, Cedar PDP, JIT), not ahead of them.

## Capability map

Status of the current MVP (`mvp/`): **Have** = working against demo data, **Partial** = modelled but simplified, **None** = not started.

### A. Access-as-code core (the wedge)

| Capability | MVP | Build / integrate | Phase | Source |
|---|---|---|---|---|
| Canonical entitlement graph across cloud, SaaS and data | Partial (generic paths, demo data) | Build | 1 | D3·M3 |
| Exact AWS effective-permission evaluator with explanations (SCP per OU level, RCP, boundary, session, resource, trust, KMS) | Partial (engine, `/api/aws/*` and traces built in `internal/aws/*`; no scheduled collection; agreement with real AWS never measured; no fidelity or trace UI yet) | Build | 1 | D3·M1, D5·M2 |
| Differential test harness against AWS Policy Simulator / Access Analyzer | Partial (`cmd/tessera-harness replay` and `gate`, Wilson gate, oracles; corpus is 12 synthetic cassettes; no sandbox or nightly run, #28) | Build | 1 | D3·M2 |
| Cedar schema and policy repo in Git, validated in CI | None (YAML policies) | Build on Cedar | 1 | D3·M5 |
| Formal diff and blast-radius simulation on every PR | Partial (what-if over the graph; AWS policy-change diff and PR comment via `/api/aws/simulate-policy-change`) | Build, using Cedar symbolic analysis | 1 | D3·M6 |
| Drift detection and "adopt or revert" reconciliation | None | Build | 1 | D3·M7, D4·M9 |
| Usage-based least privilege, delivered as PRs | Partial (recommendations, dry run) | Build; ingest Access Analyzer and GCP Recommender | 1 | D3·M8, D5·M15 |
| Privilege-escalation and attack-path analysis | None | Build; seed from pathfinding.cloud; import BloodHound for AD | 2 | D3·M4, D5·S5 |
| Compile Cedar intent to native IAM JSON, SCP/RCP, Azure and GCP bindings, Snowflake grants | None | Build | 2 | D3·M5 |
| Explicit-deny and guardrail objects (SCP, RCP, PAB, GCP deny, Azure deny assignments) | None | Build | 1 (AWS), 3 (Azure, GCP) | D3·M9 |
| Snowflake role-hierarchy closure, then Databricks Unity Catalog and BigQuery | Partial (Snowflake demo) | Build | 1 (Snowflake), 3 (others) | D3·S12 |
| Azure and GCP evaluators | None | Build | 3 | D3·M1 |
| IaC policy linting in Terraform PRs (wildcard OIDC `sub`, `Principal:*`, missing ExternalId) | None | Build | 2 | D5·S12, D3·S13 |

### B. Tessera's own security and platform identity

| Capability | MVP | Build / integrate | Phase | Source |
|---|---|---|---|---|
| SSO into Tessera via OIDC and SAML, per tenant | None | Build on hardened libraries | 0 | D1·M1, D2·M1 |
| Phishing-resistant admin sign-in, step-up for sensitive actions | None | Delegate to IdP; enforce via `acr`/`amr` | 0 | D1·M3–M4 |
| Normalized `AuthnContext` (AAL, phishing resistance, auth time, device) | None | Build | 0 | D1·M2 |
| OAuth 2.1 authorization server for API, CLI and Terraform provider (PKCE, device flow, DPoP, JWKS rotation, introspection) | None | Build on a vetted library | 0–1 | D2·M7–M9 |
| Append-only, tamper-evident audit ledger | None | Build | 0 | D4·M22, D1·M9 |
| Hardened admin recovery and admin-change paths | None | Build | 0 | D1·M10 |
| Multi-tenancy and B2B organizations | None | Build | 0 | D1·S16, spec |

### C. Identity data and lifecycle (IGA)

| Capability | MVP | Build / integrate | Phase | Source |
|---|---|---|---|---|
| HRIS-driven identity warehouse with effective dating (Workday, BambooHR, SuccessFactors, CSV) | Partial (simulated Workday) | Build connectors | 2 | D4·M1 |
| Correlation engine; orphan, dormant and shared-account detection | Partial (orphan NHIs) | Build | 2 | D4·M2 |
| Directory ingestion: Entra, Okta, Google, SCIM server, LDAP/AD agent, nested-group resolution | Partial (Okta demo) | Build | 1 (Okta), 2 (rest) | D2·M2–M3 |
| JML automation with leaver kill-switch and SLAs | Partial (leaver plan only) | Build | 2 | D4·M7 |
| Closed-loop provisioning: SCIM client, native APIs, ticketed fulfilment, verified by re-aggregation | None (graph-only changes) | Build | 2 | D4·M8, D2·M15 |
| Access request catalog, risk-tiered approvals, Slack/Teams | Partial (JIT requests) | Build | 2 | D4·M11 |
| Certification campaigns with frozen, provably complete populations | Partial (exception-only campaign) | Build | 2 | D4·M13–M15 |
| Auto-decisions with exportable rule logic and sampled QA | Partial | Build | 2 | D4·S16 |
| SoD engine with mitigating controls | Partial (simple SoD policy) | Build; integrate Pathlock/SAP for ERP | 3 | D4·S18 |
| Framework evidence packages (SOX, SOC 2, ISO, PCI, NIS2, DORA, OSCAL) and KPI dashboards | None | Build | 2 | D4·M22–M23 |
| Connector SDK for the long tail | None | Build (open) | 3 | D4·S10 |
| Native group management with full Grouper parity: folders, composites, direct/effective memberships with dates, Grouper's 22 privileges with inheritance, attribute framework, incremental membership engine at 100k+ groups | Partial (connected-system groups only) | Build | 2 | [groups design](../design/groups-grouper-parity.md) §§5–7 |
| Policy groups as access-as-code: Cedar fragment over reference groups and identity attributes, PR membership diff | None | Build | 2 | groups design §8, D3·M5–M6 |
| Group loaders (SQL, LDAP, CSV, HRIS/SIS, IdP groups) with failsafes that hold for approval | None | Build | 2 | groups design §9.1 |
| Group provisioning with verify-by-reaggregation: LDAP/AD, SCIM 2.0, SQL, Entra, Google, Okta; long tail on the connector SDK | None | Build | 2 (long tail 3) | groups design §9.2, D4·M8 |
| Group events, tamper-evident point-in-time history, attestation, deprovisioning, rules, reports | None | Build | 2 | groups design §10 |
| Grouper connector: import, shadow-compare, per-folder cut-over, Grouper-WS-compatible read API | None | Build | 2 | groups design §11 |
| Grouper permissions and limits (role × resource × action, allow/disallow, limits as Cedar conditions) | None | Build | 3 | groups design §10.10 |
| Guest, applicant, pre-hire and partner identities: affiliations, sponsorship with sponsor policy, expiry, renewal, sponsor-leaver transfer, conversion without losing history | None | Build | 2 | [guest design](../design/guest-accounts-and-claim.md) §§3, 4, 8 |
| Identity matching for intake: confidence tiers, review queue, reversible link/merge/unmerge, no auto-link from self-asserted intake | Partial (correlation row above) | Build | 2 | guest design §5, D4·M2 |
| Account claim: single-use claim links and codes, enumeration resistance, NIST 800-63A-4 verification (A0, IAL1, IAL2), credential binding to home IdP or customer IdP, terms, recovery | None | Build | 2 | guest design §§6–7 |
| Identity verification (IDV) vendors and on-site proofing agents for IAL2 claim | None | Integrate | 2 (moved from F) | guest design §6.3, D1·C18 |
| InCommon/eduGAIN federation for external identities (metadata, R&S, Sirtfi, REFEDS MFA and RAF) | None | Build on the Phase 0 SAML SP | 2 | guest design §6.6 |
| B2B partner organizations: delegated partner admins, IdP routing, partner SCIM, agreement expiry | None | Build | 3 | guest design §11 GU-14, D1·S16 |
| Hosted credential service for guests at customers without a suitable IdP | None | Embed (Ory/Keycloak) or build on go-webauthn | 3 | guest design §7.1, D1·C19 |
| Deployment readiness checklists per connector type (AD, LDAP, Entra, Okta, Google, Workday, SCIM): versioned templates, Required/Recommended/Optional items, attestation, skip-with-reason in the audit ledger, no downgrades of Required items | None | Build | 2 (MVP slice on demo connectors first) | [deployment readiness design](../design/deployment-readiness.md) §3, D2·M2–M3 |
| Gated connection lifecycle (draft → ready to validate → validated → dry-run reconciled → active, plus degraded), enforced server-side | None | Build | 2 | deployment readiness §4 |
| Safe, read-only live validation (bind, TLS chain, DN existence, per-class read rights, fill rate, incremental sync, rate-limit headroom) and the on-prem Directory Agent with a local target allowlist | None | Build | 2 (agent and real checks need test directories) | deployment readiness §5, Phase 0 §4 I3 |
| Dry-run reconciliation into a staging snapshot: orphans, people without accounts, duplicate correlations, sparse attributes, out-of-scope groups, leavers and disabled accounts with access, stale accounts, unexpected privileged members, unowned service accounts, with impact and probable cause | Partial (orphan NHIs, missed-leaver demo data) | Build | 2 | deployment readiness §6, D4·M2, M9 |
| Deployment health analytics: explainable readiness score per connection and tenant, ranked needs-attention, skipped recommendations, drift since activation, scheduled re-runs, evidence export | None | Build | 2 | deployment readiness §7, D4·M22–M23 |

### D. Privileged access, JIT and non-human identity

| Capability | MVP | Build / integrate | Phase | Source |
|---|---|---|---|---|
| JIT broker via RFC 8693 token exchange, executed natively (Identity Center, PIM, GCP PAM, Snowflake grants) | Partial (in-graph only) | Build broker; use native cloud mechanisms | 3 | D2·M10, D5·M9 |
| Credential lifetime bound to the login session | None | Build | 3 | D1·M5 |
| Break-glass workflow with alerting and attestation | None | Build | 3 | D5·M10 |
| NHI inventory with per-credential age, last use and owner inference | Partial | Build | 1 (AWS), 2 (rest) | D5·M3 |
| Third-party OAuth grant and app-trust inventory with scope risk | None | Build | 2 | D2·M22, D5·M4 |
| NHI lifecycle: owner re-attestation, quarantine then delete, reassignment on leaver | Partial | Build | 2 | D5·M16 |
| Detections mapped to MITRE ATT&CK and OWASP NHI Top 10, exported as OCSF | None | Build | 3 | D5·M19 |
| One-click response: disable key, revoke sessions, revoke OAuth grant, quarantine | None | Build | 3 | D5·M20 |
| SSF/CAEP/RISC receiver, then transmitter | None | Build | 3 | D1·M6, D2·M4, D5·S21 |
| Federated workload identity as policy subjects; trust-as-code with strict claim matching | None | Build | 2 | D2·M18–M19 |
| Ephemeral SSH and database credentials | None | Integrate (Vault, IAM DB auth) | 4 | D5·S11 |
| Secret rotation orchestration | None | Integrate (vaults, cloud APIs) | 4 | D5·S17 |
| Session recording proxy, endpoint privilege management | None | Integrate or partner | Later | D5·C13–C14 |
| Certificate inventory and SC-081 readiness | None | Build (inventory); integrate CLM | 4 | D5·S6 |

### E. AI agent identity and authorization

| Capability | MVP | Build / integrate | Phase | Source |
|---|---|---|---|---|
| Agents as a first-class identity type with required sponsor and risk tier | Partial | Build | 1 (model), 4 (lifecycle) | D6·M1 |
| Delegation-aware token exchange (`act` chain; user ∩ agent ∩ task) | Partial (chain displayed) | Build | 4 | D6·M2 |
| MCP 2026-07-28 authorization server and resource-server SDK | None | Build | 4 | D6·M5 |
| AuthZEN-compatible PDP over the Tessera graph | None | Build | 4 | D6·M6, D3·S11 |
| Human-in-the-loop approvals via CIBA with RAR details | None | Build | 4 | D6·M9, D2·S13 |
| Agent kill switch with SSF propagation | None | Build | 4 | D6·M8 |
| Agent discovery (shadow and orphaned agents) | Partial | Build; ingest Entra Agent ID, Okta, AgentCore | 4 | D6·M10, S12 |
| MCP gateway enforcement plugins, tool-definition pinning | None | Integrate with gateways | 5 | D6·S13 |
| Permission-aware RAG filtering | None | Integrate OpenFGA or SpiceDB; expose via AuthZEN | 5 | D3·C17, D6·S16 |

### G. IGA parity gaps found in the Saviynt coverage review

From [`docs/design/saviynt-feature-coverage.md`](../design/saviynt-feature-coverage.md). Row numbers refer to that checklist.

| Capability | MVP | Build / integrate | Phase | Source |
|---|---|---|---|---|
| Notification management: email templates, email history and delivery status (SMTP sender is Phase 0) | None | Build | 2 | rows 88, 108 |
| Organizations: hierarchy, owners, organization-scoped admins, organization update rules | Partial (UI Preview) | Build | 2 | rows 28, 72, 76 |
| Application onboarding workflow with owner questionnaires | None | Build | 2 | rows 46, 47 |
| Datasets (lookup tables) for rules and forms | None | Build | 2 | row 73 |
| Entitlement update rules (owner, risk and flags by pattern) | None | Build | 2 | row 77 |
| Saved request templates and approval delegation rules | Partial | Build | 2 | rows 5, 30 |
| SFTP file drops for inbound imports | None | Build | 2 | row 95 |
| Certificate inventory and expiry alerts for Tessera's own SAML, connector and agent certificates | None | Build | 2 | row 105 |
| Password management for target accounts: self-service change, help-desk reset with verification, password policies, sync (orchestrated through connectors and IdPs; Tessera stores no passwords) | None | Build orchestration; integrate IdPs | 3 | rows 17, 18, 20, 21, 71 |
| Role engineering workbench: mining, entitlement discovery, role-access mismatch, impact preview, output as policy-as-code | Partial (role trims) | Build | 3 (moved from F) | rows 36–39, D4·C20 |
| Configurable analytics and controls with run history, configurable dashboards, permission-checked data analyzer | None | Build | 3 | rows 33, 34, 89, 90, 106 |
| Application audit and privileged activity log ingestion and search | Partial (usage aggregates) | Build | 3 | rows 43, 44 |
| SaaS license management and reclamation | None | Build | 3 | row 41 |
| Tenant customization: branding, labels and localization, navigation per role | None | Build | 3 | rows 96, 97, 99 |
| Configuration transport between environments (export/import packages with diff and approval) | Partial (policy in Git) | Build | 3 | rows 109, 110 |
| Archival and retention library for closed requests and campaigns | None | Build | 3 | row 84 |
| Tenant-facing log viewer for connectors and jobs | None | Build | 3 | row 103 |

### F. Later expansion

| Capability | Build / integrate | Source |
|---|---|---|
| Kubernetes RBAC effective permissions and admission policy | Build | D3·C18 |
| Application-level ReBAC (Zanzibar) | Integrate OpenFGA or SpiceDB | D3·C16 |
| Identity verification for recovery (IDV vendors, OpenID4VP, mDL); guest and contractor IAL2 proofing moved to Phase 2 (section C) | Integrate | D1·C18, D2·C24 |
| Hosted login on-ramp for companies without an IdP | Embed Ory or Keycloak | D1·C19 |
| Device posture as policy attributes (Intune, Jamf, CrowdStrike) | Integrate | D1·S12 |
| Role mining that outputs policy-as-code proposals (moved to Phase 3, section G) | Build | D4·C20 |
| CISA ZTMM v2 posture scoring | Build | D3·C19, D6·S18 |
| Intent-based authorization for agents | Build | D6·C19 |

## Build order

Each phase ends with exit criteria. A phase is done only when the criteria hold against a real sandbox account, not demo data.

### Phase 0: Make Tessera safe to connect (about 4 weeks)

Nothing touches a customer's real accounts until Tessera itself is secure.

- Per-tenant OIDC/SAML SSO, normalized `AuthnContext`, step-up for policy changes and approvals.
- API authentication with short-lived tokens; CLI via device flow.
- Append-only audit ledger for every read of customer data and every decision.
- Multi-tenant data isolation in the backend.

**Exit:** an admin signs in through Okta with a passkey; every API call is authenticated and audited; tenant isolation tests pass.

### Phase 1: Access-as-code for AWS, Snowflake, GitHub and Okta (about 10 weeks)

The wedge, done correctly on one cloud before going wide.

- Read-only connectors for AWS Organizations/IAM/Identity Center, Snowflake, GitHub and Okta.
- Exact AWS evaluator with explanations, plus a differential harness against AWS's simulator in a sandbox org.
- Cedar schema, policy repo, CI validation, and a formal diff posted on every PR.
- Drift detection.
- Usage-based least-privilege recommendations delivered as PRs.
- AWS NHI inventory with key age and owner inference.

**Exit:** on a sandbox AWS org the evaluator agrees with AWS on at least 99.5% of sampled checks. A policy PR shows exactly who gains or loses which permission. An unused-access recommendation merges and is verified by re-reading AWS.

### Phase 2: Governance on top of the graph (about 10 weeks)

- HRIS ingestion, correlation, orphan and dormant detection.
- JML with leaver kill-switch; closed-loop provisioning through SCIM and native APIs, verified by re-aggregation.
- Access requests with risk-tiered approvals in Slack.
- Certification campaigns with frozen populations, auto-decisions with sampled QA, evidence exports for SOC 2 and SOX.
- OAuth grant inventory, workload-federation trust analysis, escalation-path analysis, Terraform PR linting.
- Native groups with Grouper parity (engine, privileges, policy groups as code, loaders, verified provisioning, PIT history, Directory → Groups) and the Grouper import and cut-over connector. Design: [groups-grouper-parity.md](../design/groups-grouper-parity.md).
- Guest, applicant, pre-hire and partner identities with sponsorship, identity matching and account claim. Design: [guest-accounts-and-claim.md](../design/guest-accounts-and-claim.md).
- Phase 2 parity gaps from section G: notifications, organizations, application onboarding, datasets, entitlement rules, certificates.
- Deployment readiness for every connection: checklists, gated activation, dry-run reconciliation and deployment health. The MVP slice can be built before Phase 0 against the demo connectors. Design: [deployment-readiness.md](../design/deployment-readiness.md).

**Exit:** a SOC 2 auditor-style walkthrough can reproduce a review population and trace every revocation to a verified removal. A university pilot runs its access policy groups natively in Tessera with effective memberships matching Grouper for 7 days, and a sponsored contractor and an InCommon partner each complete the claim flow at their required IAL and AAL.

### Phase 3: JIT, privileged access and response (about 8 weeks)

- Token-exchange JIT broker using Identity Center, Entra PIM, GCP PAM and Snowflake grants.
- Credentials bound to the login session; break-glass.
- SSF/CAEP receiver; detections with one-click response.
- Azure and GCP evaluators; SoD engine.
- Grouper permissions and limits, long-tail group provisioners, B2B partner organizations, hosted guest credential service.
- Section G Phase 3 gaps: password management orchestration, role engineering, analytics and data analyzer, activity logs, license management, customization, configuration transport, archival.

**Exit:** standing prod admin on the sandbox drops to zero, and a revoked Okta session kills the matching AWS session in under 60 seconds.

### Phase 4: AI agents (about 8 weeks)

- Agent lifecycle with sponsors; delegation-aware token exchange.
- MCP 2026-07-28 authorization server; AuthZEN PDP.
- CIBA approvals; kill switch; ingestion from Entra Agent ID and Okta for AI Agents.

**Exit:** an MCP client acting for a user gets a token limited to user ∩ agent ∩ task, every tool call is decided and audited by policy, and the kill switch revokes it everywhere.

### Phase 5 and beyond

Gateway plugins, RAG authorization, Kubernetes, ReBAC, vault and PAM integrations, IDV, certificates, role mining and ZTMM scoring, ordered by customer demand.

## Recommended first piece of work

Phase 0 and the first item of Phase 1 can run in parallel:

1. **Phase 0:** add authentication, tenant isolation and the audit ledger to the MVP backend.
2. **Phase 1, step 1:** the AWS effective-permission evaluator, together with its differential test harness. It is the hardest, most defensible piece of the platform, and every later feature (simulation, least privilege, JIT, agent scoping) depends on it being right.

Ask `iam-architect` to produce the detailed design for either one before writing code.

## Keeping this knowledge base current

- When a standard changes status (OAuth 2.1, WIMSE, Transaction Tokens and SCIM Events are still drafts), update the relevant document and this map.
- When an expert agent finds an error or gap while reviewing work, fix the document in the same PR.
- Re-check `[unverified]` items before relying on them in customer-facing material.
