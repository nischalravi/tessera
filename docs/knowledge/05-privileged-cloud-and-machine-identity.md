# 05 — Privileged Access, Cloud Entitlements, Secrets and Non-Human Identity

*Tessera knowledge base · Domain 05 · Researched 2026-10-08 · Status: living document*

> Conventions: **[unverified]** means a claim could not be confirmed against a primary source during research. Vendor statistics are vendor-reported and should be cited as such. Market facts (M&A, product names) move quickly; re-check anything older than about 90 days before using it in customer-facing material.

---

## 1. Scope and why it matters

This domain covers the identities and entitlements that do the most damage when they are misused:

- **Privileged human access**: admins, SREs, DBAs, break-glass accounts, and the PAM tooling that governs them.
- **Infrastructure access**: SSH, RDP, Kubernetes, databases and cloud consoles, increasingly granted just in time (JIT) with ephemeral credentials rather than standing ones.
- **Cloud entitlements**: the very large and fast-changing permission graphs of AWS, Azure/Entra and GCP. The discipline that manages them is CIEM.
- **Non-human identities (NHIs)**: service accounts, workload identities, API keys, OAuth apps and grants, tokens, certificates, bots, CI/CD identities and, more and more, AI agents.
- **Secrets and machine identity / PKI**: vaults, rotation, secret sprawl, and the certificate lifecycle.
- **Identity security posture (ISPM) and identity threat detection and response (ITDR)**, including attack path analysis.

**Why this matters to Tessera's "access-as-code for cloud and data infrastructure" position:**

1. **Machines now outnumber people, and their credentials leak.** GitGuardian's *State of Secrets Sprawl 2026* (March 2026) counted about 28.65M new hardcoded secrets in public GitHub commits during 2025, up 34% year on year. Leaked AI-service secrets rose 81%. It also found that 64% of valid secrets leaked in 2022 were still unrevoked in 2026 (vendor-reported).
2. **The big incidents of 2023–2026 were mostly NHI incidents.** Examples include Midnight Blizzard (OAuth app abuse), Cloudflare (unrotated tokens), Snowflake customers (credentials with no MFA), Salesloft Drift, Gainsight and Klue (stolen OAuth tokens), and Vercel/Context.ai (an OAuth chain). The common thread is a long-lived, over-scoped, unowned credential that nobody watches.
3. **The market is consolidating fast.** Palo Alto Networks closed its acquisition of CyberArk (Feb 2026). Google closed Wiz (Mar 2026). Delinea bought StrongDM (closed Mar 2026). CrowdStrike bought SGNL (closed Feb 2026). Cisco is buying Astrix, SailPoint bought Entro, Cyera is buying Oasis, 1Password bought Apono, and ServiceNow announced Veza. PAM, CIEM, NHI and ISPM are merging into "identity security platforms". A newcomer has to be credible across all of them, or be the best at the access-as-code control plane that the others plug into.

---

## 2. Core concepts (precise definitions)

**Privileged account / privileged access.** An account or entitlement whose misuse can change security controls, reach sensitive data at scale, or affect availability. Examples are domain admin, cloud org admin, root, DB owner, Kubernetes cluster-admin, and CI deploy roles. Being privileged is a property of the effective permissions, not of the account type.

**PAM (Privileged Access Management).** Controls that discover, vault, broker, monitor and govern privileged access. Gartner's PAM market includes privileged account and session management (PASM), privilege elevation and delegation management (PEDM), secrets management, and cloud infrastructure entitlements/JIT capabilities.

- **Credential vaulting**: storing privileged credentials in a hardened, encrypted store that controls check-out/check-in, enforces approvals and logs access.
- **Password rotation**: the vault changes credentials on the target automatically, either on a schedule, after each use (one-time passwords), or on demand. Rotation needs a connector for each target (AD, Linux, DBs, network devices, SaaS).
- **Session brokering / proxying**: the user connects through a proxy or jump host that injects the credential, so the user never sees it. Protocols include RDP, SSH, HTTPS, database wire protocols and kubectl.
- **Session recording**: capturing video or keystrokes of RDP sessions, and command/query transcripts of SSH, DB and Kubernetes sessions, for audit and forensics. Recordings can often be searched and some products support live monitoring and termination.
- **PEDM (Privilege Elevation and Delegation Management)**: users run with least privilege and specific commands or apps are elevated on request. Examples are sudo policy management on Unix/Linux and admin-rights removal with app elevation on Windows/macOS.
- **EPM (Endpoint Privilege Management)**: PEDM on endpoints (removing local admin, controlling which applications may elevate, credential-theft protection).
- **Break-glass (emergency access) account**: a highly privileged account kept for emergencies such as an IdP outage or MFA failure. Best practice is cloud-only, excluded from normal conditional access but protected by phishing-resistant credentials (for example FIDO2 kept in a safe), heavily monitored, and tested regularly. Microsoft recommends at least two in Entra.
- **Privileged task automation**: running privileged actions as pre-approved, parameterized tasks or runbooks (for example "restart service X", "rotate key Y") so that no interactive admin session is needed.

**Standing privilege vs JIT vs ZSP.** *Standing privilege* is an entitlement that exists continuously whether it is used or not. *Just-in-time (JIT)* access is granted for a bounded time window after a request, with approval or policy, and is revoked automatically. *Zero Standing Privilege (ZSP)* means no identity holds privileged entitlements at rest: all privilege is ephemeral, scoped and created on demand. Ideally even the credential itself is minted per session.

**Ephemeral credentials.** Credentials created for one session or task with a short TTL. Examples are SSH certificates valid for minutes to hours, Vault dynamic DB users, AWS STS session credentials, GCP short-lived access tokens, and Kubernetes projected service-account tokens.

**SSH certificates.** OpenSSH certificates signed by an SSH CA bind a public key to principals, validity and extensions. Hosts trust the CA (`TrustedUserCAKeys`) instead of distributing `authorized_keys`, and clients trust host certs (`@cert-authority`). Teleport, Vault SSH secrets engine, Smallstep and cloud tools (for example GCP OS Login, AWS EC2 Instance Connect, which pushes temporary keys) use this or similar models.

**CIEM (Cloud Infrastructure Entitlement Management).** Discovers identities and entitlements across IaaS/PaaS. It computes *effective* permissions by evaluating identity policies, resource policies, permission boundaries, SCPs/RCPs, session policies, group and role inheritance, and cross-account trust. It compares granted with used permissions to find excess privilege, and recommends or enforces right-sizing. Gartner now treats CIEM largely as a capability inside CNAPP and PAM rather than a standalone market.

**CNAPP (Cloud-Native Application Protection Platform).** A unified platform covering CSPM, CWPP, CIEM, DSPM, IaC scanning and more. In a CNAPP, identity findings are one layer of a "security graph" that is correlated with network exposure, vulnerabilities and sensitive data ("toxic combinations").

**Non-human identity (NHI).** Any identity that authenticates without a human present at the moment of authentication. Types:

| Type | Examples | Typical credential |
|---|---|---|
| Cloud workload identity | AWS IAM role on EC2/Lambda, Azure managed identity, GCP service account attached to a VM | Short-lived tokens from instance metadata (good) |
| Static cloud credential | AWS IAM user access key (AKIA…), GCP SA JSON key, Azure SP client secret | Long-lived secret (bad) |
| Directory service account | AD service accounts, gMSA, Entra service principals | Password / Kerberos keys / secret / cert |
| Kubernetes service account | `default`/app SAs, controllers | Projected JWT (bound, short-lived) or legacy secret token |
| API keys & PATs | Stripe/OpenAI keys, GitHub PATs, Slack bot tokens | Bearer secret |
| OAuth apps & grants | Third-party SaaS integrations (Drift, Gainsight, Klue), Entra app registrations, Google Workspace domain-wide delegation | Client secret/cert plus access/refresh tokens |
| Certificates & keys | TLS server certs, mTLS client certs, code-signing, SSH host/user keys, SAML/OIDC signing keys | Private key |
| CI/CD identities | GitHub Actions OIDC, GitLab, Jenkins credentials | OIDC JWT (good) or stored secrets (bad) |
| Bots / RPA / AI agents | RPA bots, chatbots, LLM agents with tool access, MCP servers | Any of the above, often delegated from a human |

**NHI lifecycle.** Creation, then registration with an owner and purpose, credential issuance, use, rotation, review/recertification, and decommissioning. Ownership matters most, because most NHIs have no accountable human. That is why "orphaned" and "improper offboarding" is the #1 OWASP NHI risk.

**Workload identity federation.** A workload proves who it is with a platform-issued token (OIDC JWT from GitHub/Kubernetes/another cloud, or an X.509 SVID) and exchanges it for short-lived cloud credentials. No stored secret is involved. Examples are AWS `AssumeRoleWithWebIdentity` and IAM Roles Anywhere, GCP Workload Identity Federation, and Entra workload identity federation (federated identity credentials).

**SPIFFE / SPIRE.** SPIFFE is a CNCF graduated standard for workload identity. It defines SPIFFE IDs (`spiffe://trust-domain/path`), SVIDs (X.509 or JWT) and the Workload API. SPIRE is the reference implementation.

**Secrets management.** Centralized storage, access control, auditing, dynamic generation, leasing/revocation and rotation of secrets. **Secret sprawl** is secrets duplicated across code, CI variables, env files, chat, tickets, wikis and container images. **Secret scanning** is detection with regex/entropy/ML plus validity checks.

**Machine identity management / CLM.** Inventory, issuance, renewal, revocation and policy for X.509 certificates and keys, including automation over ACME (RFC 8555).

**ISPM (Identity Security Posture Management).** Continuous assessment of identity configuration and hygiene across IdPs, directories, cloud and SaaS. It covers MFA gaps, stale accounts, risky permissions, misconfigured federation, shadow admins and attack paths, with prioritized remediation. It is the identity counterpart to CSPM.

**ITDR (Identity Threat Detection and Response).** Detection of attacks against identity infrastructure and identity use (credential stuffing, token theft/replay, MFA fatigue, Kerberoasting, DCSync, golden SAML, OAuth consent abuse, anomalous NHI use), plus response actions (revoke sessions/tokens, disable, step-up, rotate).

**Identity attack path.** A chain of identity relationships such as membership, role assignment, ownership, ACL rights, trust policies, delegation and "can reset password of", which lets a principal reach a target privilege. BloodHound models these as a directed graph and uses shortest-path queries.

---

## 3. Standards and frameworks

| Name | Body | Version / status (as of Oct 2026) | Relevance | Link |
|---|---|---|---|---|
| OWASP Non-Human Identities Top 10 | OWASP | 2025 edition (first release; ranked with OWASP Risk Rating Methodology) | NHI risk taxonomy; map detections to it | https://owasp.org/www-project-non-human-identities-top-10/2025/ |
| NIST SP 800-53 Rev. 5 (AC-2, AC-6, IA-5, AU) | NIST | Rev 5 (release 5.1.x/5.2) | Account mgmt, least privilege, authenticator mgmt, audit | https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final |
| NIST SP 800-207 Zero Trust Architecture | NIST | Final (2020) | PDP/PEP model that underpins JIT brokers | https://csrc.nist.gov/pubs/sp/800/207/final |
| NIST SP 800-63-4 Digital Identity Guidelines | NIST | Final (Aug 2025) | Authenticator assurance; phishing-resistance for admins | https://pages.nist.gov/800-63-4/ |
| NIST IR 8587 (protecting tokens and assertions from forgery/theft) | NIST | Draft/final status [unverified] | Post-Storm-0558 token signing-key protection guidance | https://csrc.nist.gov/ |
| CIS Controls v8.1 (Controls 5 & 6) | CIS | v8.1 | Account and access-control management | https://www.cisecurity.org/controls |
| CIS Benchmarks (AWS/Azure/GCP/Kubernetes) | CIS | Rolling versions | Concrete IAM config checks | https://www.cisecurity.org/cis-benchmarks |
| MITRE ATT&CK | MITRE | v19 released 28 Apr 2026 (Defense Evasion split into *Stealth* and *Defense Impairment*); v19.2 in Aug 2026 | Technique IDs for detections | https://attack.mitre.org/resources/updates/ |
| CA/B Forum Ballot SC-081v3 | CA/Browser Forum | Adopted 2025; 200-day max since 15 Mar 2026 → 100 days on 15 Mar 2027 → 47 days on 15 Mar 2029; DCV reuse falls to 10 days by 2029 | Forces certificate automation | https://cabforum.org/ |
| ACME (RFC 8555) + ARI (RFC 9773) | IETF | Standards | Automated cert issuance and renewal timing | https://www.rfc-editor.org/rfc/rfc8555 |
| SPIFFE | CNCF | Graduated | Workload identity format and API | https://spiffe.io/ |
| IETF WIMSE WG | IETF | Drafts: architecture -08 (Jul 2026, Informational); workload-creds -01 and mutual-tls -01 (May 2026, Standards Track); identifier -02; workload-identity-practices -07 submitted to IESG (Sep 2026) | Emerging workload-to-workload identity standard | https://datatracker.ietf.org/wg/wimse/about/ |
| OAuth 2.0 Token Exchange (RFC 8693); Transaction Tokens draft | IETF | RFC; draft-ietf-oauth-transaction-tokens status [unverified] | Delegation chains for workloads and agents | https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/ |
| OAuth 2.0 DPoP (RFC 9449) | IETF | RFC | Sender-constrained tokens; mitigates replay of stolen tokens | https://www.rfc-editor.org/rfc/rfc9449 |
| Shared Signals Framework / CAEP / RISC | OpenID Foundation | SSF 1.0, CAEP 1.0 final (2025) | Real-time revocation signals between IdP, SaaS and Tessera | https://openid.net/wg/sharedsignals/ |
| Kubernetes RBAC good practices | Kubernetes SIG Auth | Living doc | K8s privilege escalation verbs and SA token guidance | https://kubernetes.io/docs/concepts/security/rbac-good-practices/ |
| CISA / NSA guidance on cloud IAM (e.g., "Use Secure Cloud IAM Practices", 2024) | CISA/NSA | Published Mar 2024 | Government baseline | https://www.cisa.gov/resources-tools/resources |
| PCI DSS v4.0.1 (Req. 7, 8.6 — system/application accounts) | PCI SSC | v4.0.1; future-dated reqs effective 31 Mar 2025 | Explicit controls on application/system account passwords and interactive use | https://www.pcisecuritystandards.org/ |

**OWASP NHI Top 10 (2025)** — Tessera should map every NHI finding to one of these:

1. NHI1 Improper Offboarding
2. NHI2 Secret Leakage
3. NHI3 Vulnerable Third-Party NHI
4. NHI4 Insecure Authentication
5. NHI5 Overprivileged NHI
6. NHI6 Insecure Cloud Deployment Configurations
7. NHI7 Long-Lived Secrets
8. NHI8 Environment Isolation
9. NHI9 NHI Reuse
10. NHI10 Human Use of NHI

---

## 4. How it works (flows and diagrams)

### 4.1 Classic PAM (vault + session broker)

```
Admin ──SSO+MFA──► PAM portal ──policy/approval──► Vault (checkout)
   │                                                 │ injects credential
   └──────── RDP/SSH via PAM proxy (PSM/jump) ◄──────┘
                     │  records session, enforces commands
                     ▼
               Target server / DB / network device
Vault ──rotation connector──► target (rotate after checkin / on schedule)
```
Strengths: works with legacy systems, gives strong audit. Weaknesses: credentials still exist (standing), connectors are brittle, and the proxy can become a bottleneck or a high-value target.

### 4.2 Modern JIT / ZSP infrastructure access (Teleport, StrongDM, Boundary pattern)

```
Engineer ─OIDC SSO+device trust─► Access plane (auth service)
          ─request role "db-prod-ro" (15m)─► policy engine / approver (Slack, ChatOps)
Access plane mints short-lived credential:
   • SSH user cert (CA-signed, principals, TTL)
   • X.509 client cert for DB/K8s, or
   • dynamic DB user via Vault/DB plugin, or
   • AWS STS session for the console/CLI
Engineer ──► identity-aware proxy ──► target  (audit + session recording at proxy)
TTL expires → credential is useless; nothing to rotate or revoke
```
Teleport uses its own CA and agents/proxy and is open-core. StrongDM uses a gateway/relay mesh with credential injection and policy-based authorization; it is now part of Delinea. Boundary is an identity-aware proxy that brokers or injects credentials from Vault.

### 4.3 Workload identity federation (no stored secrets)

```
GitHub Actions job ──requests OIDC JWT (iss=token.actions.githubusercontent.com,
                     sub=repo:org/app:ref:refs/heads/main, aud=sts.amazonaws.com)
     └──► AWS STS AssumeRoleWithWebIdentity
          Role trust policy conditions on iss/aud/sub ──► 1h session creds
```
The security of this flow depends entirely on the trust-policy conditions. A wildcard `sub` (for example `repo:org/*`) lets any repo, or a fork's workflow, assume the role. This is one of the highest-value checks Tessera can ship. GCP WIF uses attribute mappings and conditions, and Entra uses federated identity credentials (issuer + subject + audience).

### 4.4 Cloud specifics

**AWS**
- *IAM Identity Center* (successor to AWS SSO) federates workforce users from an IdP (SAML/SCIM). It provisions **permission sets** into accounts as `AWSReservedSSO_*` roles. AWS offers a "temporary elevated access" reference pattern, and partners (for example Britive, CyberArk, Okta) provide JIT.
- *Roles and trust policies*: a role's trust policy (resource policy on the role) says who can call `sts:AssumeRole*`. Cross-account trusts without `sts:ExternalId` invite confused-deputy attacks. `Principal: {"AWS": "*"}` with weak conditions is critical. Role chaining caps sessions at 1 hour.
- *Access keys*: IAM user keys (`AKIA…`) are long-lived. STS keys (`ASIA…`) are temporary. AWS guidance is to avoid IAM users for workloads and humans (use roles/Identity Center/Roles Anywhere).
- *Guardrails*: SCPs (max permissions for principals in an org), RCPs (resource control policies, launched Nov 2024; max permissions on resources), permission boundaries, and session policies.
- *IAM Access Analyzer*: **external access** findings (free) flag resources shared outside the zone of trust. **Unused access** findings (paid, per role/user/month) flag unused roles, unused access keys and passwords, and unused services/actions on active principals. **Internal access** findings (launched June 2025, paid per resource) use automated reasoning across identity policies, resource policies, SCPs and RCPs to show which principals in the org can reach S3, DynamoDB and RDS resources. Custom policy checks (`CheckNoNewAccess`, `CheckAccessNotGranted`) are useful for policy-as-code CI gates. Findings go to EventBridge and Security Hub.
- *Logs*: CloudTrail (`AssumeRole*`, `CreateAccessKey`, `AttachRolePolicy`, `PutRolePolicy`, `UpdateAssumeRolePolicy`, `GetFederationToken`, `ConsoleLogin`); IAM credential report; last-accessed data.

**Azure / Entra**
- *PIM (Privileged Identity Management, Entra ID P2 / ID Governance)*: makes Entra roles, Azure RBAC roles and PIM-for-Groups **eligible** rather than active. It supports time-bound activation with MFA, justification, approval, ticket number, access reviews and alerts.
- *Service principals and app registrations*: an app registration (the application object, global) is instantiated as a service principal in each tenant. Credentials are client secrets, certificates or federated identity credentials. Permissions are **delegated** (act as a user) or **application** (app-only, for example Graph `Mail.Read` across all mailboxes). High-risk app permissions include `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All` and Exchange `full_access_as_app`. App **owners** can add credentials to an app, which is a classic escalation path.
- *Managed identities*: system- or user-assigned service principals whose credentials Azure manages. Tokens come from IMDS, so there are no secrets to leak, though over-privileged role assignments are still a risk.
- *Microsoft Entra Agent ID* (2025–2026): a distinct identity type for AI agents (agent blueprints, agent identities, with dedicated admin roles such as Agent ID Administrator and Agent ID Developer). Whether PIM eligibility applies to agent identities and managed identities is [unverified].
- *CIEM*: Microsoft retired standalone **Entra Permissions Management** (sales stopped Apr/May 2025, retired 1 Nov 2025). CIEM now lives in **Defender CSPM** (Defender for Cloud). Defender is also deprecating the Permissions Creep Index (PCI) in favour of activity-based CIEM logic. This leaves a gap for vendor-neutral, multi-cloud CIEM, which competitors are targeting explicitly.

**GCP**
- *Service accounts*: these are both identities and resources. Principals with `iam.serviceAccountUser` (actAs) or `iam.serviceAccountTokenCreator` on an SA can act as it, which is the key escalation primitive. Default compute SAs historically had project Editor.
- *Keys*: user-managed SA JSON keys are long-lived. Under **secure-by-default organization policies**, organizations created on or after 3 May 2024 have SA key creation and key upload disabled by default (`iam.disableServiceAccountKeyCreation` / `iam.managed.disableServiceAccountKeyCreation`), and default SAs no longer get automatic Editor grants.
- *Workload Identity Federation*: external OIDC/SAML/AWS/X.509 identities exchanged via STS for federated tokens or SA impersonation. *Workload Identity Federation for GKE* maps KSAs to IAM.
- *Tooling*: IAM Recommender (role recommendations from 90-day usage), Policy Analyzer, Policy Troubleshooter, Privileged Access Manager (Google Cloud's native JIT entitlement grants, GA 2024), and deny policies.

**Kubernetes**
- RBAC uses Role/ClusterRole bound through RoleBinding/ClusterRoleBinding to users, groups or ServiceAccounts. Escalation-relevant permissions include `escalate`, `bind`, `impersonate`, `create pods` (which lets you mount any SA in the namespace), `get secrets`/`list secrets`, `create serviceaccounts/token`, `nodes/proxy`, and wildcard `*`. Also watch `system:masters` and certificate signing (`certificatesigningrequests/approval`).
- SA tokens: since v1.24 there are no auto-generated long-lived secret tokens. Pods get **bound projected tokens** that are audience-scoped and time-limited. Legacy token secrets still exist in older clusters. Cloud mappings (IRSA / EKS Pod Identity, Azure Workload Identity, GKE WIF) link KSAs to cloud IAM.
- EKS access entries replace `aws-auth` ConfigMap management. AKS uses Entra integration. GKE uses IAM plus RBAC.

### 4.5 Secrets management and rotation

```
App ──auth (K8s SA JWT / IAM role / AppRole / OIDC)──► Vault / Secrets Manager
      ◄── static secret (KV) or dynamic secret (DB user, cloud creds, PKI cert) with lease
Lease expires/revoked → backend deletes DB user / IAM key
Rotation lambdas (AWS SM) or Vault rotation → update target + secret version
```
- **AWS Secrets Manager**: managed rotation through Lambda or managed rotation for RDS/Redshift/DocumentDB. Resource policies, replication, KMS encryption.
- **Vault (HashiCorp, IBM since Feb 2025)**: KV, dynamic secrets engines (DB, AWS, Azure, GCP, SSH, PKI), identity-based auth methods, leases. Recent HashiCorp/IBM blog items mention "IBM Vault" branding, AI-agent support and secret sync with workload identity federation (2026) [details unverified].
- Others: Azure Key Vault, GCP Secret Manager, CyberArk Conjur / Secrets Hub (syncs to cloud-native stores), Akeyless, Doppler, Infisical, 1Password Secrets Automation.
- **Scanning**: GitGuardian, GitHub Secret Scanning and Push Protection, TruffleHog, Gitleaks. Validity checks call the provider API to see whether the key is live.

### 4.6 Certificate lifecycle under SC-081

Maximum public TLS validity is now **200 days** (since 15 Mar 2026). It falls to **100 days** on 15 Mar 2027 and **47 days** on 15 Mar 2029, with domain-validation reuse shrinking to 10 days. At 47 days, manual renewal is not feasible. Every public cert must be discovered, owned and renewed over ACME/ARI or a CLM integration. Private PKI (mTLS, SPIFFE) is not bound by these rules but is moving to hours-to-days lifetimes anyway. Since Tessera is not a CA, the opportunity is **inventory and ownership plus expiry and drift detection**, linking each cert to the workload and identity graph.

### 4.7 Attack path graph (BloodHound-style)

Nodes are principals, groups, roles, resources, apps, keys and devices. Edges include `MemberOf`, `HasRole`, `CanAssume`, `Owns`, `CanResetPassword`, `GenericAll`, `AddKeyCredential`, `CanImpersonate`, `HasSecret` and `TrustedBy`. Tier-0 / "privilege zones" are the targets, and the analysis computes all paths from low-privilege nodes into them. BloodHound covers AD and Entra/Azure (AzureHound). In March 2026, **OpenGraph extensions** in BloodHound Enterprise added Okta, GitHub and Jamf-managed Mac. Cloud equivalents include PMapper (AWS), Cartography (open source, Lyft origin, now CNCF sandbox [unverified]), and the security graphs inside Wiz, Orca and Prisma/Cortex Cloud.

---

## 5. How the market implements it

### 5.1 Consolidation snapshot (2025–2026)

| Deal | Status | Why it matters |
|---|---|---|
| Palo Alto Networks ← CyberArk (~$25B) | Announced Jul 2025; **closed 11 Feb 2026** | Largest identity deal ever; PAM + NHI + Venafi (CLM, acquired by CyberArk 2024) + Zilla (IGA, 2025) inside a network/SOC vendor |
| Google ← Wiz ($32B) | Announced Mar 2025; **closed 11 Mar 2026** | Leading CNAPP/CIEM now inside Google Cloud; still multi-cloud |
| Delinea ← StrongDM | Signed Jan 2026; **closed 5 Mar 2026** | Vault-centric PAM + runtime-authorization infra access |
| CrowdStrike ← SGNL | Signed 7 Jan 2026; **closed 20 Feb 2026** (~$628M cash per 10-K) | Continuous/JIT authorization joins Falcon identity (ITDR) |
| Okta ← Axiom Security | Closed 4 Sep 2025 | Cloud-native JIT for DBs/K8s into Okta Privileged Access |
| ServiceNow ← Veza | Announced Dec 2025; close status [unverified] | Access graph and ISPM into ITSM/GRC |
| Cisco ← Astrix | Announced ~4–5 May 2026 (reported ~$250–400M); close status [unverified] | NHI and AI-agent security into Duo/Identity Intelligence |
| SailPoint ← Entro | Completed Jun 2026 (reported ~$200M) | NHI discovery and secrets context into IGA |
| Cyera ← Oasis Security | Announced/LOI 28 Jul 2026 (reported ~$1B) | NHI joins DSPM (data-centric) |
| 1Password ← Apono | Announced 15 Jun 2026 | JIT cloud access into password manager / "Unified Access" |
| IBM ← HashiCorp ($6.4B) | Closed Feb 2025 | Vault/Boundary under IBM |
| Okta ← Permiso; Snowflake ← Natoma | Reported 2026 [unverified] | ITDR and AI-agent identity |

**Takeaway:** standalone NHI, JIT and ISPM startups are being absorbed by platforms. Remaining independents include Teleport, Britive, Aembit, Clutch, Silverfort, Token Security, Andromeda and P0 Security. Buyers now expect one graph covering humans, NHIs and agents across IdP, cloud, SaaS and data.

### 5.2 Vendor landscape by capability

**Enterprise PAM.** The 2025 Gartner MQ for PAM (Oct 2025) named CyberArk, BeyondTrust and Delinea as Leaders, per vendor press releases. The full Leaders list is [unverified].
- **CyberArk (Palo Alto Networks)**: the broadest suite. It covers Privilege Cloud/PAM self-hosted (vault, CPM rotation, PSM session isolation), Endpoint Privilege Manager, Secure Infrastructure Access (ZSP/JIT, formerly Idaptive/Sia), Secure Cloud Access (JIT cloud roles), Conjur and Secrets Hub (secrets), Venafi (machine identity/CLM), Identity Security Intelligence (ITDR), and positioning for "secure AI agents". Its differentiator is depth with legacy and regulated estates. The downside is complexity and cost.
- **BeyondTrust**: Password Safe, Privileged Remote Access, EPM for Windows/Mac and Linux, and **Identity Security Insights** (ISPM/ITDR with "true privilege" graph). A cautionary note: its Remote Support SaaS API key was abused in the Dec 2024 US Treasury intrusion (see §6).
- **Delinea**: Secret Server and Platform, Privilege Manager (EPM), Server PAM (PEDM), Cloud Infrastructure Entitlements (CIEM), Iris AI, and now **StrongDM** (runtime/continuous authorization across infra protocols). It also bought Fastpath (IGA/SoD, 2024).
- Others: Saviynt (cloud PAM within IGA), One Identity Safeguard, Wallix, Senhasegura (Segura), ManageEngine PAM360, Netwrix, Keeper PAM, Okta Privileged Access (+Axiom), and Microsoft Entra PIM (native, Entra/Azure only).

**Modern infrastructure access (developer-first, JIT/ZSP).**
- **Teleport**: open-core access plane with its own CA. It covers SSH/K8s/DB/RDP/web apps/cloud consoles, short-lived certs, session recording, access requests, device trust, and **Machine & Workload Identity** (tbot, SPIFFE-compatible SVIDs). It also markets agent identity ("Beams" trusted agent runtimes [unverified detail]). Its strength is that identity, proxy and CA are one coherent system. The weakness is that it needs agents and a proxy in the data path.
- **StrongDM (Delinea)**: protocol-aware proxy mesh with credential injection, fine-grained policy (Cedar-based [unverified]), and query/command-level audit.
- **HashiCorp Boundary**: identity-aware proxy with Vault credential brokering/injection. Session recording was added for SSH and later RDP [2026 RDP recording and "1.0" milestone unverified].
- **Britive**: cloud-native ZSP/JIT for cloud roles, SaaS, DBs and K8s. It uses API-driven ephemeral permission creation in AWS/Azure/GCP (no agents) and is the closest analogue to "access-as-code" for cloud entitlements.
- **Apono (1Password)**, **P0 Security**, **ConductorOne** and **Opal**: JIT/access-request platforms with Slack-native flows and policy as code. Also **Indent** (acquired by Abnormal, 2024 [unverified]) and **Sym** [status unverified].
- Cloud-native JIT options: AWS (Identity Center plus TEAM reference solution), GCP Privileged Access Manager, Entra PIM.

**CIEM / CNAPP.**
- **Wiz (Google)**: agentless security graph across clouds. CIEM computes effective permissions (including cross-account and K8s), flags admin/privilege-escalation paths and exposed secrets on workloads, and correlates with vulns, exposure and data ("toxic combinations"). Wiz Defend adds detection.
- **Palo Alto Prisma Cloud / Cortex Cloud**: CIEM module [product lineage unverified]. It provides net-effective permissions, over-privileged findings and IAM query language (RQL `config from iam`). Palo Alto is merging Prisma Cloud into **Cortex Cloud** (2025) and adding CyberArk.
- **Microsoft Defender for Cloud (Defender CSPM)**: CIEM for Azure, AWS and GCP after the Entra Permissions Management retirement. Activity-based inactive-identity and over-permission recommendations replace PCI. Attack path analysis is in the cloud security graph.
- **Tenable Cloud Security** (Ermetic, acquired 2023): strong CIEM and JIT. Also **Orca**, **SentinelOne Cloud Native Security**, **CrowdStrike Falcon Cloud Security**, **Sonrai Security** (Cloud Permissions Firewall: auto-quarantine unused identities and privileges), and **Check Point CloudGuard**.
- Difference from PAM: CNAPPs *find and recommend* well but rarely *broker or grant*. PAM/JIT tools *grant* but have weak graph analytics. Tessera's opening is to combine analysis with enforcement, expressed as code.

**NHI security (discovery, posture, lifecycle).**
- **Astrix (→ Cisco)**: NHI discovery across SaaS, IaaS and AI agents; OAuth app and third-party connection risk; ITDR for NHIs. It published the Gainsight/Salesforce analysis.
- **Oasis Security (→ Cyera)**: NHI inventory, ownership attribution and lifecycle/rotation workflows across cloud, on-prem and vaults.
- **Entro (→ SailPoint)**: secrets-centric NHI. It scans vaults, code and collaboration tools, and adds context and anomaly detection to secrets.
- **Aembit**: "workload IAM". It brokers access between workloads with policy and secretless credential injection or federation, and covers AI agents. Independent; backed by Okta Ventures and CrowdStrike Falcon Fund.
- **Clutch Security**: NHI discovery and "zero trust for NHI" with ephemeral identities. Independent (Series A $20M).
- **Token Security**, **Natoma** (→ Snowflake [unverified]), **Andromeda**, **Veza (→ ServiceNow)**: access graph including NHIs. **GitGuardian** (NHI governance on top of secret scanning). **Valence**, **AppOmni**, **Obsidian** (SaaS OAuth/SaaS posture).

**ISPM / ITDR and attack paths.**
- **Silverfort**: inline MFA and protection for AD/Kerberos/NTLM and legacy protocols, plus service-account discovery and "virtual fencing" of service accounts to known sources/destinations. This is unique for on-prem NHIs.
- **CrowdStrike Falcon Identity Protection** (+SGNL), **Microsoft Defender for Identity**, **Semperis** (AD/Entra resilience), **Quest**, **Netwrix**, **BeyondTrust Identity Security Insights**, **Okta ISPM (Spera, acquired 2024)** and Identity Threat Protection, **Rezonate** (→ Palo Alto? [unverified]), **Push Security**, **Permiso**.
- **SpecterOps BloodHound** (CE open source; Enterprise SaaS with OpenGraph extensions as of Mar 2026). This is the *de facto* attack-path model.

**Secrets & PKI.** HashiCorp/IBM Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, CyberArk Conjur/Secrets Hub, Akeyless, Doppler, Infisical; CLM: Venafi (CyberArk), Keyfactor, AppViewX, DigiCert Trust Lifecycle, Sectigo, Smallstep, cert-manager (CNCF).

### 5.3 Notable architectural differences

| Axis | Option A | Option B | Note for Tessera |
|---|---|---|---|
| Credential model | Vault + rotate (CyberArk, Delinea) | Mint ephemeral, nothing at rest (Teleport, Britive) | Prefer B, but integrate A for legacy |
| Data path | Inline proxy (Teleport, StrongDM, Boundary, PSM) | Control-plane only via API (Britive, CNAPP, Access Analyzer) | API-only first; optional proxy later for recording |
| Deployment | Agents | Agentless API scanning | Agentless discovery is table stakes |
| Policy | GUI rules | Policy-as-code (Cedar, Rego, HCL, YAML in Git) | Core Tessera differentiator |
| NHI focus | Secrets (Entro, GitGuardian) | Identities/grants (Astrix, Oasis, Clutch) | Need both: identity *and* each of its credentials |

---

## 6. Threats, attacks and real incidents

### 6.1 Incident timeline (2023–2026)

| Date | Incident | Identity failure | OWASP NHI | Source |
|---|---|---|---|---|
| Jul 2023 | **Microsoft / Storm-0558**: forged Exchange Online tokens using a stolen MSA consumer signing key | Key management; token validation | NHI2/NHI7 | CSRB report (Mar 2024) |
| Oct 2023 | **Okta support system**: attacker used a service account whose creds an employee had saved to a personal Google profile; stole HAR files with session tokens of customers | Human use of NHI; session token theft | NHI10, NHI2 | Okta root-cause post |
| Nov 2023 | **Cloudflare "Thanksgiving"**: Nation-state used **one access token and three service account credentials** stolen in the Okta breach and **not rotated**; accessed Atlassian Confluence/Jira/Bitbucket | Incomplete rotation after third-party breach | NHI7, NHI3 | Cloudflare blog |
| Nov 2023–Jan 2024 | **Microsoft / Midnight Blizzard**: password spray on legacy non-prod test tenant account without MFA → compromised a **legacy test OAuth app** with elevated access → created malicious OAuth apps, granted Exchange **full_access_as_app** → read exec mailboxes via EWS | Orphaned overprivileged OAuth app; test-to-prod trust | NHI1, NHI5, NHI8 | MSRC, Microsoft Security blog (Jan 2024) |
| Apr–Jun 2024 | **Snowflake customer intrusions (UNC5537)**: ~165 orgs; credentials from infostealer logs dating to 2020; ≥79.7% previously exposed; no MFA, no network allowlists; extortion | Long-lived single-factor credentials, many for service/ETL use | NHI4, NHI7 | Mandiant/GTIG (Jun 2024) |
| Oct 2024 | **Internet Archive**: Zendesk API tokens left unrotated after earlier exposure (in GitLab) were used to access support tickets | Unrotated leaked tokens | NHI2, NHI7 | Press (BleepingComputer) [secondary] |
| Dec 2024 | **US Treasury via BeyondTrust Remote Support SaaS**: attackers (attributed to Chinese state actor Silk Typhoon) obtained a **Remote Support SaaS API key**, reset local app passwords | Vendor-held privileged API key | NHI3, NHI2 | BeyondTrust advisory; Treasury letter |
| Mar 2025 | **tj-actions/changed-files (CVE-2025-30066)**: compromised GitHub Action dumped CI secrets into public logs in ~23k repos; root traced to reviewdog and a stolen PAT | CI secrets exposure; PAT compromise | NHI2, NHI3 | CISA alert 18 Mar 2025 |
| Mar–Aug 2025 | **Salesloft Drift (UNC6395)**: actor in Salesloft GitHub from Mar 2025 → Drift AWS → stole Drift OAuth/refresh tokens → 8–18 Aug 2025 mass SOQL exports from customer Salesforce orgs; hunted for AWS keys (AKIA), Snowflake tokens, passwords in exported data; Drift tokens revoked 20 Aug | Third-party OAuth grant with broad scopes; secrets in CRM data | NHI3, NHI5, NHI2 | GTIG (Aug 2025); Salesloft updates |
| Sep 2025 | **Shai-Hulud npm worm**: self-propagating malware stole npm/GitHub/cloud tokens from developer machines and CI, republished packages | Developer token theft at scale | NHI2, NHI7 | CISA alert 23 Sep 2025 |
| Oct–Nov 2025 | **Gainsight apps / Salesforce**: recon from 23 Oct, mass extraction 18–19 Nov; Salesforce revoked Gainsight tokens (advisory 20 Nov); ShinyHunters claimed access derived from Drift-era theft [claim unverified] | Third-party OAuth token reuse | NHI3 | Salesforce advisory; Astrix analysis |
| Feb–Apr 2026 | **Context.ai → Vercel**: Context.ai AWS compromise (Mar 2026), OAuth tokens of its users stolen; attacker used a Vercel employee's Context.ai OAuth grant to take over their Google Workspace account, then read non-"sensitive" environment variables of some customer projects (Vercel bulletin, Apr 19–21, 2026) | Shadow-AI OAuth grant to corporate Workspace; secrets in env vars | NHI3, NHI2, NHI8 | Vercel KB bulletin; The Register |
| Jun 2026 | **Klue**: a compromised *legacy* credential from an abandoned integration prototype gave access; attacker pushed code to harvest customer OAuth tokens (Salesforce, Gong), minted fresh Salesforce API tokens, exfiltrated CRM data (victims reportedly include LastPass, Huntress, Recorded Future); Salesforce disabled the Klue integration 19 Jun 2026 | Orphaned credential + third-party OAuth tokens | NHI1, NHI3 | The Hacker News; Nudge, Field Effect analyses |

**Pattern for product design.** Five of the last six major incidents follow one chain: SaaS vendor compromise, then stolen OAuth/refresh tokens, then bulk API export from the customer tenant, then secrets harvested from the exported data, then pivot. The defences are an **inventory of third-party OAuth grants with scopes and owners**, a **behavioural baseline per integration** (volume, objects, IPs, user agents), **fast bulk revocation**, and **secret scanning of SaaS data stores** (CRM cases, tickets).

### 6.2 MITRE ATT&CK identity techniques (Enterprise, v19)

| Technique | ID | Notes for detection |
|---|---|---|
| Valid Accounts: Default / Domain / Local / **Cloud Accounts** | T1078 (.001–.004) | Baseline-driven anomaly detection on NHIs |
| Account Manipulation: Additional Cloud Credentials / Additional Email Delegate / **Additional Cloud Roles** / SSH Authorized Keys / Device Registration | T1098 (.001, .002, .003, .004, .005) | New SP secret, new access key, role attach, authorized_keys change |
| Unsecured Credentials: Credentials in Files / Cloud Instance Metadata API / Container API / Private Keys | T1552 (.001, .005, .007, .004) | IMDS abuse, secrets in env/images |
| Steal Application Access Token | T1528 | OAuth token theft (Drift, Klue) |
| Use Alternate Authentication Material: Application Access Token / Pass the Hash / Pass the Ticket / Web Session Cookie | T1550 (.001–.004) | Token replay from new ASN/UA |
| Steal or Forge Kerberos Tickets (Golden/Silver, Kerberoasting, AS-REP roasting) | T1558 | Service-account SPNs with weak passwords |
| Forge Web Credentials: SAML tokens | T1606.002 | Golden SAML |
| OS Credential Dumping (LSASS, DCSync) | T1003 | Tier-0 |
| Brute Force: Password Spraying / Credential Stuffing | T1110.003/.004 | Midnight Blizzard, Snowflake |
| Modify Authentication Process / Domain or Tenant Policy Modification (trust/federation changes) | T1556, T1484.002 | New federated domain, IdP added |
| Create Account: Cloud Account | T1136.003 | Persistence |
| Cloud Service Discovery / Permission Groups Discovery / Account Discovery | T1526, T1069.003, T1087.004 | Enumeration bursts (e.g., `iam:List*`, `GetAuthorizationDetails`) |
| Data from Information Repositories / Transfer Data to Cloud Account | T1213, T1537 | Bulk SOQL exports |
| Impair Defenses (now under **Defense Impairment** in v19): disable cloud logs | T1562.008 | `StopLogging`, diagnostic setting deletion |

Note: ATT&CK v19 split *Defense Evasion* into **Stealth** and **Defense Impairment**, so any Tessera detection metadata should use v19 tactic names.

### 6.3 Common privilege-escalation primitives (to model as graph edges)

- **AWS**: `iam:PassRole` + `lambda:CreateFunction`/`ec2:RunInstances`/`glue:CreateDevEndpoint`; `iam:CreatePolicyVersion`; `iam:AttachUserPolicy`/`PutRolePolicy`; `iam:UpdateAssumeRolePolicy`; `iam:CreateAccessKey` on another user; `sts:AssumeRole` via permissive trust; `ssm:SendCommand` to instances with strong roles.
- **Azure/Entra**: app/SP owner → add credential → app-only Graph permissions; `Application Administrator` / `Cloud Application Administrator` over privileged SPs; `Privileged Role Administrator`; Azure `Owner`/`User Access Administrator` → role assignment; Automation account / VM run command with managed identity.
- **GCP**: `iam.serviceAccounts.actAs`, `getAccessToken`, `signJwt`, `implicitDelegation`; `setIamPolicy` at any level; `compute.instances.setMetadata` (SSH key injection); deploying Cloud Functions/Run as a privileged SA.
- **Kubernetes**: `create pods` + privileged SA in namespace; `bind`/`escalate`; `impersonate`; `nodes/proxy`; secrets read; hostPath/privileged pods leading to node and then cloud IMDS creds.
- **AD**: Kerberoastable service accounts, unconstrained/constrained/RBCD delegation, ACL abuse (GenericAll/WriteDACL), AdminSDHolder, ADCS ESC1–ESC15 misconfigurations.

---

## 7. Expert and authoritative sources

- **OWASP NHI Top 10 project**: canonical NHI risk taxonomy.
- **MITRE ATT&CK**: technique IDs. Also MITRE's *Cloud* matrix and the *ATT&CK for Identity*-oriented blog posts.
- **Google Threat Intelligence Group / Mandiant**: primary write-ups on UNC5537 (Snowflake) and UNC6395 (Drift).
- **Microsoft MSRC and Microsoft Threat Intelligence**: Midnight Blizzard, Storm-0558; Entra security operations guide; emergency-access account guidance.
- **US Cyber Safety Review Board (CSRB)**: Storm-0558 report (Mar 2024).
- **CISA / NSA**: cloud IAM best practices (Mar 2024), supply-chain alerts (tj-actions, npm).
- **SpecterOps** (Andy Robbins, Jared Atkinson, Justin Kohler): attack path theory, BloodHound, "Tier Zero" definitions.
- **Rhino Security Labs / Datadog Security Labs / Wiz Research / Unit 42**: cloud privilege escalation research (for example Pacu, Stratus Red Team, the Datadog "State of Cloud Security" reports, Wiz threat research).
- **Gartner**: MQ for PAM (Oct 2025); Hype Cycle for Digital Identity; market guides on ISPM, CIEM, Machine Identity Management. **KuppingerCole**: Leadership Compass PAM/NHI.
- **CA/Browser Forum** ballots and minutes; **Let's Encrypt** blog (short-lived certs, ARI).
- **IETF WIMSE and OAuth WGs**; **SPIFFE** community; **OpenID SSF WG**.
- **CSA (Cloud Security Alliance)**: research notes on OAuth/AI SaaS supply-chain risk (2026).
- **GitGuardian State of Secrets Sprawl** (annual, vendor data).
- Practitioner voices: Christophe Tafani-Dereeper (Datadog), Ian Mckay (iann0036, AWS IAM datasets), Scott Piper (Wiz; flaws.cloud), Dirk-jan Mollema (Entra research, ROADtools), Nathan McNulty (Entra), Mark Morowczynski (Microsoft), Ian Glazer (identity strategy).

---

## 8. Implications for Tessera

### 8.1 Required capabilities

**Discovery, inventory and graph**
1. **MUST** — Agentless, read-only connectors for AWS (Organizations, IAM, Identity Center, STS trust, SCP/RCP), Azure/Entra (directory roles, PIM state, Azure RBAC, apps/SPs, managed identities, FICs), GCP (IAM at org/folder/project, SAs, keys, WIF pools), Kubernetes (RBAC, SAs, EKS access entries/IRSA/Pod Identity), and at least two data platforms (Snowflake, Postgres/Databricks), feeding one **identity-entitlement-resource graph**.
2. **MUST** — **Effective-permission computation** for AWS at minimum (identity + resource + boundary + SCP/RCP + session policy + trust chains), with explainability ("why can X do Y"). Use AWS Access Analyzer / GCP Policy Analyzer where possible as a cross-check.
3. **MUST** — **NHI inventory** covering every non-human principal and *each* of its credentials (access keys, SP secrets/certs, SA keys, PATs, OAuth grants), with creation date, last used, expiry, scopes and **owner attribution** (inferred from creator, IaC repo/CODEOWNERS, tags, CloudTrail creator events, then confirmed by humans).
4. **MUST** — **Third-party OAuth/SaaS integration inventory** (Entra enterprise apps and consented permissions, Google Workspace OAuth/DWD, Salesforce connected apps, GitHub Apps/OAuth apps, Slack apps) with scope risk scoring. This addresses the Drift/Gainsight/Klue/Context.ai pattern.
5. **SHOULD** — Attack-path analysis to Tier-0 / "crown-jewel" zones with privilege-escalation edges (§6.3); import BloodHound/OpenGraph data rather than re-collecting AD.
6. **SHOULD** — Certificate inventory (from cloud cert managers, K8s cert-manager, CT logs, and CLM integrations) linked to workloads and owners; SC-081 readiness reporting (certs not on ACME/automated renewal).
7. **COULD** — AI-agent identity inventory (Entra Agent ID, MCP servers, agent OAuth grants) as an NHI subtype with delegation chain (`acts_on_behalf_of` human).

**Access-as-code and JIT/ZSP (the core)**
8. **MUST** — Declarative access policy in Git (YAML/HCL with a Cedar/Rego evaluation engine) for **eligibility, approval, max TTL and scope**, with plan/diff/apply semantics, drift detection against the live cloud, and PR-based review.
9. **MUST** — **JIT elevation** for cloud roles (AWS Identity Center permission set assignment or STS session; Entra PIM activation via API; GCP PAM grants or conditional IAM bindings with expiry), data platforms (Snowflake roles, Postgres roles) and Kubernetes (temporary RoleBindings), with automatic revocation and an evidence trail. Use native mechanisms first (PIM, GCP PAM) rather than replacing them.
10. **MUST** — **Break-glass** workflow: registered emergency accounts, out-of-band activation, immediate alerting, mandatory post-incident review, and periodic test attestation.
11. **SHOULD** — Ephemeral credential issuance for SSH (SSH CA certs) and databases (via Vault dynamic secrets or native IAM DB auth) *by integrating*, not by running a proxy first.
12. **SHOULD** — Policy-as-code CI gates: lint IAM/trust policies in Terraform PRs (wildcard OIDC `sub`, `Principal:*`, missing ExternalId, `iam:PassRole` on `*`), using AWS custom policy checks where available.
13. **COULD** — Identity-aware proxy with session recording for SSH/DB/K8s (later phase, or partner with Teleport/Boundary).
14. **COULD** — PEDM/EPM for endpoints. Out of scope; integrate (CyberArk EPM, BeyondTrust, Delinea).

**Right-sizing and lifecycle**
15. **MUST** — **Unused-access analysis and least-privilege recommendations** (granted vs used over 90 days from CloudTrail/Activity Logs/Audit Logs; ingest Access Analyzer unused-access and GCP IAM Recommender), producing **generated code diffs** (PRs) rather than console tickets.
16. **MUST** — NHI lifecycle workflows: owner assignment and re-attestation, stale-credential disablement (with safe "quarantine then delete" via SCP/deny/disable), and offboarding linkage (human leaves, so their owned NHIs, PATs and OAuth grants are reassigned or revoked).
17. **SHOULD** — Rotation *orchestration* through vault/cloud APIs (trigger AWS SM rotation, Vault lease revoke, Entra secret roll), plus "migrate to federation" guidance (replace static key with OIDC/WIF and generate the trust policy).
18. **SHOULD** — Access reviews/certification for privileged and NHI entitlements, prefilled with usage data.

**Detection and response (ITDR for infra/NHI)**
19. **MUST** — Ship the detection rules in §8.3, mapped to ATT&CK v19 and OWASP NHI IDs, as code. Support exporting to SIEM (OCSF format).
20. **MUST** — **Response actions**: disable/deactivate key, revoke sessions (AWS `aws:TokenIssueTime` deny policy; Entra revoke sign-in sessions; GCP disable SA), revoke OAuth grants, quarantine principal. Gate them by approval, but make them one click.
21. **SHOULD** — Consume and emit **CAEP/SSF** events to share revocations with IdPs and SaaS.
22. **COULD** — Secret scanning of SaaS data stores (CRM, tickets) and code, or integrate GitGuardian/GitHub secret scanning findings and join them to the NHI graph (leaked key → identity → blast radius).

### 8.2 Data-model entities and fields (proposed)

```
Identity            id, kind{human, nhi, agent}, subtype{iam_user, iam_role, entra_user,
                    service_principal, managed_identity, gcp_sa, k8s_sa, oauth_app, bot, ai_agent},
                    provider, account/tenant/project, native_id (ARN/objectId/email),
                    display_name, created_at, created_by, last_activity_at, status,
                    owner_ids[], owner_confidence, business_purpose, environment{prod,nonprod},
                    tier{0,1,2}, tags{}, source_iac_ref (repo/path/line), is_break_glass,
                    acts_on_behalf_of (identity_id, for agents/delegation)
Credential          id, identity_id, type{password, access_key, client_secret, certificate,
                    sa_key, ssh_key, ssh_cert, pat, oauth_refresh_token, api_key, fic},
                    fingerprint/key_id (never the secret), created_at, expires_at,
                    last_used_at, last_used_ip/region/service, rotation_policy,
                    managed_by{vault_ref, secrets_manager_arn, none}, leaked_finding_ids[]
FederationTrust     id, target_identity_id, issuer, audience, subject_pattern,
                    conditions{}, wildcard_risk, external_id_required
Entitlement         id, identity_id, grant_type{direct, group, role_assignment,
                    permission_set, rolebinding, oauth_scope, db_grant},
                    role/policy_id, scope (resource/path), granted_at, granted_by,
                    expires_at (null = standing), source{iac, console, jit_request}, last_used_at
Policy              id, provider, type{identity, resource, scp, rcp, boundary, trust,
                    k8s_role, db_role}, document (normalized), version, hash
EffectivePermission identity_id, action, resource, decision, explanation_chain[], computed_at
Resource            id, provider, type, native_id, sensitivity{tier0, data_class}, owner_ids[]
AttackPathEdge      src_id, dst_id, edge_type{MemberOf, CanAssume, CanPassRole, Owns,
                    AddCredential, ActAs, Impersonate, CreatePod, ...}, evidence
AccessRequest       id, requester_id, target_entitlement, justification, ticket_ref,
                    approvers[], policy_id, requested_ttl, granted_at, revoked_at, status
Session             id, identity_id, access_request_id, source_ip, device_id, protocol,
                    start/end, recording_uri (if brokered)
OAuthGrant          id, client_app_id, publisher, verified_publisher, tenant/org,
                    consented_by, consent_type{admin,user}, scopes[], scope_risk,
                    first_seen, last_used, token_count
Certificate         id, subject/SANs, issuer, serial, not_before, not_after,
                    key_alg/size, issuance_method{acme, manual, clm}, deployed_on[], owner_ids[]
Finding             id, rule_id, severity, entity_refs[], attck_ids[], owasp_nhi_ids[],
                    first_seen, status, remediation{type, code_diff, action}
Owner/Team          id, name, contacts, source (HRIS/IdP group/CODEOWNERS)
```
Design notes: never store secret values (fingerprints only). Model **credential separately from identity**, because one identity can have many credentials and incidents are about credentials. Keep `source_iac_ref` so remediation can be emitted as a PR.

### 8.3 Detection rules worth shipping first

| # | Rule | Logic sketch | ATT&CK / OWASP NHI |
|---|---|---|---|
| D1 | Long-lived cloud key unused >90d or older than 365d | IAM credential report / SA key list / SP secret `endDateTime` | T1078.004 / NHI7, NHI1 |
| D2 | Static credential used from new ASN/geo/UA | Baseline per access key / SP / SA | T1078.004, T1550.001 / NHI2 |
| D3 | Wildcard OIDC trust | Trust policy `token.actions.githubusercontent.com:sub` with `*` at org level, or missing `aud`; GCP WIF without attribute condition | — / NHI6 |
| D4 | Cross-account trust without ExternalId to third party | `Principal` external account, no `sts:ExternalId` | — / NHI3 |
| D5 | New credential added to privileged SP/app (esp. by non-owner) | Entra audit "Add service principal credentials"/"Update application – Certificates and secrets" on SP with privileged app roles | T1098.001 / NHI5 |
| D6 | High-risk app permission granted | Admin consent to `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `full_access_as_app`, `Mail.Read` (app) | T1098.003, T1528 / NHI5 |
| D7 | OAuth integration bulk export anomaly | Salesforce/Workspace/GitHub API volume per connected app > baseline; new UA (e.g., `python-requests`, `Salesforce-Multi-Org-Fetcher`) or Tor/VPS ASN | T1213, T1550.001 / NHI3 |
| D8 | Human use of NHI | Service-account/role session from interactive console, from a corporate laptop IP, or with browser UA | T1078 / NHI10 |
| D9 | Privilege escalation API sequence | `CreatePolicyVersion --set-as-default`, `AttachRolePolicy` to self, `UpdateAssumeRolePolicy`, `CreateAccessKey` for other user, GCP `setIamPolicy`, K8s `create clusterrolebinding` to cluster-admin | T1098.003 / NHI5 |
| D10 | Standing admin outside JIT policy | Admin-equivalent entitlement with no `expires_at` and not in break-glass list | — / NHI5 |
| D11 | Break-glass account used | Any sign-in or AssumeRole by tagged emergency identity | T1078 |
| D12 | Enumeration burst | `GetAuthorizationDetails`, `List*` storm, `ListSecrets`, Graph directory enumeration by NHI | T1087.004, T1069.003 |
| D13 | Logging tamper | `StopLogging`, `DeleteTrail`, diagnostic settings removed, GCP sink deleted | T1562.008 |
| D14 | Kubernetes SA token used outside cluster / legacy token secret present | Audit log source IP not node CIDR; secrets of type `kubernetes.io/service-account-token` | T1528, T1552.007 / NHI7 |
| D15 | Secret leak joined to live identity | Scanner finding validated live → map to identity → blast radius → auto-open revoke action | T1552.001 / NHI2 |
| D16 | Orphaned NHI | Owner disabled in IdP/HRIS, or no owner and no activity for 90 days | — / NHI1 |
| D17 | Shared NHI across environments/apps | Same key fingerprint/SA used by prod and non-prod or by more than N workloads | — / NHI8, NHI9 |
| D18 | Cert expiry / non-automated public cert | `not_after` < 30d, or issuance_method=manual with validity > SC-081 cap | — |
| D19 | Federation/tenant trust change | New federated domain, new IdP, new SAML signing cert, cross-tenant access policy change | T1484.002, T1556 |
| D20 | Token replay after revocation | Use of sessions/tokens issued before a revocation event (`TokenIssueTime` < revoke time) | T1550 |

### 8.4 Build vs integrate

| Area | Recommendation | Rationale |
|---|---|---|
| Secrets vault | **Integrate** (Vault/IBM Vault, AWS SM, Azure KV, GCP SM, CyberArk Conjur/Secrets Hub, Akeyless, Doppler, 1Password) | Commodity, trust-heavy, and customers already own one. Tessera governs *who/what can read which secret* and *orchestrates rotation* |
| Secret scanning | **Integrate** (GitHub, GitGuardian, TruffleHog) plus a light built-in validator | Differentiation comes from joining a leak to an identity and its blast radius, not from regexes |
| Classic PAM vault and Windows session isolation | **Integrate/partner** (CyberArk, BeyondTrust, Delinea) | Decades of connectors; legacy estates |
| EPM/PEDM on endpoints | **Integrate** | Out of thesis |
| Certificate issuance / CA | **Integrate** (ACME CAs, Venafi, Keyfactor, cert-manager); build **inventory + ownership** | SC-081 makes inventory valuable; being a CA is not |
| CIEM effective-permission engine | **Build** (core IP), validated against Access Analyzer/Policy Analyzer | It is the "brain" behind access-as-code and right-sizing PRs |
| JIT/ZSP orchestration and policy-as-code | **Build** (core), wrapping native PIM / GCP PAM / Identity Center | The differentiator; native primitives reduce blast radius and buyer friction |
| NHI inventory, ownership and lifecycle | **Build** | The fastest-consolidating category; table stakes for any identity platform in 2026 |
| SSH CA / DB ephemeral creds | **Integrate first** (Vault SSH/DB engines, Teleport, cloud IAM DB auth); build later if a proxy is needed | Avoid the data path early |
| Session recording proxy | **Defer/partner** (Teleport, Boundary) | Expensive to build, operationally sensitive |
| AD attack paths | **Integrate** (BloodHound CE/Enterprise import, OpenGraph) | Don't re-collect AD; ingest it |
| ITDR for IdP (Kerberos, NTLM) | **Integrate** (Defender for Identity, CrowdStrike, Silverfort) | Focus Tessera ITDR on cloud/NHI/OAuth |
| SIEM | **Integrate** (export OCSF; Sentinel, Splunk, Chronicle) | Not a SIEM |

**Strategic note.** Because CNAPPs now mostly *find* and PAM vendors mostly *broker*, the gap is a Git-native control plane that **computes effective access, proposes least-privilege code, grants JIT through native primitives, and closes NHI lifecycle loops**, across cloud *and* data platforms. That is Tessera's wedge. Buyers will also ask how Tessera's own privileged connectors are protected. The Treasury/BeyondTrust and Drift/Klue incidents mean Tessera's own credentials must be **read-only by default, federated rather than keyed (OIDC/WIF into customer clouds), scoped per tenant, and revocable in bulk**, with write paths approved separately.

---

## 9. Glossary

- **Access Analyzer (AWS)**: AWS service for external, internal and unused access findings and policy validation.
- **ACME / ARI**: automated certificate management protocol (RFC 8555) and its renewal-information extension.
- **actAs**: GCP permission (`iam.serviceAccounts.actAs`) to attach or run as a service account.
- **Agent ID (Entra)**: Microsoft identity type for AI agents.
- **App registration / Service principal**: the Entra application definition and its per-tenant instance.
- **Break-glass**: emergency-access account kept outside normal controls and monitored closely.
- **CAEP / SSF**: OpenID standards for sharing session/credential change events in real time.
- **CIEM**: cloud infrastructure entitlement management.
- **CLM**: certificate lifecycle management.
- **CNAPP / CSPM**: cloud-native application protection platform / cloud security posture management.
- **Confused deputy**: a trusted service tricked into acting for an unauthorized party (mitigated by ExternalId and `aws:SourceArn`).
- **DPoP**: sender-constrained OAuth tokens bound to a client key.
- **Effective permissions**: net allowed actions after evaluating all policy layers.
- **EPM / PEDM**: endpoint privilege management / privilege elevation and delegation management.
- **FIC**: federated identity credential (Entra) used for workload identity federation.
- **gMSA**: group Managed Service Account (AD) with automatic password management.
- **IMDS**: instance metadata service that supplies workload credentials.
- **IRSA / EKS Pod Identity**: mapping K8s service accounts to AWS IAM roles.
- **ISPM / ITDR**: identity security posture management / identity threat detection and response.
- **JIT / ZSP**: just-in-time access / zero standing privilege.
- **Managed identity**: Azure-managed service principal with no customer-held secret.
- **NHI**: non-human identity.
- **OAuth grant / consent**: authorization a user or admin gives an app to access resources with given scopes.
- **PAM / PASM**: privileged access management / privileged account and session management.
- **Permission set**: IAM Identity Center template provisioned as roles into accounts.
- **PIM**: Entra Privileged Identity Management (eligible vs active assignments).
- **RCP / SCP**: AWS resource control policy / service control policy (org-level guardrails).
- **SC-081**: CA/B Forum ballot reducing public TLS certificate lifetimes to 47 days by 2029.
- **SPIFFE / SVID / SPIRE**: workload identity standard / verifiable identity document / reference implementation.
- **Tier 0 / privilege zone**: assets whose compromise means control of the whole environment.
- **Trust policy**: AWS role resource policy defining who may assume the role.
- **WIF**: workload identity federation.
- **WIMSE**: IETF Workload Identity in Multi-System Environments working group.

---

## 10. Sources

Standards and frameworks
- OWASP NHI Top 10 (2025): https://owasp.org/www-project-non-human-identities-top-10/2025/
- CSA intro to OWASP NHI Top 10: https://cloudsecurityalliance.org/articles/introducing-the-owasp-nhi-top-10-standardizing-non-human-identity-security
- MITRE ATT&CK updates (v19, Apr 2026): https://attack.mitre.org/resources/updates/updates-april-2026/
- SC-081 timeline summaries: https://www.ssl.com/article/ssl-certificate-validity-changes-what-you-need-to-know/ ; https://support.dnsimple.com/articles/announcement-ssl-certificate-validity-changes/ ; CA/B Forum: https://cabforum.org/
- IETF WIMSE WG: https://datatracker.ietf.org/wg/wimse/about/ ; architecture draft: https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch ; workload creds: https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds-01 ; practices: https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-identity-practices/07/
- SPIFFE: https://spiffe.io/
- Kubernetes RBAC good practices: https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- NIST SP 800-207: https://csrc.nist.gov/pubs/sp/800/207/final ; NIST SP 800-63-4: https://pages.nist.gov/800-63-4/

Cloud provider documentation
- AWS IAM Access Analyzer findings: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html
- Access Analyzer internal access (Jun 2025): https://aws.amazon.com/about-aws/whats-new/2025/06/iam-access-analyzer-aws-organization-access-resources
- Unused access (Nov 2023): https://aws.amazon.com/about-aws/whats-new/2023/11/iam-access-analyzer-inspecting-unused-access
- Access Analyzer pricing: https://aws.amazon.com/iam/access-analyzer/pricing
- GCP secure-by-default orgs: https://cloud.google.com/resource-manager/docs/secure-by-default-organizations
- Entra workload identities: https://learn.microsoft.com/entra/workload-id/workload-identities-overview
- Entra Agent ID admin: https://docs.azure.cn/en-us/entra/agent-id/manage-agent-identities-admin
- Defender for Cloud release notes (PCI deprecation): https://learn.microsoft.com/azure/defender-for-cloud/release-notes
- Defender for Cloud permissions management: https://learn.microsoft.com/azure/defender-for-cloud/permissions-management
- Entra Permissions Management retirement: https://techcommunity.microsoft.com/blog/microsoft-entra-blog/-/4400198

Incidents
- GTIG on Salesloft Drift (UNC6395): https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift ; Security Affairs coverage: https://securityaffairs.com/181632/hacking/unc6395-targets-salesloft-in-drift-oauth-token-theft-campaign.html ; GitHub origin: https://securityaffairs.com/182002/hacking/hackers-breached-salesloft-s-github-in-march-and-used-stole-tokens-in-a-mass-attack.html
- Mandiant on Snowflake (UNC5537): https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion ; https://thehackernews.com/2024/06/snowflake-breach-exposes-165-customers.html
- Microsoft Midnight Blizzard: https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/ ; https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/ ; Wiz analysis: https://wiz.io/blog/midnight-blizzard-microsoft-breach-analysis-and-best-practices
- Cloudflare Thanksgiving 2023: https://blog.cloudflare.com/thanksgiving-2023-security-incident/
- Okta support system root cause (Nov 2023): https://sec.okta.com/harfiles [URL unverified]
- CSRB Storm-0558 report: https://www.cisa.gov/resources-tools/resources/CSRB-Review-Summer-2023-MEO-Intrusion
- BeyondTrust Remote Support SaaS incident: https://www.beyondtrust.com/remote-support-saas-service-security-investigation
- CISA tj-actions alert: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction
- CISA npm (Shai-Hulud) alert: https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
- Gainsight/Salesforce: https://securityaffairs.com/184896/hacking/salesforce-alerts-users-to-potential-data-exposure-via-gainsight-oauth-apps.html ; https://astrix.security/learn/blog/salesforce-advisor-gainsight-breach/
- Vercel / Context.ai (Apr 2026): https://vercel.com/kb/bulletin/vercel-april-2026-security-incident ; https://www.theregister.com/2026/04/20/vercel_context_ai_security_incident/
- CSA research note on OAuth/AI SaaS blast radius (2026): https://labs.cloudsecurityalliance.org/research/csa-research-note-oauth-ai-saas-supply-chain-blast-radius-20/
- Klue (Jun 2026): https://thehackernews.com/2026/06/salesforce-disables-klue-app.html ; https://www.nudgesecurity.com/post/klue-breach-exposes-salesforce-data-across-the-saas-supply-chain ; https://fieldeffect.com/blog/klue-integration-breach-salesforce-data
- GitGuardian State of Secrets Sprawl 2026: https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html ; https://dev.to/gitguardian/the-state-of-secrets-sprawl-2026-ai-service-leaks-surge-81-and-29m-secrets-hit-public-github-2bgj

Market
- Palo Alto–CyberArk close (10-Q): https://www.sec.gov/Archives/edgar/data/1327567/000132756726000005/panw-20260131.htm ; https://washingtonexec.com/2026/02/palo-alto-networks-wraps-cyberark-acquisition/
- Google–Wiz close: https://www.clearygottlieb.com/news-and-insights/news-listing/google-completes-32-billion-acquisition-of-wiz
- Delinea–StrongDM: https://delinea.com/news/delinea-acquires-strongdm-to-secure-ai-with-continuous-authorization
- CrowdStrike–SGNL (10-K): https://www.sec.gov/Archives/edgar/data/1535527/000153552726000010/crwd-20260131.htm
- ServiceNow–Veza: https://www.businesswire.com/news/home/20251201652471/en/ServiceNow-to-Expand-Security-Portfolio-With-Acquisition-of-Veza%E2%80%99s-Leading-AI-native-Identity-Security-Platform
- Cisco–Astrix: https://www.networkworld.com/article/4166695/cisco-grabs-astrix-to-secure-ai-agents.html
- SailPoint–Entro: https://www.securityweek.com/sailpoint-to-acquire-entro-in-reported-200-million-deal/amp/
- Cyera–Oasis: https://siliconangle.com/2026/07/28/cyera-buy-nonhuman-identity-startup-oasis-security-reported-1b/
- Okta–Axiom: https://www.okta.com/newsroom/press-releases/okta-with-axiom-security--delivering-robust-privileged-access-fo/
- 1Password–Apono: https://fintech.global/2026/06/18/1password-buys-apono-to-close-enterprise-identity-gaps/
- Gartner MQ PAM 2025 (vendor releases): https://www.cyberark.com/press/cyberark-named-a-leader-in-the-2025-gartner-magic-quadrant-for-privileged-access-management/ ; https://www.beyondtrust.com/press/2025-gartner-magic-quadrant-privileged-access-management
- Teleport Machine & Workload Identity: https://goteleport.com/docs/machine-workload-identity/introduction/
- HashiCorp Boundary blog: https://www.hashicorp.com/blog/products/boundary
- SpecterOps BloodHound OpenGraph expansion (Mar 2026): https://specterops.io/news/specterops-expands-identity-attack-path-management-to-okta-github-and-mac/
- Palo Alto on Entra Permissions Management retirement: https://www.paloaltonetworks.com/blog/?p=343282
- Clutch Security Series A: https://finder.techleap.nl/news/feed/clutch-security-raises-20m-series-a
