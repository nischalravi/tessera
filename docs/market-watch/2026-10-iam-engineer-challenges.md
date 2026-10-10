# What IAM engineers are struggling with: October 2026, and how ready Tessera is

*Market intelligence report, 2026-10-09. Prepared by the `market-intelligence-analyst` agent. Domain checks follow the `iam-authn`, `iam-protocols`, `iam-authz`, `iam-governance`, `iam-pam-nhi` and `iam-agent-identity` expert definitions, and the `qa-engineer` bar: a status counts only if it is backed by code and tests. Facts that could not be verified are marked `[unverified]`. Vendor-published statistics are labelled (vendor) and should be read as directional.*

## 1. Executive summary

Practitioners in 2025–2026 keep coming back to the same problems:
- Getting applications connected at all.
- Movers and leavers whose access is not actually removed.
- Machine identities and secrets that nobody owns or rotates.
- Attackers who log in rather than break in: help-desk resets, stolen OAuth tokens, and accounts that never got MFA.

AI agents are the fastest-growing concern, but the incidents so far are mostly near-misses. Universities have all of these problems plus multi-affiliation lifecycles, sponsored guests, Grouper operations and federation compliance.

**Tessera's readiness is low for production use, though the core logic is good in places.** Every connector in `dev` is a demo connector, nothing is ever written to a target system, and the API has no authentication. As a result, **none of the 79 checklist items is Solved**. 30 are Partial, mostly real, tested engine logic running over demo data. 16 are Designed, mainly Groups, Guests, Phase 0 and the AWS evaluator. 33 are Gaps.

### Top 10 challenges and Tessera's readiness

| # | Challenge (as engineers put it) | Severity / frequency | Tessera today | Key items |
|---|---|---|---|---|
| 1 | "Only the easy apps are connected. Everything else is manual." Connector and app-onboarding effort | High / very high | **Gap.** Demo connectors only. No flat-file import. Readiness checks are designed but not built | C1 Gap (#104), C3 Gap (#105), C4 Designed |
| 2 | "Movers keep their old access, and leavers are only disabled in the IdP." JML gaps | High / high | **Partial.** Good leaver, mover and joiner plans with tests, but they change the graph only and never revoke sessions | J1–J3 Partial, J4 Gap (#106), P1 Gap (#103) |
| 3 | "Service accounts and keys have no owner and are never rotated." NHI sprawl and secrets | High / very high | **Partial/Gap.** NHI inventory and owner-left detection exist on demo data. Rotation is a timestamp only | N1–N2 Partial, N3 Gap (#113) |
| 4 | "A vendor's OAuth token emptied our Salesforce." Third-party OAuth and SaaS token theft | High / every 3–6 months | **Gap.** No OAuth grant inventory | N4 Gap (#107) |
| 5 | "The help desk reset MFA for the attacker." Help-desk social engineering and recovery | Very high / continuous waves | **Gap.** Recovery is designed for guests only | M3 Gap (#108) |
| 6 | "Our agents run on a human's full token." AI agent identity and authorization | High and rising fastest / near-universal concern | **Partial (model only).** Agents are an identity type with sponsor and PII policies. No enforcement, no MCP AS, no discovery | AG1–AG2 Partial, AG3 (#115), AG4 (#116) Gap |
| 7 | "Workday data is wrong, and contractor-to-FTE conversion creates duplicates." HR data quality and correlation | High / high | **Designed/Partial.** Correlation by id or email only. Tiered matching and data-quality checks are designed | H1 Partial, H2–H3 Designed |
| 8 | "Reviewers rubber-stamp, and we build audit evidence from screenshots." Certification fatigue and audit evidence | High / high | **Partial/Gap.** Risk-scoped campaigns with reasons work on demo data. No frozen population, export or point-in-time view | R1–R2 Partial, R3 (#110), A2 (#111) Gap |
| 9 | "Moving off IIQ, OIM or Saviynt is a multi-year rebuild." Legacy IGA migration | High / rising (OIG 12c end of support [unverified]) | **Gap** for IGA importers. Grouper migration is Designed | LM1 Gap (#112), G5 Designed |
| 10 | "We had an MFA policy, but that account wasn't in it." Missing MFA, session and token theft | Extreme impact / periodic | **Gap.** No MFA posture data, no SSF/CAEP receiver | M1–M2 (#109), I1 (#114) Gap |

Also frequent:
- **Cost and licensing.** The Entra governance add-on, the "SSO tax" and per-module pricing.
- **Staffing and skills.** Senior-heavy roles that take a long time to fill.
- **Groups, guests and higher-ed lifecycle.** Tessera's Groups and Guest designs (Designed, #44–#77) are its strongest answer here.

## 2. Scorecard

| Theme | Items | Solved | Partial | Designed | Gap |
|---|---|---|---|---|---|
| T1 Connectors and onboarding | 5 | 0 | 0 | 2 | 3 |
| T2 Joiner, mover, leaver | 8 | 0 | 6 | 0 | 2 |
| T3 HR data quality and correlation | 3 | 0 | 1 | 2 | 0 |
| T4 Orphaned, dormant and shared accounts | 2 | 0 | 2 | 0 | 0 |
| T5 Certifications | 7 | 0 | 4 | 0 | 3 |
| T6 Role explosion and role engineering | 3 | 0 | 1 | 1 | 1 |
| T7 Separation of duties | 3 | 0 | 1 | 0 | 2 |
| T8 Audit evidence | 3 | 0 | 1 | 0 | 2 |
| T9 Access requests | 3 | 0 | 2 | 0 | 1 |
| T10 Non-human identities and secrets | 6 | 0 | 2 | 0 | 4 |
| T11 AI agent identity | 5 | 0 | 2 | 0 | 3 |
| T12 MFA, passkeys and recovery | 4 | 0 | 0 | 1 | 3 |
| T13 Session and token theft, ITDR | 2 | 0 | 0 | 0 | 2 |
| T14 Cloud entitlements (CIEM) | 6 | 0 | 3 | 1 | 2 |
| T15 Data platform access | 3 | 0 | 2 | 0 | 1 |
| T16 Group management | 5 | 0 | 0 | 5 | 0 |
| T17 Guests, B2B and external identities | 4 | 0 | 0 | 3 | 1 |
| T18 Legacy IGA migration | 2 | 0 | 1 | 0 | 1 |
| T19 Cost, staffing and operability | 3 | 0 | 2 | 0 | 1 |
| T20 Platform prerequisites | 2 | 0 | 0 | 1 | 1 |
| **All** | **79** | **0** | **30** | **16** | **33** |

**How to read it:**
- **Partial** mostly means the logic exists and is tested over the demo graph, but cannot read a real system or write to one.
- **Designed** areas are concentrated in Groups, Guests, Deployment readiness, Phase 0 and the AWS evaluator.
- **Gaps** cluster in four places:
  - Connecting to real systems
  - Revoking sessions and tokens
  - MFA and recovery
  - OAuth grants and agents

## 3. Part 1: challenges by theme

**Method:**
- Three research passes ran on 2026-10-09:
  - Practitioner forums and higher-ed sources
  - Reviews and analyst reports
  - Breach post-mortems
- In total they made about 100 searches and fetches.

**Limitations:**
- **Reddit** (r/IdentityManagement, r/sysadmin, r/AZURE, r/okta) **could not be reached**. The research tooling rejects reddit.com. One r/sysadmin post was seen only through a third-party mirror and is marked `[unverified]`.
- **Gartner Peer Insights** returned 403. Its review evidence comes from search snippets, marked `[unverified]`.
- **G2** evidence comes from G2 reviews syndicated on AWS Marketplace, plus PeerSpot.
- **Substitutes:** Hacker News, vendor community forums, Microsoft Q&A, Internet2/InCommon and job postings stood in for the unreachable sources.
- **Dates:** where a page was seen only as a snippet, its date is marked `[unverified]`.

### 3.1 Connector and application onboarding effort
- **The challenge:**
  - Out-of-the-box connectors cover mainstream SaaS. Anything legacy, custom or non-SCIM needs custom building and constant tuning.
  - "Works in Postman, fails in the IGA tool."
  - Tokens expire and need manual fixes, and entitlement mapping fails silently.
  - Programmes cover the easy apps and leave the rest manual.
- **Evidence:**
  - Saviynt forum threads on NetSuite onboarding, ServiceNow token expiry and SAV4SAV mapping failures (2023–24, dates `[unverified]`): https://forums.saviynt.com/t5/identity-governance/netsuite-onboarding/td-p/57237, https://forums.saviynt.com/t5/identity-governance/connection-issues-for-saviynt-app-integration-in-servicenow/td-p/67332
  - PeerSpot reviews of SailPoint ISC call out "limitations with connectors" (financial services, 10k+, Dec 2025): https://www.peerspot.com/products/sailpoint-identity-security-cloud-pros-and-cons
  - Omada reviewers had to fall back on a generic REST connector: https://www.peerspot.com/products/omada-identity-cloud-pros-and-cons
  - Cerby 2025 survey of about 600 leaders, republished by CSA on 2025-07-07 (vendor):
    - 96% rely on manual identity workflows.
    - 72% distribute entitlement data manually or by flat file.
    - https://cloudsecurityalliance.org/articles/why-identity-automation-fails-at-96-of-organizations
  - CyberArk 2025 State of IGA (vendor): 82% report integration struggles and 6% are fully automated: https://www.scworld.com/resource/2025-state-of-iga-report-reveals-persistent-gaps-in-automation-and-integration
  - Internet2 TechEx25 session on AI-assisted application onboarding (Dec 2025) `[unverified]`: https://evolveum.com/techex2025
  - Onboarding is estimated at $15k–$75k per app `[unverified, vendor]`: https://static.carahsoft.com/concrete/files/1917/8594/2560/The_Real_Cost_of_IGA_Application_Onboarding_Whitepaper.pdf
- **Who has it:** Mid-size to large enterprises (especially 10k+ in financial services and retail) running SailPoint, Saviynt or Omada, and universities running midPoint. IGA admins and implementers.
- **Severity and frequency:** High. Very frequent: the most common thread type on vendor forums and the most consistent review complaint.

### 3.2 SCIM, SAML and OIDC app integration quality
- **The challenge:**
  - SCIM in practice means "whatever Entra and Okta send":
    - Booleans arrive as strings.
    - PATCH semantics drift.
    - Large groups come back unpaginated.
  - SAML failures come from issuer mismatches and missing claims. The claims UI also locks once a claims-mapping policy exists.
  - SSO and SCIM are gated behind enterprise pricing tiers.
- **Evidence:**
  - HN, "What a developer needs to know about SCIM" (Jun 2025): https://news.ycombinator.com/item?id=44196393
  - Microsoft Q&A, locked claims UI (Feb 2026): https://learn.microsoft.com/en-us/answers/questions/5762167/editing-attributes-and-claims-in-saml-based-single
  - Microsoft Q&A, AADSTS700016 (Dec 2025; dates from snippets `[unverified]`): https://learn.microsoft.com/en-us/answers/questions/5642308/how-do-i-fix-aadsts700016
  - HN threads on the SSO tax: https://news.ycombinator.com/item?id=38344733
- **Who has it:** Enterprise IAM engineers onboarding apps and SaaS developers. The SSO tax hits SMBs hardest.
- **Severity and frequency:** Medium per incident, high in aggregate. Daily volume on Q&A sites.

### 3.3 Joiner, mover and leaver gaps (movers especially)
- **The challenge:**
  - Movers have no lifecycle state of their own. The identity goes from active to active, so teams hand-roll attribute comparisons.
  - Workday incremental sync misses some changes.
  - Entra Lifecycle Workflows only trigger automatically on hire and leave dates.
  - Leavers get disabled in the IdP, but sessions, tokens and non-SSO apps survive.
- **Evidence:**
  - SailPoint Developer Community, "Lifecycle state Mover setting" (Nov 2024): https://developer.sailpoint.com/discuss/t/lifecycle-state-mover-setting-how-to-identify-the-change-of-attribute-and-how-to-configure-jml/88973
  - Microsoft Learn on Workday attribute updates not flowing (date `[unverified]`): https://learn.microsoft.com/nb-no/Entra/Identity/app-provisioning/hr-user-update-issues
  - InCommon TechEx25 preview, including Georgia Tech's session on Grouper membership lifecycles across employment changes (Aug 2025): https://incommon.org/news/grouper-therapy-techex-citement-and-revamped-training
  - Cerby 2025: 58% found former employees still had access (link above).
  - Veza State of Access (early 2025): deactivated users hold 16.5% of permissions `[unverified, snippet]`: https://www.sdxcentral.com/press-releases/industry-first-report-from-veza-showcases-the-challenge-of-managing-access-permissions-for-identity-and-security-teams/
- **Who has it:** Every HR-driven shop (Workday with Entra, Okta or SailPoint) from mid-size up, and universities managing employment and affiliation changes.
- **Severity and frequency:** High, high. Movers are the main source of access creep and audit findings.

### 3.4 HR data quality and identity correlation
- **The challenge:**
  - Converting a contractor to an employee creates duplicate identities.
  - Rehires need manual reactivation.
  - HR feeds contain null or circular managers and bad termination dates.
  - Everything downstream inherits these errors.
- **Evidence:**
  - Okta KB on contractor-to-FTE conversion with Workday (date `[unverified]`): https://support.okta.com/help/s/article/How-To-Convert-From-Contractor-to-FullTime-Employee-Using-Workday-Provisioning
  - Atricore names HR data as the first reason IGA projects stall (vendor, `[unverified]` date): https://www.atricore.com/blog/why-iga-projects-stall
  - "Handling rehires" article `[unverified]`: https://www.windows-active-directory.com/handling-rehires-the-duplicate-identity-nightmare-in-hr-driven-provisioning.html
- **Who has it:** Workday-sourced enterprises, and universities with student and HR systems of record.
- **Severity and frequency:** High, high.

### 3.5 Certification fatigue and rubber-stamping
- **The challenge:**
  - Managers face hundreds of cryptic entitlement rows and approve everything.
  - Campaigns run for weeks.
  - Okta OIG is seen as "IGA lite" for complex certifications.
  - Entra reviews are group-level.
  - Legacy group ownership is never reviewed.
- **Evidence:**
  - SailPoint community FAQ on certification fatigue: https://community.sailpoint.com/t5/Customer-Success-Engineering-FAQ/What-is-certification-fatigue-and-what-are-some-best-practices/ta-p/236575
  - Saviynt reviews on AWS Marketplace (campaign UX "not user-friendly at all"; problems at about 50k IDs): https://aws.amazon.com/marketplace/reviews/reviews-list/B07YQ54WNS
  - Okta on Gartner Peer Insights `[unverified, 403]`: https://www.gartner.com/reviews/market/identity-governance-administration/vendor/okta
  - UVA's Grouper attestation session (InCommon, Aug 2025; link above)
  - Start with Identity heuristic, a revoke rate below 5% suggests rubber-stamping: https://startwithidentity.com/articles/access-review-certification-best-practices/
  - Ponemon's 63% rubber-stamping figure, seen only via Avatier `[unverified]`
- **Who has it:** SOX-, finance- and healthcare-regulated enterprises, and higher-ed group owners.
- **Severity and frequency:** Medium-high, high.

### 3.6 Audit evidence and SoD
- **The challenge:**
  - Auditors test completeness and accuracy of user listings (source, parameters, row counts, reconciliation to HR).
  - Teams juggle CSVs, reminder emails and before-and-after screenshots.
  - Reporting in IGA tools is rigid.
  - SoD is mostly an ERP problem, and SAP integration is hard.
- **Evidence:**
  - Veza documentation on completeness and accuracy (vendor): https://docs.veza.com/4yItIzMvkpAvMVFAamTf/features/access-reviews/how-to/completeness-accuracy-procedures
  - SafePaaS on SOX UAR (vendor): https://www.safepaas.com/access-control/automating-user-access-reviews-for-sox-compliance/
  - PeerSpot reviews: SailPoint ISC reporting is "inadequate and hard to use", and Omada reporting has limited customisation (links above).
  - One Identity's SAP integration is "really difficult": https://www.peerspot.com/products/identity-manager-by-one-identity-pros-and-cons
- **Evidence quality:** practitioner evidence for SoD is thin. No 2025–26 survey was found.
- **Who has it:** Public companies, and SOX-scoped IAM and GRC teams.
- **Severity and frequency:** High where audit findings occur. Medium frequency in forums.

### 3.7 Role explosion
- **The challenge:**
  - A new role for every edge case, and reorgs double the count.
  - Roles have no owner.
  - Mining raw access just reproduces access creep.
- **Evidence:**
  - Veza: about 700 groups per 1,000 users `[unverified, snippet]` (link above).
  - NHIMG on role design breaking at scale: https://nhimg.org/articles/role-design-for-least-privilege-is-breaking-at-enterprise-scale/
  - Zluri (vendor): https://www.zluri.com/eye-on-identity/rbac-role-explosion-hybrid-access-control
  - SailPoint mover thread, where respondents push RBAC (link above).
- **Who has it:** Large enterprises with frequent M&A.
- **Severity and frequency:** Medium, medium. The evidence is mostly vendor material, and SailPoint's role modelling is actually praised in reviews.

### 3.8 Orphaned accounts, service accounts and NHIs
- **The challenge:**
  - Service accounts and keys have no manager, no hire date and no offboarding.
  - Ownership is lost when people leave or companies merge.
  - These identities are found only after an audit or incident.
  - Secrets leak and stay valid for years.
- **Evidence (counts per human):**
  - CyberArk 2025 Identity Security Landscape: 82 machine identities per human (2025-04-23, vendor): https://www.businesswire.com/news/home/20250423817886/en
  - Entro: 144:1 (vendor): https://www.scworld.com/news/nhis-outpace-human-accounts-by-1441
- **Evidence (governance surveys):**
  - CSA/Oasis State of NHI and AI Security (2026-01-27), https://cloudsecurityalliance.org/press-releases/2026/01/27/79-of-it-pros-feel-ill-equipped-to-prevent-attacks-via-nhi-csa-oasis-survey-finds:
    - 51% have no clear ownership of NHIs.
    - 24% take more than 24 hours to rotate an exposed credential.
  - SANS 2026 ITDR report: only 8% rotate most NHI credentials every 90 days `[snippet]`: https://www.sans.org/research/identity-threat-detection-response-report
- **Evidence (leaked secrets, GitGuardian 2026, Mar 2026, vendor):**
  - 28.65M new secrets on public GitHub in 2025.
  - 64% of secrets first found in 2022 are still valid.
  - 24,008 secrets in MCP config files.
  - https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html
- **Evidence (standard):** OWASP NHI Top 10 2025 lists improper offboarding as NHI1 and secret leakage as NHI2: https://owasp.org/www-project-non-human-identities-top-10/2025/top-10-2025/
- **Breaches:**
  - Cloudflare (unrotated tokens from the Okta breach): https://blog.cloudflare.com/thanksgiving-2023-security-incident
  - Internet Archive (Oct 2024)
  - BeyondTrust and US Treasury API key (Dec 2024): https://www.techtarget.com/cybersecurity/news/366617509/Treasury-Department-breached-through-BeyondTrust-service
  - tj-actions (Mar 2025)
  - Nx and Shai-Hulud (Aug–Sep 2025): https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
  - Klue: a credential for an abandoned integration was never deactivated (Jun 2026): https://www.huntress.com/blog/klue-breach-investigation
- **Who has it:** Every engineering organisation with CI/CD and cloud. Worst in cloud-native companies.
- **Severity and frequency:** High. Very high frequency, effectively continuous.

### 3.9 Third-party OAuth and SaaS-to-SaaS token theft
- **The challenge:** A vendor integration's stored OAuth and refresh tokens are stolen and used to bulk-export CRM data. No platform vulnerability is needed, and nobody knew which apps held which scopes.
- **Evidence:**
  - Salesloft Drift (Aug 2025, 700+ organisations): https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift
  - UNC6040 fake Data Loader connected apps (Jun–Jul 2025): https://www.bleepingcomputer.com/news/security/google-hackers-target-salesforce-accounts-in-data-extortion-attacks/amp/
  - Gainsight (Nov 2025): https://astrix.security/learn/blog/salesforce-advisor-gainsight-breach/
  - Vercel via Context.ai (Apr 2026): https://specterops.io/blog/2026/04/21/the-vercel-breach-explains-why-identity-attack-path-management-cant-wait/
  - Klue (Jun 2026; attribution single-source)
  - CSA research note on the year-long ShinyHunters pattern (Jul 2026): https://labs.cloudsecurityalliance.org/research/csa-research-note-shinyhunters-oauth-saas-abuse-20260716-csa/
- **Who has it:** Every Salesforce or Google Workspace tenant with connected apps. Security vendors are frequent victims.
- **Severity and frequency:** High. A major wave every 3–6 months.

### 3.10 MFA and passkey rollout, help-desk recovery and social engineering
- **The challenge:**
  - Lost phones mean manual MFA resets, by one anecdote 3–4 staff-hours each `[unverified, r/sysadmin mirror]`.
  - Passkey adoption stalls without enrolment tooling.
  - Recovery design is the hard part.
  - The help-desk reset is now the main attack path, and agents lack caller-verification tools.
- **Evidence (rollout pain):**
  - Harvard FAS passwordless rollout handout (May 2026) `[unverified, 403]`: https://adminops.fas.harvard.edu/sites/g/files/omnuum796/files/2026-05/May%207%20FINAL%20presentation_Handout.pdf
  - FIDO Alliance: 87% of US and UK enterprises deploying passkeys (Feb 2025): https://fidoalliance.org/new-fido-alliance-research-shows-87-percent-us-uk-workforces-are-deploying-passkeys-for-employee-sign-ins/
  - Identiverse 2026: the conversation moved to recovery and enrolment `[snippet]`: https://startwithidentity.com/blog/identiverse-2026-recap/
  - Gartner 2026 Predicts: 30% will eliminate service-desk account recovery by 2028 (vendor summary): https://www.radiantlogic.com/blog/gartners-2026-iam-predictions-identity-visibility-is-no-longer-optional/
- **Evidence (help-desk attacks):**
  - CISA AA23-320A update (29 Jul 2025): https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
  - ASD/ACSC Scattered Spider advisory (Jul 2025): https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/scattered-spider
- **Breaches:**
  - MGM and Caesars (2023)
  - M&S (Apr 2025, about £300M): https://www.computing.co.uk/news/2025/security/m-s-ends-contract-with-tcs
  - Co-op (Apr 2025, 6.5M members): https://www.bleepingcomputer.com/news/security/co-op-confirms-data-of-65-million-members-stolen-in-cyberattack/
- **Who has it:** Everyone. Acute in higher ed (large, transient, BYOD populations) and for help-desk managers.
- **Severity and frequency:** Very high. Continuous waves organised by sector.

### 3.11 Missing MFA on out-of-scope accounts, and session or token theft
- **The challenge:** "We had an MFA policy." The breached account was a test tenant, a remote-access portal or a data-platform service user outside it. Stolen session tokens also bypass MFA.
- **Breaches:**
  - Microsoft and Midnight Blizzard (Jan 2024): https://www.bleepingcomputer.com/news/security/microsoft-reveals-how-hackers-breached-its-exchange-online-accounts/amp/
  - Change Healthcare (Feb 2024): https://www.techtarget.com/cybersecurity/news/366582824/Change-Healthcare-breached-via-Citrix-portal-with-no-MFA
  - Snowflake customer tenants (2024, about 165 organisations): https://thehackernews.com/2024/06/snowflake-breach-exposes-165-customers.html
  - Okta support HAR session tokens (2023): https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/
- **Statistics:**
  - Verizon DBIR 2025: credential abuse is the top initial vector at 22%, and third-party involvement doubled to 30%: https://verizon.com/about/news/2025-data-breach-investigations-report
  - SANS 2026: 85% have ITDR tooling, yet 55% were still breached `[snippet]`.
  - Sophos 2026: 71% had an identity breach in 2025: https://itdaily.com/news/security/71-percent-organizations-victims-identity-theft-breaches-2025/
- **Who has it:** All sizes. Healthcare and retail have seen the largest losses.
- **Severity and frequency:** Extreme impact, periodic.

### 3.12 AI agent identity
- **The challenge:**
  - Agents run on broad, long-lived, human-equivalent tokens and hold destructive rights with no approval gate.
  - Nobody knows how many agents exist.
  - Authorization, not authentication, is the hard problem.
  - Standards are fragmented.
- **Survey evidence:**
  - SailPoint and Dimensional Research (Jun 2025), https://www.hpcwire.com/aiwire/2025/06/04/sailpoint-research-reveals-ai-agents-as-enterprise-security-blind-spot/:
    - 82% use agents.
    - 44% have policies for them.
    - 80% saw unintended actions.
  - Okta AI at Work 2025: 91% use agents and fewer than 10% have a strategy to secure them: https://www.okta.com/newsroom/articles/ai-at-work-2025--securing-the-ai-powered-workforce/
  - CSA/Oasis: 78% have no policy for AI identities (link above).
- **Standards and conference signals:**
  - OWASP Top 10 for Agentic Applications (Dec 2025) lists Identity and Privilege Abuse as ASI03.
  - MCP authorization spec 2025-11-25: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
  - Forrester's Identiverse 2026 recap: https://www.forrester.com/blogs/identiverse-2026-recap-identity-security-for-agentic-ai-dominates/
- **Incidents:**
  - GitHub MCP toxic agent flow (May 2025): https://invariantlabs.ai/blog/mcp-github-vulnerability
  - Replit production database deletion (Jul 2025): https://www.eweek.com/news/replit-ai-coding-assistant-failure/
  - Amazon Q extension (Jul 2025)
  - Nx malware that weaponised local AI CLIs (Aug 2025): https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/
  - MCP Python SDK OAuth flaw (Sep 2026): https://thehackernews.com/2026/09/official-mcp-python-sdk-flaw-can-let.html
- **Who has it:** Near-universal concern. Acute in engineering-led organisations.
- **Severity and frequency:** High and rising fastest. Most incidents so far are proofs of concept or near-misses.

### 3.13 Cloud entitlements and data-platform access
- **The challenge:**
  - Only a tiny share of granted cloud permissions is ever used.
  - Snowflake users are routinely over-provisioned.
  - Multi-cloud effective permissions are hard to explain.
- **Evidence:**
  - Microsoft 2024 State of Multicloud Security: 2% of permissions used `[snippet]`: https://redmondmag.com/articles/2023/04/03/microsoft-suggests-tracking-cloud-permissions-in-2023-report.aspx
  - Veza on Snowflake over-provisioning (vendor): https://veza.com/blog/securing-snowflake-a-cisos-guide-to-effective-access-control/
  - Entro: 5.5% of AWS machine identities are admins (vendor, link above).
  - Snowflake 2024 breach retrospectives: https://nhimg.org/community/nhi-breaches/snowflake-service-accounts-and-the-nhi-governance-gap-teams-missed/
- **Gaps in the evidence:** no 2025 primary CIEM report and no Databricks data were found.
- **Who has it:** Cloud-first companies and data teams.
- **Severity and frequency:** Medium-high, common. Tessera's wedge sits here.

### 3.14 Group management and Grouper operations (higher ed)
- **The challenge:**
  - Upgrades risk mass deprovisioning in AD.
  - Incremental provisioning doesn't retry.
  - Full syncs take hours.
  - It is unclear whether Grouper, Entra or Okta should provision each target.
  - Legacy groups have no owner.
- **Evidence:** Internet2 Grouper developer-call notes, all from snippets `[unverified]`:
  - Feb 2025: https://spaces.at.internet2.edu/display/GrIntDev/26-February-2025
  - May 2025: https://spaces.at.internet2.edu/display/GrIntDev/21-May-2025
  - Jan 2026: https://spaces.at.internet2.edu/spaces/GrIntDev/pages/373850509/14-Jan-2026
  - InCommon TechEx25 preview (Aug 2025, link above).
- **Who has it:** R1 and large universities with central IAM teams.
- **Severity and frequency:** Medium-high, steady.

### 3.15 Guests, B2B and higher-ed affiliation lifecycle
- **The challenge:**
  - Stale guests pile up.
  - Entra's automated inactive-guest reviews need ID Governance licences, so admins script around them.
  - In higher ed, people move between student, employee, alum, retiree and visiting scholar, often holding several roles at once.
  - Every campus writes its own grace periods.
  - Sponsored identities sit outside HR and the student information system.
  - InCommon Baseline Expectations require SIRTFI, accurate metadata and good TLS.
- **Evidence:**
  - Microsoft Learn, clean up stale guests: https://learn.microsoft.com/en-us/entra/identity/users/clean-up-stale-guest-accounts
  - Tech Community, removing inactive guests `[unverified date]`: https://techcommunity.microsoft.com/blog/nonprofittechies/efficiently-removing-inactive-guest-users-in-m365azure/4407232
  - COmanage, managing population lifecycles: https://spaces.at.internet2.edu/spaces/COmanage/pages/243080413/Managing+Population+Lifecycles
  - InCommon Baseline Expectations: https://incommon.org/federation/baseline-expectations-for-trust-in-federation
  - InCommon guest systems: https://incommon.org/software/guest-systems
  - Fresno State retention standards: https://fresnostate.teamdynamix.com/TDClient/1922/Portal/KB/ArticleDet?ID=170065
  - EDUCAUSE 2025 IAM roundtable `[unverified, 403]`.
- **Who has it:** All of higher ed, plus M365-centric enterprises with research or partner collaborators.
- **Severity and frequency:** Medium-high, high in higher ed.

### 3.16 Migrating off legacy IGA
- **The challenge:**
  - IIQ's freedom (custom objects, plugins, direct data access, cross-identity rules) cannot be replicated in ISC.
  - Cloud-rule deployment depends on vendor support.
  - Oracle OIG 12c support reportedly ends in Dec 2026 `[unverified]`.
  - Sun IDM still exists.
  - Lift-and-shift fails.
- **Evidence:**
  - SailPoint Developer Community, hardest IIQ capabilities to replace in ISC (Aug 2026): https://developer.sailpoint.com/discuss/t/for-organizations-that-have-migrated-from-identityiq-iiq-to-identity-security-cloud-isc-which-iiq-capabilities-were-the-hardest-to-replace-in-isc/220277
  - Xalient case study (32 gaps, 78% complex): https://xalient.com/sailpoint-identityiq-to-identity-security-cloud-migration-case-study
  - Netwrix (vendor): https://netwrix.com/en/resources/blog/oracle-identity-governance-alternatives/
  - Evolveum on Sun/Waveset: https://evolveum.com/tag/waveset
- **Who has it:** Large enterprises with 5–15 years of IIQ or OIM customisation, and their system integrators.
- **Severity and frequency:** High, rising in 2026.

### 3.17 Cost and licensing
- **The challenge:**
  - Access reviews need Entra P2 or ID Governance (about $7 per user on P1).
  - External-identity governance MAU pricing is opaque.
  - Okta costs climb with modules.
  - Fixing issues sometimes needs a paid upgrade.
  - Universities are cutting alumni access partly over licensing.
- **Evidence:**
  - Microsoft Q&A on External ID governance pricing (Jun 2026): https://learn.microsoft.com/en-us/answers/questions/5920874/general-guidance-regarding-mircosoft-entra-externa
  - CIAOPS on P2 access reviews for SMBs (2025-09-27): https://blog.ciaops.com/2025/09/27/microsoft-entra-id-p2-access-reviews-a-critical-evaluation-for-smb-customers-in-australia/
  - PeerSpot reviews of SailPoint pricing (link above).
  - Wesleyan alumni account policy: https://www.wesleyan.edu/its/policies/accounts_policy.html
- **Who has it:** SMBs on Microsoft, enterprises stacking modules, and budget-constrained higher ed.
- **Severity and frequency:** Medium-high, high.

### 3.18 Staffing and skills
- **What postings ask for:** SailPoint ISC (most common), Saviynt, Okta and Entra; SCIM, SAML, OIDC, OAuth and REST; Python or PowerShell; Terraform as a "preferred" skill. Certifications: SC-300 and Okta.
- **The challenge:**
  - Postings skew senior, at 77.6% in German data.
  - North American integration talent is scarce.
  - Higher ed loses funding to AI and cloud priorities.
- **Evidence:**
  - Dice SailPoint ISC posting: https://www.dice.com/job-detail/ac71c638-5b4d-4c34-99d7-2e21165c322b
  - Insight Global Saviynt posting: https://jobs.insightglobal.com/find_a_job/virginia/job-489947
  - KuppingerCole guest blog on German IAM job data: https://www.kuppingercole.com/blog/guest/the-most-wanted-professionals-in-iam-germanys-identity-workforce-demand-through-data
  - ISACA State of Cybersecurity 2025: 55% understaffed (cybersecurity broadly): https://mms.businesswire.com/media/20250929794833/en/2592986/1/ISACA_StateofCyber_2025_Infographic_FINAL.pdf
  - PeerSpot (link above).
- **Who has it:** Programme owners and hiring managers. Worst in higher ed and the public sector.
- **Severity and frequency:** High, high. It makes everything above harder. Tools that need less custom code (declarative policy, explainable access) help directly.

### 3.19 Other themes the evidence showed
- **Upgrade and operations risk in self-hosted IAM.** Grouper mass deletions, the move to containers, and Shibboleth hosting.
- **Vendor dependency in SaaS IGA.** ISC cloud rules need vendor support to deploy and debug.
- **"Identity fabric" and visibility-first buying.** IVIP and ISPM: Gartner IAM Summit 2025–2026 and Gartner 2026 Predicts, abstract at https://www.gartner.com/en/documents/7358330.
- **AI as an assistant for IAM work.** TechEx25 sessions.

## 4. The capability checklist and Tessera's status

Status is from reading `dev` at `b4dfac4` and running it (`go vet` and `go test ./...` pass; API started on :8170 with the seeded demo database and probed with curl). Strict rules: demo connectors, simulated Workday and UI Preview mocks count as **Partial** at best. "Graph-only" means the change is written to Tessera's SQLite graph and never to the target system.

Two facts shape almost every row:

- **Every connector in `dev` is a demo connector.** `connectors.Load` only knows `demo-*` factories (`mvp/server/internal/connectors/demo.go`). No real Okta, Entra, AWS, Workday or SCIM system can be read.
- **Nothing is written to a target system.** JML execution, review revocation, JIT grant and expiry, and least-privilege revoke all mutate `grant_edges`/`accounts` rows only (`jml.applyStep`, `reviews.Decide`, `jit.dropEdge`). The `rotate_secret` step only stamps `last_rotated_at`.
- **The API has no authentication.** `GET /api/audit` returns 200 to an anonymous caller; the audit `actor` is whatever the client sends.

So no checklist item reaches **Solved**. The engine logic behind many Partial rows is real and tested; what is missing is the path to and from real systems.

| ID | Capability (testable) | Challenge it solves | Status | Evidence | Next step |
|---|---|---|---|---|---|
| **T1 Connectors and onboarding** | | | | | |
| C1 | Read-only production connectors ingest a real Okta, Entra ID, Google Workspace and Workday tenant (identities, accounts, groups, app assignments, last sign-in) with incremental sync | Connector and onboarding effort | Gap | Connector interface exists (`internal/connectors/connector.go`: `Discover`, `StreamEvents`) but `connectors.Load` only has `demo-*` factories. #93–#98 are read-only *probes* (deployment-readiness §5.4), not ingestion. AWS ingestion is separate and Designed (#26, see CL1) | #104 (new) |
| C2 | Generic SCIM 2.0 client reads and writes Users and Groups for any SCIM app, verified by re-read | Connector effort; SAML/OIDC app onboarding | Designed | Group provisioning to SCIM: `groups-grouper-parity.md` §9.2, #54. SCIM app live checks: #99. Account/entitlement SCIM provisioning is not designed | #103 (new) |
| C3 | Flat-file (CSV/SFTP) import of accounts and entitlements for disconnected apps, with schema mapping and delta detection | Connector effort; long tail of apps | Gap | Capability map §G "SFTP file drops" (row 95) and §C "Connector SDK" (Phase 3); no design, no issue | #105 (new) |
| C4 | A connection cannot go live until readiness checks pass and a dry-run reconciliation (orphans, unmatched, sparse attributes) has been reviewed | Connector effort; HR data quality | Designed | `deployment-readiness.md` §§3–6; #82–#90. UI `features/insights/DeploymentHealth.tsx` is a Preview over mock data | Build #82–#88 |
| C5 | App onboarding workflow: catalog entry, owner questionnaire, SSO type, entitlement owners, review cadence | SAML/OIDC app onboarding | Gap | Capability map §G "Application onboarding workflow" (Saviynt rows 46–47); no design or issue | Backlog (medium; not filed) |
| **T2 Joiner, mover, leaver** | | | | | |
| J1 | Joiner: HR event creates identity and birthright access computed from attributes before the start date | JML gaps | Partial | `jml.JoinerPlan`, `jml.ExecuteEvent`; test `TestDemoJoinerAndMoverPlans`; `POST /api/hris/events`, `GET /api/hris/events/{id}/plan`, `POST …/execute`; UI Governance → Lifecycle. Missing: real HRIS, attribute rules (birthright = team inference), target writes, effective-date scheduler | #103 (new); HRIS connector #104 |
| J2 | Mover: access not justified by the new role is removed or sent for review on a deadline, not just added | Mover access accumulation | Partial | `jml.MoverPlan` emits `remove_grant` and `review_grant` (30-day flag); `TestDemoJoinerAndMoverPlans`. Missing: review deadline is text only, nothing enforces it; graph-only | Wire `review_grant` to a micro-certification with expiry |
| J3 | Leaver: every account in every connected system is disabled or deleted, and Tessera re-reads each system to prove it | Leaver gaps; orphaned accounts | Partial | `jml.LeaverPlan`/`ExecuteEvent`; tests `TestLeaverPlanContents`, `TestExecuteLeaverEventRemovesAllAccess`, `TestDemoMarcusLeaverPlan`; `GET /api/jml/leaver-plan/{id}`. Missing: no target writes, no verification | #103 (new) |
| J4 | Leaver kill-switch revokes active IdP sessions, refresh tokens, OAuth grants, PATs and API keys, not just account status | Leaver gaps; session/token theft | Gap | `applyStep` has no session/token action; `rotate_secret` only sets `last_rotated_at`. Capability map §C "leaver kill-switch" row has no design or issue | #106 (new) |
| J5 | Effective-dated events (future start, scheduled termination, rehire, leave of absence) execute at the effective time | JML gaps; HR data quality | Partial | `hris_events.effective_at` stored; execution is manual (`POST …/execute`); no scheduler, no rehire or LOA types | Add scheduler with the closed-loop work |
| J6 | When an owner leaves, every service account, key and agent they own is reassigned to a named person | Orphaned NHIs | Partial | Leaver plan `reassign_owner` step (`jml.go`), `TestLeaverPlanContents`. Missing: new owner is inferred (manager), no acceptance by the new owner | Owner-acceptance task |
| J7 | Leaver SLA report: time from HR termination to last access removed, per system | Audit evidence; JML | Gap | Not designed | #111 (new) |
| J8 | Detect missed leavers: terminated in HR but still has effective access anywhere | Leaver gaps | Partial | Policy `policies/leaver-access.yaml` (`terminated_with_access`); `TestLeaverPlanForAlreadyTerminatedIdentityFindsLeftovers`, `TestDemoPoliciesProduceExpectedFindings`; `GET /api/violations` shows 3 on demo data | Real connectors |
| **T3 HR data quality and correlation** | | | | | |
| H1 | Account-to-identity correlation with confidence tiers, a review queue and reversible link/unlink | HR data quality; orphan accounts | Partial | `ingest.Resolver` correlates by external id then email only. Tiered matching designed: `guest-accounts-and-claim.md` §5, `deployment-readiness.md` §6.2; #68, #85 | Build #68/#85 |
| H2 | HR data-quality checks (missing manager, department, duplicate email, sparse attributes) flagged before they drive JML | HR data quality | Designed | `deployment-readiness.md` §6.3; #85 | Build #85 |
| H3 | Several authoritative sources (HRIS, SIS, sponsor) with per-attribute precedence and multiple concurrent affiliations | Higher-ed lifecycle; HR data | Designed | `guest-accounts-and-claim.md` §§3–4, §9.1; #64, #67 | Build #64 |
| **T4 Orphaned, dormant and shared accounts** | | | | | |
| O1 | Orphan accounts (no correlated identity) listed per system with last use | Orphaned accounts | Partial | NHI `orphaned` flag (`nhi.go`), review reason `orphaned_nhi`; `GET /api/nhi`. Human orphan-account report not built; designed `deployment-readiness.md` §6.3, #85 | Build #85 |
| O2 | Dormant accounts and unused entitlements from real last-login/usage data | Orphaned and dormant accounts; least privilege | Partial | `usage` index, `leastpriv` (`TestUsageIndexLastUsed`, `TestUnusedPermissionsDetected`); `GET /api/summary` (36% unused on demo). Usage comes from demo events only | Ingest CloudTrail/Okta System Log |
| **T5 Certifications** | | | | | |
| R1 | Risk-scoped campaigns send only flagged grants to reviewers, each with the reason it was flagged | Certification fatigue | Partial | `reviews.GenerateCampaign`; `POST /api/reviews/campaigns` (probe: 219 grants, 81 items, 138 auto-certified); `TestAPISmoke` asserts exception-only. `internal/reviews` has no unit tests. Auditor caveat: capability map "Corrections" | Unit tests; documented scoping rules |
| R2 | Each review item shows last use, peer coverage and why it was flagged | Certification fatigue (rubber-stamping) | Partial | `context` JSON in `review_items`; UI Governance → Reviews | Real usage data |
| R3 | Review population is frozen and provably complete, and the campaign can be exported and re-derived for an auditor | Audit evidence | Gap | Items are stored at generation, but no completeness proof, no export, no reproduction. Capability map §C row has no design or issue (groups attestation #57 is groups-only) | #110 (new) |
| R4 | A "revoke" decision removes the access in the target and the item stays open until a re-read confirms it | Certification; audit evidence | Partial | `reviews.Decide` deletes the graph edge and audits `review.revoke`; no target write or verification | #103 (new) |
| R5 | Auto-decisions record the rule that made them and a random sample is routed for human QA | Certification fatigue; audit | Partial | `auto_certified` count stored; no per-item rule record, no sampling | #110 (new) |
| R6 | Campaign reminders, escalation to the reviewer's manager, delegation and due dates | Certification fatigue | Gap | Notifications are capability map §G (Phase 2), no issue | Backlog (medium; not filed) |
| R7 | Event-driven micro-certification on mover or risk change | Mover accumulation | Gap | Not designed | Backlog (medium; not filed) |
| **T6 Role explosion and role engineering** | | | | | |
| RL1 | Role mining proposes roles from actual entitlements and usage, with impact preview, output as policy-as-code | Role explosion | Partial | Only role trimming: `leastpriv` `role_trim` (`TestRoleTrimFlagsPermissionNoHolderUses`). Mining is capability map §G Phase 3, no issue | Backlog |
| RL2 | Attribute-based (policy) groups replace hand-assigned roles, with a membership diff on every change | Role explosion; group management | Designed | `groups-grouper-parity.md` §8; #52 | Build #52 |
| RL3 | Every entitlement has an owner, description and risk level, set by pattern rules | Role explosion; certification | Gap | Capability map §G "Entitlement update rules" (row 77); no issue | Backlog (medium; not filed) |
| **T7 Separation of duties** | | | | | |
| S1 | SoD evaluated on effective permissions across systems, through groups and nested roles | SoD | Partial | `policies/sod-payments.yaml`, `policy.go` `separation_of_duties`; `TestTinyWorldPolicyFindings`, `TestDemoPoliciesProduceExpectedFindings`; `GET /api/violations`; UI Insights → SoD conflicts | Real connectors; rule library |
| S2 | Preventive SoD: a request or JIT grant that would create a conflict is blocked or escalated before approval | SoD | Gap | `jit.CreateRequest`/`Approve` do not call `policy.Evaluate`. `/api/simulate` reports `violations_introduced` but is not wired into approval | Small change; backlog (not filed, medium) |
| S3 | Mitigating controls and time-bound SoD exceptions with owner and expiry | SoD; audit | Gap | Capability map §C "SoD engine with mitigating controls" (Phase 3); no issue | Backlog |
| **T8 Audit evidence** | | | | | |
| A1 | Append-only, tamper-evident audit ledger whose actor is an authenticated principal | Audit evidence; Tessera's own security | Partial | A plain `audit` table and `GET /api/audit` exist (`store.Audit`), but it is mutable and the actor is client-supplied (anonymous probe returned 200). Ledger designed: `phase-0-platform-security.md`; #7 | Build #7, #9 |
| A2 | One-click evidence pack per framework (SOC 2, SOX ITGC, ISO 27001, PCI DSS v4 8.x): user listing, JML samples, reviews, revocations with proof | Audit evidence | Gap | Capability map §C "Framework evidence packages" (None); only deployment evidence #89 | #111 (new) |
| A3 | Point-in-time query: who could reach resource X on date D, and why | Audit evidence | Gap | Graph is current-state only; groups PIT history #46 covers groups only | #111 (new) |
| **T9 Access requests** | | | | | |
| Q1 | Catalog request with risk-tiered approval chain (manager, owner, security) | Access request friction | Partial | JIT requests with single approver: `jit.CreateRequest`/`Approve`; `TestDecisionStateMachine`; `POST /api/jit/requests`. UI Access → Request access is a Preview over mocks | Approval chains |
| Q2 | Approve and request from Slack, Teams or email | Request friction; staffing | Gap | Not designed (capability map §C mentions Slack/Teams) | Backlog (medium; not filed) |
| Q3 | Time-bound access expires automatically and is removed in the target | Standing access | Partial | `jit.Sweep`, `POST /api/jit/sweep`; `TestJITLifecycle`, `TestExpiredJITEdgesAreIgnored`; graph-only | #103 (new); native JIT later |
| **T10 Non-human identities and secrets** | | | | | |
| N1 | NHI inventory across cloud and SaaS with owner, credential age and last use per credential | NHI sprawl | Partial | `nhi.Inventory`; `GET /api/nhi` (31 items on demo, flags `orphaned`, `owner_left`, `stale_secret`, `dormant`); `internal/nhi` has no unit tests (covered by `TestAPISmoke`). Demo data only | AWS NHI after #26 |
| N2 | Ownerless NHIs flagged and owners re-attest on a schedule | NHI ownership | Partial | `policies/nhi-ownership.yaml`; review reason `orphaned_nhi` | Owner attestation campaign type |
| N3 | Secret rotation orchestrated through vaults and cloud APIs, then verified by re-reading the credential's age | NHI secrets; breach root cause | Gap | `rotate_secret` step only updates a timestamp; capability map §D "Secret rotation orchestration" (Phase 4, integrate) has no issue | #113 (new) |
| N4 | Third-party OAuth app and grant inventory (Salesforce connected apps, Google/Entra consents, GitHub apps) with scopes, last use, risk and one-click revoke | SaaS-to-SaaS token theft | Gap | Capability map §D "Third-party OAuth grant and app-trust inventory" (None, Phase 2); no issue | #107 (new) |
| N5 | Leaked secrets found by a scanner are matched to the owning NHI and routed to its owner | NHI secrets | Gap | Not designed | Backlog (integrate GitGuardian/GitHub secret scanning; not filed) |
| N6 | Workload-federation trust lint: wildcard OIDC `sub`, `Principal:*`, missing ExternalId | NHI; cloud entitlements | Gap | Capability map §A "IaC policy linting" and §D "Federated workload identity" rows; no issue. AWS evaluator will evaluate trust policies (#24) but not lint them | Backlog (not filed) |
| **T11 AI agent identity** | | | | | |
| AG1 | Agents are a first-class identity type with a required human sponsor and risk tier | AI agent identity | Partial | Identity type `ai_agent`; `policies/nhi-ownership.yaml`, `policies/ai-agents-no-pii.yaml`; UI Directory agent cards. No risk tier, demo data | Phase 4 plan |
| AG2 | Agent access is bounded by user ∩ agent ∩ task at token issuance, not only shown | AI agent over-privilege | Partial | Delegations stored and displayed (`nhi.delegationView`); nothing enforces the intersection | #115 (new) |
| AG3 | MCP authorization server issues short-lived, audience-bound, delegation-aware tokens (RFC 8693 `act`), with every tool call decided and audited | AI agent identity; MCP | Gap | Capability map §E (Phase 4), no design, no issue | #115 (new) |
| AG4 | Discover agents, MCP servers and agent OAuth clients from Entra Agent ID, Okta, Copilot Studio, Bedrock AgentCore and code repos | Shadow agents | Gap | Capability map §E "Agent discovery" (Partial = demo); no issue | #116 (new) |
| AG5 | Agent kill switch revokes every credential and delegation of an agent everywhere | AI agent incidents | Gap | `revoke_delegation` exists only in the human-leaver plan | #106 (new) |
| **T12 MFA, passkeys and recovery** | | | | | |
| M1 | MFA posture report: each person's registered methods by strength (phishing-resistant, push, SMS) and coverage gaps per IdP | MFA/passkey rollout | Gap | Not designed | #109 (new) |
| M2 | Detect accounts in SaaS and data platforms that bypass SSO or have no MFA (local passwords, Snowflake password users, test tenants) | Missing MFA on out-of-scope accounts | Gap | Not designed | #109 (new) |
| M3 | Help-desk reset workflow: verify the caller (call-back to number on record, manager approval, IDV for privileged), then reset, all audited | Help-desk social engineering | Gap | Only guest-account recovery is designed (`guest-accounts-and-claim.md` §7.5, #73); capability map §G password management (Phase 3) has no issue | #108 (new) |
| M4 | Tessera's own admins sign in with phishing-resistant MFA and step up for sensitive actions; every API route is authenticated | Tessera's own security | Designed | `phase-0-platform-security.md` §§8–12; #5–#19. Today `GET /api/audit` answers anonymous callers | Build Phase 0 |
| **T13 Session and token theft, ITDR** | | | | | |
| I1 | Receive SSF/CAEP/RISC events and propagate session revocation downstream within 60 s | Session/token theft | Gap | Capability map §D "SSF/CAEP/RISC receiver" (Phase 3); no issue | #114 (new) |
| I2 | Detections for help-desk reset followed by new MFA device, new federation/IdP added, bulk export by an integration | ITDR | Gap | Capability map §D detections row (Phase 3); no issue | Backlog (not filed; partly SIEM's job) |
| **T14 Cloud entitlements (CIEM)** | | | | | |
| CL1 | Exact AWS effective permissions including SCP per OU, RCP, boundary, session and resource policies, with a "why" trace | Cloud entitlements | Designed | `aws-effective-permission-evaluator.md`; #20–#31 | Build #20–#31 |
| CL2 | Unused cloud access removed as a reviewed change and verified by re-reading the cloud | Least privilege | Partial | `leastpriv`; `GET /api/least-privilege/recommendations`, `POST /api/least-privilege/revoke` (dry run and apply); `TestRevokeDryRunAndApplyViaAPI`, `TestRecommendationsRemoveVsRightSize`; graph-only | After #26; writes via #103 |
| CL3 | Azure RBAC + Entra roles and GCP IAM effective permissions | Cloud entitlements (multi-cloud) | Gap | Capability map §A "Azure and GCP evaluators" (Phase 3); no issue | Backlog (not filed; Phase 3) |
| CL4 | Zero standing privilege: privileged access granted just-in-time through the cloud's own mechanism (Identity Center, PIM, GCP PAM) | Standing privilege | Partial | `policies/no-standing-prod-admin.yaml` (`TestJITOnlyAdminIsNotAViolation`); JIT is graph-only | Native JIT broker |
| CL5 | What-if simulation of a change shows who gains or loses which permission and which policies break | Change risk | Partial | `simulate`; `TestSimulation`; `POST /api/simulate` (probe returned per-identity diff and violation delta) | Cedar diff per PR (Phase 1) |
| CL6 | Privilege-escalation path analysis | Cloud entitlements | Gap | Capability map §A (Phase 2); no issue | Backlog |
| **T15 Data platform access** | | | | | |
| DP1 | Snowflake role-hierarchy closure to database/schema/table grants, with who-can-access per object | Data platform access | Partial | Graph role inheritance (`TestRoleInheritanceIsFollowed`, `TestDescribePathAndWhoCanAccess`); demo Snowflake connector | Real Snowflake connector |
| DP2 | Databricks Unity Catalog and BigQuery access | Data platform access | Gap | Capability map §A (Phase 3); no issue | Backlog |
| DP3 | Report who can reach PII- or financial-tagged data, including agents | Data access; agents | Partial | Resource tags; `TestDemoCompanyAliceReachesCustomerPII`; `policies/ai-agents-no-pii.yaml` | Tags from real classifiers |
| **T16 Group management** | | | | | |
| G1 | Native groups with composites, include/exclude, effective membership and dates | Group management | Designed | `groups-grouper-parity.md` §§5–6; #44, #45 (today only connected-system groups are read) | Build #44–#45 |
| G2 | Loaders from SQL/LDAP/SIS with failsafe thresholds that hold large changes for approval | Group management; higher-ed | Designed | §9.1; #53 | Build #53 |
| G3 | Group provisioning to AD/LDAP, Entra, Google, Okta verified by re-read | Group management | Designed | §9.2; #54, #55 | Build |
| G4 | Group owner attestation and stale-group cleanup | Group sprawl | Designed | §10; #57 | Build |
| G5 | Grouper migration with shadow-compare and per-folder cut-over | Legacy migration (higher-ed) | Designed | §11; #58, #59 | Build |
| **T17 Guests, B2B and external identities** | | | | | |
| GU1 | Sponsored guests with expiry, renewal and transfer when the sponsor leaves | Guest/B2B sprawl | Designed | `guest-accounts-and-claim.md` §§4, 8; #65, #74 | Build |
| GU2 | Account claim with NIST 800-63A-4 verification and enumeration resistance | Guest onboarding; recovery attacks | Designed | §6; #69, #70 | Build |
| GU3 | InCommon/eduGAIN federation for external users | Higher-ed collaboration | Designed | §6.6; #72 | Build |
| GU4 | Inventory of existing Entra B2B and Google external guests with inviter, last sign-in and stale-guest cleanup | Guest/B2B sprawl | Gap | Guest design covers Tessera-native guests, not discovery of existing IdP guests; no issue | Backlog (medium; not filed) |
| **T18 Legacy IGA migration** | | | | | |
| LM1 | Importer for SailPoint IIQ/ISC and Saviynt: identities, roles, entitlements, SoD rules, campaign history, with shadow-compare | Migration off legacy IGA | Gap | `saviynt-feature-coverage.md` is a parity checklist, not migration tooling; only Grouper migration is designed (#58) | #112 (new) |
| LM2 | Policies and configuration as code with review and promotion between environments | Staffing (no-PS changes); migration | Partial | YAML policies loaded from disk/Git (`TestLoaderReadsMultiDocumentListsAndReloads`, `TestAllRepoPoliciesLoadAndHaveKnownTypes`); `GET /api/policies`. No transport/promotion | Cedar repo (Phase 1) |
| **T19 Cost, staffing and operability** | | | | | |
| CS1 | SaaS licence reclamation: unused paid seats found and reclaimed | Cost and licensing | Gap | Capability map §G row 41 (Phase 3) | Backlog |
| CS2 | "Why does X have Y" answered in one view with every path | Staffing; audit | Partial | `graph` path engine (`TestEffectivePermissionPathThroughGroupsAndRoles`, `TestMultiplePathsAreAllReported`); `GET /api/identities/{id}`, `GET /api/graph`; UI Insights → Graph explorer | Real data |
| CS3 | Common changes (rules, workflows) made by IAM engineers without vendor services or custom code | Staffing; connector effort | Partial | Declarative YAML policies; UI Governance → Workflows is a Preview mock | Workflow engine |
| **T20 Platform prerequisites** | | | | | |
| P1 | Closed-loop provisioning engine: SCIM and native API writes, retries, and verify-by-re-read for accounts and entitlements | Underpins J1–J3, R4, Q3, CL2 | Gap | Capability map §C "Closed-loop provisioning" (None); only group provisioning #54 | #103 (new) |
| P2 | Tenant isolation | Tessera's own security | Designed | `phase-0-platform-security.md` §7; #5, #18 | Build Phase 0 |

## 5. Biggest gaps that matter most to customers (ranked)

Ranked by customer severity × frequency, then by how many other checklist items each gap blocks.

1. **No real connectors** (C1, #104; AWS #26; C3 flat-file, #105). Every number Tessera shows today is demo data. Connector effort is also the most common complaint about incumbents. Shipping Okta, Entra, Google and Workday ingestion plus a CSV path is the precondition for any pilot.
2. **No writes to target systems, and no verification** (P1, #103). JML, review revocation, JIT expiry and least-privilege revoke are all graph-only. This single gap keeps J1–J3, R4, Q3 and CL2 at Partial. Design rule 4 in the capability map ("nothing is done until re-read") is not implemented anywhere yet.
3. **Leavers and compromised identities keep their sessions and tokens** (J4, #106; I1, #114). This lines up with the 2025–26 incidents: stolen sessions and OAuth tokens outlive account disablement.
4. **Third-party OAuth grant inventory** (N4, #107). This was the most damaging SaaS attack pattern of the past 15 months, and Tessera's graph model is a natural fit for it.
5. **Help-desk verified reset and MFA posture** (M3, #108; M1–M2, #109). This is the Scattered Spider playbook. The IdP still owns login, but Tessera can own the verification workflow and the coverage report.
6. **Audit-grade reviews and evidence** (R3, #110; A2, #111). Risk-scoped reviews are a differentiator only if the population can be proven complete and exported. Without that, the auditor caveat in the capability map stands.
7. **Legacy IGA migration path** (LM1, #112). Most prospects arrive from SailPoint, Saviynt or OIM. Grouper migration is designed, but there is no IGA equivalent.
8. **Secrets rotation** (N3, #113). The inventory is there; the action is not.
9. **AI agents: enforcement and discovery** (AG3, #115; AG4, #116). The capability map deliberately puts these in Phase 4. Market pressure is high, so they are filed now at medium priority to keep the scope visible.
10. **Tessera's own security** (M4, P2, A1: Phase 0 #5–#19). This is already planned. It is listed because the API currently answers anonymous callers, which blocks any customer connection.

What Tessera does well today, all on demo data:
- Explainable effective-permission paths through groups and nested roles.
- Cross-system SoD on effective permissions.
- What-if simulation with violation deltas.
- Leaver plans that include NHI owner reassignment and agent delegation revocation.
- Risk-scoped review campaigns with reasons.

These are differentiated and tested. They become customer value once gaps 1 and 2 close.

## 6. Notes for the capability map

These notes are recorded here rather than as edits to `docs/knowledge/README.md`. The map's own definitions treat demo data as "Have", so the map is not wrong by its own terms.

- **"Partial" or "Have" in the map means "against demo data".** By this report's stricter definitions, the map's rows for JML, reviews, NHI and least privilege are Partial, and none is Solved.
- **The "JML automation with leaver kill-switch" row** should say explicitly that the current leaver plan revokes no sessions or tokens.
- **No row exists for MFA posture, help-desk verified reset (beyond the passwords row), or IGA-platform migration.** Consider adding them; issues #108, #109 and #112 track them.

## 7. Issues created

Every issue is labelled `agent-backlog`, `type:feature`, `source:market` and a priority. Before filing, open and closed issues were searched by title keywords (provisioning, session, OAuth, MFA, help desk, evidence, rotation, CAEP, MCP, agent, migration, SailPoint, CSV, connector, Okta, Entra). The only overlaps found were partial:
- #54/#55: group provisioning only.
- #93–#98: readiness probes, not ingestion.
- #89: deployment evidence only.
- #14: Tessera's own OAuth server.

The new issues reference these where relevant.

| # | Item | Title | Priority |
|---|---|---|---|
| #103 | P1 | Closed-loop account and entitlement provisioning with verify-by-re-read | high |
| #104 | C1 | Production read connectors for Okta, Entra ID, Google Workspace and Workday | high |
| #105 | C3 | Flat-file (CSV/SFTP) import for disconnected applications | high |
| #106 | J4 | Kill-switch: revoke sessions, refresh tokens, OAuth grants, PATs and API keys | high |
| #107 | N4 | Third-party OAuth app and grant inventory with scope risk and one-click revoke | high |
| #108 | M3 | Verified help-desk reset workflow for passwords and MFA | high |
| #109 | M1, M2 | MFA posture report and detection of accounts that bypass SSO or MFA | high |
| #110 | R3, R5 | Frozen, provably complete certification populations with auditor export | high |
| #111 | A2, A3, J7 | Framework evidence packs and point-in-time access queries | high |
| #112 | LM1 | Migration importer for SailPoint IIQ/ISC and Saviynt with shadow-compare | high |
| #113 | N3 | Secret rotation orchestration through vaults and cloud APIs | medium |
| #114 | I1 | SSF/CAEP/RISC receiver that propagates revocation downstream | medium |
| #115 | AG2, AG3 | MCP authorization server issuing delegation-aware, task-scoped tokens | medium |
| #116 | AG4 | Discover AI agents, MCP servers and agent OAuth clients | medium |

Gaps not filed, because they are medium severity or already part of a planned phase:

| Item | Gap |
|---|---|
| C5 | App onboarding workflow |
| R6 | Campaign reminders and escalation |
| R7 | Micro-certification on mover or risk change |
| RL3 | Entitlement update rules |
| S2 | Preventive SoD (a small change) |
| S3 | Mitigating controls |
| Q2 | Slack/Teams approvals |
| N5 | Secret-scanner linkage |
| N6 | Trust-policy lint |
| I2 | Detections |
| CL3 | Azure/GCP evaluators |
| CL6 | Escalation paths |
| DP2 | Databricks/BigQuery |
| GU4 | Discovery of existing IdP guests |
| CS1 | Licence reclamation |
| RL1 | Role mining |

## 8. Sources

All links were seen by the research passes on 2026-10-09. Items marked `[unverified]` were seen only as search snippets, returned 403, or rest on a single or contested source.

**Practitioner forums and communities**
- Hacker News, SCIM (Jun 2025): https://news.ycombinator.com/item?id=44196393
- Hacker News, SSO tax: https://news.ycombinator.com/item?id=38344733, https://news.ycombinator.com/item?id=35525608
- Hacker News, offboarding leaves manual cleanup: https://news.ycombinator.com/item?id=35643709
- SailPoint Developer Community, mover lifecycle state (Nov 2024): https://developer.sailpoint.com/discuss/t/lifecycle-state-mover-setting-how-to-identify-the-change-of-attribute-and-how-to-configure-jml/88973
- SailPoint Developer Community, IIQ to ISC migration (Aug 2026): https://developer.sailpoint.com/discuss/t/for-organizations-that-have-migrated-from-identityiq-iiq-to-identity-security-cloud-isc-which-iiq-capabilities-were-the-hardest-to-replace-in-isc/220277
- SailPoint Developer Community, beyond lift-and-shift: https://developer.sailpoint.com/discuss/t/beyond-the-lift-and-shift-architecting-success-in-the-iiq-to-isc-migration/209983
- SailPoint community, certification fatigue FAQ: https://community.sailpoint.com/t5/Customer-Success-Engineering-FAQ/What-is-certification-fatigue-and-what-are-some-best-practices/ta-p/236575
- Saviynt forums: https://forums.saviynt.com/t5/identity-governance/netsuite-onboarding/td-p/57237, https://forums.saviynt.com/t5/identity-governance/connection-issues-for-saviynt-app-integration-in-servicenow/td-p/67332, https://forums.saviynt.com/t5/application-access-governance/sav4sav-account-and-entitlements-association-failure/m-p/96326
- Microsoft Q&A, locked claims UI: https://learn.microsoft.com/en-us/answers/questions/5762167/editing-attributes-and-claims-in-saml-based-single
- Microsoft Q&A, AADSTS700016: https://learn.microsoft.com/en-us/answers/questions/5642308/how-do-i-fix-aadsts700016
- Microsoft Q&A, External ID governance pricing: https://learn.microsoft.com/en-us/answers/questions/5920874/general-guidance-regarding-mircosoft-entra-externa
- Microsoft Learn, Workday attribute updates not flowing: https://learn.microsoft.com/nb-no/Entra/Identity/app-provisioning/hr-user-update-issues
- Microsoft Learn, clean up stale guests: https://learn.microsoft.com/en-us/entra/identity/users/clean-up-stale-guest-accounts
- Microsoft Learn, clean up unmanaged accounts: https://learn.microsoft.com/en-us/entra/identity/users/clean-up-unmanaged-accounts
- Okta KB, contractor-to-FTE conversion: https://support.okta.com/help/s/article/How-To-Convert-From-Contractor-to-FullTime-Employee-Using-Workday-Provisioning
- Okta FastPass AMA recap: https://support.okta.com/help/s/blog/a674z00000014AkAAI/fastpass-ama-recap-top-highlights
- r/sysadmin, via a third-party mirror `[unverified]`: https://reddit.sentinel-team.org/posts/1sm204b/snapshots/2026-04-17T19%3A21%3A16.92198Z

**Higher education**
- InCommon, TechEx25 preview: https://incommon.org/news/grouper-therapy-techex-citement-and-revamped-training
- InCommon, Baseline Expectations: https://incommon.org/federation/baseline-expectations-for-trust-in-federation
- InCommon, guest systems: https://incommon.org/software/guest-systems
- Internet2 Grouper developer-call notes `[unverified]`: https://spaces.at.internet2.edu/display/GrIntDev/26-February-2025, https://spaces.at.internet2.edu/display/GrIntDev/21-May-2025, https://spaces.at.internet2.edu/spaces/GrIntDev/pages/346129633/16-July-2025, https://spaces.at.internet2.edu/spaces/GrIntDev/pages/373850509/14-Jan-2026
- COmanage, managing population lifecycles: https://spaces.at.internet2.edu/spaces/COmanage/pages/243080413/Managing+Population+Lifecycles
- Internet2, Federation Expectations working group report: https://spaces.at.internet2.edu/spaces/TI/pages/350159404/TI.181.1
- EDUCAUSE 2025 IAM roundtable `[unverified]`: https://events.educause.edu/annual-conference/2025/agenda/iam-roundtable-share-review-and-strategize
- Harvard FAS passwordless rollout handout `[unverified]`: https://adminops.fas.harvard.edu/sites/g/files/omnuum796/files/2026-05/May%207%20FINAL%20presentation_Handout.pdf
- Fresno State retention standards: https://fresnostate.teamdynamix.com/TDClient/1922/Portal/KB/ArticleDet?ID=170065
- Wesleyan accounts policy: https://www.wesleyan.edu/its/policies/accounts_policy.html
- Evolveum, TechEx 2025 `[unverified]`: https://evolveum.com/techex2025

**Reviews**
- PeerSpot, SailPoint ISC: https://www.peerspot.com/products/sailpoint-identity-security-cloud-pros-and-cons
- PeerSpot, Omada: https://www.peerspot.com/products/omada-identity-cloud-pros-and-cons
- PeerSpot, One Identity Manager: https://www.peerspot.com/products/identity-manager-by-one-identity-pros-and-cons
- Saviynt reviews on AWS Marketplace (G2-syndicated): https://aws.amazon.com/marketplace/reviews/reviews-list/B07YQ54WNS
- Gartner Peer Insights, Okta IGA `[unverified]`: https://www.gartner.com/reviews/market/identity-governance-administration/vendor/okta
- G2, Lumos and ConductorOne `[snippets]`: https://www.g2.com/products/lumos/reviews_and_filters, https://www.g2.com/products/conductorone/reviews

**Analyst, survey and conference sources**
- Verizon DBIR 2025: https://verizon.com/about/news/2025-data-breach-investigations-report
- CyberArk 2025 Identity Security Landscape: https://www.businesswire.com/news/home/20250423817886/en
- CyberArk 2025 State of IGA: https://www.scworld.com/resource/2025-state-of-iga-report-reveals-persistent-gaps-in-automation-and-integration
- Cerby 2025, via CSA: https://cloudsecurityalliance.org/articles/why-identity-automation-fails-at-96-of-organizations
- CSA/Oasis State of NHI and AI Security (2026): https://cloudsecurityalliance.org/press-releases/2026/01/27/79-of-it-pros-feel-ill-equipped-to-prevent-attacks-via-nhi-csa-oasis-survey-finds
- SANS 2026 ITDR report: https://www.sans.org/research/identity-threat-detection-response-report
- Sophos State of Identity Security 2026: https://itdaily.com/news/security/71-percent-organizations-victims-identity-theft-breaches-2025/
- IDSA 2025 trends: https://www.bravurasecurity.com/blog/2025-idsa-identity-security-trends-report
- SailPoint and Dimensional Research, AI agents: https://www.hpcwire.com/aiwire/2025/06/04/sailpoint-research-reveals-ai-agents-as-enterprise-security-blind-spot/
- Okta AI at Work 2025: https://www.okta.com/newsroom/articles/ai-at-work-2025--securing-the-ai-powered-workforce/
- ConductorOne 2025 survey: https://www.conductorone.com/news/press-release/survey-security-leaders-go-all-in-on-ai-agents-to-address-surging-identity-attacks
- Entro, NHI ratio: https://www.scworld.com/news/nhis-outpace-human-accounts-by-1441
- Veza State of Access `[snippet]`: https://www.sdxcentral.com/press-releases/industry-first-report-from-veza-showcases-the-challenge-of-managing-access-permissions-for-identity-and-security-teams/
- FIDO Alliance, passkey deployment: https://fidoalliance.org/new-fido-alliance-research-shows-87-percent-us-uk-workforces-are-deploying-passkeys-for-employee-sign-ins/
- ISACA State of Cybersecurity 2025: https://mms.businesswire.com/media/20250929794833/en/2592986/1/ISACA_StateofCyber_2025_Infographic_FINAL.pdf
- KuppingerCole, IAM workforce demand: https://www.kuppingercole.com/blog/guest/the-most-wanted-professionals-in-iam-germanys-identity-workforce-demand-through-data
- KuppingerCole, IGA Leadership Compass 2026: https://www.kuppingercole.com/research/lc80864/identity-governance-and-administration-iga
- Gartner 2026 Predicts IAM (abstract): https://www.gartner.com/en/documents/7358330
- Gartner IAM Summit 2026 recap: https://dev.to/gitguardian/gartner-iam-summit-2026-identity-expanded-faster-than-most-programs-did-2m8f
- Identiverse 2025: https://www.techtarget.com/cybersecurity/opinion/Top-identity-security-themes-at-Identiverse-2025
- Identiverse 2026 (Forrester): https://www.forrester.com/blogs/identiverse-2026-recap-identity-security-for-agentic-ai-dominates/
- CIAOPS, Entra P2 access reviews: https://blog.ciaops.com/2025/09/27/microsoft-entra-id-p2-access-reviews-a-critical-evaluation-for-smb-customers-in-australia/
- Directions on Microsoft: https://www.directionsonmicrosoft.com/reports/microsoft-entra-the-collected-services/
- Vendor sources:
  - Veza docs: https://docs.veza.com/4yItIzMvkpAvMVFAamTf/features/access-reviews/how-to/completeness-accuracy-procedures
  - SafePaaS: https://www.safepaas.com/access-control/automating-user-access-reviews-for-sox-compliance/
  - Zluri: https://www.zluri.com/eye-on-identity/rbac-role-explosion-hybrid-access-control
  - NHIMG: https://nhimg.org/articles/role-design-for-least-privilege-is-breaking-at-enterprise-scale/
  - Netwrix: https://netwrix.com/en/resources/blog/oracle-identity-governance-alternatives/
  - Xalient: https://xalient.com/sailpoint-identityiq-to-identity-security-cloud-migration-case-study
  - Atricore: https://www.atricore.com/blog/why-iga-projects-stall
  - Radiant Logic: https://www.radiantlogic.com/blog/gartners-2026-iam-predictions-identity-visibility-is-no-longer-optional/

**Job postings**
- Dice: https://www.dice.com/job-detail/ac71c638-5b4d-4c34-99d7-2e21165c322b
- Insight Global: https://jobs.insightglobal.com/find_a_job/virginia/job-489947
- EY: https://careers.ey.com/ey/job/caba-iam-engineer-sailpoint-isc-senior-ey-gds-b-1001/1433535833/

**Breaches and advisories**
- Okta support system root cause: https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/
- Cloudflare: https://blog.cloudflare.com/thanksgiving-2023-security-incident
- Microsoft and Midnight Blizzard: https://www.bleepingcomputer.com/news/security/microsoft-reveals-how-hackers-breached-its-exchange-online-accounts/amp/
- Change Healthcare: https://www.techtarget.com/cybersecurity/news/366582824/Change-Healthcare-breached-via-Citrix-portal-with-no-MFA
- Snowflake customers: https://www.darkreading.com/cloud-security/snowflake-cloud-accounts-rampant-credential-issues, https://thehackernews.com/2024/06/snowflake-breach-exposes-165-customers.html
- US Treasury via BeyondTrust: https://www.techtarget.com/cybersecurity/news/366617509/Treasury-Department-breached-through-BeyondTrust-service
- Coinbase: https://www.theregister.com/2025/05/21/coinbase_confirms_insider_breach_affects/
- tj-actions: https://thehackernews.com/2025/03/cisa-warns-of-active-exploitation-in.html
- Oracle Cloud `[unverified, denied by Oracle]`: https://www.csoonline.com/article/3852643/oracle-cloud-breach-may-impact-140000-enterprise-customers.html
- M&S: https://www.computing.co.uk/news/2025/security/m-s-ends-contract-with-tcs
- Co-op: https://www.bleepingcomputer.com/news/security/co-op-confirms-data-of-65-million-members-stolen-in-cyberattack/
- Columbia University (root cause undisclosed): https://www.bleepingcomputer.com/news/security/columbia-university-data-breach-impacts-nearly-870-000-students-applicants-employees/
- UNC6040 vishing: https://www.bleepingcomputer.com/news/security/google-hackers-target-salesforce-accounts-in-data-extortion-attacks/amp/
- Salesloft Drift: https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift
- Nx: https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/
- Shai-Hulud (CISA): https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
- Gainsight: https://astrix.security/learn/blog/salesforce-advisor-gainsight-breach/
- Vercel via Context.ai: https://specterops.io/blog/2026/04/21/the-vercel-breach-explains-why-identity-attack-path-management-cant-wait/
- Klue: https://www.huntress.com/blog/klue-breach-investigation
- CSA note on ShinyHunters: https://labs.cloudsecurityalliance.org/research/csa-research-note-shinyhunters-oauth-saas-abuse-20260716-csa/
- GitHub MCP: https://invariantlabs.ai/blog/mcp-github-vulnerability
- Replit: https://www.eweek.com/news/replit-ai-coding-assistant-failure/
- Amazon Q: https://aws.amazon.com/security/security-bulletins/rss/aws-2025-015
- MCP Python SDK flaw: https://thehackernews.com/2026/09/official-mcp-python-sdk-flaw-can-let.html
- CISA AA23-320A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
- ASD/ACSC Scattered Spider: https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/scattered-spider

**Standards**
- OWASP NHI Top 10 2025: https://owasp.org/www-project-non-human-identities-top-10/2025/top-10-2025/
- OWASP Top 10 for Agentic Applications 2026: https://www.giskard.ai/knowledge/owasp-top-10-for-agentic-application-2026
- MCP authorization 2025-11-25: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- GitGuardian State of Secrets Sprawl 2025: https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/
- GitGuardian State of Secrets Sprawl 2026: https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html
