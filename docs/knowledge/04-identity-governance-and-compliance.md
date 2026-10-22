# 04 — Identity Governance & Administration (IGA) and Compliance

*Tessera knowledge base · Domain research · Last researched: 2026-10-08*
*Conventions: [unverified] means I could not confirm the claim against a primary or authoritative source during research. Vendor claims are vendor-reported unless stated otherwise.*

---

## 1. Scope and why it matters

Identity Governance and Administration (IGA) is the part of IAM that answers three questions: **who has access to what, how did they get it, and should they still have it?** Access management (SSO, MFA, federation) decides whether an authentication or session request succeeds *right now*. IGA governs the **standing state of entitlements** across every system over time, and it produces the **evidence** that auditors and regulators test.

Why it matters for Tessera:

- **IGA is where compliance budget is spent.** SOX ITGCs, SOC 2, ISO 27001, PCI DSS, HIPAA, NIS2, DORA and FedRAMP all ask for the same core things: authorized provisioning, timely deprovisioning, periodic access review, least privilege, separation of duties and control of privileged access. A platform that produces those artifacts automatically and in a form auditors trust replaces spreadsheets, tickets and screenshots.
- **The market is moving from campaigns to continuous governance.** Gartner's 2026 *Market Guide for IGA* (published 28 Aug 2026) describes IGA moving from quarterly manual review cycles toward autonomous, continuous, outcome-driven governance. It also points to convergence with PAM, CIEM and ISPM and to the growth in non-human and AI-agent identities (summary via vendor reprints; the full report is paywalled). Gartner has published Market Guides rather than a Magic Quadrant for IGA since the last IGA MQ in 2019 [the exact retirement year is unverified; the last MQ I could find is 2019].
- **Access-as-code is a natural fit.** Policies, roles, SoD rules, birthright rules and review policies are declarative and can be versioned. A Git history of those definitions is itself strong change-management evidence.
- **The hard problems are data problems.** Examples: correlating accounts to people, the completeness and accuracy of entitlement listings, entitlement metadata, and ownership. A newcomer can beat incumbents here with a better data model and better connectors.

Out of scope here (covered in other KB files): authentication protocols, PAM session brokering, CIEM internals and customer identity (CIAM).

---

## 2. Core concepts (precise definitions)

**Identity (governed identity).** The canonical record of a person or non-human actor that the organization is accountable for, keyed by a stable, immutable identifier (not email). It carries attributes such as employment status, department, cost center, manager, location, worker type and start/end dates. One identity can own many accounts.

**Account.** A credentialed principal in a specific target system (an AD user, an AWS IAM user, a Snowflake user, a Salesforce user). Accounts are *correlated* to identities. Accounts that cannot be correlated are *uncorrelated* or *orphan* accounts.

**Entitlement.** The smallest unit of access that is governed: a group membership, role assignment, permission set, database grant or SaaS license tier. Entitlements live on accounts. IGA tools *aggregate* them into an **entitlement catalog** that holds metadata: owner, description, risk, sensitivity, requestable flag and certifiable flag.

**Authoritative source (source of truth).** The system whose attribute values win in a conflict, usually the HRIS (Workday, SAP SuccessFactors, BambooHR, Oracle HCM, UKG). It is the system of record for the employment lifecycle. Contractors often come from a VMS (SAP Fieldglass, Beeline) or a manually managed "non-employee" register. Per-attribute authority is common: HR owns title and manager, while IT owns email.

**Joiner / Mover / Leaver (JML).** Lifecycle events derived from changes in the authoritative source:
- *Joiner:* create the identity, provision birthright access before or on day one.
- *Mover:* an attribute change (department, manager, location, job code). Grant the new birthright access, and **remove or recertify access tied to the old role**. Skipping this step causes privilege creep.
- *Leaver:* disable and deprovision promptly. Rehire and conversion (contractor to employee) cases must re-link to the original identity.

**Identity correlation / matching.** Linking accounts to identities by rules (exact employee ID, then email, then fuzzy name match with manual confirmation). Correlation quality determines the accuracy of everything downstream.

**Account aggregation.** Periodically reading accounts and entitlements from targets (full and delta) to build the "actual" state. Then comes **reconciliation**: comparing *actual* with *expected* (policy, approved requests) and acting on drift, by revoking, re-provisioning or flagging.

**Orphan account.** An account with no active owning identity (owner left, or never correlated). **Dormant account.** An account that has not authenticated or been used within a threshold (PCI DSS: 90 days). **Shared / generic account.** An account used by several people. Most frameworks discourage it or require exception handling.

**Provisioning / deprovisioning.** Creating, modifying or removing accounts and entitlements in targets, by these methods:
- *Direct connectors*: API, LDAP, JDBC, SCIM 2.0 (RFC 7643 schema, RFC 7644 protocol).
- *Indirect*: via an IdP or directory group that the app consumes.
- *Ticket-based / manual fulfillment*: open a ServiceNow or Jira ticket for a human, then **verify closure by re-aggregation**. Closing the ticket is not proof the change happened.

**Birthright access.** Access granted automatically from attributes (all employees get email; all engineers in team X get GitHub org Y). It is usually implemented as attribute-based rules or business roles.

**Access request.** A self-service or on-behalf request for catalog items, routed through an **approval policy** (manager, then entitlement owner, then security for high-risk items). It can be *time-bound* or *just-in-time (JIT)*. **Delegation** means an approver temporarily assigns their approval or review authority to another person. It must be logged, and it must not be possible to delegate to the requester.

**Access certification (access review, recertification, attestation).** A reviewer (manager, entitlement or app owner, data owner) affirms or revokes each access item.
- *Campaign types:* manager/user-centric, application- or entitlement-owner-centric, role-composition (are the role's contents right?), role-membership, privileged access, SoD-violation review, and targeted or ad hoc reviews.
- *Micro-certification / event-based review:* a small review triggered by an event (mover, new high-risk grant, anomaly, SoD violation) rather than a calendar.
- *Continuous certification:* micro-certifications plus policy-driven auto-decisions in place of periodic bulk campaigns.

**Rubber-stamping.** Approving review items without a meaningful decision ("approve all"). It is the central weakness of certification. It is driven by **reviewer fatigue** (too many items, too little context). An IDPro BoK article (Gupta, 2025) and practitioner literature recommend risk-based prioritization and automation to counter it.

**Role.** A named bundle of entitlements.
- *Business role:* defined by job function and assigned from attributes or membership, for example "AP Clerk – US".
- *Technical / IT role:* an app-level bundle, for example "SAP F_BKPF_BUK display + FB03".
- In the common *two-tier model*, business roles contain technical roles.
- **Role mining** is bottom-up clustering of existing assignments to propose roles. **Role engineering** is top-down definition from processes and functions plus mining.
- **Role explosion** is the growth of roles to near the number of users, which defeats the purpose. Attribute-based rules (ABAC-style birthright) and parameterized roles counter it.

**Separation (segregation) of duties (SoD).** A control that prevents one person from holding conflicting capabilities: create vendor + pay vendor; create user + approve user; develop + deploy to production.
- A **SoD rule** names two or more *functions*. Each function maps to the specific entitlements, transactions or permissions that realize it.
- A **toxic combination** is a set of entitlements that together violate a rule.
- SoD can be *preventive* (checked at request time) or *detective* (scanned after the fact).
- A **mitigating (compensating) control** is a documented control that reduces residual risk when a violation is accepted, for example a monthly review of payments by a second person. It has an owner, an expiry and evidence.
- ERP SoD needs **fine-grained** analysis down to SAP transaction codes, authorization objects and field values, or Oracle EBS/Fusion functions and privileges.

**Least privilege.** Grant only the access needed for the task, for the time needed. In governance terms this becomes *right-sizing*: removing unused or excessive entitlements.

**Privileged access.** Access that can change system configuration, security controls or other users' access, or bulk-read sensitive data. Every framework treats it separately and more strictly.

**Peer group analysis / outlier detection.** Comparing an identity's entitlements with peers who share attributes (department, title, manager). Access held by few peers is flagged as an outlier and used to drive review recommendations.

**Information Produced by the Entity (IPE).** Auditor term for system-generated reports (user listings, termination lists, review populations) that the auditor relies on. Under PCAOB AS 1105.10 the auditor must test IPE completeness and accuracy, or test the controls over them. For IGA, this means **the review population itself must be provably complete**.

---

## 3. Standards, frameworks and regulations

### 3.1 Status summary (as of 2026-10-08)

| Framework | Body | Version / status | Notes |
|---|---|---|---|
| SOX §404 ITGCs | US SEC / PCAOB (AS 2201, AS 1105); COSO 2013 | In force | No prescribed IAM rules. Auditors test *management's* ITGCs over financially relevant systems: access provisioning, termination, periodic review, privileged access. |
| SOC 2 | AICPA | 2017 Trust Services Criteria with revised points of focus (2022) | CC6.1–CC6.3 are core for IAM; CC6.6–6.8 are adjacent. |
| ISO/IEC 27001:2022 (+Amd 1:2024) | ISO/IEC JTC 1/SC 27 | Current; 2013 transition ended Oct 2025 | Annex A 5.15–5.18, 8.2, 8.3, 8.5. Guidance in ISO/IEC 27002:2022. |
| PCI DSS | PCI SSC | **v4.0.1 is current** (published June 2024). Future-dated requirements mandatory since 31 Mar 2025. RFC on v4.0.1 for the next revision ran 3 Jun–20 Jul 2026; no successor published. | Requirements 7 and 8. |
| HIPAA Security Rule | HHS OCR | Current rule (45 CFR 164 Subpart C) in force. **NPRM of 6 Jan 2025 not finalized.** OMB agenda moved it to "long-term actions"; final rule now projected July 2027 at earliest. | Proposed: MFA required, addressable/required distinction removed, termination of access ≤1 hour. |
| GDPR | EU | In force since 2018 | Principles-based (Art. 5(1)(f), 25, 32). No explicit review frequency. |
| NIST SP 800-53 | NIST | Rev. 5, **Release 5.2.0 (27 Aug 2025)** | 5.2.0 changed SA/SI (software update integrity), not AC/IA. Baselines (800-53B) unchanged. |
| NIS2 | EU Directive 2022/2555 + Commission Implementing Regulation (EU) 2024/2690 | Directive applies via national transposition (deadline 17 Oct 2024; transposition uneven). CIR 2024/2690 applies directly to digital-infrastructure / ICT service entities. | Art. 21(2)(i),(j); CIR Annex §11 "Access control". |
| DORA | EU Regulation 2022/2554 + Delegated Reg. (EU) 2024/1774 (RTS on ICT risk management) | Applicable since 17 Jan 2025 | RTS Art. 20 (identity management) and Art. 21 (access control); Art. 33 for the simplified framework. |
| FedRAMP | GSA FedRAMP PMO | Rev5 baselines still active. **FedRAMP 20x** made a generally available path via Consolidated Rules 2026 (finalized 25 Jun 2026). Rules mandatory 1 Jan 2027; new Rev5 applications stop 11 Jun 2027 (per secondary sources) [dates unverified against fedramp.gov]. | KSIs include an Identity & Access Management domain, with machine-readable, continuous evidence. |

### 3.2 Control-mapping table (what each framework actually requires of IAM)

| Capability | SOX ITGC (typical tested control) | SOC 2 | ISO 27001:2022 Annex A | PCI DSS v4.0.1 | HIPAA (current; NPRM in brackets) | NIST 800-53 r5 | NIS2 CIR 2024/2690 | DORA RTS 2024/1774 |
|---|---|---|---|---|---|---|---|---|
| Unique identity / no shared IDs | Implied (accountability) | CC6.1 | 5.16 Identity management | 8.2.1 unique ID; 8.2.2 shared/generic only by exception, with individual attribution | 164.312(a)(2)(i) unique user ID (required) | IA-2, IA-4, AC-2 | §11.5 identification | Art. 20: unique identity, one-to-one mapping of persons (incl. third-party staff) to accounts |
| Authorized provisioning | New access approved by an appropriate person before grant; sampled | CC6.2 (register and authorize before credentials), CC6.3 | 5.15 access control policy; 5.18 access rights (authorized provisioning) | 7.2.1–7.2.3 (model, job function, approved by authorized personnel); 8.2.4 adds/changes authorized | 164.308(a)(4) information access management; (a)(3) workforce security | AC-2(a–e), AC-2(1) automated mgmt, AC-6 | §11.2 management of access rights | Art. 21: need-to-know, need-to-use, least privilege |
| Timely deprovisioning (leavers) | Terminated users removed timely (often tested against an HR term list; "timely" defined by the company, commonly 1–5 business days) | CC6.2, CC6.3 | 5.18; 5.16 (removal when no longer needed); 6.5 | 8.2.5 terminated users' access **immediately** revoked | 164.308(a)(3)(ii)(C) termination procedures (addressable) [NPRM: ≤1 hour; notify other CE/BA ≤24 h] | AC-2(h), PS-4, PS-5, AC-2(3) | §11.2 | Art. 21: withdraw without undue delay |
| Movers / transfers | Transfer access modified; often a deficiency | CC6.3 | 5.18 (adjust on change) | 7.2.4 catches drift | 164.308(a)(4)(ii)(C) access modification | PS-5, AC-2 | §11.2 | Art. 20 lifecycle; Art. 21 |
| Periodic access review | User access recertification for in-scope apps/DB/OS (commonly quarterly for financial apps and privileged access, semi-annual or annual otherwise; set by the company) | CC6.2/CC6.3 (no frequency set) | 5.18 review at planned intervals (frequency not prescribed) | **7.2.4 all user accounts incl. third-party at least every 6 months**, management acknowledges; 7.2.5.1 system/app accounts per targeted risk analysis | 164.308(a)(4) implies; no explicit frequency | AC-2(j) review at org-defined frequency; AC-6(7) review of privileges | §11.2 regular review | **≥ annual; ≥ every 6 months for ICT supporting critical or important functions** (per secondary summaries of Art. 21) |
| Dormant accounts | Often a supplementary control | CC6.2 | 5.18 | **8.2.6 disable/remove after 90 days inactivity** | — | AC-2(3) disable after org-defined inactivity | — | — |
| Privileged access | Admin access restricted, approved and reviewed (often quarterly); activity monitoring | CC6.1, CC6.3 | **8.2 privileged access rights** (restrict, re-auth, time-bound, log); 8.5 secure authentication | 7.2.2 least privilege; 8.4.1/8.4.2 MFA for CDE access; 8.6.1–8.6.3 system accounts | 164.312(d) authentication [NPRM: MFA required] | AC-2(7), AC-6(1),(2),(5),(9),(10), IA-2(1),(2) | §11.3 privileged / sysadmin accounts; §11.7 MFA | Art. 21 strong authentication for privileged, remote and critical access |
| SoD | Conflicting access in ERP/financial apps prevented or detected; mitigating controls | CC5.1 (control activities), CC6.3 | 5.3 segregation of duties | Implicit in 7.2 | — | **AC-5** separation of duties | §11 (role-based rights) | Art. 21 (segregation implied) |
| Logging of access changes | Change evidence | CC6.x, CC7.2 | 5.18 (changes logged), 8.15 | 10.2.1.x logs incl. 10.2.1.5 changes to IDs/credentials | 164.312(b) audit controls | AU-2, AU-12, AC-2(4) | §12 logging | Art. 20 records retained |
| Third-party / non-employee | In scope | CC6.2 "external users" | 5.18 temporary rights revoked when work ends | 7.2.4 includes vendor accounts; 8.2.7 vendor remote access enabled only when needed | Business associates | AC-2, PS-7 | §11 | Art. 20 incl. ICT third-party staff |

Primary links: AICPA TSC (aicpa-cima.com), ISO/IEC 27001:2022 (iso.org/standard/27001), PCI DSS document library (pcisecuritystandards.org), HIPAA 45 CFR 164.308/164.312 (ecfr.gov) and the NPRM (federalregister.gov, 90 FR 898, 6 Jan 2025), NIST SP 800-53 r5 (csrc.nist.gov), CIR 2024/2690 and Delegated Reg. 2024/1774 (eur-lex.europa.eu), FedRAMP (fedramp.gov). See §10.

### 3.3 Framework notes that matter for product design

- **SOX does not prescribe a review frequency or method.** The company defines its control. The external auditor tests whether it is designed and operating effectively. PCAOB inspection findings repeatedly cite failure to test the **completeness and accuracy of the user listing (IPE)** used for access reviews. Common deficiencies are reviews that cannot be evidenced and populations pulled *after* clean-up. Review precision matters: reviews at the individual access level rather than a summary sign-off, reasons recorded for revocations, and no self-review.
- **SOC 2 sets no frequency.** Auditors sample authorization records, termination timeliness and review sign-offs over the 3–12-month Type II window.
- **ISO 27001:2022 5.18** turned several 2013 controls (9.2.x) into a managed-lifecycle control, adding temporary rights for non-staff and logging of changes. One commentator notes that the explicit "review privileged rights more frequently" language from 2013 9.2.5 is no longer in 5.18; privileged rights move to 8.2 [unverified against the paywalled 27002 text].
- **PCI DSS v4.0.1** is the most prescriptive: a 6-month review (7.2.4), 90-day dormancy (8.2.6), immediate termination (8.2.5), MFA for all CDE access (8.4.2), and periodic review of application and system accounts based on a targeted risk analysis (7.2.5.1). Assessors expect evidence of the review itself: listings, sign-off, removals.
- **HIPAA (2025 NPRM)**, if finalized as proposed, would make technical IAM controls far more prescriptive for healthcare: MFA, encryption, access termination within one hour, 24-hour notice to other regulated entities, and an asset inventory. Not binding as of Oct 2026. The CHIME-led coalition has asked HHS to withdraw it.
- **NIS2 CIR 2024/2690 §11** groups access-control policy, rights management, privileged accounts, sysadmin systems, identification, authentication and MFA. Regulators stress demonstrable effectiveness ("who has access, for how long, and can you prove it"). Germany's BSIG §30 transposition points to IT-Grundschutz ORP.4.
- **DORA RTS Art. 21** is notable for a **six-month review for systems supporting critical or important functions** and annual for others (per Springlex summaries; confirm against EUR-Lex). Art. 20 requires retaining identity-assignment records after reorganization or contract end, and expects automated lifecycle tooling where appropriate.
- **FedRAMP 20x** moves assessment from narratives to **Key Security Indicators**, which are machine-validated and continuously evidenced, aligned to OSCAL. KSI counts differ by source (56 Low / 61 Moderate vs. "46") [unverified]. This is a strong signal that *evidence-as-data* is where compliance is heading.

---

## 4. How it works (lifecycle and workflow diagrams)

### 4.1 Identity lifecycle (JML) driven by the authoritative source

```
 HRIS (Workday / SuccessFactors / BambooHR)      VMS / contractor register
          │  hire, change, term (webhook, report, or delta API)   │
          ▼                                                       ▼
   ┌──────────────── Identity Warehouse (Tessera) ─────────────────┐
   │ 1. Ingest + normalize attributes (per-attribute authority)    │
   │ 2. Match/merge identity (employee ID → email → fuzzy + manual)│
   │ 3. Detect lifecycle event: JOINER / MOVER / LEAVER / REHIRE   │
   └──────────────┬──────────────────────────────┬─────────────────┘
                  │                              │
          Policy evaluation              Account aggregation (targets)
   (birthright rules, roles, SoD)        AD, Entra, Okta, AWS, GCP, Azure,
                  │                      Snowflake, Databricks, GitHub, SaaS
                  ▼                              │
        Expected state  ◄──── Reconciliation ────┘ Actual state
                  │           (diff: missing / excess / orphan / dormant)
                  ▼
   Fulfillment: SCIM/API connector ─► verify by re-aggregation
                Ticket (ServiceNow/Jira) ─► human ─► verify by re-aggregation
                  │
                  ▼
   Evidence log (immutable): event, policy version, approver, time-to-fulfill
```

Key timing semantics:
- **Joiner:** pre-hire provisioning (start-date-aware), with access activated on day one.
- **Mover:** grant new access immediately. Remove old birthright access after a configurable grace period, *or* trigger a micro-certification of retained access to the new manager.
- **Leaver:** disable immediately on the termination timestamp (or scheduled). Revoke sessions and tokens. Deprovision or archive accounts later per data-retention needs. Transfer ownership of owned resources. Also handle the "no-HR-signal" case, for example contractor end dates.

### 4.2 Access request and approval

```
Requester ──► Catalog (requestable entitlements/roles, with descriptions & risk)
    │
    ├─► Pre-checks: SoD simulation, eligibility policy, duplicate/implicit access
    ▼
Approval routing (policy-as-code):
    low risk  → manager (or auto-approve if birthright-eligible)
    medium    → manager → resource owner
    high/priv → manager → owner → security; time-bound (JIT) by default
    SoD hit   → risk owner accepts + selects mitigating control (with expiry)
    │  (delegation, escalation on SLA breach, no self-approval)
    ▼
Fulfillment ─► verification ─► scheduled expiry / auto-revoke ─► evidence
```

### 4.3 Certification campaign vs. continuous review

```
Scheduled campaign (quarterly/semiannual)          Continuous / event-based
──────────────────────────────────────────         ──────────────────────────────
1. Freeze population snapshot (IPE)                Triggers: mover, new high-risk grant,
   + completeness evidence (counts reconcile       SoD violation, peer outlier, dormancy,
   to source, extraction timestamp, query hash)    owner change, policy change
2. Generate items + context (usage, peer           → micro-certification to the right
   coverage, risk, how granted)                       reviewer with context
3. Route to reviewers; reminders; escalation       Policy auto-decisions (documented
4. Decisions: certify / revoke / reassign /           rules, versioned) for defined
   (comment required for high-risk certify)           low-risk classes
5. Remediation → verify removal by re-aggregation  Periodic "backstop" campaign still run
6. Close: signed report, exceptions, metrics          for in-scope SOX/PCI systems
```

### 4.4 SoD rule design

```
Risk (e.g., "P2P-01 Create vendor & post payment")
   ├─ Function A: Maintain vendor master  → SAP: XK01/XK02/FK01 + F_LFA1_BUK(ACTVT=01,02)
   │                                         Oracle: "Manage Suppliers" privilege
   └─ Function B: Process payments        → SAP: F110/FB10 + F_REGU_BUK
Rule = A ∧ B for the same identity (across accounts/systems via correlation)
Evaluation: preventive (at request) + detective (after aggregation)
Outcome: remediate | accept with mitigating control (owner, test frequency, expiry)
```

Cross-system SoD (for example a cloud-console admin who also approves changes in ServiceNow) depends on identity correlation across accounts. A per-app SoD engine cannot detect it.

### 4.5 IGA maturity model (synthesized)

There is no single standard IGA maturity model; Gartner, KuppingerCole, IDPro BoK articles and vendors (e.g., ConductorOne's "UAR maturity curve", SailPoint's identity maturity assessments) publish variants. A consensus synthesis:

| Level | Name | Characteristics | Typical evidence quality |
|---|---|---|---|
| 0 | Ad hoc | Spreadsheet reviews, email approvals, manual offboarding checklists | Screenshots; frequent findings |
| 1 | Managed (tool-assisted) | Central catalog for key apps, ticketed provisioning, scheduled campaigns for SOX/PCI apps | Exported reports; IPE often weak |
| 2 | Automated lifecycle | HRIS-driven JML, connectors for most critical apps, birthright rules, reconciliation | System logs; timely termination provable |
| 3 | Risk-based governance | Entitlement metadata + risk, SoD preventive checks, micro-certifications, peer analytics, NHI ownership | Item-level context; fewer, sharper reviews |
| 4 | Continuous / autonomous | Policy-as-code, JIT by default, zero standing privilege for admins, auto-remediation with human gates, continuous control monitoring | Machine-readable, continuously generated evidence (FedRAMP 20x-style) |

Tessera's opportunity is to let customers jump from level 1 to 3–4 for cloud/data infrastructure without a multi-year programme.

---

## 5. How the market implements it

| Vendor | Positioning (2026) | Notable implementation details / differences |
|---|---|---|
| **SailPoint** (NASDAQ: SAIL, re-IPO'd Feb 2025) | Category incumbent. Identity Security Cloud and IdentityIQ (on-prem). FY26 (ended 31 Jan 2026): total ARR $1.125B (+28%), SaaS ARR $746M. | Deep connector library, roles, SoD, AI recommendations (peer-group "AI-Driven Identity Security"), Access Modeling (role mining). In 2025 shipped Agent Identity Security (AI agents governed to entitlement level). At Navigate 2026 (6 Oct 2026) also announced IdentityIQ 9.0 (on-prem/hybrid, time-based role and entitlement access, automated upgrade tool; [press release](https://www.sailpoint.com/press-releases/sailpoint-announces-modernization-capabilities-for-both-cloud-and-on-premises-identity-security)) and announced Autonomous Agents and Autonomous ISPM on its "Atlas" platform, plus "Human Fabric" and "Agentic Fabric" packaging [packaging details partly unverified]. Heavy implementation effort; partner-led. |
| **Saviynt** | Converged cloud IGA + PAM + application access ("Identity Cloud"). $700M round led by KKR at ~$3B valuation (Dec 2025). | Strong in ERP/application GRC (SAP, Oracle, Workday SoD), CIEM-style cloud entitlements and converged PAM. Uses "micro-certification" heavily. Targets SailPoint and Oracle Identity Manager replacements. |
| **Okta Identity Governance (OIG)** | Governance native to the Okta Workforce Identity Cloud. Representative vendor (full-suite) in the 2026 Gartner Market Guide. | 2026 features: Governance Analyzer (AI recommendations, GA in preview orgs per 2026.06 release notes), Smart Review (grouped review to reduce fatigue), assignment-method visibility in campaigns, resource owner as reviewer, additive time-bound entitlements, Slack campaign notifications (beta Feb 2026). Acquired Axiom Security (PAM/JIT for databases and Kubernetes, 2025). Strongest when Okta is already the IdP; thinner for deep ERP SoD. |
| **Microsoft Entra ID Governance** | Bundled with the Entra ecosystem (ID Governance SKU / Entra Suite). | Access reviews with ML recommendations (user-to-group affiliation and inactivity sign-ins; limits on large groups), entitlement management (access packages, connected orgs for B2B), Lifecycle Workflows (joiner/mover/leaver and inactive-user triggers), PIM for JIT roles. Inactivity detection up to 2 years. An "Access Review Agent" (Security Copilot / Teams) has been reported [availability unverified]. Cheap and good enough for Microsoft-centric estates; weak beyond Entra-connected apps without custom connectors. |
| **Omada** | European full-suite IGA (Omada Identity Cloud). Owned by GRO Fund III and Kirk Kapital since 2025. | Strong process framework ("IdentityPROCESS+"), EU regulatory focus (NIS2/DORA). Launched Omada Agent Governance (Jun 2026) and acquired **EmpowerID** (24 Sep 2026) for runtime agent authorization. |
| **One Identity** (Quest; separation announced Jun 2026) | One Identity Manager (on-prem/hybrid), plus Safeguard PAM and Active Roles. | v10.0 (Jan 2026): natural-language reporting via customer-controlled LLM, risk-based governance, ITDR, CEF Syslog. Strong for complex AD/SAP estates. Spin-out from Quest to an independent Cork-HQ company announced 24 Jun 2026 [completion unverified]. |
| **ConductorOne** (now **C1.ai**) | Cloud-native, developer-friendly IGA/access platform. $79M Series B (Oct 2025, Greycroft; CrowdStrike Falcon Fund). **Workday signed a definitive agreement to acquire it on 13 Oct 2026**; price undisclosed, close expected by 31 Jan 2027 ([Workday release](https://newsroom.workday.com/2026-10-13-Workday-to-Acquire-C1-ai,-a-Leading-Agentic-Identity-Platform-for-People-and-Agents), [C1 post](https://www.c1.ai/blog/c1-ai-to-join-workday)). Open question: continuity for customers on non-Workday HR systems. Sept-Oct 2026 launches: credential vending and egress proxy, LLM gateway, AppHub. | Open-source "Baton" connector SDK, policy engine with ordered rules (auto-certify/auto-deny conditions), usage-aware reviews, JIT access via Slack, AI copilot that flags items. Closest to Tessera's access-as-code ethos. |
| **Lumos** | "Autonomous Identity Platform", mid-market to enterprise SaaS-heavy. ~$65M raised (Series B $35M, 2024). | AI agent "Albus" for reviews, JIT, JML, role mining (RBAC/ABAC policy generation from HRIS + IdP + usage), NHI discovery. Strong SaaS license/spend angle. Strong Performer in 2026 Gartner Voice of the Customer for IGA (self-reported). |
| Others to track | Pathlock (application access governance / SAP GRC alternative), Veza (authorization graph, data-system permissions; now "Veza from ServiceNow", [Oct 2026 blog](https://veza.com/blog/servicenows-next-frontier-comprehensive-identity-as-the-foundation-for-neocloud-governance/)), Astrix (Cisco announced intent to acquire, [4 May 2026](https://astrix.security/learn/blog/a-new-chapter-astrix-security-is-joining-cisco/)), Linx, Zluri, Opal, Indent, Pathlock/SAP IAG, IBM Verify Governance, Oracle. | SAP Access Control 12.0 mainstream maintenance ends **end-2027**, extended to **2030** (SAP Note 3326989). This creates a large ERP-SoD replacement wave (SAP Cloud IAG, Pathlock, Saviynt, SailPoint). |

**Patterns across the market**
1. **Breadth of connectors and data quality** still decide deals. The "long tail" of disconnected apps is handled by ticketed fulfillment plus flat-file or CSV aggregation.
2. **AI is now table stakes.** Peer-group recommendations exist in every major product. In 2026 the differentiation moved to *agents that act* (auto-remediation, AI-run campaigns) and to **governing AI agents as identities**.
3. **Convergence.** IGA is absorbing JIT/PAM-lite, CIEM and ISPM. Analysts call this "continuous governance".
4. **Developer-first entrants** (ConductorOne, Lumos, Opal, Veza) win on time-to-value and SaaS/cloud coverage. Incumbents win on ERP SoD, complex roles and regulated-enterprise audit pedigree.

---

## 6. Failure modes

### 6.1 Common audit findings (SOX/SOC 2/PCI/ISO)
1. **Untimely termination.** Leavers keep active accounts beyond the policy window, especially in apps not behind SSO, local DB accounts and SaaS with local passwords. Auditors find this by matching the HR termination list to last-login data.
2. **No or unauthorized provisioning approval.** Grants made directly in the target with no ticket or request, or approval dated *after* the grant.
3. **Incomplete review population (IPE failure).** The listing excludes service accounts, local accounts or one environment. It was extracted after clean-up. There is no evidence of how it was generated.
4. **Rubber-stamped reviews.** Items approved in seconds, 100% approval rate, managers certifying access they cannot interpret. Auditors increasingly ask for evidence that the review was precise enough to catch errors.
5. **Revocations not executed.** Reviewers revoked access, but nothing removed it, or a ticket was closed with no verification.
6. **Self-review / conflicted reviewer.** Admins certifying their own admin access.
7. **Privileged access not reviewed or overly broad.** Shared admin accounts, standing cloud admin roles, break-glass accounts with no monitoring.
8. **Movers accumulating access (privilege creep).** No mover process, so transfers keep prior department entitlements.
9. **Orphan and dormant accounts.** Uncorrelated accounts, contractors with no end date, 90-day dormancy violations (PCI 8.2.6).
10. **SoD conflicts without mitigation**, or mitigating controls that are documented but never operated or tested.
11. **Non-human identities ignored.** Service accounts, API keys and integration users with no owner and no review. PCI 7.2.5/7.2.5.1 and 8.6.x now explicitly cover system accounts.

### 6.2 Why certifications fail
- **Volume without context.** Reviewers see cryptic entitlement names ("GRP_FIN_APP_RW_02") with no description, owner, usage or risk.
- **Wrong reviewer.** Managers cannot judge technical entitlements, and owners don't know the users. A two-stage review (manager, then owner) helps but doubles fatigue.
- **Calendar-driven, not risk-driven.** Low-risk items get as much attention as admin rights.
- **No closed loop.** Revocations are not verified, so the same access reappears next cycle.
- **Data quality.** Wrong managers in the HRIS route reviews to the wrong people.
- **Gaming.** Bulk "approve all" (some tools allow it), delegation to subordinates.

### 6.3 Orphaned access root causes
Correlation rule gaps (no employee ID in the target). Contractors outside the HRIS. Acquisitions (separate directories). Local accounts created by app admins outside the IGA. Name or email changes. Rehires creating duplicate identities. NHIs created by engineers in cloud consoles or IaC with no owner tag.

### 6.4 Programme-level failure modes
Role-engineering projects that take 18 months and deliver role explosion. "Big-bang" IGA deployments that never connect beyond a few apps. Treating IGA as an annual audit project rather than an operational control. Over-customized on-prem IGA (IdentityIQ, OIM) that cannot be upgraded.

---

## 7. Expert and authoritative sources

**Standards and regulators.** NIST CSRC (SP 800-53 r5, 800-53A, SP 1800-series practice guides), AICPA (TSC, SOC 2 guide), ISO/IEC 27001/27002, PCI SSC (document library, FAQs, *Information Supplement: Best Practices for Maintaining PCI DSS Compliance*), HHS OCR (Security Rule guidance; 2025 NPRM), PCAOB (AS 2201, AS 1105, staff inspection observations), ENISA (NIS2 technical implementation guidance for CIR 2024/2690), EBA/ESMA/EIOPA (DORA), FedRAMP PMO (20x KSIs).

**Communities and bodies of knowledge.**
- **IDPro** and its **Body of Knowledge** (bok.idpro.org), peer-reviewed. Relevant articles: Gupta, *Optimizing Access Recertifications* (2025); Glazer/Robinson/Hamlin, *User Provisioning in the Enterprise* (2022); Koot, *Strategic Alignment and Access Governance* (2022); Carter, *Techniques to Approach Least Privilege* (2022). IDPro also runs the **CIDPRO** certification.
- **Identity Defined Security Alliance (IDSA)** for identity-security best practices and research.
- **ISACA** (COBIT, ITGC audit programs, CISA body of knowledge) and **IIA** (GTAG on IAM) for the auditor's perspective.
- **OpenID Foundation** (Shared Signals/CAEP, which are relevant to event-driven deprovisioning) and IETF **SCIM** working group (RFC 7642–7644; SCIM events drafts).

**Analysts.** Gartner (2026 Market Guide for IGA, Archambault, Guthrie, Mezzera, Wessels; IGA Voice of the Customer; Hype Cycle for Digital Identity), KuppingerCole (Leadership Compass: IGA; regular blog coverage, for example of Omada–EmpowerID), Forrester (Wave/Landscape for IGA), Omdia.

**Practitioners and books.** Ian Glazer (IDPro co-founder; former Gartner IGA analyst; IGA strategy talks); André Koot (governance and role design); the SailPoint and Saviynt identity-research teams; SAP GRC practitioner community (SAP Community, Pathlock and Protiviti blogs) for ERP SoD. Books: Haber & Rolls, *Identity Attack Vectors* (Apress, 2nd ed. 2024); Coyne & Weil, "ABAC and RBAC: Scalable, Flexible, and Auditable Access Management" (IEEE IT Professional, 2013) on avoiding role explosion; NIST RBAC standard (ANSI/INCITS 359). [A dedicated, current IGA textbook of authoritative standing could not be identified — rely on IDPro BoK.]

**Vendor documentation worth mining for patterns.** SailPoint Compass community, Saviynt docs, Okta OIG release notes, Microsoft Learn (Entra ID Governance deployment guides), ConductorOne docs (policy engine, Baton SDK), Veza docs (completeness and accuracy procedures for UAR).

---

## 8. Implications for Tessera

### 8.1 Required capabilities

**Identity data foundation**
1. **MUST:** HRIS-driven identity warehouse with per-attribute authority, effective dating (future hires and terminations) and immutable identity IDs. First-class connectors for Workday, BambooHR and SuccessFactors, plus a generic CSV/SFTP source for long-tail HR and VMS feeds.
2. **MUST:** A deterministic, explainable correlation engine (rule tiers, manual confirm queue) with orphan, uncorrelated, dormant and shared-account detection. Dormancy thresholds are configurable per policy (PCI 90-day default).
3. **MUST:** Full and delta aggregation of accounts *and* entitlements, with usage/last-activity signals, from cloud (AWS/GCP/Azure IAM, Entra, Okta, Google Workspace) and data infrastructure (Snowflake, Databricks, BigQuery, Postgres/MySQL, Kubernetes, GitHub). This is Tessera's wedge.
4. **MUST:** Treat non-human identities (service accounts, keys, workload identities, AI agents) as governed identities with a **required human owner** and lifecycle (owner-leaver triggers reassignment).
5. **SHOULD:** Identity resolution across M&A directories, rehire and conversion handling, and preferred-name changes.

**Policy and lifecycle (access-as-code)**
6. **MUST:** Declarative, Git-versioned policy for birthright rules, roles, approval policies, SoD rules, review policies and dormancy policies. Every decision records the **policy version hash** it was evaluated under.
7. **MUST:** JML automation with mover handling (grant new, schedule removal or micro-certify old), leaver kill-switch (disable, session and token revocation in IdP and cloud, scheduled deprovision), and configurable SLAs with breach alerting.
8. **MUST:** Closed-loop fulfillment: SCIM 2.0 and native API connectors, plus ticketed fulfillment (ServiceNow/Jira) **with verification by re-aggregation** before an item is marked done.
9. **MUST:** Continuous reconciliation (expected vs. actual) with drift alerts and optional auto-revert of out-of-band grants.
10. **SHOULD:** Connector SDK (open, like Baton or SCIM-based) so customers and partners can build the long tail.

**Requests and JIT**
11. **MUST:** Access request catalog with risk-tiered approval routing, no self-approval, delegation with audit, escalation, and time-bound/JIT grants with automatic expiry. ChatOps surfaces (Slack/Teams) are expected.
12. **SHOULD:** Preventive SoD and policy simulation at request time ("what-if" impact before approval).

**Certifications**
13. **MUST:** Campaign engine (user/manager, resource-owner, privileged, role-membership, NHI-owner, SoD-violation) with **frozen, provably complete populations** (record counts reconciled to source, extraction timestamps, connector run IDs, hash of the population). Rich context per item: description, owner, usage, peer coverage, how granted, risk. Reasons required on high-risk certifications. Self-review blocked.
14. **MUST:** Closed-loop remediation of revocations with verified removal and evidence.
15. **MUST:** Event-based micro-certifications (mover, new privileged grant, dormancy, outlier, owner change).
16. **SHOULD:** Policy-driven auto-decisions for defined low-risk classes, with **reviewer-visible, auditor-exportable rule logic** and a sampled human QA of auto-decisions (see 8.2).
17. **SHOULD:** Reviewer-quality analytics: time per decision, approval rate per reviewer, bulk-approve detection, and alerts for rubber-stamping patterns.

**SoD, roles, analytics**
18. **SHOULD:** Cross-system SoD engine (function-to-entitlement mapping, toxic combinations, mitigating controls with owner, frequency, expiry and evidence). **COULD:** fine-grained SAP/Oracle rulesets. For ERP, integrate with Pathlock, SAP IAG or SAP GRC rather than build, at least initially.
19. **SHOULD:** Peer-group outlier detection and unused-access right-sizing recommendations, with explainable reasons (not opaque scores).
20. **COULD:** Role mining (clustering) that outputs *policy-as-code* proposals (ABAC birthright rules preferred over static roles, to avoid role explosion).
21. **COULD:** AI agents that run campaigns and draft remediation, always with a human approval gate and full audit logs.

**Evidence and compliance**
22. **MUST:** Immutable, append-only evidence ledger (who, what, when, why, policy version, source data snapshot). Exportable audit packages per framework (SOX, SOC 2, ISO 5.15–5.18/8.2, PCI 7/8, NIS2 §11, DORA Art. 20–21) in PDF/CSV, plus machine-readable output (JSON; **OSCAL** for FedRAMP 20x).
23. **MUST:** Control dashboards with framework-specific KPIs: termination SLA adherence, % accounts correlated, orphans, dormant >90d, review completion and revocation rates, privileged account counts, SoD violations open and mitigated.
24. **SHOULD:** Auditor read-only portal with sample-selection support and population reproducibility.
25. **COULD:** Continuous-control-monitoring APIs feeding GRC tools (AuditBoard, Vanta, Drata, ServiceNow IRM).

### 8.2 What evidence auditors accept, especially for exception-only or usage-based certification

**Generally accepted evidence (all frameworks):**
- *Provisioning:* the request record with an approver who is authorized per policy, a timestamp *before* the grant, and the fulfillment record. For automated birthright, the rule definition (versioned) plus evidence the rule was reviewed and approved (change management) and that the rule executed as designed. Auditors test a well-controlled automated control once (baseline) plus change management, rather than sampling every instance. This "test-of-one" approach for automated application controls is standard audit practice and is a major advantage of access-as-code.
- *Termination:* HR termination list (itself IPE, with completeness evidence) matched to disable or deprovision timestamps in each in-scope system.
- *Periodic review:* a complete population with generation evidence, reviewer identity and authority, item-level decisions with timestamps and reasons, and remediation evidence showing removal (re-aggregated state, not just a ticket).
- *Dormancy:* last-activity reports and the automated disable log.

**Exception-only / usage-based / auto-certified reviews: research findings**
- **No framework mandates human review of every item.** SOX, SOC 2 and ISO 27001 let the organization design the control. PCI 7.2.4 requires that "all user accounts and related access privileges" be reviewed every six months with management acknowledgement. That makes a pure exception-only design risky for PCI in-scope systems. DORA and NIS2 require "review" without defining the method.
- **I found no authoritative audit guidance (PCAOB, AICPA, PCI SSC, ISACA) explicitly endorsing exception-only or usage-only certification as a replacement for periodic review.** Practitioner and vendor sources support *risk-based scoping*: concentrating human review on privileged, financially significant and sensitive access, and reviewing low-risk access less often or with lighter mechanisms. Auditors accept documented, well-justified scope exclusions (for example read-only roles). Pure exception-based designs are treated with caution [synthesis of secondary sources; confirm with Big Four ITGC methodology, which is not public].
- **Conditions under which auto-decisions are most likely to be accepted** (practitioner consensus plus how automated controls are normally tested):
  1. Auto-certification logic is a **documented, versioned, approved policy** under change management (access-as-code helps).
  2. The rules are **tested by the auditor** (inputs, logic, outputs). The usage data feeding them is complete and accurate (IPE over activity logs, plus retention long enough to cover the lookback).
  3. Auto-decisions are limited to **low-risk classes**. Privileged, SoD-relevant, financially significant and PCI CDE access still gets human review.
  4. Auto-*revocation* of unused access (deny by default) is far easier to defend than auto-*certification* of used access. Usage shows that access is *exercised*, not that it is *appropriate*. Expect auditors to push back on "used = appropriate".
  5. A human still **signs off on the campaign as a whole** (management acknowledgement of the auto-decided set), and a **sample of auto-decisions gets human QA**.
  6. Get the **external auditor's agreement on the design in advance**. Practitioner sources consistently recommend this.
- **Product implication:** Tessera should implement auto-decisions as *auditable policy*, not hidden ML. It should store the inputs (usage window, last-activity source, peer coverage) per item. It should generate an "auto-decision evidence appendix" listing each auto-decided item, the rule and version, and the input values. It should support "human acknowledgement of the auto-decided population". Default posture: **auto-revoke unused, human-review the rest by risk tier, and never auto-certify privileged or SoD-relevant access**.

### 8.3 Data-model entities and key fields

| Entity | Key fields |
|---|---|
| `Identity` | id (immutable UUID), type (employee/contractor/NHI/agent/external), status, lifecycle_state, attributes{} with per-attribute source + effective_from/to, manager_id, owner_id (for NHI), employee_id, emails[], start_date, end_date, risk_score, created/updated |
| `AuthoritativeSource` | id, kind (HRIS/VMS/CSV), attribute_authority_map, sync_cursor, last_success_at, record_count |
| `System` (target) | id, name, type, environment, criticality, in_scope_frameworks[] (SOX/PCI/…), owner_id, connector_id, fulfillment_mode (direct/scim/ticket/manual) |
| `Account` | id, system_id, native_id, username, identity_id (nullable), correlation_rule/confidence, account_type (human/service/shared/break-glass), status, last_login_at, last_activity_at, created_at_source, privileged flag |
| `Entitlement` | id, system_id, native_ref, name, display_name, description, owner_id, risk_level, sensitivity/data_class, privileged flag, requestable, certifiable, sod_functions[], tags, framework_scope[] |
| `Grant` (account–entitlement assignment) | id, account_id, entitlement_id, granted_via (birthright rule/role/request/direct/out-of-band), source_ref (request_id/policy_id), granted_at, expires_at, last_used_at, state (expected/actual/drift) |
| `Role` | id, kind (business/technical), definition (static members or rule expression), entitlements[], owner_id, version |
| `Policy` | id, kind (birthright/approval/sod/review/dormancy/auto-decision), body (code), version, git_commit, approved_by, effective_at |
| `AccessRequest` | id, requester_id, beneficiary_id, items[], justification, duration, sod_check_result, status, approvals[] |
| `Approval` / `Decision` | id, subject (request item or review item), actor_id, delegated_from, decision, reason, timestamp, policy_version, auto (bool) + rule_id |
| `Campaign` | id, type, scope query, policy_version, population_snapshot_id, schedule, reviewers strategy, due_at, status, signoff (actor, timestamp) |
| `PopulationSnapshot` | id, campaign_id, extracted_at, connector_run_ids[], record_counts per system, reconciliation_to_source result, content_hash |
| `ReviewItem` | id, campaign_id, grant_id, reviewer_id, context{usage, peer_pct, how_granted, risk}, decision_id, remediation_id |
| `Remediation` / `FulfillmentTask` | id, action (grant/revoke/disable), mode (connector/ticket), ticket_ref, requested_at, completed_at, **verified_at + verification_run_id**, status |
| `SoDRule` / `SoDViolation` / `MitigatingControl` | rule: functions[], severity, owner. Violation: identity_id, grants[], detected_at, status. Control: description, owner, frequency, evidence_refs, expires_at |
| `LifecycleEvent` | id, identity_id, type (joiner/mover/leaver/rehire/conversion), source_change_ref, detected_at, sla_due_at, completed_at |
| `EvidenceRecord` | append-only, hash-chained: event type, refs, actor, timestamp, policy_version, payload digest; exportable per framework control ID |
| `ControlMapping` | framework, control_id (e.g., PCI 7.2.4, ISO A.5.18, SOC2 CC6.3, DORA RTS Art.21), Tessera evidence queries |

### 8.4 Build vs. integrate

| Area | Recommendation | Rationale |
|---|---|---|
| Identity warehouse, correlation, policy-as-code engine, evidence ledger, campaign engine | **Build** (core IP) | This is Tessera's differentiation and the data model everything depends on. |
| Cloud and data-platform connectors (AWS/GCP/Azure, Snowflake, Databricks, K8s, GitHub, DBs) | **Build** (wedge) | Deep, fine-grained, usage-aware connectors are the access-as-code wedge. |
| Long-tail SaaS connectors | **Integrate**: SCIM 2.0, open connector SDK, possibly adopt or compat-layer ConductorOne's open-source Baton format [licensing to be verified], plus IdP-mediated provisioning via Okta/Entra | Breadth is a commodity race. |
| HRIS connectors | **Build** Workday, BambooHR, SuccessFactors. **Integrate** the rest via unified HRIS APIs (e.g., Merge, Finch) or CSV | Top three cover most mid-market and enterprise. |
| Ticketing fulfillment | **Integrate** (ServiceNow, Jira) | Standard pattern; verify by re-aggregation. |
| ERP fine-grained SoD (SAP/Oracle) | **Integrate/partner** (Pathlock, SAP IAG/GRC, Saviynt) initially. Cross-system SoD at entitlement level: **build** | Rulesets need deep domain content. The SAP AC 12.0 end-of-maintenance (2027/2030) wave is an opportunity for later expansion. |
| PAM session management | **Integrate** (CyberArk, Delinea, Teleport, StrongDM). Build JIT grants natively | JIT is governance; session brokering is a separate product. |
| GRC/audit platforms | **Integrate** (AuditBoard, Vanta, Drata, ServiceNow IRM) via APIs and OSCAL | Auditors live there; feed them evidence. |
| AI recommendations | **Build** explainable peer/usage analytics; use LLMs for descriptions and summarization of entitlements | Explainability is required for audit acceptance. |

---

## 9. Glossary

- **Access certification / recertification / attestation:** Reviewer confirmation that access remains appropriate.
- **Access package:** Microsoft term for a requestable bundle of resources with policies.
- **Aggregation:** Collecting accounts and entitlements from a target system.
- **Authoritative source:** System of record for identity attributes (usually the HRIS).
- **Birthright access:** Access granted automatically by attributes.
- **Break-glass account:** An emergency privileged account, tightly controlled and monitored.
- **CIEM:** Cloud Infrastructure Entitlement Management.
- **Correlation:** Linking accounts to identities.
- **Dormant account:** An account unused beyond a threshold.
- **Entitlement:** The atomic unit of governed access.
- **IGA:** Identity Governance and Administration.
- **IPE:** Information Produced by the Entity, i.e. system reports relied on by auditors.
- **ISPM:** Identity Security Posture Management.
- **ITGC:** IT General Controls.
- **JIT:** Just-in-time (time-bound) access.
- **JML:** Joiner/Mover/Leaver.
- **KSI:** Key Security Indicator (FedRAMP 20x).
- **Micro-certification:** A small, event-triggered review.
- **Mitigating control:** A compensating control accepted for an SoD conflict.
- **NHI:** Non-human identity.
- **Orphan account:** An account with no active owner.
- **OSCAL:** NIST Open Security Controls Assessment Language.
- **Privilege creep:** Accumulation of access over time.
- **Reconciliation:** Comparing expected and actual access and correcting drift.
- **Role explosion:** Proliferation of roles approaching the number of users.
- **Role mining:** Algorithmic discovery of candidate roles.
- **Rubber-stamping:** Approving without real review.
- **SCIM:** System for Cross-domain Identity Management (RFC 7643/7644).
- **SoD:** Separation/segregation of duties.
- **Toxic combination:** An entitlement set that violates SoD.
- **UAR:** User access review.

---

## 10. Sources

Standards, regulation, primary bodies
- PCI SSC RFC on PCI DSS v4.0.1 (June 2026): https://www.pcisecuritystandards.org/rfc_instructions_pci-dss-v4-0-1-june2026/
- PCI SSC blog, RFC for next PCI DSS: https://blog.pcisecuritystandards.org/request-for-comments-pci-data-security-standard-pci-dss-v4.0.1
- PCI DSS 7.2.4 summary: https://www.myctrl.tools/frameworks/pci-dss-v4/7-2-4 ; 8.2.6: https://myctrl.tools/frameworks/pci-dss-v4/8-2-6
- NIST SP 800-53 Rev. 5 Release 5.2.0: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final ; announcement: https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls
- HIPAA NPRM timing (moved to July 2027): https://www.fiercehealthcare.com/health-tech/feds-push-back-hipaa-security-rule-overhaul-july-2027
- HIPAA NPRM deadlines (1-hour termination, 24-hour notice): https://www.nortonrosefulbright.com/en/knowledge/publications/ab74043f/hhs-proposes-security-rule-amendments-including-new-deadlines
- HIPAA NPRM overview: https://www.cov.com/en/news-and-insights/insights/2025/01/hhs-issues-notice-of-proposed-rulemaking-to-update-the-hipaa-security-rule ; https://www.goodwinlaw.com/en/insights/publications/2025/01/alerts-otherindustries-hltc-hhs-proposes-major-revisions
- DORA RTS 2024/1774 Art. 20: https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-20/ ; Art. 21: https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-21/ ; Art. 33: https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-33/
- NIS2 CIR 2024/2690 §11: https://nisd2.eu/en/wiki/fundamentals/cir-2024-2690 ; https://advisera.com/articles/nis2-cir-2024-2690-digital-infrastructure-companies/
- EUR-Lex (authoritative texts): https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj ; https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj
- ISO 27002 5.18 summary: https://isms.online/iso-27002/control-5-18-access-rights ; 8.2: https://www.isms.online/iso-27002/control-8-2-privileged-access-rights
- SOC 2 CC6.2/CC6.3 summaries: https://docs.alertlogic.com/analyze/reports/compliance/SOC2-CC-6.2-user-registration.htm ; https://docs.alertlogic.com/analyze/reports/compliance/SOC2-CC-6.3-access-modification-and-removal.htm
- FedRAMP 20x / CR26: https://secureframe.com/blog/fedramp-20x.md ; https://www.grcreport.com/post/proof-over-paperwork-fedramps-shift-from-rev5-to-20x ; https://bleepingcomputer.com/news/security/fedramp-rev5-is-ending-what-the-20x-transition-really-requires ; https://www.fedramp.gov/
- SAP Access Control maintenance: https://www.ibsolution.com/academy/blog_en/cyber-security/sap-identity-and-access-management/maintenance-for-sap-access-control-expires-in-2027-what-comes-next

Audit practice
- Schneider Downs, UAR auditor expectations: https://schneiderdowns.com/our-thoughts-on/user-access-reviews-tips-to-meet-auditor-expectations/
- Veza, completeness and accuracy procedures: https://docs.veza.com/4yItIzMvkpAvMVFAamTf/features/access-reviews/how-to/completeness-accuracy-procedures
- Forvis Mazars, IPE fundamentals: https://www.forvismazars.us/getattachment/3bbb3927-73c5-4734-9635-5a2ed6da45b3/The-SOCial-Hour-IPE-Fundamentals-for-SOC-Examinations.pdf
- PCAOB ITGC inspection commentary: https://www.goingconcern.com/pcaob-inspectors-find-it-auditors-struggle-bus/
- Risk-based SOX UAR (vendor): https://www.safepaas.com/blog/automating-user-access-reviews-for-sox-compliance/ ; https://youattest.com/blog/sox-user-access-review-quarterly-certifications/
- ISSA Journal Sep/Oct 2025 on review fatigue: https://issa.mydigitalpublication.com/september-october-2025/page-16

Communities and analysts
- IDPro Body of Knowledge: https://idpro.org/body-of-knowledge/ ; https://bok.idpro.org/article/id/119/
- Gartner 2026 Market Guide for IGA (abstract): https://www.gartner.com/en/documents/8321653 ; summary: https://pathlock.com/blog/2026-gartner-iga-market-guide-top-findings/
- KuppingerCole on Omada–EmpowerID: https://www.kuppingercole.com/blog/deshpande/omada-gains-runtime-agent-governance

Vendors
- SailPoint Navigate 2026 press release: https://www.sailpoint.com/press-releases/sailpoint-unlocks-a-secure-agentic-era-with-autonomous-identity-security
- SailPoint FY26 results (transcript): https://www.marketbeat.com/earnings/reports/2026-3-18-sailpoint-technologies-holdings-inc-stock/
- Saviynt $700M round: https://finder.techleap.nl/news/feed/saviynt-raises-700m-at-3b-valuation-to-replace-legacy-identity-systems ; https://www.kirkland.com/news/press-release/2025/12/kirkland-advises-sixth-street-growth-on-investment-in-saviynt
- Okta Identity Governance release notes: https://help.okta.com/en-us/Content/Topics/ReleaseNotes/iga/iga-release-notes.htm ; https://developer.okta.com/docs/release-notes/2026-okta-identity-governance
- Okta 2026 Gartner Market Guide recognition: https://www.okta.com/resources/research/2026-gartner-market-guide-for-identity-governance-and-administration/
- Okta–Axiom: https://www.channele2e.com/news/okta-acquires-axiom-security-to-strengthen-privileged-access-in-the-ai-era
- Microsoft Entra ID Governance deployment guide: https://learn.microsoft.com/en-gb/entra/architecture/governance-deployment-employee-access ; inactive users lifecycle workflow: https://docs.azure.cn/en-us/entra/id-governance/lifecycle-workflow-inactive-users ; ML recommendations: https://office365itpros.com/2023/07/21/entra-id-access-review-ai/ ; Access Review Agent: https://petri.com/microsoft-entra-id-access-review-agent/
- Omada acquires EmpowerID: https://techintelpro.com/pressreleases/omada-acquires-empowerid-to-close-the-ai-agent-security-gap ; CVC exit: https://www.cvc.com/media/news/2025/cvc-growth-funds-announce-exit-of-omada/
- One Identity Manager 10.0: https://techstartups.com/2026/01/20/one-identity-unveils-major-upgrade-to-identity-manager-strengthening-enterprise-identity-security/
- ConductorOne $79M Series B: https://parsers.vc/news/251031-conductorone-fuels-ai-identity-security/ ; policies: https://conductorone.com/docs/product/admin/policies ; UAR maturity guide: https://info.conductorone.com/hubfs/Guide%20-%20UAR%20Maturity%20Curve.pdf
- Lumos roadmap 2026: https://www.lumos.com/webinars/lumos-roadmap-2026
- Pathlock: https://pathlock.com/products/application-access-governance/
