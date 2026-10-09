# Tessera: Competitive Landscape for Identity Governance (IGA/IAM)

*As of 2026-10-08. Compiled from web research (vendor press releases, trade press, filings, analyst summaries). Vendor claims are marked as such. Items tagged **[unverified]** could not be confirmed against a primary or second independent source.*

---

## 0. TL;DR

- **The market spent 2025–2026 consolidating.** Palo Alto bought CyberArk (~$25B, closed Feb 2026). ServiceNow bought Veza (~$1B, closed Mar 2026). CrowdStrike bought SGNL (~$740M). Cisco bought Astrix (~$400M). Cyera bought Oasis (~$1B). SailPoint bought Entro (~$200M reported). 1Password bought Apono (>$250M reported). Snowflake is buying Natoma, Okta bought Axiom and Permiso, and Saviynt raised $700M at ~$3B. Most of the well-known standalone NHI and agent-identity startups have now been absorbed into platforms.
- **The most crowded wedge is "AI agent identity".** Agent registry, discovery, MCP/agent gateways and runtime JIT for agents shipped in 2026 from Okta, Microsoft, SailPoint, Saviynt, CyberArk/PANW, Ping, C1 (ConductorOne), Britive, Aembit, Keycard, Snowflake/Natoma and Cisco/Astrix. Leading with "we govern AI agents" is not differentiated.
- **Other crowded wedges.** JIT access (Opal, Apono/1Password, Britive, C1, Okta+Axiom, Entra PIM). AI-assisted access reviews (everyone). Mid-market "modern IGA" (C1, Lumos, Opal, Zilla/CyberArk, Okta OIG, Entra ID Governance at $4–7/user/month). The access graph itself (Veza, now ServiceNow).
- **White space that remains:**
  1. **Access-as-code.** Cedar/OPA policies, Git review, CI tests and *pre-merge blast-radius simulation* for entitlements. No IGA vendor productizes this; incumbents offer plain-language policy drafting and config versioning.
  2. **Usage-evidenced, event-driven least privilege with automatic, reversible revocation.** Many vendors claim "real-time", but none clearly lead on "prove it's unused, then remove it safely".
  3. **Vendor-neutral delegation-chain provenance** (human → agent → sub-agent → tool/credential) that spans Okta XAA, Entra Agent ID, MCP gateways and cloud IAM. Each platform sees only its own slice.
  4. **A neutral home for customers stranded by M&A** (Veza, Astrix, Oasis, Apono, SGNL, Entro customers now facing bundling or re-platforming).
- **Recommended positioning:** "Access-as-code and continuous least privilege for cloud and data infrastructure, covering humans, workloads and agents in one graph." Land with platform/security engineering at cloud-native, AI-heavy companies of 500–5,000 employees. Treat agents as first-class identities inside the graph. Do not sell a standalone agent product, and do not build an IdP or MCP gateway; integrate with them.

---

## 1. Market context (2025–2026)

| Signal | Detail | Source confidence |
|---|---|---|
| Analyst framing | Gartner reportedly named "IAM adapts to AI agents" a top 2026 cybersecurity trend. | Secondary [unverified primary] |
| Market size | IDC (via press) puts identity security at $29B in 2025, rising to $56B by 2029. | Secondary |
| IGA growth | Gartner IGA market growth of 9.2% (2023→24) and a 10.7% forecast for 2025 (via Pathlock). | Vendor-cited |
| Implementation pain | 451 Research (via Oleria) says legacy IGA takes 12–24 months plus seven-figure services. A Gartner figure (via Orchid) gives 42 months on average. CyberArk's 2025 State of IGA says 83% blame integration difficulty for manual processes. | Vendor-cited [methodology unverified] |
| Agent adoption | SailPoint survey: 79% of enterprises run AI agents in production, but only 2% have tooling built to govern them. | Vendor survey |
| Bellwether growth | SailPoint FY26 (Jan 2026): ARR $1.125B (+28%), SaaS ARR $746M (+38%). FY27 guide: +21% ARR. | Public filings/press |

**Takeaway:** Demand is real and budgets are moving. The big platforms' answer is to bundle agent identity into existing suites, and they are acquiring rather than building to get there.

---

## 2. Competitor profiles

### 2.1 Incumbent IGA platforms

#### SailPoint (Identity Security Cloud → "Human Fabric", Atlas, Agentic Fabric)
- **Positioning:** The enterprise IGA leader, re-platformed on **Atlas**. In Aug 2026 it unified humans, machines and agents: Human Fabric (formerly ISC) plus Agentic Fabric (GA Aug 2026).
- **Recent moves:**
  - Agentic Fabric was announced May 2026.
  - The Entro acquisition (NHI/secrets discovery, owner lineage) was announced Jun 15, 2026, at ~$200M reported. It is reported complete but platform integration is "soon".
  - Navigate (Oct 6, 2026) announced:
    - three classes of Autonomous Agents (policy enforcement, privilege right-sizing)
    - Autonomous ISPM (A-ISPM, expected Q4 FY27)
    - shadow-AI discovery, runtime authorization and an agent "kill switch"
    - JIT provisioning
    - Harbor Pilot Policy Agent (plain-language policy authoring)
    - Atlas versioning and execution history
    - IdentityIQ 9.0
- **Strengths:**
  - Default choice for Global 2000 compliance-driven IGA.
  - Huge connector and partner (SI) ecosystem.
  - Scale: >$1.1B ARR.
  - Now has a credible NHI/agent story via Entro.
- **Weaknesses:**
  - Long implementations that depend on SIs.
  - Certification-centric heritage.
  - "Real-time" claims sit on top of an aggregation-based model [inference].
  - Policy is authored in a UI or natural language, not as code with Git review.
  - Usage-based revocation is not explicitly described.
- **Pricing:** Not public (enterprise quotes).
- **Threat to Tessera:** High in large enterprise. Low in engineering-led mid-market.

#### Saviynt (Enterprise Identity Cloud)
- **Positioning:** Converged identity cloud covering IGA, PAM, application access governance, ISPM and access gateway, for all identity types.
- **Recent moves:**
  - $700M Series B led by KKR at ~$3B valuation (Dec 2025).
  - "Identity Security for AI" launched Mar 24, 2026, in three parts:
    - ISPM for AI
    - agent lifecycle management
    - an Agent Access Gateway providing runtime authorization
  - Claims agent discovery across Bedrock, Copilot Studio, Vertex AI, ServiceNow AI and Agentforce.
- **Strengths:**
  - Broad converged suite.
  - Strong in regulated and ERP/application-access-governance (SAP) deals.
  - 600+ enterprises; claims more than 1/5 of the Fortune 100.
  - Now very well capitalized.
- **Weaknesses:** Complex suite. Implementation still heavy, partner-led [inference based on category norms].
- **Pricing:** Not public.

#### Okta (Okta Identity Governance, Privileged Access, Okta for AI Agents)
- **Positioning:** Workforce IdP leader expanding into an "identity security fabric" covering governance, PAM, ITDR and agents.
- **Recent moves:**
  - Bought Axiom Security (PAM/JIT; $54M per 10-K; closed Sep 2025). The plan includes JIT for GitHub, Snowflake, Postgres and EKS, plus an **AI-based connector builder**.
  - Cross App Access (XAA) is an OAuth extension adopted into MCP as an authorization extension. It was early access in Jan 2026.
  - Oktane 2026 (Sep 22–24):
    - Okta for AI Agents is GA
    - Agent SSO built on XAA, at no extra cost
    - Agent Gateway, which brokers MCP tool calls and injects credentials
    - Agent-to-Agent Connections with delegation and audit
    - shadow-agent discovery (with CrowdStrike, and via Okta Verify)
    - the multi-vendor "Blueprint Alliance" reference architecture
    - "On-demand SaaS integrations"
    - ITDR via the Permiso acquisition [deal date unverified]
- **Strengths:** IdP control point, a de facto agent-auth standard (XAA) and distribution.
- **Weaknesses:**
  - OIG is typically seen as lighter than SailPoint/Saviynt for complex enterprise governance [inference].
  - Governance stops at Okta's view and lacks deep cloud-IAM effective permissions.
- **Pricing signals:** OIG add-on reportedly ~$9–11/user/month [unverified, third-party]. Essentials suite ~$17/user/month [unverified].

#### Microsoft (Entra ID Governance, Entra Agent ID, Agent 365)
- **Positioning:** The bundled default for Microsoft-centric enterprises.
- **Recent moves:**
  - Entra Agent ID gives each agent its own identity in Entra.
  - Conditional Access and ID Protection for agents began rolling out Jul 2026, added into Agent 365 / M365 E7.
  - Access Review Agent: AI recommendations delivered via Teams. Reported limits: ≤35 decisions per review, single-stage only, no Azure/Entra roles or PIM groups yet.
  - Agent 365 went GA May 1, 2026 at $15/user/month. It is licensed per human, with sponsored agents covered.
  - Gartner advised deferring Agent 365 purchases until it matures.
  - The agent registry UI is moving to Agent 365.
- **Strengths:** Price and bundling, Conditional Access integration, and ownership of the Copilot/agent runtime.
- **Weaknesses:**
  - Weaker outside the Microsoft estate (AWS, GCP, non-Microsoft SaaS).
  - Features are often preview-grade with quotas and limits.
  - Licensing is confusing.
- **Pricing:** ID Governance add-on ~$7/user/month on P1 or ~$4 on P2. Entra Suite ~$12. Agent 365 $15; E7 ~$99 [secondary, verify].
- **Threat to Tessera:** Very high as a "good enough and already paid for" option in Microsoft shops.

#### Ping Identity / ForgeRock (Thoma Bravo)
- **Positioning:** CIAM and workforce IAM, merged with ForgeRock (2023). Same owner as SailPoint (Thoma Bravo).
- **Recent moves:** "Identity for AI" was announced Nov 2025 and GA Mar 2026. It has three parts: Agent IAM Core, Agent Gateway and Agent Detection, with runtime delegated authority and human oversight.
- **Strengths:** CIAM and agentic-commerce angle; large regulated customers (banking).
- **Weaknesses:**
  - The Ping and ForgeRock roadmap convergence is still in progress, per competitor commentary.
  - The governance product is secondary.
  - Little evidence of a cloud-entitlement graph.
- **Pricing:** Not public.
- **Relevance:** Low direct overlap with Tessera's governance wedge.

#### One Identity (Quest)
- **Positioning:** Mid- and large-enterprise IGA (Identity Manager), PAM (Safeguard) and OneLogin.
- **Recent moves:** Identity Manager 10.0 (Jan 2026) adds AI-driven threat response, risk-based governance and a new browser UI [feature depth unverified]. Its 2026 predictions emphasize over-privileged agents and regulators pushing for continuous evidence over annual attestations.
- **Strengths:** On-prem/hybrid depth; strong in Europe.
- **Weaknesses:**
  - Legacy architecture.
  - No visible agent-native product beyond messaging [unverified].
- **Pricing:** Not public.
- **Relevance:** Low.

### 2.2 Modern / cloud-native governance challengers

#### Veza (now "Veza from ServiceNow")
- **Positioning:** The **Access Graph**: authorization metadata across apps, data and cloud, showing effective permissions and *how they were granted* (nested roles and so on), for human, machine and AI identities.
- **Recent moves:**
  - $108M Series D (2025, ~$808M valuation).
  - ServiceNow announced the acquisition Dec 2, 2025, at ~$1B reported. It closed ~Mar 2, 2026 (~$1.2B per one source [unverified]).
  - Being integrated into ServiceNow **AI Control Tower**.
  - Veza Access Agents were early access Feb 2026, with GA targeted end of Q2 2026 [GA unverified].
- **Strengths:** **Owns the "effective permissions graph" category narrative** and has the deepest authorization-metadata connectors. Now has ServiceNow distribution and workflow.
- **Weaknesses:**
  - Post-acquisition, the roadmap bends toward ServiceNow buyers and the CMDB/ITSM motion.
  - Independent and non-ServiceNow customers may feel deprioritized [inference].
  - Graph freshness (event-driven vs. periodic extraction) is not clearly marketed [unverified].
- **Honest read:** Tessera **cannot** claim "the permissions graph" as novel. Veza and SailPoint Atlas both have one. Differentiation must come from *freshness + usage + policy-as-code + simulation*, not the graph itself.

#### ConductorOne (rebranding as "C1")
- **Positioning:** "AI-native identity security" that unifies IGA, IAM and PAM. Strong in access requests, JIT and reviews for cloud-native companies (Zscaler, Ramp, DoorDash cited).
- **Recent moves:**
  - $79M Series B (Oct 2025; Greycroft lead, CrowdStrike Falcon Fund participating; >$100M total).
  - 2026 launches, in order:
    - Headless Identity Infrastructure (May): graph, policy engine and audit exposed via API, MCP, CLI and SDK
    - Claude Compliance API integration (Jun)
    - enterprise-managed authorization for MCP, with C1 issuing tokens (Jun)
    - C1 Autonomous Worker (Jun)
    - Shadow AI Discovery (Jul)
    - Agentic Vault (Jul)
    - Agent Runtime Governance: per-tool-call policy (Jul)
    - Agentic Security and Intelligence (Jul)
    - C1 AppHub, credential vending/egress swap and an LLM Gateway (Sep–Oct 2026)
  - Wiz partnership (Apr 2026).
- **Strengths:**
  - Fastest-shipping challenger.
  - Developer-friendly: API/CLI and a Terraform-style posture.
  - Already covers humans, NHIs and agents.
  - Strong mid-market and growth-tech logos.
  - Open-source connector heritage (Baton) [from memory; verify].
- **Weaknesses:**
  - Breadth is sprawling (vault, LLM gateway, app hosting), which risks focus.
  - Less proven in heavy-compliance Global 2000.
- **Pricing:** Not public (quote-based, per user).
- **Honest read:** C1 is **Tessera's closest and most dangerous competitor**. It already occupies JIT-by-default, AI-assisted reviews, agent runtime governance and "headless/API-first" identity for engineering-led companies. Tessera must not try to out-feature C1 on breadth.

#### Lumos
- **Positioning:** Autonomous identity governance plus SaaS management, with an app store for access requests, mostly mid-market.
- **Recent moves:**
  - Albus, a multi-agent IGA assistant (Jun 2025).
  - Agentic user access reviews (Dec 2025).
  - Identity Security Agents (Dec 2025 waitlist; launched Mar 2026).
  - "Identity Agent Force" (Jun 2026) [unverified, aggregator].
  - Funding: $35M Series B (May 2024). Total ~$65–85M [conflicting]. No 2025–26 round found.
- **Strengths:** Fast time-to-value, SaaS spend and shadow-IT angle, attractive UX.
- **Weaknesses:**
  - Less depth in cloud infrastructure entitlements.
  - Smaller war chest than C1 or Saviynt.
- **Pricing:** Lumos' own marketing says "from ~$1/user/month" [vendor claim; quote-based in practice].

#### Opal Security
- **Positioning:** Access management and JIT for engineering-heavy companies (infrastructure, databases, cloud), now with the Paladin AI engine.
- **Recent moves:**
  - $23M round (Jun 2026; Greylock and Battery). Round label is inconsistent; total ~$57M.
  - New CTO, and a CPO hired from Veza.
  - More than 60% of staff joined in 2026.
  - Customers include Scale AI and Grammarly.
- **Strengths:** Strong JIT and engineer-centric UX. Closest in spirit to Tessera's "JIT by default".
- **Weaknesses:** Smaller scale. Visible leadership turnover / rebuild.
- **Pricing:** Not public.

#### CyberArk Identity Governance (ex-Zilla), now part of Palo Alto Networks
- Covered under §2.4.

### 2.3 NHI and AI-agent identity specialists (mostly acquired)

| Company | Focus | 2025–26 status | Notes |
|---|---|---|---|
| **Astrix Security** | NHI discovery and posture (API keys, OAuth, service accounts), AI agents | **Acquired by Cisco** (announced ~May 4–5, 2026; ~$400M reported). Being folded into Cisco Identity Intelligence, Duo, Secure Access and Splunk. | Series B $45M (Dec 2024, Menlo). |
| **Oasis Security** | NHI lifecycle; "Agentic Access Management" (JIT, ephemeral permissions, vaulted/federated credentials) | $120M Series B (Mar 2026, Craft; $195M total; claimed 5x new ARR). **Cyera letter of intent ~$1B (Jul 28, 2026)**; completion reported Sep 2026 [single source]. | Runs as an independent unit in Cyera, a data-security-plus-identity thesis. |
| **Entro Security** | NHI/secrets discovery, owner lineage | **Acquired by SailPoint** (Jun 2026; ~$200M reported). | Now a standalone offering inside SailPoint. |
| **Aembit** | Workload IAM; secretless, short-lived creds; "IAM for Agentic AI" (Blended Identity, MCP Identity Gateway) | Launched Oct 2025, GA around RSA 2026. Independent. Funding ~$25–45M [conflicting]. | Strong in workload-to-workload; access broker, not governance. |
| **Token Security** | NHI and AI-agent lifecycle (discovery → deprovisioning, owners) | $20M Series A (Jan 2025; ~$27–28M total). Independent. | Likely acquisition target. |
| **Keycard** | Identity and access for AI agents; task-scoped tokens; MCP/OAuth standards | $38M seed + A (Oct 2025; a16z, Boldstart, Acrew). Independent. | Developer/agent-builder audience. |
| **Natoma** | Enterprise MCP gateway: per-tool-call identity, policy, audit | **Snowflake intent to acquire** (May 28, 2026; pending; terms undisclosed). | |
| **SGNL** | Continuous/runtime access enforcement between IdP and resources (event-driven, CAEP-style) | **Acquired by CrowdStrike** (Jan 2026; ~$740M reported). | Closest prior art to "event-driven, policy-based access"; now inside Falcon. |
| **Apono** | JIT/JEP access for cloud, data, humans, machines, agents | **Acquired by 1Password** (Jun 15, 2026; >$250M per Globes [single source]). | Inside 1Password Unified Access + Credential Broker. |
| **Silverfort** | Identity protection; reportedly acquired Fabrix (Apr 2026) for an agent-identity engine | [Fabrix deal unverified] | |
| **Oleria** | Autonomous identity security | $19M (Nov 2025; >$60M total) [secondary] | Adjacent challenger. |
| **Clutch Security** | NHI security | No 2025–26 data found [unverified] | |

**Read:** The pure-play NHI category has largely been **absorbed** by Cisco, SailPoint, Cyera, CrowdStrike, 1Password, Snowflake and PANW/CyberArk. Standalone NHI discovery is now a *feature* of platforms. A new entrant cannot win on "find your service accounts and API keys".

### 2.4 PAM / JIT: CyberArk (Palo Alto Networks), Britive

#### CyberArk, now Palo Alto Networks (incl. Venafi and Zilla)
- **Deal:** PANW closed its ~$25B CyberArk acquisition **Feb 11, 2026** ($45 cash + 2.2005 PANW shares per CyberArk share). CyberArk remains available standalone. Integration into Strata and Cortex (XSIAM) is underway.
- **Portfolio:**
  - PAM leader.
  - **Venafi** (machine identity/PKI, ~$1.54B, 2024).
  - **Zilla** (modern AI-driven IGA, up to $175M, Feb 2025; claims broad app-integration coverage, including custom apps).
  - **Secure AI Agents Solution** (GA Nov 2025): agent discovery, owners, zero standing privileges, behavioral monitoring.
- **Strengths:**
  - Privileged control plane.
  - Machine-identity depth.
  - PANW's distribution and SOC integration.
  - The "every agent is a privileged identity" framing.
- **Weaknesses:**
  - Integration distraction during the merger.
  - Zilla IGA is young relative to SailPoint. A competitor (SailPoint) alleges uneven provisioning support across Zilla's integrations.
- **Pricing:** Not public.

#### Britive
- **Positioning:** Cloud-native **zero standing privilege / JIT** across AWS, Azure, GCP, OCI, Kubernetes, SaaS and on-prem, for humans, NHIs and agents.
- **Recent moves:**
  - AI Identity Security suite (Sep 2025): agent lifecycle, owners, runtime JIT, MCP tool access, agent-to-agent delegation, human-to-agent approvals, "on behalf of" audit.
  - **Britive ARC** (Agentic Runtime Control, Aug 2026): task-scoped credentials injected at runtime and revoked on completion, plus command/SQL-level control via the Britive MCP Gateway.
  - No 2025–26 funding found [unverified].
- **Strengths:** Already ships most of Tessera's "JIT as default" and "delegation chain audit" for agents in cloud infrastructure.
- **Weaknesses:**
  - PAM/JIT-centric, not full IGA (joiner/mover/leaver lifecycle, certifications, SoD).
  - Smaller company.
- **Pricing:** AWS Marketplace listing exists; specific prices not captured [unverified].

### 2.5 Policy-as-code / authorization infrastructure (adjacent)
- **Cedar / Amazon Verified Permissions:**
  - Open-source (Apache-2.0, 2023).
  - Formally modeled in Dafny; forbid overrides permit; default deny.
  - Used by AVP and AWS Verified Access.
  - Strong technical fit for analyzable entitlement policy and a natural base for blast-radius analysis.
- **OPA (CNCF), Cerbos (~$11M raised), Permit.io (~$14M raised):** These serve **application authorization for developers**, not workforce/infrastructure IGA. No 2025–26 funding found [unverified].
- **Read:** Nobody has bridged *policy-as-code tooling* with *identity governance outcomes* (certification evidence, SoD, joiner/mover/leaver). This is genuine white space, but it also explains why there may be no established buyer for it yet (see Risks).

---

## 3. Market map

```
                       ENFORCEMENT AT RUNTIME (per-request / per-tool-call)
                                        ▲
   Britive ARC · Aembit · Keycard ·     │   Okta Agent Gateway/XAA · Entra CA for agents
   Natoma(Snowflake) · SGNL(CrowdStrike)│   Ping Identity for AI · Saviynt Agent Gateway
   C1 Agent Runtime Gov · Oasis(Cyera)  │   CyberArk Secure AI Agents (PANW)
                                        │
 POINT / ENGINEER-LED ◄─────────────────┼────────────────► SUITE / COMPLIANCE-LED
                                        │
   Opal · Apono(1Password) · Lumos ·    │   SailPoint (Atlas, Agentic+Human Fabric)
   C1 (requests/reviews/JIT) ·          │   Saviynt · Okta OIG · Entra ID Governance
   Token Security · Astrix(Cisco)       │   One Identity · CyberArk/Zilla IGA
   Veza(ServiceNow) graph/ISPM          │   Veza→ServiceNow AI Control Tower
                                        ▼
                    POSTURE / GOVERNANCE (periodic analysis, reviews, lifecycle)

      Tessera target: engineer-led, but bridging posture → runtime through
      policy-as-code + simulation + usage-evidenced auto-remediation.
```

**Tessera thesis vs. who already does each pillar:**

| Tessera pillar | Already shipping / claimed by | Crowding | Tessera's honest edge |
|---|---|---|---|
| Effective-permissions graph across IdP, cloud, SaaS | Veza/ServiceNow (category owner), SailPoint Atlas, C1 graph, Saviynt ISPM | **High** | Only via *event-driven freshness* and usage overlay, if real |
| Event-driven, not batch | SGNL (now CrowdStrike), SailPoint "real-time" claims, Okta ITDR signals | Medium (claims abound, proof is rare) | Defensible if Tessera demonstrably reflects changes in seconds to minutes and publishes per-connector freshness SLOs |
| Usage-based least privilege, auto-revoke unused | SailPoint right-sizing agents, Lumos role recommendations, C1, CIEM tools (Wiz, etc.) | Medium | **Safe, reversible auto-revoke** with blast-radius proof is under-served |
| Exception-only certifications | Everyone shipping "AI review agents" (Entra, Lumos, C1, SailPoint, Veza) | **High** | Weak alone; strong as an outcome of usage evidence (auditor-acceptable evidence packs) |
| NHI and AI agents first-class (owners, lifecycle, delegation) | SailPoint+Entro, Saviynt, Okta, Entra Agent ID, CyberArk, Britive, C1, Ping, Token, Aembit, Keycard | **Very high** | Only **cross-vendor delegation-chain provenance** is open |
| JIT as default | Britive, Opal, Apono/1Password, C1, Okta+Axiom, Entra PIM, CyberArk, Oasis | **Very high** | Table stakes; must have it, cannot lead with it |
| Policy-as-code (Cedar/OPA) + Git review + blast-radius simulation | Nobody in IGA productizes this. SailPoint has plain-language policy drafting and config versioning. App-authz vendors (Cerbos, Permit, AVP) do code but not governance. | **Low** | **Primary differentiator** |
| Declarative/AI-generated connectors (days, not months) | Okta (AI connector builder; on-demand SaaS integrations), Zilla/CyberArk (custom-app integrations), C1 (open connector SDK), SailPoint Atlas extensibility | Medium–high (claimed) | Necessary to compete. A differentiator only if Tessera publishes connector-build times and coverage depth (read/write/usage/events) |

---

## 4. Where the white space is

1. **Access-as-code for entitlements (strongest).** Treat roles, birthright rules, JIT eligibility, SoD and agent scopes as Cedar (or OPA) in Git:
   - pull-request review
   - CI tests ("no engineer can reach prod PII without JIT")
   - **pre-merge blast-radius simulation** against the live graph ("this change grants 412 identities new paths to S3 bucket X; 3 are agents")

   Incumbents move toward natural-language policy for admins. Engineering-led security teams want reviewable, testable, diffable artifacts. Cedar's analyzability makes this technically credible.
2. **Provable, reversible least privilege.** Many vendors recommend removals; few will *auto-revoke in production*, because the fear of outages is rational. The combination below turns least privilege from a report into an operating loop:
   - usage evidence with explicit confidence
   - staged revocation with automatic restore on denial or JIT re-request
   - simulation before acting
3. **Cross-platform delegation provenance for agents.** Okta XAA, Entra Agent ID, MCP gateways (Okta, C1, Natoma/Snowflake, Britive, Aembit) and cloud IAM each log their own hop. No neutral layer reconstructs *human → agent → sub-agent → tool → cloud role → data* end to end, or answers "what is the maximum reach of this agent including what it can borrow". This is a governance and audit product, not a gateway.
4. **Neutrality as a feature after M&A.** Veza is now ServiceNow; Astrix is Cisco; Oasis is Cyera; SGNL is CrowdStrike; Apono is 1Password; CyberArk is PANW. Buyers with heterogeneous stacks (Okta and Entra, AWS and GCP, multiple EDRs) may prefer a vendor not tied to one security platform. Acquired products' existing customers face re-platforming in 2026–27, which creates a displacement pipeline.
5. **Continuous compliance evidence.** One Identity and others expect regulators and auditors to move from annual attestations toward continuous evidence. Exception-only certification works only if auditors accept the evidence. Shipping SOX/SOC 2/ISO-mapped evidence packs derived from usage and policy-as-code history is under-served.

---

## 5. Crowded wedges (do **not** lead with these)

- **"Identity for AI agents" / agent registry / MCP gateway.** At least 12 vendors shipped in 2025–26, including every IdP. Okta gives Agent SSO away free. Microsoft bundles agent controls into Agent 365/E7. **Owned by platforms.**
- **NHI discovery and posture.** Consolidated by SailPoint (Entro), Cisco (Astrix), Cyera (Oasis), CyberArk/Venafi and Saviynt. **Feature, not company.**
- **JIT access.** Britive, Opal, Apono/1Password, C1, Okta+Axiom, Entra PIM. **Table stakes.**
- **AI-assisted access reviews.** Entra Access Review Agent, Lumos, C1, SailPoint, Veza. **Commodity.**
- **"The access graph".** Veza created the narrative and ServiceNow paid ~$1B for it. SailPoint Atlas and C1 also have graphs. **Not novel.**
- **Mid-market modern IGA (requests + reviews + joiner/mover/leaver for SaaS).** C1, Lumos, Opal, Okta OIG, and Entra at $4–7/user/month. **Price-compressed and crowded.**

---

## 6. Recommended positioning and ICP

**Positioning statement (draft):**
> *Tessera is access-as-code for cloud and data infrastructure. Every entitlement for people, workloads and AI agents is a reviewed, tested policy. Every change is simulated against a live, usage-aware permissions graph before it merges. Unused access is removed automatically, and safely.*

**Category to claim:** "Access-as-code" / "Continuous least privilege". Avoid "IGA" (pulls Tessera into SailPoint/Saviynt RFPs) and "AI agent security" (crowded).

**Initial wedge (land):**
- Cloud and data infrastructure entitlements: AWS/GCP/Azure IAM, Kubernetes, Snowflake/Databricks/BigQuery, GitHub, Postgres, plus Okta or Entra as the identity source.
- Humans, service accounts and agents all live in one graph.
- Lead features:
  1. Cedar policy repo with CI and blast-radius diffs
  2. usage-evidenced right-sizing with staged, reversible auto-revoke
  3. JIT as the fallback path
- **Integrate with, do not replace:** Okta/Entra (identity source, XAA/Agent ID signals), MCP gateways (as enforcement points) and SailPoint/Saviynt (export evidence to them in enterprise accounts).

**Expand:** SaaS apps via declarative/AI-generated connectors, exception-only certifications with auditor evidence packs, and cross-vendor agent delegation provenance.

**ICP:**
- **Company:** 500–5,000 employees, cloud-native, multi-cloud or heavy single-cloud, a data platform (Snowflake/Databricks), active internal agent development (Bedrock, Vertex, Claude, internal MCP servers). SOC 2/ISO today, SOX or FedRAMP on the horizon.
- **Buyer:** Head of security engineering / platform security / cloud security, *not* the traditional IAM or IGA admin.
- **Champion:** Staff engineer who already writes Terraform and policy and lives in GitHub.
- **Trigger events:**
  - first SOX audit or IPO prep
  - an incident involving over-privileged service accounts or agents
  - a Veza, Apono, Astrix or SGNL customer facing re-platforming after acquisition
  - an Okta+AWS shop that won't buy Entra governance
- **Anti-ICP (initially):** Global 2000 with SAP/mainframe-heavy IGA requirements (SailPoint/Saviynt home turf), and Microsoft-only shops (Entra bundling).

**Pricing hypothesis:** Price per *governed identity including NHIs and agents*, or per resource/connector tier, not per employee. That aligns with value and avoids head-to-head comparison against Entra's $4–7 per user. Offer a free or OSS tier for the policy-as-code CLI and simulator to seed bottom-up adoption [recommendation, untested].

---

## 7. Top risks

1. **C1 (ConductorOne) converges first.** C1 already exposes its graph and policy engine via API, MCP and CLI ("Headless Identity", May 2026), ships agent runtime governance, and has >$100M raised plus CrowdStrike as a strategic investor. If C1 adds Git-native policy plus simulation, Tessera's primary differentiator narrows. *Mitigation:* go deeper on Cedar formal analysis and simulation quality, and ship OSS tooling early to own the developer mindshare.
2. **Platform bundling.** Okta gives agent SSO away. Microsoft bundles governance at $4–7 and agent controls in Agent 365/E7. SailPoint, Saviynt and PANW sell suites. Budget holders may accept "good enough".
3. **Persona and market risk for policy-as-code.** IAM teams historically don't write code. Security-engineering buyers may see this as "nice infra" rather than a budget line. Pull must be validated with design partners before building breadth.
4. **"Real-time" is gated by source systems.** Many SaaS apps lack change webhooks or usage/audit APIs, or rate-limit them. Event-driven freshness will be uneven, and over-claiming it would damage credibility. *Mitigation:* publish per-connector freshness and usage-signal SLOs.
5. **Auto-revoke trust.** One bad revocation that takes down production can end a deployment. Needs:
   - simulation
   - staged rollout
   - instant restore
   - conservative defaults
6. **Auditor acceptance of exception-only certifications.** If auditors still require periodic full attestations, the "no more reviews" pitch weakens. Engage audit firms early.
7. **Connector moat is shrinking.** Okta, Zilla/CyberArk and others now market AI-built connectors. Fast connectors are necessary but not sufficient.
8. **Standards churn.** MCP spec revisions (major one Jul 2026), XAA, Entra Agent ID APIs in preview and the Blueprint Alliance architecture all add integration cost and risk of building on moving targets.
9. **Capital asymmetry and exit dynamics.** Competitors raised $79M (C1), $120M (Oasis) and $700M (Saviynt). Exits of $200M–$1B for NHI startups show strong acquirer appetite. They also show that platforms buy the category once it is proven, so Tessera needs a clearly distinct category, not a feature, to avoid being out-bundled.

---

## 8. Sources

**Consolidation / M&A**
- Palo Alto–CyberArk close: https://www.crnasia.com/news-network/2026/palo-alto-networks-completes-25b-acquisition-of-cyberark-for-identity-security-push ; https://startwithidentity.com/blog/2026-02-11-palo-alto-networks-completes-cyberark-acquisition/ ; https://www.sec.gov/Archives/edgar/data/1327567/000119312526045600/d40626dex991.htm
- ServiceNow–Veza: https://www.constellationr.com/insights/news/servicenow-acquires-veza-will-integrate-ai-control-tower ; https://startwithidentity.com/blog/2026-03-02-servicenow-completes-veza-acquisition/ ; https://businesswire.com/news/home/20260225220347/en/Veza-Introduces-Native-Access-Agents-to-Secure-the-Modern-AI-Driven-Enterprise-with-Enterprise-Agent-Identity-Control-Plane
- CrowdStrike–SGNL: https://securityboulevard.com/2026/01/crowdstrike-acquires-sgnl-for-740-million-to-thwart-ai-powered-cyber-threats/ ; https://techradar.com/pro/crowdstrike-acquires-continuous-identity-firm-sgnl-for-usd740m-in-push-for-next-gen-security
- Cisco–Astrix: https://www.networkworld.com/article/4166695/cisco-grabs-astrix-to-secure-ai-agents.html ; https://www.calcalistech.com/ctechnews/article/dy5obf581
- Cyera–Oasis: https://www.securityweek.com/cyera-acquiring-oasis-security-in-1-billion-deal/amp/ ; https://en.globes.co.il/en/article-1001550634 ; https://itbrief.news/story/cyera-completes-usd-1-billion-oasis-security-deal
- SailPoint–Entro: https://www.securityweek.com/sailpoint-to-acquire-entro-in-reported-200-million-deal/amp/ ; https://pulse2.com/sailpoint-completes-acquisition-of-entro-security/
- 1Password–Apono: https://siliconangle.com/2026/06/15/1password-acquires-just-time-access-provider-apono/ ; https://en.globes.co.il/en/article-1001545918
- Snowflake–Natoma: https://investors.snowflake.com/news/news-details/2026/Snowflake-Announces-Intent-to-Acquire-Natoma-Providing-Secure-Connectivity-For-The-Agentic-Enterprise/default.aspx
- Okta–Axiom: https://www.sec.gov/Archives/edgar/data/1660134/000166013426000020/okta-20260131.htm ; https://www.computerweekly.com/news/366629921/Okta-makes-AI-identity-play-with-Axiom-acquisition
- CyberArk–Zilla: https://www.bankinfosecurity.com/cyberark-bolsters-identity-governance-175m-zilla-buy-a-27513

**Vendors**
- SailPoint Navigate 2026: https://www.sailpoint.com/press-releases/sailpoint-unlocks-a-secure-agentic-era-with-autonomous-identity-security ; unified launch: https://itbrief.com.au/story/sailpoint-launches-unified-identity-security-for-ai-agents ; FY26 results: https://www.marketbeat.com/earnings/reports/2026-3-18-sailpoint-technologies-holdings-inc-stock/ ; https://www.barchart.com/story/news/34686711/sailpoint-announces-fiscal-second-quarter-2026-results
- Saviynt: https://www.barchart.com/story/news/36524676/saviynt-raises-700m-at-approximately-3b-valuation-in-kkr-led-round-to-establish-identity-security-as-the-foundation-for-the-ai-era ; https://saviynt.com/press-release/saviynt-identity-security-for-ai-agent-governance
- Okta: https://s205.q4cdn.com/566291348/files/doc_events/2026/Sep/23/Okta-Oktane-2026-Announcements.pdf ; https://s205.q4cdn.com/566291348/files/doc_events/2025/Sep/25/FINAL-Okta-Oktane-2025-Announcements.pdf ; https://www.msspalert.com/brief/okta-introduces-access-control-protocol-for-ai-agent-interactions
- Microsoft: https://petri.com/microsoft-entra-id-access-review-agent/ ; https://blog.admindroid.com/service-plans-for-agent-conditional-access-and-identity-protection/ ; https://www.gartner.com/en/documents/7567237 ; https://redresscompliance.com/agent-365-licensing-guide.html ; https://www.directionsonmicrosoft.com/reports/microsoft-entra-the-collected-services/
- Ping: https://press.pingidentity.com/2025-11-06-Ping-Identity-Launches-Identity-for-AI-Solution-to-Power-Innovation-and-Trust-in-the-Agent-Economy ; https://securitybrief.news/story/ping-launches-identity-for-ai-with-runtime-controls
- One Identity: https://www.scworld.com/brief/one-identity-predicts-ai-agent-breaches-tighter-controls-in-2026
- ConductorOne / C1: https://www.c1.ai/news/index.xml ; https://pulse2.com/conductorone-79-million-series-b-closed-for-scaling-ai-native-identity-security-platform
- Lumos: https://luminary.lumos.com/blog/lumos-launches-albus-ai-agent-autonomous-identity-governance ; https://www.businesswire.com/news/home/20240523314788/en/Lumos-Secures-35M-Series-B-Funding-to-Unify-the-SaaS-and-Identity-Management-Industries ; https://www.lumos.com/identity-matters/identity-governance/conductorone-competitors-and-alternatives
- Opal: https://raising.fi/news/opal-security-undisclosed-june-2026 ; https://www.caplight.com/company/opal-2
- CyberArk Secure AI Agents: https://www.businesswire.com/news/home/20251104815025/en/CyberArk-Introduces-First-Identity-Security-Solution-Purpose-Built-to-Protect-AI-Agents-with-Privilege-Controls
- Britive: https://techintelpro.com/news/britive-arc-brings-zero-standing-access-to-ai-workforce ; https://nhimg.org/community/nhi-product-announcements-forum/britive-introduces-ai-identity-security-to-govern-and-secure-agentic-ai-access-at-runtime
- Oasis Series B: https://www.newswire.com/view/content/oasis-security-raises-120m-series-b-to-secure-the-rise-of-enterprise-22748198
- Aembit: https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/ ; https://aembit.io/faq/
- Token Security: https://techcrunch.com/2025/01/27/hackers-are-targeting-machine-identities-token-security-just-raised-20m-to-stop-them
- Keycard: https://www.securityweek.com/keycard-emerges-from-stealth-mode-with-38-million-in-funding/amp/
- Astrix funding: https://pulse2.com/astrix-security-45-million-series-b-raised-to-secure-non-human-identities
- Oleria / Silverfort: https://pulse2.com/oleria-33-1-million-funding/ ; https://en.globes.co.il/en/article-1001468385

**Policy-as-code and market data**
- Cedar: https://aws.amazon.com/about-aws/whats-new/2023/05/cedar-open-source-language-access-control ; https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/terminology-differences-avp-cedar.html
- Cerbos: https://www.securityweek.com/cerbos-raises-7-5-million-for-authorization-platform/amp/ ; Permit.io: https://www.cbinsights.com/company/permitio/financials
- IGA implementation pain: https://www.cyberark.com/resources/modern-iga/the-2025-state-of-iga-survey-is-available-now ; https://nhimg.org/articles/iga-adoption-lags-because-legacy-governance-is-too-costly/ ; https://www.zluri.com/eye-on-identity/iga-implementation-timeline-how-long-does-it-take
- IGA market growth (Gartner via Pathlock): https://pathlock.com/news/pathlock-recognized-in-the-2025-gartner-market-guide-for-iga/
- Okta pricing (third-party): https://metacto.com/blogs/the-true-cost-of-okta-a-comprehensive-guide-to-pricing-and-integration

**Unverified / caveats summary:**
- Prices for Veza (~$1.0B vs. ~$1.2B), Astrix (~$400M), Entro (~$200M), Apono (>$250M) and SGNL (~$740M) are press-reported, not company-confirmed.
- Cyera–Oasis completion rests on a single source.
- Okta–Permiso and Silverfort–Fabrix deal details are unverified.
- Veza Access Agents GA is unverified.
- Okta OIG pricing ($9–11) and Microsoft Agent 365/E7 pricing are third-party figures.
- Lumos total funding is conflicting, Lumos "Identity Agent Force" is unverified, and the Britive and Clutch funding status is unknown.
- C1's open-source connector heritage (Baton) is from background knowledge and was not re-verified.
- Graph freshness claims (event-driven vs. batch) for Veza and SailPoint are not independently verified.
