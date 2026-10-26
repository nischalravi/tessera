# Tessera roadmap

The build order, as GitHub milestones. Agents pick work from the lowest milestone that still has ready issues. See `.claude/agents/product-manager.md`.

## Why this order (revised October 2026)

Identity governance for people, machines and AI agents is now table stakes. SailPoint (Agentic Fabric, Entro), Saviynt (Identity Security for AI), Okta, Microsoft and at least eight others shipped agent registries, discovery and gateways in 2025–26 ([`competitive-analysis.md`](competitive-analysis.md) §0, §5). Tessera has to cover that ground, but it cannot win on it.

Tessera wins on three things no IGA vendor does today, so they now come first:

1. **Exact, explainable effective permissions.** "Why can X do Y" answers exactly as the cloud enforces it, and its agreement with AWS is proven every night.
2. **Access as code, with pre-merge blast radius.** Roles, birthright rules, JIT eligibility, SoD rules and agent scopes are Cedar policies in Git. Every change is tested in CI and simulated against the live graph before it merges.
3. **Provable, reversible least privilege.** Unused access is found from usage evidence with an explicit confidence. It is removed in stages, restored automatically if someone needs it, and every change is verified by re-reading the target.

The plan for each, with the current state in code, the PR list, acceptance criteria and success metrics, is in [`design/differentiators-plan.md`](design/differentiators-plan.md).

The October validation still applies ([`market-watch/2026-10-iam-engineer-challenges.md`](market-watch/2026-10-iam-engineer-challenges.md)). M1 to M3 remain the foundation: sign-in and audit, real read-only data, and verified write-back. The differentiators build directly on them.

## Milestones

| Milestone | Goal | Issues | Done when |
|---|---|---|---|
| **M1 · Make Tessera safe to connect** | Platform security (Phase 0): customer separation, audit ledger, sign-in via the customer's IdP, step-up, tokens, admin hardening | #5–#19, #91 | The Phase 0 exit gate (#19) is signed off; real AWS and partner tenants can be connected |
| **M2 · Real read-only data** | Deployment readiness; production read connectors for Okta, Entra, Google, Workday, AD/LDAP and flat files; the exact AWS permission engine | #20–#31, #82–#90, #92–#99, #104, #105 | Insights, NHI and review screens run on a real tenant's data |
| **M3 · Close the loop** | Write-back verified by re-read; a kill switch; OAuth grant inventory; verified help-desk resets; MFA posture; frozen review populations; audit evidence packs; secret rotation; SSF/CAEP revocation | #89, #103, #106–#111, #113, #114 | Leaver, mover, review and rotation actions change real systems and are verified |
| **M5 · Exact AWS, proven** | Scheduled AWS collection, federated reader credentials (no stored keys), sandbox org and nightly agreement harness (#28), stratified generator at n ≥ 10,000, real-call probes for the ambiguity register, production shadow agreement, a "why" UI. Also, read-only and in parallel: CloudTrail and Access Advisor usage ingest, the confidence model, and the Cedar schema design | #636–#647, #28, #577 | Nightly real-AWS agreement has a Wilson 95% lower bound ≥ 99.5% at n ≥ 10,000 for 14 nights, every stratum ≥ 99%, and no confident-wrong verdict |
| **M6 · Access as code and blast radius** | Policy bundle and offline CLI; detection invariants in Cedar; roles, birthright, JIT eligibility, SoD and agent scopes as code; one blast-radius diff across IdP, roles, AWS and agents; Terraform plan input; a GitHub App check run; merge sync with a check that the prediction held | #648–#657 | A design partner makes every governed entitlement change by PR for 30 days, every PR gets a blast-radius diff (p95 < 60 s), and observed changes match the prediction |
| **M7 · Provable least privilege** | Design of the loop; verified right-sizing; an AWS IAM and Identity Center write target; staged revocation with caps and a kill switch; restore on denial and on JIT re-request; auto mode as code (off by default, two people to enable); recommendations as PRs; evidence | #658–#666, #569 | At a design partner over 60 days: ≥ 50% fewer unused AWS permissions, restore rate ≤ 1% with median restore < 15 min, no outage caused by a revocation, every revocation verified |
| **M8 · Azure and GCP** | The same exact evaluator, harness and gate for Azure RBAC and GCP IAM, then blast radius and least privilege for each | #667, #668 | Each cloud meets the M5 agreement gate |
| **M4 · Expansion** | Groups with full Grouper parity, guest accounts and claim, legacy IGA migration, long-tail connectors | #44–#77, #112, #115, #116, #612, #617 | Per the designs in `docs/design/` |

The critical path is M1 (#19) → sandbox and nightly harness (#28, EP-3) → the agreement gate (EP-4) → verified right-sizing (LP-3) → staged revocation (LP-5) → restore on denial (LP-6). Blast radius (AC-8) needs scheduled collection (EP-1). Automatic revocation needs usage (LP-1, LP-2), exact verdicts (EP-4), a verified writer (LP-4) and the policy repo (AC-2).

## What moved down

These are crowded or outside the target customer ([`competitive-analysis.md`](competitive-analysis.md) §5–§6). They move to M4 and wait until M5–M7 are on track:

- Guest claim: #70, #71, #72, #77
- Groups expansion: #55, #58, #59, #63
- Legacy and long-tail transports: #612 (IBM i), #617 (SFTP hardening; its security items stay in scope)
- Live checks for other sources: #93 (AD), #97 (Google), #98 (Workday); #95 (Entra) and #96 (Okta) stay, as the identity sources for the target customer
- Wizard and connector polish: #574, #594, #595, #597

Connector breadth and agent coverage stay maintained. They are expected by buyers, but they are not where new effort goes first.

## Needs a human

Issues that need real systems, credentials or paid services carry `needs-human` and wait for the founder, whatever their milestone. For M5–M8 these are:

- an AWS sandbox organization with a budget and a nightly OIDC role (#28);
- a design-partner AWS organization that approves the read role, its CloudTrail organization trail and, later, the writer role;
- a GitHub App registration for check runs;
- approval of the Cedar schema (AC-0) and the least-privilege loop design (LP-0);
- an Azure subscription and a GCP organization sandbox.

The product goal is every box in [`PRODUCT-CHECKLIST.md`](PRODUCT-CHECKLIST.md) checked, with the three differentiators proven on a design partner. The checklist validation is re-run after each milestone, and this order is revisited each time.
