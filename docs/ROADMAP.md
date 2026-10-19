# Tessera roadmap

The build order, as GitHub milestones. Agents pick work from the lowest milestone that still has ready issues. See `.claude/agents/product-manager.md`.

## Why this order

The October 2026 validation against what IAM engineers struggle with ([`docs/market-watch/2026-10-iam-engineer-challenges.md`](market-watch/2026-10-iam-engineer-challenges.md)) found that none of 79 needed capabilities was fully solved. 30 were partial, 16 were designed only, and 33 were gaps. The logic Tessera has is good and tested, but three things hold it back:

1. The API has no sign-in, and audit entries record whatever actor the caller sends.
2. Every connector is a demo connector.
3. Nothing is written back to target systems or re-read to verify.

So we make what exists real before adding new areas.

| Milestone | Goal | Issues | Done when |
|---|---|---|---|
| **M1 · Make Tessera safe to connect** | Platform security (Phase 0): customer separation, audit ledger, sign-in via the customer's IdP, step-up, tokens, admin hardening | #5–#19, #91 | An admin signs in through Okta with a passkey; every API call is authenticated and audited; tenant isolation tests pass |
| **M2 · Real read-only data** | Deployment readiness (gated, validated, reconciled connections); production read connectors for Okta, Entra, Google, Workday, AD/LDAP and flat files; the exact AWS permission engine | #20–#31, #82–#90, #92–#99, #104, #105 | Insights, NHI and review screens run on a real tenant's data; the AWS engine agrees with AWS on ≥ 99.5% of sampled checks |
| **M3 · Close the loop** | Write-back verified by re-read; a kill switch for sessions, tokens, grants and keys; OAuth grant inventory; verified help-desk resets; MFA posture; frozen review populations; audit evidence packs; secret rotation; SSF/CAEP revocation | #89, #103, #106–#111, #113, #114 | Leaver, mover, review and rotation actions change real systems and are verified; most "Partial" checklist items become "Solved" |
| **M4 · Expansion** | Groups with full Grouper parity, guest accounts and claim, legacy IGA migration, AI agent authorization | #44–#77, #112, #115, #116 | Per the designs in `docs/design/` |

Issues that need real systems, credentials or paid services carry `needs-human` and wait for the founder, whatever their milestone.

The product goal is every box in [`PRODUCT-CHECKLIST.md`](PRODUCT-CHECKLIST.md) checked: 64 capabilities in 13 areas, each with its status, evidence and the milestone that closes it. The checklist validation is re-run after each milestone, and this order is revisited each time.
