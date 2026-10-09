# Guest accounts, external identities and account claim

| | |
|---|---|
| Status | Draft for review |
| Author | iam-architect, with iam-authn-expert, iam-governance-expert and iam-protocols-expert |
| Date | 2026-10-09 |
| Phase | 2 (governance), with Phase 0 prerequisites; the hosted credential service and partner SCIM are Phase 3 |
| Requirements covered | D1·M2, M3, M10, S14, S16, C18; D2·M1, M15; D4·M1, M2, M5, M7, M11, M22; README rules 1, 4, 6, 8 |
| Reviewers to sign off | `iam-authn-expert` (§§6, 7: claim, verification, credentials, recovery, NIST 800-63-4), `iam-governance-expert` (§§3, 5, 8: intake, sponsors, matching, lifecycle), `iam-protocols-expert` (§§6.6, 7: federation, InCommon/eduGAIN, Entra B2B, Okta, SCIM), `iam-authz-expert` (§9.3: sponsor policy and IAL gating in Cedar) |

**Problem.** Every organization has people who are not employees: visitors, contractors, volunteers, applicants, admitted students, new hires before day one and staff of partner organizations. Today each of them is usually handled by a different tool (a sponsorship system, the admissions CRM, the HR onboarding portal, Entra B2B invitations), and the same person often ends up with several unlinked accounts. When a contractor becomes an employee or an applicant becomes a student, history is lost and access is re-granted by hand.

**What Tessera does.** One person, one identity, many affiliations. Each population has an intake channel, sponsor rules, a required assurance level and a lifetime. Intake goes through identity matching so a returning or converting person is **linked, not duplicated**, without letting a wrong match hand someone else's account to an attacker. A single claim flow verifies the person to the required NIST SP 800-63A-4 identity assurance level (IAL), binds a credential (passkey, password with MFA, or federated login with the person's home IdP), records terms acceptance, and connects the identity to groups and access requests.

**Exit criteria.** (1) A sponsored contractor, an applicant from the SIS, a pre-hire from the HRIS and an InCommon research partner each go from intake to first sign-in on a sandbox, at the IAL and AAL their population requires. (2) A contractor converted to an employee keeps one identity, and every earlier membership, approval and sign-in stays in its history. (3) The claim endpoints pass the enumeration, replay and rate-limit tests in §10.2. (4) Expiry, renewal and sponsor-leaver handling remove access on time, and the removal is verified in each target.

---

## Contents

1. [Summary of key decisions](#1-summary-of-key-decisions)
2. [Sources and current practice](#2-sources-and-current-practice)
3. [Populations](#3-populations)
4. [Intake](#4-intake)
5. [Identity matching, linking and merging](#5-identity-matching-linking-and-merging)
6. [The claim process](#6-the-claim-process)
7. [Credentials, MFA, terms and recovery](#7-credentials-mfa-terms-and-recovery)
8. [Lifecycle](#8-lifecycle)
9. [Data model, APIs, UI and integration with Groups and access requests](#9-data-model-apis-ui-and-integration)
10. [Threats and mitigations](#10-threats-and-mitigations)
11. [Implementation plan (ordered PRs)](#11-implementation-plan-ordered-prs)
12. [Risks](#12-risks)
13. [Open questions](#13-open-questions)
14. [Knowledge-base corrections](#14-knowledge-base-corrections)
15. [References](#15-references)

---

## 1. Summary of key decisions

| # | Decision | Why |
|---|---|---|
| K1 | **One person, one identity, many affiliations.** Guests, applicants, admits, pre-hires and partners are identities in the same warehouse as employees and students. Each relationship is an **affiliation** with its own source, sponsor, start and end. Conversion adds and ends affiliations; it never creates a second identity. | History survives conversion. Access is driven by affiliations through reference groups, so it changes automatically. |
| K2 | **Source records under persons** (the COmanage and TAP ID Match model). Each system of record contributes a *source record*; matching attaches source records to a person. Link, merge and unmerge move source records, so every merge can be undone. | Reversible merges are the main defence against the damage of a wrong match. |
| K3 | **A match is never authority.** Intake from a self-asserted channel (sponsor invite, self-registration, partner invite) can **never** auto-link to an existing identity. If it resembles one, the claimant must prove possession of that identity's credential (sign in) or a reviewer must link it and the claimant must re-verify at the existing identity's IAL. Auto-linking is allowed only between two authoritative feeds (HRIS and SIS) on authoritative identifiers. | Stops account takeover by typing a victim's email or name into an invitation. |
| K4 | **Claim links are continuation codes; verification uses fresh confirmation codes.** The invitation carries a 256-bit single-use secret in the URL **fragment**, stored only as a hash. Opening it starts a claim session. Proof of control of an email or phone uses a new 6-digit confirmation code with the NIST lifetimes (≤ 10 minutes for SMS or voice, ≤ 24 hours for email; Tessera uses 10 minutes for both). | Matches SP 800-63A-4 §3.8 (confirmation and continuation codes); the token never reaches server logs or `Referer`. |
| K5 | **Assurance is per population and per access.** Levels: **A0** (sponsor-vouched, no proofing), **IAL1**, **IAL2**. IAL2 uses an integrated IDV vendor (document plus biometric, or digital evidence such as an mDL), federation from an IdP that asserts IAL2-equivalent assurance, or on-site attended proofing by a trained proofing agent (orientation, day one). IAL3 is out of scope. Access policies can require `principal.ial >= 2`. | 800-63A-4 §4. Most guests do not need proofing; pre-hires with remote access and research data access do. |
| K6 | **No knowledge-based verification.** SP 800-63A-4 §2.5.1 says KBV "SHALL NOT be used for identity verification". Tessera never counts a knowledge check (applicant ID plus date of birth, and so on) toward an IAL. It may use one only as a fraud signal or to resume a claim, and it is labelled **weak** in the UI and the record. | The request asked for KBV "only where unavoidable, flagged as weak"; the final standard goes further, so Tessera does too. |
| K7 | **Tessera orchestrates the claim; the credential lives with a credential authority.** In order of preference: (a) the person's **home IdP** through federation (partners, InCommon/eduGAIN, Entra, Okta, Google); (b) the **customer's IdP or directory**, which Tessera provisions and hands the person into (Okta activation, an Entra Temporary Access Pass, an LDAP/AD/Kerberos password set through Tessera); (c) a **Tessera-hosted credential service** for guests only, for customers that have neither (Phase 3). | README rule 1 and D1·§8.1: integrate with IdPs rather than become one. Option (c) is D1·C19 brought forward for one narrow population. |
| K8 | **Every sponsorship has an end date and a living sponsor.** Maximum durations are per population (default 1 year, matching Michigan, Stanford and Duke practice). When a sponsor leaves, sponsorships transfer to the sponsor's manager or the unit's sponsor administrators with a deadline, and end if nobody accepts them. | README rule 6 applied to people: every guest has a human owner. |
| K9 | **Guest access is group access.** Sponsorships, affiliations and intake states maintain reference groups (`ref:guest:*`, `ref:applicant:*`, `ref:prehire:*`, `ref:partner:*`). Policy groups and access requests use them; a sponsorship's access bundle is direct memberships that end with the sponsorship. | One mechanism (the groups engine) for all access, with PIT history and verified provisioning. |
| K10 | **Public endpoints reveal nothing.** Invalid, expired, used and unknown tokens get the same response and timing. "Request a new link" and self-registration always say "if we have something for you, we emailed you". | Applicant and guest lists are sensitive (admissions decisions, visa-related visits). |

**PR sequence** (§11): GU-1 data model → GU-2 sponsorship and sponsor policy → GU-3 self-registration → GU-4 SIS and HRIS intake → GU-5 matching, review queue, link/merge → GU-6 claim core → GU-7 IDV vendor integration → GU-8 credential binding → GU-9 InCommon and eduGAIN → GU-10 terms, consent and recovery → GU-11 lifecycle → GU-12 groups and access-request integration → GU-13 UI → GU-14 B2B partner organizations.

---

## 2. Sources and current practice

**NIST SP 800-63-4** (final, 2025). Points this design relies on, from the published web text of SP 800-63A-4 and 800-63B-4:

- 800-63A-4 §2.5.1: KBV "SHALL NOT be used for identity verification" (it MAY be used inside a CSP's fraud management program, §3.2.1).
- §4.1 (IAL1): one piece of FAIR evidence that can be digitally validated or has a portrait, or one STRONG, or one SUPERIOR; validate core attributes against an authoritative or credible source; verify by one of: a confirmation code to a validated address, a microtransaction, an AAL2/FAL2 authentication to an account related to the evidence, automated or visual facial comparison, or comparison to a live sample.
- §4.2 (IAL2): one FAIR plus one STRONG, two STRONG, or one SUPERIOR; three verification pathways (non-biometric, digital evidence, biometric); CSPs should offer more than one and record which was used. Remote unattended IAL2 has no additional requirements beyond the general ones.
- §4 (IAL3): a trained proofing agent interacts directly with the applicant, on site, and collects a biometric.
- §3.8: confirmation codes have at least 6 decimal digits and live at most 10 minutes (phone), 24 hours (email), 21 or 30 days (postal); continuation codes have at least 64 bits of entropy, are stored hashed, are throttled and are single use.
- §3.2: a fraud management program is required (including death-record checks); §3.14: injection-attack and forged-media controls for remote capture; §3.15: trusted referees (SHOULD be offered when automated verification fails) and applicant references (SHALL be supported for applicants under 18).
- §5: a CSP may enrol subscribers who have not been proofed (pseudonymous accounts). That is Tessera's A0 level.
- 800-63B-4 (summarized in `docs/knowledge/01` §3.1): passwords ≥ 15 characters when single-factor and ≥ 8 when part of MFA, no composition rules, no forced rotation, blocklist check, paste allowed; email is not an out-of-band authenticator; SMS/voice is restricted; synced passkeys allowed at AAL1–AAL2; recovery must not be weaker than the AAL it restores.

**Universities.**

- *University of Michigan*: departments sponsor people for uniqnames and MCommunity profiles through the MCommunity Sponsor System; sponsored people are affiliates who are not faculty, staff, students, retirees or alumni (research collaborators, volunteers, short-term guests); maximum sponsorship is one year, renewable while active; with several sponsorships, the account expires when the last one ends; sponsorship provisions a uniqname and password, a directory profile with affiliation "Sponsored Affiliate", Google and AD accounts; some sponsored people are "Covered Visitors" under SPG 601.42 and need HR review and a background check. U-M also offers "Friend" accounts with social login for lighter-weight guests.
- *Stanford*: sponsored SUNet IDs run up to one year with start and end dates entered by the sponsor; the entry becomes invalid at the end of sponsorship with no grace period; wireless guest sponsorships run 1 to 14 days.
- *Duke*: an active faculty or staff member must sponsor; students, alumni and other affiliates cannot sponsor; sponsors accept terms and conditions; default lifetime is one year (can be shortened) with sponsor renewal; contractors are sponsored the same way.
- *Internet2 TAP and COmanage*: COmanage Registry enrolment flows (invitations, petitions, approvals) and COmanage Match, a heuristic identity-match service based on the TAP ID Match API: one matchgrid per tenant, records keyed by system of record (SOR) and SORID, each real person receives a reference identifier, and potential matches are returned as `300 Multiple Choices` (interactive resolution) or `202 Accepted` (resolved externally, with callbacks since Match 1.1.0).
- *InCommon and eduGAIN*: federation through signed SAML metadata, the REFEDS Research and Scholarship (R&S) entity category (minimal attribute bundle: persistent identifier, name, email), REFEDS Sirtfi (incident response), the REFEDS MFA profile, and the REFEDS Assurance Framework carried in `eduPersonAssurance` (identifier uniqueness, identity assurance profiles low/medium/high).

**Commercial models.**

- *Microsoft Entra B2B*: invitation redemption with a configurable identity-provider order (an Entra tenant first, then configured federation, then email one-time passcode, then a Microsoft account); email OTPs are valid for 30 minutes; entitlement management "connected organizations" let partner users request access packages and, by default, blocks a governed guest 30 days after their last assignment ends and then removes it. Guests have a **sponsors** property used in approvals.
- *Okta*: inbound federation with partner IdPs selected by IdP routing rules (by domain, attribute or app), Org2Org hub-and-spoke for partner Okta orgs, and JIT account creation with account-linking policy. Okta documents that routing rules add no security on their own.

Full citations are in §15.

---

## 3. Populations

| | Sponsored guests (visitors, contractors, volunteers) | Applicants and admits | Pre-hires | External partners (B2B, federation) |
|---|---|---|---|---|
| **Typical examples** | Conference visitor, visiting scholar, contractor developer, event volunteer | Undergraduate and graduate applicants, admitted students before matriculation | Accepted offer, start date in the future | Researchers at other universities (InCommon/eduGAIN), staff of a vendor or partner company |
| **Intake channels** | Sponsor invite (single or CSV); self-registration with sponsor approval; VMS feed for contractors | SIS or admissions CRM feed (Slate, Banner, PeopleSoft CS, Workday Student) | HRIS feed (Workday, SuccessFactors, BambooHR) with future-dated hire | Sponsor invite with home-IdP login; partner org admin invite; partner self-request with sponsor approval; partner SCIM (Phase 3) |
| **Affiliation types** | `guest_visitor`, `contractor`, `volunteer` | `applicant` → `admit` → `student` | `prehire` → `employee` | `partner` (with `partner_org_id`) |
| **Who sponsors** | Active faculty or staff in `ref:sponsor:eligible` (students, alumni and guests cannot); contractors need a sponsor in `ref:sponsor:contractor` (manager or unit admin) | The admissions office as an organizational sponsor (no individual sponsor) | The hiring manager from the HRIS record (organizational sponsor: HR) | An internal sponsor (PI, project or vendor owner), under a partner organization with its own agreement |
| **Default maximum duration** | Visitor 30 days; contractor 1 year; volunteer 1 year | Applicant: application term + 6 months unless admitted; admit: until matriculation + 30 days | Start date + 30 days if no hire event arrives | 1 year per sponsorship, capped by the partner agreement's end |
| **Default IAL** | A0 (visitors, volunteers); IAL1 (contractors); IAL2 when the access bundle contains sensitive access | A0 for the applicant portal; IAL1 at admit (validated SIS attributes plus confirmation code); IAL2 before access that needs it, via IDV or at orientation | IAL2 before any access beyond the onboarding portal (remote-hire fraud, §10.1 T12); or on-site at day one | From the home IdP: REFEDS RAF `IAP/medium` or `IAP/high`, or InCommon assurance, maps to IAL2; otherwise A0 |
| **Default AAL** | AAL1 for Wi-Fi-only visitors; AAL2 otherwise | AAL2 (passkey or password + MFA) | AAL2 | AAL2: home IdP asserts REFEDS MFA or `amr` with MFA, else Tessera step-up (§7.3) |
| **Credential** | Home IdP or social login (visitors); customer IdP account (contractors, volunteers) | Customer IdP account created at admit or deposit; applicant portal may use social login | Customer IdP account, activated in the claim flow | Home IdP only; no local password |
| **Ends when** | Sponsorship ends, is revoked, or the sponsor leaves without transfer | Application withdrawn or denied, or matriculation (affiliation converts) | Hire event (converts), or rescinded offer | Sponsorship or partner agreement ends; partner deprovisioning signal |

All defaults are tenant settings per population and are enforced by sponsor policy (§4.3).

---

## 4. Intake

### 4.1 Channels

| Channel | Who starts it | What Tessera receives | Matching mode (§5.2) |
|---|---|---|---|
| **Sponsor invite** | A sponsor in Access → Guests I sponsor | Name, invited email, population, purpose, end date, access bundle; optional phone, company, country | self-asserted |
| **Bulk sponsor invite** | A sponsor uploads CSV (≤ 500 rows) | Same, per row | self-asserted |
| **Self-registration with sponsor approval** | The guest, on a public page linked from an event or department site | Name, email, requested sponsor (picked from a sponsor-searchable list, or a sponsorship code the sponsor shared), purpose, dates | self-asserted; nothing is created until the sponsor approves |
| **SIS/CRM feed** | The SIS connector | Applicant ID, legal and preferred name, date of birth, personal email and phone, term, program, status (applied, admitted, deposited, matriculated, withdrawn) | authoritative |
| **HRIS feed** | The HRIS connector | Worker ID, legal and preferred name, personal email and phone, start date, position, manager, worker type | authoritative |
| **VMS feed** | A VMS connector or CSV (Fieldglass, Beeline) | Contractor ID, name, company, work email, end date, sponsor | authoritative for contractor ID, self-asserted for the rest |
| **Partner invite** | A sponsor or partner org admin | Name, email, partner org; the identity binds at first federated login | federated (binding to `(issuer, subject)` at claim) |
| **Partner SCIM** (Phase 3) | The partner's IdP pushes users | SCIM User with `externalId` | authoritative within the partner org namespace |

Every channel produces an **intake record** (§9.1) and runs matching before anything else is created.

### 4.2 Required attributes

| Population | Required | Optional | Never collected |
|---|---|---|---|
| Visitor | display name, email, purpose, end date | phone, home institution | DOB, government ID |
| Contractor | legal name, email, company, end date, sponsor | phone, contract/PO number, country of citizenship (only if export-control policy requires it) | government ID numbers (IDV vendor holds evidence; Tessera keeps references) |
| Volunteer | legal name, email, program, end date | phone, DOB (only for programs with minors that require background checks) | |
| Applicant / admit | applicant ID, legal name, DOB, personal email, term | phone, preferred name | SSN unless the institution's matching policy requires an HMAC of it (§5.3) |
| Pre-hire | worker ID, legal name, personal email, start date, manager | phone, preferred name, DOB | |
| Partner | email (invite) or federated identifier, name, partner org | `eduPersonScopedAffiliation`, `eduPersonAssurance`, ORCID | |

Data minimization rules: DOB and phone are stored encrypted (`seal`, Phase 0) and shown masked; matching uses keyed hashes where possible (§5.3); fields marked optional are off unless the tenant enables them.

### 4.3 Sponsor rules

Sponsor policy lives in the tenant's policy repository as Cedar (the same repo as policy groups in `groups-grouper-parity.md` §8), with defaults shipped by Tessera:

```cedar
// policies/guests/sponsor.cedar
@id("contractor-sponsors")
permit (principal, action == Tessera::Action::"sponsor", resource is Tessera::SponsorshipRequest)
when {
  resource.population == "contractor" &&
  principal in Tessera::Group::"ref:sponsor:contractor" &&
  resource.durationDays <= 365 &&
  principal.activeSponsorships.contractor < 25
};

@id("no-self-sponsor")
forbid (principal, action == Tessera::Action::"sponsor", resource is Tessera::SponsorshipRequest)
when { resource has matchedIdentity && resource.matchedIdentity == principal };

@id("sensitive-bundles-need-ial2")
forbid (principal, action == Tessera::Action::"sponsor", resource is Tessera::SponsorshipRequest)
when { resource.bundleSensitivity == "high" && resource.requiredIal < 2 };
```

Rules every tenant can configure (the defaults in brackets):

- **Who can sponsor**: membership in a sponsor reference group per population [`ref:sponsor:eligible` = active faculty and staff; contractors need `ref:sponsor:contractor`]. Guests, students, alumni and other sponsored identities cannot sponsor [Duke's rule].
- **Limits**: maximum active sponsorships per sponsor per population [visitor 50, contractor 25, volunteer 100]; maximum invites per day [50].
- **Maximum duration** per population [§3]; renewals are new terms, each up to the maximum.
- **Approval**: whether a sponsorship needs a second approver (unit sponsor admin) [contractors: yes when the bundle contains privileged or sensitive access; others: no].
- **Access bundles**: which groups and access packages a population may receive, and the IAL/AAL each bundle requires.
- **Covered-visitor checks**: a population or bundle can require an external check (background check, export-control screening) recorded as an approval step with an attestation from HR or the compliance office (the Michigan SPG 601.42 pattern). Tessera stores the result reference, not the report.

Policy decisions record the policy version (README rule 2). Sponsors accept sponsor terms once per year [Duke's sign-off requirement].

---

## 5. Identity matching, linking and merging

### 5.1 Model

```
Person (identities row)  ◀── link ──  Source record (identity_source_records)
   id 4711                              (sor="hris",  sorid="W000123")
                                        (sor="sis",   sorid="A2026-77812")
                                        (sor="sponsorship", sorid="sp_9f2…")
                                        (sor="federation", sorid="https://idp.example.edu/idp/shibboleth!a7c3…")
```

- A **source record** holds what one source said about the person (attributes, identifiers, status, timestamps). It is never edited by another source.
- A **person** (the existing `identities` table) holds the reconciled view, with per-attribute authority (D4·M1).
- **Identifiers** (`identity_identifiers`) are typed and carry how they were verified (email confirmation code, federation, HRIS authoritative, and so on).

### 5.2 Matching modes

Matching runs on every intake record, before anything is created or granted, in one of three modes:

| Mode | Applies to | Allowed outcomes |
|---|---|---|
| **authoritative** | HRIS, SIS, VMS contractor ID, partner SCIM `externalId` | Tier A auto-link; Tier B auto-link only if the tenant enables it **and** both sides are authoritative sources; otherwise review |
| **self-asserted** | Sponsor invites, self-registration, partner invites | **No auto-link ever.** Tier A/B/C produce a *suspected existing person* flag (§5.5) |
| **federated** | First login from a home IdP | Auto-bind on an existing `(issuer, subject)` binding; otherwise as self-asserted |

### 5.3 Rules and confidence tiers

Rules are configured per tenant and evaluated in order; each produces a tier and an explanation. Defaults:

| Tier | Rule (any of) | Typical case |
|---|---|---|
| **A: exact** | Same source and SORID already linked (re-sent record) · same authoritative identifier across sources that share it (for example the SIS and HRIS both carry the university ID) · same federated `(issuer, pairwise-id or subject-id)` already bound · **the claimant authenticated as the existing person during the claim** ("link by sign-in") | Rehire; an applicant record re-sent; a student worker in the HRIS |
| **B: strong** | Same keyed hash of a national identifier (SSN/SIN/NI) **and** same DOB · same verified personal email **and** same DOB **and** name similarity ≥ 0.92 (Jaro-Winkler on normalized names, with transposition-tolerant DOB comparison) | Guest becomes employee; admit is already a guest |
| **C: possible** | Name similarity ≥ 0.85 **and** DOB · same verified email only · same verified phone only | Common names, shared family emails |
| **D: none** | No rule matched | New person |

- National identifiers, when a tenant chooses to use them, are stored only as `HMAC-SHA-256(tenant_match_key, normalized_value)`; the key is sealed and rotatable (re-keying recomputes from sources that still hold the value).
- Names are normalized (Unicode NFKC, case folding, diacritics removed for comparison, given and family name order variants), and preferred names are compared as well as legal names.
- Every result stores the rules that fired, the compared attributes (masked) and the score. "Why did this match" is answerable for every link.

### 5.4 Link, merge and unmerge

- **Link**: attach a new source record to an existing person. Used for Tier A and for reviewer decisions.
- **Merge**: two persons are found to be one. The **survivor** keeps its ID; the other becomes `lifecycle_state='merged'` with `merged_into`. Source records, identifiers, affiliations, sponsorships, direct group memberships, accounts, access requests, terms acceptances and NHI ownership move to the survivor in one transaction, with one event per moved item and one audit ledger entry listing all of them. Group memberships move through the groups engine (`groups-grouper-parity.md` §6), which also gives G-15 (member change subject) its implementation.
- **Credentials do not move.** The merged person's sessions and federated bindings are revoked and its credentials are disabled in their authority; the survivor's credentials are unchanged. Both contact channels on record are notified of the merge.
- **Unmerge** (within 180 days by default, longer by setting) replays the recorded move list in reverse. Items created after the merge stay with the survivor and are listed for a reviewer.
- **Four eyes**: a merge or a reviewer link into a person who holds privileged access, has IAL2 or higher, or is an employee needs a second reviewer.

### 5.5 Avoiding account takeover through a wrong match

A wrong link would give the claimant everything the existing person has. The rules that prevent it:

1. **Self-asserted intake never auto-links** (K3). An invite to `alice@gmail.com` that matches Alice the employee does not touch Alice's identity.
2. A **suspected existing person** changes the claim flow, invisibly to the claimant: the claim can complete only by (a) **signing in** with the existing person's credential, which links the intake by proof of possession (Tier A "link by sign-in"), or (b) creating a **new, separate** identity at the population's IAL, with the suspicion recorded for a reviewer; or (c) if the population requires it, waiting for reviewer decision. The claimant is never told that a match exists.
3. **Reviewer links require re-verification at the existing person's IAL** before the claimant gets any credential of that person. An IAL2 employee cannot be linked to a claimant who proved only email control.
4. **Credentials never transfer** in a merge (§5.4).
5. **Notifications** go to the existing person's verified channels whenever a link or merge happens, with a "this wasn't me" path that freezes the change and opens an incident.
6. **Merges are reversible** (§5.4) and audited.

### 5.6 Review queue

Inbox → **Identity matches**: one item per intake record with Tier B or C candidates (and Tier A when the tenant requires review). The item shows the intake and each candidate side by side with masked attributes, which rules fired, the source of each value, the candidate's affiliations, privileged access and IAL, and recent activity. Decisions: **link to candidate**, **new person**, **reject intake** (fraud, duplicate request). A reason is required. SLA defaults: 2 business days, with escalation to the identity team. While an item is pending, authoritative intake (HRIS, SIS) still creates a provisional identity that cannot claim or receive access; self-asserted intake waits.

### 5.7 Interoperability

An optional endpoint implements the TAP ID Match API shape (`PUT /match/api/1/v1/people/{sor}/{sorid}`, `300` for potential matches, `202` for externally resolved requests) so that a COmanage Registry, or another registry, can use Tessera as its match service during a migration. Phase 2, last PR in the matching work (GU-5), behind a tenant flag.

---

## 6. The claim process

### 6.1 Overview

```
 intake ─▶ matching ─▶ sponsorship approved / feed eligible ─▶ invitation issued
                                                                     │
                       claim link (email)  or  claim code (letter)   ▼
 ┌────────────── claim session (cookie, 60 min idle, 24 h max) ─────────────────┐
 │ 1 start: exchange token ─▶ 2 verify contact (confirmation code)              │
 │ ─▶ 3 identity verification to the population's IAL (if > A0)                 │
 │ ─▶ 4 suspected-match branch (sign in as existing person, or continue new)    │
 │ ─▶ 5 terms and consent ─▶ 6 credential (home IdP / customer IdP / hosted)    │
 │ ─▶ 7 MFA enrolment check (AAL) ─▶ 8 recovery setup ─▶ 9 complete             │
 └──────────────────────────────────────────────────────────────────────────────┘
          ─▶ identity active, affiliation active, groups and provisioning run
```

### 6.2 Claim links and codes

| Property | Claim link | Claim code |
|---|---|---|
| Format | `https://<tenant host>/claim#t=<43 chars base64url>` (256 bits from `crypto/rand`) | 16 Crockford base32 characters in 4 groups (80 bits), for letters and in-person handover |
| Where the secret travels | URL **fragment** only: not sent in the HTTP request line, not logged, not in `Referer`. The claim page's script posts it to `POST /public/t/{slug}/claim/start` and removes it from the address bar with `history.replaceState`. | Typed into the claim page together with the invited email address |
| Storage | `SHA-256(token)` only, with the tenant ID as a domain-separation prefix | Same |
| Use | **Single use**: `start` atomically moves the token from `issued` to `consumed` (`UPDATE … WHERE status='issued' AND expires_at > now RETURNING`) and creates a claim session | Same; also locks after 5 failed attempts across the email+code pair |
| Lifetime | Visitor 7 days; contractor, volunteer, partner 14 days; applicant 30 days; pre-hire from start − 14 days to start + 7 days | Pre-hire letters: same window |
| Re-issue | A new invitation revokes all earlier tokens for the same intake | Same |
| Binding | Bound to the intake record and the invited email's hash; the confirmation code in step 2 goes to that email | Same |

These are **continuation codes** in 800-63A-4 terms (§3.8: ≥ 64 bits, hashed, throttled, single use). They prove nothing about identity on their own; step 2 does.

**Claim session.** `__Host-tessera_claim` cookie (Secure, HttpOnly, SameSite=Lax), 60 minutes idle and 24 hours absolute, bound to the intake and to a per-session DPoP-style key held by the page (WebCrypto non-extractable key, signed request header) so a stolen cookie alone does not work. If the session is lost, the person asks for a new link (§6.4).

### 6.3 Verification steps by assurance level

| Level | Step 2: contact | Step 3: identity | Recorded as |
|---|---|---|---|
| **A0** (sponsor-vouched) | 6-digit confirmation code to the invited email (10 min) | none; the sponsor's attestation is recorded | `ial=0`, `vouched_by=sponsor` |
| **IAL1** | Confirmation code to a **validated** email or phone from the authoritative record (SIS, HRIS, VMS); 10 minutes for both | Core attributes validated against the authoritative source; verification = the confirmation code to the validated address (800-63A-4 §4.1.6), **or** an AAL2/FAL2 federated login to an account related to the evidence (for example the person's existing university account) | `ial=1`, method, evidence source |
| **IAL2** | As IAL1 | One of: **(a) IDV vendor**, biometric pathway (document capture with live capture, PAD liveness, face comparison, injection-attack detection, per §3.14) or digital evidence pathway (mDL or EUDI wallet through OpenID4VP / the Digital Credentials API, with issuer signature validation); **(b) federation** from an IdP that asserts IAL2-equivalent proofing (REFEDS RAF `https://refeds.org/assurance/IAP/medium` or `/high`, or an InCommon-certified assurance profile) at AAL2/FAL2; **(c) on-site attended** proofing by a trained proofing agent in Tessera's proofing-agent screen (document inspection checklist and visual comparison), for orientation and day one; **(d) trusted referee** (a trained help-desk agent over supervised video) when (a) fails, per §3.15 | `ial=2`, pathway, vendor and result reference, agent ID for (c)/(d) |
| **KBV** | n/a | **Not available as verification** (K6). A knowledge check (applicant ID + DOB) may be used to resume an expired claim session or as a fraud signal, and is recorded as `weak_signal` | never raises `ial` |

Evidence handling: Tessera stores the vendor's decision, the evidence types, the pathway, scores and the vendor transaction reference (`ProofingResult`, D1·§8.3), **not** document images or selfies. Vendor contracts must allow deletion on request and set retention. The vendor must document compliance with 800-63A-4 §3.14 (injection and forged-media detection) and independent PAD testing (ISO/IEC 30107-3).

**Minors** (for example applicants under 18, volunteers in youth programs): 800-63A-4 §4.5 requires CSPs to support applicant references for minors. Tessera supports an **applicant reference** step where a parent or guardian, proofed to the same or a higher IAL, vouches for the minor. Tenants decide whether minors may claim at all.

### 6.4 Rate limits and enumeration resistance

| Endpoint | Limits (defaults) | Response for unknown, expired, used or locked |
|---|---|---|
| `POST /claim/start` | 10 per IP per 10 min; 100 per tenant per minute before a bot challenge appears | Always `200 {"next":"check_link"}` after a constant-time path (dummy hash lookup and a fixed minimum duration of 300 ms) |
| `POST /claim/code` (claim code + email) | 5 attempts per email+code pair, then locked; 20 per IP per hour | Same generic response |
| `POST /claim/verify/send` (confirmation code) | 3 per session per 10 min; 5 per destination per hour; 10 per destination per day | Same response whether or not a message was sent |
| `POST /claim/verify/check` | 5 attempts per code, then the code is void; codes compared in constant time | Generic failure |
| `POST /claim/resend` ("send me a new link") | 3 per email per day | "If an invitation exists for this address, we have sent a new link." |
| `POST /register` (self-registration) | 5 per IP per hour; bot challenge (Turnstile or equivalent) | "Check your email." If the email already belongs to someone, the email says "you already have an account, sign in" instead of creating anything |

Limits use the Phase 0 `ratelimit` package keyed by IP, session, destination hash and tenant. Every throttle event is audited (without the code or token).

### 6.5 Suspected existing person

If matching flagged the intake (§5.5), step 4 offers: "Do you already have an account with *Tenant name*?" (always asked, for every claimant, so its presence leaks nothing). **Yes** starts a sign-in with the tenant's IdP; on success, Tessera checks that the authenticated person is a candidate from the match, links by sign-in, and skips credential creation. **No** continues as a new identity, and the suspicion stays in the review queue.

### 6.6 Federated claim (partners, InCommon, eduGAIN)

- The claim page offers the person's home organization through a discovery service (SeamlessAccess for research and education federations; email-domain routing for known partner organizations).
- SAML: metadata from the InCommon aggregate or MDQ, signature-verified against the pinned federation signing key, with entity categories and registration authority recorded. Tessera's SP requests the **REFEDS MFA** authentication context when the population requires AAL2, and checks it in the response.
- Identifier: SAML `pairwise-id` or `subject-id` (OASIS SAML V2.0 Subject Identifier Attributes Profile) preferred; `eduPersonUniqueId` next; `eduPersonPrincipalName` only with RAF `ID/unique` and `ID/no-eppn-reassign`. Scoped attributes must match the IdP's `shibmd:Scope`. Email is never the binding key.
- OIDC partners (Entra, Okta, Google Workspace): `(iss, sub)`; for Entra multi-tenant, also `tid`.
- The binding `(issuer, subject)` is stored as an identifier with `verified_by=federation`, and the person's AuthnContext at claim is recorded.

---

## 7. Credentials, MFA, terms and recovery

### 7.1 Credential authorities

| Authority | When | How the claim binds it | MFA |
|---|---|---|---|
| **Home IdP** (federation) | Partners, research collaborators, visitors who prefer it | Store the `(issuer, subject)` binding; future sign-ins to Tessera-protected apps go through the tenant IdP's federation (Entra B2B, Okta IdP routing, Shibboleth proxy) | From the home IdP (REFEDS MFA, `amr`); else step-up (§7.3) |
| **Customer IdP / directory** | Contractors, volunteers, admits, pre-hires | Tessera provisions the account (`groups-grouper-parity.md` §9.2 and D4·M8), then hands the person into the IdP's own activation: **Okta**: create the user without sending email, take the activation token, redirect to Okta's activation and authenticator enrolment; **Entra ID**: create the user and issue a **Temporary Access Pass** through Microsoft Graph, which the person uses to register a passkey or Microsoft Authenticator; **Google Workspace**: create the user and redirect to the set-password and 2-Step Verification enrolment; **LDAP / AD / Kerberos** (common at universities): the claim page collects a password that meets §7.2 and sets it over LDAPS or kpasswd; it is never stored or logged by Tessera | The IdP's enrolment; Tessera checks the resulting AuthnContext at the first sign-in after claim |
| **Tessera-hosted credential service** (Phase 3) | Guests at customers with no suitable IdP for external people | An OIDC provider for guests only, passkey first, password + TOTP as fallback, recovery codes; built either on `go-webauthn` (already used for Phase 0 break-glass) or an embedded open-source core (open question 1) | Built in |

The claim is **complete** only when Tessera has seen a sign-in at the population's required AAL through the bound authority. Until then the identity stays `pending_claim` and no access bundle is provisioned beyond the onboarding groups.

### 7.2 Passwords (when a password is set through Tessera)

Following SP 800-63B-4 (knowledge doc 01 §3.1):

- Minimum 15 characters if the password will be the only factor; 8 if the account requires MFA (Tessera requires MFA for every population above A0, so 8 is the floor; tenants may set 12 or 15). Maximum at least 64 characters.
- All printable ASCII, space and Unicode accepted, normalized with NFKC before hashing and checking; each code point counts as one character.
- **No composition rules, no periodic rotation, no hints, no security questions.**
- Checked against a blocklist (common passwords, the tenant name, the person's names and identifiers, and a breached-password corpus queried through a k-anonymity range API or a local Bloom filter), with the reason shown.
- Paste and password managers allowed; a show-password toggle.
- Transmitted only over TLS to the claim endpoint, passed directly to the directory's password operation, zeroed after use, and excluded from logs, traces and audit details.

### 7.3 MFA and passkeys

- **Passkeys are the default** offered first in every authority that supports them. Synced passkeys meet AAL2; device-bound keys with attestation are required for AAL3, which no guest population uses by default.
- Other second factors: authenticator app (TOTP) and security keys. **SMS and voice OTP** are allowed only where the tenant enables them for a population, never for privileged bundles, with SIM-swap and porting signals checked where the carrier data is available. **Email OTP is not an authenticator** (800-63B-4) and is used only as a contact confirmation code.
- **Federated MFA gap.** If a partner's home IdP cannot assert MFA and the access needs AAL2, the population setting chooses: deny with an explanation to the partner's IT contact, or **step-up**: the person enrols a passkey with the Tessera-hosted credential service (Phase 3), used as a second factor after the federated login (the Entra B2B "MFA trust" pattern in reverse).

### 7.4 Terms and consent

- Terms documents (acceptable use, privacy notice, population-specific agreements such as a contractor confidentiality notice) are versioned, stored with a SHA-256 of their rendered text, and assigned to populations and access bundles.
- Acceptance happens in claim step 5, **before** a credential is bound. The acceptance (identity, document ID and hash, time, claim session, IP and user-agent hash) is written to the audit ledger and to `terms_acceptances`.
- A new version of a document triggers re-acceptance at the next sign-in, with a grace period set per document.
- **Attribute release consent** for federated logins shows which attributes the home IdP released and why; R&S-tagged SP behaviour is followed for research collaboration.
- For EU partners, the privacy notice states the GDPR lawful basis per attribute; consent is recorded only where consent is actually the basis.

### 7.5 Recovery

Recovery must not be weaker than the AAL it restores (800-63B-4 §4.2):

- **Federated identities** recover at their home IdP. Tessera does not offer a separate reset.
- **Customer-IdP identities** use the IdP's recovery (second passkey, recovery codes, TAP issued by the help desk). Tessera adds a **re-claim** path: a sponsor or the help desk issues a `purpose=recovery` claim token, and the person must re-verify at the identity's recorded IAL (IAL2 identities repeat IDV or see a proofing agent); all channels on record are notified, and accounts with privileged bundles have a 24-hour cooling-off before the new credential is active.
- **Hosted-service identities** get 10 single-use recovery codes at enrolment (shown once, stored hashed) and may register a second passkey.
- Help-desk verification follows D1·S14 (push to an enrolled passkey or re-proofing, never "verify your sponsor's name").

---

## 8. Lifecycle

### 8.1 States

```
prospective ─▶ invited ─▶ pending_claim ─▶ active ─▶ expiring ─▶ expired ─▶ deprovisioned
     │             │             │            │  ▲         │                    │
     │             └─ revoked ◀──┴────────────┤  └─renewed─┘                    └─▶ (retention) ─▶ purged
     └─ rejected                              └─ suspended (sponsor, security)
merged (terminal, points to survivor)
```

The state is derived from affiliations: an identity is `active` while at least one affiliation is active; `expiring` when the last active affiliation ends within the notice window.

### 8.2 Expiry and renewal

- Each sponsorship has `ends_at` ≤ the population's maximum. The access bundle's direct memberships carry `disabled_at = ends_at`, so the groups engine removes access on time (`groups-grouper-parity.md` §6.4: at most 60 seconds late).
- Reminders to the sponsor at 30, 14 and 3 days before the end, and to the guest at 14 days (with a "request renewal" link that creates an Inbox task for the sponsor).
- **Renewal** re-runs sponsor policy (the sponsor must still be eligible, within limits), extends `ends_at` by up to the maximum, and records a fresh justification. A renewal of a bundle that now requires a higher IAL sends the guest through a step-up claim before the bundle continues.
- **Several sponsorships**: the identity stays active until the last one ends (the Michigan rule). Each sponsorship's bundle ends independently.

### 8.3 Sponsor leaves or changes role

On a JML **leaver** or **mover** event for a sponsor (or the sponsor losing `ref:sponsor:*` eligibility):

1. Each active sponsorship gets an Inbox **transfer task** for the sponsor's manager and the unit's sponsor admins, with a deadline (default 14 days).
2. Accepting moves the sponsorship (audited, new sponsor policy check). Declining or the deadline passing **ends** the sponsorship on the deadline (default) or **suspends** it (tenant setting).
3. A sponsorship is never left without a living sponsor. The governance dashboard counts "sponsorships pending transfer" and "auto-ended by sponsor departure".

### 8.4 Conversion without losing history

| Conversion | Trigger | What changes | What stays |
|---|---|---|---|
| Applicant → admit | SIS status `admitted` | Affiliation `applicant` ends, `admit` starts; IAL requirement may rise (claim step-up) | Identity, credential, application-era audit |
| Admit → student | SIS status `matriculated` or term start | `admit` ends, `student` starts; student birthright through `ref:student:*` groups | Same identity, NetID, credential |
| Pre-hire → employee | HRIS hire effective date | `prehire` ends, `employee` starts; onboarding-only groups end, birthright groups start | Identity, credential claimed before day one, day-one IAL upgrade |
| Guest/contractor → employee | HRIS hire for a person who matches the guest (Tier A by sign-in if the person claims the employee invitation while signed in as the guest; otherwise review) | `employee` starts; contractor sponsorship ends at the hire date (or continues if the sponsor confirms dual status) | One identity: all prior memberships, approvals, sign-ins and reviews in PIT history |
| Employee → guest (retiree, emeritus, visiting after leaving) | Sponsorship of a former employee | New `guest_*` affiliation on the same identity; leaver deprovisioning already ran | History; the credential, if the IdP account is kept |
| Partner → employee | HRIS hire matched to the partner identity | Same pattern as guest; the federated binding stays as a second identifier | History |

Conversions are ordinary affiliation changes, so they emit JML events (`conversion`, D4·§8.3) and the reference groups update through the engine.

### 8.5 Deprovisioning

When the last affiliation ends:

1. **Immediately**: sponsorship-sourced memberships end (they already had `disabled_at`), time-bound access-request grants end, sessions are revoked through the IdP's API (and through SSF/CAEP in Phase 3), and accounts in targets are **disabled** through provisioning, verified by re-read (README rule 4).
2. After the **grace period** (default 30 days; 0 for visitors): accounts are deleted or left disabled per target policy; NHI and group ownership held by the person is reassigned (README rule 6); the identity becomes `deprovisioned`.
3. After the **retention period** (default 7 years for anyone who held access to in-scope systems, 1 year for visitors with Wi-Fi only): PII is purged to a tombstone (ID, affiliation history, hashes of identifiers kept only if the tenant enables re-match on return).

A guest who returns within the retention period is matched (Tier A on identifiers or by sign-in) and gets the same identity back.

---

## 9. Data model, APIs, UI and integration

### 9.1 Data model (SQLite DDL; Go structs follow the same fields)

```sql
-- internal/store/schema/0201_guests.sql
ALTER TABLE identities ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'active'
  CHECK (lifecycle_state IN ('prospective','invited','pending_claim','active','expiring','suspended',
                             'expired','deprovisioned','rejected','revoked','merged','purged'));
ALTER TABLE identities ADD COLUMN ial INTEGER NOT NULL DEFAULT 0 CHECK (ial IN (0,1,2,3));
ALTER TABLE identities ADD COLUMN ial_evidence_ref TEXT;
ALTER TABLE identities ADD COLUMN merged_into INTEGER REFERENCES identities(id);
ALTER TABLE identities ADD COLUMN subtype TEXT;            -- 'guest','partner','entity', … (also used by groups)

CREATE TABLE identity_source_records (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants(id),
  identity_id  INTEGER REFERENCES identities(id),           -- null while pending review
  sor          TEXT NOT NULL,                               -- hris | sis | vms | sponsorship | selfreg | federation | partner_scim | grouper
  sorid        TEXT NOT NULL,
  attributes   TEXT NOT NULL,                               -- JSON, sealed fields marked
  status       TEXT NOT NULL,
  received_at  TEXT NOT NULL,
  UNIQUE (tenant_id, sor, sorid)
);

CREATE TABLE identity_identifiers (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL REFERENCES tenants(id),
  identity_id   INTEGER NOT NULL REFERENCES identities(id),
  type          TEXT NOT NULL,   -- email | phone | employee_id | student_id | applicant_id | netid | eppn | saml_subject_id | saml_pairwise_id | oidc_sub | national_id_hmac
  issuer        TEXT NOT NULL DEFAULT '',                   -- for federated identifiers
  value_norm    TEXT,                                       -- null for hashed-only types
  value_hmac    TEXT NOT NULL,                              -- HMAC(tenant_match_key, normalized value)
  verified_at   TEXT,
  verified_by   TEXT,            -- confirmation_code | federation | authoritative_source | proofing_agent
  source_record_id TEXT REFERENCES identity_source_records(id),
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
  UNIQUE (tenant_id, type, issuer, value_hmac)
);

CREATE TABLE affiliations (
  id             TEXT PRIMARY KEY,
  tenant_id      TEXT NOT NULL REFERENCES tenants(id),
  identity_id    INTEGER NOT NULL REFERENCES identities(id),
  type           TEXT NOT NULL,   -- employee | student | applicant | admit | prehire | contractor | guest_visitor | volunteer | partner | alum | retiree
  source         TEXT NOT NULL,   -- hris | sis | sponsorship | partner_org | manual
  source_ref     TEXT,            -- sponsorship id, source record id
  org_unit       TEXT,
  partner_org_id TEXT,
  starts_at      TEXT NOT NULL,
  ends_at        TEXT,
  status         TEXT NOT NULL CHECK (status IN ('pending','active','ended','revoked'))
);
CREATE INDEX affiliations_identity ON affiliations(tenant_id, identity_id, status);
CREATE INDEX affiliations_ending ON affiliations(tenant_id, ends_at) WHERE status = 'active';

CREATE TABLE sponsorships (
  id                  TEXT PRIMARY KEY,
  tenant_id           TEXT NOT NULL REFERENCES tenants(id),
  guest_identity_id   INTEGER REFERENCES identities(id),     -- null until matching resolves
  intake_id           TEXT NOT NULL,
  sponsor_identity_id INTEGER REFERENCES identities(id),     -- null for organizational sponsors
  sponsor_org         TEXT,                                  -- 'admissions', 'hr', partner org id
  population          TEXT NOT NULL,
  purpose             TEXT NOT NULL,
  access_bundle       TEXT NOT NULL DEFAULT '[]',            -- JSON: group names, access packages
  required_ial        INTEGER NOT NULL,
  required_aal        INTEGER NOT NULL,
  starts_at           TEXT NOT NULL,
  ends_at             TEXT NOT NULL,
  status              TEXT NOT NULL CHECK (status IN ('requested','pending_approval','approved','active',
                       'renewal_pending','transfer_pending','ended','revoked','rejected')),
  policy_version      TEXT NOT NULL,
  created_by          TEXT NOT NULL,
  created_at          TEXT NOT NULL
);

CREATE TABLE intake_records (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL REFERENCES tenants(id),
  channel       TEXT NOT NULL,  -- sponsor_invite | bulk_invite | self_registration | sis | hris | vms | partner_invite | partner_scim
  match_mode    TEXT NOT NULL CHECK (match_mode IN ('authoritative','self_asserted','federated')),
  source_record_id TEXT REFERENCES identity_source_records(id),
  submitted_by  TEXT,
  status        TEXT NOT NULL CHECK (status IN ('received','matching','review','resolved','rejected')),
  created_at    TEXT NOT NULL
);

CREATE TABLE match_results (
  id                TEXT PRIMARY KEY,
  tenant_id         TEXT NOT NULL REFERENCES tenants(id),
  intake_id         TEXT NOT NULL REFERENCES intake_records(id),
  candidate_id      INTEGER REFERENCES identities(id),
  tier              TEXT NOT NULL CHECK (tier IN ('A','B','C','D')),
  rules             TEXT NOT NULL,                  -- JSON: rules fired, compared attributes (masked), scores
  decision          TEXT CHECK (decision IN ('auto_link','link','new','reject','suspected')),
  decided_by        TEXT, second_reviewer TEXT, reason TEXT, decided_at TEXT
);

CREATE TABLE identity_merges (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
  survivor_id INTEGER NOT NULL, merged_id INTEGER NOT NULL,
  moves TEXT NOT NULL,                              -- JSON list of moved items, for unmerge
  reason TEXT NOT NULL, actor TEXT NOT NULL, second_actor TEXT,
  merged_at TEXT NOT NULL, unmerged_at TEXT, audit_seq INTEGER NOT NULL
);

CREATE TABLE claim_tokens (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants(id),
  intake_id    TEXT NOT NULL,
  identity_id  INTEGER,
  kind         TEXT NOT NULL CHECK (kind IN ('link','code')),
  purpose      TEXT NOT NULL CHECK (purpose IN ('claim','renewal_stepup','recovery')),
  token_hash   TEXT NOT NULL UNIQUE,                -- SHA-256("tessera-claim-v1|" || tenant || "|" || token)
  email_hmac   TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  status       TEXT NOT NULL CHECK (status IN ('issued','consumed','revoked','expired','locked')),
  not_before   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  consumed_at  TEXT,
  created_at   TEXT NOT NULL
);

CREATE TABLE claim_sessions (
  id_hash      TEXT PRIMARY KEY,                    -- hash of the cookie value
  tenant_id    TEXT NOT NULL,
  token_id     TEXT NOT NULL REFERENCES claim_tokens(id),
  key_jkt      TEXT NOT NULL,                       -- thumbprint of the page's WebCrypto key
  step         TEXT NOT NULL,
  verified     TEXT NOT NULL DEFAULT '{}',          -- JSON: channels confirmed, IAL achieved, pathway
  created_at   TEXT NOT NULL, last_seen_at TEXT NOT NULL, expires_at TEXT NOT NULL
);

CREATE TABLE confirmation_codes (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, session_id_hash TEXT NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('email','sms','voice')),
  destination_hmac TEXT NOT NULL, code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL, used_at TEXT
);

CREATE TABLE proofing_results (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, identity_id INTEGER, intake_id TEXT,
  pathway TEXT NOT NULL,          -- biometric | digital_evidence | non_biometric | federation | onsite_agent | trusted_referee
  provider TEXT, provider_ref TEXT, ial_achieved INTEGER NOT NULL,
  evidence_types TEXT NOT NULL, decision TEXT NOT NULL, scores TEXT,
  agent_identity_id INTEGER, decided_at TEXT NOT NULL, retention_expiry TEXT NOT NULL
);

CREATE TABLE credential_bindings (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, identity_id INTEGER NOT NULL,
  authority TEXT NOT NULL CHECK (authority IN ('home_idp','customer_idp','hosted')),
  connection_id TEXT NOT NULL, external_subject TEXT NOT NULL,
  aal_observed INTEGER, first_signin_at TEXT, created_at TEXT NOT NULL, revoked_at TEXT,
  UNIQUE (tenant_id, connection_id, external_subject)
);

CREATE TABLE terms_documents (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT NOT NULL, version TEXT NOT NULL,
  locale TEXT NOT NULL, sha256 TEXT NOT NULL, body_ref TEXT NOT NULL,
  effective_at TEXT NOT NULL, reaccept_grace_days INTEGER NOT NULL DEFAULT 14,
  UNIQUE (tenant_id, kind, version, locale)
);
CREATE TABLE terms_acceptances (
  tenant_id TEXT NOT NULL, identity_id INTEGER NOT NULL, document_id TEXT NOT NULL,
  accepted_at TEXT NOT NULL, context TEXT NOT NULL, audit_seq INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, identity_id, document_id)
);

CREATE TABLE partner_organizations (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
  domains TEXT NOT NULL DEFAULT '[]', idp_connection_ids TEXT NOT NULL DEFAULT '[]',
  federation_entity_ids TEXT NOT NULL DEFAULT '[]',
  min_ial INTEGER NOT NULL DEFAULT 0, require_mfa INTEGER NOT NULL DEFAULT 1,
  agreement_ref TEXT, agreement_ends_at TEXT, partner_admins TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active', UNIQUE (tenant_id, name)
);
```

Population settings (durations, required attributes, IAL/AAL, token lifetimes, grace and retention) live in a typed `guest_populations` table edited in Admin, with sponsor policy in Cedar (§4.3).

### 9.2 APIs

Authenticated (Phase 0 sessions and tokens, audited):

| Route | Purpose |
|---|---|
| `POST /api/guests/invitations` · `POST /api/guests/invitations:bulk` | Sponsor invites (policy-checked; returns per-row results) |
| `GET /api/guests?sponsor=me&state=&population=` | Guests I sponsor; admins can filter all |
| `POST /api/sponsorships/{id}:approve|:reject|:renew|:end|:transfer|:accept-transfer` | Sponsorship lifecycle (most surfaced as Inbox actions) |
| `POST /api/guests/{identity}:resend-invitation` · `:revoke-invitation` | Invitation management |
| `GET /api/identity-matches?status=review` · `POST /api/identity-matches/{id}:decide` | Review queue |
| `POST /api/identities/{id}:merge` · `POST /api/identity-merges/{id}:unmerge` | Merge and unmerge (four-eyes where required) |
| `POST /api/proofing/agent-sessions` · `POST /api/proofing/agent-sessions/{id}:complete` | On-site proofing by a trained agent |
| `GET|POST /api/admin/guest-populations` · `/api/admin/terms` · `/api/admin/partner-orgs` · `/api/admin/idv-providers` | Configuration |
| `PUT /match/api/1/v1/people/{sor}/{sorid}` (flagged) | TAP ID Match-compatible matching |

Public (per-tenant host or `/public/t/{slug}`; no authentication; rate-limited per §6.4; CSRF-protected with the claim session):

`POST /claim/start` · `POST /claim/code` · `POST /claim/verify/send` · `POST /claim/verify/check` · `POST /claim/idv/start` → vendor redirect → `GET /claim/idv/callback` · `POST /claim/existing-account` (starts IdP sign-in) · `GET /claim/terms` · `POST /claim/terms/accept` · `POST /claim/credential` (choose authority; returns a redirect or a password form) · `GET /claim/credential/callback` · `GET /claim/status` · `POST /claim/resend` · `POST /register`.

Webhooks out: `guest.invited`, `guest.claimed`, `guest.expiring`, `guest.expired`, `sponsorship.*`, `identity.merged`, `identity.unmerged` (CloudEvents, same mechanism as group events).

### 9.3 Integration with Groups and access requests

- **Reference groups maintained by the guest service** (system-managed, `managed_by='connector'` in the groups design): `ref:guest:active`, `ref:guest:visitor`, `ref:guest:contractor`, `ref:guest:volunteer`, `ref:applicant:active`, `ref:admit:<term>`, `ref:prehire:active`, `ref:prehire:<start-month>`, `ref:partner:<org>`, `ref:ial:2` (everyone with IAL ≥ 2), `ref:sponsor:eligible` (computed from employee and faculty groups), and per-unit `org:<unit>:guests`.
- **Access bundles** are direct memberships with `source='guest_sponsorship'`, `source_ref` = the sponsorship, and `disabled_at` = the sponsorship end. Renewing updates `disabled_at`; ending removes them; PIT history shows exactly which sponsorship gave which access.
- **Policy groups** use these references, for example the Wi-Fi guest policy `permit … when { principal in Group::"ref:guest:active" }`, and IAL gating in Cedar: `forbid … when { resource.sensitivity == "high" && principal.ial < 2 }`.
- **Access requests**: guests can request catalog items allowed for their population; approval goes to the sponsor first, then the resource owner; items requiring a higher IAL or AAL start a step-up claim before fulfilment.
- **Attestation**: sponsors attest their guests at renewal and in a quarterly "guests I sponsor" campaign (frozen population, usage context per guest: last sign-in, last use of each bundle item).
- **Grouper migration**: Grouper external subjects and invite-created memberships (G-17 in the groups design) import as sponsorships with the inviting user as sponsor.

### 9.4 UI flows

| Where | What |
|---|---|
| **Access → Guests I sponsor** | List with state, population, end date and days left; Invite (single form with population, dates, bundle picker showing required IAL); Bulk invite (CSV template, preview with per-row policy result); row actions Renew, End, Resend invitation, Transfer |
| **Inbox** | Sponsorship approvals; self-registration requests; renewal requests; sponsor-leaver transfer tasks; identity match reviews; proofing referrals |
| **Directory → People** | Filters for affiliation and lifecycle state; person page gains an **Affiliations** timeline (each with source, sponsor, dates), **Identity** card (IAL, pathway, identifiers with verification method), **Claim** status, **Source records**, and Merge/Unmerge actions |
| **Governance → Lifecycle** | Expiring and expired guests, conversions this month, sponsorships pending transfer, claims stuck at a step, KPIs (time to claim, claim completion rate, IDV failure rate) |
| **Admin → Guests and external identities** | Populations (attributes, durations, IAL/AAL, token lifetimes), sponsor policy (link to repo, simulation), terms documents, IDV providers, federation (InCommon/eduGAIN metadata source and filters), partner organizations, proofing agents |
| **Public claim pages** | Tenant-branded: start → verify contact → verify identity (vendor handoff or "visit a proofing agent" instructions) → "do you already have an account?" → terms → choose sign-in method (organization login, create passkey, or set password + MFA) → recovery setup → done (links to the apps in the bundle). Accessible (WCAG 2.2 AA), localized, works on mobile, no third-party scripts except the IDV vendor's SDK on its own step |
| **Proofing agent screen** | For on-site IAL2: search the person, check evidence against a checklist, capture document type and number reference, visual comparison attestation, complete; requires the agent to be in `ref:proofing:agents` and phishing-resistant step-up |

---

## 10. Threats and mitigations

### 10.1 Threat table

| # | Threat | Mitigation |
|---|---|---|
| T1 | **Account takeover by wrong match**: an attacker gets invited with a victim's email or name and inherits the victim's identity | K3 and §5.5: no auto-link from self-asserted intake; link only by sign-in as the existing person or by reviewer with re-verification at the existing IAL; credentials never move in a merge; notifications to the existing person; reversible merges |
| T2 | **Invitation link intercepted or forwarded** | The link only starts a session; a fresh confirmation code to the bound channel is still required; single use; short lifetime; re-issue revokes; IAL1+ populations need verification beyond the email |
| T3 | **Token leakage via logs or `Referer`** | Token in the URL fragment; `Referrer-Policy: no-referrer`; removed from the address bar; only hashes stored |
| T4 | **Enumeration** of applicants, guests or employees through claim, resend or registration endpoints | K10 and §6.4: identical responses and timing, generic messages, rate limits, bot challenges |
| T5 | **Brute force of claim codes or confirmation codes** | 80-bit claim codes paired with the email; 5 attempts then lock; 6-digit codes with 5 attempts and 10-minute lifetime; per-destination and per-IP limits |
| T6 | **Guest's email account compromised** | A0 populations get only low-risk access; IAL1+ requires validated channels and IDV or federation; MFA required above A0; email is never an authenticator |
| T7 | **SIM swap or SMS interception** | SMS restricted, never for privileged bundles; carrier risk signals; passkeys first |
| T8 | **Sponsor abuse**: sponsoring fake identities, an alter ego, or exceeding limits; collusion | Sponsor policy limits, no sponsoring identities that match the sponsor, second approver for sensitive bundles, sponsor attestation campaigns, anomaly report (sponsor with many invites to one domain, short-lived guests with privileged bundles) |
| T9 | **Stale guests** (sponsorship never ended; sponsor left) | Mandatory end dates, maximum durations, reminders, sponsor-leaver transfer with deadline, expiry enforced by the groups engine with verified deprovisioning |
| T10 | **Help-desk social engineering for recovery** | Recovery at the original IAL; help-desk verification workflow (D1·S14); cooling-off and notification; no recovery via sponsor's say-so alone |
| T11 | **Phishing of the claim flow** (lookalike claim pages harvesting codes and passwords) | Passkeys first (phishing-resistant); tenant-branded verified domains only; invitations from DMARC-aligned domains; the claim page never asks for the person's password at another organization (federation goes to the home IdP) |
| T12 | **Remote-hire identity fraud** (impostor candidates, synthetic identities, fraudulent remote IT workers) | IAL2 before access beyond onboarding for pre-hires with remote access; IDV with liveness and injection-attack detection; mismatch between HRIS identity and IDV result blocks the claim and alerts HR security; day-one on-site upgrade as an alternative |
| T13 | **IDV bypass with deepfakes, virtual cameras, injected media** | Vendor must meet 800-63A-4 §3.14 and show PAD test results; Tessera checks vendor results include injection-detection signals; trusted-referee fallback; fraud signals to the fraud program |
| T14 | **Malicious or compromised federated IdP** asserting someone else's identifier | Bind on `(issuer, subject)` only, never email; verify metadata signatures; scoped-attribute checks against `shibmd:Scope`; per-partner minimum assurance; Sirtfi contacts for incident response; ability to suspend an IdP's bindings at once |
| T15 | **Recycled email addresses** (a new person receives an old guest's email) | Email confirmation proves control only now; re-invitations of a known identity require sign-in or re-verification at the previous IAL; identifiers older than the retention window are retired |
| T16 | **Self-registration spam and bot accounts** | Nothing is created until a sponsor approves; bot challenge; rate limits; sponsor-searchable list does not reveal sponsor emails |
| T17 | **Over-privileged guests** | Population-allowed bundles, IAL/AAL gating in Cedar, sponsor and owner approval for requests, attestation with usage context, SoD checks at request time |
| T18 | **PII exposure** (DOB, phone, national IDs) | Sealed fields, keyed hashes for matching, masked display, purge after retention, IDV evidence kept by the vendor only as long as the contract allows |
| T19 | **Password capture during directory password set** | TLS to Tessera, never stored or logged, zeroed after the LDAP/kpasswd call, code path excluded from tracing; prefer passkeys and the IdP's own enrolment where available |
| T20 | **Claim session hijack** | `__Host-` cookie, short idle timeout, binding to a non-extractable WebCrypto key, re-verification before credential binding if the IP's network changes |

### 10.2 Security tests (land with the PRs that introduce each surface)

- `TestClaim_SameResponseForUnknownExpiredUsed` (body, status, headers and a timing tolerance).
- `TestClaim_TokenSingleUseUnderConcurrency` (100 parallel starts, exactly one session).
- `TestClaim_CodeLockoutAfterFiveFailures`, `TestConfirmation_ExpiresAfterTenMinutes`.
- `TestMatch_SelfAssertedNeverAutoLinks` (fuzz over intake attributes that equal an existing employee's).
- `TestMerge_CredentialsNotTransferred`, `TestUnmerge_RestoresMoves`.
- `TestSponsorLeaver_TransfersOrEnds`, `TestExpiry_RemovesAccessWithin60s`.
- `TestFederation_RejectsUnscopedEPPN`, `TestFederation_BindsOnSubjectNotEmail`.
- `TestPassword_NoCompositionRules_BlocklistApplied` and `TestPassword_NeverLogged` (log capture scan).

---

## 11. Implementation plan (ordered PRs)

**Preconditions.** As for the groups design: the Go port merged, Phase 0 PR1 (#5), PR2 (#6, sealing and rate limiting), PR3 (#7), PR5 (#9) merged. Each PR keeps `./run.sh test` and `./run.sh build` green, adds `TestIsolation_*` coverage for its tables and passes `go vet`, `staticcheck`, `govulncheck`. "GR-n" refers to the groups design's PRs.

### GU-1: Identity data model for affiliations, source records and identifiers (3 days)
- **Files:** `internal/store/schema/0201_guests.sql` (identity columns, source records, identifiers, affiliations, populations), `internal/store/model_identity.go`, `repo_identity_ext.go`, `internal/identity/affiliations/` (derive lifecycle state from affiliations), seed data for each population in the demo tenant.
- **Tests:** `TestLifecycleState_DerivedFromAffiliations`, `TestIdentifiers_HMACUniqueness`, isolation tests.
- **Depends on:** #5, #6, #7.

### GU-2: Sponsorships, sponsor policy and sponsor invites (4 days)
- **Files:** `internal/guests/sponsorship/` (create, approve, renew, end, transfer), sponsor policy evaluation (Cedar fragment, same parser as GR-9 or a Go evaluator with the same semantics until Cedar lands), invitations (single and CSV), Inbox task types, notification templates through the Phase 0 outbox, `/api/guests/*`, `/api/sponsorships/*`.
- **Tests:** `TestSponsorPolicy_LimitsAndDurations`, `TestSponsor_CannotSponsorSelfOrMatch`, `TestBulkInvite_PerRowResults`, policy version recorded on every decision.
- **Depends on:** GU-1, #9, #16.

### GU-3: Self-registration with sponsor approval (2 days)
- **Files:** public `POST /register` with bot challenge hook and rate limits, sponsor search that exposes names only, sponsorship codes, Inbox approval.
- **Tests:** `TestRegister_NoAccountCreatedBeforeApproval`, `TestRegister_ExistingEmailGetsSignInMail`, enumeration tests.
- **Depends on:** GU-2.

### GU-4: SIS and HRIS intake for applicants, admits and pre-hires (3 days)
- **Files:** connector mappings for SIS status changes and future-dated HRIS hires to intake records and affiliations; organizational sponsors (admissions, HR); conversion events; demo SIS and HRIS connectors extended.
- **Tests:** `TestSIS_ApplicantToAdmitToStudentKeepsIdentity`, `TestHRIS_PrehireToEmployeeKeepsIdentity`, `TestHRIS_RescindedOfferEndsPrehire`.
- **Depends on:** GU-1.

### GU-5: Identity matching, review queue, link, merge and unmerge (5 days)
- **Files:** `internal/identity/match/` (rules, normalization, Jaro-Winkler, tiers, explanations, modes), `internal/identity/merge/` (move list, credential revocation, notifications, four-eyes), Inbox match reviews, `/api/identity-matches/*`, `/api/identities/{id}:merge`, flagged TAP ID Match-compatible endpoint.
- **Tests:** `TestMatch_SelfAssertedNeverAutoLinks`, `TestMatch_TierExplanations`, `TestMerge_MovesMembershipsThroughEngine`, `TestMerge_CredentialsNotTransferred`, `TestUnmerge_RestoresMoves`, ID Match API conformance tests.
- **Depends on:** GU-1, GU-4, GR-1 and GR-2 (groups design) for moving memberships.

### GU-6: Claim core: tokens, sessions, confirmation codes and enumeration resistance (4 days)
- **Files:** `internal/guests/claim/` (tokens and codes, claim session with key binding, confirmation codes by email and SMS through the notification outbox with an SMS provider interface, rate limits, generic responses, suspected-match branch), public claim pages skeleton in `frontend/src/public/claim/`.
- **Tests:** all `TestClaim_*` in §10.2, `TestConfirmation_*`, Playwright happy path for an A0 visitor with the dev IdP as the customer IdP.
- **Depends on:** GU-2, GU-5, #6.

### GU-7: Identity verification providers (IAL2) and the proofing-agent screen (4 days, needs-human)
- **Files:** `internal/guests/idv/` (provider interface, a mock provider for tests, one real provider adapter chosen in open question 2), `ProofingResult` storage, trusted-referee and proofing-agent flows, IAL recording.
- **Tests:** mock-provider tests for each pathway and decision; `TestIDV_NoImagesStored`; a human runs the real vendor's sandbox end to end and signs off.
- **Depends on:** GU-6.

### GU-8: Credential binding: customer IdP activation, home IdP federation, password set and AAL check (5 days, needs-human)
- **Files:** `internal/guests/credential/` (authorities: Okta activation token, Entra Temporary Access Pass, Google Workspace, LDAP/AD password set with 800-63B-4 checks and blocklist, generic OIDC/SAML home IdP binding), first-sign-in AAL check against the Phase 0 AuthnContext, credential bindings table.
- **Tests:** dev IdP based tests for OIDC and SAML binding and AAL checks; LDAP password set against an in-process LDAP server; `TestPassword_*`; opt-in live suites for Okta and Entra that a human runs against sandbox tenants.
- **Depends on:** GU-6, #10, #13.

### GU-9: InCommon and eduGAIN federation (4 days, needs-human)
- **Files:** metadata aggregate and MDQ client with signature verification and pinned keys, entity-category and registration-authority filters, SeamlessAccess discovery integration, REFEDS MFA request and check, RAF `eduPersonAssurance` mapping to IAL, subject-id/pairwise-id handling, scope checks.
- **Tests:** fixtures from the InCommon test federation metadata; `TestFederation_*` in §10.2; a human registers the SP in the InCommon test federation and signs in from a test IdP.
- **Depends on:** GU-8, #13.

### GU-10: Terms, consent and recovery (3 days)
- **Files:** terms documents and acceptances with ledger events, re-acceptance on version change, attribute-release consent screen for federated claims, recovery claim tokens with re-verification at the recorded IAL, cooling-off for privileged bundles, notifications.
- **Tests:** `TestTerms_ReacceptOnNewVersion`, `TestRecovery_RequiresOriginalIAL`, `TestRecovery_NotifiesAllChannels`.
- **Depends on:** GU-6.

### GU-11: Lifecycle: expiry, renewal, sponsor leaver, conversion and deprovisioning (4 days)
- **Files:** `internal/guests/lifecycle/` (reminders, renewal with step-up, multi-sponsorship expiry, sponsor-leaver transfer tasks on JML events, grace and retention jobs, PII purge to tombstone), Governance → Lifecycle data endpoints.
- **Tests:** `TestSponsorLeaver_TransfersOrEnds`, `TestExpiry_LastSponsorshipEndsIdentity`, `TestDeprovision_VerifiedInTargets`, `TestPurge_KeepsTombstoneOnly`.
- **Depends on:** GU-2, GU-4, GR-11 (groups design) for verified deprovisioning.

### GU-12: Groups and access-request integration (3 days)
- **Files:** system-maintained reference groups (`ref:guest:*`, `ref:applicant:*`, `ref:prehire:*`, `ref:partner:*`, `ref:ial:2`, `ref:sponsor:eligible`), access bundles as direct memberships with sponsorship end dates, IAL/AAL gating in policy groups and request approvals, sponsor attestation campaign, Grouper external-subject import mapping.
- **Tests:** `TestBundle_EndsWithSponsorship`, `TestRequest_StepUpWhenIALTooLow`, `TestRefGroups_TrackAffiliations`.
- **Depends on:** GU-11, GR-5 and GR-9 (groups design).

### GU-13: UI: sponsor portal, review queue, person page and admin (5 days)
- **Files:** `frontend/src/features/access/Guests.tsx`, Inbox item types, Directory person page sections, Governance → Lifecycle views, Admin → Guests and external identities, public claim pages completed (all steps, localization scaffolding, accessibility).
- **Tests:** component tests; Playwright: sponsor invites a contractor, contractor claims with IAL1 and passkey, sponsor renews, sponsor leaves and the transfer task appears; accessibility checks.
- **Depends on:** GU-2, GU-5, GU-6.

### GU-14: B2B partner organizations (Phase 3) (4 days, needs-human)
- **Files:** partner organizations with domains, IdP connections and agreements; partner admins with delegated invite rights; IdP routing (email domain to partner IdP); partner SCIM inbound (`/scim/v2` write endpoints scoped to a partner org); partner deprovisioning signals (SCIM delete, SSF RISC `account-disabled` when available); agreement expiry ending all partner sponsorships.
- **Tests:** `TestPartnerAdmin_CanOnlyInviteOwnOrg`, `TestPartnerSCIM_ScopedToOrg`, `TestAgreementExpiry_EndsSponsorships`; a human connects a real partner Entra or Okta tenant.
- **Depends on:** GU-8, GU-12.

---

## 12. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Building a credential service conflicts with "do not become an IdP" | Scope creep, security burden | Options (a) and (b) first (K7); the hosted service is Phase 3, guests only, on a proven core |
| IDV vendor dependence, cost and bias | Cost per proofing, failure rates for some groups | Pluggable providers; offer at least two IAL2 pathways (vendor, on-site agent, federation); trusted referee fallback; publish failure-rate metrics by pathway |
| Matching quality on messy SIS/HRIS data | Duplicates or wrong links | Conservative defaults (no auto-link from self-asserted intake), explainable rules, review queue with SLA, reversible merges, match-quality metrics |
| Applicant volumes (hundreds of thousands per cycle) | Load on matching and claim | Batch matching, indexes on identifier hashes, claim for applicants optional by tenant |
| Federation complexity (metadata, scopes, assurance) | Integration delays with research partners | Use InCommon test federation early (GU-9), reuse Phase 0 SAML SP hardening |
| Legal and privacy requirements differ by country (GDPR, FERPA, state privacy laws, I-9 rules) | Misconfiguration | Data minimization defaults, per-population fields off by default, legal review of templates; Tessera does not perform I-9 or background checks |
| Sponsors ignore reminders | Stale access or sudden loss | End dates enforced automatically; transfer tasks with deadlines; dashboards for unit admins |

---

## 13. Open questions

1. **Hosted credential service core.** Build on `go-webauthn` with a minimal OIDC provider, or embed Ory (Kratos/Hydra) or Keycloak as D1·C19 suggests? The answer also decides the "no IdP" on-ramp for Phase 3.
2. **Which IDV vendor first** (Persona, Socure, Incode, Jumio, iProov, Veriff, or a university-preferred vendor such as ID.me)? Criteria: 800-63A-4 §3.14 evidence, Kantara or FedRAMP status, mDL support, price per verification, data retention terms.
3. **SMS provider** and whether SMS is enabled at all by default (recommendation: off, tenant opt-in per population).
4. **National identifier HMAC for matching.** Do target customers want SSN-based matching between HR and SIS? It improves conversions but raises the stakes of a key compromise.
5. **Default grace and retention periods** per population need the founder's and early customers' input (the values here follow common university practice, not a standard).
6. **Minors.** Should Tessera support applicant references in Phase 2, or should tenants exclude minors from self-service claim until Phase 3?
7. **Covered-visitor and background-check integrations** (Sterling, HireRight, Checkr): record an attestation only, or integrate APIs?
8. **NetID assignment timing** for admits (at admit or at deposit) varies by school; make it a population setting or a rule in the SIS connector?
9. **SSF/CAEP for partners.** Should partner organizations be asked to send RISC `account-disabled` events as a condition of the partner agreement once Tessera's receiver ships (Phase 3)?

---

## 14. Knowledge-base corrections

- `docs/knowledge/01-authentication-and-identity-proofing.md` §3.2 says remote unattended IAL2 details were unverified. Verified against the final SP 800-63A-4 web text: §4.2.6 defines three IAL2 verification pathways (non-biometric, digital evidence, biometric), remote unattended IAL2 has no requirements beyond the general ones, KBV "SHALL NOT be used for identity verification" (§2.5.1), and confirmation and continuation code rules are in §3.8. Update the doc and drop the `[unverified]` mark.
- The same doc's build-vs-integrate table puts "Identity verification for recovery and contractor onboarding" in Phase 5 (capability map F). Guest claim pulls the IDV integration into Phase 2 (GU-7) for IAL2 populations. The capability map is updated in this branch.
- `docs/knowledge/04-identity-governance-and-compliance.md` does not cover sponsored accounts, applicant and pre-hire identities, or federated research collaborators. Add a short section on external identity lifecycle, citing the university practices in §2.

---

## 15. References

- NIST SP 800-63-4 suite (final, 2025): SP 800-63A-4 *Identification and Proofing* (https://pages.nist.gov/800-63-4/sp800-63a.html), SP 800-63B-4 *Authentication and Authenticator Management*, SP 800-63C-4 *Federation and Assertions*.
- University of Michigan ITS, MCommunity Sponsor System support (https://documentation.its.umich.edu/mcommunity-sponsor-system-support); U-M Standard Practice Guide 601.42 (Covered Visitors); "Be Our Guest: Using Friend Accounts, Social Login and Sponsorship for U-M Guests" (Michigan IT Symposium 2021).
- Stanford University IT, Sponsorship and Sponsored Services (https://uit.stanford.edu/service/sponsorship/sponsoredservices); Stanford Medicine SUNet ID sponsorship (https://uit.stanford.edu/service/accounts/healthcareemployees).
- Duke OIT, Sponsored Accounts (https://oit.duke.edu/service/sponsored-accounts) and Sponsored Account Policy (https://oit.duke.edu/policy/sponsored-account-policy/).
- Internet2 COmanage Registry and COmanage Match; TAP ID Match API (https://spaces.at.internet2.edu, COmanage space; Match 1.0.0 and 1.1.0 release announcements).
- REFEDS: Research and Scholarship entity category, Sirtfi, MFA Profile, Assurance Framework (https://refeds.org); OASIS SAML V2.0 Subject Identifier Attributes Profile; InCommon Federation (https://incommon.org); eduGAIN (https://edugain.org); SeamlessAccess (https://seamlessaccess.org).
- Microsoft Learn: B2B collaboration invitation redemption (https://learn.microsoft.com/entra/external-id/redemption-experience), email one-time passcode (https://learn.microsoft.com/entra/external-id/one-time-passcode), entitlement management for external users (https://learn.microsoft.com/entra/id-governance/entitlement-management-external-users), Temporary Access Pass.
- Okta Help: Identity Provider routing rules (https://help.okta.com/oie/en-us/content/topics/security/identity_provider_discovery.htm), integrating with a company that uses an external IdP (https://help.okta.com/oie/en-us/content/topics/architecture/ma/ma-ext-idp.htm).
- OpenID for Verifiable Presentations (OpenID4VP) and the W3C Digital Credentials API; ISO/IEC 18013-5 (mDL); ISO/IEC 30107-3 (presentation attack detection).
- Tessera: `docs/knowledge/01-authentication-and-identity-proofing.md`, `docs/knowledge/04-identity-governance-and-compliance.md`, `docs/design/phase-0-platform-security.md`, `docs/design/groups-grouper-parity.md`.
