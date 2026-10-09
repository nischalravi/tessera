# Deployment readiness: checklists, gated activation, dry-run reconciliation and deployment health

| | |
|---|---|
| Status | Draft for review |
| Author | iam-architect, with iam-protocols-expert (directories: AD, LDAP, Entra ID, Okta, Google, SCIM) and iam-governance-expert (correlation, reconciliation, orphan accounts, evidence) |
| Date | 2026-10-09 |
| Phase | 2 (governance on top of the graph). The MVP slice (§12) builds now against the demo connectors, before Phase 0 lands. |
| Requirements covered | D2·M2, M3, M23; D4·M1, M2, M8, M9, M22, M23; README rules 4, 6 and 8; Phase 0 §4 I3 (SSRF), §7.1 (sealed secrets), §13 (audit ledger) |
| Reviewers to sign off | `iam-protocols-expert` (§3 templates, §5 live checks, §5.3 directory agent), `iam-governance-expert` (§6 reconciliation, §7 score and evidence), `security-engineer` (§5.2, §5.3, §11), `fullstack-developer` (§§8–10) |

**The requirement (founder).** Customers must be able to see what was missed during deployment. Before Tessera connects to AD, LDAP or any other directory: (1) the required configuration options are a checklist; (2) mandatory items are a prerequisite for establishing the connection; (3) the configuration is validated and a reconciliation identifies what is missing; (4) analytics highlight deployment gaps and items that need attention.

**Exit criteria for this design.** (1) A connection cannot reach `active` through any API path unless every Required item passes, which a server-side test proves. (2) Every template item has a level, a verification method and a remediation hint, and the template linter enforces it. (3) On the demo company, the dry-run reconciliation finds the planted gaps exactly (for example, Oren Whitlock's Okta account left active after termination), and the readiness score explains every point it deducts. (4) An auditor can take the evidence export and reproduce what was checked, by whom, and what was accepted as a known gap.

---

## Contents

1. [Summary of key decisions](#1-summary-of-key-decisions)
2. [Problem, users and scope](#2-problem-users-and-scope)
3. [Readiness checklist model and templates](#3-readiness-checklist-model-and-templates)
4. [Gating: the connection state machine](#4-gating-the-connection-state-machine)
5. [Validation: safe, read-only live checks](#5-validation-safe-read-only-live-checks)
6. [Dry-run reconciliation](#6-dry-run-reconciliation)
7. [Deployment health analytics](#7-deployment-health-analytics)
8. [Data model (Go structs and SQL DDL)](#8-data-model-go-structs-and-sql-ddl)
9. [API](#9-api)
10. [UI](#10-ui)
11. [Security considerations](#11-security-considerations)
12. [MVP slice](#12-mvp-slice)
13. [Implementation plan (ordered PRs)](#13-implementation-plan-ordered-prs)
14. [Risks](#14-risks)
15. [Open questions](#15-open-questions)
16. [Knowledge-base notes](#16-knowledge-base-notes)
17. [References](#17-references)

---

## 1. Summary of key decisions

| # | Decision | Why |
|---|---|---|
| K1 | **A Connection is a governed object with a lifecycle**, not an environment variable. `TESSERA_CONNECTORS` keeps working for the demo, but every customer system is a `connections` row with a pinned checklist template, sealed credentials and a state. | Today the MVP has no connection object at all (`connectors.Load` reads an env var). Gating needs something to gate. |
| K2 | **Checklist templates are versioned YAML embedded in the Go binary**, one per connector type, all extending a shared `base` template. Items declare level, verification, remediation, dependencies and applicability in a **closed vocabulary** (no expression language). | Reviewable in PRs like policy (README rule 2), and no arbitrary code (the lesson of Grouper's JEXL advisories, groups design K6). |
| K3 | **Customers can add items and raise levels, never lower them.** A template's Required item stays Required. A Recommended item can be *skipped* with a written reason, which is recorded in the audit ledger and stays visible forever as a known gap. | The founder's requirement, and an auditor's: accepted risk must be explicit and attributable. |
| K4 | **Six states**: `draft → ready_to_validate → validated → dry_run_reconciled → active`, plus `degraded` (entered from `active`) and `retired`. Each forward transition has a server-side gate in one package (`internal/readiness`), which is the only code allowed to change a connection's state. | Enforcement in the UI alone is a suggestion. A source-scan test (like Phase 0's dependency test) proves no other package writes the state column. |
| K5 | **Evidence is bound to configuration.** Every check result and attestation records the hash of the non-secret configuration and the secret version it ran against. Changing the base DN after validation makes the affected results stale and moves the revision back. Live results also expire (24 hours by default) before activation. | Prevents "validated against the lab DC, activated against production". |
| K6 | **Editing an active connection creates a draft revision.** The active revision keeps syncing while the new one goes through the same gates, and activation swaps them atomically. | Config changes never cause an outage, and never bypass the checklist. |
| K7 | **Live checks are read-only by construction.** Each check is a Go function that may call only a read-only probe interface. Least privilege is verified by reading effective rights, never by attempting a write: AD's constructed `allowedAttributesEffective`, 389-DS's Get Effective Rights control, the `roles` claim of an Entra access token, Okta's granted scopes, and Google token issuance for a forbidden scope. | A readiness tool that writes to the customer's directory to "test" it would be a finding itself. |
| K8 | **Private directories are reached only through the Tessera Directory Agent.** It runs inside the customer network, connects outbound to Tessera, and runs a closed set of read-only operations against hosts on **its own local allowlist**. Direct cloud-to-directory LDAP is allowed only to public addresses under the Phase 0 SSRF rules, through a new `safedial` sibling of `safehttp`. | Phase 0 forbids private IPs from the cloud, correctly. An agent that would dial any host a tenant admin types in would turn SSRF into internal network scanning. |
| K9 | **Dry runs write to a staging snapshot (`stg_*` tables keyed by run), never to the live graph.** Reconciliation runs the real correlation engine over the staged accounts against the authoritative HR source and the other active connections. | Customers see orphans, leavers with access and duplicate correlations *before* those records drive reviews, alerts or revocations. |
| K10 | **Every finding has a severity, a count, a denominator, capped samples, an impact estimate and a probable cause.** Cause analysers turn "3,412 uncorrelated" into "3,412 accounts uncorrelated because `employeeID` is empty on 97% of them; 3,051 would match by email (needs review)". | Turns a report into a to-do list. That is the founder's "items that need attention". |
| K11 | **The readiness score is a published formula with a per-point explanation**: checklist completion weighted by level, minus a capped penalty for open findings, hard-capped below 50 while any Required item fails. The tenant score is the account-weighted mean. | Scores nobody can explain are ignored. Every deduction links to the item or finding that caused it. |
| K12 | **Correlation is never automatic on self-asserted attributes.** Tier 1 is an exact HR-id match, tier 2 an immutable cross-system link (for example Entra `onPremisesImmutableId` to AD `objectGUID`), and tier 3 (email or UPN) only *proposes* a match into the review queue. | D4·M2 and the nOAuth class of attacks (Phase 0 S4); matches the guest design's no-auto-link rule. |

**PR sequence** (§13): DR-1 templates → DR-2 connections, state machine and gating → DR-3 check framework and simulated validation → DR-4 staging and dry-run reconciliation → DR-5 score, needs-attention and dashboard API → DR-6 setup wizard UI → DR-7 deployment-health and Home UI (DR-1 to DR-7 are the **MVP slice**) → DR-8 evidence export → DR-9 drift and Degraded → DR-10 tenancy, RBAC and step-up → DR-11 directory agent and `safedial` → DR-12 to DR-18 real live checks per directory.

---

## 2. Problem, users and scope

**Problem.** IGA deployments fail quietly. A base DN that misses one OU, a service account that cannot read `userAccountControl`, a correlation rule keyed on `mail`, an Okta list call that silently omits deprovisioned users, or a Workday report that excludes contingent workers all produce a connection that "works": it syncs, it shows numbers, and its numbers are wrong. The consequences surface months later as audit findings: orphaned accounts, terminated users with access, incomplete review populations (D4 §6.1, §6.3). Auditors test the completeness and accuracy of system-generated user listings (information produced by the entity, IPE) under SOX ITGC, and an incomplete connection makes every downstream review population unreliable.

**Users.**

| User | Needs |
|---|---|
| Deployment engineer (customer IAM team or partner) | A checklist that says exactly what to configure and why, and tells them as early as possible when something is wrong. |
| Directory owner (AD or Entra admin) | Proof that Tessera's service account is least-privilege and read-only before granting it. |
| IAM program owner | One page that says what was missed, what was accepted, and what to fix next, per connection and for the tenant. |
| Auditor | Evidence that the population is complete, and a record of known gaps and who accepted them. |

**In scope.** Read paths (ingestion) for AD, generic LDAP (OpenLDAP, 389-DS), Entra ID, Okta, Google Workspace, Workday as the HR source, and generic SCIM 2.0 applications; and the write-back gate for connections that also provision (groups design §9.2). The model is generic, so the AWS, GitHub and Snowflake connectors get templates later through the same mechanism.

**Out of scope.** Building the production connectors themselves (Phase 1 and 2 connector work, groups design GR-11 and GR-12); fixing the customer's directory (Tessera recommends; the customer changes their directory); attack-path analysis of AD (README: import BloodHound, Phase 2).

---

## 3. Readiness checklist model and templates

### 3.1 Concepts

| Term | Meaning |
|---|---|
| **Template** | A versioned list of checklist items for one connector type (`ad`, `ldap`, `entra`, `okta`, `google`, `workday`, `scim_app`). Every template extends `base`. |
| **Item** | One thing that must be true for a correct deployment, such as "LDAPS with certificate validation". |
| **Level** | `required` (blocks activation), `recommended` (must pass or be skipped with a reason before activation), `optional` (informational; never blocks). |
| **Verification** | How the item is proven: `attestation` (a named person confirms it, with a note), `live` (a read-only check against the system), `data` (a check over the staged snapshot after the dry-run sync). An item can list several; all must pass. |
| **Applicability** | When the item applies, for example only when write-back is enabled, or only if the tenant also has an Entra connection. Non-applicable items are shown as "Not applicable" and excluded from the score. |
| **Dependency** | Item B depends on item A: B is `blocked` (and its checks are not run) until A passes. |
| **Overlay** | Tenant additions: custom items, raised levels, tighter thresholds. |

### 3.2 Item schema

```yaml
# mvp/server/internal/readiness/templates/ad.yaml (excerpt)
template: ad
version: 1.0.0                     # semver; a connection pins major.minor
extends: base@1
display_name: Active Directory
connector_types: [ad]
required_attributes:               # feeds base.attrs.required and the fill-rate check
  user: [objectGUID, sAMAccountName, userPrincipalName, userAccountControl, accountExpires,
         pwdLastSet, lastLogonTimestamp, whenCreated, memberOf, employeeID, manager, mail]
  group: [objectGUID, cn, groupType, member, managedBy]
thresholds:
  fill_rate.required: 0.95         # tenant overlay may tighten, never loosen
  stale_days: 90
  stale_lag_days: 14               # lastLogonTimestamp replication lag
items:
  - id: ad.tls.chain
    title: Server certificate validates
    category: transport
    level: required
    why: >
      Without certificate validation, anyone on the network path can impersonate the
      domain controller and capture the service account's bind password.
    verify:
      - kind: live
        check: tls_chain
        params: { min_days_valid: 30 }
    remediation:
      hint: >
        Upload the issuing CA (often your AD CS root) in Connection → Transport. Do not use
        "skip verification"; Tessera does not offer it.
      link: https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority
    depends_on: [ad.tls.ldaps]
  - id: ad.hybrid.entra
    title: Hybrid users linked to the Entra connection
    category: identity_keys
    level: recommended
    applies_when: { tenant_has_connection_type: [entra] }
    verify:
      - kind: data
        check: cross_link_rate
        params: { attr: objectGUID, other_type: entra, other_attr: onPremisesImmutableId, min: 0.98 }
    # ...
```

**Closed vocabulary.** `applies_when` accepts only these keys, all ANDed: `write_mode` (list of `off|dry_run|scoped`), `role` (`authoritative|account_source`), `tenant_has_connection_type` (list), `config_flag` (a named boolean in the connector's typed config, such as `hybrid` or `use_dirsync`). `verify.check` must name a check registered in Go for that connector type (§5.4); the linter rejects unknown names. There is no expression language.

**Item status** (per connection revision): `pending`, `pass`, `fail`, `blocked` (a dependency is not passing), `stale` (evidence is for an old config hash or has expired), `skipped` (Recommended only, with reason), `not_applicable`.

### 3.3 Verification kinds

| Kind | Who or what decides | Evidence stored | Expires |
|---|---|---|---|
| `attestation` | A user with `connections.manage` ticks the box and writes a note (minimum 10 characters; a link to a change ticket is encouraged). The attester cannot be the only approver of the activation for write-enabled connections (§4.2). | user id, time, note, config hash | When the config hash changes. |
| `live` | A registered read-only check (§5) run against the system through a probe. | check id, result, observed values (no secrets, no personal data beyond counts), duration, config hash, agent id | 24 h before activation (configurable 1–72 h); after activation, re-run on schedule (§7.4). |
| `data` | A check over the staged snapshot of the latest dry run (§6). | run id, metric, threshold, observed value | When a new dry run supersedes it, or the config hash changes. |

### 3.4 Dependencies and applicability

- `depends_on` forms a DAG within a template plus its base. The linter rejects cycles and dependencies on items that are not applicable in some configuration where the dependent is.
- A `blocked` item shows *which* dependency blocks it. The UI lists the root blockers first, so users fix causes rather than symptoms.
- A failing Required item blocks all dependants, including Recommended ones; a failing Recommended item blocks only its own dependants.

### 3.5 Versioning and customer overlays

- Templates live in `internal/readiness/templates/*.yaml`, embedded with `embed.FS`, and parsed with `yaml.v3` with `KnownFields(true)`. Template data never comes from the database or the network.
- A connection revision pins `template_id@major.minor`. Patch releases (wording, remediation links) apply automatically. A minor release that adds items applies to new revisions; for active connections it appears as "template update available" and new Required items become **drift** with a 30-day grace period (§7.4), not an instant deactivation. A major release requires a new revision.
- **Overlays** (`readiness_overlays`, per tenant, optionally per connection): add custom items (any level, verification `attestation` or a registered `data` check with parameters), raise an item's level (`optional → recommended → required`), tighten thresholds. The overlay validator rejects any lowering, removing or disabling of template items with HTTP 422 `level_downgrade_forbidden`. Overlay changes are audited (`readiness.overlay.changed`).

### 3.6 Base items (included by every template)

Verification column: **A** attestation, **L:** live check, **D:** data check. Levels: **R** Required, **Rec** Recommended, **O** Optional.

| ID | Item | Lvl | Verified by | Depends on | Why it matters | Remediation |
|---|---|---|---|---|---|---|
| `base.owner` | Technical owner and business owner named | R | A | | README rule 6: every connection and its findings need an accountable human. | Set both owners on the Connect step. |
| `base.cred.sealed` | Credential stored sealed in Tessera or as a vault reference; never in config text | R | L:`cred_storage` | | Phase 0 §7.1. A credential in plain config leaks through exports and logs. | Use the credential field (write-only) or a vault reference. |
| `base.cred.expiry` | Credential or certificate expiry known and more than 30 days away | Rec | L:`cred_expiry` | `base.cred.sealed` | Expired credentials are the commonest silent sync outage. | Rotate; set a reminder; prefer certificates or federation. |
| `base.clock` | Clock skew between Tessera and the system under 2 min (fail at 5 min) | Rec | L:`clock_skew` | | Skew corrupts last-login staleness, effective dating and token validation. Kerberos fails at 5 min. | Fix NTP on the directory or agent host. |
| `base.correlation.key` | Immutable correlation key selected and populated on 100% of in-scope objects, unique | R | A, D:`key_unique` | | Email, UPN and usernames are renamed and reused; correlating on them merges people. | Choose the template's immutable key (§3.7+). |
| `base.correlation.rule` | Correlation to the authoritative source configured (tier 1 HR id; tier 3 email only proposes) | R | D:`correlation_rate` | `base.correlation.key` | D4·M2. Without it, every account is an orphan. | Map the HR id attribute; see the cause analysis in the reconciliation report. |
| `base.attrs.required` | Template's required attributes mapped and filled on ≥ 95% of in-scope records | R | D:`fill_rate` | | Missing attributes break reviews, SoD and JML rules. | Map the attribute or fix the source data. |
| `base.scope.count` | Staged object counts within ±2% of the counts the owner expects | Rec | A, D:`count_match` | | The fastest way to catch a missing OU, domain or population. | Enter expected user and group counts from the directory's own console. |
| `base.dryrun.reviewed` | Dry run completed; every critical and high finding resolved or accepted with a reason | R | D:`findings_acknowledged` | `base.correlation.rule` | Makes the gaps visible before they become audit findings. | Open the reconciliation report (§10.4). |
| `base.writeback.scope` | Write-back off, or limited to named containers or groups with the minimum rights | R | L:`write_scope` | | Least privilege for provisioning (D4·M8). | Delegate rights only on the provisioned OU or groups. |
| `base.writeback.dryrun` | First provisioning run executed in `dry_run` and its planned operations reviewed | R | A | `base.writeback.scope` | Catches mass changes before they happen (groups design §9.2 failsafes). | Run Provisioning → Dry run and review the op list. |
| `base.stale.threshold` | Dormancy threshold set (default 90 days, PCI DSS v4 8.2.6) | Rec | A | | Drives stale-account findings and reviews. | Set in Identity rules. |
| `base.schedule` | Full sync at least weekly and incremental sync scheduled | Rec | A | | Incremental feeds miss deletes and permission changes; a periodic full sync is the backstop. | Set the schedule on the Review step. |

`base.writeback.*` apply only when `write_mode` is not `off`. `base.correlation.rule` does not apply when the connection's role is `authoritative` (the HR source).

### 3.7 Active Directory (`ad`, 36 items + 13 base)

| ID | Item | Lvl | Verified by | Depends on | Why it matters | Remediation |
|---|---|---|---|---|---|---|
| `ad.svc.readonly` | Dedicated service account, in no privileged group (RIDs 512, 518, 519, 544, 548–551, DnsAdmins, Group Policy Creator Owners) and `adminCount` ≠ 1 | R | L:`ad_svc_groups` (reads the bound account's `tokenGroups`) | `ad.bind` | A domain-admin service account turns Tessera into a domain compromise path. | Create a standard user; grant read only. |
| `ad.svc.no_write` | No write rights on in-scope users and groups (unless write-back, then only there) | R | L:`ad_effective_rights` (constructed `allowedAttributesEffective` and `allowedChildClassesEffective` on sampled objects must be empty) | `ad.svc.readonly` | Proves read-only without attempting a write. | Remove delegated write ACEs; check inherited ACEs on OUs. |
| `ad.svc.no_replication` | Account does not hold "Replicating Directory Changes All" (DCSync) | R | L:`ad_replication_rights` (reads the domain head's DACL) | `ad.bind` | DCSync rights expose every password hash in the domain. | Remove the extended right. Tessera's default incremental method (uSNChanged) needs no replication right. |
| `ad.svc.password` | Agent runs as a gMSA, or the account password is ≥ 25 characters, sealed and on a rotation schedule | Rec | A | | Long-lived static passwords on service accounts are a top AD finding. | Use a gMSA for the agent's Windows service. |
| `ad.svc.no_interactive` | Interactive and RDP logon denied to the service account | O | A | | Limits misuse if the password leaks. | GPO: "Deny log on locally / through RDS". |
| `ad.tls.ldaps` | LDAPS (636) or StartTLS (389); no simple bind in cleartext | R | L:`tls_handshake` | | Simple bind sends the password in clear text. | Enable LDAPS on the DCs. |
| `ad.tls.chain` | Certificate chains to a configured CA, hostname matches, valid > 30 days | R | L:`tls_chain` | `ad.tls.ldaps` | Prevents DC impersonation. | Upload the AD CS root; fix SANs. |
| `ad.tls.signing_cb` | DCs require LDAP signing and channel binding (Microsoft ADV190023) | Rec | A | | Stops NTLM relay to LDAP against the domain. | Set the DC policies to "Require". |
| `ad.bind` | Bind succeeds on every configured DC | R | L:`bind` | `ad.tls.chain` | Baseline connectivity. | Check the account, password, DC names and firewall. |
| `ad.dc.redundancy` | At least two DCs, or DNS SRV locator, configured | Rec | L:`dc_count` | `ad.bind` | A single DC is a single point of sync failure. | Add a second DC or enable the locator. |
| `ad.scope.base_dns` | Every base DN exists and is readable | R | L:`dn_exists` | `ad.bind` | A typo in a base DN returns zero objects, not an error. | Pick DNs from the browser in the Scope step. |
| `ad.scope.filter` | Filters parse, and people use `(objectCategory=person)(objectClass=user)` so computers are excluded | R | L:`filter_parse`, L:`sample_search` | `ad.scope.base_dns` | `objectClass=user` alone matches computer accounts. | Use the template filter. |
| `ad.scope.read_perms` | Read permission per object class: user, inetOrgPerson, group, msDS-GroupManagedServiceAccount, contact; required attributes returned | R | L:`read_per_class` | `ad.scope.base_dns` | Objects visible with missing attributes indicate ACL gaps (for example confidential attributes). | Grant read on the attribute set; check "List Object" mode. |
| `ad.scope.paging` | Paged results (1.2.840.113556.1.4.319) work past `MaxPageSize` (default 1,000) | R | L:`paging` | `ad.scope.base_dns` | Without paging a search silently stops at 1,000 objects. | Tessera pages automatically; the check fails if the DC refuses the control. |
| `ad.scope.service_accounts` | OUs holding service accounts and gMSAs are in scope | Rec | A, D:`class_present` (msDS-GroupManagedServiceAccount) | `ad.scope.read_perms` | NHIs are the accounts most often missed (D5). | Add the service-account OUs. |
| `ad.key.objectguid` | `objectGUID` is the correlation key (decoded as a little-endian GUID); not `sAMAccountName`, UPN or `mail` | R | D:`key_unique` | `base.correlation.key` | Names are renamed and reused; `objectGUID` survives renames and moves within the forest. | Select objectGUID as the key. |
| `ad.key.employeeid` | `employeeID` or `employeeNumber` mapped to the HR worker id | Rec | D:`fill_rate` | `ad.scope.read_perms` | Tier-1 correlation needs it; without it most accounts fall to email proposals. | Populate it from HR (often via the HR-to-AD feed). |
| `ad.key.sid_history` | `sIDHistory` captured for migrated accounts | O | D:`attr_present` | | Keeps links for accounts migrated between domains. | Map the attribute. |
| `ad.status.disabled` | Disabled from `userAccountControl` bit 0x2 (ACCOUNTDISABLE) | R | D:`uac_mapped` | `ad.scope.read_perms` | Treating disabled accounts as active inflates reviews; the reverse hides leavers. | Uses the template mapping; fails if UAC is unreadable. |
| `ad.status.lockout` | Lockout from `msDS-User-Account-Control-Computed` bit 0x10 or `lockoutTime`, not from `userAccountControl` | Rec | D:`attr_present` | `ad.status.disabled` | DCs do not maintain the lockout bit in `userAccountControl`. | Map the computed attribute. |
| `ad.status.expiry` | `accountExpires` parsed (0 and 0x7FFFFFFFFFFFFFFF mean never; FILETIME UTC); expired accounts treated as inactive | R | D:`expiry_parsed` | `ad.scope.read_perms` | Contractor accounts often "end" by expiry rather than disablement. | Uses the template parser. |
| `ad.status.pwdlastset` | `pwdLastSet` and DONT_EXPIRE_PASSWORD (0x10000) captured | Rec | D:`attr_present` | | Feeds password-age and never-expires findings on privileged accounts. | Map both. |
| `ad.status.lastlogon` | Staleness from `lastLogonTimestamp`, with its replication lag (up to 14 days by default) | Rec | D:`attr_present` | | `lastLogon` is per DC and not replicated; without the lag, active users look stale. | Keep `stale_lag_days` at 14 unless `msDS-LogonTimeSyncInterval` was changed. |
| `ad.groups.nested` | Nested groups resolved (recursive expansion with cycle detection) | R | D:`nesting_resolved` | `ad.scope.read_perms` | Most AD access is granted through nesting (D2·M3). | Automatic; fails if group objects are out of scope. |
| `ad.groups.range` | `member;range=…` retrieval for groups larger than `MaxValRange` (1,500, or 5,000 on newer DCs `[unverified]`) | R | L:`range_retrieval` (largest group: ranged count equals the full count) | `ad.scope.read_perms` | Without ranged retrieval large groups are silently truncated. | Automatic; fails if the DC refuses ranged reads. |
| `ad.groups.primary` | Primary group (`primaryGroupID`, usually Domain Users) reconstructed | Rec | D:`primary_group` | `ad.groups.nested` | Primary group membership is not in `member`. | Automatic. |
| `ad.groups.fsp` | Foreign security principals resolved by SID to another connection, or flagged | Rec | D:`fsp_resolved` | `ad.groups.nested` | Members from trusted forests are invisible otherwise. | Add the trusted forest as a connection. |
| `ad.groups.privileged` | Privileged groups tagged (well-known RIDs, `adminCount=1` as a hint, plus customer list), each with an expected-member list | R | A, D:`privileged_unexpected` | `ad.groups.nested` | Drives the most important finding: unexpected privileged members. | List expected members or an owning policy. |
| `ad.sync.usn` | Incremental on `uSNChanged` per DC; `invocationId` and `highestCommittedUSN` tracked; a DC switch or restore forces a full sync | R | L:`incremental_capable` (reads rootDSE) | `ad.bind` | USNs are per DC; reading them from a different DC skips changes. | Automatic; pin the DC or let Tessera track per DC. |
| `ad.sync.dirsync` | DirSync control used instead of USN polling | O | L:`dirsync_allowed` | `ad.sync.usn` | Needs "Replicating Directory Changes"; only if the customer prefers it. Conflicts with the least-privilege default. | Leave off unless required. |
| `ad.sync.deleted` | Deletions detected: Deleted Objects readable with the show-deleted control (1.2.840.113556.1.4.417), or full-sync diff with a failsafe; full-sync interval shorter than the tombstone lifetime (default 180 days) | R | L:`deleted_objects_readable` or A (diff mode) | `ad.sync.usn` | Incremental polling of live objects never sees deletions. | Delegate List and Read on CN=Deleted Objects, or accept diff mode. |
| `ad.sync.recycle_bin` | AD Recycle Bin state known | O | L:`recycle_bin_state` | `ad.bind` | Restored objects keep `objectGUID`; Tessera relinks them. | Informational. |
| `ad.topo.domains` | Every domain in the forest holding in-scope users is configured (compared with the Partitions container) | R | L:`forest_domains` | `ad.bind` | Multi-domain forests are the commonest cause of missing people. | Add a base DN per domain naming context. |
| `ad.topo.gc` | Global catalog (3268/3269) used only for forest-wide lookups; domain-local group membership and non-PAS attributes read from domain DCs | Rec | A | `ad.topo.domains` | The GC holds a partial attribute set and omits domain-local memberships. | Use domain DCs for sync. |
| `ad.topo.trusts` | External and forest trusts inventoried; trusted forests have their own connection or are flagged | Rec | L:`trusts` | `ad.bind` | Access via trusts is invisible otherwise. | Add connections or accept the gap. |
| `ad.hybrid.entra` | Hybrid users linked to the Entra connection (`objectGUID` ↔ `onPremisesImmutableId`) | Rec | D:`cross_link_rate` | `ad.key.objectguid` | Prevents duplicate correlations of one person. | Applies when an Entra connection exists. |

### 3.8 Generic LDAP: OpenLDAP and 389-DS (`ldap`, 23 items + 13 base)

| ID | Item | Lvl | Verified by | Depends on | Why it matters | Remediation |
|---|---|---|---|---|---|---|
| `ldap.svc.readonly` | Dedicated bind DN; not the rootDN or `cn=Directory Manager` | R | L:`bind_identity` (Who Am I, RFC 4532) | `ldap.bind` | The root DN bypasses all access control. | Create a service entry with read ACIs (389-DS) or `olcAccess` rules (OpenLDAP). |
| `ldap.svc.no_write` | No write access on in-scope entries | R | L:`effective_rights` on 389-DS (Get Effective Rights control); A on OpenLDAP | `ldap.svc.readonly` | Proves read-only without writing. | Restrict ACIs to `read,search,compare`. |
| `ldap.svc.ppolicy` | The bind DN is exempt from password expiry and lockout, or rotation is scheduled | Rec | A | | A ppolicy lockout of the service account stops every sync. | Use a dedicated policy subentry. |
| `ldap.tls.ldaps` | LDAPS or StartTLS | R | L:`tls_handshake` | | Clear-text bind. | Enable TLS. |
| `ldap.tls.chain` | Certificate validates, hostname matches, valid > 30 days | R | L:`tls_chain` | `ldap.tls.ldaps` | Server impersonation. | Upload the CA. |
| `ldap.tls.version` | TLS 1.2 or later | Rec | L:`tls_handshake` | `ldap.tls.ldaps` | Older protocol versions are deprecated. | Set the minimum protocol on the server. |
| `ldap.bind` | Bind succeeds | R | L:`bind` | `ldap.tls.chain` | Baseline. | Check DN and password. |
| `ldap.replica` | Reads go to a consumer replica, not the provider | O | A | | Spares the write master. | Point at a read replica. |
| `ldap.scope.base_dns` | Base DNs exist and are readable | R | L:`dn_exists` | `ldap.bind` | Typos return nothing. | Use the DN browser. |
| `ldap.scope.filter` | Filters parse and select people, not service or host entries, unless intended | R | L:`filter_parse`, L:`sample_search` | `ldap.scope.base_dns` | Over- or under-inclusive populations. | Use the template filter for the schema. |
| `ldap.scope.read_perms` | Read permission per object class (inetOrgPerson, posixAccount, groupOfNames, groupOfUniqueNames, posixGroup) and the required attributes returned | R | L:`read_per_class` | `ldap.scope.base_dns` | Partial ACLs return entries without attributes. | Extend the ACIs. |
| `ldap.scope.limits` | Paged results supported and the bind DN's limits exceed a page (OpenLDAP `sizelimit` default 500; 389-DS `nsslapd-sizelimit` 2,000, `nsslapd-lookthroughlimit`, `nsPagedSizeLimit`) | R | L:`paging` (search past the limit without resultCode 4, sizeLimitExceeded) | `ldap.scope.base_dns` | Size limits truncate results; some clients treat that as success. | Raise limits for the bind DN only (`olcLimits` or per-entry `nsSizeLimit`). |
| `ldap.key.entryuuid` | `entryUUID` (RFC 4530; operational, so requested explicitly) or 389-DS `nsUniqueId` as key; not DN, `uid` or `mail` | R | L:`attr_returned`, D:`key_unique` | `base.correlation.key` | DNs change on rename and move. | Select the key in Mapping. |
| `ldap.key.hr_id` | `employeeNumber` (or the site's HR id attribute) mapped | Rec | D:`fill_rate` | `ldap.scope.read_perms` | Tier-1 correlation. | Map it. |
| `ldap.status.disabled` | Disabled expression configured, because LDAP has no standard flag: OpenLDAP ppolicy `pwdAccountLockedTime` (`000001010000Z` means locked by an administrator), 389-DS `nsAccountLock`, `shadowExpire`, or a site-specific attribute or OU | R | A, D:`disabled_expression` (evaluates on the sample; reports counts) | `ldap.scope.read_perms` | Without it every account looks active. | Choose the site's convention. |
| `ldap.status.expiry` | Expiry mapped (`shadowExpire` in days since 1970; ppolicy `pwdEndTime` where used) | Rec | D:`expiry_parsed` | `ldap.status.disabled` | Expired accounts treated as active. | Map it. |
| `ldap.status.lastlogin` | Last-login source known: OpenLDAP `lastbind` overlay (`pwdLastSuccess`), 389-DS account policy (`lastLoginTime`), or the IdP connection | Rec | A | | Staleness otherwise impossible. | Enable the overlay or rely on the IdP. |
| `ldap.groups.types` | Group classes configured: `groupOfNames` (`member` DN), `groupOfUniqueNames` (`uniqueMember`, possibly with a `#'…'B` suffix), `posixGroup` (`memberUid` holds a uid, not a DN) | R | D:`member_resolution` (unresolved member references < 1%) | `ldap.scope.read_perms` | Mixing the three silently drops members. | Select every class in use. |
| `ldap.groups.nested` | Nested groups resolved | R | D:`nesting_resolved` | `ldap.groups.types` | Effective membership (D2·M3). | Automatic. |
| `ldap.groups.memberof` | If `memberOf` (overlay or plugin) is used, sampled consistency with `member` ≥ 99.9% | O | D:`memberof_consistency` | `ldap.groups.types` | `memberOf` goes stale when the overlay was added after the data. | Run the fix-up task, or let Tessera use `member`. |
| `ldap.sync.incremental` | Incremental: syncrepl refreshOnly (RFC 4533) with a cookie, the OpenLDAP accesslog, or the 389-DS retro changelog; otherwise `modifyTimestamp` polling | R | L:`incremental_capable` (rootDSE `supportedControl` and changelog DN readable) | `ldap.bind` | Full syncs only, on large directories, mean stale data. | Enable syncprov or the retro changelog for the bind DN. |
| `ldap.sync.deletes` | Deletes detected (syncrepl delete phase or full-sync diff with failsafe) | R | D:`delete_detection_mode` | `ldap.sync.incremental` | `modifyTimestamp` polling never sees deletions. | Schedule a full diff at least weekly. |
| `ldap.schema.custom` | Custom schema attributes discovered (subschema subentry) and mapped where needed | O | L:`schema_read` | `ldap.bind` | Site-specific HR ids and status flags live in custom attributes. | Map in the Mapping step. |

### 3.9 Entra ID (`entra`, 17 items + 13 base)

| ID | Item | Lvl | Verified by | Depends on | Why it matters | Remediation |
|---|---|---|---|---|---|---|
| `entra.app.dedicated` | Dedicated single-tenant app registration for Tessera | R | A | | Shared apps blur accountability and over-grant. | Register a new app. |
| `entra.app.credential` | Certificate credential or workload identity federation; no client secret | Rec | L:`credential_type` | `entra.tenant` | Secrets leak and are copied; certificates and federation are bound. | Upload a certificate; remove secrets. |
| `entra.tenant` | Tenant id (a GUID, not a domain) and cloud (global, US Government, China) correct; token acquired | R | L:`token_acquire` | | A wrong authority silently connects to a different tenant or cloud. | Copy the tenant id from Overview. |
| `entra.perms.readonly` | Application permissions limited to `User.Read.All`, `Group.Read.All` or `GroupMember.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory` (plus `Application.Read.All` if NHI inventory is on); no `*.ReadWrite.*` | R | L:`token_roles` (decodes the access token's `roles` claim) | `entra.tenant` | Exact and read-only proof of least privilege. | Remove write permissions; re-consent. |
| `entra.perms.consent` | Admin consent granted (the `roles` claim is not empty) | R | L:`token_roles` | `entra.tenant` | Without consent every call returns 403. | Grant admin consent. |
| `entra.key.objectid` | Object `id` as key; not UPN or `mail` | R | D:`key_unique` | `base.correlation.key` | UPNs change; `mail` is not unique and can be set by others (nOAuth). | Select `id`. |
| `entra.key.employeeid` | `employeeId` mapped to the HR worker id | Rec | D:`fill_rate` | | Often empty in cloud-only tenants. | Populate it from HR provisioning. |
| `entra.hybrid.link` | Synced users linked to the AD connection (`onPremisesImmutableId`, `onPremisesSecurityIdentifier`) | Rec | D:`cross_link_rate` | `entra.key.objectid` | One person, two correlations otherwise. | Applies when `config_flag: hybrid`. |
| `entra.status.enabled` | `accountEnabled` mapped; soft-deleted users (`directory/deletedItems`, 30 days) treated as deleted | R | D:`status_mapped` | | Deleted users are absent from `/users` but restorable. | Automatic. |
| `entra.status.signin` | `signInActivity` readable (needs `AuditLog.Read.All` and Entra ID P1 or P2) | Rec | L:`signin_activity_available` | `entra.perms.readonly` | Without it there is no staleness. | Add the permission or license; otherwise accept and use app-level signals. |
| `entra.guests` | Guests (`userType=Guest`, `#EXT#` UPNs, `externalUserState`) classified as guests, linked to sponsors, never correlated to employees by email | R | D:`guest_classification` | `entra.key.objectid` | Guests matched to employees by email gain the employee's lifecycle. | Automatic; see the guest design. |
| `entra.groups.transitive` | Nested membership resolved; dynamic-group rules captured; role-assignable groups tagged privileged | R | D:`nesting_resolved` | | Effective membership (D2·M3). | Automatic. |
| `entra.groups.types` | Security, Microsoft 365, mail-enabled security and distribution groups distinguished | Rec | D:`group_types` | | Distribution lists grant no access and should not be reviewed as such. | Automatic. |
| `entra.roles` | Directory role assignments and PIM eligible and active assignments read; privileged roles tagged (Global Administrator, Privileged Role Administrator and similar) | R | L:`roles_readable`, D:`privileged_unexpected` | `entra.perms.readonly` | Eligible PIM roles are standing privilege in waiting. | Add `RoleManagement.Read.Directory`. |
| `entra.sync.delta` | Delta queries for users and groups (with members); `deltaLink` stored; an expired token (HTTP 410) forces a full sync | R | L:`delta_capable` (one call with `$deltatoken=latest`, which returns a link and no data) | `entra.perms.readonly` | Full Graph scans of large tenants are slow and throttled. | Automatic. |
| `entra.ratelimit` | Throttling honoured (429 with `Retry-After`; `$top=999`; `$batch` of at most 20); no throttling observed during validation | Rec | L:`rate_headroom` | `entra.perms.readonly` | Throttling during sync means partial snapshots. | Lower concurrency. |
| `entra.scope.admin_units` | If scoped to administrative units, the units are listed and counts reconcile | O | A | | AU-scoped deployments miss users outside the AUs. | List the AUs. |

### 3.10 Okta (`okta`, 14 items + 13 base)

| ID | Item | Lvl | Verified by | Depends on | Why it matters | Remediation |
|---|---|---|---|---|---|---|
| `okta.auth.oauth` | OAuth 2.0 service app with `private_key_jwt`, not an SSWS API token | Rec | L:`auth_mode` | | API tokens carry the creating admin's full privileges and expire after 30 days unused. | Create an API service app; upload a public key. |
| `okta.auth.scopes` | Granted scopes read-only: `okta.users.read`, `okta.groups.read`, `okta.apps.read`, `okta.logs.read`, `okta.roles.read`; no `*.manage` | R | L:`token_scopes` (the token response's `scope`) | `okta.org` | Proof of read-only access. | Revoke manage scopes. |
| `okta.auth.admin_role` | The service app's admin role is Read-Only Administrator or a custom read-only role, not Super Admin | R | L:`app_admin_roles` | `okta.auth.scopes` | Scopes are capped by the admin role; a Super Admin role makes a leaked key catastrophic. | Assign Read-Only Administrator. |
| `okta.org` | Org URL is an Okta domain or a verified custom domain, reached through `safehttp` | R | L:`token_acquire` | | Wrong org; SSRF. | Use the org URL from the admin console. |
| `okta.key.userid` | Okta user `id` (`00u…`) as key; `login` and `email` are mutable | R | D:`key_unique` | `base.correlation.key` | Renames break correlation. | Select `id`. |
| `okta.key.employee_number` | `employeeNumber` profile attribute mapped to the HR worker id | Rec | D:`fill_rate` | | Tier-1 correlation. | Map it in the profile or from HR. |
| `okta.status.all` | All statuses mapped (STAGED, PROVISIONED, ACTIVE, RECOVERY, LOCKED_OUT, PASSWORD_EXPIRED, SUSPENDED, DEPROVISIONED) and DEPROVISIONED users fetched explicitly | R | L:`deprovisioned_visible`, D:`status_mapped` | `okta.auth.scopes` | The default list-users call omits DEPROVISIONED users, which hides leavers. | Automatic. |
| `okta.status.lastlogin` | `lastLogin` captured; null means never | Rec | D:`attr_present` | | Staleness. | Automatic. |
| `okta.groups.types` | `OKTA_GROUP`, `APP_GROUP` (mastered in AD or an app) and `BUILT_IN` (Everyone, excluded from findings) distinguished | R | D:`group_types` | | APP_GROUPs must be governed at their source. | Automatic. |
| `okta.groups.rules` | Group rules captured, so rule-driven membership is explained and not flagged as unexpected | Rec | L:`group_rules_readable` | `okta.auth.scopes` | False positives otherwise. | Automatic. |
| `okta.roles.admins` | Admin role assignments (to users and to groups) read; Super Admin and Org Admin tagged privileged | R | L:`roles_readable`, D:`privileged_unexpected` | `okta.auth.scopes` | Okta admin is the keys to every SSO app. | Add `okta.roles.read`. |
| `okta.mastering` | Profile source known: users mastered by AD or an HR source correlate through it, not twice | Rec | D:`profile_source` | | Duplicate correlation. | Automatic. |
| `okta.sync.syslog` | Incremental through System Log polling (`/api/v1/logs`, `since` and the `after` cursor) inside the 90-day retention; weekly full sync | R | L:`syslog_readable` | `okta.auth.scopes` | Full scans only, on large orgs, eat the rate limit. | Add `okta.logs.read`. |
| `okta.ratelimit` | Rate-limit headroom: `X-Rate-Limit-Remaining` over `X-Rate-Limit-Limit` observed on users, groups and logs; Tessera stays under its share (default 50%), and a per-app rate-limit percentage is set in Okta `[unverified: availability by plan]` | Rec | L:`rate_headroom` | `okta.auth.scopes` | Okta limits are per org; Tessera must not starve the customer's other integrations. | Set the app's share in the rate-limit dashboard; lower concurrency. |

### 3.11 Google Workspace (`google`, 15 items + 13 base)

| ID | Item | Lvl | Verified by | Depends on | Why it matters | Remediation |
|---|---|---|---|---|---|---|
| `gws.sa.dedicated` | Dedicated service account in a dedicated Google Cloud project | R | A | | Shared projects share keys and quotas. | Create a project for Tessera. |
| `gws.sa.keyless` | No downloadable JSON key (keyless signing via the IAM Credentials API with workload identity federation), or a sealed key rotated within 90 days | Rec | L:`credential_type` | | Exported keys are the commonest Google credential leak. | Use federation; the org policy can block key creation. |
| `gws.dwd.scopes` | Domain-wide delegation grants only read scopes: `admin.directory.user.readonly`, `admin.directory.group.readonly`, `admin.directory.group.member.readonly`, `admin.directory.orgunit.readonly`, `admin.directory.rolemanagement.readonly`, `admin.reports.audit.readonly` | R | L:`dwd_scopes` (requests a token for each configured scope, and for one write scope, which must be refused; token issuance has no side effect) | | Delegation is domain-wide: an extra write or Gmail scope is a tenant-wide grant. | Edit the client's scopes under Security → API controls. |
| `gws.dwd.subject` | The impersonated admin is a dedicated user with a custom read-only admin role, not a super admin | R | L:`subject_roles` | `gws.dwd.scopes` | Effective access is scopes ∩ the subject's privileges. | Create a read-only role and user. |
| `gws.customer` | Customer (`my_customer`) and every secondary domain included | R | L:`domains_list` | `gws.dwd.subject` | Users on secondary domains are otherwise missed. | Automatic; check the domain list. |
| `gws.scope.ou` | Org units in scope selected; counts reconcile | Rec | L:`ou_list`, D:`count_match` | `gws.customer` | OU scoping misses moved users. | Select the OUs. |
| `gws.key.id` | Numeric user `id` as key; `primaryEmail` and aliases change | R | D:`key_unique` | `base.correlation.key` | Renames break correlation. | Select `id`. |
| `gws.key.employee` | `externalIds` (type `organization`) or `employeeId` mapped to the HR worker id | Rec | D:`fill_rate` | | Tier-1 correlation. | Populate from HR. |
| `gws.status` | `suspended` and `archived` mapped; deleted users (restorable for 20 days) treated as deleted | R | D:`status_mapped` | | Suspended users look active otherwise. | Automatic. |
| `gws.lastlogin` | `lastLoginTime` used (1970-01-01 means never) | Rec | D:`attr_present` | | Staleness. | Automatic. |
| `gws.groups.members` | Nested groups, external members and `CUSTOMER`-type members ("everyone in the domain") resolved | R | D:`member_resolution` | | Externals and whole-domain grants are invisible otherwise. | Automatic. |
| `gws.roles` | Admin role assignments read; super admins tagged privileged | R | L:`roles_readable`, D:`privileged_unexpected` | `gws.dwd.subject` | Super admin is full tenant control. | Add the role-management read scope. |
| `gws.quota` | Directory API quota headroom; exponential backoff on 403 `rateLimitExceeded` or `userRateLimitExceeded` and on 429 | Rec | L:`rate_headroom` | `gws.dwd.subject` | Quota exhaustion yields partial snapshots. | Request a quota increase or lower concurrency. |
| `gws.incremental` | Incremental from Reports API admin activity, with a daily full sync | Rec | L:`reports_readable` | `gws.dwd.scopes` | Directory API list calls have no change filter for users `[unverified]`. | Add the audit read scope. |
| `gws.2sv` | `isEnrolledIn2Sv` and `isEnforcedIn2Sv` captured | O | D:`attr_present` | | Feeds MFA coverage findings. | Automatic. |

### 3.12 Workday as the HR source (`workday`, 15 items + 13 base)

Role `authoritative`, so `base.correlation.rule` is not applicable. `base.attrs.required` uses: worker id, worker type, legal and preferred name, status, hire date, termination date, manager, supervisory organisation, cost centre, location, work email.

| ID | Item | Lvl | Verified by | Depends on | Why it matters | Remediation |
|---|---|---|---|---|---|---|
| `wd.authoritative` | Marked as the authoritative source for joiner/mover/leaver and person attributes | R | A | | Every other connection reconciles against it (D4·M1). | Set role = authoritative. |
| `wd.isu.dedicated` | Dedicated Integration System User, "Do Not Allow UI Sessions" set, password-expiry behaviour known | R | A | | A shared or expiring ISU stops HR feeds. | Create an ISU for Tessera. |
| `wd.isu.get_only` | The ISU's integration system security group has Get-only (view) access on the needed domains; no Put | R | A | `wd.isu.dedicated` | Least privilege; HR data is the most sensitive data Tessera reads. | Review domain security policies. |
| `wd.isu.minimal_fields` | Only needed fields returned: no national ids, compensation, bank details or date of birth | R | L:`field_inventory` (forbidden field names in the sample fail the check; values are not stored) | `wd.endpoint` | Data minimisation (GDPR art. 5(1)(c)); Tessera should never hold these. | Remove fields from the report or web-service response group. |
| `wd.endpoint` | Tenant host and name correct, API version pinned, reached through `safehttp` | R | L:`endpoint_reachable` | | Wrong tenant (sandbox versus production) is a common slip. | Copy from the Workday tenant URL. |
| `wd.interface` | Interface chosen: `Get_Workers` web service, or a RaaS report owned by the ISU | R | A | `wd.endpoint` | RaaS reports silently change when their owner edits them. | Use a dedicated report owned by the ISU. |
| `wd.key.worker_id` | Employee and contingent worker ids as the identity key, WID kept as secondary; a rehire reactivates the existing identity | R | D:`key_unique` | `base.correlation.key` | Duplicated identities on rehire break history and reviews. | Automatic. |
| `wd.population` | Employees, contingent workers, pre-hires (future-dated) and recent terminations (default 90 days) all included | R | A, D:`population_mix` | `wd.endpoint` | Contractors are the population most often missing. | Include all worker types. |
| `wd.effective_dating` | Future-dated hires and terminations captured with effective dates; rescinded and corrected events handled | R | D:`future_dated_present` | `wd.population` | Leavers processed late or never. | Use effective and entry date parameters. |
| `wd.tz` | Effective dates read in the Workday tenant time zone; terminations take effect at the end of the local day | R | A | `wd.effective_dating` | Off-by-one-day leavers across time zones. | Set the tenant time zone in the connection. |
| `wd.manager` | Manager resolves for ≥ 98% of active workers | Rec | D:`fill_rate` | | Manager-based reviews and approvals depend on it. | Fix vacant supervisory organisations. |
| `wd.email` | Work email filled for ≥ 95% of active workers | Rec | D:`fill_rate` | | Needed for notifications and tier-3 proposals. | Fix in Workday. |
| `wd.multiple_positions` | Primary position chosen for workers with concurrent positions | Rec | D:`multi_position` | | Department and manager become ambiguous. | Automatic, using the primary flag. |
| `wd.incremental` | Incremental through `Get_Workers` transaction-log criteria or a dated RaaS prompt; daily full | R | L:`incremental_capable` | `wd.interface` | Leavers must flow within the SLA. | Automatic. |
| `wd.leaver_sla` | Sync frequency meets the leaver SLA (default every 4 hours) | Rec | A | `wd.incremental` | D4·M7 leaver kill-switch timing. | Set the schedule. |

### 3.13 Generic SCIM 2.0 application (`scim_app`, 13 items + 13 base)

Tessera acts as a SCIM client that reads the application's SCIM service (RFC 7643, 7644).

| ID | Item | Lvl | Verified by | Depends on | Why it matters | Remediation |
|---|---|---|---|---|---|---|
| `scim.endpoint` | Base URL is HTTPS and reachable through `safehttp` | R | L:`endpoint_reachable` | | SSRF and transport. | Use the app's documented URL. |
| `scim.auth` | OAuth client credentials or a long random bearer token with a known expiry; read-only if the app supports it | R | L:`auth_ok` | `scim.endpoint` | SCIM tokens are often full admin. | Prefer OAuth; set expiry. |
| `scim.discovery` | `/ServiceProviderConfig`, `/Schemas` and `/ResourceTypes` readable; capabilities recorded (filter, sort, ETag, PATCH, bulk, pagination) | R | L:`scim_discovery` | `scim.auth` | Many servers deviate from the RFCs; Tessera adapts to declared capabilities. | Ask the vendor if discovery is missing. |
| `scim.paging` | Paging works (index-based, or cursor-based where supported); `totalResults` consistent with pages; server maximum respected | R | L:`paging` | `scim.discovery` | Broken paging silently truncates. | Lower the page size. |
| `scim.key.id` | SCIM `id` (server-assigned) as key; `externalId` only if Tessera set it; not `userName` | R | D:`key_unique` | `base.correlation.key` | `userName` is mutable. | Select `id`. |
| `scim.key.correlate` | `userName`, primary email or enterprise `employeeNumber` mapped for correlation | Rec | D:`fill_rate` | | Correlation to HR. | Map the field. |
| `scim.status` | `active` mapped; the app's deletion semantics (hard delete versus `active=false`) recorded | R | A, D:`status_mapped` | | Hard deletes look like disappearances; soft deletes look like active accounts. | Record per app. |
| `scim.groups.members` | Group membership complete: some servers omit or cap `members` on list calls, so groups are fetched individually with `attributes=members` | R | L:`members_complete` | `scim.paging` | Truncated groups hide access. | Automatic. |
| `scim.groups.nested` | Nested groups (members of type `Group`) handled | Rec | D:`nesting_resolved` | `scim.groups.members` | Effective membership. | Automatic. |
| `scim.entitlements` | Roles and entitlements (`roles`, `entitlements` or an extension) captured and admin roles tagged privileged | Rec | D:`privileged_unexpected` | | App admins are privileged access. | Map the extension. |
| `scim.local_accounts` | Accounts not provisioned by the IdP (local accounts) identified | Rec | D:`local_accounts` | `scim.key.correlate` | Local accounts bypass SSO and leaver processing. | Compare with the IdP's app assignments. |
| `scim.lastlogin` | Last-login source known (vendor extension, app logs, or the IdP) | O | A | | Staleness. | Choose a source. |
| `scim.ratelimit` | 429 with `Retry-After` honoured; no throttling during validation | Rec | L:`rate_headroom` | `scim.auth` | Partial snapshots. | Lower concurrency. |

### 3.14 Counts

| Template | Template items | With base | Required | Recommended | Optional |
|---|---|---|---|---|---|
| `base` | 13 | 13 | 8 | 5 | 0 |
| `ad` | 36 | 49 | 27 | 18 | 4 |
| `ldap` | 23 | 36 | 23 | 10 | 3 |
| `entra` | 17 | 30 | 18 | 11 | 1 |
| `okta` | 14 | 27 | 16 | 11 | 0 |
| `google` | 15 | 28 | 16 | 11 | 1 |
| `workday` | 15 | 28 | 19 | 9 | 0 |
| `scim_app` | 13 | 26 | 15 | 10 | 1 |

Counts with base include the two Required write-back items, which apply only when write-back is enabled, and `base.correlation.rule`, which does not apply to the Workday template's authoritative role. The template linter (DR-1) asserts these counts in a golden file, so a template change shows up in review.

---

## 4. Gating: the connection state machine

### 4.1 States

```mermaid
stateDiagram-v2
  [*] --> draft
  draft --> ready_to_validate: config complete and every Required attestation done
  ready_to_validate --> validated: every Required live check passes (fresh, same config hash)
  validated --> dry_run_reconciled: dry run done; Required data checks pass; critical and high findings acknowledged
  dry_run_reconciled --> active: activate (Recommended passed or skipped with reason; step-up)
  active --> degraded: scheduled check fails twice, credential < 7 days from expiry, sync failing > 24 h, or a new Required item past its grace period
  degraded --> active: the cause clears (re-run passes)
  ready_to_validate --> draft: config or attestation invalidated
  validated --> ready_to_validate: config hash changed, or live evidence expired
  dry_run_reconciled --> validated: config hash changed for a data-affecting field
  active --> retired
  degraded --> retired
  draft --> retired
```

States belong to a **connection revision**. A connection has at most one `active` (or `degraded`) revision and at most one revision in `draft…dry_run_reconciled`. The connection's displayed state is its active revision's state, with "update in progress" when a draft revision exists.

### 4.2 Transition rules

| Transition | Gate (all must hold) | Who | Audit event |
|---|---|---|---|
| create → `draft` | Template exists for the connector type; config parses into the typed config struct | `connections.manage` | `connection.created` |
| `draft → ready_to_validate` | Typed config valid; credential present; every applicable Required item whose only verification is `attestation` is attested for the current config hash | `connections.manage` | `connection.state_changed` |
| `ready_to_validate → validated` | A validation run for the current config hash finished less than `live_ttl` ago (default 24 h) and every applicable Required item with a `live` verification passes | system, after `POST …/validate` | `readiness.validation.completed`, `connection.state_changed` |
| `validated → dry_run_reconciled` | A dry run for the current config hash finished; every Required `data` check passes; every critical and high finding is `resolved` or `accepted` with a reason | `connections.manage` | `readiness.dryrun.completed`, `connection.state_changed` |
| `dry_run_reconciled → active` | Gates above still hold (re-evaluated, not cached); live evidence still fresh; every applicable Recommended item is `pass` or `skipped` with a reason; for `write_mode ≠ off`, a second approver through the Phase 0 admin-change workflow; step-up (phishing-resistant, fresh) | `connections.activate` | `connection.activated` with the full gate report |
| `active → degraded` | §7.5 | system | `connection.degraded` {reason} |
| `degraded → active` | The degrading condition has cleared on a re-run | system | `connection.recovered` |
| any → `retired` | Confirmation; for active connections, data is kept read-only for the retention period | `connections.manage` + step-up | `connection.retired` |

**Activation is idempotent and race-safe.** `Activate` runs in one transaction: it locks the revision row, re-evaluates the gate from stored results, and writes the state with a compare-and-set on `(state, config_hash, gate_version)`. If anything changed in between, it returns 409.

### 4.3 Item-level rules

- **Required** items cannot be skipped. `POST …/skip` on a Required item returns 422 `required_item_not_skippable`.
- **Recommended** skip needs a reason of at least 20 characters, and optionally a review date (default 90 days, after which the skip expires and the item becomes `pending` again, shown in Needs attention). Skip and un-skip are audited (`readiness.item.skipped`, `readiness.item.unskipped`) with item id, level, reason and template version.
- **Findings** acceptance (`accepted`) also needs a reason and is audited (`readiness.finding.accepted`). Accepting a critical finding additionally needs step-up.
- An attestation by user U and the activation approval for a write-enabled connection cannot both be by U alone (two-person rule, using the Phase 0 admin-change workflow).

### 4.4 Server-side enforcement

1. **One writer.** Only `internal/readiness` calls `store.SetRevisionState`. A test (`TestOnlyReadinessWritesConnectionState`) parses the Go sources with `go/parser` and fails if any other package references the method or writes the `state` column of `connection_revisions` in SQL.
2. **Ingest refuses non-active connections.** `ingest.Sync` takes `[]readiness.ActiveConnection`, a type only `readiness` can construct (unexported fields), so code that tries to sync a draft connection into the live graph does not compile. Dry runs go through `ingest.Stage`, which writes only `stg_*` tables (§6.1).
3. **Write-back refuses non-active connections.** The provisioning framework (groups design §9.2) calls `readiness.CanWrite(ctx, tx, connectionID)` before `Apply`. It returns false unless the revision is `active` (not `degraded`) and `write_mode = scoped`; in `dry_run` mode operations are planned and never applied.
4. **The API returns the gate report.** Every refused transition returns 409 with the same structure the UI renders:

```json
{
  "error": "activation_blocked",
  "state": "dry_run_reconciled",
  "blocking": [
    {"item": "ad.groups.range", "level": "required", "status": "stale", "reason": "live evidence older than 24h"},
    {"item": "ad.tls.signing_cb", "level": "recommended", "status": "pending", "reason": "attest or skip with a reason"},
    {"finding": "RF-06", "severity": "critical", "status": "open", "reason": "acknowledge or resolve"}
  ]
}
```

5. **Tests** (DR-2): a table-driven test over every (state, action) pair; tests that each gate condition alone blocks activation; a race test with two concurrent activations and one config edit; an API test that a Required skip is 422; and a test that the legacy `TESSERA_CONNECTORS` path does not create revisions or bypass gates (it remains the demo path, marked `legacy` in `/api/connectors`).

### 4.5 Configuration hash

`config_hash = SHA-256(JCS(typed_config_without_secrets) || secret_version_id || template_id@version || overlay_version)`. Each item declares which config fields it depends on (`verify.params.config_fields`, defaulting to all), so changing the sync schedule does not invalidate the TLS check, but changing the host does.

---

## 5. Validation: safe, read-only live checks

### 5.1 Framework

```go
// internal/readiness/checks/check.go
type Kind string // "live" | "data"

type Check interface {
	ID() string                     // "tls_chain"
	Kind() Kind
	ConnectorTypes() []string       // which templates may reference it
	Run(ctx context.Context, env Env, params Params) Result
}

type Env struct {
	Probe    connectors.Prober      // live checks: read-only operations only
	Snapshot reconcile.SnapshotView // data checks: staged run, read-only
	Now      time.Time
}

type Result struct {
	Status   Status         // pass | fail | warn | error | skipped
	Observed map[string]any // counts, versions, expiry dates; never secrets or raw personal data
	Message  string         // one sentence for the UI
	Duration time.Duration
}
```

```go
// internal/connectors/probe.go — implemented by real connectors and by the demo connectors
type Prober interface {
	// Each method is a fixed, read-only operation. There is no generic "execute" method.
	Connect(ctx context.Context) (ConnInfo, error)            // TCP + TLS (chain, version, expiry)
	Authenticate(ctx context.Context) (AuthInfo, error)       // bind / token; returns granted scopes or roles
	RootInfo(ctx context.Context) (RootInfo, error)           // rootDSE, ServiceProviderConfig, org info
	ObjectExists(ctx context.Context, ref string) (bool, error)
	Sample(ctx context.Context, q SampleQuery) (SampleStats, error) // ≤ 500 objects; returns per-attribute fill counts
	EffectiveRights(ctx context.Context, ref string) (Rights, error)
	ChangeFeed(ctx context.Context) (FeedInfo, error)          // incremental capability, current cursor
	RateLimits(ctx context.Context) (RateInfo, error)          // headers seen during the run
	Time(ctx context.Context) (time.Time, error)               // server clock, where available
}
```

The runner (`internal/readiness/runner.go`) resolves the applicable items, orders their checks topologically by `depends_on`, skips checks whose dependencies failed (status `blocked`), and runs the rest with the limits below. It writes one `readiness_check_runs` row and one `readiness_check_results` row per check.

### 5.2 Safety rules (enforced in code and tests)

| Rule | Mechanism |
|---|---|
| Read-only | `Prober` has no write method. LDAP probes use only Bind, Search (with `sizeLimit`), Who Am I and rootDSE reads. HTTP probes use only GET, plus POST to token endpoints. A test wraps every demo and fake prober in a recorder and fails on any other verb or operation. |
| Bounded | Per-check timeout 10 s (connect 5 s); whole run 120 s; at most 500 sampled objects per class; at most 2 concurrent requests per connection; a run aborts on the first 429 and records `rate_limited`. |
| No secrets in results | `Observed` is typed per check; no field can hold a credential. A test serialises every result and scans for the configured secret bytes. |
| Minimal personal data | Samples return attribute *fill counts* and distinct counts, not values. Data-check samples for findings (§6.4) carry object ids and display names only, capped at 10, and expire with the run (default 30 days). |
| One run at a time | A per-revision advisory lock; a second `POST …/validate` returns 409 with the running run's id. |
| Rate | At most 6 validation runs per connection per hour, and at most 1 dry run in flight per tenant (Phase 0 `ratelimit`). |
| Audited | `readiness.validation.started`, `.completed` {passed, failed, duration}; never the observed values. |

### 5.3 Network path: `safehttp`, `safedial` and the Directory Agent

- **HTTP connectors** (Entra, Okta, Google, Workday, SCIM) use Phase 0's `safehttp.Client()`: HTTPS only, IPs checked after DNS resolution, no private, loopback or link-local addresses, no cross-host redirects, size and time limits. Each template adds a **host allowlist pattern** (Entra: `login.microsoftonline.com`, `graph.microsoft.com` and the sovereign equivalents; Okta: `*.okta.com`, `*.oktapreview.com`, `*.okta-emea.com` or a verified custom domain; Google: `*.googleapis.com`, `oauth2.googleapis.com`; Workday: `*.workday.com`, `*.myworkday.com`).
- **LDAP from the cloud** uses a new `internal/safedial` package that shares `safehttp`'s address policy for raw TCP (ports 389 and 636 only, TLS required, IP check after resolution). This is rare: most directories are private.
- **Private directories use the Tessera Directory Agent** (DR-11):
  - A small Go binary the customer runs on a Windows or Linux host in their network. It connects **outbound** to Tessera over mTLS (an agent certificate issued at enrolment, bound to one tenant; enrolment uses a single-use code with a 15-minute lifetime, stored only as a hash).
  - It accepts only the fixed `Prober` and `Discover` operations, serialised as typed messages. There is no operation that sends arbitrary bytes or arbitrary LDAP operations.
  - **Local allowlist.** The agent reads `allowed_targets` (host:port pairs) from its own configuration file, which only a local administrator can edit. A request for any other target fails locally. A compromised Tessera tenant admin cannot point the agent at the HR database or scan the network.
  - It stores the directory credential locally (Windows DPAPI or a gMSA), so the bind password never leaves the customer network. Tessera then holds only a reference (`secret_ref = agent:<id>/<name>`), which satisfies `base.cred.sealed`.
  - Heartbeat, version and allowlist hash are visible in Admin → Connections; an out-of-date agent is a Recommended item failure.

### 5.4 Live check catalogue

| Check | What it does (read-only) | Pass criteria | Templates |
|---|---|---|---|
| `cred_storage` | Inspects Tessera's own record | Secret sealed or a vault/agent reference; no secret-shaped values in config | all |
| `cred_expiry` | Certificate `NotAfter`; token or secret expiry where the API reports it | > 30 days | all |
| `clock_skew` | AD rootDSE `currentTime`; HTTP `Date` header | < 120 s (warn), < 300 s (fail) | all where available |
| `tls_handshake`, `tls_chain` | TLS handshake; verify chain against configured CAs; hostname; protocol version | Chain valid, TLS ≥ 1.2, > 30 days to expiry | ad, ldap (HTTP connectors get it via `safehttp`) |
| `bind`, `token_acquire`, `auth_ok` | Simple bind or SASL; OAuth token request | Success | all |
| `bind_identity` | Who Am I extended operation | Not the root DN or a configured forbidden DN | ldap |
| `ad_svc_groups` | Reads `tokenGroups` of the bound account | No privileged SID | ad |
| `ad_effective_rights`, `effective_rights` | `allowedAttributesEffective` on sampled objects; 389-DS Get Effective Rights | Empty, or only on write-back scope | ad, ldap |
| `ad_replication_rights` | Reads the domain head's security descriptor (SD flags control, DACL only) | Bound account not granted DS-Replication-Get-Changes-All | ad |
| `dn_exists` | Base-scope search on each base DN | Exists and readable | ad, ldap |
| `filter_parse`, `sample_search` | Parse filter locally; one search with `sizeLimit` 50 | Parses; returns ≥ 1 object of the expected classes | ad, ldap |
| `read_per_class` | Sample per object class; per-attribute fill counts | Every required attribute returned on ≥ 1 object | ad, ldap |
| `paging`, `range_retrieval` | Fetches page 2 of a paged search; ranged read of the largest group | Pages beyond the limit; ranged count = expected | ad, ldap, scim_app |
| `incremental_capable`, `delta_capable`, `syslog_readable`, `reports_readable` | Reads the change cursor (rootDSE USN, syncrepl support, `$deltatoken=latest`, one System Log page, one Reports page) | Cursor obtained | per template |
| `deleted_objects_readable` | Search CN=Deleted Objects with the show-deleted control, `sizeLimit` 1 | Readable | ad |
| `forest_domains`, `trusts`, `recycle_bin_state` | Reads crossRef objects in the Partitions container, trustedDomain objects, optional features | Every user-bearing domain configured | ad |
| `token_roles`, `token_scopes`, `app_admin_roles`, `dwd_scopes`, `subject_roles` | Decodes the access token or token response; lists admin roles of the app or subject; requests a token for one forbidden scope | Only allowed permissions; forbidden scope refused | entra, okta, google |
| `roles_readable`, `group_rules_readable`, `signin_activity_available`, `deprovisioned_visible` | One small read of each | 200 with data, or a documented empty result | per template |
| `rate_headroom` | Collects rate-limit headers and 429s during the run | Remaining ≥ 50% of the limit; no 429 | entra, okta, google, scim_app |
| `scim_discovery`, `members_complete` | Reads discovery endpoints; compares one group's members from list and get | Capabilities recorded; counts equal | scim_app |
| `field_inventory` | Lists the field names of one sampled worker | No forbidden field present | workday |

### 5.5 Simulated results (demo connectors)

The demo connectors implement `Prober` with **scenarios**: YAML files under `internal/connectors/demo_readiness/` that give each check id a result for each demo system. Two scenarios ship:

- `happy`: everything passes except two Recommended items, so the skip flow can be shown.
- `gaps` (the default demo): realistic misses, for example `demo-ad`'s `ad.groups.range` fails (a 2,100-member group truncated at 1,500), `ad.key.employeeid` fill rate is 61%, `okta.auth.oauth` uses an API token, and `wd.population` lacks contingent workers in the expected-count attestation.

Selected by `TESSERA_READINESS_SCENARIO`. Every simulated result is stored with `simulated = true` and shown with a **Simulated** badge. A simulated result can never satisfy a gate for a non-demo connector type (`readiness.Gate` rejects it, and a test proves it).

---

## 6. Dry-run reconciliation

### 6.1 Staging snapshot

- `POST /api/connections/{id}/dry-run` runs `Discover` on the revision's connector (through the agent if private) and writes the result with `ingest.Stage(tx, runID, result)` into `stg_identities`, `stg_accounts`, `stg_groups`, `stg_memberships` and `stg_attr_stats`. These tables have the same shape as the live tables plus `run_id`, and **no code path copies staged rows into live tables**. Activation starts a normal first sync.
- The connector interface gains two optional fields, backwards-compatible with existing connectors:
  - `AccountRecord.Attributes map[string]string`, limited to the attributes the template maps (correlation and status attributes), never the whole entry.
  - `DiscoveryResult.Stats *DiscoveryStats`: per object class, total objects and per-attribute present and distinct counts, computed by the connector, so fill rates do not require copying attribute values.
- Staging runs are retained for the last 3 runs per revision and deleted 30 days after activation or retirement.
- Isolation test: `TestStage_NoLiveWrites` records the row counts of every live table, runs a dry run, and asserts that nothing changed.

### 6.2 Correlation (tiered, deterministic)

Reconciliation runs the correlation engine (D4·M2) over the staged accounts against (a) the live identities of the **authoritative** HR connection and (b) the live accounts of other active connections.

| Tier | Rule | Outcome |
|---|---|---|
| 1 | Exact match of the mapped HR id attribute (for example `employeeID` = Workday Employee_ID), after normalisation (trim, leading zeros per tenant setting) | `correlated` |
| 2 | Immutable cross-system link to an already-correlated account (Entra `onPremisesImmutableId` = base64 of AD `objectGUID`; Okta profile source id; Google `externalIds`) | `correlated` |
| 3 | Case-insensitive email, UPN or login match | `proposed` (goes to the review queue; never linked automatically) |
| — | Account `kind` is service, or it sits in a configured service-account OU | `service` (needs an owner, not a person) |
| — | No match | `uncorrelated` |

Ambiguities (two identities match at the same tier, or one identity matches two non-service accounts of the same kind in one system) are `ambiguous` and never auto-resolved.

### 6.3 Findings

| Code | Finding | Default severity | Count definition |
|---|---|---|---|
| RF-01 | **Orphan accounts**: enabled accounts that match no person | high; critical if any is in a privileged group | `uncorrelated` and enabled, excluding `service` |
| RF-02 | **People with no account**: active people in the HR source with no account here, where one is expected (all active employees for a directory; birthright policy otherwise) | medium | identities in the expected population without a correlated account |
| RF-03 | **Duplicate and ambiguous correlations**: one account matching several people, several accounts of one kind for one person, or conflicting tier-2 links across connections | high | `ambiguous` accounts plus identities with duplicates |
| RF-04 | **Sparse attributes**: mapped attributes empty in more than X% of records (X = 5% for required attributes, 25% for recommended) | medium (required), low (recommended) | one finding per attribute |
| RF-05 | **Groups out of scope**: memberships pointing at groups outside the base DNs or scope, unresolved foreign security principals, members from other tenants | medium | distinct referenced groups not in the snapshot |
| RF-06 | **Disabled or departed but still holding access**: (a) disabled or expired accounts with group memberships; (b) people terminated in HR whose account here is enabled | (a) medium, (b) high; critical if privileged | accounts |
| RF-07 | **Stale accounts**: enabled, no login for more than the threshold plus the source's lag, or never logged in and created more than 30 days ago | medium | accounts |
| RF-08 | **Unexpected privileged members**: members of privileged groups or roles not on the expected list and not granted by an approved policy, or members that are disabled, external or guests | critical | memberships |
| RF-09 | **Service accounts without an owner** | medium; high if privileged | accounts of kind service with no owner |
| RF-10 | **Uncorrelated by tier-3 only**: accounts that only match by email or UPN (proposals awaiting review) | low | accounts |
| RF-11 | **Password never expires on privileged accounts** (AD DONT_EXPIRE_PASSWORD; LDAP ppolicy exemptions) | high | accounts |
| RF-12 | **Count mismatch**: staged counts outside ±2% of the attested expected counts | high | absolute difference |

Severity rules are data in `internal/reconcile/rules.yaml` (thresholds per tenant overlay). RF-01, RF-06(b) and RF-08 also run continuously after activation, where they become the existing orphan and leaver detections (D4·M2, M7).

### 6.4 Finding record: severity, count, samples, impact

```go
type Finding struct {
	Code        string   // "RF-06"
	Variant     string   // "b"
	Severity    Severity // critical | high | medium | low | info
	Title       string   // "Departed in Workday but enabled in Okta"
	Count       int
	Denominator int      // population the count is measured against
	Samples     []Sample // ≤ 10; object ref, display name, the reason it matched
	Impact      Impact
	Cause       *Cause   // §6.5; nil if no analyser explains it
	ItemID      string   // checklist item that fixes it, if any ("ad.key.employeeid")
	Status      FindingStatus // open | accepted | resolved
}

type Impact struct {
	AffectedIdentities int
	AffectedAccounts   int
	PrivilegedGrants   int      // memberships in privileged groups or roles
	DownstreamPerms    int      // permissions reachable through staged groups via existing maps_to edges (e.g. AD group → AWS role)
	ReviewItems        int      // review items this would add or remove in the next campaign
	Sentence           string   // "12 disabled accounts still in AWS-Prod-Admins, which maps to 3 AWS roles"
}
```

The downstream estimate uses the live graph: staged group nodes are joined with existing `maps_to` and `grants` edges (for example an AD group federated into an AWS role), so impact is stated in terms of what the access actually reaches.

### 6.5 Cause analysis

Analysers run after the findings and attach a probable cause and a fix:

| Analyser | Applies to | Logic | Example output |
|---|---|---|---|
| `unmapped_key` | RF-01, RF-10 | Fill rate of the tier-1 attribute among the unmatched versus the matched | "3,412 accounts uncorrelated because `employeeID` is empty on 97% of them. Fix: `ad.key.employeeid`." |
| `email_would_match` | RF-01 | Counts unmatched accounts with a tier-3 proposal | "3,051 of them match a person by email. Map `employeeID`, or review the proposals." |
| `scope_concentration` | RF-02 | Distribution of missing people by department, location and worker type versus the whole population; flags a slice holding > 60% of the missing | "82% of people with no account are contingent workers in 'Field Ops'. Check the base DN `OU=Contractors`." |
| `leaver_process` | RF-06 | Days since HR termination; whether the account is disabled elsewhere | "3 people left more than 14 days ago and are enabled only here. The leaver process does not cover this system." |
| `scope_exclusion` | RF-05 | Common DN suffix of the out-of-scope groups | "41 groups under `OU=Groups,DC=corp` are outside the base DN." |
| `privileged_policy_gap` | RF-08 | Whether the unexpected members share a nesting path | "All 5 reach Domain Admins through `IT-Helpdesk-L2`." |

### 6.6 Acknowledgement

Each finding is `open`, `accepted` (reason, actor, optional expiry) or `resolved` (a later dry run no longer finds it). Gate rule: no `open` finding of severity critical or high. Medium and low findings remain on the dashboard without blocking.

---

## 7. Deployment health analytics

### 7.1 Connection readiness score

For one connection revision:

1. **Checklist score.** For each applicable item i with weight w (Required 5, Recommended 2, Optional 0) and credit c (pass = 1; pending, fail, blocked, stale or skipped = 0):
   `C = 100 × Σ wᵢcᵢ / Σ wᵢ`.
   Skipped items earn no credit: an accepted gap is still a gap.
2. **Finding penalty.** For each finding, points by severity (critical 15, high 8, medium 3, low 1, info 0); accepted findings count half (rounded down); resolved findings count zero.
   `P = min(40, Σ points)`.
3. **Score.** `S = max(0, round(C − P))`. If any applicable Required item is not passing, `S = min(S, 49)`.
4. **Band.** 90–100 *Healthy*, 70–89 *Needs attention*, 50–69 *At risk*, 0–49 *Not ready*. A connection with more than 10% of its Recommended weight skipped cannot be *Healthy*, whatever its score.

The API returns the breakdown, and the UI shows it as a list that sums to the score:

```json
{"score": 74, "band": "needs_attention",
 "checklist": {"score": 88, "earned": 132, "possible": 150,
   "missing": [{"item": "ad.key.employeeid", "level": "recommended", "points": 2, "status": "fail"},
               {"item": "ad.tls.signing_cb", "level": "recommended", "points": 2, "status": "skipped", "reason": "Scheduled for Q1 DC upgrade"}]},
 "penalty": {"total": 14, "capped": false,
   "findings": [{"code": "RF-01", "severity": "high", "points": 8}, {"code": "RF-07", "severity": "medium", "points": 3}, {"code": "RF-04", "severity": "medium", "points": 3}]}}
```

### 7.2 Tenant score

`T = Σ Sc × nc / Σ nc` over connections whose state is `validated` or later, with `nc` = in-scope accounts in the latest snapshot (minimum 1). Draft connections are listed but excluded. If the tenant has no active authoritative HR source, `T` is capped at 69, because RF-02 cannot be computed. The tenant view also shows the D4·M23 KPIs: percentage of accounts correlated, orphans, dormant over 90 days, privileged account count.

### 7.3 Needs attention

One ranked list per tenant, built from: failing or stale Required items, pending Recommended items, open findings, skips whose review date passed, drift events, expiring credentials and offline agents.

`rank = severity_weight × (1 + log10(1 + affected)) × (privileged ? 2 : 1) × (blocks_activation ? 1.5 : 1)`, with severity weights critical 8, high 4, medium 2, low 1. Ties go to the oldest item.

Each entry has a sentence (from the cause analyser when there is one), the connection, the age, and a single "Fix" link to the checklist item, mapping screen or finding drawer. Examples:

- "3,412 accounts in Active Directory uncorrelated because employeeID isn't mapped." (high, links to `ad.key.employeeid`)
- "Oren Whitlock left 20 days ago and is still active in Okta." (high, privileged: no; links to the finding)
- "Okta uses an API token that expires after 30 days unused, skipped by J. Rivera: 'migration in Q1' (review due in 12 days)."

### 7.4 Skipped recommendations, drift and re-runs

- **Skipped recommendations** have their own table: item, connection, level, who, when, reason and review date. They never disappear from the dashboard while skipped.
- **Baseline.** On activation, Tessera stores a baseline: score, item states, finding counts, object counts and config hash.
- **Scheduled re-runs.** Live checks daily (configurable 1–7 days); post-activation reconciliation weekly, run against the live tables instead of staging. The schedule is a job in Admin → Jobs.
- **On-demand re-run.** `POST /api/insights/deployment-health/rerun` (tenant) or per connection.
- **Drift** compares every run with the baseline: newly failing checks, finding counts moving beyond tolerance (±10% or ±25 objects, whichever is larger), object counts moving beyond ±5% between consecutive runs (a sign of a scope or permission change), credentials within 30 days of expiry, template updates with new Required items (30-day grace), and changes made outside Tessera, such as a new write permission on the service account.

### 7.5 Degraded

A revision moves `active → degraded` when a Required live check fails on two consecutive scheduled runs, a credential is within 7 days of expiry, sync has failed for more than 24 hours, the change cursor was lost three times in 7 days, or a new Required template item passes its grace period. In `degraded`:

- reads continue, so the graph stays as current as possible, and data from the connection is labelled "from a degraded connection" in reviews;
- write-back stops (`CanWrite` is false);
- an Inbox task goes to the connection's technical owner, and the Home admin card shows it.

### 7.6 Evidence export

`GET /api/connections/{id}/readiness/evidence` and `GET /api/insights/deployment-health/evidence` return a ZIP containing `manifest.json` (SHA-256 of every file, template versions, generation time, the audit ledger sequence range and chain head), `checklist.csv` (item, level, status, verification, attester or check run, timestamps), `checks.csv`, `findings.csv` (counts, severity, status, acceptance reasons; samples as object ids only), `skipped.csv` and `score.json`. The export itself is audited (`readiness.evidence.exported` with the manifest hash), so an auditor can verify it against the ledger with `tessera audit verify`.

The export is mapped to the controls auditors test: SOC 2 CC6.1 to CC6.3 (logical access provisioning and removal), ISO/IEC 27001:2022 Annex A 5.15 to 5.18 (access control, identity management, access rights), SOX ITGC completeness and accuracy of user listings (IPE), and PCI DSS v4 8.2.6 (inactive accounts). The mapping is text in the manifest; Tessera does not claim the export satisfies a control on its own (README correction on auditor endorsement).

---

## 8. Data model (Go structs and SQL DDL)

### 8.1 Conventions

Phase 0 §7.1 applies: `tenant_id` on every table; UUID text primary keys for new tables; every unique constraint starts with `tenant_id`; RFC 3339 UTC text timestamps in SQLite; typed JSON columns; all SQL in `internal/store`. **Before Phase 0 PR1 (#5) lands**, the MVP slice creates the same tables inside `store.Migrate` with `tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000002'` (a fixed default-tenant id). PR1's migration then adds the foreign key and removes the default. The struct field is `TenantID tenancy.ID` once `tenancy` exists, and a `string` alias until then.

New files: `internal/store/schema/0201_connections.sql`, `0202_readiness.sql`, `0203_staging.sql`; `internal/store/model_readiness.go`, `repo_connections.go`, `repo_readiness.go`, `repo_staging.go`.

### 8.2 Go structs

```go
// internal/store/model_readiness.go
package store

type Connection struct {
	ID               string
	TenantID         tenancy.ID
	Name             string
	ConnectorType    string  // ad | ldap | entra | okta | google | workday | scim_app | demo-*
	System           string  // graph system name, e.g. "ad-corp"
	Role             string  // authoritative | account_source
	ActiveRevisionID *string
	Health           string  // ok | degraded | none
	TechnicalOwnerID *string // platform user
	BusinessOwner    *string
	AgentID          *string
	CreatedAt, UpdatedAt time.Time
	RetiredAt        *time.Time
}

type ConnectionRevision struct {
	ID              string
	TenantID        tenancy.ID
	ConnectionID    string
	Rev             int
	State           RevisionState // draft | ready_to_validate | validated | dry_run_reconciled | active | degraded | retired | superseded
	TemplateID      string
	TemplateVersion string        // "1.0"
	OverlayVersion  int
	Config          ConnConfig    // typed per connector type; no secrets
	SecretRef       *string       // sealed:<id> | vault:<path> | agent:<id>/<name>
	SecretVersion   *string
	ConfigHash      string
	WriteMode       string        // off | dry_run | scoped
	ExpectedCounts  *ExpectedCounts
	ActivatedAt     *time.Time
	ActivatedBy     *string
	GateReport      *GateReport   // stored on every transition attempt that succeeded
	CreatedBy       string
	CreatedAt, UpdatedAt time.Time
}

type ReadinessItemState struct {
	TenantID     tenancy.ID
	RevisionID   string
	ItemID       string
	Level        Level  // effective level after overlay
	Status       ItemStatus
	Source       string // attestation | live | data | skip
	ActorID      *string
	Note         *string // attestation note or skip reason
	ReviewBy     *time.Time
	CheckRunID   *string
	ConfigHash   string
	UpdatedAt    time.Time
}

type CheckRun struct {
	ID, RevisionID string
	TenantID       tenancy.ID
	Kind           string // validation | scheduled | dry_run
	Simulated      bool
	AgentID        *string
	Status         string // running | completed | aborted | rate_limited
	ConfigHash     string
	StartedAt      time.Time
	FinishedAt     *time.Time
}

type CheckResult struct {
	RunID, CheckID string
	TenantID       tenancy.ID
	ItemIDs        []string
	Status         string // pass | fail | warn | error | skipped | blocked
	Observed       CheckObserved // typed union, JSON
	Message        string
	DurationMS     int
}

type ReconRun struct {
	ID, RevisionID string
	TenantID       tenancy.ID
	Mode           string // staging | live
	CheckRunID     string
	Counts         ReconCounts // staged objects per class, correlated per tier
	StartedAt      time.Time
	FinishedAt     *time.Time
	Status         string
}

type ReconFinding struct {
	ID, RunID   string
	TenantID    tenancy.ID
	ConnectionID string
	Code, Variant string
	Severity    string
	Count, Denominator int
	Samples     []FindingSample
	Impact      FindingImpact
	Cause       *FindingCause
	ItemID      *string
	Status      string // open | accepted | resolved
	AcceptedBy  *string
	Reason      *string
	ExpiresAt   *time.Time
	FirstSeenAt, LastSeenAt time.Time
}

type ReadinessScore struct {
	TenantID     tenancy.ID
	Scope        string  // connection | tenant
	ConnectionID *string
	RevisionID   *string
	ComputedAt   time.Time
	Score        int
	Band         string
	Breakdown    ScoreBreakdown
}

type ReadinessBaseline struct {
	TenantID   tenancy.ID
	RevisionID string
	CapturedAt time.Time
	Score      int
	Snapshot   BaselineSnapshot // item states, finding counts, object counts
}

type ReadinessOverlay struct {
	ID           string
	TenantID     tenancy.ID
	ConnectorType string
	ConnectionID *string        // nil = all connections of the type
	Version      int
	Body         OverlayBody    // custom items, raised levels, thresholds
	UpdatedBy    string
	UpdatedAt    time.Time
}
```

### 8.3 SQL DDL (SQLite dialect; Postgres generated as in Phase 0 §7.5)

```sql
-- 0201_connections.sql
CREATE TABLE connections (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  connector_type TEXT NOT NULL,
  system TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'account_source' CHECK (role IN ('authoritative','account_source')),
  active_revision_id TEXT,
  health TEXT NOT NULL DEFAULT 'none' CHECK (health IN ('none','ok','degraded')),
  technical_owner_id TEXT, business_owner TEXT, agent_id TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, retired_at TEXT,
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, system)
);
CREATE INDEX connections_tenant ON connections(tenant_id);

CREATE TABLE connection_revisions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  connection_id TEXT NOT NULL REFERENCES connections(id),
  rev INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('draft','ready_to_validate','validated','dry_run_reconciled','active','degraded','retired','superseded')),
  template_id TEXT NOT NULL, template_version TEXT NOT NULL, overlay_version INTEGER NOT NULL DEFAULT 0,
  config TEXT NOT NULL,                 -- typed JSON, no secrets
  secret_ref TEXT, secret_version TEXT,
  config_hash TEXT NOT NULL,
  write_mode TEXT NOT NULL DEFAULT 'off' CHECK (write_mode IN ('off','dry_run','scoped')),
  expected_counts TEXT,                 -- JSON
  gate_report TEXT,                     -- JSON of the last successful transition
  activated_at TEXT, activated_by TEXT,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connection_id, rev)
);
-- at most one live and one in-progress revision per connection
CREATE UNIQUE INDEX conn_rev_live ON connection_revisions(tenant_id, connection_id)
  WHERE state IN ('active','degraded');
CREATE UNIQUE INDEX conn_rev_pending ON connection_revisions(tenant_id, connection_id)
  WHERE state IN ('draft','ready_to_validate','validated','dry_run_reconciled');

-- 0202_readiness.sql
CREATE TABLE readiness_item_states (
  tenant_id TEXT NOT NULL, revision_id TEXT NOT NULL REFERENCES connection_revisions(id),
  item_id TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('required','recommended','optional')),
  status TEXT NOT NULL CHECK (status IN ('pending','pass','fail','blocked','stale','skipped','not_applicable')),
  source TEXT NOT NULL CHECK (source IN ('attestation','live','data','skip','system')),
  actor_id TEXT, note TEXT, review_by TEXT, check_run_id TEXT,
  config_hash TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id, item_id),
  CHECK (status <> 'skipped' OR (level = 'recommended' AND length(note) >= 20))
);
CREATE TABLE readiness_check_runs (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, revision_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('validation','scheduled','dry_run')),
  simulated INTEGER NOT NULL DEFAULT 0, agent_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('running','completed','aborted','rate_limited')),
  config_hash TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT
);
CREATE INDEX check_runs_rev ON readiness_check_runs(tenant_id, revision_id, started_at);
CREATE TABLE readiness_check_results (
  tenant_id TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES readiness_check_runs(id),
  check_id TEXT NOT NULL, item_ids TEXT NOT NULL,     -- JSON list
  status TEXT NOT NULL CHECK (status IN ('pass','fail','warn','error','skipped','blocked')),
  observed TEXT NOT NULL, message TEXT NOT NULL, duration_ms INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, run_id, check_id)
);
CREATE TABLE recon_runs (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, revision_id TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('staging','live')),
  check_run_id TEXT NOT NULL, counts TEXT, status TEXT NOT NULL,
  started_at TEXT NOT NULL, finished_at TEXT
);
CREATE TABLE recon_findings (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES recon_runs(id),
  connection_id TEXT NOT NULL, code TEXT NOT NULL, variant TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  count INTEGER NOT NULL, denominator INTEGER NOT NULL,
  samples TEXT NOT NULL, impact TEXT NOT NULL, cause TEXT, item_id TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','resolved')),
  accepted_by TEXT, reason TEXT, expires_at TEXT,
  first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
  CHECK (status <> 'accepted' OR length(reason) >= 20)
);
CREATE INDEX recon_findings_conn ON recon_findings(tenant_id, connection_id, status, severity);
CREATE TABLE readiness_scores (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('connection','tenant')),
  connection_id TEXT, revision_id TEXT,
  computed_at TEXT NOT NULL, score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  band TEXT NOT NULL, breakdown TEXT NOT NULL
);
CREATE INDEX readiness_scores_series ON readiness_scores(tenant_id, scope, connection_id, computed_at);
CREATE TABLE readiness_baselines (
  tenant_id TEXT NOT NULL, revision_id TEXT NOT NULL, captured_at TEXT NOT NULL,
  score INTEGER NOT NULL, snapshot TEXT NOT NULL,
  PRIMARY KEY (tenant_id, revision_id)
);
CREATE TABLE readiness_overlays (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
  connector_type TEXT NOT NULL, connection_id TEXT,
  version INTEGER NOT NULL, body TEXT NOT NULL,
  updated_by TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, connector_type, connection_id, version)
);
CREATE TABLE directory_agents (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
  cert_fingerprint TEXT NOT NULL, enrolment_code_hash TEXT, enrolled_at TEXT,
  last_seen_at TEXT, version TEXT, allowlist_hash TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending','online','offline','revoked')),
  UNIQUE (tenant_id, name)
);

-- 0203_staging.sql (mirrors live tables; abridged)
CREATE TABLE stg_accounts (
  tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, system TEXT NOT NULL, external_id TEXT NOT NULL,
  username TEXT, kind TEXT, status TEXT, created_at TEXT, last_login_at TEXT,
  attributes TEXT,                       -- JSON, mapped attributes only
  correlation TEXT,                      -- tier result: correlated | proposed | service | ambiguous | uncorrelated
  identity_id INTEGER, proposed_identity_id INTEGER,
  PRIMARY KEY (tenant_id, run_id, system, external_id)
);
CREATE TABLE stg_groups (
  tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, system TEXT NOT NULL, external_id TEXT NOT NULL,
  name TEXT NOT NULL, kind TEXT, privileged INTEGER NOT NULL DEFAULT 0, in_scope INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, run_id, system, external_id)
);
CREATE TABLE stg_memberships (
  tenant_id TEXT NOT NULL, run_id TEXT NOT NULL,
  member_kind TEXT NOT NULL, member_xid TEXT NOT NULL, group_xid TEXT NOT NULL,
  PRIMARY KEY (tenant_id, run_id, member_kind, member_xid, group_xid)
);
CREATE TABLE stg_attr_stats (
  tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, object_class TEXT NOT NULL, attribute TEXT NOT NULL,
  total INTEGER NOT NULL, present INTEGER NOT NULL, distinct_values INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, run_id, object_class, attribute)
);
```

`TestIsolation_ReadinessTables` (Phase 0 §14.4 meta-test) covers every table above.

### 8.4 Packages

```
internal/readiness/
  template/        types, YAML loader, linter, overlay merge (no downgrades)
  templates/       base.yaml, ad.yaml, ldap.yaml, entra.yaml, okta.yaml, google.yaml, workday.yaml, scim_app.yaml
  checks/          registry; live checks; data checks
  runner.go        validation runs (timeouts, ordering, persistence)
  state.go         state machine; the only writer of revision state
  gate.go          gate evaluation and reports
  score.go         §7.1–7.3
  drift.go         baselines, scheduled re-runs, degraded
  evidence.go      export
internal/reconcile/  correlation tiers over staging, finding rules, impact, cause analysers
internal/connectors/ probe.go (Prober), demo_readiness/ (scenarios), demo_ad.go (simulated AD from DemoCompany)
internal/agent/      agent protocol (DR-11); cmd/tessera-agent
internal/safedial/   raw TCP dialer with the safehttp address policy (DR-11)
```

---

## 9. API

All routes are tenant-scoped (Phase 0 §12.4). New permissions: `connections.read` (tenant_admin, auditor, read-only admin), `connections.manage` (tenant_admin, connector_admin), `connections.activate` (tenant_admin; step-up required). Routes are added to `openapi.json`.

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/api/readiness/templates` | `connections.read` | List templates (id, version, display name, item counts) |
| GET | `/api/readiness/templates/{type}` | `connections.read` | Full template after the tenant overlay |
| PUT | `/api/readiness/overlays/{type}` | `connections.manage` + step-up | Add items, raise levels, tighten thresholds; 422 on downgrade |
| GET | `/api/connections` | `connections.read` | Connections with state, health, score and blocking count |
| POST | `/api/connections` | `connections.manage` | Create (state `draft`) |
| GET | `/api/connections/{id}` | `connections.read` | Connection, active and pending revisions |
| PATCH | `/api/connections/{id}/config` | `connections.manage` | Edit the pending revision (creates one if the connection is active); returns invalidated items |
| PUT | `/api/connections/{id}/credential` | `connections.manage` + step-up | Write-only credential or reference; never returned |
| GET | `/api/connections/{id}/checklist` | `connections.read` | Items with level, status, verification, dependencies, blockers |
| POST | `/api/connections/{id}/checklist/{item}/attest` | `connections.manage` | `{note}`; 409 if dependencies are not passing |
| POST | `/api/connections/{id}/checklist/{item}/skip` | `connections.manage` | `{reason, review_by?}`; 422 for Required items |
| DELETE | `/api/connections/{id}/checklist/{item}/skip` | `connections.manage` | Un-skip |
| POST | `/api/connections/{id}/validate` | `connections.manage` | Start a validation run; 202 with run id; 409 if one is running |
| GET | `/api/connections/{id}/validations/{run}` | `connections.read` | Results per check |
| POST | `/api/connections/{id}/dry-run` | `connections.manage` | Start a staging sync and reconciliation; 202 |
| GET | `/api/connections/{id}/dry-runs/{run}` | `connections.read` | Counts, correlation tiers, findings summary |
| GET | `/api/connections/{id}/findings` | `connections.read` | Filter by run, code, severity, status |
| POST | `/api/connections/{id}/findings/{fid}/accept` | `connections.manage` (+ step-up for critical) | `{reason, expires_at?}` |
| POST | `/api/connections/{id}/transition` | per §4.2 | `{to: "ready_to_validate" \| "dry_run_reconciled"}`; 409 with the gate report |
| POST | `/api/connections/{id}/activate` | `connections.activate` + step-up | 409 with the gate report; 202 pending second approval for write-enabled |
| POST | `/api/connections/{id}/retire` | `connections.manage` + step-up | |
| GET | `/api/connections/{id}/health` | `connections.read` | Score breakdown, drift since baseline, schedule |
| GET | `/api/connections/{id}/readiness/evidence` | `connections.read` + `audit.export` | ZIP (§7.6) |
| GET | `/api/insights/deployment-health` | `connections.read` | Tenant score, per-connection scores, needs-attention, skipped items, drift |
| POST | `/api/insights/deployment-health/rerun` | `connections.manage` | Re-run live checks (and optionally reconciliation) for all connections |
| GET | `/api/insights/deployment-health/evidence` | `connections.read` + `audit.export` | Tenant ZIP |

`GET /api/connectors` keeps its response and adds `connection_id`, `state` and `score` fields when a connector is backed by a connection, and `legacy: true` for env-configured demo connectors. `GET /api/summary` gains `readiness: {score, band, needs_attention, draft, degraded}` for the Home card.

---

## 10. UI

Everything follows the current design system in `mvp/frontend/src/`: `Page` with crumbs, `Tabs`, `DataTable` (sorting, CSV export, narrow-screen columns), `Kpi`, `Bar`, `Badge` and `PreviewBadge`, `Sev`, `Status`, `Callout`, `Drawer`, `Dialog` and `ConfirmProvider`, `FilterChips`, `Segmented`, `EmptyState`, toasts. Two new shared components: `components/Stepper.tsx` and `components/Checklist.tsx`. While a page runs on the mock layer it carries the **Preview** badge, as today; once DR-5 ships it is live. Simulated check results carry a **Simulated** badge (`Badge tone="info"`, with a title explaining the demo scenario).

### 10.1 Navigation

- Admin → **Connections & integrations** (`/admin/connections`, already `live`) becomes the connection list: name, type, state (`Status`), health, readiness score (`Bar`), blocking items, last sync. "New connection" opens the wizard. The existing "Sync all now" stays for legacy demo connectors.
- New routes: `/admin/connections/new`, `/admin/connections/:id` (wizard and detail), `/admin/connections/:id/validation/:run`, `/admin/connections/:id/reconciliation/:run`.
- Insights gets `{ path: "/insights/deployment-health", label: "Deployment health", keywords: "readiness checklist deployment gaps connection setup reconciliation orphans missed" }` in `app/nav.ts`, so the sidebar, breadcrumbs and command palette pick it up.
- Command palette actions: "New connection", "Run deployment health check".

### 10.2 Connection setup wizard with checklist panel

Two columns on wide screens (the checklist panel stacks under the form on narrow screens):

- **Left: `Stepper`**: 1 Choose type → 2 Connect (endpoint, agent, credential, transport, owners) → 3 Scope (base DNs with a DN browser, filters, OUs, populations, expected counts) → 4 Mapping (correlation key, HR id, status attributes, required attributes) → 5 Validate → 6 Dry run → 7 Review and activate. Each step shows which checklist items it satisfies. Steps 5 to 7 are disabled until the state allows them, with the reason in a `Callout`.
- **Right: `ChecklistPanel`** (sticky): a header with progress ("Required 21/25 · Recommended 9/18 · Optional 1/4") and the current score; `FilterChips` for All, Blocking, Required, Recommended, Optional, Skipped; items grouped by category (Credentials and access, Transport, Scope, Identity keys, Account status, Groups, Change tracking, Data quality, Topology, Write-back).
  - Each row has a status icon *and* a text label (Pass, Fail, Pending, Blocked by …, Stale, Skipped, N/A), so state is never conveyed by colour alone; a level `Badge`; and the verification method (Attest, Live check, Data check).
  - Expanding a row shows *why it matters*, *how it is verified*, the last evidence, the remediation hint and link, and dependencies.
  - Attestation items are real checkboxes. Ticking one opens a `Dialog` asking for a note; the box is checked only after the server accepts it.
  - Recommended items have "Skip…", which opens a `Dialog` with a reason (minimum 20 characters) and a review date. Required items have no skip control.
- **Activate** is a primary button. When disabled, a list of blockers is shown under it (the same gate report the server returns). The server enforces the same rules (§4.4).

### 10.3 Validation results

A `DataTable` of checks grouped by category: status (`Status`), check, items it covers, observed value (for example "TLS 1.3, expires in 212 days", "sizeLimit 500, paging OK"), duration, message, remediation link. A `Kpi` row with passed, failed, blocked and duration. "Re-run" and "Re-run failed only" buttons. Stale results are labelled "Older than 24 h: re-run before activating". The Simulated badge appears on the page header when results are simulated.

### 10.4 Reconciliation report

- `Kpi` row: objects staged (accounts, groups, memberships), correlated (with a tier breakdown in a `Bar`), orphans, people with no account, privileged unexpected.
- Findings `DataTable`: severity (`Sev`), code and title, count and percentage of the denominator, impact sentence, cause, status. `FilterChips` by severity and status. CSV export.
- A finding row opens a `Drawer` with samples (ids and names only), the cause analysis, the fix link (to the checklist item or mapping field), and "Accept with reason" (a `Dialog`; step-up for critical findings).
- A `Callout` at the top states what activation would do: "Activating will add 3,412 accounts to the graph; 3,412 will be orphans until employeeID is mapped."

### 10.5 Insights → Deployment health

- Header `Kpi`s: tenant readiness score and band, accounts correlated (%), open critical and high findings, connections not yet active or degraded.
- **Connections**: a table with score `Bar`, band, state, last validated, drift indicator; each row links to the connection detail.
- **Needs attention**: the ranked list from §7.3, each with severity, sentence, connection, age and a "Fix" button.
- **Skipped recommendations**: item, connection, who, when, reason, review date.
- **Drift since activation**: per connection, baseline versus now (score, findings, counts), with a small `Segmented` switch for 7, 30 and 90 days.
- Actions: "Re-run now", the schedule ("Daily at 02:00; reconciliation weekly"), and "Export evidence".

### 10.6 Home cards for admins

In `AdminOverview` (`features/home/Home.tsx`), a fifth `Kpi`: "Deployment readiness" with the tenant score, the band as the tone (`warning` below 70, `critical` below 50), and the sub-line "N items need attention · M connections in setup", linking to `/insights/deployment-health`. Below the KPI grid, a "Needs attention" card listing the top three entries, each with its Fix link. Degraded connections also create Inbox tasks (a new `InboxKind` source `connection`).

### 10.7 Accessibility

Checklist rows are list items with `aria-describedby` pointing at the status text; the stepper uses `aria-current="step"`; dialogs trap focus (existing `Dialog`); the score is never conveyed by colour alone (the band text is always shown).

---

## 11. Security considerations

| Threat | Mitigation |
|---|---|
| A readiness check modifies the customer directory | `Prober` has no write methods; recorder test on every prober; least privilege is checked by reading effective rights (K7). |
| SSRF through connection endpoints | `safehttp` and `safedial` address policy; per-template host allowlists; agent-side local allowlist (K8). |
| A compromised tenant admin pivots through the agent | The agent only runs typed read operations against local-allowlisted targets; it cannot be told to dial elsewhere. Agent certificates are per tenant and revocable. |
| Credential exposure | Write-only credential endpoint; sealed with AAD (Phase 0 §7.1), or held only by the agent; results and exports are scanned for secret bytes in tests. |
| Personal data in readiness artefacts | Fill counts instead of values; samples capped at 10, ids and names only, deleted after 30 days; Workday forbidden fields fail a check before any data sync. |
| Bypassing the gate | One state writer; `ActiveConnection` type cannot be constructed outside `readiness`; compare-and-set activation; server returns the gate report; simulated results cannot satisfy gates for real connector types. |
| Accepting risk without accountability | Skip and accept reasons are mandatory, audited, attributable and visible on the dashboard; critical acceptance needs step-up; two-person activation for write-enabled connections. |
| Evidence tampering | Export manifest hash recorded in the audit ledger; chain verification with `tessera audit verify`. |
| Denial of service against the customer's IdP | Run limits, concurrency 2, abort on first 429, rate-limit headroom target 50%. |

---

## 12. MVP slice

Buildable now on the Go backend and the demo company, without Phase 0 and without a real directory.

| Area | In the MVP slice | Later |
|---|---|---|
| Templates | All 8 YAML files (base + 7), loader, linter, golden counts; overlays with the no-downgrade rule | Template upgrade and grace flow (DR-9) |
| Connections and gating | `connections`, `connection_revisions`, item states; full state machine and gates; API with 409 gate reports; audit via the current `audit()` helper, with event names from §4.2 | Step-up, RBAC, two-person activation (DR-10); ledger events (DR-8) |
| Validation | Check framework, runner, timeouts, persistence; `Prober` implemented by demo connectors from scenarios (`happy`, `gaps`); a simulated `demo-ad` connector built from DemoCompany people (sAMAccountName, objectGUID, employeeID filled for 61%, a 2,100-member group, Domain Admins with one unexpected member, 3 service accounts without owners, stale and expired accounts) that is used only in staging unless activated | Real live checks per directory (DR-12 to DR-18), agent (DR-11) |
| Reconciliation | Staging tables, `ingest.Stage`, tiers 1–3, RF-01 to RF-12, impact through existing `maps_to` edges, the six cause analysers | Post-activation live reconciliation on schedule (DR-9) |
| Analytics | Score, tenant score, needs-attention, skipped list, on-demand re-run, `GET /api/insights/deployment-health` | Scheduled re-runs, drift and Degraded (DR-9); evidence export (DR-8) |
| UI | Wizard with checklist panel, validation results, reconciliation report, Insights → Deployment health, Home card | Agent enrolment screens (DR-11) |

**Demo walkthrough the slice must support.** An admin opens Admin → Connections → New connection → Active Directory (demo). The checklist shows 49 items (46 applicable: write-back is off and the demo has no Entra connection). Attestations move it to *Ready to validate*. Validation shows `ad.groups.range` failing and `ad.key.employeeid` at 61%. After fixing the simulated range setting (a scenario toggle), validation passes. The dry run finds RF-01 orphans with the cause "employeeID empty on 94% of them", RF-08 with one unexpected Domain Admin, and RF-09 with three unowned service accounts. The admin accepts RF-09 with a reason, skips `ad.tls.signing_cb` with a reason, and activates. Insights → Deployment health shows the tenant score, the Okta finding that Oren Whitlock left 20 days ago and is still active, the skipped item, and the Home card shows "Deployment readiness 74 · Needs attention".

**MVP non-goals.** No real network calls; no non-demo connector type can be activated until DR-10 (the server returns 403 `phase0_required` for non-demo types while `TESSERA_ENV` is not `dev`).

---

## 13. Implementation plan (ordered PRs)

Every PR: `cd mvp && ./run.sh test` and `./run.sh build` pass; existing API parity tests stay green; new tables are covered by the isolation meta-test once #5 lands.

### DR-1: Readiness templates and linter (2–3 days) · MVP slice

- **Files:** `internal/readiness/template/{types.go,load.go,lint.go,overlay.go}`, `internal/readiness/templates/{base,ad,ldap,entra,okta,google,workday,scim_app}.yaml`, `internal/readiness/template/testdata/counts.golden`, `cmd/tessera` subcommand `readiness lint`.
- **Tests:** `TestTemplates_Lint` (every shipped template: unique ids, known check names per connector type, DAG, required fields present, remediation non-empty), `TestTemplates_Counts` (golden counts in §3.14), `TestOverlay_NoDowngrade` (table: lowering, removing or disabling an item → error; raising and adding → ok), `TestAppliesWhen_ClosedVocabulary`, `TestVersionPinning`.

### DR-2: Connections, state machine and server-side gating (4 days) · MVP slice

- **Files:** schema `0201_connections.sql`, `0202_readiness.sql` (item states only; runs in DR-3) inside `store.Migrate` with the default tenant id, `internal/store/{model_readiness.go,repo_connections.go,repo_readiness.go}`, `internal/readiness/{state.go,gate.go,confighash.go}`, `internal/api/connections.go` (create, get, list, config, credential, checklist, attest, skip, transition, activate, retire), `openapi.json`, audit events from §4.2.
- **Tests:** `TestStateMachine_AllTransitions` (table of state × action), `TestGate_EachConditionBlocks`, `TestActivate_409GateReport`, `TestSkipRequired_422`, `TestSkipReasonMinLength`, `TestConfigEdit_InvalidatesDependentItems`, `TestActiveEdit_CreatesRevision`, `TestActivate_ConcurrentCAS`, `TestOnlyReadinessWritesConnectionState` (go/parser source scan), `TestLegacyConnectors_Unchanged`.

### DR-3: Check framework and simulated validation for demo connectors (3–4 days) · MVP slice

- **Files:** `internal/connectors/probe.go` (`Prober`), `internal/connectors/demo_readiness/{happy,gaps}.yaml`, `internal/connectors/demo_ad.go` (simulated AD built from DemoCompany; staging only by default), `internal/readiness/checks/` (registry plus all check ids referenced by templates, each with a demo implementation), `internal/readiness/runner.go`, `0202_readiness.sql` (runs and results), routes `validate` and `validations/{run}`.
- **Tests:** `TestRunner_TimeoutPerCheck` (slow fake prober), `TestRunner_DependencyBlocks`, `TestRunner_ConfigHashStale`, `TestRunner_LiveTTL`, `TestProbers_ReadOnly` (recorder), `TestResults_NoSecretBytes`, `TestSimulated_CannotGateRealTypes`, `TestScenarios_Deterministic`, `TestDemoAD_DoesNotChangeDefaultSeed` (default `demo` spec output unchanged, so parity fixtures hold).

### DR-4: Staging snapshot and dry-run reconciliation (5 days) · MVP slice

- **Files:** `0203_staging.sql`, `internal/store/repo_staging.go`, `internal/ingest/stage.go`, `internal/connectors/connector.go` (optional `Attributes` and `Stats`), `internal/reconcile/{correlate.go,rules.go,rules.yaml,impact.go,cause.go}`, routes `dry-run`, `dry-runs/{run}`, `findings`, `findings/{id}/accept`.
- **Tests:** `TestStage_NoLiveWrites`, `TestCorrelation_Tiers` (tier 3 only proposes), `TestCorrelation_Ambiguous`, golden findings over DemoCompany plus `demo-ad` (`TestFindings_Golden`: RF-06(b) contains exactly Oren Whitlock for Okta; RF-08 contains the planted Domain Admin; RF-09 equals 3), `TestImpact_ThroughMapsTo`, `TestCause_UnmappedKey`, `TestSamples_CappedAndMinimal`, `TestAccept_ReasonRequired`.

### DR-5: Readiness score, needs-attention and dashboard API (3 days) · MVP slice

- **Files:** `internal/readiness/{score.go,attention.go}`, `readiness_scores` table, `internal/api/deployment_health.go` (`/api/insights/deployment-health`, `/rerun`, `/api/connections/{id}/health`), `/api/summary` `readiness` block, `/api/connectors` additions.
- **Tests:** `TestScore_Formula` (golden table including the cap at 49, the 40-point penalty cap and half-weight accepted findings), `TestScore_BreakdownSumsToScore`, `TestTenantScore_Weighted`, `TestTenantScore_NoHRSourceCap`, `TestAttention_Ranking`, `TestSummary_ReadinessBlock`.

### DR-6: Setup wizard, checklist panel, validation results and reconciliation report UI (5 days) · MVP slice

- **Files:** `mvp/frontend/src/components/{Stepper.tsx,Checklist.tsx}`, `features/admin/connections/{ConnectionsList.tsx,Wizard.tsx,ValidationResults.tsx,ReconReport.tsx,FindingDrawer.tsx}`, routes in `app/App.tsx`, `api.ts` types, `features/admin/Admin.tsx` (Connections section), command palette actions.
- **Tests:** `npm run build` type-check; a scripted walkthrough of §12 recorded in the PR (screenshots in light and dark, narrow and wide); keyboard-only pass over the checklist and dialogs.

### DR-7: Insights → Deployment health and Home cards (3 days) · MVP slice

- **Files:** `features/insights/DeploymentHealth.tsx`, `app/nav.ts`, `features/home/Home.tsx` (Kpi and Needs attention card), `features/inbox/model.ts` (connection tasks).
- **Tests:** type-check; walkthrough screenshots; the Home card renders with the API down (Loading and error states).

### DR-8: Evidence export and audit-ledger events (2 days)

- **Depends on:** Phase 0 PR3 (#7).
- **Files:** `internal/readiness/evidence.go`, export routes, ledger event catalogue additions (`connection.*`, `readiness.*`), control mapping text.
- **Tests:** `TestEvidence_ManifestHashes`, `TestEvidence_LedgerEventMatchesManifest`, `TestEvidence_NoSamplesBeyondIds`.

### DR-9: Drift, Degraded state, scheduled re-runs and template upgrades (3 days)

- **Files:** `internal/readiness/drift.go`, `readiness_baselines`, scheduler job in Admin → Jobs, `CanWrite`, live-mode reconciliation, template minor-upgrade grace logic, Inbox task source.
- **Tests:** `TestDrift_Tolerances`, `TestDegraded_TwoConsecutiveFailures`, `TestDegraded_BlocksWrite`, `TestRecovered`, `TestTemplateUpgrade_GracePeriod`.

### DR-10: Tenancy, RBAC, step-up and two-person activation (2 days)

- **Depends on:** Phase 0 PR1 (#5), PR5 (#9), PR8 (#12), PR12 (#16).
- **Files:** permissions in `internal/auth/rbac.go`, route declarations with step-up, admin-change applier `connection.activate`, migration removing the default tenant id, `TestIsolation_ReadinessTables`.
- **Tests:** permission matrix test per route, step-up required on activate, credential and critical acceptance, two-person rule for write-enabled connections, isolation.

### DR-11: Directory agent and `safedial` (5 days)

- **Depends on:** Phase 0 PR2 (#6).
- **Files:** `internal/safedial/`, `internal/agent/` (protocol, enrolment, mTLS), `cmd/tessera-agent` (local allowlist, DPAPI or file credential store, heartbeat), `directory_agents` table, Admin → Connections agent screens.
- **Tests:** `TestSafedial_BlocksPrivateUnlessAgent`, `TestAgent_RejectsNonAllowlisted`, `TestAgent_OnlyTypedOps`, `TestEnrolment_SingleUseHashed`, an in-process LDAP test server for end-to-end probe calls.

### DR-12: Active Directory live checks against a test domain (4 days, needs-human)

- **Files:** `internal/connectors/ad/probe.go` (all `ad` checks in §5.4), DirSync and USN cursor handling, objectGUID decoding.
- **Tests:** unit tests on recorded LDAP responses; an integration suite tagged `addc` run against a real test domain (a human provides the domain controller, test OUs, a large group and the service account).

### DR-13: OpenLDAP and 389-DS live checks (3 days, needs-human)

- **Files:** `internal/connectors/ldap/probe.go`, schema variants, syncrepl and retro changelog detection, Get Effective Rights.
- **Tests:** containers for OpenLDAP and 389-DS in an integration job (a human approves the CI change under `.github/`), recorded fixtures for unit tests.

### DR-14: Entra ID live checks (3 days, needs-human)

- **Files:** `internal/connectors/entra/probe.go` (token roles, delta, sign-in activity, roles, guests), sovereign-cloud allowlists.
- **Tests:** recorded Graph fixtures; integration against a developer tenant provided by a human.

### DR-15: Okta live checks (2 days, needs-human)

- **Files:** `internal/connectors/okta/probe.go` (scopes, admin role of the app, DEPROVISIONED visibility, System Log, rate-limit headers).
- **Tests:** recorded fixtures; integration against an Okta developer org.

### DR-16: Google Workspace live checks (2 days, needs-human)

- **Files:** `internal/connectors/google/probe.go` (DWD scope probe including the forbidden-scope refusal, subject roles, domains, quotas, Reports API).
- **Tests:** recorded fixtures; integration against a test Workspace.

### DR-17: Workday live checks (3 days, needs-human)

- **Files:** `internal/connectors/workday/probe.go` (endpoint, field inventory with forbidden fields, population mix, incremental criteria), time-zone handling.
- **Tests:** recorded SOAP and RaaS fixtures; integration against a Workday sandbox tenant.

### DR-18: Generic SCIM application live checks (2 days)

- **Files:** `internal/connectors/scim/probe.go` (discovery, paging, members completeness, rate limits).
- **Tests:** an in-process SCIM 2.0 test server with misbehaviour switches (truncated members, broken `totalResults`, 429s).

---

## 14. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Checklists become box-ticking: admins attest without checking | False confidence | Prefer live and data verification; attestations require notes and are attributable; data checks re-verify many attested facts (counts, fill rates). |
| Too many Required items slow down the first deployment | Customers abandon setup | Keep Required for items that cause wrong data or security exposure; everything else is Recommended with a skip path; the wizard orders steps so most items pass automatically. |
| Live checks are themselves heavy on large directories | Customer complaints, throttling | Fixed small samples, bounded runs, headroom targets, abort on 429. |
| Simulated results mistaken for real ones | Misleading demos | Simulated badge on every screen; simulated results can never gate a real connector type. |
| Cause analysers guess wrong | Misdirected fixes | Every cause is labelled "probable", shows the numbers it used, and links to the evidence. |
| Score gaming (skipping every Recommended item) | Inflated readiness | Skipped items earn no credit and stay listed; the band cannot be Healthy with more than 10% of Recommended weight skipped. |
| Agent becomes an attack surface inside customer networks | Lateral movement | Outbound-only, typed operations, local allowlist, per-tenant certificates, signed releases, minimal privileges (gMSA). |
| Pre-Phase-0 MVP tables need a migration later | Rework | Tables carry `tenant_id` from day one with a fixed default; DR-10 migrates. |

## 15. Open questions

1. Should `okta.auth.oauth` (OAuth service app instead of an API token) be Required for new tenants from 2027? It is a strong control, but some Okta plans and existing integrations still rely on API tokens. (iam-protocols-expert)
2. What is the right default for the "people with no account" expected population for a directory: all active employees, or only those whose HR record has a work location that uses AD? Universities and companies with frontline workers differ. (iam-governance-expert)
3. Should accepted critical findings expire automatically (for example after 30 days) and reopen? Proposed: yes, with a reminder 7 days before.
4. Do we need a customer-visible "readiness policy" per tenant (for example "no connection may be Active with a score under 70")? Proposed: an overlay field, Phase 3.
5. Should the Directory Agent also carry write-back for AD provisioning (groups design GR-11), or should provisioning use a separate agent role with its own allowlist? Proposed: the same binary with a separate, off-by-default capability and a separate local allowlist.
6. Do the AD defaults hold for very old domain functional levels (`MaxValRange` and `MaxPageSize` differ by version)? To verify in DR-12 against a real domain.

## 16. Knowledge-base notes

- D2 §8.1 M2 says LDAP and AD ingestion goes "through an on-prem agent" but does not say the agent must enforce a **local** target allowlist. This design makes that a requirement (K8); D2 should say so.
- D4 §8.1 M2 (correlation) should state explicitly that email or UPN matches only *propose* links, consistent with the guest design and Phase 0 S4. This design assumes it (K12).
- The capability map gains four rows in section C (deployment readiness), added in the same change.

## 17. References

- Microsoft: userAccountControl flags; `msDS-User-Account-Control-Computed`; `accountExpires`; `lastLogonTimestamp` and `msDS-LogonTimeSyncInterval`; LDAP policies (`MaxPageSize`, `MaxValRange`); range retrieval of attribute values; DirSync control and required rights; Deleted Objects and the show-deleted control; tombstone lifetime; AD Recycle Bin; global catalog partial attribute set; ADV190023 (LDAP channel binding and signing); well-known SIDs.
- RFC 2696 (Simple Paged Results), RFC 4511 (LDAP), RFC 4530 (entryUUID), RFC 4532 (Who Am I), RFC 4533 (Content Synchronization), RFC 7643 and 7644 (SCIM 2.0).
- OpenLDAP Administrator's Guide (limits, syncprov, accesslog, ppolicy, lastbind); 389 Directory Server documentation (size and look-through limits, retro changelog, account lock, Get Effective Rights).
- Microsoft Graph: users and groups delta queries, `signInActivity`, throttling, JSON batching, directory roles and PIM APIs, `deletedItems`.
- Okta Developer: OAuth 2.0 for Okta APIs (service apps, scopes, admin roles for apps), API token lifetime, List users and statuses, System Log API, rate limits and headers.
- Google Workspace Admin SDK: Directory API (users, groups, members, role assignments), domain-wide delegation, Reports API, quotas and error codes; Google Cloud workload identity federation.
- Workday Community: integration system users and security groups, Get_Workers, RaaS (behind customer login; summarised from practitioner knowledge, `[unverified]` in detail).
- Tessera: `docs/knowledge/02-federation-and-protocols.md` §8.1 M2–M3; `docs/knowledge/04-identity-governance-and-compliance.md` §6, §8.1 M1–M2, M7–M9, M22–M23; `docs/design/phase-0-platform-security.md` §4, §7.1, §13, §14; `docs/design/groups-grouper-parity.md` §9; `docs/design/guest-accounts-and-claim.md` §5.
