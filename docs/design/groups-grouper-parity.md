# Groups: native Grouper parity, and a Grouper connector for migration

| | |
|---|---|
| Status | Draft for review |
| Author | iam-architect, with iam-governance-expert, iam-protocols-expert and iam-authn-expert |
| Date | 2026-10-09 |
| Phase | 2 (governance), with Phase 0 prerequisites; some items in Phases 3 and 4 (see the parity matrix, §12) |
| Requirements covered | D4·M2, M6, M8, M9, M11, M13–M15, M22; D2·M2–M3, M15; D3·M5–M6; README rules 2, 4, 6, 8 |
| Reviewers to sign off | `iam-governance-expert` (§§6, 8, 9, 10: lifecycle, attestation, deprovisioning, provisioning), `iam-protocols-expert` (§§9, 11: SCIM, LDAP, Entra, Google, Grouper WS), `iam-authz-expert` (§§5, 7: privilege model, Cedar fragment), `iam-authn-expert` (§10.9: who can run loaders and change privileges, step-up) |

**The requirement.** Every capability Internet2 Grouper has must exist natively in Tessera, so that a customer never needs Grouper. A Grouper connector is still built, but only to import existing folders, groups and memberships and to coexist during a migration.

**Exit criteria for this design.** (1) Every row of the parity matrix (§12) has a native Tessera equivalent, a phase and a test. (2) A synthetic university tenant with 150,000 groups, 3 million direct memberships and 20 million effective memberships meets the performance targets in §6.7. (3) A real Grouper deployment can be imported, run in shadow mode until effective memberships match, and cut over one folder at a time with no access change for end users.

---

## Contents

1. [Summary of key decisions](#1-summary-of-key-decisions)
2. [Sources and what was checked](#2-sources-and-what-was-checked)
3. [Grouper capability inventory](#3-grouper-capability-inventory)
4. [Concepts and naming in Tessera](#4-concepts-and-naming-in-tessera)
5. [Data model (Go structs and SQL DDL)](#5-data-model-go-structs-and-sql-ddl)
6. [Membership evaluation engine](#6-membership-evaluation-engine)
7. [Privilege model](#7-privilege-model)
8. [Policy groups as access-as-code](#8-policy-groups-as-access-as-code)
9. [Loaders and provisioning](#9-loaders-and-provisioning)
10. [Everything else: events, PIT, rules, attestation, deprovisioning, reports, API, CLI, UI](#10-everything-else)
11. [The Grouper connector: import, coexistence and cut-over](#11-the-grouper-connector)
12. [Parity matrix](#12-parity-matrix)
13. [Implementation plan (ordered PRs)](#13-implementation-plan-ordered-prs)
14. [Risks](#14-risks)
15. [Open questions](#15-open-questions)
16. [Knowledge-base corrections](#16-knowledge-base-corrections)
17. [References](#17-references)

---

## 1. Summary of key decisions

| # | Decision | Why |
|---|---|---|
| K1 | **Native groups are a first-class object model in Tessera**: folders, groups, roles, direct and effective memberships, privileges, attributes, loaders and provisioners. Grouper is never a runtime dependency. | The founder's requirement. Universities should be able to switch Grouper off. |
| K2 | **One membership engine.** Direct memberships, nesting edges and composite definitions are the only stored inputs. Effective memberships are **materialized** and kept current by **per-identity delta propagation** over an acyclic dependency graph, with **support counts** for unions and nesting and point lookups for intersection and complement. A nightly full recompute in a shadow table proves the incremental result. | Large universities have 100k+ groups and tens of millions of effective memberships. Reads ("is X a member", "list members", "groups of X") must be index lookups, and a single change must cost work proportional to what it actually affects. |
| K3 | **Composites keep Grouper's semantics**: union, intersection and complement (left minus right), and a composite group has no direct members. Tessera allows n-ary union and intersection; complement stays binary. | Imports map one-to-one. N-ary operators remove Grouper's "intermediate group" clutter. |
| K4 | **Access policy groups are code.** The TIER pattern (`allow − deny` over reference groups) is written as a restricted, decidable fragment of **Cedar** in Git, compiled to the same engine. The Cedar PDP answers per-request "is member" queries with the same semantics, and a test cross-checks the two. | README rule 2 (policy is code in Git, every decision records its version). Grouper's JEXL "ABAC scripted groups" become reviewable, diffable, simulatable policy. |
| K5 | **Grouper's 22 privileges keep their names and meaning** (8 on groups, 5 on folders, 9 on attribute definitions; §7). **Inheritance is dynamic**: a privilege granted on a folder with scope `sub` applies to everything below it at check time instead of being copied at creation, as Grouper's inheritance rules do. | Same mental model for Grouper admins, no stale copies, and "why can Y edit this group" is explainable. |
| K6 | **No arbitrary code anywhere.** No JEXL, no GSH scripts or GSH templates, no in-process hooks. Rules use a closed vocabulary of triggers, conditions and actions. Extension happens out of process through webhooks and the connector SDK. | Grouper's own security advisories are mostly about code paths of this kind: GSH templates (GRP-6566), the rules UI (GRP-7359) and loader configuration (GRP-6311). |
| K7 | **Loaders are Tessera connectors** that implement a `GroupSource` interface (SQL, LDAP, CSV/SFTP, HRIS/SIS, IdP groups, any connector's groups). **Failsafes hold a run for approval** and show the downstream impact: who loses which policy group and which provisioned access. | Grouper's failsafes stop a run. Tessera also says what the run would have broken. |
| K8 | **Provisioning is closed-loop.** Full and incremental sync to LDAP/AD, Entra ID, Google Workspace, Okta, SCIM 2.0 and SQL targets. A provisioning operation counts as done only after a targeted re-read confirms it. | README rule 4 and D4·M8. |
| K9 | **Every change is an event** in a per-tenant outbox (CloudEvents 1.0). Point-in-time (PIT) history is derived from events. A daily Merkle digest of the group events is appended to the Phase 0 audit ledger, so PIT history is tamper-evident without writing millions of effective changes into the ledger. | D4·M22 and README rule 8. Grouper's PIT tables are not tamper-evident. |
| K10 | **Native groups project into the access graph** as group nodes with `system='tessera'`. Reviews, least privilege, SoD, simulation and "who can access" work on them unchanged. | One graph. A group is valuable for what it grants downstream, and Tessera can show that. |
| K11 | **The Grouper connector is read-only**, works through Grouper Web Services (WS mode) or a read-only database replica (SQL mode), and drives a per-folder **mirror → shadow-compare → cut-over** migration. A **Grouper-WS-compatible read API** lets applications that call Grouper keep working after cut-over by changing a base URL. | Coexistence without dual writes. Each folder has exactly one writer at a time. |

**PR sequence** (§13): GR-1 store → GR-2 engine → GR-3 events and PIT → GR-4 privileges → GR-5 API → GR-6 CLI → GR-7 attributes and object types → GR-8 UI → GR-9 policy groups as code → GR-10 loaders → GR-11 provisioning framework with LDAP/AD, SCIM and SQL → GR-12 cloud provisioners → GR-13 rules and membership constraints → GR-14 attestation, deprovisioning and reports → GR-15 Grouper import → GR-16 coexistence and cut-over → GR-17 scale gate → GR-18 event streaming → GR-19 permissions and limits → GR-20 long-tail provisioners.

---

## 2. Sources and what was checked

Grouper's current documentation and code were read from primary sources:

- **Code**: the `Internet2/grouper` repository, default branch `GROUPER_6_BRANCH` (last push 2026-10-05). Package lists under `grouper/src/grouper/edu/internet2/middleware/grouper/` and `.../grouper/app/` were used to make the inventory complete. Privilege names were taken from `privs/AccessPrivilege.java`, `NamingPrivilege.java` and `AttributeDefPrivilege.java`; composite types from `CompositeType.java`; rule actions from `rules/RuleThenEnum.java`; object types from `app/grouperTypes/GrouperObjectTypesSettings.java`.
- **Documentation**: the wiki mirror committed in the same repository (`grouper-misc/grouper-docs/wikiMirror/spaces/Grouper/`, 1,024 pages, copied from `grouper.atlassian.net`; the old `spaces.at.internet2.edu` pages return HTTP 403 to automated readers). That includes the **Grouper Deployment Guide** (the TIER/InCommon guide, now a wiki section), the administration and user guides, the provisioning framework pages and the release notes.
- **Current version**: Grouper **v7.6.0**, released **2026-09-28** (container `i2incommon/grouper:7.6.0`). v7 is the enhancement line. The v7 release notes say "v9 is the database rewrite". v6 removed SOAP web services, legacy (pre-framework) provisioners and the bundled Apache/Shibboleth SP. v7 added an MCP server, OAuth for MCP clients, in-place conversion of a group to a composite, provisioning sync-back, a group-level incremental loader and an all-report-configs screen. v7.6.0 also vetoes circular memberships at any depth.

Where a detail could not be confirmed from the code or wiki it is marked `[unverified]`.

---

## 3. Grouper capability inventory

**102 capabilities in 16 areas.** IDs (`G-01` …) are used throughout this document, in the parity matrix and in the PR plan. "Source" names the code package (`app/x` means `.../grouper/app/x`) or the wiki page.

### 3.1 Folders, naming and organization

| ID | Capability | Source |
|---|---|---|
| G-01 | Folders (stems): a hierarchy with `:`-separated names. Each object has an ID path (`extension`, `name`) and a separate display path (`displayExtension`, `displayName`), plus a description. | `Stem.java`, glossary |
| G-02 | Move, copy and rename of folders and groups. Old names stay resolvable as alternate names. | `StemMove`, `StemCopy`, `GroupMove`, `GroupCopy` |
| G-03 | Object name constraints: allowed characters, case-insensitive uniqueness, the same extension not reused within a folder tree. | "Configuring object name constraints", unique-name hooks |
| G-04 | Integer ID indexes on every object alongside UUIDs, for compact references and URLs. | "Integer IDs on Grouper objects" |
| G-05 | Object types from the Deployment Guide on folders and groups: `ref`, `basis`, `policy`, `bundle`, `manual`, `intermediate`, `etc`, `org`, `test`, `service`, `app`, `grouperSecurity`, each with a data owner and a member description. | `app/grouperTypes` |
| G-06 | Template wizard and custom templates: create a standard application folder (security, service, ref, policy groups) in one step. | "Template wizard" |
| G-07 | Favorites and recently used objects per user. | `userData` |

### 3.2 Groups, roles and subjects

| ID | Capability | Source |
|---|---|---|
| G-08 | Groups with name, display name, description, and enabled and disabled dates on the group itself. | `Group.java` |
| G-09 | Roles: a special kind of group used for RBAC, with a role hierarchy (role inheritance). | `permissions/role` |
| G-10 | Local entities: non-person subjects created in Grouper (applications, services) that can be members and hold privileges. | `entity`, "Grouper local entities" |
| G-11 | Subject sources: JDBC, JDBC2, LDAP, web service and data-field sources, with subject search and resolution, an identifier column and subject caching. | `subj`, "Subject sources" |
| G-12 | Subject API diagnostics in the UI. | "Subject API diagnostics" |
| G-13 | Member search and sort columns (`search_string0..4`, `sort_string0..4`) so lists can be searched and sorted without resolving every subject. | "Member search and sort columns" |
| G-14 | Unresolvable subjects: the Universal Subject Daemon Utility (USDU) finds subjects that no longer resolve and removes or reports their memberships, with thresholds. | `app/usdu` |
| G-15 | Member change subject: move a member's memberships and privileges to another subject (renames, duplicates). | WS `memberChangeSubject` |
| G-16 | Special subjects and system groups: `GrouperSystem` (root), `GrouperAll`/EveryEntity, the wheel (sysadmin) group, read-only and view-only admin groups, and UI and WS access groups (`etc:grouper_ui`, `etc:grouper_ws`). | Deployment Guide "etc folder", "Initializing administration of privileges" |
| G-17 | External subjects: invite people by email to join groups, self-registration through a separate public URL, auto-expiry of the added memberships. | "Grouper external subjects", `externalSubjects` |
| G-18 | Group summary screen (v6). | "Group summary screen" |

### 3.3 Memberships

| ID | Capability | Source |
|---|---|---|
| G-19 | Direct (immediate) memberships. | `Membership.java` |
| G-20 | Indirect memberships through groups as members (nesting), and effective memberships across every path, with "trace membership" in the UI. | `MembershipFinder`, UI |
| G-21 | Composite groups: union, intersection and complement of two factor groups. Composite groups have no direct members. | `CompositeType.java`, `Composite.java` |
| G-22 | Convert an existing group to a composite in place, without removing and re-adding memberships (v7). | v7 new features |
| G-23 | Enabled and disabled dates on memberships, applied by a daemon. | "Enabled and disabled dates", `GrouperDaemonEnabledDisabledCheck` |
| G-24 | Circular memberships vetoed at any depth (v7.6). | v7 release notes, GRP-7291 |
| G-25 | Custom membership lists (fields) beyond the default `members` list, attached through group types. | `Field`, `FieldType`, `GroupType` |
| G-26 | Opt-in and opt-out: subjects join or leave a group themselves when they hold OPTIN or OPTOUT. | `AccessPrivilege` |
| G-27 | Recent memberships (grace periods): a group that keeps people who were in another group within the last N days, with optional "include current members". | `app/serviceLifecycle`, "Recent memberships grace periods" |
| G-28 | Membership require: a subject must be in group A to stay in group B, enforced by a hook and a full-sync job. | `app/membershipRequire` |
| G-29 | Subjects in one group only: at most one membership among the groups of a folder (built-in hook). | "Built in Grouper hook for one membership in folder" |
| G-30 | Bulk add, import and export of members (CSV), including emailing member exports (v7.6). | UI, v7 release notes |
| G-31 | Membership queries with filters (immediate, effective, composite, enabled, disabled, by source, by field) and `hasMember`. | WS `getMemberships`, `hasMember` |
| G-32 | SQL membership cache tables for fast lookups by other systems, with history (`sqlCache`, v6). | `sqlCache`, "ABAC membership cache tables" |
| G-33 | ABAC scripted groups (JEXL) over groups and entity data fields, with incremental evaluation, script analysis and a "verify change" preview (v4–v6). | `abac`, "Grouper ABAC with scripted groups" |
| G-34 | Entity data fields and data providers: attributes loaded from SQL or LDAP for ABAC, with a data-field dictionary and dependency SQL caching (v5–v6). | `dataField`, `app/dataProvider` |
| G-35 | User lifecycle events: track changes in a person's relationship to the institution and act on them (v6). | `userLifecycle` |

### 3.4 Privileges

| ID | Capability | Source |
|---|---|---|
| G-36 | Group privileges: ADMIN, UPDATE, READ, VIEW, OPTIN, OPTOUT, GROUP_ATTR_READ, GROUP_ATTR_UPDATE. | `AccessPrivilege.java` |
| G-37 | Folder privileges: STEM_ADMIN, CREATE, STEM_ATTR_READ, STEM_ATTR_UPDATE, STEM_VIEW (VIEW added in v4 with folder-level security filtering). Legacy `STEM` is the old name of STEM_ADMIN. | `NamingPrivilege.java` |
| G-38 | Attribute definition privileges: ATTR_ADMIN, ATTR_UPDATE, ATTR_READ, ATTR_VIEW, ATTR_OPTIN, ATTR_OPTOUT, ATTR_DEF_ATTR_READ, ATTR_DEF_ATTR_UPDATE. | `AttributeDefPrivilege.java` |
| G-39 | Privilege inheritance from folders to groups, folders and attribute definitions below them, at one level or all levels (implemented as rules that assign privileges). | `PrivilegeGroupInheritanceSave`, `PrivilegeStemInheritanceSave`, `PrivilegeAttributeDefInheritanceSave` |
| G-40 | Default privileges on new objects (for example READ or VIEW for EveryEntity) and creator privileges. | `grouper.properties` |
| G-41 | Privileges held by groups (a group as the privilege holder), effective privileges through membership, and privilege lists as memberships. | `privs` |
| G-42 | Act-as: a trusted caller acts as another subject in WS calls, limited by an act-as group. | "Grouper web services act as" |

### 3.5 Attribute framework

| ID | Capability | Source |
|---|---|---|
| G-43 | Attribute definitions: type (attr, limit, perm, type, service), value type (string, integer, floating, timestamp, memberId, marker), single or multi-assign, single or multi-valued, and which objects they can be assigned to (folder, group, member, membership, immediate membership, attribute definition, another assignment). | `attr` |
| G-44 | Attribute names under definitions; name inheritance (implied names). | `attr`, WS `assignAttributeDefNameInheritance` |
| G-45 | Actions on attribute definitions, with action inheritance. | WS `assignAttributeDefActions` |
| G-46 | Attribute assignments and values, including assignments on assignments and enabled/disabled dates on assignments. | `attr/assign` |
| G-47 | Attributes editable in the group edit screen. | v4 new features |
| G-48 | Services: mark a folder as a service so users can find "which services do I have access to". | attribute def type `service` |

### 3.6 Permissions and limits

| ID | Capability | Source |
|---|---|---|
| G-49 | Permissions: role × resource (attribute name) × action, assigned to a role or to a subject in the context of a role. | `permissions` |
| G-50 | Resource and action inheritance for permissions. | "Role and permission management" |
| G-51 | Allow and disallow with heuristics for resolving conflicts between wider allows and narrower disallows. | `PermissionHeuristic*`, "Permissions allow and disallow" |
| G-52 | Permission limits: run-time constraints (amount, IP range, time window, expression) attached to a direct permission assignment. | `permissions/limits` |
| G-53 | Permission queries, including point in time. | WS `getPermissionAssignments`, `PITPermissionAllView` |

### 3.7 Loader

| ID | Capability | Source |
|---|---|---|
| G-54 | SQL simple loader: one group from one query. | `app/loader/db` |
| G-55 | SQL group-list loader: many groups from one query, with a groups query for names and descriptions; loader-created groups. | `app/loader/db` |
| G-56 | LDAP loaders: simple, group list, and attribute-values-to-groups. | `app/loader/ldap` |
| G-57 | Scheduling: cron or interval, priorities, clustered Quartz across nodes. | `GrouperLoader`, quartz |
| G-58 | Incremental loaders: a change table or messages trigger reloads for single subjects; group-level incremental (v7). | `GrouperLoaderIncrementalJob`, v7 new features |
| G-59 | Failsafes: refuse a run that removes too many members, makes a group too small or removes too many groups. | "Loader - fail safe" |
| G-60 | AND-groups, display-name sync, and handling of groups no longer returned (delete or leave). | loader configuration |
| G-61 | Load from provisioner targets (Duo, Zoom and others) into Grouper (v4). | v4 new features |
| G-62 | CSV, SFTP and Google Sheet sources, and GSH-script loaders. | "Grouper loader with CSV data sources", "GSH script daemon loader" |
| G-63 | Loader UI: configuration, diagnostics, logs, a wizard, and export/import of loader configuration (v6). | "Grouper Loader Administration", "Loader Import Export Config" |
| G-64 | Organization hierarchies loaded as folders and groups. | "Organization hierarchies via the grouper loader" |
| G-65 | Sync to Grouper from SQL: folders, groups, composites, memberships and privileges from tables, used to sync between group-management systems. | `app/syncToGrouper` |
| G-66 | Table sync and SQL import: SQL-to-SQL, LDAP-to-SQL and SFTP-to-SQL synchronization. | `app/tableSync`, `app/sqlSync`, `app/ldapToSql` |

### 3.8 Provisioning

| ID | Capability | Source |
|---|---|---|
| G-67 | Generic provisioning framework: full and incremental sync of groups, entities and memberships; translation and matching expressions; failsafes; CRUD operation order; per-object provisionable marking with folder inheritance; sync state tables; logs and error reporting; provisioning UI on groups and folders. | `app/provisioning`, "Grouper provisioning framework" |
| G-68 | Provisioning diagnostics. | v4 new features |
| G-69 | Provisioning sync-back: cache what was read from and written to the target (v7). | v7 new features |
| G-70 | LDAP and Active Directory provisioner, including entity attributes such as `isMemberOf`/`eduPersonEntitlement`. | `app/ldapProvisioning` |
| G-71 | Entra ID (Azure) provisioner. | `app/azure` |
| G-72 | Google Workspace provisioner. | `app/google` |
| G-73 | SCIM 2.0 provisioner (generic, AWS, GitHub, Atlassian Cloud). | `app/scim2Provisioning` |
| G-74 | SQL provisioner. | `app/sqlProvisioning` |
| G-75 | Okta provisioner. | `app/okta` |
| G-76 | Box, Duo (users, groups, admin roles), Zoom, Adobe, Dropbox, GitHub, Jamf, Datadog, C•CURE (physical access), Interfolio, TeamDynamix, Remedy, Freshservice, midPoint, TrueFoundry provisioners. | `app/*` |
| G-77 | Messaging provisioner and GSH-template (custom) provisioner. | `app/messagingProvisioning`, `app/gshTemplateProvisioner` |
| G-78 | External systems: shared connection configuration (LDAP, web service with bearer or OAuth credentials, SMTP), mock services for testing. | `app/externalSystem` |

### 3.9 Change log, messaging and ESB

| ID | Capability | Source |
|---|---|---|
| G-79 | Change log: typed change entries with sequence numbers, moved from a temp table into the change log by a daemon. | `changeLog` |
| G-80 | Change log consumers with cursors (including GSH consumers). | `changeLog/consumer` |
| G-81 | Messaging: built-in, ActiveMQ, RabbitMQ, AWS SQS/SNS; outbound and inbound messages (inbound can change memberships). | `messaging`, "Grouper messaging system" |
| G-82 | ESB connector: publish changes over HTTP or XMPP; incoming beans. | `esb`, "Grouper ESB connector" |

### 3.10 Rules and hooks

| ID | Capability | Source |
|---|---|---|
| G-83 | Rules engine: 15 check types (membership add/remove, flattened add/remove, group/folder create, …), if-conditions, and 16 actions (add disabled date, remove from owner group, add to owner group, veto, assign privileges, reassign privileges, send email, …). Rules editable in the UI (v6). | `rules`, `RuleThenEnum`, `RuleCheckType` |
| G-84 | Hooks: Java code before or after operations, plus built-in hooks. | `hooks`, "Grouper Hooks" |

### 3.11 Attestation, deprovisioning and lifecycle

| ID | Capability | Source |
|---|---|---|
| G-85 | Attestation on groups and folders: interval, owners emailed with reminders, "groups that need attestation" screens, attestation audit log. | `app/attestation` |
| G-86 | Automatic group disable, or automatic removal of memberships, when a group is not attested. | "Automatic group disable if not attested" |
| G-87 | Deprovisioning: affiliations, a list of subjects who lost an affiliation, per-object settings, owner emails, a report, and a hook that vetoes adding deprovisioned subjects. | `app/deprovisioning` |

### 3.12 Reports, visualization and workflow

| ID | Capability | Source |
|---|---|---|
| G-88 | Reports: SQL or GSH reports configured on folders and groups, scheduled, stored, emailed as CSV; all-report-configs screen (v7). | `app/reports` |
| G-89 | Visualization: graphs of folders, groups, memberships and provisioners; a user's group graph (v6). | `app/visualization` |
| G-90 | Daily email notifications and the notification daemon. | `NotificationDaemon` |
| G-91 | Forms, workflow and approvals: a request (for example to join a group) routes through approval states and provisions the membership on completion. | `app/workflow` |

### 3.13 History and audit

| ID | Capability | Source |
|---|---|---|
| G-92 | Audit log: actions by actor and on objects ("user audit log"). | `audit` |
| G-93 | Point-in-time (PIT) tables for folders, groups, members, memberships, group sets, attributes, roles and permissions; queries such as "members at time T" or "between T1 and T2"; recovery of deleted groups. | `pit`, "Point in Time Auditing" |
| G-94 | Data retention: delete-old-records daemon and data cleanup. | `GrouperDaemonDeleteOldRecords` |

### 3.14 Interfaces

| ID | Capability | Source |
|---|---|---|
| G-95 | Web UI: folder browser, search, group and folder screens, membership and privilege editing, trace membership, attribute editor, admin screens, daemon screens, configuration editor, custom UI pages, banners, WCAG work in v7.6. | `grouper-ui` |
| G-96 | REST web services (JSON/XML; lite and batch variants; versioned; OpenAPI/Swagger). SOAP was removed in v6. | `grouper-ws`, "Grouper Web Services" |
| G-97 | WS authentication options: built-in, LDAP, Kerberos, Tomcat, OIDC, trusted JWT, self-service JWT. | "Grouper Web Services Authentication" |
| G-98 | SCIM 2.0 server: Grouper exposes groups and memberships over SCIM. | `grouper-ws` SCIM, "Grouper SCIM web service" |
| G-99 | GSH (Grouper Shell): scripting, export of objects to GSH, and GSH templates with input forms runnable from the UI. | `app/gsh`, "GrouperShell (gsh)" |
| G-100 | Grouper client (command-line and Java client library). | `grouperClient` |
| G-101 | Daemon and scheduler: loader daemon, "other jobs", change log consumers, health-check endpoint, job history chart, configuration stored in the database. | `app/daemon`, "Grouper Daemon", health check |
| G-102 | MCP server, with Grouper as the OAuth authorization server for MCP clients (v7). | v7 new features |

### 3.15 Deployment Guide practices (summarized; each maps to G-05, G-06 and §8)

The Grouper Deployment Guide's "Folder and Group Design" section defines the practices Tessera has to support and should encourage:

- **Group types.** *Basis groups* are raw cohorts from source systems, used only by the IAM team. *Reference groups* are institutionally meaningful cohorts ("labels or tags"), the best available truth for access control. *Access policy groups* are composites of an **allow** (include) group minus a **deny** (exclude) group, whose membership should be indirect (through reference groups) so they track attribute changes. *Account policy groups* say an account should exist in a target. *Manual* groups are maintained by people. *Intermediate* groups exist only to make a policy work.
- **Standard folders**: `etc:` (system configuration, loader jobs, the admin groups `etc:grouper_ui`, `etc:grouper_ws`, `etc:grouper_admin`), `basis:` (for example `basis:hris:*`, `basis:sis:*`), `ref:` (`ref:role:`, `ref:employee:`, `ref:student:`, `ref:alum:`, `ref:course:`, `ref:dept:`), `app:` (per application: `app:foo:security:fooAdmin`, `app:foo:service:ref:`, `app:foo:service:policy:foo_user` = `foo_user_allow − foo_user_deny`, `foo_user_allow_manual` for exceptions, `foo_user_deny` including `ref:iam:global_deny`), `org:` (delegated namespaces, for example `org:compsci:`) and `test:`. Code also recognizes `bundle` (sets of reference groups) and `service`.
- **Access control models** (the guide's section 6): policy groups with static application permissions, with dynamic application permissions, for front-door access, Grouper for access reporting, Grouper-managed permissions, and `eduPersonAffiliation` for authorization.
- **Operational guidance**: delegate through folders and inherited privileges; keep manual reference groups small and prefer loaders; use the "this group's membership in other groups" view to see where a reference group is used.

---

## 4. Concepts and naming in Tessera

| Grouper term | Tessera term | Notes |
|---|---|---|
| Stem / folder | **Folder** | Same `:` path syntax, so imported names are unchanged. |
| Group | **Group** (`kind=group`) | |
| Role | **Group** with `kind=role` | Role hierarchy is ordinary nesting plus the permission framework (§10.10). |
| Local entity | **Identity** with `type=service`, `subtype=entity` | Entities become governed non-human identities and therefore need a human owner (README rule 6). |
| Subject | **Identity** (person, service, agent, guest) | Tessera's identity warehouse is the subject registry. Subject sources become connectors plus correlation (§10.6). |
| Member | **Member**: an identity or a group | |
| Immediate membership | **Direct membership** | |
| Effective membership | **Effective membership** | Materialized (§6). |
| Composite | **Composite group** | n-ary union and intersection, binary complement (K3). |
| Access policy group | **Policy group** | Defined in Cedar, usually in Git (§8). |
| Privilege | **Privilege** | Same 22 names (§7). |
| Attribute def / name / assign | **Attribute definition / name / assignment** | §10.9. |
| Loader job | **Loader** (a connector job) | §9.1. |
| Provisioner | **Provisioner** (a connector target) | §9.2. |
| Change log | **Group events** | §10.1. |
| GSH | **CLI and declarative plans** | §10.12. |

**Native groups and connected-system groups are different things.** The MVP's existing `groups` table holds groups *read from* connected systems (Okta groups, AWS roles, Snowflake roles). Native groups are *owned by* Tessera and live in new `grp_*` tables. Each native group is also projected into the access graph as a group node with `system='tessera'` (K10), so a native policy group that is provisioned to Okta appears as `tessera:app:foo:foo_user → okta:foo_user → …`, and a path explains both halves.

---

## 5. Data model (Go structs and SQL DDL)

### 5.1 Conventions

The Phase 0 conventions apply (Phase 0 design §7.1 and §14, v2 on branch `go-replan`): every table has `tenant_id`; all SQL lives in `internal/store`; tenant tables are reached only through `*store.TenantTx`, which binds `@tenant` itself; new tables use UUID text primary keys; every unique constraint starts with `tenant_id`; timestamps are RFC 3339 UTC text in SQLite and `timestamptz` in Postgres; JSON columns are typed structs. Existing integer `identities.id` values are referenced as `INTEGER`.

New files:

```
internal/store/schema/0101_groups.sql        folders, groups, composites, memberships, closure, effective
internal/store/schema/0102_group_privs.sql   privileges
internal/store/schema/0103_group_events.sql  events, cursors, PIT
internal/store/schema/0104_group_attrs.sql   attribute framework
internal/store/schema/0105_group_loaders.sql loaders, runs, unresolved subjects
internal/store/schema/0106_group_prov.sql    provisioners, provisionable marks, sync state, operations
internal/store/schema/0107_group_gov.sql     rules, attestation settings, deprovisioning, reports
internal/store/model_groups.go, repo_groups*.go
internal/groups/...                          domain packages (§5.4)
```

### 5.2 Go structs (core)

```go
// internal/store/model_groups.go
package store

type FolderID string // uuid
type GroupID string  // uuid
type ListID string   // uuid; the built-in "members" list has a fixed per-tenant id

type Folder struct {
	ID               FolderID
	TenantID         tenancy.ID
	ParentID         *FolderID // nil only for the tenant root
	Extension        string    // "foo"
	DisplayExtension string    // "Foo application"
	Name             string    // "app:foo", unique per tenant; "" for the root
	DisplayName      string
	Description      string
	IDIndex          int64
	ObjectTypes      []ObjectType // §10.9: ref, basis, policy, bundle, manual, intermediate, etc, org, test, service, app, security
	DataOwner        *string
	ManagedBy        ManagedBy // ui | policy_repo | loader | grouper_mirror | connector
	ExternalRef      *string   // e.g. Grouper stem uuid when imported
	CreatedAt        time.Time
	CreatedBy        *string // platform user id
	Version          int64   // optimistic concurrency
}

type GroupKind string      // group | role
type Definition string     // basic | composite | policy
type CompositeOp string    // union | intersection | complement

type Group struct {
	ID               GroupID
	TenantID         tenancy.ID
	FolderID         FolderID
	Extension        string
	DisplayExtension string
	Name             string // "app:foo:service:policy:foo_user"
	DisplayName      string
	Description      string
	IDIndex          int64
	Kind             GroupKind
	Definition       Definition
	CompositeOp      *CompositeOp // non-nil iff Definition == composite
	PolicyRef        *PolicyRef   // non-nil iff Definition == policy: repo path, git commit, compiled hash
	ManagedBy        ManagedBy
	LoaderID         *string
	ObjectTypes      []ObjectType
	DataOwner        *string
	MemberDescription *string
	EnabledFrom      *time.Time
	DisabledAt       *time.Time
	Status           string // active | disabled | deleted
	Requestable      bool   // appears in the access-request catalog
	EffectiveCount   int64  // cached
	EffectiveVersion int64  // bumped by the engine on every applied batch
	RecomputeState   string // clean | pending | failed
	ExternalRef      *string
	CreatedAt        time.Time
	CreatedBy        *string
	Version          int64
}

type MemberType string // identity | group

type DirectMembership struct {
	ID              string
	TenantID        tenancy.ID
	GroupID         GroupID
	ListID          ListID
	MemberType      MemberType
	MemberIdentity  *int64   // identities.id
	MemberGroup     *GroupID
	EnabledFrom     *time.Time
	DisabledAt      *time.Time
	Source          string   // manual | loader | rule | request | guest_sponsorship | grouper_import | policy_exception
	SourceRef       *string  // loader id, rule id, access request id, sponsorship id
	Reason          *string
	CreatedBy       *string
	CreatedAt       time.Time
}

type EffectiveMembership struct {
	GroupID  GroupID
	ListID   ListID
	Identity int64
	Support  int32 // basic groups: number of active direct rows + child groups containing the identity; composites: 1
	Since    time.Time
}
```

### 5.3 SQL DDL (SQLite dialect; Postgres generated as in Phase 0 §7.5)

```sql
-- 0101_groups.sql ------------------------------------------------------------
CREATE TABLE grp_folders (
  id                TEXT PRIMARY KEY,
  tenant_id         TEXT NOT NULL REFERENCES tenants(id),
  parent_id         TEXT REFERENCES grp_folders(id),
  extension         TEXT NOT NULL CHECK (extension GLOB '[A-Za-z0-9_.-]*' AND length(extension) BETWEEN 0 AND 255),
  display_extension TEXT NOT NULL,
  name              TEXT NOT NULL,                     -- full path, ':' separated
  display_name      TEXT NOT NULL,
  description       TEXT NOT NULL DEFAULT '',
  id_index          INTEGER NOT NULL,
  object_types      TEXT NOT NULL DEFAULT '[]',
  data_owner        TEXT,
  managed_by        TEXT NOT NULL DEFAULT 'ui'
                    CHECK (managed_by IN ('ui','policy_repo','loader','grouper_mirror','connector')),
  external_ref      TEXT,
  created_at        TEXT NOT NULL,
  created_by        TEXT,
  version           INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id_index)
);
CREATE UNIQUE INDEX grp_folders_ci ON grp_folders(tenant_id, lower(name));   -- case-insensitive uniqueness (G-03)

CREATE TABLE grp_name_aliases (                         -- old names after move/rename (G-02)
  tenant_id   TEXT NOT NULL REFERENCES tenants(id),
  object_type TEXT NOT NULL CHECK (object_type IN ('folder','group')),
  object_id   TEXT NOT NULL,
  old_name    TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (tenant_id, object_type, old_name)
);

CREATE TABLE grp_groups (
  id                 TEXT PRIMARY KEY,
  tenant_id          TEXT NOT NULL REFERENCES tenants(id),
  folder_id          TEXT NOT NULL REFERENCES grp_folders(id),
  extension          TEXT NOT NULL CHECK (extension GLOB '[A-Za-z0-9_.-]*' AND length(extension) BETWEEN 1 AND 255),
  display_extension  TEXT NOT NULL,
  name               TEXT NOT NULL,
  display_name       TEXT NOT NULL,
  description        TEXT NOT NULL DEFAULT '',
  id_index           INTEGER NOT NULL,
  kind               TEXT NOT NULL DEFAULT 'group' CHECK (kind IN ('group','role')),
  definition         TEXT NOT NULL DEFAULT 'basic' CHECK (definition IN ('basic','composite','policy')),
  composite_op       TEXT CHECK (composite_op IN ('union','intersection','complement')),
  policy_ref         TEXT,                               -- JSON {path, commit, compiled_sha256}
  managed_by         TEXT NOT NULL DEFAULT 'ui'
                     CHECK (managed_by IN ('ui','policy_repo','loader','grouper_mirror','connector')),
  loader_id          TEXT,
  object_types       TEXT NOT NULL DEFAULT '[]',
  data_owner         TEXT,
  member_description TEXT,
  enabled_from       TEXT,
  disabled_at        TEXT,
  status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','deleted')),
  requestable        INTEGER NOT NULL DEFAULT 0,
  effective_count    INTEGER NOT NULL DEFAULT 0,
  effective_version  INTEGER NOT NULL DEFAULT 0,
  recompute_state    TEXT NOT NULL DEFAULT 'clean' CHECK (recompute_state IN ('clean','pending','failed')),
  external_ref       TEXT,
  created_at         TEXT NOT NULL,
  created_by         TEXT,
  version            INTEGER NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id_index),
  CHECK ((definition = 'composite') = (composite_op IS NOT NULL)),
  CHECK ((definition = 'policy') = (policy_ref IS NOT NULL))
);
CREATE UNIQUE INDEX grp_groups_ci ON grp_groups(tenant_id, lower(name));
CREATE INDEX grp_groups_folder ON grp_groups(tenant_id, folder_id);

CREATE TABLE grp_composite_factors (
  tenant_id       TEXT NOT NULL REFERENCES tenants(id),
  group_id        TEXT NOT NULL REFERENCES grp_groups(id),
  position        INTEGER NOT NULL,                      -- complement: 0 = left, 1 = right
  factor_group_id TEXT NOT NULL REFERENCES grp_groups(id),
  PRIMARY KEY (tenant_id, group_id, position)
);

CREATE TABLE grp_lists (                                 -- custom lists (G-25); 'members' is built in
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants(id),
  name        TEXT NOT NULL,
  read_priv   TEXT NOT NULL DEFAULT 'read',
  write_priv  TEXT NOT NULL DEFAULT 'update',
  UNIQUE (tenant_id, name)
);

CREATE TABLE grp_direct_memberships (
  id                 TEXT PRIMARY KEY,
  tenant_id          TEXT NOT NULL REFERENCES tenants(id),
  group_id           TEXT NOT NULL REFERENCES grp_groups(id),
  list_id            TEXT NOT NULL REFERENCES grp_lists(id),
  member_type        TEXT NOT NULL CHECK (member_type IN ('identity','group')),
  member_identity_id INTEGER REFERENCES identities(id),
  member_group_id    TEXT REFERENCES grp_groups(id),
  enabled_from       TEXT,
  disabled_at        TEXT,
  source             TEXT NOT NULL,
  source_ref         TEXT,
  reason             TEXT,
  created_by         TEXT,
  created_at         TEXT NOT NULL,
  CHECK ((member_type = 'identity') = (member_identity_id IS NOT NULL)),
  CHECK ((member_type = 'group')    = (member_group_id IS NOT NULL)),
  CHECK (disabled_at IS NULL OR enabled_from IS NULL OR disabled_at > enabled_from)
);
CREATE UNIQUE INDEX grp_dm_ident ON grp_direct_memberships(tenant_id, group_id, list_id, member_identity_id)
  WHERE member_type = 'identity';
CREATE UNIQUE INDEX grp_dm_group ON grp_direct_memberships(tenant_id, group_id, list_id, member_group_id)
  WHERE member_type = 'group';
CREATE INDEX grp_dm_by_identity ON grp_direct_memberships(tenant_id, member_identity_id);
CREATE INDEX grp_dm_enable ON grp_direct_memberships(tenant_id, enabled_from) WHERE enabled_from IS NOT NULL;
CREATE INDEX grp_dm_disable ON grp_direct_memberships(tenant_id, disabled_at) WHERE disabled_at IS NOT NULL;

-- dependency DAG: child feeds parent, by nesting or as a composite factor
CREATE TABLE grp_deps (
  tenant_id       TEXT NOT NULL REFERENCES tenants(id),
  parent_group_id TEXT NOT NULL REFERENCES grp_groups(id),
  child_group_id  TEXT NOT NULL REFERENCES grp_groups(id),
  kind            TEXT NOT NULL CHECK (kind IN ('nest','factor')),
  list_id         TEXT NOT NULL REFERENCES grp_lists(id),
  PRIMARY KEY (tenant_id, parent_group_id, child_group_id, kind, list_id)
);
CREATE INDEX grp_deps_child ON grp_deps(tenant_id, child_group_id);

CREATE TABLE grp_closure (                               -- transitive closure of grp_deps (cycle veto, ancestors)
  tenant_id     TEXT NOT NULL REFERENCES tenants(id),
  ancestor_id   TEXT NOT NULL,
  descendant_id TEXT NOT NULL,
  paths         INTEGER NOT NULL,                        -- number of distinct paths, for maintenance on delete
  min_depth     INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, ancestor_id, descendant_id)
) WITHOUT ROWID;
CREATE INDEX grp_closure_desc ON grp_closure(tenant_id, descendant_id);

CREATE TABLE grp_levels (                                -- longest path from a leaf; engine processes ascending
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  group_id  TEXT NOT NULL REFERENCES grp_groups(id),
  level     INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, group_id)
);

CREATE TABLE grp_effective (
  tenant_id   TEXT NOT NULL REFERENCES tenants(id),
  group_id    TEXT NOT NULL,
  list_id     TEXT NOT NULL,
  identity_id INTEGER NOT NULL,
  support     INTEGER NOT NULL CHECK (support > 0),
  since       TEXT NOT NULL,
  PRIMARY KEY (tenant_id, group_id, list_id, identity_id)
) WITHOUT ROWID;
CREATE INDEX grp_eff_identity ON grp_effective(tenant_id, identity_id, list_id, group_id);

CREATE TABLE grp_engine_queue (                          -- work that did not fit the synchronous budget (§6.5)
  tenant_id  TEXT NOT NULL REFERENCES tenants(id),
  seq        INTEGER NOT NULL,
  kind       TEXT NOT NULL,                              -- seed | recompute_group | rebuild_tenant
  payload    TEXT NOT NULL,                              -- JSON
  enqueued_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);
```

```sql
-- 0102_group_privs.sql -------------------------------------------------------
CREATE TABLE grp_privileges (
  id                 TEXT PRIMARY KEY,
  tenant_id          TEXT NOT NULL REFERENCES tenants(id),
  object_type        TEXT NOT NULL CHECK (object_type IN ('folder','group','attr_def')),
  object_id          TEXT NOT NULL,
  privilege          TEXT NOT NULL CHECK (privilege IN (
     'admin','update','read','view','optin','optout','group_attr_read','group_attr_update',
     'stem_admin','create','stem_attr_read','stem_attr_update','stem_view',
     'attr_admin','attr_update','attr_read','attr_view','attr_optin','attr_optout',
     'attr_def_attr_read','attr_def_attr_update')),
  holder_type        TEXT NOT NULL CHECK (holder_type IN ('identity','group','everyone')),
  holder_identity_id INTEGER REFERENCES identities(id),
  holder_group_id    TEXT REFERENCES grp_groups(id),
  applies_to         TEXT NOT NULL DEFAULT 'self'
                     CHECK (applies_to IN ('self','groups','folders','attr_defs')),
  scope              TEXT NOT NULL DEFAULT 'self' CHECK (scope IN ('self','one','sub')),
  source             TEXT NOT NULL,                      -- ui | api | creator_default | grouper_import | template
  created_by         TEXT,
  created_at         TEXT NOT NULL,
  CHECK ((applies_to = 'self') = (scope = 'self')),
  CHECK (applies_to = 'self' OR object_type = 'folder'),
  CHECK ((holder_type = 'identity') = (holder_identity_id IS NOT NULL)),
  CHECK ((holder_type = 'group') = (holder_group_id IS NOT NULL))
);
CREATE INDEX grp_priv_object ON grp_privileges(tenant_id, object_type, object_id);
CREATE INDEX grp_priv_holder_g ON grp_privileges(tenant_id, holder_group_id);
CREATE INDEX grp_priv_holder_i ON grp_privileges(tenant_id, holder_identity_id);
```

```sql
-- 0103_group_events.sql ------------------------------------------------------
CREATE TABLE grp_events (
  tenant_id       TEXT NOT NULL REFERENCES tenants(id),
  seq             INTEGER NOT NULL,                      -- per-tenant, gap-free, assigned under the engine lock
  type            TEXT NOT NULL,                         -- §10.1 catalogue
  object_type     TEXT NOT NULL,
  object_id       TEXT NOT NULL,
  identity_id     INTEGER,
  member_group_id TEXT,
  list_id         TEXT,
  data            TEXT NOT NULL DEFAULT '{}',            -- JSON (old/new values)
  cause_type      TEXT NOT NULL,                         -- api | loader | rule | engine | timewheel | policy_repo | import
  cause_ref       TEXT,
  audit_seq       INTEGER,                               -- audit_events.seq of the ledger event that caused it
  occurred_at     TEXT NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);
CREATE INDEX grp_events_object ON grp_events(tenant_id, object_type, object_id, seq);

CREATE TABLE grp_event_cursors (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  consumer  TEXT NOT NULL,                               -- pit | graph | provisioner:<id> | webhook:<id> | ...
  last_seq  INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, consumer)
);

-- PIT (G-93). Intervals are half-open [start_at, end_at).
CREATE TABLE grp_pit_objects (                           -- names, folders, definitions over time
  tenant_id TEXT NOT NULL, object_type TEXT NOT NULL, object_id TEXT NOT NULL,
  snapshot  TEXT NOT NULL,                               -- JSON: name, display_name, folder, definition, op, factors, status
  start_at  TEXT NOT NULL, end_at TEXT, start_seq INTEGER NOT NULL, end_seq INTEGER,
  PRIMARY KEY (tenant_id, object_type, object_id, start_seq)
);
CREATE TABLE grp_pit_direct (
  tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, list_id TEXT NOT NULL,
  member_type TEXT NOT NULL, member_identity_id INTEGER, member_group_id TEXT,
  source TEXT NOT NULL, start_at TEXT NOT NULL, end_at TEXT, start_seq INTEGER NOT NULL, end_seq INTEGER
);
CREATE INDEX grp_pit_direct_g ON grp_pit_direct(tenant_id, group_id, start_at);
CREATE TABLE grp_pit_effective (
  tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, list_id TEXT NOT NULL, identity_id INTEGER NOT NULL,
  start_at TEXT NOT NULL, end_at TEXT, start_seq INTEGER NOT NULL, end_seq INTEGER,
  PRIMARY KEY (tenant_id, group_id, list_id, identity_id, start_seq)
) WITHOUT ROWID;
CREATE INDEX grp_pit_eff_identity ON grp_pit_effective(tenant_id, identity_id, start_at);
CREATE TABLE grp_pit_privileges (
  tenant_id TEXT NOT NULL, privilege_id TEXT NOT NULL, snapshot TEXT NOT NULL,
  start_at TEXT NOT NULL, end_at TEXT, start_seq INTEGER NOT NULL, end_seq INTEGER,
  PRIMARY KEY (tenant_id, privilege_id, start_seq)
);
CREATE TABLE grp_pit_digests (                           -- daily Merkle root anchored in the audit ledger (K9)
  tenant_id TEXT NOT NULL, day TEXT NOT NULL, first_seq INTEGER NOT NULL, last_seq INTEGER NOT NULL,
  merkle_root TEXT NOT NULL, audit_seq INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, day)
);
```

The DDL for attributes (0104), loaders (0105), provisioning (0106) and governance (0107) is given in the sections that use it (§10.9, §9.1, §9.2, §10.3–§10.5).

### 5.4 Packages

```
internal/groups/
  naming/        path parsing, validation, case-insensitive uniqueness, aliases (G-01..G-04)
  model/         folder and group services: create, rename, move, copy, delete, convert-to-composite
  engine/        closure.go, levels.go, propagate.go, composite.go, timewheel.go, verify.go, budget.go (§6)
  privs/         model.go, implies.go, inherit.go, check.go, explain.go (§7)
  attrs/         attribute framework and object types (§10.9)
  policygroups/  Cedar fragment parser, compiler to engine definitions, repo sync, PR diff (§8)
  loaders/       GroupSource jobs, failsafes, schedules, recent memberships (§9.1)
  provisioning/  framework, translation, sync state, verification; targets in subpackages (§9.2)
  events/        outbox, consumers, CloudEvents encoding, webhooks (§10.1)
  pit/           PIT writer, as-of queries, digests (§10.2)
  rules/         closed-vocabulary rules, membership constraints (§10.3)
  attest/        attestation settings, campaign generation via internal/reviews (§10.4)
  deprov/        affiliation-loss handling (§10.5)
  reports/       saved reports and schedules (§10.7)
  api/           /api/groups/* handlers and the Grouper-WS-compatible read API (§10.11, §11.6)
  grouperconn/   the Grouper connector (§11)
```

Only `internal/store` issues SQL. The engine receives a `*store.TenantTx` and calls repository methods that run set-based statements.

---

## 6. Membership evaluation engine

### 6.1 Semantics

For identity `i`, list `L` and time `now`:

- A direct membership row is **active** if `status` of its group is `active`, `enabled_from ≤ now` (or null) and `now < disabled_at` (or null).
- A **disabled or deleted group** has no effective members and contributes the empty set to its parents.
- **Basic group** `g`: `i ∈ E(g)` if there is an active direct row `(g, i)` or an active direct row `(g, h)` for a group `h` with `i ∈ E(h)`.
- **Composite** `g` with factors `f1..fn`: union = any `i ∈ E(fk)`; intersection = all; complement (n = 2) = `i ∈ E(f1) ∧ i ∉ E(f2)`. A composite has no direct members; the API refuses them.
- **Policy group**: compiled to a composite tree (§8.3); evaluated the same way.
- The dependency graph (nesting and factor edges) must be **acyclic**. An edge `child → parent` is refused if `parent` is already a descendant of `child` in `grp_closure` (G-24). Error: `409 {"error":"cycle","path":[…]}`.

Only identities are stored in `grp_effective`. "Which groups contain group h" comes from `grp_closure`.

### 6.2 Inputs and invariants

| Stored input | Changed by |
|---|---|
| `grp_direct_memberships` | API, UI, loaders, rules, access requests, guest sponsorship, import |
| `grp_composite_factors`, group `definition`/`composite_op` | API, UI, policy repo sync, import |
| group `status`, `enabled_from`, `disabled_at` | API, UI, attestation auto-disable, time wheel |

**Invariant I1.** For every `(g, L, i)`: the row exists in `grp_effective` iff the semantics in §6.1 say `i ∈ E(g)`. For basic groups, `support` equals the number of active direct identity rows `(g, i)` (0 or 1) plus the number of active direct group rows `(g, h)` with `i ∈ E(h)`.

**Invariant I2.** `grp_closure` is the transitive closure of `grp_deps`, and `grp_levels.level(g) = 1 + max(level(child))` (leaves are 0).

### 6.3 Incremental algorithm: per-identity delta propagation

A change produces **seeds**. A seed is either a support delta `(g, L, i, ±1)` on a basic group, or a recompute request `(g, L, i)` on a composite. The engine processes seeds in ascending `level` order, so by the time a composite is evaluated its factors are final.

```go
// internal/groups/engine/propagate.go
type seed struct {
	group    store.GroupID
	list     store.ListID
	identity int64
	delta    int8 // +1/-1 for basic groups; 0 means "recompute" for composites
}

// Apply processes seeds to a fixed point and returns the effective changes (for events and PIT).
func (e *Engine) Apply(ctx context.Context, tx *store.TenantTx, seeds []seed) ([]Change, error) {
	q := newLevelQueue(tx)          // buckets by grp_levels.level; dedupes (group,list,identity)
	q.push(seeds...)
	var out []Change
	for q.next() {
		s := q.pop()
		g := q.groupMeta(s.group)   // definition, op, factors, status (cached per batch)
		var was, is bool
		switch g.Definition {
		case store.Basic:
			old, now, err := tx.AdjustSupport(ctx, s.group, s.list, s.identity, int32(s.delta)) // upsert; deletes row at 0
			if err != nil {
				return nil, err
			}
			was, is = old > 0, now > 0
		default: // composite or compiled policy node
			was = tx.IsEffective(ctx, s.group, s.list, s.identity)
			is = g.Active && evalComposite(ctx, tx, g, s.list, s.identity) // point lookups on factors
			if was != is {
				if err := tx.SetEffective(ctx, s.group, s.list, s.identity, is); err != nil {
					return nil, err
				}
			}
		}
		if was == is {
			continue
		}
		out = append(out, Change{s.group, s.list, s.identity, is})
		for _, p := range q.parents(s.group) { // grp_deps where child = s.group
			if p.Kind == store.DepNest {
				q.push(seed{p.Parent, p.List, s.identity, sign(is)})
			} else {
				q.push(seed{p.Parent, p.List, s.identity, 0})
			}
		}
	}
	return out, nil
}
```

**Cost.** One direct change for one identity touches at most `|ancestors(g)|` groups, and stops early wherever the identity's membership does not change (for example, it was already a member through another path). With support counts, a union or nesting parent never has to scan its other children.

**Set-based batches.** Changes that affect many identities at once (adding group `h` with 50,000 members as a member of `g`, a loader run, a composite redefinition) use the same algorithm on **sets** of identities per group instead of single identities:

- Nesting: `INSERT INTO grp_effective … SELECT identity_id FROM grp_effective WHERE group_id = h … ON CONFLICT DO UPDATE SET support = support + 1 RETURNING identity_id, support` returns exactly the identities whose support went from 0 to 1, which become the seed set for `g`'s parents. Removal is symmetric, with a final `DELETE … WHERE support = 0 RETURNING`.
- Composites: for a candidate set `D`, one set query computes the new truth for all of `D` (`D ∩ E(f1) ∩ E(f2)`, `D ∩ E(f1) − E(f2)`, …) and diffs against current rows.
- Redefinition (factors or operator changed): the candidate set is `E_old(g) ∪ E(new factors)`; recompute that set.

SQLite 3.35+ (the `modernc.org/sqlite` driver bundles a current SQLite) and Postgres both support `RETURNING`.

**Structural changes.** Adding a nesting or factor edge updates `grp_closure` (for each ancestor `a` of the parent, including itself, and each descendant `d` of the child, including itself, add `paths(a→parent) × paths(child→d)`), refuses cycles, and recomputes `grp_levels` for the parent's ancestors. Removing an edge subtracts paths and deletes rows that reach zero.

### 6.4 Time: enabled and disabled dates

`engine/timewheel.go` runs per tenant every 30 seconds and also schedules a precise wake-up for the next boundary (`MIN(enabled_from) > now`, `MIN(disabled_at) > now` over the partial indexes). Each boundary crossed becomes a seed with `cause_type='timewheel'`. Group-level `enabled_from`/`disabled_at` become a status change and a recompute of the group's members. The maximum lag between a disabled date and the effective removal is 60 seconds (target p99), which beats Grouper's daemon cadence and is tested. Authorization checks never count a membership whose `disabled_at` has passed even if the time wheel is behind: `IsMember` checks the direct row's dates for basic groups as a guard (this closes the class of bug in Grouper GRP-7325, "authorization checks counted disabled memberships").

### 6.5 Transactions, concurrency and the synchronous budget

- A direct change commits in the API transaction **together with** its audit ledger event (Phase 0 rule) and, when the estimated work is small, its full engine propagation. The estimate is `|ancestors(g)| × |identities affected|`. The default budget is 5,000 effective-row operations (`TESSERA_GROUPS_SYNC_BUDGET`). Under budget, the response already reflects effective memberships.
- Over budget, the transaction commits the direct change, writes a `grp_engine_queue` row, sets `recompute_state='pending'` on the affected root group and returns `202` with an operation id. A per-tenant worker drains the queue in `seq` order in chunks of 2,000 identities per transaction. The UI shows "Recalculating: 41,200 of 120,000" and the effective count updates when done.
- **One engine writer per tenant.** SQLite serializes writers already. In Postgres, every engine transaction first takes `pg_advisory_xact_lock(hashtext('grp-engine:' || tenant_id))`. API transactions that only touch direct rows also take it, briefly, so `grp_events.seq` stays gap-free and ordered.
- Readers see committed state. During a pending recompute, reads of the affected groups are marked `stale=true` in API responses (`effective_version` lets clients detect change).

### 6.6 Verification: full recompute and the oracle

- `engine/verify.go` recomputes every group's effective members from scratch into a shadow table, in level order, using set operations, and diffs with `grp_effective`. It runs nightly per tenant and on demand (`tessera groups verify`). A difference is a bug. It is repaired (events emitted with `cause_type='engine_repair'`), logged at `ERROR`, counted in `groups_engine_repairs_total` and alerted on. This is Tessera's equivalent of Grouper's "bad membership finder", but it runs continuously.
- Tests compare the incremental engine with a naive in-memory oracle over random DAGs and random operation sequences (Go native fuzzing; `TestEngine_MatchesOracle`), including dates, disabled groups, composites of composites and cycle attempts.

### 6.7 Performance targets

Reference tenant ("large university"): 150,000 groups, 25,000 folders, 600,000 identities, 3,000,000 direct memberships, 20,000,000 effective memberships, dependency depth up to 12, a reference group (`ref:student:enrolled`, 45,000 members) used by 400 policy groups. Production on Postgres 16 with 8 vCPU and 32 GB RAM; SQLite numbers apply to tenants up to 10% of this size.

| Operation | Target |
|---|---|
| `hasMember(group, identity)` | p99 ≤ 5 ms |
| List members of a group, first page of 100, sorted by name | p95 ≤ 100 ms |
| List all groups of an identity (effective, ≤ 2,000 groups) | p95 ≤ 80 ms |
| Single direct add/remove, ≤ 50 ancestors, effective state visible on response | p95 ≤ 75 ms |
| Add a 45,000-member group into a group used by 400 policy groups (≈ 18M row checks, ≈ 1–3M changes) | complete ≤ 5 min; first provisioning ops start ≤ 30 s |
| Loader run with 50,000 membership changes | engine complete ≤ 60 s |
| Effective-change event to provisioning operation applied (incremental) | p95 ≤ 60 s, excluding target API latency |
| Nightly full verification of the reference tenant | ≤ 45 min, runs on a read replica in production |
| PIT "members as of T" for a 45,000-member group | ≤ 2 s |
| Folder browser: list a folder with 5,000 children the user can VIEW | p95 ≤ 300 ms |
| Storage | ≤ 4 GB for `grp_effective` and its index; PIT grows ≈ 1–2 GB per year at 5% monthly churn |

GR-17 builds a synthetic generator and benchmark harness for this tenant and makes these numbers a CI gate (run nightly, not per PR).

---

## 7. Privilege model

### 7.1 Privileges and implication

The 22 Grouper privileges (G-36..G-38) keep their names, lower-cased (`STEM` is accepted on import as `stem_admin`).

| Object | Privilege | Allows | Implies |
|---|---|---|---|
| Group | `admin` | everything on the group, including privileges and deletion | all group privileges |
| | `update` | add and remove members | `view` |
| | `read` | see members | `view` |
| | `view` | see that the group exists and its metadata | |
| | `optin` / `optout` | add or remove **yourself** | `view` |
| | `group_attr_read` / `group_attr_update` | read or change attribute assignments on the group | `group_attr_update` ⇒ `group_attr_read` |
| Folder | `stem_admin` | everything in the folder: create, rename, delete, privileges | `create`, `stem_attr_*`, `stem_view` |
| | `create` | create groups, attribute definitions and subfolders | `stem_view` |
| | `stem_attr_read` / `stem_attr_update` | attributes on the folder | `stem_attr_update` ⇒ `stem_attr_read` |
| | `stem_view` | see the folder in browse and search | |
| Attribute definition | `attr_admin`, `attr_update`, `attr_read`, `attr_view`, `attr_optin`, `attr_optout`, `attr_def_attr_read`, `attr_def_attr_update` | as Grouper | `attr_admin` ⇒ all; `attr_update`, `attr_read` ⇒ `attr_view` |

The implication table lives in `privs/implies.go` and is checked against Grouper's behaviour on import: the importer reads Grouper's effective privileges and compares them with Tessera's computed ones (§11.3). Any mismatch fails the import's reconciliation report `[the exact Grouper implication of OPTIN/OPTOUT to VIEW is to be confirmed against PrivilegeHelper during GR-15]`.

### 7.2 Holders and effective privileges

A privilege row's holder is an identity, a group (every effective member holds it), or `everyone` (all identities in the tenant; enabling it on any object needs `tenant_admin`, equivalent to restricting EveryEntity in Grouper). Platform users are linked to identities (`platform_users.identity_id`, added in GR-4), so a signed-in admin's group privileges come from their identity's effective memberships.

**Dynamic inheritance (K5).** A row on folder `F` with `applies_to ∈ {groups, folders, attr_defs}` and `scope = one` applies to objects whose parent is `F`; `scope = sub` applies to every object below `F`. Checking privilege `p` for identity `i` on object `o`:

```
holders(o, p) = rows(object = o, applies_to = self, privilege ∈ impliedBy(p))
              ∪ rows(object = F, applies_to = type(o), privilege ∈ impliedBy(p))
                   for F = parent(o) with scope ∈ {one, sub}
                   and F ∈ ancestors(parent(o)) with scope = sub
allowed(i, o, p) = ∃ h ∈ holders(o, p): h = identity i  ∨  h = everyone  ∨  i ∈ E(h)
```

Folder ancestors come from the name path (no recursive query). A check is one indexed query over at most `depth + 1` objects plus one `grp_effective` probe per holder group, and results are cached per request.

**Platform roles still apply.** Phase 0's `tenant_admin` is the equivalent of Grouper's wheel group and implicitly holds every privilege; `auditor` holds `read`/`view`/`*_attr_read` everywhere (Grouper's read-only admin group); `viewer` holds `view` everywhere a tenant setting allows (Grouper's view-only admin). There is no `GrouperSystem` login; break-glass is Phase 0 §15.4.

**Explanations.** `GET /api/groups/{id}/privileges/effective?identity=…` returns, for each privilege, every path: "Ivan holds UPDATE on `app:foo:…:foo_user` because he is in `app:foo:security:fooAdmin`, which holds STEM_ADMIN on folder `app:foo` with scope `sub` (granted by Alice on 2026-03-02)".

**Act-as (G-42)** is replaced by OAuth token exchange (RFC 8693) in Phase 3. Until then, service clients act as themselves and need the privileges themselves. There is no "act as" header.

### 7.3 Cedar shape

Privilege checks are written so they translate directly into the Cedar schema planned for Phase 1:

```cedar
// entity types: Tessera::Identity in [Tessera::Group]; Tessera::Group in [Tessera::Folder]; Tessera::Folder in [Tessera::Folder]
permit (principal, action == Tessera::Action::"groups:update", resource)
when { resource has privHolders && principal in resource.privHolders.update };
```

Phase 2 ships the Go check (`privs/check.go`) with the exact semantics above. When the Phase 1 Cedar PDP is available, GR-4's table-driven test cases run against both and must agree.

---

## 8. Policy groups as access-as-code

### 8.1 Why Cedar for group policy

The Deployment Guide's access policy group is a precomputed authorization decision over reference groups: `allow − deny`. Grouper expresses this as composites, and more complex cases as JEXL scripts (G-33). Tessera expresses it once, as code, in a form that can be reviewed in a pull request, diffed by membership before merge, evaluated per request, and precomputed for provisioning.

### 8.2 The restricted fragment

A policy group file contains Cedar `permit` and `forbid` policies on the action `Tessera::Action::"member"` with a single resource, `Tessera::Group::"<name>"`. The `when`/`unless` conditions may use only:

- `principal in Tessera::Group::"<name>"` (a reference to any group, including other policy groups and manual exception groups),
- `principal.<attr> == <literal>`, `principal.<attr> in [<literals>]`, `principal.<attr>.contains(<literal>)` and `principal has <attr>`, over a declared set of identity attributes (department, affiliation, employee type, campus, cost center, class year, and so on; §8.4),
- `&&`, `||`, `!` and parentheses.

No `context`, no `resource` attributes, no arithmetic, no datetime, no extension functions. Anything else fails validation in CI and in the API with a precise error. Within this fragment, membership is decidable and equals:

```
E(policy) = ( ⋃ permit-conditions ) − ( ⋃ forbid-conditions )
```

### 8.3 Example and compilation

`groups/app/foo/foo_user.cedar` in the tenant's policy repository:

```cedar
@group("app:foo:service:policy:foo_user")
@display("Foo users")
@owner("app:foo:security:fooAdmin")
@provision("ldap-main", "entra")
@id("allow")
permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:service:policy:foo_user")
when {
  principal in Tessera::Group::"ref:employee:faculty" ||
  (principal in Tessera::Group::"ref:student:enrolled" && principal.campus == "main") ||
  principal in Tessera::Group::"app:foo:service:policy:foo_user_allow_manual"
};

@id("deny")
forbid (principal, action == Tessera::Action::"member", resource == Tessera::Group::"app:foo:service:policy:foo_user")
when {
  principal in Tessera::Group::"ref:iam:global_deny" ||
  principal in Tessera::Group::"app:foo:service:policy:foo_user_deny_manual"
};
```

The compiler (`policygroups/compile.go`) normalizes each condition to a tree of union, intersection and complement over **operands**: groups, and **attribute groups**. It emits internal composite groups named `…:foo_user:_allow`, `…:foo_user:_deny` and `…:foo_user:_n<hash>` (type `intermediate`, `managed_by='policy_repo'`, hidden by default in the UI), and the policy group itself as `complement(_allow, _deny)`. Identical subtrees across files share a node (hash-consed by canonical form), so 400 policy groups that all say "faculty or enrolled students on main campus" reuse one node.

**Attribute groups.** `principal.campus == "main"` compiles to a system-maintained group `sys:attr:campus:main`, kept current from identity attributes by the attribute indexer (§8.4). Attribute groups are ordinary basic groups whose direct memberships have `source='attribute'`, so the engine needs no special case.

### 8.4 Identity attributes (Grouper data fields)

The policy schema (`groups/schema.cedarschema`) declares which identity attributes policy may use, their types and their source (HRIS, SIS, IdP or a data provider connector). This replaces Grouper's entity data fields and data providers (G-34): a data provider is a connector that contributes attributes to identities, with per-attribute authority (D4·M1). The attribute indexer maintains `sys:attr:<name>:<value>` groups only for attribute/value pairs actually referenced by compiled policy, so cardinality stays bounded.

### 8.5 Lifecycle of a policy change

1. A pull request changes a `.cedar` file.
2. CI runs `tessera groups policy validate` (fragment, schema, references exist, no cycles) and `tessera groups policy diff --base main`, which calls the tenant API in **simulation mode**: it compiles both versions, evaluates the changed nodes against the live effective memberships, and posts a comment: "+1,204 identities, −13 identities; downstream: `entra:foo_user` (+1,204/−13), AWS permission set `FooReadOnly` via SCIM (+1,204/−13); 3 of the 13 removed used Foo in the last 30 days." That last fact comes from the usage index and is something Grouper cannot tell you.
3. Merge triggers sync (webhook or poll). Tessera checks out the commit, compiles, applies definition changes through the engine as one batch, records `policy_ref.commit` on each group and writes `groups.policy.applied` to the audit ledger with the commit SHA.
4. Every effective change caused by the sync carries `cause_type='policy_repo'` and the commit, so PIT history answers "which policy version made Bob a member".

Policy groups can also be created in the UI with the policy builder (§10.13). The UI writes the same Cedar text to the database (`managed_by='ui'`) and offers "Export to repository", which opens a pull request. Groups with `managed_by='policy_repo'` are read-only in the UI except their manual exception groups, which are ordinary groups.

### 8.6 Cross-check with the PDP

Because the fragment is valid Cedar, the Phase 1/4 PDP (AuthZEN, D6·M6) can answer "is Bob a member of `foo_user`" per request from live attributes. `TestPolicyGroups_PDPAgreesWithEngine` generates random identities and policies and asserts that the Cedar evaluator and the materialized engine agree.

---

## 9. Loaders and provisioning

### 9.1 Loaders as connectors

```go
// internal/groups/loaders/source.go
type SubjectRef struct {
	Source     string // "hris", "sis", "ldap-main", or a connector id
	Identifier string // employee id, student id, uid, email, DN
}

type LoadedGroup struct {
	Name        string // relative to the loader's target folder, after the name template
	DisplayName string
	Description string
	Members     []SubjectRef
}

type GroupSource interface {
	Full(ctx context.Context, job LoaderJob) ([]LoadedGroup, error)
	// Changes is optional; ok=false means the source has no incremental feed.
	Changes(ctx context.Context, job LoaderJob, cursor string) (changes []GroupChange, next string, ok bool, err error)
}
```

| Loader type | Grouper equivalent | Notes |
|---|---|---|
| `sql_simple`, `sql_group_list` | G-54, G-55 | Runs against a **Connection** (Admin → Connections) with sealed credentials. Read-only transaction, statement timeout (default 120 s), row limit, `SELECT`/`WITH` only (checked by parsing the first keyword and by running in a read-only transaction). |
| `ldap_simple`, `ldap_group_list`, `ldap_attribute` | G-56 | Paged search (RFC 2696), LDAPS or StartTLS only, scope and filter validated. |
| `csv`, `sftp_csv` | G-62 | Header-mapped; file hash recorded; SFTP host keys pinned. |
| `connector_groups` | G-61 | Any connector's groups (Okta, Entra, Google, Duo, Zoom…) become native groups. |
| `attribute` | G-34, G-64 | Groups from identity attributes, for example one group per department under `ref:dept:` (organization hierarchies). |
| `recent_memberships` | G-27 | "People in group X within the last N days", optionally including current members. Fed by PIT (§10.2), so it is exact. |
| `hris_sis_feed` | basis groups | Workday, Banner, PeopleSoft Campus Solutions and Slate via their connectors; effective-dated. |

```sql
-- 0105_group_loaders.sql
CREATE TABLE grp_loaders (
  id               TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL REFERENCES tenants(id),
  name             TEXT NOT NULL,
  type             TEXT NOT NULL,
  connection_id    TEXT,                       -- Admin → Connections
  config           TEXT NOT NULL,              -- JSON, typed per loader type
  target_folder_id TEXT NOT NULL REFERENCES grp_folders(id),
  name_template    TEXT NOT NULL DEFAULT '{{.Name}}',
  on_missing_group TEXT NOT NULL DEFAULT 'empty' CHECK (on_missing_group IN ('empty','disable','delete','keep')),
  and_group_id     TEXT REFERENCES grp_groups(id),   -- only keep subjects also in this group (G-60)
  schedule         TEXT NOT NULL,              -- cron
  incremental_secs INTEGER,                    -- null = no incremental
  failsafe         TEXT NOT NULL,              -- JSON (below)
  status           TEXT NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled','disabled','held')),
  created_by TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);
CREATE TABLE grp_loader_runs (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, loader_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('full','incremental','preview')),
  started_at TEXT NOT NULL, finished_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('running','applied','held','failed','approved','rejected')),
  source_rows INTEGER, groups_seen INTEGER, adds INTEGER, removes INTEGER, unresolved INTEGER,
  failsafe_tripped TEXT, impact TEXT,          -- JSON downstream impact (K7)
  source_hash TEXT, error TEXT
);
CREATE TABLE grp_loader_unresolved (
  tenant_id TEXT NOT NULL, loader_id TEXT NOT NULL, source TEXT NOT NULL, identifier TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, groups TEXT NOT NULL,   -- JSON list of group names
  PRIMARY KEY (tenant_id, loader_id, source, identifier)
);
```

**Failsafes** (G-59), per loader, defaults in brackets: maximum members removed from one group as a percentage [20%] and absolute [500]; minimum group size [unset]; maximum groups emptied or deleted per run [5%]; maximum unresolved subjects [2%]. A tripped failsafe sets the run to `held`, applies nothing and creates an **Inbox task** for the loader's owners with the diff and its **downstream impact** (policy groups that change, provisioned targets that change, how many removed people used the downstream access in the last 30 days). Approve applies the held run as it was computed; reject discards it. Every decision is in the audit ledger.

**Loader-managed groups** (`managed_by='loader'`) cannot be edited by hand. The UI offers "add an exception", which creates or uses the matching `_allow_manual` or `_deny_manual` group, following the Deployment Guide.

**Subject resolution.** `SubjectRef` resolves to an identity through the correlation engine (D4·M2): exact identifier match on a verified identifier of the given source; otherwise the reference goes to `grp_loader_unresolved` (G-14) and is retried each run. Unresolved subjects are never silently dropped and are counted in the failsafe.

**Who can configure loaders.** Creating or changing a loader with a SQL or LDAP query needs the platform permission `groups.loader.admin` (granted to `tenant_admin` and `policy_admin`), a fresh phishing-resistant step-up (Phase 0 `STEP_UP_POLICY`), and for SQL loaders a second approver through the Phase 0 admin-change workflow. This is the lesson of Grouper GRP-6311 (non-admins could configure loader jobs).

### 9.2 Provisioning framework

```go
// internal/groups/provisioning/provisioner.go
type Capabilities struct {
	Groups, Entities, Memberships, EntityAttributes bool // EntityAttributes: isMemberOf-style values on users
	CreateEntities                                    bool
	Incremental                                       bool
	MaxBatch                                          int
}

type Provisioner interface {
	Capabilities() Capabilities
	ReadAll(ctx context.Context, scope Scope) (TargetState, error)         // full read for full sync
	Read(ctx context.Context, refs []TargetRef) (TargetState, error)       // targeted re-read for verification
	Apply(ctx context.Context, ops []Op) ([]OpResult, error)
}
```

- **Desired state.** For each provisioner, the set of provisionable groups is computed from `grp_provisionable` marks with folder inheritance (G-67): a mark on a folder with scope `sub` covers every group under it unless a group opts out. Each group's target name, object class and attributes come from a **translation template** (Go `text/template` with a fixed, side-effect-free function set: `lower`, `upper`, `replace`, `truncateHash`, `ldapEscape`, `join`; no JEXL, K6). Members translate to target member references through the identity's **account** in the target system (the existing `accounts` table). If an identity has no account and the provisioner can create entities, membership in the group's **account policy group** (Deployment Guide) decides whether to create one.
- **Full sync** (nightly by default, and on demand): `ReadAll` → diff with desired → ops. First run uses **adopt mode**: existing target objects are matched by name or a match attribute and recorded, but nothing is changed until an admin reviews the diff and enables the provisioner.
- **Incremental sync**: a consumer of group events (§10.1) turns effective changes for provisionable groups into ops, coalescing within a 2-second window and per batch limits.
- **Verification (README rule 4).** After `Apply`, the framework calls `Read` for every touched object and compares. Only matching ops become `verified`. Mismatches retry with backoff and, after 3 attempts, become `drift` and raise an Inbox task. Status `done` is reserved for `verified`.
- **Failsafes**: maximum deletes per run (default 2% of target memberships or 1,000), maximum groups deleted (default 0 without approval), and a `dry_run` flag.
- **Sync-back** (G-69): `grp_sync_*` tables cache the last-read target state, so full sync can diff without re-reading unchanged objects when the target supports change tokens (Entra delta queries, Google `updatedMin` on some resources, LDAP `modifyTimestamp`).
- **Diagnostics** (G-68): `POST /api/provisioners/{id}/diagnose?group=…&identity=…` explains why something will or will not be provisioned and shows the exact ops a sync would produce, without applying them.

```sql
-- 0106_group_prov.sql (abridged)
CREATE TABLE grp_provisioners (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
  target_type TEXT NOT NULL,   -- ldap | ad | entra | google | okta | scim2 | sql | webhook | box | duo | zoom | github | ...
  connection_id TEXT NOT NULL, config TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'adopt' CHECK (mode IN ('adopt','dry_run','active','paused')),
  full_schedule TEXT NOT NULL DEFAULT '0 2 * * *', failsafe TEXT NOT NULL,
  UNIQUE (tenant_id, name)
);
CREATE TABLE grp_provisionable (
  tenant_id TEXT NOT NULL, provisioner_id TEXT NOT NULL,
  object_type TEXT NOT NULL CHECK (object_type IN ('folder','group')), object_id TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'self' CHECK (scope IN ('self','one','sub')),
  include INTEGER NOT NULL DEFAULT 1,           -- 0 = explicit opt-out under an inherited mark
  metadata TEXT NOT NULL DEFAULT '{}',          -- per-group target settings (e.g. AD group scope, Google email)
  PRIMARY KEY (tenant_id, provisioner_id, object_type, object_id)
);
CREATE TABLE grp_sync_groups (
  tenant_id TEXT NOT NULL, provisioner_id TEXT NOT NULL, group_id TEXT NOT NULL,
  target_id TEXT, target_name TEXT, state_hash TEXT, last_read_at TEXT, last_verified_at TEXT,
  status TEXT NOT NULL, PRIMARY KEY (tenant_id, provisioner_id, group_id)
);
CREATE TABLE grp_sync_ops (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, provisioner_id TEXT NOT NULL, run_id TEXT,
  op TEXT NOT NULL, object_ref TEXT NOT NULL, payload_hash TEXT NOT NULL,
  cause_seq INTEGER,                            -- grp_events.seq
  status TEXT NOT NULL CHECK (status IN ('planned','applied','verified','failed','drift','skipped')),
  attempts INTEGER NOT NULL DEFAULT 0, error TEXT,
  planned_at TEXT NOT NULL, applied_at TEXT, verified_at TEXT
);
```

**Targets.**

| Target | Phase | Implementation notes |
|---|---|---|
| LDAP / OpenLDAP / 389-DS | 2 | Groups as `groupOfNames` or `groupOfUniqueNames` or `posixGroup`; optional entity attributes (`isMemberOf`, `eduPersonEntitlement`) on people. Range-limited member writes for large groups. This is how universities release `isMemberOf` through Shibboleth. |
| Active Directory | 2 | Universal/global/domain-local scope, `sAMAccountName` ≤ 64 characters via `truncateHash`, ranged retrieval of `member;range=…` for groups over 1,500 members. |
| SCIM 2.0 (RFC 7643/7644) | 2 | Generic client; profiles for AWS IAM Identity Center, GitHub Enterprise Managed Users, Atlassian Cloud, Slack, Zoom. PATCH for membership changes; full read via `/Groups?attributes=members` with paging. |
| SQL table | 2 | Writes `(group, member)` rows to a customer database for applications that read memberships from SQL (G-74, and replaces G-32 membership cache tables for external consumers). |
| Webhook / event stream | 2 | Signed CloudEvents for custom consumers (G-77 messaging provisioner). |
| Entra ID | 2 | Microsoft Graph, `$batch`, delta queries; security and Microsoft 365 groups; `members@odata.bind` in chunks of 20. Needs a real tenant to verify. |
| Google Workspace | 2 | Admin SDK Directory API, batch requests, quotas. Needs a real tenant. |
| Okta | 2 | Groups API; Okta-mastered groups only. Needs a real org. |
| Box, Duo, Zoom, Adobe, Dropbox, GitHub org teams, Jamf, Datadog, C•CURE, Interfolio, TeamDynamix, Remedy, Freshservice, TrueFoundry, midPoint | 3 | Connector SDK (D4·S10); ticketing targets via fulfilment tasks (D4·M8). |

---

## 10. Everything else

### 10.1 Change events (G-79..G-82)

Every committed change writes rows to `grp_events` in the same transaction, with a per-tenant gap-free `seq`. Event types:

`folder.created|renamed|moved|deleted`, `group.created|updated|renamed|moved|deleted|disabled|enabled|definition_changed`, `membership.direct.added|removed|dates_changed`, `membership.effective.added|removed`, `privilege.granted|revoked`, `attribute.assigned|removed|value_changed`, `loader.run.applied|held|approved|rejected`, `provisioning.op.verified|failed|drift`, `attestation.due|completed|overdue_action`, `rule.fired`.

Consumers keep cursors in `grp_event_cursors`. Internal consumers: the PIT writer (synchronous, same transaction), the graph projection (K10), provisioners, the access-review engine (micro-certifications on privileged group joins, D4·M15), and SSF/CAEP when a membership removal must kill sessions (Phase 3). External delivery uses CloudEvents 1.0 JSON over signed webhooks in Phase 2 and AWS SQS/SNS, RabbitMQ and Kafka in GR-18. **Inbound messages** (G-81) are the batch membership API with idempotency keys (§10.11), not a queue listener with privileged access.

### 10.2 Point-in-time history (G-93)

- The PIT writer closes and opens intervals in `grp_pit_*` for every object, direct membership, effective membership and privilege change, using the event `seq` as `start_seq`/`end_seq`.
- **As-of queries**: `GET /api/groups/{id}/members?as_of=2026-03-01T00:00:00Z` and `…?between=T1,T2` (members at any time in the window). "Why was Bob a member at T" replays `grp_pit_direct` and `grp_pit_objects` for the group's ancestors at T.
- **Deleted groups** are soft-deleted (`status='deleted'`) with PIT intact. "Restore" recreates the definition and direct memberships as of a chosen time, as a reviewed change.
- **Tamper evidence (K9).** At 00:05 UTC a job computes a Merkle root over the previous day's `grp_events` rows (canonical JSON per row, RFC 8785) and appends `groups.pit.digest {day, first_seq, last_seq, root}` to the audit ledger, whose checkpoints are anchored externally (Phase 0 §13.6). `tessera groups pit verify --day …` recomputes and checks. PIT tables are derived data: `tessera groups pit rebuild` replays `grp_events`, and a weekly job rebuilds a sample of groups and compares.
- **Retention**: events and PIT are kept for 7 years by default (`groups.retention_days`), longer than most audit windows; the delete-old-records job (G-94) prunes beyond that and records what it pruned.

### 10.3 Rules and membership constraints (G-28, G-29, G-83, G-84)

Rules use a closed vocabulary (K6). Each rule is owned by a folder or group and needs `admin` (or `stem_admin`) on its owner **and** on every object its action touches; this is checked when the rule is saved and again when it fires (fixing the class of Grouper GRP-7359, rules UI privilege escalation).

| Trigger | Conditions | Actions |
|---|---|---|
| direct or effective membership added/removed in owner group, or in any group under owner folder | identity attribute equals/in; identity in group; membership source is X; group has object type | add disabled date N days to memberships in owner group; remove from group; add to group; veto (with message); assign privilege on created object; notify (template); open Inbox task; start micro-certification |
| group or folder created under owner folder | name matches pattern | assign privileges; assign object type; mark provisionable |
| identity lost an affiliation (from JML) | affiliation | deprovisioning action (§10.5) |

Built-in constraints are rules with a dedicated UI: **membership require** (G-28: must be in group A to be in B; enforced as a veto on add and as removal on change), **one group only** in a folder (G-29), **no self-add** (a Grouper sample hook), **no `everyone` without `tenant_admin`**, and **no deletion of provisioned groups** without first un-provisioning. Rule actions that send email are off by default per tenant (Grouper GRP-7381 made this "default closed"). Hooks (G-84) become signed webhooks with optional synchronous veto (timeout 2 s, fail closed or open by configuration).

```sql
-- 0107_group_gov.sql (rules part)
CREATE TABLE grp_rules (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
  owner_type TEXT NOT NULL CHECK (owner_type IN ('folder','group')), owner_id TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'self' CHECK (scope IN ('self','one','sub')),
  trigger TEXT NOT NULL, conditions TEXT NOT NULL DEFAULT '[]', action TEXT NOT NULL, params TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL, created_at TEXT NOT NULL
);
```

### 10.4 Attestation (G-85, G-86)

Attestation is a **group-membership campaign** in the Phase 2 certification engine (`internal/reviews`), so it inherits frozen, provably complete populations (D4·M13). Settings on a group or folder (inherited): interval in days, reviewers (group admins by default, or a named group), reminder schedule, and the action when overdue: none, **disable the group**, or **remove unattested memberships** (G-86). Remove actions go through the engine and are verified downstream like any removal.

Where Tessera is better: each item shows **usage context** for what the membership grants downstream (for example "Bob has not used `aws:FooReadOnly` granted through this group in 94 days"), how the membership was granted (direct, loader, exception, request), peer coverage, and the policy group exceptions. Auto-decisions follow D4·§8.2: auto-revoke unused direct exceptions where the policy allows it, never auto-certify privileged access, sample auto-decisions for human QA.

### 10.5 Deprovisioning (G-87) and lifecycle events (G-35)

- **Affiliations** are reference groups designated in Admin → Groups settings (for example `ref:employee:all`, `ref:student:enrolled`, `ref:guest:active`).
- When an identity leaves all affiliations that kept it eligible (a JML leaver event, an affiliation-loss event from the engine, or a guest expiry from the guest design), Tessera creates per-folder **deprovisioning tasks** in the Inbox for owners of folders where the identity still has **direct** memberships or privileges. Folder settings choose: notify owners only, auto-remove after N days, or auto-remove immediately. A built-in rule vetoes **new** direct memberships for deprovisioned identities (Grouper's `MembershipVetoIfDeprovisionedHook`) unless the actor overrides with a reason.
- A deprovisioning report lists open items per folder and their age; overdue items appear on the JML SLA dashboard (D4·M23).
- User lifecycle events (G-35) are Tessera's JML events (`LifecycleEvent`, D4·§8.3), which rules can trigger on.

### 10.6 Subjects, search and unresolvable subjects (G-10..G-17)

- The subject registry is the identity warehouse. Grouper's subject sources become connectors (HRIS, SIS, LDAP, IdP, CSV) plus correlation (D4·M2).
- **Search and sort** (G-13): `identities` gains `search_text` and `sort_key`. SQLite uses an FTS5 virtual table; Postgres uses `pg_trgm`. Member lists sort by `sort_key` and search by prefix and trigram without resolving subjects.
- **Subject diagnostics** (G-12): Admin → Connections → (source) → "Resolve a subject" shows the matching rule, candidates and confidence.
- **Unresolvable subjects** (G-14): when an identity is deleted or becomes unresolvable in its authoritative source, its memberships are marked in the UI and an Inbox task lists them; after a configurable grace period (default 30 days) they are removed with `cause_type='unresolvable'`. Nothing is removed silently, and a threshold (default 1% of identities in a day) holds the run, as Grouper's USDU does.
- **Member change subject** (G-15) is the identity **merge** operation in the guest design (`guest-accounts-and-claim.md` §5.4), which moves memberships and privileges with history and can be undone.
- **Entities** (G-10) are non-human identities with an owner. **External subjects** (G-17) are guests with sponsors, claim and expiry (guest design).

### 10.7 Reports and visualization (G-88..G-90)

- **Reports** are saved, parameterized queries from a fixed catalogue (no free SQL in Phase 2): members of a group (direct/effective, with sources and dates), groups of a person, privileges in a folder, groups without owners, policy groups with more than N direct exceptions, basis groups referenced directly by policy (a Deployment Guide anti-pattern), loader failsafe history, provisioning drift, attestation status, deprovisioning backlog. Schedules, CSV/JSON output, delivery by email (Phase 0 notification outbox) or to S3. A custom SQL report console is a Phase 3 item shared with the Saviynt-parity "data analyzer" gap.
- **Visualization**: Insights → Access graph gains a "Groups" lens: the dependency DAG of a group (up to N levels each way), its provisioners and downstream entitlements, and a person's group graph. Every node is filtered by VIEW (avoids the class of Grouper GRP-7387, a folder information leak in visualization).
- **Daily email** (G-90): the notification digest (Phase 0 outbox) includes group changes for owners who subscribe.

### 10.8 Workflow and requests (G-26, G-91)

Requestable groups (`requestable=1`) appear in **Access → Request access**. Approval routing uses the Phase 2 access-request engine (risk tiers, no self-approval, SoD preview). The default approvers are the group's `update` holders; folder settings can name an approver group. Approved requests create a direct membership with `source='request'`, an optional `disabled_at` (time-bound), and a link to the request. Opt-in and opt-out (G-26) are immediate when the identity holds the privilege, and are audited.

### 10.9 Attribute framework, object types and services (G-43..G-48, G-05)

- Tables `grp_attr_defs`, `grp_attr_names`, `grp_attr_name_implies` (closure), `grp_attr_actions`, `grp_attr_action_implies`, `grp_attr_assigns` (owner type: folder, group, identity, direct membership, effective membership (read-only), attribute definition, another assignment; enabled/disabled dates; `disallowed` flag) and `grp_attr_values` (typed columns: `value_string`, `value_integer`, `value_timestamp`, `value_member_id`; floating values stored as decimal strings so audit hashing stays float-free).
- Attribute definitions live in folders and carry the eight `attr_*` privileges.
- **Object types** (G-05) are a built-in attribute definition `etc:objectTypes` with values from the Deployment Guide list (`ref`, `basis`, `policy`, `bundle`, `manual`, `intermediate`, `etc`, `org`, `test`, `service`, `app`, `security`), plus `data_owner` and `member_description`. They drive UI badges and lint warnings (for example "policy group has 312 direct members").
- **Services** (G-48): a folder marked as a service appears under My access → "Services I can use" with the policy groups that grant it.

### 10.10 Permissions and limits (G-49..G-53), Phase 3

Grouper's role/permission framework maps onto Tessera's existing permission graph: a **permission resource** is an attribute name in a `perm` definition, an **action** is a definition action, and an assignment is `(role, resource, action, allow|disallow)` or `(role, identity, resource, action, …)`. Resource and action inheritance use the implies closures. Conflict resolution follows Grouper's heuristics table (more specific resource, then more specific action, then direct over inherited, then disallow over allow) `[confirm against PermissionHeuristics on import]`. **Limits** become Cedar `when` conditions over `context` on the compiled permission policy, which is where Tessera's PDP evaluates them; the Grouper limit types (amount less than, IP on network, time window, expression) map to Cedar `context.amount < …`, `ip(context.ip).isInRange(…)`, and so on. GR-19 implements this and the PIT permission view.

### 10.11 API (WS parity, G-96..G-98)

All routes are under `/api/groups/...`, authenticated by Phase 0 sessions or DPoP tokens, and audited. Writes accept `Idempotency-Key`. Batches accept up to 1,000 operations and are atomic per batch unless `"atomic": false`.

| Tessera route | Grouper WS equivalent |
|---|---|
| `GET /api/groups/folders?parent=&q=&scope=one|sub` · `POST/PATCH/DELETE /api/groups/folders/{id}` · `POST /api/groups/folders/{id}:move|:copy` | findStems, stemSave, stemDelete, move/copy |
| `GET /api/groups?folder=&q=&type=&scope=` · `POST/PATCH/DELETE /api/groups/{id}` · `:move` `:copy` `:convert-to-composite` `:restore` | findGroups, groupSave, groupDelete |
| `GET /api/groups/{id}/members?filter=direct|indirect|effective|composite&list=&enabled=&as_of=&between=&q=&sort=&page=` | getMembers, getMemberships, PIT |
| `GET /api/groups/{id}/members/{identity}` (hasMember, with `trace=true` for all paths) | hasMember |
| `POST /api/groups/{id}/members:batch` `{add:[…], remove:[…], enabled_from, disabled_at, reason}` | addMember, deleteMember, inbound messages |
| `GET /api/identities/{id}/groups?filter=&as_of=` | getGroups |
| `GET|POST|DELETE /api/groups/{id}/privileges` · `GET …/privileges/effective?identity=` · same under folders and attribute definitions | getGrouperPrivileges, assignGrouperPrivileges |
| `GET|POST /api/groups/attr-defs` · `/attr-names` · `/attr-assignments` | attribute def/name save/delete, assignAttributes(Batch), getAttributeAssignments |
| `POST /api/groups:simulate` `{changes:[…]}` → membership and downstream diff | (no equivalent; "verify change" for ABAC only) |
| `GET /api/groups/events?after_seq=&type=` (pull) and webhooks (push) | change log, messaging, ESB |
| `GET /api/audit?target_type=group&target_id=…` | getAuditEntries |
| `POST /api/identities/{id}:merge` (guest design) | memberChangeSubject |
| `GET /scim/v2/Groups`, `/scim/v2/Users` (read-only SCIM server over native groups, G-98) | Grouper SCIM server |

The OpenAPI document is generated from the route table, as in the Go port.

### 10.12 CLI and declarative plans (GSH parity, G-99, G-100)

`tessera groups` subcommands mirror the API: `ls`, `show`, `create`, `mv`, `cp`, `rm`, `members add|rm|ls|trace`, `privs grant|revoke|explain`, `attrs`, `loader run|preview|approve`, `prov sync|diagnose`, `pit as-of|between|verify|rebuild`, `verify`, `policy validate|diff|apply`, `import grouper`.

GSH's role as a scripting and bulk-change tool is covered by **declarative plans**:

```yaml
# plan.yaml
folders:
  - name: app:foo
    template: application        # expands the Deployment Guide structure (G-06)
    params: {admins: "org:it:staff:iam"}
groups:
  - name: app:foo:service:ref:testers
    members: {add: [ "employee:12345", "employee:23456" ]}
privileges:
  - object: folder:app:foo
    grant: {stem_admin: ["group:app:foo:security:fooAdmin"], scope: sub}
```

`tessera groups plan -f plan.yaml` prints the diff and its membership and downstream impact. `apply` executes it as audited batches. **Templates** (GSH templates, G-99) are server-side, versioned plan templates with typed inputs, which users run from the UI with a form. They cannot execute code (K6). Export of a folder to a plan (`tessera groups export app:foo > plan.yaml`) replaces "export to GSH".

The Grouper client's role (G-100) is covered by the Go CLI and a generated Go/TypeScript client. The v7 Grouper MCP server (G-102) maps to Tessera's Phase 4 MCP tools over this API, authorized through the Phase 4 MCP authorization server.

### 10.13 UI: Directory → Groups

The redesigned UI's **Directory → Groups** list (branch `ui-redesign`, `features/directory/Lists.tsx`) today lists connected-system groups. It becomes two views with a toggle: **Managed groups** (native) and **Connected groups** (from systems).

| Screen | Contents |
|---|---|
| **Folder browser** | Tree plus breadcrumb (`app › foo › service › policy`), children list with type badges, member counts and provisioning icons; only objects the user can VIEW; search across names and display names; favorites and recents (G-07). |
| **Group page** | Header: display name, path, type badges, owner, status, "Recalculating…" banner if pending. Tabs: **Members** (direct / indirect / effective filter; source column; enabled and disabled dates; bulk add/remove/import/export; "trace" drawer showing every path), **Definition** (for composites and policy groups: a visual set builder showing allow/deny/exceptions; for policy groups the Cedar source, commit and a "propose change" button), **Privileges** (direct and inherited, with explanations), **Usage** (where this group is used: parent groups, policy groups, provisioned targets, downstream entitlements in the access graph and their 30/90-day use), **Provisioning** (targets, last verified sync, drift, diagnose), **Loader** (source, schedule, last run, held runs), **Attributes**, **History** (PIT: as-of date picker, diff between two dates, event timeline with causes), **Attestation**, **Rules**. |
| **Folder page** | Children, privileges with inheritance scope, object types, provisioning marks, attestation and deprovisioning settings, rules, templates. |
| **Change preview** | Every save of a membership batch, composite definition, privilege or loader shows a simulation first: "+1,204 / −13 identities in 4 groups; 2 provisioned targets; 3 removed people used this access in the last 30 days; 1 SoD conflict introduced". |
| **New application** wizard | The Deployment Guide template (security, service, ref and policy groups, allow/deny/exception groups) in one step (G-06). |
| **Admin → Groups settings** | Affiliations, default privileges, `everyone` policy, retention, sync budget, email rules gate. |
| **Admin → Jobs** | Loaders, provisioners, time wheel, verifier, PIT digest: status, history chart, last error, run now (G-63, G-101). |
| **Inbox** | Held loader runs, provisioning drift, deprovisioning tasks, attestation items, unresolved subjects. |

### 10.14 Daemon, scheduler and configuration (G-101)

Tessera's background job framework (Phase 0 `ForEachActiveTenant`, Admin → Jobs) runs: engine queue worker, time wheel, verifier, loaders, provisioners (full and incremental), PIT digest, attestation reminders, deprovisioning, reports and retention. Each job exposes health, last success, lag and errors on `/api/admin/jobs` and the existing health endpoint. Configuration lives in the database, is versioned and audited, and secrets are sealed (Phase 0 `seal`). Grouper's config overlays, `morphString` encryption and quartz tables are not needed.

---

## 11. The Grouper connector

### 11.1 Scope

The connector **reads** from Grouper. It never writes to Grouper, except optional **reverse sync** of cut-over folders (§11.5), which is off by default. It supports two read modes:

| Mode | How | Use when |
|---|---|---|
| **WS mode** | Grouper REST web services v2.x (JSON) with a dedicated Grouper service subject that has READ/VIEW (and attribute read) on the folders being migrated. Auth: Grouper built-in WS user, OIDC, or trusted JWT (G-97), with credentials sealed in a Tessera Connection. | Small and medium deployments, or no database access. |
| **SQL mode** | Read-only credentials on a Grouper database replica. Reads Grouper's views (`grouper_memberships_lw_v`, `grouper_groups`, `grouper_stems`, `grouper_composites`, `grouper_aval_asn_*_v`, `grouper_pit_*`, `grouper_change_log_entry`). | Large deployments (millions of memberships), PIT import, and near-real-time change feed. |

The Grouper ESB HTTP publisher (G-82) can also be configured **in Grouper** to POST change-log events to a Tessera webhook endpoint, which needs no Grouper code and gives low-latency changes in WS mode.

### 11.2 What is imported

| Grouper object | Imported as | Notes |
|---|---|---|
| Folders | `grp_folders`, same names, `managed_by='grouper_mirror'`, `external_ref` = stem UUID | Display names and descriptions too. |
| Groups and roles | `grp_groups` with kind | Enabled/disabled dates kept. |
| Composites | composite groups, same operator and factors | |
| Direct memberships (default list and custom lists) | `grp_direct_memberships`, `source='grouper_import'`, dates kept | Members that are groups become nesting edges. |
| Effective memberships | **Not imported**; computed by the engine, then **compared** with Grouper's (§11.4) | The comparison is the correctness proof. |
| Privileges (all 22, including inherited-privilege rules) | `grp_privileges`; Grouper privilege-inheritance rules become dynamic inherited rows; privileges that Grouper copied from those rules are recognized and not duplicated | Effective privileges are compared like memberships. |
| Subjects | Resolved to Tessera identities through correlation by `(sourceId, subjectId)` and identifiers, with confidence tiers; local entities become `subtype=entity` identities with owners from the entity's admins | Unresolved subjects go to a review queue and their memberships are held, not dropped. |
| Attribute definitions, names, actions, assignments, values | attribute framework | Object types, data owner, member description. |
| Loader configuration (attributes `grouperLoader*`) | `grp_loaders` in `status='disabled'` with the SQL or LDAP query, schedule and failsafe settings; the Grouper database or LDAP connection must be re-created as a Tessera Connection | Enabled only at cut-over. |
| Provisioning marks and provisioner config | `grp_provisionable` and `grp_provisioners` in `mode='adopt'` | Cut-over per target (§11.5). |
| Attestation, deprovisioning, rules (attribute-based config) | settings and rules where the vocabulary maps; unmappable rules are listed in the import report | JEXL scripted groups (G-33) are translated to Cedar where they use supported constructs; others are listed for manual rewrite. |
| Reports, workflows, GSH templates | listed in the import report only | Recreated by hand. |
| PIT history (SQL mode, optional) | `grp_pit_*` with `start_seq`/`end_seq` null and an `import` marker; not part of the Tessera digest chain before the import date | Lets auditors query pre-migration history in one place. |
| Audit entries | not imported; exported to the customer's archive | |

### 11.3 Conflict handling

- **Names.** The import has a mount point (default: the root, so names are unchanged). If a Tessera-native object with the same name exists, the import stops for that subtree and reports it. The admin chooses: rename the native object, import under a prefix (for example `grouper:`), or **adopt** (treat the native object as the mirror target if definitions match).
- **One writer per folder.** A folder is in exactly one of `mirror` (Grouper writes, Tessera reads), `shadow` (Grouper writes, Tessera computes natively and compares) or `native` (Tessera writes). In `mirror` and `shadow`, Tessera's API and UI refuse writes to the folder (`409 folder_mirrored`) except to unrelated native objects.
- **Subjects.** Low-confidence matches never auto-link. A subject that maps to two identities, or an identity claimed by two subjects, goes to the review queue. Until resolved, the membership is kept in `grp_import_unresolved` and counted in the reconciliation.
- **Semantics.** Where Grouper and Tessera could disagree (privilege implication edge cases, disabled factor groups in composites, memberships of disabled groups), the comparison reports the exact rows, and the import is not allowed to proceed to `native` until each difference is either fixed or accepted with a reason recorded in the ledger.
- **Concurrent change during import.** The import records Grouper's change log sequence (SQL mode) or a start timestamp (WS mode) and then applies changes since, so a long import converges.

### 11.4 Shadow-compare

In `shadow`, Tessera runs the imported definitions natively: composites and nesting through its own engine, and (optionally) the imported loaders in `preview` mode against the same sources. A comparison job runs hourly per folder: for every group, compare Tessera's effective members with Grouper's (WS `getMembers` with effective filter, or `grouper_memberships_lw_v` in SQL mode), and Tessera's effective privileges with Grouper's. Results: `match`, `differs` (with the identities and the reason class) or `not comparable` (unresolved subjects). The **folder readiness** score is the share of groups that matched for the last 7 days.

### 11.5 Cut-over, per folder

1. **Inventory.** Import in `mirror` mode. Read the import report: counts reconciled to Grouper's own counts, unresolved subjects, unmappable rules and scripts.
2. **Resolve subjects** until unresolved < 0.1% and every unresolved subject is understood (typically departed people who should be cleaned up in Grouper first).
3. **Shadow.** Switch the folder to `shadow`. Enable imported loaders in `preview`. Wait until readiness is 100% for 7 consecutive days, or every difference is explained and accepted.
4. **Provisioning dry run.** For each provisioner that Grouper runs for this folder, configure the Tessera provisioner in `dry_run`: compare Tessera's desired target state with the target's actual state (which Grouper is maintaining). The diff must be empty, or explained.
5. **Flip, one target at a time.** Disable Grouper's provisioner for the folder (a Grouper admin does this; Tessera shows the exact Grouper setting), then switch Tessera's to `active`. Verify-by-reaggregation confirms nothing changed downstream.
6. **Flip the folder.** Switch to `native`: Tessera becomes the writer, loaders run for real, and the Grouper folder is frozen by a Grouper admin (remove UPDATE/ADMIN from non-wheel holders, disable loader jobs). Optional **reverse sync** writes Tessera's memberships back into the frozen Grouper folder through WS for applications that still read from Grouper.
7. **Move readers.** Applications that call Grouper WS switch to Tessera's **Grouper-WS-compatible read API** (§11.6) or to SCIM/LDAP. Grouper's WS access log tells you who still calls.
8. **Decommission** when no folder is mirrored and the Grouper WS access log has been quiet for 30 days. Export Grouper's audit and PIT tables to the customer's archive.

**Rollback** at any step before 6 is a mode switch. After 6, rollback is "switch the folder back to `mirror` and re-enable Grouper's provisioners", which works because Grouper's folder was frozen, not deleted, and reverse sync (if enabled) kept it current.

### 11.6 Grouper-WS-compatible read API

`/grouper-ws/servicesRest/v2_6_000/` (and the other v2.x version paths Grouper accepts) implements the read operations applications use most: `hasMember` (lite and batch), `getMembers`, `getGroups`, `findGroups`, `findStems`, `getMemberships`, `getGrouperPrivilegesLite`. Requests and responses follow Grouper's JSON shapes, including `WsRestResultProblem` errors, so a client changes only its base URL and credentials. Authentication is a Tessera machine client (Phase 0 PR11) mapped to the caller; there is no Grouper-style basic-auth user store. Writes are not implemented, which keeps the compatibility surface small. Grouper is Apache 2.0 licensed; implementing a compatible API is permitted, and no Grouper code is copied.

---

## 12. Parity matrix

Phase is the capability-map phase in `docs/knowledge/README.md`. "Better" lists where Tessera exceeds Grouper; "same" means equivalent by design.

| ID | Grouper capability | Tessera equivalent | Phase | Where Tessera is better |
|---|---|---|---|---|
| G-01 | Folders and naming | `grp_folders`, `:` paths, display paths (§5) | 2 | same |
| G-02 | Move, copy, rename with old names | `:move`, `:copy`, `grp_name_aliases` | 2 | moves show downstream impact before applying |
| G-03 | Name constraints | `naming/`, case-insensitive unique indexes | 2 | enforced in the schema, not hooks |
| G-04 | Integer ID indexes | `id_index` | 2 | same |
| G-05 | Deployment Guide object types | `etc:objectTypes` attribute, badges, lint (§10.9) | 2 | lint flags anti-patterns (basis used by policy, too many exceptions) |
| G-06 | Template wizard, custom templates | "New application" wizard, plan templates (§10.12) | 2 | templates are reviewed data, not GSH code |
| G-07 | Favorites and recents | per-user preferences | 2 | same |
| G-08 | Groups with enabled/disabled dates | `grp_groups` | 2 | same |
| G-09 | Roles and role hierarchy | `kind=role` + nesting | 2 | roles visible in the access graph with what they grant |
| G-10 | Local entities | NHI identities with `subtype=entity` and required owner | 2 | owners, credential inventory and lifecycle (README rule 6) |
| G-11 | Subject sources and resolution | identity warehouse, connectors, correlation | 2 | per-attribute authority and effective dating (D4·M1) |
| G-12 | Subject API diagnostics | "Resolve a subject" in Connections | 2 | shows match rule and confidence |
| G-13 | Member search and sort columns | `search_text`, `sort_key`, FTS5/pg_trgm | 2 | no per-source config needed |
| G-14 | USDU (unresolvable subjects) | unresolvable handling with grace and threshold (§10.6) | 2 | never silent; Inbox task |
| G-15 | Member change subject | identity link/merge/unmerge (guest design §5.4) | 2 | reversible, with history |
| G-16 | System subjects and admin groups | platform roles (`tenant_admin`, `auditor`, `viewer`), `everyone` holder | 0 | phishing-resistant admin roles, two-person admin changes (Phase 0) |
| G-17 | External subjects, invites, self-registration | guest accounts and claim (guest design) | 2 | sponsors, identity matching, NIST 800-63A-4 proofing, expiry |
| G-18 | Group summary screen | group page header and Usage tab | 2 | downstream access and usage |
| G-19 | Direct memberships | `grp_direct_memberships` with source and reason | 2 | every membership says why it exists |
| G-20 | Indirect/effective memberships, trace | materialized engine, trace with all paths (§6) | 2 | explains downstream grants too |
| G-21 | Composites (union, intersection, complement) | composite groups, n-ary union/intersection | 2 | fewer intermediate groups |
| G-22 | Convert to composite in place | `:convert-to-composite` | 2 | simulation shows who changes |
| G-23 | Enabled/disabled membership dates | dates + time wheel (§6.4) | 2 | ≤ 60 s lag; authz never counts expired rows |
| G-24 | Circular membership veto | closure-based cycle check | 2 | same, plus the offending path |
| G-25 | Custom lists | `grp_lists` | 2 | same |
| G-26 | Opt-in / opt-out | privileges + self-service in Access | 2 | audited, appears in My access |
| G-27 | Recent memberships (grace) | `recent_memberships` loader fed by PIT | 2 | exact, from tamper-evident history |
| G-28 | Membership require | built-in constraint rule (§10.3) | 2 | same |
| G-29 | One group only in a folder | built-in constraint rule | 2 | same |
| G-30 | Bulk add, import, export | batch API, CSV import/export, email export | 2 | preview before apply |
| G-31 | Membership queries, hasMember | `/members`, `/members/{identity}`, filters | 2 | as-of and between on every query |
| G-32 | SQL membership cache tables | `grp_effective` (internal); SQL provisioner (external) | 2 | always current, verified nightly |
| G-33 | ABAC scripted groups (JEXL) | Cedar policy groups (§8) | 2 | code review, PR membership diff, PDP agreement test |
| G-34 | Entity data fields, data providers | identity attributes from connectors, attribute groups (§8.4) | 2 | per-attribute authority and effective dating |
| G-35 | User lifecycle events | JML lifecycle events (D4) | 2 | SLAs and leaver kill-switch |
| G-36 | Group privileges (8) | same names (§7) | 2 | explanations of every effective privilege |
| G-37 | Folder privileges (5) | same names | 2 | same |
| G-38 | Attribute definition privileges (8) | same names | 2 | same |
| G-39 | Privilege inheritance | dynamic inheritance, `one`/`sub` | 2 | no stale copied privileges |
| G-40 | Default privileges | Admin → Groups settings, creator privileges | 2 | `everyone` grants need `tenant_admin` |
| G-41 | Privileges held by groups | holder groups through the engine | 2 | same |
| G-42 | Act-as | RFC 8693 token exchange | 3 | delegation is explicit and scoped |
| G-43 | Attribute definitions | `grp_attr_defs` (§10.9) | 2 | float-free values for audit hashing |
| G-44 | Attribute names and inheritance | `grp_attr_names`, implies closure | 2 | same |
| G-45 | Actions and action inheritance | `grp_attr_actions`, implies closure | 2 | same |
| G-46 | Assignments and values, on assignments | `grp_attr_assigns`, `grp_attr_values` | 2 | same |
| G-47 | Attributes in group edit screen | Attributes tab and inline fields | 2 | same |
| G-48 | Services | service folders in My access | 2 | linked to real downstream usage |
| G-49 | Permissions (role × resource × action) | permission graph + Cedar (§10.10) | 3 | evaluated with effective-permission context across clouds |
| G-50 | Resource and action inheritance | implies closures | 3 | same |
| G-51 | Allow/disallow heuristics | ordered heuristics, Cedar forbid | 3 | formal diff of permission changes (D3·M6) |
| G-52 | Permission limits | Cedar `when` over `context` | 3 | limits evaluated by the same PDP as all other policy |
| G-53 | Permission queries incl. PIT | permission API, PIT permission view | 3 | same |
| G-54 | SQL simple loader | `sql_simple` (§9.1) | 2 | read-only enforcement, two-person config |
| G-55 | SQL group-list loader | `sql_group_list` | 2 | same |
| G-56 | LDAP loaders | `ldap_*` | 2 | TLS-only |
| G-57 | Scheduling, clustering | job framework, per-tenant workers | 2 | multi-tenant isolation |
| G-58 | Incremental loaders, group-level incremental | `Changes()` cursors, per-group reload | 2 | same |
| G-59 | Loader failsafes | failsafes that **hold for approval** with downstream impact | 2 | shows who would lose what, and recent usage |
| G-60 | AND-groups, display sync, missing groups | `and_group_id`, `on_missing_group` | 2 | same |
| G-61 | Load from provisioner targets | `connector_groups` loader | 2 | any connector, including cloud |
| G-62 | CSV, SFTP, Google Sheet, GSH loaders | `csv`, `sftp_csv`; Sheets via a connector; no script loaders | 2 | no code execution (K6) |
| G-63 | Loader UI, diagnostics, export/import | Admin → Jobs, preview runs, plan export | 2 | preview is a full diff |
| G-64 | Org hierarchies via loader | `attribute` loader | 2 | same |
| G-65 | Sync to Grouper from SQL | Grouper connector (SQL mode) and plan import | 2 | reconciliation report |
| G-66 | Table sync, LDAP-to-SQL, SFTP-to-SQL | SQL provisioner, connectors | 3 | general data sync is out of scope beyond groups |
| G-67 | Provisioning framework (full, incremental, translation, failsafes, marks) | provisioning framework (§9.2) | 2 | **verify-by-reaggregation**; adopt mode |
| G-68 | Provisioning diagnostics | `:diagnose` | 2 | shows exact planned ops |
| G-69 | Provisioning sync-back | `grp_sync_*` and change tokens | 2 | same |
| G-70 | LDAP/AD provisioner | `ldap`, `ad` targets | 2 | ranged writes, verified |
| G-71 | Entra ID provisioner | `entra` | 2 | delta queries, verified |
| G-72 | Google provisioner | `google` | 2 | verified |
| G-73 | SCIM 2.0 provisioner | `scim2` with profiles | 2 | AWS Identity Center profile ties to effective AWS permissions |
| G-74 | SQL provisioner | `sql` | 2 | same |
| G-75 | Okta provisioner | `okta` | 2 | same |
| G-76 | Box, Duo, Zoom, Adobe, Dropbox, GitHub, Jamf, Datadog, C•CURE, Interfolio, TeamDynamix, Remedy, Freshservice, midPoint, TrueFoundry | connector SDK targets and ticketed fulfilment | 3 | ticketed targets still verified by re-read where possible |
| G-77 | Messaging and GSH-template provisioners | webhook/event-stream target; no code templates | 2 | signed events |
| G-78 | External systems config | Admin → Connections | 0 | sealed secrets, SSRF-guarded HTTP (Phase 0) |
| G-79 | Change log | `grp_events` outbox | 2 | gap-free per-tenant sequence, tamper-evident digests |
| G-80 | Change log consumers | cursors, internal consumers | 2 | same |
| G-81 | Messaging (SQS, RabbitMQ, ActiveMQ), inbound | webhooks (2); SQS/SNS, RabbitMQ, Kafka (GR-18); inbound = batch API | 3 | inbound requires an authorized client, not a queue |
| G-82 | ESB connector | webhooks with CloudEvents | 2 | standard envelope, signatures |
| G-83 | Rules engine | closed-vocabulary rules (§10.3) | 2 | privilege checked at save and at fire time |
| G-84 | Hooks | signed webhooks with optional veto | 3 | out of process |
| G-85 | Attestation | group-membership campaigns (§10.4) | 2 | **usage-aware**, frozen populations, sampled QA |
| G-86 | Auto disable / remove if not attested | overdue actions, verified downstream | 2 | removal verified in targets |
| G-87 | Deprovisioning | affiliation loss → Inbox tasks, veto, report (§10.5) | 2 | tied to JML SLAs and leaver kill-switch |
| G-88 | Reports | report catalogue, schedules, delivery (§10.7) | 2 | evidence-grade exports (D4·M22) |
| G-89 | Visualization | Groups lens in the access graph | 2 | shows downstream permissions; VIEW-filtered |
| G-90 | Daily email notifications | notification digest | 2 | same |
| G-91 | Forms, workflow, approvals | access-request engine (§10.8) | 2 | risk tiers, SoD preview, no self-approval |
| G-92 | Audit log | Phase 0 audit ledger | 0 | hash-chained, anchored, verifiable |
| G-93 | Point-in-time history | `grp_pit_*` + daily digests (§10.2) | 2 | **tamper-evident**, rebuildable from events |
| G-94 | Delete old records, cleanup | retention job, recorded pruning | 2 | pruning is itself audited |
| G-95 | Web UI | Directory → Groups (§10.13) | 2 | change preview, usage, trace, WCAG from day one |
| G-96 | REST web services | `/api/groups/*`, OpenAPI; Grouper-WS-compatible read API | 2 | idempotent batches, simulation endpoint |
| G-97 | WS authentication options | Phase 0 OAuth AS (DPoP, private_key_jwt), sessions | 0 | sender-constrained tokens |
| G-98 | SCIM 2.0 server | read-only `/scim/v2` over native groups | 2 | same |
| G-99 | GSH, export to GSH, GSH templates | CLI, declarative plans, plan templates, export to plan | 2 | no arbitrary code; plans show impact |
| G-100 | Grouper client | Go CLI, generated clients | 0 | DPoP device-flow login |
| G-101 | Daemon, scheduler, health, DB config | job framework, Admin → Jobs, sealed config | 2 | per-tenant isolation |
| G-102 | MCP server and OAuth for MCP clients | Phase 4 MCP authorization server and tools | 4 | delegation-aware tokens (D6·M2) |

**Counts by the Phase column.** 102 capabilities: **Phase 0: 5** (G-16, G-78, G-92, G-97, G-100, delivered by the Phase 0 platform work), **Phase 2: 86**, **Phase 3: 10** (G-42, G-49–G-53, G-66, G-76, G-81, G-84), **Phase 4: 1** (G-102). 5 + 86 + 10 + 1 = 102.

---

## 13. Implementation plan (ordered PRs)

**Preconditions.** The Go port (`go-backend`) is merged, and Phase 0 PR1 (tenancy, #5), PR3 (audit ledger, #7) and PR5 (auth core, #9) are merged. Every PR keeps `./run.sh test` (`go test -race ./...`) and `./run.sh build` green, passes `go vet`, `staticcheck` and `govulncheck`, and extends the tenant isolation meta-tests (`TestIsolation_*`) to its new tables. Paths are relative to `mvp/server/` unless they start with `frontend/` or `docs/`.

### GR-1: Groups store and folder/group CRUD (3 days) · #44
- **Files:** `internal/store/schema/0101_groups.sql` (folders, aliases, groups, composite factors, lists, direct memberships; engine tables created empty), `internal/store/model_groups.go`, `internal/store/repo_groups.go`, `internal/groups/naming/`, `internal/groups/model/` (create, rename, move, copy, soft delete), `internal/api/groups_folders.go` (folder and group CRUD only, guarded by `tenant_admin` until GR-4), audit events `groups.folder.*`, `groups.group.*`.
- **Tests:** `naming_test.go` (characters, case-insensitive uniqueness, aliases), `model_test.go` (move/copy/rename keep aliases; root folder per tenant), `TestIsolation_GroupsTables`, API tests for CRUD and 409s.
- **Depends on:** #5, #7, #9.

### GR-2: Membership engine (5 days) · #45
- **Files:** `internal/groups/engine/` (`closure.go`, `levels.go`, `propagate.go`, `composite.go`, `budget.go`, `timewheel.go`, `verify.go`), `internal/store/repo_group_engine.go` (set-based upserts with `RETURNING`), direct-membership service, `:convert-to-composite`, cycle veto, engine queue worker registered with the job framework.
- **Tests:** `TestEngine_MatchesOracle` (fuzz: random DAGs, composites of composites, dates, disabled groups), `TestEngine_CycleVeto`, `TestEngine_SyncBudgetFallsBackToQueue`, `TestTimewheel_DisableWithin60s`, `TestIsMember_IgnoresExpiredRowsWhenWheelLags`, `TestVerify_DetectsAndRepairsInjectedCorruption`; a benchmark at 10% of the reference tenant.
- **Depends on:** GR-1.

### GR-3: Group events and point-in-time history (3 days) · #46
- **Files:** `internal/store/schema/0103_group_events.sql`, `internal/groups/events/` (outbox, cursors, CloudEvents encoding), `internal/groups/pit/` (writer, as-of/between queries, daily Merkle digest into the audit ledger, `verify` and `rebuild`), retention job.
- **Tests:** `TestPIT_AsOfMatchesReplay`, `TestPIT_DigestDetectsTamper`, `TestEvents_GapFreeSeqUnderConcurrency`, `TestPIT_RebuildEqualsLive`.
- **Depends on:** GR-2, #7.

### GR-4: Privilege model (3 days) · #47
- **Files:** `internal/store/schema/0102_group_privs.sql`, `internal/groups/privs/` (implication table, dynamic inheritance, check, explain), `platform_users.identity_id` link, enforcement on every group route (replacing the GR-1 `tenant_admin` guard), creator and default privileges, `everyone` policy.
- **Tests:** table-driven implication tests for all 22 privileges, `TestPrivs_InheritanceOneVsSub`, `TestPrivs_ExplainListsAllPaths`, `TestPrivs_EveryoneNeedsTenantAdmin`, `TestPrivs_ViewFiltersBrowseAndSearch`, authorization tests for every route (403 without the privilege).
- **Depends on:** GR-2, #9.

### GR-5: Groups REST API (WS parity) (3 days) · #48
- **Files:** `internal/groups/api/` (members with filters, trace, batch add/remove with idempotency keys, groups of an identity, privileges, simulation endpoint, as-of/between parameters), OpenAPI generation, read-only SCIM server `/scim/v2/Groups|Users`, parity fixtures for new routes.
- **Tests:** API contract tests per route, `TestBatch_AtomicAndIdempotent`, `TestSimulate_NoSideEffects`, SCIM read conformance tests (filter, paging), isolation tests at the API layer.
- **Depends on:** GR-3, GR-4.

### GR-6: CLI and declarative plans (3 days) · #49
- **Files:** `cmd/tessera-cli` `groups` subcommands, `internal/groups/plan/` (plan parse, diff, apply as batches, export folder to plan, server-side plan templates with typed inputs), the `application` template from the Deployment Guide.
- **Tests:** golden tests for `plan` output, `TestPlan_ApplyIsIdempotent`, `TestTemplate_ApplicationMatchesDeploymentGuide`, `TestExportThenApply_RoundTrip`.
- **Depends on:** GR-5, #14.

### GR-7: Attribute framework, object types and services (3 days) · #50
- **Files:** `internal/store/schema/0104_group_attrs.sql`, `internal/groups/attrs/` (definitions, names, actions, implies closures, assignments on all owner types, values, attribute privileges), object types and lint rules, service folders.
- **Tests:** assignment-on-assignment, implies closure maintenance, `attr_*` privilege checks, `TestValues_NoFloats`, lint rule tests.
- **Depends on:** GR-4.

### GR-8: Directory → Groups UI (5 days) · #51
- **Files:** `frontend/src/features/directory/groups/` (folder browser, group page with Members/Definition/Privileges/Usage/History/Attributes tabs, folder page, trace drawer, change preview dialog, New application wizard), `frontend/src/api.ts` functions, Managed/Connected toggle on the Groups list.
- **Tests:** component tests for the change preview and trace; Playwright smoke: create folder from template, add members with dates, see effective change, view as-of history; accessibility checks (labels, focus, keyboard).
- **Depends on:** GR-5, GR-7 (and the `ui-redesign` branch merged).

### GR-9: Policy groups as code (5 days) · #52
- **Files:** `internal/groups/policygroups/` (fragment parser and validator on the Cedar grammar, compiler to composite trees with hash-consing, attribute indexer for `sys:attr:*` groups, repository sync by webhook or poll, PR diff via simulation), `cmd/tessera-cli groups policy validate|diff|apply`, example repo layout in `docs/`, GitHub Action snippet for the PR comment.
- **Tests:** `TestFragment_RejectsUnsupported` (context, resource attrs, arithmetic), `TestCompile_EquivalentToNaive` (fuzz), `TestHashConsing_SharesSubtrees`, `TestPolicyGroups_PDPAgreesWithEngine` (using the Cedar Go evaluator), `TestSync_RecordsCommitOnEveryChange`.
- **Depends on:** GR-2, GR-7.

### GR-10: Loaders as connectors (5 days) · #53
- **Files:** `internal/store/schema/0105_group_loaders.sql`, `internal/groups/loaders/` (`GroupSource`, SQL with read-only enforcement, LDAP, CSV/SFTP, `connector_groups`, `attribute`, `recent_memberships`; schedules; incremental cursors; failsafes with held runs and downstream impact; unresolved subjects), Inbox task type `loader_held`, Admin → Jobs entries, two-person approval for SQL loaders via the Phase 0 admin-change flow.
- **Tests:** in-process fakes (SQLite source DB, an in-process LDAP test server, temp CSV/SFTP), `TestFailsafe_HoldsAndShowsImpact`, `TestSQLLoader_RejectsWrites`, `TestUnresolved_NeverDropped`, `TestRecentMemberships_FromPIT`.
- **Depends on:** GR-5, #16.

### GR-11: Provisioning framework with LDAP/AD, SCIM 2.0, SQL and webhook targets (5 days) · #54
- **Files:** `internal/store/schema/0106_group_prov.sql`, `internal/groups/provisioning/` (desired-state computation with inherited marks, translation templates, full and incremental sync, verify-by-reaggregation, failsafes, adopt and dry-run modes, diagnostics, sync-back cache), targets `ldap`, `ad`, `scim2` (generic plus AWS Identity Center and GitHub EMU profiles), `sql`, `webhook`.
- **Tests:** fakes for LDAP (including AD ranged attributes), a SCIM 2.0 test server, SQLite target; `TestProvision_VerifiedOnlyAfterReread`, `TestProvision_AdoptModeChangesNothing`, `TestProvision_FailsafeMaxDeletes`, `TestProvision_IncrementalEqualsFull`.
- **Depends on:** GR-3.

### GR-12: Entra ID, Google Workspace and Okta provisioners (4 days, needs-human) · #55
- **Files:** `internal/groups/provisioning/entra/`, `google/`, `okta/`; Connection types and credential flows; recorded-response fixtures.
- **Tests:** unit tests on recorded responses; an opt-in live test suite (`-tags live`) against sandbox tenants that a human provides; verify-by-reaggregation on each.
- **Depends on:** GR-11.

### GR-13: Rules and membership constraints (3 days) · #56
- **Files:** `internal/store/schema/0107_group_gov.sql` (rules), `internal/groups/rules/` (triggers, conditions, actions; privilege checks at save and fire time; email-rule tenant gate), built-in constraints (membership require, one group only, no self-add, no deletion of provisioned groups), webhook hooks with optional veto.
- **Tests:** `TestRules_PrivilegeCheckedAtFireTime`, `TestMembershipRequire_VetoAndRemove`, `TestOneGroupOnly`, `TestEmailRulesOffByDefault`, `TestVetoHookFailClosed`.
- **Depends on:** GR-3, GR-4.

### GR-14: Attestation, deprovisioning and reports (4 days) · #57
- **Files:** attestation settings and campaign generation through `internal/reviews` with usage context, overdue actions; `internal/groups/deprov/` (affiliations, Inbox tasks, veto rule, report); `internal/groups/reports/` (catalogue, schedules, CSV/JSON delivery); Groups lens in the access graph.
- **Tests:** `TestAttestation_FrozenPopulation`, `TestAttestation_OverdueRemovesAndVerifies`, `TestDeprov_AffiliationLossCreatesTasks`, report golden files, `TestVisualization_RespectsView`.
- **Depends on:** GR-3, GR-4, GR-13.

### GR-15: Grouper connector: import in mirror mode (5 days, needs-human) · #58
- **Files:** `internal/groups/grouperconn/` (WS client for Grouper REST v2 JSON, SQL-mode reader for Grouper views, import of folders, groups, composites, direct memberships, privileges, attributes, loader and provisioning config as disabled objects; subject mapping through correlation with a review queue; import report and reconciliation counts), `cmd/tessera-cli groups import grouper`.
- **Tests:** fixtures captured from a Grouper 7.6 container (`i2incommon/grouper:7.6.0` quickstart) for WS and SQL modes; `TestImport_CountsReconcile`, `TestImport_UnresolvedHeldNotDropped`, `TestImport_PrivilegeInheritanceBecomesDynamic`. A human runs the import against a real university Grouper (read-only credentials) and signs off the report.
- **Depends on:** GR-5, GR-7, GR-10.

### GR-16: Coexistence: shadow-compare, cut-over and the Grouper-WS-compatible read API (5 days, needs-human) · #59
- **Files:** folder modes (`mirror`/`shadow`/`native`) with write guards; change feed (SQL change log reader, ESB HTTP webhook receiver); comparison job and readiness score; per-target provisioning cut-over checklist in the UI; optional reverse sync over Grouper WS; `/grouper-ws/servicesRest/v2_x/*` read endpoints.
- **Tests:** `TestFolderMode_RefusesWritesWhenMirrored`, `TestShadowCompare_ReportsDifferencesWithReasons`, compatibility tests replaying captured Grouper WS requests/responses against the compatible API. A human runs a pilot cut-over of one folder.
- **Depends on:** GR-15, GR-11.

### GR-17: Scale gate (3 days) · #60
- **Files:** `internal/groups/benchgen/` (synthetic university generator), `cmd/tessera-bench groups`, nightly CI job on Postgres, dashboard of the §6.7 targets.
- **Tests:** the §6.7 targets as assertions on the reference tenant (nightly, not per PR).
- **Depends on:** GR-2, GR-5, GR-11, #18.

### GR-18: Event streaming (3 days) · #61
- **Files:** `internal/groups/events/sinks/` (AWS SQS/SNS, RabbitMQ, Kafka), delivery guarantees (at-least-once, ordered per group), dead-letter handling, Admin UI for sinks.
- **Tests:** in-process broker fakes; `TestSink_OrderedPerGroup`, `TestSink_DeadLetterAfterRetries`.
- **Depends on:** GR-3.

### GR-19: Permissions and limits (Phase 3) (4 days) · #62
- **Files:** permission assignments on roles and on (role, identity), resource and action inheritance, allow/disallow heuristics, limits compiled to Cedar `context` conditions, permission API and PIT permission view, Grouper import of permissions.
- **Tests:** heuristics table tests mirrored from Grouper's documented examples, `TestLimits_EvaluatedByPDP`, import round-trip.
- **Depends on:** GR-7, GR-9, GR-15.

### GR-20: Long-tail provisioners via the connector SDK (Phase 3) (ongoing, needs-human) · #63
- **Files:** Box, Duo, Zoom, Adobe, Dropbox, GitHub org teams, Jamf, Datadog, C•CURE, Interfolio, TeamDynamix, Remedy, Freshservice, midPoint targets on the connector SDK (D4·S10), with ticketed fulfilment where there is no API.
- **Tests:** recorded-response tests per target; live suites opt-in.
- **Depends on:** GR-11, the connector SDK (capability map C).

---

## 14. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Engine bug produces wrong effective memberships | Wrong access everywhere downstream | Oracle fuzzing (GR-2), nightly full verification with auto-repair and alerts, shadow-compare against Grouper during migration, provisioning failsafes. |
| Large fan-out changes saturate the database | Slow UI, delayed provisioning | Sync budget with queued chunks, per-tenant engine lock, read replicas for verification, the GR-17 scale gate before the first large customer. |
| SQLite limits for big tenants | Performance | SQLite is for dev and small tenants; Postgres is required above ~15k groups (documented, enforced by a tenant-size check). |
| Semantics differ subtly from Grouper (privilege implication, disabled factors) | Migration surprises | Comparison of effective memberships **and** effective privileges in shadow mode; differences block cut-over until accepted with a reason. |
| Universities depend on JEXL scripts and custom hooks that do not map | Migration blocked for some folders | Import report lists them; Cedar fragment covers the documented ABAC patterns; webhooks for the rest; keep those folders in mirror mode longer. |
| Customers expect GSH for ad-hoc bulk changes | Adoption friction | Plans and the CLI cover bulk changes with previews; export to plan; templates for repeated tasks. |
| Provisioning to targets that Grouper manages leads to two writers | Flapping memberships in targets | Per-target cut-over with dry run, explicit Grouper-side disable step shown in the UI, adopt mode. |
| PIT storage growth | Cost | Interval tables (not snapshots), retention setting, partitioning by month in Postgres. |
| Policy-as-code is unfamiliar to Grouper admins | Slow uptake | UI policy builder writes the same Cedar; "export to repository" is optional. |
| Scope: 102 capabilities across 20 PRs | Schedule | Phase 2 covers 86 rows; the matrix shows which rows ship in which PR; Phase 3 items (permissions, long tail) are not blockers for university pilots that use groups for access policy and provisioning. |

---

## 15. Open questions

1. **Mount point default.** Import Grouper at the root (names unchanged) or under `grouper:`? The design defaults to the root because policy files and downstream names reference full names. Confirm with the first university customer.
2. **Grouper-WS-compatible API scope.** Which WS read operations do customers' applications actually call? Collect Grouper WS access logs from the pilot before GR-16 to confirm the list in §11.6.
3. **Reverse sync.** Is writing back into frozen Grouper folders needed, or is moving readers to SCIM/LDAP/the compatible API enough? Reverse sync adds a write path into the customer's Grouper.
4. **Effective rows for groups-as-members.** Grouper exposes effective memberships of groups in groups. Tessera answers that from `grp_closure`. Is any consumer relying on Grouper's group-member effective rows in WS responses?
5. **Privilege implication edge cases** (OPTIN/OPTOUT → VIEW, UPDATE → OPTIN/OPTOUT?) need confirmation from Grouper's `PrivilegeHelper` during GR-15.
6. **Cedar evaluator in Go.** Use `cedar-policy/cedar-go` for the fragment parser and the PDP cross-check, or wait for the Phase 1 decision on the Cedar runtime? GR-9 assumes `cedar-go`.
7. **Retention default.** 7 years for group events and PIT, or follow the audit ledger's retention (Phase 0 OQ8)?
8. **Who owns the `ref:` folder in a university** that also has HR- and registrar-owned basis data? This is a policy question for customers, but the default privileges of the `application` template depend on it.
9. **Course rosters.** Should SIS course roster groups (tens of thousands of small groups each term) be native groups, or a separate lightweight "roster" type with term-based archival? Native groups are assumed; GR-17 should include a term rollover in the benchmark.

---

## 16. Knowledge-base corrections

- `docs/knowledge/04-identity-governance-and-compliance.md` §5 does not mention Internet2 Grouper or COmanage, which are the incumbent group-management and registry tools in higher education. Add a short entry: Grouper v7.6.0 (2026-09-28), its group/folder/privilege model and provisioning framework, and that Tessera targets full parity.
- The capability map has no row for native group management, policy groups or the Grouper migration path. Added in this branch (README, section C).

---

## 17. References

- Internet2 Grouper source, `GROUPER_6_BRANCH`: https://github.com/Internet2/grouper (packages `grouper/src/grouper/edu/internet2/middleware/grouper/{privs,rules,pit,changeLog,abac,dataField,sqlCache,userLifecycle,attr,permissions}` and `.../grouper/app/*`).
- Grouper wiki mirror in the repository: `grouper-misc/grouper-docs/wikiMirror/spaces/Grouper/` (pages for the Deployment Guide, administration guides, provisioning framework, web services and release notes). Live wiki: https://grouper.atlassian.net/wiki/spaces/Grouper
- Grouper v7 release notes (v7.6.0, 2026-09-28) and v7, v6 and v4 new features: wiki pages "v7 Release Notes", "v7 new features", "v6 new features", "v4 new features".
- Grouper Deployment Guide (TIER/InCommon): wiki section "Grouper Deployment Guide", in particular "Folder and Group Design" and "Access Control Models".
- Grouper security advisories referenced: GRP-6311, GRP-6566, GRP-7325, GRP-7359, GRP-7381, GRP-7387 (wiki "Grouper Security Issues" and v7 release notes).
- RFC 7643 and RFC 7644 (SCIM 2.0); RFC 4511 (LDAP); RFC 2696 (LDAP paged results); RFC 8693 (token exchange); RFC 8785 (JCS); CloudEvents 1.0 (CNCF).
- Cedar policy language: https://docs.cedarpolicy.com
- Tessera: `docs/knowledge/README.md`, `docs/knowledge/04-identity-governance-and-compliance.md`, `docs/design/phase-0-platform-security.md` (v2 Go on branch `go-replan`).
