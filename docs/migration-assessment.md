# Offline migration assessment (phase 1 of #112)

`tessera migration assess` produces a report from a local export. It does not
open the Tessera database, connect to a vendor, grant access, activate a policy,
or create a review. The explicit tenant label namespaces source references; it
does not authenticate a tenant or correlate source objects with live identities.
Keep reports private: they contain identity and access metadata. `--out` is
required; reports are created with mode 0600 and published atomically. Existing
outputs are refused unless `--force` is supplied. Input files and their symlink
or hard-link aliases cannot be replaced, even with `--force`.

From `mvp/server`:

```sh
go run ./cmd/tessera migration assess --tenant lab --product saviynt \
  --instance synthetic --format normalized-json \
  --file internal/migration/testdata/normalized.json --out assessment.json
go run ./cmd/tessera migration assess --tenant lab --product sailpoint-iiq \
  --instance synthetic --format iiq-xml \
  --file internal/migration/testdata/iiq.xml --out iiq-assessment.json
```

The same interchange format accepts `sailpoint-isc`, `sailpoint-iiq`, or `saviynt`.
**Normalized JSON is a Tessera interchange contract, not any vendor's native
API response or export format.** All current fixtures are synthetic. Native
compatibility is unverified until sanitized real samples and version-specific
adapters are tested. Input errors fail the command without a partial report;
semantic blockers produce a report with `blocking: true` diagnostics. A zero
exit code means parsing succeeded, not that migration is safe or complete.

## Interchange schema v1

Use the [complete synthetic example](../mvp/server/internal/migration/testdata/normalized.json).
Unknown fields, duplicate JSON keys, duplicate IDs within an object type,
missing IDs, trailing documents and unsupported schema versions are rejected.
ID references are exact strings within the input pack, never name/email matching.
Absent references are blockers; source IDs remain source IDs, not Tessera IDs.
Proposals include escaped tenant/product/instance/type/ID references to avoid
namespace collisions. The source digest is over the original input bytes.

| Field | Contract |
| --- | --- |
| `schema_version` | Must be 1 |
| `product_version` | Source version supplied by operator; not verified |
| `captured_at` | RFC3339 capture time; absent/invalid time is a blocker |
| `complete` | Operator's source completeness assertion; false/absent is a blocker, true is not independently proven |
| `identities` | `id`, `name` |
| `accounts` | `id`, `identity_id`, `application`, `native_identity`, `entitlement_ids` |
| `entitlements` | `id`, `application`, `attribute`, `value`, optional `owner_id` |
| `roles` | `id`, `name`, optional `owner_id`, `entitlement_ids` |
| `sod` | `id`, `name`, nonempty `actions_a`, `actions_b`; exact permission action names, not groups |
| `certifications` | `id`, `identity_id`, `entitlement_id`, `decision` (`approve`/`revoke`), RFC3339 `decided_at`; source history only |
| `unsupported` | `object_id`, `kind`, `content`; content replaced by a digest and blocking diagnostic in output |

Do not put credentials or secret values into the mapped fields. The fixed schema
rejects extra fields such as passwords; arbitrary strings in allowed metadata
fields cannot be reliably classified as secrets. Unsupported logic content is
never echoed. Original files remain under the operator's control.

Unsupported entries must carry the source-specific kind, for example
`isc.transform`, `isc.approval_scheme`, `isc.correlation_config`,
`saviynt.analytics`, `saviynt.sql_rule`, or `saviynt.custom_query_entitlement`.
All yield `unsupported_logic` plus their kind, object reference and digest.
The adapter that builds the interchange pack must declare unsupported semantics;
this phase cannot detect content omitted by an external export transformation.

Role proposals are draft business-role data, pending validation against
`internal/roles` after #188 lands. SoD proposals use the existing policy engine's
`separation_of_duties` conflict shape and have `enabled: false`. The engine-shape
test demonstrates the action conflict when deliberately enabled in an isolated
test graph. No proposal is automatically applied; exact source action names
still need explicit mapping to target permission actions before activation.

## IIQ XML subset and safety

Supports a single object or a `sailpoint` wrapper. Maps:

- Identity `id`/`name` and nested `Links/Link` account references.
- Link `id`/`application`/`nativeIdentity`. Entitlement membership is not mapped.
- ManagedAttribute `id`/`application`/`attribute`/`value` and an exact
  `Owner/Reference` with `class="sailpoint.object.Identity"` and source `id`.
- Bundle `id`/`name` and the same owner reference, as a draft business role.
  Profiles, selectors, inheritance and membership criteria remain blockers.

All other elements/attributes/text are digest-only blocking diagnostics. Rules,
Source/Script, workflows, forms, policy violations and certification models are
not translated. Application reference elements and other native variations are
also reported as unsupported; no broad vendor coverage is claimed. Clean exports
without IDs get provisional source-local IDs and blockers. XML capture time and
completeness are unknown, so native XML reports always remain incomplete here.

Bounds: 8 MiB input, 20,000 records, nesting depth 32, 200,000 tokens, 8 KiB per
string/text/attribute value or XML name, and 128 attributes per XML element.
XML is token-streamed, retaining one bounded object
at a time. Entity declarations/internal DTD subsets are refused; a bare external
IIQ DTD declaration is inert and never fetched. Namespaced XML is unsupported.
Errors do not echo input content. Limits apply before proposals are produced.

## Follow-up gates

#112 stays open. This phase deliberately has no database staging or upload API.
Existing `stg_*` tables reference readiness runs; future migration persistence
needs migration-owned run provenance and tenant-guarded staging, with same-
transaction CLI audit and no-live-writes tests. Public routes wait for platform
RBAC and step-up on dev: `migration.read`, and `migration.manage` with fresh
phishing-resistant sign-in. Native API collection needs vendor sandboxes,
safehttp and recorded sanitized samples. Shadow comparison must reuse
reconcile/graph with explicit mappings and completeness/staleness checks; daily
jobs wait for the job-run framework. `comparison_status` is `not_performed` in
every report from this phase, including complete interchange packs.
