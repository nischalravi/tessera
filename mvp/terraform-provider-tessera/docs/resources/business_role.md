---
page_title: "tessera_business_role Resource - tessera"
subcategory: ""
description: |-
  A business role: a named bundle of entitlement groups that people request as one. Applied only after a person approves a proposal.
---

# tessera_business_role (Resource)

A business role: a named bundle of entitlement groups that people request as one. It needs the `config.propose` scope (see
`tessera_alert_rule`) and is applied only after a person approves the proposal with a step-up sign-in; apply waits and
fails with the change's URL on a refusal or a timeout. Refresh reads the role back (with the viewer role); an update is
proposed against the version last read and is refused if the role moved on. Roles are retired in the admin center, not by
Terraform: destroy only removes the resource from state, with a warning.

## Example Usage

```terraform
data "tessera_entitlements" "aws" {
  system = "aws"
}

# A role that bundles two entitlements. The key never changes; the apply waits for a person to approve the proposal.
resource "tessera_business_role" "engineer" {
  key         = "engineer"
  name        = "Engineer"
  description = "Day-to-day engineering access."
  risk        = "medium"
  requestable = true
  entitlement_group_ids = [
    data.tessera_entitlements.aws.entitlements[0].id,
    data.tessera_entitlements.aws.entitlements[1].id,
  ]
  note = "Managed with Terraform."
}
```

## Schema

### Required

- `entitlement_group_ids` (Set of Number) The entitlement groups the role grants (ids from `tessera_entitlements`); at least one.
- `key` (String) The role's stable key (letters, digits, `.`, `_`, `:` and `-`). It never changes: a new key is a new role.
- `name` (String) 1 to 200 characters.
- `risk` (String) `low`, `medium` or `high`.

### Optional

- `description` (String) Up to 1000 characters. Default empty.
- `note` (String) Why the change was made; kept in the role's version history. Not read back.
- `owner_identity_id` (Number) The active person who owns the role. Not read back.
- `requestable` (Boolean) Whether people can request the role. Default false.

### Read-Only

- `change_id` (String) The id of the change request that applied the last create or update.
- `change_url` (String) Where a person reviews that change request.
- `id` (String) The role id.
- `version` (Number) The role's version on the server.
