---
page_title: "tessera_catalog_item Resource - tessera"
subcategory: ""
description: |-
  The access-request catalog entry of one entitlement group. Applied only after a person approves a proposal.
---

# tessera_catalog_item (Resource)

The access-request catalog entry of one entitlement group (an id from `tessera_entitlements`): whether people can request
it, its risk, who may, for how long and who approves. It needs the `config.propose` scope (see `tessera_alert_rule`) and
is applied only after a person approves the proposal with a step-up sign-in; apply waits and fails with the change's URL
on a refusal or a timeout. The server offers no read for a catalog item to a machine client, so refresh cannot see changes
made elsewhere. Destroy only removes the resource from state, with a warning.

## Example Usage

```terraform
data "tessera_entitlements" "aws" {
  system = "aws"
}

# Make the first AWS entitlement requestable for up to a day, approved by its owner.
resource "tessera_catalog_item" "aws_first" {
  group_id        = data.tessera_entitlements.aws.entitlements[0].id
  requestable     = true
  risk            = "medium"
  description     = "Read-only access to the AWS sandbox."
  default_hours   = 8
  max_hours       = 24
  approval_stages = ["owner"]
}
```

## Schema

### Required

- `group_id` (Number) The entitlement group's id. Changing it replaces the resource.
- `risk` (String) `low`, `medium` or `high`.

### Optional

- `approval_stages` (List of String) Approval stages in order: `manager`, `owner`, `decider`. Unset: unchanged.
- `default_hours` (Number) Default duration of a grant, in hours (a privileged item that is requestable needs one).
- `description` (String) Up to 1000 characters shown to requesters. Default empty.
- `eligible_departments` (Set of String) Departments that may request it. Unset: any.
- `eligible_types` (Set of String) Identity types that may request it: `human`, `service`, `ai_agent`. Unset: any.
- `escalate_after_hours` (Number) Hours before a pending approval escalates. Unset: unchanged.
- `max_hours` (Number) Longest grant, in hours.
- `owner_identity_id` (Number) The active person who owns the entitlement (an id from `tessera_identities`).
- `requestable` (Boolean) Whether people can request the entitlement. Default false.

### Read-Only

- `change_id` (String) The id of the change request that applied the last create or update.
- `change_url` (String) Where a person reviews that change request.
- `id` (String) The group id, as text.
