---
page_title: "tessera_mitigating_control Resource - tessera"
subcategory: ""
description: |-
  A mitigating control of the separation-of-duties control library. Applied only after a person approves a proposal.
---

# tessera_mitigating_control (Resource)

A mitigating control: an entry of the separation-of-duties control library (a review, a limit, a report) that a person's SoD mitigation
cites. It needs the `config.propose` scope (see `tessera_alert_rule`) and is applied only after a person approves the proposal with a step-up sign-in; apply waits and fails with the change's URL on a refusal or a timeout. Refresh reads it back, an update is refused if it moved on since it was read, and it can be imported by its id. Destroy only removes the resource from state, with a warning: the server has no proposal that retires it.

## Example Usage

```terraform
data "tessera_identities" "owner" {
  query = "ingrid"
}

resource "tessera_mitigating_control" "monthly_review" {
  name                 = "Monthly access review by the CFO"
  description          = "The CFO reviews every payment approver each month."
  owner_identity_id    = data.tessera_identities.owner.identities[0].id
  type                 = "detective"
  frequency            = "monthly"
  evidence_requirement = "The signed review report."
}
```

## Schema

### Required

- `frequency` (String) `continuous`, `daily`, `weekly`, `monthly`, `quarterly` or `annually`.
- `name` (String) A unique name.
- `owner_identity_id` (Number) The identity accountable for the control (see `tessera_identities`).
- `type` (String) `preventive`, `detective` or `corrective`.

### Optional

- `description` (String) Default empty.
- `evidence_requirement` (String) What the person who runs the control must keep as evidence. Default empty.

### Read-Only

- `change_id` (String) The id of the change request that applied the last create or update.
- `change_url` (String) Where a person reviews that change request.
- `id` (String) The control id.
- `version` (Number) The control's version on the server.

## Import

```sh
terraform import tessera_mitigating_control.monthly_review <control id>
```
