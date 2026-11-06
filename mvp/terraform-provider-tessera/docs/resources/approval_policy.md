---
page_title: "tessera_approval_policy Resource - tessera"
subcategory: ""
description: |-
  An approval policy: a workflow that routes access requests, and where it applies. Applied only after a person approves a proposal.
---

# tessera_approval_policy (Resource)

An approval policy: a versioned workflow (approval, questionnaire, notify, wait and condition steps) that routes access requests, and the catalog
items and request types it applies to (`/api/workflows`). It needs the `config.propose` scope (see `tessera_alert_rule`) and is applied only after a person approves the proposal with a step-up sign-in; apply waits and fails with the change's URL on a refusal or a timeout. Refresh reads it back, an update is refused if it moved on since it was read, and it can be imported by its id. Destroy only removes the resource from state, with a warning: the server has no proposal that retires it.

## Example Usage

```terraform
resource "tessera_approval_policy" "manager_then_owner" {
  name  = "Manager, then resource owner"
  scope = "access"
  steps_json = jsonencode([
    { id = "m", type = "approval", approver = "manager" },
    { id = "d", type = "approval", approver = "decider" },
  ])

  # leave targets out to keep the assignments as they are
  targets = [
    { kind = "request_type", target_id = "access" },
  ]
}
```

## Schema

### Required

- `name` (String) A unique name, 1 to 80 characters.
- `scope` (String) `access` or `service_account`. Changing it replaces the resource.
- `steps_json` (String) The steps as a JSON array. The server validates them (every path ends, groups and questionnaires exist) before anyone is asked.

### Optional

- `description` (String) Default empty.
- `targets` (Attributes Set) Where the policy applies. Leave it out to keep the assignments as they are; set it to `[]` to route nothing. (see [below for nested schema](#nestedatt--targets))

### Read-Only

- `change_id` (String) The id of the change request that applied the last create or update.
- `change_url` (String) Where a person reviews that change request.
- `id` (String) The workflow id.
- `version` (Number) The policy's version on the server.

<a id="nestedatt--targets"></a>
### Nested Schema for `targets`

Required:

- `kind` (String) `catalog_item` or `request_type`.
- `target_id` (String) The catalog item id, or the request type (`access`, `service_account_create`, ...).

## Import

```sh
terraform import tessera_approval_policy.manager_then_owner <workflow id>
```
