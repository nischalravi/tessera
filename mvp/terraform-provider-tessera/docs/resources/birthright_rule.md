---
page_title: "tessera_birthright_rule Resource - tessera"
subcategory: ""
description: |-
  A birthright rule: the attribute condition a business role's birthright rule names. Applied only after a person approves a proposal.
---

# tessera_birthright_rule (Resource)

A birthright rule: the attribute condition (for example `identity.department = Finance`) that a business role's birthright rule names in its
`policy` field, so everyone who matches holds the role. It is Tessera's attribute policy (`/api/abac/policies`). It needs the `config.propose` scope (see `tessera_alert_rule`) and is applied only after a person approves the proposal with a step-up sign-in; apply waits and fails with the change's URL on a refusal or a timeout. Refresh reads it back, an update is refused if it moved on since it was read, and it can be imported by its id. Destroy only removes the resource from state, with a warning: the server has no proposal that retires it.

## Example Usage

```terraform
resource "tessera_birthright_rule" "finance_staff" {
  name        = "Finance staff"
  description = "Everyone in the Finance department."
  condition_json = jsonencode({
    attr  = "identity.department"
    op    = "eq"
    value = "Finance"
  })
}
```

## Schema

### Required

- `condition_json` (String) The condition as a JSON object; `all`, `any` and `not` combine conditions. The server validates it.
- `name` (String) A unique name, 1 to 120 characters.

### Optional

- `description` (String) Default empty.
- `note` (String) Why the change was made. Not read back.

### Read-Only

- `change_id` (String) The id of the change request that applied the last create or update.
- `change_url` (String) Where a person reviews that change request.
- `id` (String) The policy id, which a business role's birthright rule names.
- `version` (Number) The policy's version on the server.

## Import

```sh
terraform import tessera_birthright_rule.finance_staff <policy id>
```
