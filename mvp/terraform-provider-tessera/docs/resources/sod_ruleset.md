---
page_title: "tessera_sod_ruleset Resource - tessera"
subcategory: ""
description: |-
  A separation-of-duties ruleset, the named set of SoD risks that are checked together. Applied only after a person approves a proposal.
---

# tessera_sod_ruleset (Resource)

A separation-of-duties ruleset: the named set of SoD risks that are checked together. It needs the `config.propose` scope
(see `tessera_alert_rule`) and is applied only after a person approves the proposal with a step-up sign-in; apply waits
and fails with the change's URL on a refusal or a timeout. Refresh reads the ruleset back; an update is refused if the
ruleset moved on since it was read. Rulesets are retired in the admin center, not by Terraform: destroy only removes the
resource from state, with a warning. Risks and functions inside a ruleset are not managed yet.

## Example Usage

```terraform
resource "tessera_sod_ruleset" "payments" {
  key         = "payments"
  name        = "Payments separation of duties"
  description = "Nobody both creates and approves a payment."
  enabled     = true
}
```

## Schema

### Required

- `key` (String) The ruleset's stable key. A new key is a new ruleset.
- `name` (String) 1 to 200 characters.

### Optional

- `description` (String) Default empty.
- `enabled` (Boolean) A disabled ruleset is not checked. Default true.
- `note` (String) Why the change was made. Not read back.

### Read-Only

- `change_id` (String) The id of the change request that applied the last create or update.
- `change_url` (String) Where a person reviews that change request.
- `id` (String) The ruleset id.
- `version` (Number) The ruleset's version on the server.
