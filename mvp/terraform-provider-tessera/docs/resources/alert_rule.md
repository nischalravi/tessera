---
page_title: "tessera_alert_rule Resource - tessera"
subcategory: ""
description: |-
  The settings of a built-in alert rule (whether it fires, its severity, threshold and window). Applied only after a person approves a proposal.
---

# tessera_alert_rule (Resource)

The settings of a built-in alert rule (whether it fires, its severity, threshold and window). It needs the
`config.propose` scope, which an admin grants with a change request that a second admin approves. The resource is applied
only after a person approves the proposal with a step-up sign-in; until then apply waits (provider settings `wait_timeout`
and `poll_interval`) and fails with the change's URL on a refusal or a timeout. Alert rules are built in, so destroy leaves
the settings as they are (it only warns).

Refresh reads the rule when the client also holds the audit scope and the auditor role; otherwise the state is what was
last applied.

## Example Usage

```terraform
# Raise an alert after 3 failed sign-ins in 20 minutes. The apply files a proposal and waits for a person to approve it
# (with a step-up sign-in) in Admin > Change requests; it fails with the change's URL if nobody does within wait_timeout.
resource "tessera_alert_rule" "signin_failures" {
  rule_id        = "signin_failures"
  enabled        = true
  severity       = "high"
  threshold      = 3
  window_minutes = 20
}
```

## Schema

### Required

- `enabled` (Boolean) Whether the rule raises alerts.
- `rule_id` (String) The built-in rule id, for example `signin_failures`. Changing it replaces the resource.
- `severity` (String) `low`, `medium`, `high` or `critical`.
- `threshold` (Number) Events in the window that raise an alert (1 to 10000).
- `window_minutes` (Number) The window in minutes (1 to 10080).

### Read-Only

- `change_id` (String) The id of the change request that applied the last create or update.
- `change_url` (String) Where a person reviews that change request.
- `id` (String) The rule id.

## Import

```shell
terraform import tessera_alert_rule.signin_failures signin_failures
```
