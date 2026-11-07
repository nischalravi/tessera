---
page_title: "tessera_connection Resource - tessera"
subcategory: ""
description: |-
  A connection to a connected system, created in draft, with its configuration and credential. Applied only after a person approves a proposal.
---

# tessera_connection (Resource)

A connection to a connected system with its configuration and credential. The server creates it in `draft`: it still needs its validation and dry run, and a person activates it as a separate step, which Terraform cannot do. It needs the `config.propose` scope (see `tessera_alert_rule`) and is applied only after a person approves the proposal with a step-up sign-in; apply waits and fails with the change's URL on a refusal or a timeout. Refresh reads the connection back (the client needs `tessera:read` and the auditor role). A connection is retired in the admin center, not by Terraform: destroy only removes the resource from state, with a warning.

## Secrets

`secret` is **write-only** and `Sensitive`: Terraform passes it to the provider while planning and applying and never writes it to the plan or the state (Terraform 1.11 or later; an older Terraform is refused). The server seals it when the proposal is filed, apart from the proposal, bound to the tenant, the proposal and the field; opens it only to apply the change after a person approves; never returns or logs it; and deletes it when the proposal is rejected, withdrawn, expired, applied or failed. A proposal can replace a secret but can never read one.

Because the state holds no secret, Terraform cannot see that it changed. `secret_version` is how a change is signalled: the secret is sent on create and, on an update, only when this version differs from the one in the state; otherwise the server keeps the secret it has. To rotate, change the secret and its version together. Setting a secret without its version is refused at plan time, and so is changing the version without a secret.

## Example Usage

```terraform
variable "okta_api_token" {
  type      = string
  sensitive = true
  ephemeral = true # Terraform 1.10+; the value never reaches the plan or the state
}

resource "tessera_connection" "okta" {
  name           = "Okta production"
  connector_type = "okta"
  config_json    = jsonencode({ org_url = "https://acme.okta.com" })

  # write-only: never in the plan or the state. Change the version with the secret to send the new one.
  secret         = var.okta_api_token
  secret_version = "1"
}

# The server creates the connection in draft. Validating, dry-running and activating it stay steps a person takes.
```

## Schema

### Required

- `connector_type` (String) The connector type, for example `okta`; see the `tessera_connectors` data source. Changing it replaces the resource.
- `name` (String) A unique name, at most 100 characters. Changing it replaces the resource.

### Optional

- `config_json` (String) The connection's settings as a JSON object, merged over the connector type's defaults. Put no secret here: the server refuses a config key that names one. Not read back, so a change made elsewhere is not seen. The server refuses a host that is a cloud metadata service, when the proposal is filed and again when it is approved.
- `credential_reference` (String) A reference to a credential held elsewhere, `vault:<path>` or `agent:<id>/<name>`. Use this or `secret`.
- `role` (String) `authoritative` or `account_source`; the connector type's own when omitted.
- `secret` (String, Sensitive, Write-only) The connector's secret (a password, client secret or API key).
- `secret_version` (String) Any text; change it along with `secret` to send the new secret.
- `system` (String) The system name in the graph; the server derives it when omitted.

### Read-Only

- `change_id` (String) The id of the change request that applied the last create or update.
- `change_url` (String) Where a person reviews that change request.
- `id` (String) The connection id.
- `state` (String) The connection's readiness state on the server (`draft` until a person activates it).

## Import

```sh
terraform import tessera_connection.okta <connection id>
```
