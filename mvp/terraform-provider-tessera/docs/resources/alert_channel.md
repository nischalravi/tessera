---
page_title: "tessera_alert_channel Resource - tessera"
subcategory: ""
description: |-
  A channel that alerts are delivered to: email addresses or a signed webhook. Applied only after a person approves a proposal.
---

# tessera_alert_channel (Resource)

A channel that alerts are delivered to: a list of email addresses, or an HTTPS webhook whose payloads are signed with an HMAC secret you choose and give the receiver (the server cannot show a secret it generated for a proposal, so a webhook needs `signing_secret`). It needs the `config.propose` scope (see `tessera_alert_rule`) and is applied only after a person approves the proposal with a step-up sign-in; apply waits and fails with the change's URL on a refusal or a timeout. A webhook URL usually carries a token (Slack, Teams and Sumo Logic put it in the path), so it goes in the write-only `target_url`, with `target_url_version`: the server seals it, the approver sees its origin and a keyed fingerprint of the whole URL (and a flag when only the path changed), and the state keeps just the origin and fingerprint. The server checks the URL when the proposal is filed and again when it is approved: it must be `https`, carry no credentials and not point at a cloud metadata service. Moving a webhook to another origin needs a new `signing_secret`. Channels are switched off with `enabled = false`, not deleted: destroy only removes the resource from state, with a warning. Reading channels needs the admin scope, so refresh keeps the state as applied unless the client can read them.

## Secrets

`signing_secret` is **write-only** and `Sensitive`: Terraform passes it to the provider while planning and applying and never writes it to the plan or the state (Terraform 1.11 or later; an older Terraform is refused). The server seals it when the proposal is filed, apart from the proposal, bound to the tenant, the proposal and the field; opens it only to apply the change after a person approves; never returns or logs it; and deletes it when the proposal is rejected, withdrawn, expired, applied or failed. A proposal can replace a secret but can never read one.

Because the state holds no secret, Terraform cannot see that it changed. `signing_secret_version` is how a change is signalled: the secret is sent on create and, on an update, only when this version differs from the one in the state; otherwise the server keeps the secret it has. To rotate, change the secret and its version together. Setting a secret without its version is refused at plan time, and so is changing the version without a secret.

## Example Usage

```terraform
variable "soc_webhook_url" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "soc_webhook_signing_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "tessera_alert_channel" "soc" {
  name         = "SOC webhook"
  kind         = "webhook"
  min_severity = "high"

  # the URL usually carries a token: write-only, never in the plan or the state. The state keeps target_origin and
  # target_fingerprint (compare the fingerprint with the one the approver sees).
  target_url         = var.soc_webhook_url
  target_url_version = "1"

  # the receiver verifies the HMAC signature with this secret; write-only
  signing_secret         = var.soc_webhook_signing_secret
  signing_secret_version = "1"
}

resource "tessera_alert_channel" "mail" {
  name         = "SOC mailbox"
  kind         = "email"
  target       = "soc@example.com, secops@example.com"
  min_severity = "critical"
}
```

## Schema

### Required

- `kind` (String) `email` or `webhook`. Changing it replaces the resource.
- `name` (String) A name, at most 100 characters.

### Optional

- `target_url` (String, Sensitive, Write-only) The URL (absolute `https`, no credentials, not a cloud metadata service). It usually carries a token, so it is write-only: never in the plan or the state. The server seals it; the approver sees its origin and a keyed fingerprint, and flags a path-only change.
- `target_url_version` (String) Any text; change it along with `target_url` to send the new URL.
- `target` (String) Email: up to 20 addresses separated by commas. A webhook uses `target_url`.
- `enabled` (Boolean) Whether alerts are sent. Default true.
- `min_severity` (String) `low`, `medium`, `high` (default) or `critical`.
- `signing_secret` (String, Sensitive, Write-only) A webhook's HMAC signing secret, 16 to 256 characters. Required for a webhook.
- `signing_secret_version` (String) Any text; change it along with `signing_secret` to send the new secret.

### Read-Only

- `target_fingerprint` (String) A keyed fingerprint of the whole sealed URL (16 hex characters), shown to the approver too: compare it with the one on the change request to confirm the receiver, path included. It cannot be computed from a list of candidate URLs.
- `target_origin` (String) The scheme, host and port of the sealed URL (never its path).
- `change_id` (String) The id of the change request that applied the last create or update.
- `change_url` (String) Where a person reviews that change request.
- `id` (String) The channel id.

## Import

```sh
terraform import tessera_alert_channel.soc <channel id>
```
