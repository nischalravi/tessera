---
page_title: "tessera_siem_sink Resource - tessera"
subcategory: ""
description: |-
  A SIEM sink: the audit ledger streamed to Splunk HEC, a JSON webhook, a syslog collector or S3. Applied only after a person approves a proposal.
---

# tessera_siem_sink (Resource)

A SIEM sink: the audit ledger streamed to Splunk HEC (`kind = "webhook"`, `flavor = "hec"`), a JSON webhook, a syslog-over-TLS collector or an S3 bucket. It needs the `config.propose` scope (see `tessera_alert_rule`) and is applied only after a person approves the proposal with a step-up sign-in; apply waits and fails with the change's URL on a refusal or a timeout. The server applies the rules of the admin route: HEC and S3 need their `token`, a webhook must be `https` and not a cloud metadata service, a syslog collector must not be a private address, and a sink that moves to another origin needs a new `token` (the stored one never follows it). These are checked when the proposal is filed and again when it is approved. A webhook or S3 URL may carry a token, so it goes in the write-only `target_url`, with `target_url_version`; the state keeps only its origin and a keyed fingerprint. Sinks are switched off with `enabled = false`, not deleted: destroy only removes the resource from state, with a warning. Refresh reads the sink when the client also holds the audit scope and keeps the state as applied otherwise.

## Secrets

`token` is **write-only** and `Sensitive`: Terraform passes it to the provider while planning and applying and never writes it to the plan or the state (Terraform 1.11 or later; an older Terraform is refused). The server seals it when the proposal is filed, apart from the proposal, bound to the tenant, the proposal and the field; opens it only to apply the change after a person approves; never returns or logs it; and deletes it when the proposal is rejected, withdrawn, expired, applied or failed. A proposal can replace a secret but can never read one.

Because the state holds no secret, Terraform cannot see that it changed. `token_version` is how a change is signalled: the secret is sent on create and, on an update, only when this version differs from the one in the state; otherwise the server keeps the secret it has. To rotate, change the secret and its version together. Setting a secret without its version is refused at plan time, and so is changing the version without a secret.

## Example Usage

```terraform
variable "splunk_hec_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "tessera_siem_sink" "splunk" {
  name   = "Splunk"
  kind   = "webhook"
  flavor = "hec"
  format = "json"

  # write-only; bump the version with it to move the sink (the sink then also needs a new token)
  target_url         = "https://splunk.example.com:8088/services/collector"
  target_url_version = "1"

  event_filter = ["auth.*", "admin.change.*"]

  # write-only: never in the plan or the state. Rotate by changing both.
  token         = var.splunk_hec_token
  token_version = "1"
}
```

## Schema

### Required

- `kind` (String) `webhook`, `syslog` or `s3`. Changing it replaces the resource.
- `name` (String) A name, at most 100 characters.

### Optional

- `target_url` (String, Sensitive, Write-only) The URL (absolute `https`, no credentials, not a cloud metadata service). It usually carries a token, so it is write-only: never in the plan or the state. The server seals it; the approver sees its origin and a keyed fingerprint, and flags a path-only change.
- `target_url_version` (String) Any text; change it along with `target_url` to send the new URL.
- `target` (String) Syslog: `host:port` (6514 by default). A webhook or S3 sink uses `target_url`.
- `access_key_id` (String) S3: the access key id (the secret access key is `token`).
- `ca_pem` (String) A syslog collector's CA bundle (PEM certificates, public).
- `enabled` (Boolean) Whether events are sent. Default true.
- `event_filter` (Set of String) Audit actions or prefixes (`auth.*`) the sink receives; unset means every event.
- `flavor` (String) A webhook's flavor, `hec` or `json`.
- `format` (String) `json` (default) or `ocsf`.
- `include_http` (Boolean) Whether `http.request` events are sent too. Default false.
- `region` (String) S3: the signing region.
- `start` (String) On creation: `now` (default) or `beginning`.
- `token` (String, Sensitive, Write-only) An HEC token, or an S3 secret access key.
- `token_version` (String) Any text; change it along with `token` to send the new token.

### Read-Only

- `target_fingerprint` (String) A keyed fingerprint of the whole sealed URL (16 hex characters), shown to the approver too: compare it with the one on the change request to confirm the receiver, path included. It cannot be computed from a list of candidate URLs.
- `target_origin` (String) The scheme, host and port of the sealed URL (never its path).
- `change_id` (String) The id of the change request that applied the last create or update.
- `change_url` (String) Where a person reviews that change request.
- `id` (String) The sink id.

## Import

```sh
terraform import tessera_siem_sink.splunk <sink id>
```
