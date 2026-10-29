# terraform-provider-tessera

A Terraform provider for Tessera configuration (issue #719), built on `terraform-plugin-framework`. It is a separate Go module:
it talks only to the public `/api/v1` API and imports nothing from `mvp/server`, so the server's dependencies are unchanged.
Publishing to the registry is out of scope (it needs a GPG key and a namespace); build and use it locally for now.

## How it signs in

Only the API's machine-client path, never a browser session or the dev IdP: OAuth 2.0 **client credentials** with a
**private-key JWT** (RFC 7523, `token_endpoint_auth_method=private_key_jwt`, ES256 or EdDSA), optionally **DPoP**-bound
(RFC 9449; `dpop = true`, needed for clients registered with `dpop_required`, which is the default). There is no client secret.
The provider reads the tenant's `/.well-known/oauth-authorization-server` metadata, signs a 60 second assertion whose `aud` is the
token endpoint, and keeps the access token in memory (renewed when it expires or the API answers 401). It refuses a token endpoint
or a redirect on another origin than `endpoint`, `endpoint` must be https (http only for localhost), and TLS verification is on
unless `insecure_skip_verify` is set.

Register the client with the public key (the private key never leaves you):

```sh
tessera admin add-client -tenant larkspur -name "terraform" -owner pat.policy@larkspur.example \
  -jwks-file public.jwks -scope "tessera:read tessera:write" -roles viewer,operator,auditor
```

The same can be done in Admin > API clients. The server's `TESSERA_PUBLIC_URL` must equal the provider's `endpoint`.

## What it can manage, and what it cannot

The server decides what a machine client may do: it holds `viewer`, `operator` and `auditor` at most (never an admin role or the
`tessera:admin` scope), its permissions never exceed those of the person who approved it, and it can never pass a step-up sign-in.
Most configuration routes need an admin role or a step-up, so a Terraform provider that signs in non-interactively cannot call them.
Checked against the route table and by calling the routes with a machine token:

| In the issue | Route | Why a machine client cannot manage it |
| --- | --- | --- |
| connectors | `/api/connections` | `connections.manage` is tenant admin only; credential and config changes also need step-up. Reads work (`tessera_connectors`) |
| catalog items, birthright rules | `/api/catalog/items/*` | `catalog.manage` is policy admin, plus step-up. `GET /api/catalog` is refused for a token (403) |
| business roles | `/api/roles` | `roles.manage` is policy admin, plus step-up; reading roles needs `requests.create`, which no token scope grants (403) |
| SoD rules, mitigating controls | `/api/sod/*` | `sod.manage` is policy admin, plus step-up |
| approval policies | `/api/workflows` | `workflows.manage` is policy admin, plus step-up |
| alert rules and channels | `/api/alerts/*` | `alerts.configure` needs the admin scope and role, plus step-up |
| SIEM sinks | `/api/siem/sinks` | `siem.configure` needs the admin scope and role, plus step-up |
| transport package export/import | `/api/config/*` | `config.transport` needs the admin scope and role; import apply needs step-up |
| group folders and groups (not in the issue) | `/api/groups*` | a machine client holds no group privilege (not even create on the root folder): 403 `privilege_required` |

Those writes are reached another way: **proposals** (server issue #721). A machine client that holds the `config.propose` scope files a
change request instead of writing, a person approves it with a step-up sign-in, and only then does the server apply it. The client
never holds an admin role and never passes a step-up, so it cannot approve or apply anything itself.

* `config.propose` is not a registration option (the UI, the API and `tessera admin add-client` refuse it). Two admins grant it: one files a
  change request of type `api_client.propose.grant` for the client (admin center, or `POST /api/admin/change-requests`), a different one approves it
  with a step-up sign-in. The client then gets a new token that carries the scope.
* A proposal (`POST /api/v1/proposals/...`) is a change request in the existing admin workflow, filed in the name of the client's owner, so the
  owner cannot approve it either (nor can any admin who is the same person). It answers `202` with a change id and URL, waits at most
  72 hours, and every submitted, approved and applied event in the audit trail carries the client id.
* The provider files the proposal and **waits** (provider settings `wait_timeout`, default 30m, and `poll_interval`, default 5s). The resource
  returns once the change is applied. On a refusal, a withdrawal, an expiry, a failed apply or a timeout, the apply fails with the change id and
  the URL a person opens; a timed-out proposal stays open, and applying again files a new one. Plan stays read-only.
* Proposable today: alert rules, catalog items, business roles and SoD rulesets (create and update; the server has no proposal for retire or
  delete, so destroy only removes the resource from state and warns). Connectors, approval policies, SIEM sinks, transport and group folders
  stay out.

In:

| Kind | Name | API |
| --- | --- | --- |
| resource | `tessera_review_schedule` (the issue's "review templates") | `/api/v1/reviews/schedules` (`reviews.manage`: operator with `tessera:write`) |
| data source | `tessera_identities` | `/api/v1/identities` |
| data source | `tessera_entitlements` | `/api/v1/groups` |
| data source | `tessera_connectors` | `/api/v1/connections` (needs the auditor role too) |
| resource | `tessera_alert_rule` | `/api/v1/proposals/alert-rules/{rule_id}` (needs `config.propose`; read with `tessera:audit` and the auditor role) |
| resource | `tessera_catalog_item` | `/api/v1/proposals/catalog-items/{group_id}` (needs `config.propose`; no read) |
| resource | `tessera_business_role` | `/api/v1/proposals/roles` (needs `config.propose`; read with `tessera:read`) |
| resource | `tessera_sod_ruleset` | `/api/v1/proposals/sod-rulesets` (needs `config.propose`; read with `tessera:read`) |

`tessera_roles` is not offered: the route is refused for tokens. `tessera_review_schedule` supports import (by UUID), plan-time
validation (ranges, enums, `reminder_days < duration_days`, `escalate` needs a reviewer, RFC 3339 times) and server validation errors
surface unchanged. The API has no delete route and no read-one route: destroy disables the schedule, and read lists and filters.
No resource here carries a secret, so there is no write-only attribute yet; the provider's own `private_key` is `Sensitive` and is
never put in a diagnostic or log. A resource with a secret (a connector credential) must use a write-only attribute (Terraform 1.11+).

## Build and test

```sh
cd mvp/terraform-provider-tessera
go build ./... && go vet ./... && go test ./...              # unit tests: client, validation, provider configuration
TF_ACC=1 go test ./internal/provider -run Acc -v             # acceptance tests against a real `tessera serve`
```

The acceptance tests (`TestAcc_*`) build `../server/cmd/tessera` (or use `TESSERA_BIN`), seed a SQLite database in a temp dir, register
two machine clients (Bearer and DPoP) with `tessera admin add-client`, start `tessera serve` on a free port from 8400, and stop that
process by its PID at the end. `TestAcc_Proposals` also builds and starts the dev IdP (`TESSERA_DEVIDP_BIN`) and signs two admins in with a
passkey, who grant the client `config.propose` and approve, reject or ignore its proposals while the provider waits. They drive the provider through the Terraform plugin protocol in process (configure, plan, apply, refresh,
import, destroy), so they need no `terraform` binary. `TestAccCLI_ReviewSchedule` runs the same lifecycle through the real `terraform`
CLI (terraform-plugin-testing); it also needs `TF_ACC=1` and a terraform binary.

To try it by hand, build the provider and point a dev override at it:

```sh
go build -o ~/go/bin/terraform-provider-tessera .
# ~/.terraformrc: provider_installation { dev_overrides { "nischalravi/tessera" = "/home/you/go/bin" } direct {} }
```

## Docs

`docs/` and `examples/` follow the tfplugindocs layout. `docs/` is written by hand because generating it needs the terraform binary;
regenerate with `go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate` once a terraform binary is on the PATH.

## CI

There is no CI job for this module yet (`.github/` is not edited by the agents). It needs one that runs, in this directory,
`gofmt -l .`, `go vet ./...`, `go test -race ./...` and `TF_ACC=1 go test ./internal/provider -run Acc`, and `govulncheck ./...`.
