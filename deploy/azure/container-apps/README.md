# Azure Container Apps (reference)

One app with two containers (nginx `ui` on 8080 as the ingress target, `api` on 8000 over localhost), at least
two replicas, PostgreSQL Flexible Server (private access, TLS required) behind. `deploy/terraform/azure`
creates the environment, identity, Key Vault and database; `containerapp.yaml` is the app itself.

- Container Apps does not offer a read-only root filesystem setting; writable paths are limited to the
  EmptyDir volumes mounted in the YAML and the images run as non-root (65532 / 101).
- Secrets are Key Vault references resolved by the user-assigned identity (grant it `Key Vault Secrets User`).
- The Tessera audit anchor must be an S3 bucket in prod (`TESSERA_AUDIT_ANCHOR=s3://...`); keep the AWS key pair
  in Key Vault, scoped to that bucket (docs/deploy/README.md, "Audit anchor").
- `TESSERA_TRUSTED_PROXIES`: confirm the peer addresses the platform ingress presents and list them. The value in
  the YAML is a starting point, not a verified fact.
- Probes on `/livez` and `/readyz` and leader election: available once #517 merges.
- Migrations run on the first replica's start (advisory lock). For a gated rollout use a Container Apps job with
  the api image and args `["check-db"]` and only `TESSERA_DB`.
