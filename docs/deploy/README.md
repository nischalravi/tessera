# Deploying Tessera (issue #516)

Everything here is a **reference**: read it, adapt it, review it against your own standards. Nothing in it
was run against a live cloud account by the authors. What was validated is listed in the pull request.

Files: `deploy/docker` (images), `deploy/compose` (one VM), `deploy/helm/tessera` (Kubernetes),
`deploy/aws/ecs-fargate`, `deploy/azure/container-apps`, `deploy/gcp/cloud-run` (PaaS manifests),
`deploy/terraform/{aws,azure,gcp}` (infrastructure), `deploy/prometheus` (alert rules).

## 1. What runs

| Piece | Image / binary | Notes |
|---|---|---|
| API | `tessera-api` (`cmd/tessera`, distroless static, uid 65532) | `serve -addr 0.0.0.0:8000`. Also `worker`, `admin`, `backup`, `check-db` subcommands |
| UI | `tessera-ui` (nginx-unprivileged, uid 101) | **The Go API does not serve the web UI.** The UI image serves `mvp/frontend/dist` and proxies `/api`, `/public/t`, `/.well-known`, `/t/<slug>/oauth|bootstrap|mcp` to the API, so one origin serves both (prod UI is same-origin, CORS off). Same path list as `mvp/frontend/vite.config.ts` |
| UI headers | (same image) | Static responses carry a strict CSP (`default-src 'self'`, no inline script, `frame-ancestors 'none'`), `nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options`. `Strict-Transport-Security` is sent only when `X-Forwarded-Proto` is `https`; its value is the container env `TESSERA_HSTS` (default `max-age=31536000; includeSubDomains`, set it empty to turn HSTS off). Headers live in `deploy/docker/nginx/tessera-headers.inc` |
| Base images | `deploy/docker/Dockerfile`, `deploy/compose` | Pinned by tag and `@sha256` digest (a test in `internal/archtest` rejects unpinned or `:latest` third-party images). Refresh with `docker buildx imagetools inspect <tag>`. Compose `init-certs`/`init-kek` use the Dockerfile `init` target (pinned alpine + openssl); the KEK is mounted only into `init-kek` |
| CLI | `tessera-cli` target | Operator/user CLI (device sign-in). Optional |
| Dev IdP | `tessera-devidp` target | Development only. Listens on loopback only, never in the prod image, refused by the prod guard rails |
| Database | Postgres 16 | Required for more than one replica. SQLite is single-node only |

Build (from the repo root): `docker build -f deploy/docker/Dockerfile --target api -t tessera-api .` (and `ui`).
Multi-arch: `docker buildx build --platform linux/amd64,linux/arm64 ...`; the Go stage cross-compiles with
`CGO_ENABLED=0 -trimpath` (SQLite is pure Go). Pin base images by digest (`--build-arg GO_IMAGE=...@sha256:...`) for
reproducible builds. The API image has no shell, so it carries no `HEALTHCHECK`; probes use `GET /api/health`.
The UI image has a `HEALTHCHECK` on `/healthz`. Both run on a read-only root filesystem: only `/tmp` (and
`/var/lib/tessera` for the API) need to be writable, as volumes.

## 2. Which option

| You have | Choose | Why |
|---|---|---|
| One VM (EC2, Azure VM, GCE), a small team, no HA need | **Compose** (`deploy/compose`) | Simplest; Caddy gives automatic TLS; one API replica and one database, so an outage means downtime |
| A Kubernetes platform (EKS, AKS, GKE, OpenShift) | **Helm** (`deploy/helm/tessera`) | N replicas, HPA, PDB, NetworkPolicy, CSI secrets, ServiceMonitor |
| No cluster, want managed containers | **PaaS**: ECS Fargate, Container Apps, Cloud Run | No nodes to patch. Always with managed Postgres. Each replica runs the UI and API in one task/revision |
| Starting from nothing in a cloud | **Terraform** module of that cloud | Network, Postgres, secrets, service, load balancer in one apply |

The availability design is `docs/design/ha-postgres.md`: stateless API replicas behind a load balancer and a
Postgres primary plus synchronous standby (all three managed services provide this as Multi-AZ /
zone-redundant / regional HA).

## 3. Configuration

Required with `TESSERA_ENV=prod` (the server refuses to start otherwise and lists every problem; see
`mvp/README.md`, "Server hardening"):

| Variable | Value |
|---|---|
| `TESSERA_ENV` | `prod` (the images default to it) |
| `TESSERA_PUBLIC_URL` | the https origin users type. It is also the OIDC issuer base and the CSRF Origin |
| `TESSERA_DB` | owner DSN `postgres://tessera_owner:...@host:5432/tessera?sslmode=require` (migrations, operator commands) |
| `TESSERA_DB_APP` | application DSN, **a different login** (`tessera_app`: no BYPASSRLS, owns nothing), TLS `require` or stricter on both |
| `TESSERA_KEK` or `TESSERA_KEK_FILE` | base64 of 32 random bytes (below) |
| `TESSERA_AUDIT_ANCHOR` | `s3://bucket/prefix` of an S3 Object Lock bucket (below) |
| `TESSERA_TRUSTED_PROXIES` | CIDRs of every hop in front of the API that may set `X-Forwarded-For`; none broader than /8 (IPv4) |

Must be unset or off in prod: `TESSERA_CORS_ORIGINS`, `TESSERA_DEV_IDP_URL`, `TESSERA_NOW`,
`TESSERA_OUTBOUND_ALLOW_LOOPBACK`, `TESSERA_COOKIE_SECURE=false`, `TESSERA_DEV_DB_ALLOW_PRIVILEGED_APP`.

Optional: `TESSERA_METRICS_ADDR` (off in prod unless set; a loopback/private IP, or `0.0.0.0:9464` together with
`TESSERA_METRICS_ALLOW_WILDCARD=true` when a NetworkPolicy or security group limits the scraper; `off` in PaaS),
`TESSERA_READY_MAX_LOOP_LAG_SECONDS`, `TESSERA_BACKUP_DIR`/`_EVERY_MINUTES`/`_KEEP` (SQLite only), archive
(`TESSERA_ARCHIVE_URL` + `TESSERA_ARCHIVE_TOKEN_SEALED`), SMTP, connector credentials (`mvp/README.md`).

### Audit anchor (needs an S3 bucket on every cloud)

Prod refuses any `TESSERA_AUDIT_ANCHOR` that is not `s3://`. The bucket must have Object Lock; the identity needs
`s3:PutObject`, `s3:PutObjectRetention`, `s3:GetObject`, `s3:GetObjectVersion`. The AWS SDK's HTTP traffic goes
through the SSRF guard, which blocks the EC2/ECS metadata credential endpoints: give the process credentials by
**IRSA / web identity** (EKS) or by `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` from your secret store (any
cloud; use a key scoped to that bucket). The Terraform AWS module creates the bucket and grants the task role;
on Azure and GCP you bring the bucket and the keys. Anchors in Azure Blob / GCS: available once #517 merges
(it adds those archive stores; confirm whether it also covers the anchor sink).

### KEK (key-encryption key)

The KEK seals every signing key and secret in the database. Without it no database or backup can be opened:
**escrow it offline**. Generate with `openssl rand -base64 32`.

- Now: from the platform secret store as the **`TESSERA_KEK` environment variable** (ECS `secrets`, Container
  Apps Key Vault reference, Cloud Run `secretKeyRef`, Kubernetes Secret synced by the CSI driver or created by
  hand, Compose secret installed by the `init` service).
- `TESSERA_KEK_FILE` also works but the file must be mode 0600 with no group/other bits. Kubernetes secret
  volumes with `fsGroup` and CSI mounts are group-readable and are refused, so the chart uses the env form.
  Compose's `init` service installs the file with the right owner and mode.
- After #517 merges: KMS-wrapped KEK (`TESSERA_KEK_WRAPPED` + `TESSERA_KEK_KMS`: AWS KMS, Azure Key Vault key,
  Cloud KMS), so the plain KEK is never stored. The manifests will gain these variables then; until then they use
  the forms above.

### TLS and proxies

The API speaks plain HTTP on 8000; a TLS terminator sits in front. The `__Host-` session cookie needs https at
the browser. Set `TESSERA_TRUSTED_PROXIES` to the hops between the user and the API **including the nginx
sidecar** (`127.0.0.1/32`). The API takes the rightmost `X-Forwarded-For` entry that is not itself trusted, so
every hop that appends to the header must be listed, or all users share one rate-limit bucket (the load balancer
address).

| Front door | Terminates TLS | Add to `TESSERA_TRUSTED_PROXIES` |
|---|---|---|
| Compose + Caddy | Caddy (Let's Encrypt) | `172.16.0.0/12` (compose networks) |
| AWS ALB (ECS or EKS target-type ip) | ALB + ACM | the VPC (or ALB subnet) CIDRs |
| Azure Container Apps ingress | environment (managed cert or custom domain) | the environment's ingress peer range (verify; the sample lists the VNet and 100.64.0.0/10) |
| Azure Application Gateway / nginx ingress on AKS | gateway / cert-manager | the gateway subnet / the ingress pod CIDR |
| GCP external HTTPS LB to Cloud Run | LB + managed certificate | `127.0.0.1/32` only if Cloud Run's front end appends no further hop (verify X-Forwarded-For on your service) |
| GKE Ingress | LB + managed certificate | `130.211.0.0/22`, `35.191.0.0/16`, plus node/pod range |
| OpenShift Route | router (edge) | the cluster network CIDR that carries the router pods |

"Verify" means: call the service with a known client address and read what the API sees. The values in the
samples are starting points, not facts about your network.

### Postgres

Create the two roles once, before the first start, as in `mvp/README.md` ("Postgres"): `tessera_owner`
(BYPASSRLS, owns the database) and `tessera_app` (NOSUPERUSER, NOBYPASSRLS, no `GRANT` between them). Compose does
it in `deploy/compose/postgres/10-roles.sh`; on managed services run the SQL as the admin user from inside the
network. `sslmode=require` encrypts and satisfies the guard rail; **`verify-full`** also authenticates the server
and needs the CA: the cloud CAs are not in the distroless root store, so mount the bundle (Helm
`database.caConfigMap`, then `...&sslrootcert=/etc/tessera/db-ca/ca.crt`). RDS and Azure host names match their certificates, so `verify-full` works there. A Cloud SQL private IP does not match
its server certificate: use `sslmode=require` (or `verify-ca` with the instance server CA, output by the GCP module).

Schema migrations run on every start under a Postgres advisory lock, as the owner login. Upgrade order:

1. Back up (below). 2. Deploy the new image: Helm runs the migration Job first (`migration.enabled`, existing
Secret only), PaaS and Compose migrate on the first new instance, or run `tessera check-db` once with only
`TESSERA_DB` set. 3. Roll the API replicas (RollingUpdate with `maxUnavailable: 0`, ECS 100/200, Container Apps
single revision). 4. Watch `/api/health` and the alert rules. Migrations are forward-only: to roll back the image
across a migration, restore the database backup taken in step 1 (rollback note per release in the promotion PR).
The first tenant is created with `tessera admin create-tenant -slug ... -name ...` (a one-off task/pod/exec with the
same environment).

### Backups and point-in-time recovery

Tessera's own `backup create` is SQLite-only. On Postgres use the service's:

| Service | What the reference configures | Restore |
|---|---|---|
| RDS | `backup_retention_period` 14 days, PITR to any second, encrypted, final snapshot, Multi-AZ | restore to a new instance, repoint the DSN secrets |
| Azure Database for PostgreSQL Flexible | 14 days PITR, zone-redundant HA; turn on geo-redundant backup for region loss | restore to a new server; the private DNS zone needs re-linking |
| Cloud SQL | automated backups + PITR (7 days of logs), regional HA | clone/restore to a new instance |

After a restore run the verification of `docs/runbooks/disaster-recovery.md` (audit chains, anchors, heads) before
serving, and keep the KEK escrow: backups are useless without it. Restores revoke sessions and signing keys by design.

## 4. Monitoring

`/metrics` is only on the internal listener (`TESSERA_METRICS_ADDR`). Helm: `metrics.serviceMonitor.enabled` and
`metrics.prometheusRule.enabled` install a ServiceMonitor and the rules of `deploy/prometheus/tessera-rules.yml` (a
copy in `deploy/helm/tessera/files/`; keep them identical, `diff` is part of the review checklist).
PaaS: logs go to CloudWatch, Log Analytics and Cloud Logging; metrics scraping needs a private path and is off
(`TESSERA_METRICS_ADDR=off`) in the samples. `/livez` and `/readyz` exist in the API; probes use `/api/health` until
the split probe semantics and advisory-lock leader election of #517 merge ("available once #517 merges"), then set
`probes.livenessPath: /livez` and `probes.readinessPath: /readyz` in Helm.

Until leader election lands, **every replica runs the background loops** (sweepers, key rotation, checkpoints,
schedules). The design lists the loops as safe behind a lock; run more than one replica only after confirming that
for the version you deploy, or run `worker` processes with `TESSERA_EXTERNAL_WORKER_KINDS` as in `mvp/README.md`.

## 5. Sizing (starting points, measure with `./run.sh bench`)

| Size | API | Postgres |
|---|---|---|
| Trial | 1 vCPU / 1 GiB, 2 replicas | 2 vCPU / 8 GiB (db.t4g.medium, D2ds_v5, db-custom-2-7680), 50 GiB |
| Production | 2 vCPU / 2 GiB, 3+ replicas (HPA on CPU 70%) | 4+ vCPU / 16 GiB, Multi-AZ, storage autoscaling |

Postgres connections: each replica holds a pool; keep `replicas x pool` under the database limit.
Request bodies are capped at 1 MiB; keep proxy limits equal or smaller.

## 6. Hardening checklist

Non-root, read-only root filesystem, all capabilities dropped, RuntimeDefault seccomp, no privilege escalation
(Compose, Helm, ECS). Container Apps and Cloud Run cannot set a read-only root; writable paths are the declared
volumes. Secrets never in images, env files committed to git, or Terraform state (the modules create empty secret
containers). Images are not signed or scanned by this change; add `cosign` and a registry scanner to your pipeline.
