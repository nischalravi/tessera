# AWS ECS on Fargate (reference)

Two containers per task (`ui` nginx on 8080 in front, `api` on 8000, talking over the task's localhost), an
ALB in front, RDS for PostgreSQL behind. The Terraform module `deploy/terraform/aws` builds all of this; use
these files if you manage ECS yourself.

```bash
# replace ACCOUNT_ID, REGION, TAG, subnets, security groups and the target group, then:
aws ecs register-task-definition --cli-input-json file://taskdef.json
aws ecs create-service --cli-input-json file://service.json     # or update-service for upgrades
```

Notes

- Postgres is required (two or more tasks). Secrets come from Secrets Manager (`secrets[].valueFrom`); the
  execution role needs `secretsmanager:GetSecretValue` on those three ARNs only.
- The task role (not the execution role) is what the app uses for the audit anchor: `s3:PutObject`,
  `s3:PutObjectRetention`, `s3:GetObject`, `s3:GetObjectVersion` on the Object Lock bucket. The AWS SDK inside
  Tessera cannot reach the ECS credential endpoint (the SSRF guard blocks 169.254.170.2): if the anchor fails
  to authenticate, give the task `AWS_ROLE_ARN`/web identity or scoped keys from Secrets Manager (see
  docs/deploy/README.md, "Audit anchor"). Verify this on your account before relying on it.
- `TESSERA_TRUSTED_PROXIES`: `127.0.0.1/32` (nginx sidecar) plus the VPC subnets that carry the ALB nodes.
- Volumes are ephemeral bind mounts on top of directories that exist in the images (`/tmp`,
  `/var/lib/tessera`), so they inherit the image ownership; the root filesystems are read-only.
- Target group health check: path `/api/health`, matcher 200 (through the ui container, so it tests both).
- Probes on `/livez` and `/readyz` and leader election for the background loops: available once #517 merges.
- Migrations run when the first task starts (advisory lock), as the owner login. For a gated rollout run
  `aws ecs run-task` once with `--overrides` setting `command: ["check-db"]` on the `api` container.
- Create the first tenant the same way with `command: ["admin","create-tenant","-slug","acme","-name","Acme"]`.
