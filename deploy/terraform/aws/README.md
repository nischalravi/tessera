# Terraform: AWS reference module

REFERENCE, not a turnkey product. Review it against your account standards (naming, KMS keys, WAF, SCPs,
flow logs) before production. It builds: VPC (public, private, database subnets, NAT per AZ), RDS for PostgreSQL
16 (encrypted, `rds.force_ssl`, Multi-AZ, 14-day point-in-time recovery, RDS-managed master secret), Secrets
Manager secret containers, an S3 Object Lock bucket for audit anchors, ECS Fargate (two containers, see
`deploy/aws/ecs-fargate`), an ALB with an ACM certificate (HTTP redirects to HTTPS), CloudWatch logs, and two
least-privilege IAM roles (execution: read three secrets; task: write the anchor bucket).

No secret value is created by Terraform, so none is in state: the module creates empty secrets that you fill.

```bash
terraform init
terraform apply -var public_url=https://tessera.example.com -var certificate_arn=arn:aws:acm:... \
  -var api_image=ACCOUNT.dkr.ecr.REGION.amazonaws.com/tessera-api:TAG -var ui_image=...:TAG   # desired_count = 0

# 1. roles (from a host in the VPC, TLS verify-full with the RDS CA bundle). Master secret: output database_master_secret_arn
#    CREATE ROLE tessera_owner ... / tessera_app ... exactly as mvp/README.md "Postgres" says.
# 2. fill the secrets (values never touch Terraform):
aws secretsmanager put-secret-value --secret-id tessera/prod/db-owner-dsn --secret-string \
  'postgres://tessera_owner:PW@HOST:5432/tessera?sslmode=require'
aws secretsmanager put-secret-value --secret-id tessera/prod/db-app-dsn   --secret-string \
  'postgres://tessera_app:PW@HOST:5432/tessera?sslmode=require'
openssl rand -base64 32 | tr -d '\n' | aws secretsmanager put-secret-value --secret-id tessera/prod/kek --secret-string file:///dev/stdin
# 3. terraform apply -var desired_count=2 ...   then create the first tenant with an ECS run-task override.
```

- State: use a remote backend with encryption and locking (S3 + DynamoDB). It holds the RDS endpoint and ARNs,
  not passwords.
- `verify-full` needs the RDS CA bundle inside the image or a mounted file; the distroless image does not carry
  it. `sslmode=require` (shown) satisfies the prod guard rail and encrypts, but does not authenticate the server.
- Costs: 2 NAT gateways, Multi-AZ RDS, ALB. Set `az_count = 2` (minimum for the ALB) and `db_multi_az = false`
  for a trial.
