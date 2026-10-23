# Terraform: GCP reference module

REFERENCE, not a turnkey product. Builds: VPC and subnet, private services access, Cloud SQL for PostgreSQL 16
(private IP only, `ssl_mode=ENCRYPTED_ONLY`, regional HA, automated backups with point-in-time recovery),
Secret Manager containers, a service account with `secretAccessor` on those five secrets only, Cloud Run with
two containers (`deploy/gcp/cloud-run`) and Direct VPC egress, and a global external HTTPS load balancer with a
Google-managed certificate (TLS 1.2+ policy, HTTP redirects to HTTPS). Cloud Run accepts traffic only from the
load balancer. Add Cloud Armor in front for a public deployment.

No password or secret value is created by Terraform, so none is in state.

```bash
terraform init
terraform apply -var project_id=... -var domain=tessera.example.com \
  -var api_image=REGION-docker.pkg.dev/PROJECT/tessera/tessera-api:TAG -var ui_image=...:TAG \
  -var anchor_bucket=s3://my-tessera-anchors/prod            # min_instances = 0 on the first apply

# 1. database: set the postgres password, then create tessera_owner / tessera_app (mvp/README.md "Postgres")
gcloud sql users set-password postgres --instance=tessera --password="$(openssl rand -hex 24)"   # store it
#    connect from a host in the VPC (private IP), e.g. a short-lived IAP-tunnelled VM.
# 2. secrets (values never touch Terraform)
openssl rand -base64 32 | tr -d '\n' | gcloud secrets versions add tessera-kek --data-file=-
printf '%s' 'postgres://tessera_owner:PW@PRIVATE_IP:5432/tessera?sslmode=require' | gcloud secrets versions add tessera-db-owner-dsn --data-file=-
#    ... tessera-db-app-dsn, tessera-aws-access-key-id, tessera-aws-secret-access-key
# 3. DNS A record for the domain -> load_balancer_ip, then terraform apply -var min_instances=2 ...
```

- The prod audit anchor needs an S3 Object Lock bucket (an AWS account) and AWS keys limited to that bucket;
  this module does not create it.
- `TESSERA_TRUSTED_PROXIES` is only the nginx sidecar here; verify the X-Forwarded-For chain on your service.
- Remote state in a versioned GCS bucket with a retention policy.
