# Terraform: Azure reference module

REFERENCE, not a turnkey product. Builds: resource group, VNet (delegated subnets), Azure Database for PostgreSQL
Flexible Server 16 (private access only, `require_secure_transport=on`, TLS 1.2+, zone-redundant HA, 14-day
point-in-time recovery, write-only administrator password so it never enters state; needs Terraform 1.11+), Key Vault (RBAC, purge
protection), a user-assigned identity (Key Vault Secrets User, AcrPull), Log Analytics, and a Container Apps
environment with the two-container Tessera app (`deploy/azure/container-apps`).

```bash
az login
terraform init
export TF_VAR_db_admin_password="$(openssl rand -hex 24)"   # keep a copy in your password vault
terraform apply -var subscription_id=... -var registry_server=myacr.azurecr.io -var registry_id=... \
  -var api_image=myacr.azurecr.io/tessera-api:TAG -var ui_image=myacr.azurecr.io/tessera-ui:TAG \
  -var anchor_bucket=s3://my-tessera-anchors/prod        # desired_min_replicas = 0 on the first apply

# 1. connect as the Entra admin (the deploying principal) from inside the VNet (jump host / Cloud Shell with VNet)
#    and create tessera_owner and tessera_app exactly as mvp/README.md "Postgres" says, with generated passwords.
# 2. set the secrets in Key Vault (names are fixed, values never enter Terraform state):
#    db-owner-dsn db-app-dsn kek aws-access-key-id aws-secret-access-key
az keyvault secret set --vault-name $(terraform output -raw key_vault_name) --name kek --value "$(openssl rand -base64 32)"
# 3. terraform apply -var desired_min_replicas=2 ...
```

- The prod audit anchor needs an S3 Object Lock bucket (an AWS account) and AWS keys with only
  `s3:PutObject/PutObjectRetention/GetObject/GetObjectVersion`; this module does not create the bucket.
- Custom domain and managed certificate are not in the azurerm provider yet: bind them with
  `az containerapp hostname bind`, then set `public_url`.
- `trusted_proxy_cidrs` is a starting point: confirm what the environment ingress presents (docs/deploy/README.md).
- Remote state in an encrypted storage account with locking. It holds ids and FQDNs, no secret values.
