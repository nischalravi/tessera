variable "subscription_id" {
  type = string
}

variable "name" {
  description = "Name prefix (lowercase letters and digits, max 12)."
  type        = string
  default     = "tessera"
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "public_url" {
  description = "https URL users reach. Empty uses the environment's default https://<name>.<default-domain> address (Azure-managed certificate). For a custom domain bind it and a certificate afterwards, then set this."
  type        = string
  default     = ""
}

variable "api_image" {
  description = "tessera-api image in your registry, pinned by digest if possible."
  type        = string
}

variable "ui_image" {
  type = string
}

variable "registry_server" {
  description = "Container registry host (for example myacr.azurecr.io). The app's managed identity gets AcrPull when registry_id is set."
  type        = string
}

variable "registry_id" {
  description = "Resource id of the Azure Container Registry, for the AcrPull assignment. Empty skips it."
  type        = string
  default     = ""
}

variable "anchor_bucket" {
  description = "s3://bucket/prefix for audit anchors. TESSERA_ENV=prod requires an S3 URL, even on Azure."
  type        = string
}

variable "anchor_aws_region" {
  type    = string
  default = "us-east-1"
}

variable "vnet_cidr" {
  type    = string
  default = "10.1.0.0/16"
}

variable "trusted_proxy_cidrs" {
  description = "Peers allowed to set X-Forwarded-For besides the nginx sidecar (127.0.0.1/32). Verify the ranges your environment presents; none broader than /8."
  type        = list(string)
  default     = ["10.1.0.0/16", "100.64.0.0/10"]
}

variable "desired_min_replicas" {
  description = "0 on the first apply (secrets are not filled yet), then 2 or more."
  type        = number
  default     = 0
}

variable "max_replicas" {
  type    = number
  default = 6
}

variable "db_sku_name" {
  type    = string
  default = "GP_Standard_D2ds_v5"
}

variable "db_storage_mb" {
  type    = number
  default = 65536
}

variable "db_high_availability" {
  description = "Zone-redundant standby."
  type        = bool
  default     = true
}

variable "db_backup_retention_days" {
  type    = number
  default = 14
}

variable "db_zone" {
  type    = string
  default = "1"
}

variable "db_standby_zone" {
  type    = string
  default = "2"
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "db_admin_password" {
  description = "Initial PostgreSQL administrator password. Ephemeral and write-only: it is sent to Azure at apply time and is NOT stored in state or plan (needs Terraform 1.11+). Pass it with TF_VAR_db_admin_password and keep it in a vault."
  type        = string
  sensitive   = true
  ephemeral   = true
}

variable "key_vault_public_network_access" {
  description = "Allow the Key Vault public endpoint (still default-deny: only key_vault_allowed_ips and trusted Azure services get in). Default false: set secret values from a network that reaches a private endpoint, or turn this on temporarily."
  type        = bool
  default     = false
}

variable "key_vault_allowed_ips" {
  description = "Public IPs or CIDRs (for example your workstation as a.b.c.d/32) allowed through the Key Vault firewall. Only effective when key_vault_public_network_access is true."
  type        = list(string)
  default     = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
