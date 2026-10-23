variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "name" {
  type    = string
  default = "tessera"
}

variable "domain" {
  description = "DNS name users reach (for example tessera.example.com). A Google-managed certificate is issued for it once the DNS A record points at the load balancer address."
  type        = string
}

variable "api_image" {
  description = "tessera-api image in Artifact Registry, pinned by digest if possible."
  type        = string
}

variable "ui_image" {
  type = string
}

variable "anchor_bucket" {
  description = "s3://bucket/prefix for audit anchors. TESSERA_ENV=prod requires an S3 URL, even on GCP."
  type        = string
}

variable "anchor_aws_region" {
  type    = string
  default = "us-east-1"
}

variable "subnet_cidr" {
  type    = string
  default = "10.20.0.0/20"
}

variable "min_instances" {
  description = "0 on the first apply (secrets are empty), then 2 or more."
  type        = number
  default     = 0
}

variable "max_instances" {
  type    = number
  default = 6
}

variable "db_tier" {
  type    = string
  default = "db-custom-2-7680"
}

variable "db_disk_gb" {
  type    = number
  default = 50
}

variable "db_high_availability" {
  type    = bool
  default = true
}

variable "db_backup_retention_days" {
  type    = number
  default = 14
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "labels" {
  type    = map(string)
  default = {}
}
