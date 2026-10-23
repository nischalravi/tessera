variable "name" {
  description = "Name prefix for every resource."
  type        = string
  default     = "tessera"
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "public_url" {
  description = "https URL users reach (becomes TESSERA_PUBLIC_URL). Its host must match certificate_arn."
  type        = string
  validation {
    condition     = startswith(var.public_url, "https://")
    error_message = "public_url must start with https:// (TESSERA_ENV=prod refuses http)."
  }
}

variable "certificate_arn" {
  description = "ACM certificate (same region) for the ALB HTTPS listener."
  type        = string
}

variable "api_image" {
  description = "tessera-api image, preferably pinned by digest."
  type        = string
}

variable "ui_image" {
  description = "tessera-ui image, preferably pinned by digest."
  type        = string
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "az_count" {
  type    = number
  default = 2
}

variable "desired_count" {
  description = "Tasks. Leave 0 on the first apply, fill the secrets (see README), then set 2 or more."
  type        = number
  default     = 0
}

variable "task_cpu" {
  type    = number
  default = 1024
}

variable "task_memory" {
  type    = number
  default = 2048
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_allocated_storage" {
  type    = number
  default = 50
}

variable "db_multi_az" {
  type    = bool
  default = true
}

variable "db_backup_retention_days" {
  description = "Automated backups with point-in-time recovery."
  type        = number
  default     = 14
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "alb_ingress_cidrs" {
  description = "Who may reach the load balancer. Narrow it for an internal deployment."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "tags" {
  type    = map(string)
  default = {}
}
