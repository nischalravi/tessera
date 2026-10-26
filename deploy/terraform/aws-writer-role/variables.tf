variable "issuer_url" {
  description = "The connector's OIDC issuer: the `federation.issuer` of the AWS connector (https://<public host>/t/<slug>/aws)."
  type        = string
  validation {
    condition     = startswith(var.issuer_url, "https://")
    error_message = "issuer_url must be the https issuer shown on the AWS connector."
  }
}

variable "subject" {
  description = "The writer's token subject: tessera:tenant:<tenant id>:aws-writer:<connector id>. It is not the reader's `federation.subject`: the reader's token cannot assume this role and the writer's cannot assume the reader's."
  type        = string
  validation {
    condition     = can(regex("^tessera:tenant:[^:]+:aws-writer:[^:]+$", var.subject))
    error_message = "subject must be tessera:tenant:<tenant id>:aws-writer:<connector id>."
  }
}

variable "role_name" {
  description = "Name of the writer role. Tessera's target setting `aws.writer_role` must match when it is not the default."
  type        = string
  default     = "TesseraWriter"
}

variable "oidc_provider_arn" {
  description = "The IAM OIDC provider of the issuer, if the account already has one (the reader role's setup creates it). Empty creates it."
  type        = string
  default     = ""
}

variable "oidc_thumbprints" {
  description = "Thumbprints for a provider this module creates (IAM no longer validates them for the major CAs, but the API still requires one)."
  type        = list(string)
  default     = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
}

variable "tags" {
  description = "Extra tags for the role. tessera:protected=true is always set: the writer's own policy denies it any write on a protected resource, itself included."
  type        = map(string)
  default     = {}
}
