variable "soc_webhook_url" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "soc_webhook_signing_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "tessera_alert_channel" "soc" {
  name         = "SOC webhook"
  kind         = "webhook"
  min_severity = "high"

  # the URL usually carries a token: write-only, never in the plan or the state. The state keeps target_origin; the
  # approver confirms the whole URL with Check this URL in the admin center.
  target_url         = var.soc_webhook_url
  target_url_version = "1"

  # the receiver verifies the HMAC signature with this secret; write-only
  signing_secret         = var.soc_webhook_signing_secret
  signing_secret_version = "1"
}

resource "tessera_alert_channel" "mail" {
  name         = "SOC mailbox"
  kind         = "email"
  target       = "soc@example.com, secops@example.com"
  min_severity = "critical"
}
