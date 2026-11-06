variable "soc_webhook_signing_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "tessera_alert_channel" "soc" {
  name         = "SOC webhook"
  kind         = "webhook"
  target       = "https://hooks.example.com/services/T000/B000/XXXX" # sensitive; sealed by the server
  min_severity = "high"

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
