variable "splunk_hec_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "tessera_siem_sink" "splunk" {
  name   = "Splunk"
  kind   = "webhook"
  flavor = "hec"
  format = "json"

  # write-only; bump the version with it to move the sink (the sink then also needs a new token)
  target_url         = "https://splunk.example.com:8088/services/collector"
  target_url_version = "1"

  event_filter = ["auth.*", "admin.change.*"]

  # write-only: never in the plan or the state. Rotate by changing both.
  token         = var.splunk_hec_token
  token_version = "1"
}
