variable "okta_api_token" {
  type      = string
  sensitive = true
  ephemeral = true # Terraform 1.10+; the value never reaches the plan or the state
}

resource "tessera_connection" "okta" {
  name           = "Okta production"
  connector_type = "okta"
  config_json    = jsonencode({ org_url = "https://acme.okta.com" })

  # write-only: never in the plan or the state. Change the version with the secret to send the new one.
  secret         = var.okta_api_token
  secret_version = "1"
}

# The server creates the connection in draft. Validating, dry-running and activating it stay steps a person takes.
