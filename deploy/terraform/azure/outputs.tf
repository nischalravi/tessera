output "public_url" {
  description = "Use as TESSERA_PUBLIC_URL (already set on the app) and for the IdP redirect URIs."
  value       = local.public_url
}

output "app_fqdn" {
  value = azurerm_container_app.this.ingress[0].fqdn
}

output "key_vault_name" {
  value = azurerm_key_vault.this.name
}

output "postgres_fqdn" {
  description = "Private FQDN, use it in both DSNs with sslmode=require (or verify-full with the DigiCert roots)."
  value       = azurerm_postgresql_flexible_server.this.fqdn
}

output "app_identity_client_id" {
  value = azurerm_user_assigned_identity.app.client_id
}
