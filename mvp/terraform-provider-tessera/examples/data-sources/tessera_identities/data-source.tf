data "tessera_identities" "service_accounts" {
  type   = "service_account"
  status = "active"
}

output "service_account_names" {
  value = [for i in data.tessera_identities.service_accounts.identities : i.name]
}
