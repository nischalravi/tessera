data "tessera_roles" "payments" {
  name = "Payments approver"
}

output "payments_role_id" {
  value = one(data.tessera_roles.payments.roles[*].id)
}
