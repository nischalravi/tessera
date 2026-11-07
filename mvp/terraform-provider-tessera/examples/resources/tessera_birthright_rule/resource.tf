resource "tessera_birthright_rule" "finance_staff" {
  name        = "Finance staff"
  description = "Everyone in the Finance department."
  condition_json = jsonencode({
    attr  = "identity.department"
    op    = "eq"
    value = "Finance"
  })
}
