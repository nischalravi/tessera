resource "tessera_sod_ruleset" "payments" {
  key         = "payments"
  name        = "Payments separation of duties"
  description = "Nobody both creates and approves a payment."
  enabled     = true
}
