# Raise an alert after 3 failed sign-ins in 20 minutes. The apply files a proposal and waits for a person to approve it
# (with a step-up sign-in) in Admin > Change requests; it fails with the change's URL if nobody does within wait_timeout.
resource "tessera_alert_rule" "signin_failures" {
  rule_id        = "signin_failures"
  enabled        = true
  severity       = "high"
  threshold      = 3
  window_minutes = 20
}
