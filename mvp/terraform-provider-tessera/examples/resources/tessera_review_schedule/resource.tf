data "tessera_identities" "controller" {
  query  = "ingrid"
  status = "active"
}

# Certify privileged access every quarter; undecided items go to an escalation reviewer after the due date.
resource "tessera_review_schedule" "privileged_quarterly" {
  name            = "Quarterly privileged access review"
  recurrence      = "quarterly"
  first_run_at    = "2027-01-04T08:00:00Z"
  privileged_only = true
  unused_days     = 45
  duration_days   = 21
  reminder_days   = 5

  close_out              = "escalate"
  escalation_identity_id = data.tessera_identities.controller.identities[0].id
  escalation_days        = 10
}

# Scope a review to one system.
resource "tessera_review_schedule" "aws_annual" {
  name         = "Annual AWS review"
  system       = "aws"
  recurrence   = "annual"
  first_run_at = "2027-03-01T08:00:00Z"
}
