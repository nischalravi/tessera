# Needs the auditor role on the machine client as well as tessera:read.
data "tessera_connectors" "okta" {
  system = "okta"
}

# Name a review schedule after the system it certifies.
resource "tessera_review_schedule" "okta" {
  name         = "Review of ${data.tessera_connectors.okta.connectors[0].system}"
  system       = data.tessera_connectors.okta.connectors[0].system
  recurrence   = "semiannual"
  first_run_at = "2027-02-01T08:00:00Z"
}
