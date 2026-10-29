data "tessera_entitlements" "aws" {
  system = "aws"
}

# A role that bundles two entitlements. The key never changes; the apply waits for a person to approve the proposal.
resource "tessera_business_role" "engineer" {
  key         = "engineer"
  name        = "Engineer"
  description = "Day-to-day engineering access."
  risk        = "medium"
  requestable = true
  entitlement_group_ids = [
    data.tessera_entitlements.aws.entitlements[0].id,
    data.tessera_entitlements.aws.entitlements[1].id,
  ]
  note = "Managed with Terraform."
}
