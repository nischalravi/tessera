data "tessera_identities" "owner" {
  query = "ingrid"
}

resource "tessera_mitigating_control" "monthly_review" {
  name                 = "Monthly access review by the CFO"
  description          = "The CFO reviews every payment approver each month."
  owner_identity_id    = data.tessera_identities.owner.identities[0].id
  type                 = "detective"
  frequency            = "monthly"
  evidence_requirement = "The signed review report."
}
