resource "tessera_approval_policy" "manager_then_owner" {
  name  = "Manager, then resource owner"
  scope = "access"
  steps_json = jsonencode([
    { id = "m", type = "approval", approver = "manager" },
    { id = "d", type = "approval", approver = "decider" },
  ])

  # leave targets out to keep the assignments as they are
  targets = [
    { kind = "request_type", target_id = "access" },
  ]
}
