data "tessera_entitlements" "aws" {
  system = "aws"
}

# Make the first AWS entitlement requestable for up to a day, approved by its owner.
resource "tessera_catalog_item" "aws_first" {
  group_id        = data.tessera_entitlements.aws.entitlements[0].id
  requestable     = true
  risk            = "medium"
  description     = "Read-only access to the AWS sandbox."
  default_hours   = 8
  max_hours       = 24
  approval_stages = ["owner"]
}
