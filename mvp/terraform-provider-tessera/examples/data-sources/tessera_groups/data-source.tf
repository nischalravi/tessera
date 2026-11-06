data "tessera_groups" "privileged_aws" {
  system     = "aws"
  privileged = true
}

output "privileged_aws_groups" {
  value = [for g in data.tessera_groups.privileged_aws.groups : g.name]
}
