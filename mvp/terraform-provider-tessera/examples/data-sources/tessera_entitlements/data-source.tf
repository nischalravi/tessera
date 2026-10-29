data "tessera_entitlements" "aws_privileged" {
  system = "aws"
}

output "aws_privileged_entitlements" {
  value = [for e in data.tessera_entitlements.aws_privileged.entitlements : e.name if e.privileged]
}
