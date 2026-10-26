# The Tessera AWS write role (issue #660, least-privilege loop LP-4; design docs/design/least-privilege-loop.md §6.3).
#
# Apply it in each account Tessera may change, after the reader role (TesseraReader) is in place. It is a different
# role from the reader, with its own trust: only a token whose subject is the writer subject can assume it. Tessera
# uses it to take access away (detach and delete policies, a new default version of a policy, remove a user from a
# group, delete an Identity Center assignment) and to put it back, and re-reads every change with the READER role: the
# role that wrote never certifies its own change.
#
# Nothing is written until write-back is switched on for the AWS target in Tessera, which takes a second admin.
#
# The permissions policy is writer-policy.json, which a Tessera test keeps equal to awsorg.WriterPolicy().

locals {
  issuer_host       = trimprefix(var.issuer_url, "https://")
  create_oidc       = var.oidc_provider_arn == ""
  oidc_provider_arn = local.create_oidc ? aws_iam_openid_connect_provider.tessera[0].arn : var.oidc_provider_arn
}

resource "aws_iam_openid_connect_provider" "tessera" {
  count           = local.create_oidc ? 1 : 0
  url             = var.issuer_url
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = var.oidc_thumbprints
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.issuer_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.issuer_host}:sub"
      values   = [var.subject]
    }
  }
}

resource "aws_iam_role" "writer" {
  name                 = var.role_name
  description          = "Tessera least-privilege write role: revokes and restores access. Verified by the reader role."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = merge(var.tags, { "tessera:protected" = "true" })
}

resource "aws_iam_role_policy" "writer" {
  name   = "TesseraRevokeAndRestore"
  role   = aws_iam_role.writer.id
  policy = file("${path.module}/writer-policy.json")
}
