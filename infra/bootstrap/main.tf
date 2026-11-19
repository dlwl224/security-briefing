data "aws_caller_identity" "current" {}

locals {
  account_id      = data.aws_caller_identity.current.account_id
  state_bucket    = "${var.project}-tfstate-${local.account_id}"
  state_arn       = "arn:aws:s3:::${local.state_bucket}"
  stack_state_arn = "${local.state_arn}/stacks/*"
  oidc_host       = "token.actions.githubusercontent.com"
}

module "state_bucket" {
  source = "../modules/private_bucket"

  name                    = local.state_bucket
  noncurrent_version_days = 90
}

resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
