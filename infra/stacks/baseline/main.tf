data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "${var.project}-trail"
  trail_arn  = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
  log_bucket = "${var.project}-cloudtrail-${local.account_id}"
}

data "aws_iam_policy_document" "trail_delivery" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${local.log_bucket}"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${local.log_bucket}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

module "trail_bucket" {
  source = "../../modules/private_bucket"

  name                    = local.log_bucket
  policy_json             = data.aws_iam_policy_document.trail_delivery.json
  expiration_days         = var.log_retention_days
  noncurrent_version_days = 30
}

resource "aws_cloudtrail" "this" {
  name                          = local.trail_name
  s3_bucket_name                = module.trail_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [module.trail_bucket]
}
