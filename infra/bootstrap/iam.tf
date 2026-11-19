data "aws_iam_policy_document" "guardrails" {
  statement {
    sid           = "DenyObjectReadOutsideStackState"
    effect        = "Deny"
    actions       = ["s3:GetObject", "s3:GetObjectVersion"]
    not_resources = [local.stack_state_arn]
  }

  statement {
    sid    = "DenySecretValues"
    effect = "Deny"
    actions = [
      "secretsmanager:GetSecretValue",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:GetParameterHistory",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyAuditTampering"
    effect = "Deny"
    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "s3:PutAccountPublicAccessBlock",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyStateBucketChanges"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:PutBucket*",
      "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration",
    ]
    resources = [local.state_arn]
  }

  statement {
    sid    = "DenyIamChanges"
    effect = "Deny"
    actions = [
      "iam:Add*",
      "iam:Attach*",
      "iam:Create*",
      "iam:Delete*",
      "iam:Detach*",
      "iam:PassRole",
      "iam:Put*",
      "iam:Remove*",
      "iam:Tag*",
      "iam:Untag*",
      "iam:Update*",
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "state_lock" {
  statement {
    sid       = "StateLock"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["${local.stack_state_arn}.tflock"]
  }
}

data "aws_iam_policy_document" "apply" {
  statement {
    sid       = "StateWrite"
    actions   = ["s3:PutObject"]
    resources = [local.stack_state_arn]
  }

  statement {
    sid = "ProjectBuckets"
    actions = [
      "s3:CreateBucket",
      "s3:PutBucket*",
      "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration",
    ]
    resources = ["arn:aws:s3:::${var.project}-*"]
  }

  statement {
    sid = "ProjectTrail"
    actions = [
      "cloudtrail:AddTags",
      "cloudtrail:CreateTrail",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:RemoveTags",
      "cloudtrail:StartLogging",
      "cloudtrail:UpdateTrail",
    ]
    resources = ["arn:aws:cloudtrail:*:${local.account_id}:trail/${var.project}-*"]
  }
}

resource "aws_iam_role" "plan" {
  name                 = "${var.project}-tf-plan"
  description          = "GitHub Actions terraform plan (read-only)"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_read" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy" "plan_guardrails" {
  name   = "guardrails"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.guardrails.json
}

resource "aws_iam_role_policy" "plan_lock" {
  name   = "state-lock"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.state_lock.json
}

resource "aws_iam_role" "apply" {
  name                 = "${var.project}-tf-apply"
  description          = "GitHub Actions terraform apply (environment-gated)"
  assume_role_policy   = data.aws_iam_policy_document.apply_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "apply_read" {
  role       = aws_iam_role.apply.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy" "apply_guardrails" {
  name   = "guardrails"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.guardrails.json
}

resource "aws_iam_role_policy" "apply_lock" {
  name   = "state-lock"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.state_lock.json
}

resource "aws_iam_role_policy" "apply" {
  name   = "deploy"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.apply.json
}
