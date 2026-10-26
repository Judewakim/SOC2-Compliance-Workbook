terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Read-only role for soc2kit. No long-lived access keys are created:
# the scanner assumes this role with STS and must present the External ID.
data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.trusted_principal_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "scan" {
  name                 = var.role_name
  description          = "Read-only role for soc2kit SOC 2 evidence collection"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "scan" {
  name   = "soc2kit-readonly"
  role   = aws_iam_role.scan.id
  policy = file("${path.module}/../soc2kit-readonly-policy.json")
}
