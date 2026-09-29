# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The role a build's image push runs as.
#
# It exists because the build itself must not hold a registry credential. A
# Dockerfile RUN instruction executes code out of the repository being built,
# so a builder that pushes is a builder whose environment holds a live push
# token for whoever wrote that repository. AppHub splits the two: kaniko writes
# a tarball with no credential at all, and a separate process assumes this role
# to upload it (BuildConfig.PushRoleARN, and compute/aws/pushcreds.go for the
# session policy that narrows each assumption to the repositories one build may
# touch).
#
# So the grant below is the *ceiling*: pushing to the AppHub registry
# namespace. Each individual build gets a session credential scoped further,
# for fifteen minutes.

data "aws_iam_policy_document" "push_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.worker_role_arn]
    }
  }
}

# Terraform-managed roles live at the root; the worker's path-qualified
# workload-role grants must not match the role it can assume.
resource "aws_iam_role" "push" {
  name                 = "${var.name_prefix}-ecr-push"
  path                 = "/"
  assume_role_policy   = data.aws_iam_policy_document.push_assume.json
  permissions_boundary = aws_iam_policy.push_boundary.arn
  max_session_duration = 3600

  tags = local.tags
}

data "aws_iam_policy_document" "push" {
  # GetAuthorizationToken has no resource-level ARN: the API returns a token
  # for the whole registry and is authorised on "*" or not at all. The token it
  # returns is still only usable where the statement below allows.
  statement {
    sid       = "RegistryAuthorization"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "PushToAppHubRepositories"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [local.repository_arn_pattern]
  }
}

# The inline grant alone is not a ceiling: a new policy (including
# AdministratorAccess) would otherwise expand an assumed push session. Keep
# the boundary on the role itself, independent of the caller's session policy.
resource "aws_iam_policy" "push_boundary" {
  name        = "${var.name_prefix}-ecr-push-boundary"
  description = "ECR-only ceiling on the AppHub image push role"
  policy      = data.aws_iam_policy_document.push.json

  tags = local.tags
}

resource "aws_iam_role_policy" "push" {
  name   = "${var.name_prefix}-ecr-push"
  role   = aws_iam_role.push.id
  policy = data.aws_iam_policy_document.push.json
}
