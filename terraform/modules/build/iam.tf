# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The build task's execution role, and only that.
#
# It belongs to the ECS agent rather than to the task: the agent assumes it to
# pull the builder image and to create the task's log stream, both before the
# container starts. It is not reachable from inside the container -- the task
# credentials endpoint serves the *task* role, which a build task deliberately
# does not have.
#
# Scoped to the two things the agent does, against this deployment's own
# resources. The managed AmazonECSTaskExecutionRolePolicy would work and is
# broader than it needs to be: it grants ECR pull on every repository in the
# account, which for the one task definition in this deployment that runs an
# image nobody in this deployment wrote is the wrong direction.

data "aws_iam_policy_document" "execution_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name_prefix}-build-execution"
  assume_role_policy = data.aws_iam_policy_document.execution_assume.json

  tags = local.tags
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "RegistryAuthorization"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  # Only when the builder image is served from this account's registry. A
  # builder pulled from a public registry needs no credential at all, and
  # granting one for it would be authority nothing uses.
  dynamic "statement" {
    for_each = var.builder_repository_arn == "" ? [] : [1]

    content {
      sid    = "PullTheBuilderImage"
      effect = "Allow"
      actions = [
        "ecr:BatchGetImage",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
      ]
      resources = [var.builder_repository_arn]
    }
  }

  statement {
    sid     = "WriteTheBuildLog"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "${aws_cloudwatch_log_group.build.arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "${var.name_prefix}-build-execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}
