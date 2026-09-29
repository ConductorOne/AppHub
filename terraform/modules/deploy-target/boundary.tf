# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The permissions boundary on every role AppHub creates -- the workload's own
# identity and the per-service task execution role alike.
#
# compute/aws/config.go permits an empty boundary and says what that costs:
# "without a boundary, the ceiling on what any role apphub creates can ever be
# granted is whatever apphub's own principal may grant." The worker's principal
# can create roles and attach policies to them, so without this the ceiling is
# the worker's own authority and a compromised deploy path could mint a role
# more powerful than the worker.
#
# A boundary is a ceiling, not a grant. A role still holds nothing until
# AppHub's granter ports attach something; this only decides what the attached
# policy can ever mean.

data "aws_iam_policy_document" "workload_boundary" {
  # The floor: the ordinary runtime surface a deployed application needs, plus
  # whatever compute.Granter attaches to it for a table or a bucket it asked
  # for.
  statement {
    sid    = "AllowApplicationRuntime"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "kms:Decrypt",
      "dynamodb:*",
      "s3:*",
      "sqs:*",
      "sns:*",
      "rds-db:connect",
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }

  # The task execution role creates the application's log group on first start
  # (awslogs-create-group). CreateLogStream does not authorize that call, and
  # CloudWatch authorizes CreateLogGroup on the group ARN itself. Scoped to the
  # application prefix so a workload cannot create groups anywhere else.
  statement {
    sid     = "AllowApplicationLogGroupCreate"
    effect  = "Allow"
    actions = ["logs:CreateLogGroup"]
    resources = [
      "arn:${local.partition}:logs:${local.region}:${local.account}:log-group:${var.app_log_group_prefix}*",
    ]
  }

  # Nothing AppHub creates may create, alter or assume an identity. This is the
  # privilege-escalation path a boundary exists to close: a workload that can
  # write IAM can write itself a policy the boundary was supposed to cap.
  statement {
    sid    = "DenyIdentityMutation"
    effect = "Deny"
    actions = [
      "iam:*",
      "sts:AssumeRole",
      "organizations:*",
      "account:*",
    ]
    resources = ["*"]
  }

  # AppHub's control-plane and audit tables and its own parameter tree are off
  # limits to everything AppHub deploys. An application that could write state
  # could grant itself an owner; one that could write audit events could forge
  # its own history.
  statement {
    sid     = "DenyControlPlaneState"
    effect  = "Deny"
    actions = ["dynamodb:*"]
    resources = [
      var.control_plane_table_arn,
      "${var.control_plane_table_arn}/*",
      var.audit_table_arn,
      "${var.audit_table_arn}/*",
    ]
  }

  statement {
    sid     = "DenyControlPlaneParameters"
    effect  = "Deny"
    actions = ["ssm:*"]
    resources = [
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter${var.control_plane_parameter_prefix}",
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter${var.control_plane_parameter_prefix}/*",
    ]
  }
}

resource "aws_iam_policy" "workload_boundary" {
  name        = "${var.name_prefix}-workload-boundary"
  path        = var.identity_path_prefix
  description = "Permissions ceiling on every IAM role AppHub creates"
  policy      = data.aws_iam_policy_document.workload_boundary.json

  tags = local.tags
}
