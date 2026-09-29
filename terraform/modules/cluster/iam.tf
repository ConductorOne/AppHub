# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The task execution role ECS itself assumes to start AppHub's own tasks: pull
# the image, create the log stream, read the parameters named in a task
# definition's `secrets` block.
#
# It is not the workload's identity. Nothing AppHub's code does runs with this
# role, and it is deliberately separate from the roles in modules/deploy-target
# that deployed applications get: an execution role is the agent that starts a
# task, a task role is the task.

data "aws_iam_policy_document" "ecs_assume" {
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
  name               = "${var.name_prefix}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# The managed policy above covers ECR and CloudWatch Logs. Parameter reads are
# scoped here, to this deployment's own parameter tree, rather than granted
# account-wide.
data "aws_iam_policy_document" "execution_parameters" {
  statement {
    sid     = "ReadOwnParameters"
    effect  = "Allow"
    actions = ["ssm:GetParameters", "ssm:GetParameter"]
    resources = [
      "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${var.parameter_prefix}/*",
    ]
  }
}

resource "aws_iam_role_policy" "execution_parameters" {
  name   = "${var.name_prefix}-execution-parameters"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_parameters.json
}

data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
