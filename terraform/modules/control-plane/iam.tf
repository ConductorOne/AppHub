# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The API's task role.
#
# It holds persistence permissions and nothing else. It cannot deploy, cannot
# push an image, cannot assume the push role, and cannot read a source
# credential -- the repository's rule is that the API never holds source
# credentials, and this is the AWS half of it. The Go half is
# internal/ghappkey's write-only Store type, which serve is handed instead of
# the Reader.

data "aws_iam_policy_document" "task_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task" {
  name               = "${var.name_prefix}-api"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json

  tags = local.tags
}

data "aws_iam_policy_document" "task" {
  statement {
    sid    = "ControlPlaneState"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:BatchGetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:TransactGetItems",
      "dynamodb:TransactWriteItems",
      "dynamodb:ConditionCheckItem",
    ]
    resources = concat([var.table_arn], var.table_index_arns)
  }

  statement {
    sid    = "AuditEvents"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:TransactWriteItems",
    ]
    resources = [var.audit_table_arn]
  }

  # The init container materialises the two configuration documents. Scoped to
  # those parameters; IDs and secrets are injected by the execution role
  # through the task definition's secrets block, and this role cannot read them.
  statement {
    sid     = "ReadOwnConfiguration"
    effect  = "Allow"
    actions = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = [
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter${var.apphub_config_parameter}",
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter${var.aws_config_parameter}",
    ]
  }

  # The admin-managed GitHub App key.
  #
  # Write and existence-check only. internal/ghappkey's package documentation
  # asks for exactly this: "the operator's own IAM policy for serve's task role
  # should still be scoped to exactly ssm:PutParameter and
  # ssm:DescribeParameters (never ssm:GetParameter or kms:Decrypt) on the
  # configured parameter, as real defense in depth". Exists() calls
  # DescribeParameters, which never returns a value.
  #
  # The path is derived by cmd/apphub from the table name with no operator
  # toggle: /apphub/<tableName>/github-app/private-key.
  statement {
    sid     = "WriteGitHubAppKey"
    effect  = "Allow"
    actions = ["ssm:PutParameter", "ssm:DeleteParameter", "ssm:AddTagsToResource"]
    resources = [
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter${local.github_app_key_parameter}",
    ]
  }

  statement {
    sid       = "DescribeParameters"
    effect    = "Allow"
    actions   = ["ssm:DescribeParameters"]
    resources = ["*"]
  }

  # Belt and braces around the statement above. Nothing in the allow
  # statements currently reaches this parameter, and this makes that true
  # independently of how parameter_prefix is ever changed.
  statement {
    sid     = "NeverReadGitHubAppKey"
    effect  = "Deny"
    actions = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
    resources = [
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter${local.github_app_key_parameter}",
    ]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn == null ? [] : [1]

    content {
      sid       = "DecryptOwnParameters"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = [var.kms_key_arn]
    }
  }

  # ------------------------------------------------------------------------
  # Application secret handoff. The API encrypts a secret's value and stores
  # only the ciphertext in the control-plane table; the worker holds the
  # matching kms:Decrypt grant (modules/worker). Both statements are gated on
  # handoff_kms_key_arn being set, so an environment that never configures the
  # feature grants neither.
  # ------------------------------------------------------------------------
  dynamic "statement" {
    for_each = var.handoff_kms_key_arn == "" ? [] : [1]

    content {
      sid       = "EncryptApplicationSecrets"
      effect    = "Allow"
      actions   = ["kms:Encrypt"]
      resources = [var.handoff_kms_key_arn]

      # Every encrypt call must carry exactly this encryption context and no
      # other. ForAllValues:StringEquals alone only whitelists which context
      # keys are allowed to appear -- it does not require any of them to be
      # present -- so the three Null conditions below additionally require
      # the ciphertext to actually be bound to an application, a secret and a
      # deployment, matching what the worker's decrypt grant demands.
      condition {
        test     = "ForAllValues:StringEquals"
        variable = "kms:EncryptionContextKeys"
        values   = ["apphub:application", "apphub:secret", "apphub:deployment"]
      }

      condition {
        test     = "Null"
        variable = "kms:EncryptionContext:apphub:application"
        values   = ["false"]
      }

      condition {
        test     = "Null"
        variable = "kms:EncryptionContext:apphub:secret"
        values   = ["false"]
      }

      condition {
        test     = "Null"
        variable = "kms:EncryptionContext:apphub:deployment"
        values   = ["false"]
      }
    }
  }

  # Belt and braces around the statement above, in the same style as
  # NeverReadGitHubAppKey: the API must never be able to read back what it
  # just encrypted. Only ciphertext should ever leave the API process, and an
  # explicit deny makes that true independently of how the allow statement
  # above is ever changed.
  dynamic "statement" {
    for_each = var.handoff_kms_key_arn == "" ? [] : [1]

    content {
      sid       = "NeverDecryptSecretHandoffKey"
      effect    = "Deny"
      actions   = ["kms:Decrypt"]
      resources = [var.handoff_kms_key_arn]
    }
  }

  # Break-glass ECS Exec, granted only when the service enables it. Without
  # these four actions `enable_execute_command` is accepted by ECS and then
  # fails at session start, which reads as a broken feature rather than as a
  # missing grant.
  dynamic "statement" {
    for_each = var.enable_execute_command ? [1] : []

    content {
      sid    = "ExecuteCommandChannel"
      effect = "Allow"
      actions = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
      ]
      resources = ["*"]
    }
  }

  # The Workspace log viewer. Read-only, and only the groups the operator
  # named in observability.logGroups.
  dynamic "statement" {
    for_each = length(var.observability_log_group_arns) == 0 ? [] : [1]

    content {
      sid       = "ReadNamedLogGroups"
      effect    = "Allow"
      actions   = ["logs:FilterLogEvents", "logs:DescribeLogStreams", "logs:DescribeLogGroups"]
      resources = var.observability_log_group_arns
    }
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${var.name_prefix}-api"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

locals {
  partition = data.aws_partition.current.partition
  account   = data.aws_caller_identity.current.account_id
  region    = data.aws_region.current.region

  # cmd/apphub derives this and offers no way to configure it, so Terraform
  # derives it the same way rather than inventing a parameter for it.
  github_app_key_parameter = "/apphub/${var.table_name}/github-app/private-key"
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
