# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The worker's identity.
#
# This is the credential-bearing half of AppHub. It deploys, it reads source
# credentials, and it mints push sessions -- which is exactly why the API's role
# (modules/control-plane) holds none of those. The separation is the
# repository's stated rule: "Give the API only its persistence permissions. Give
# the dedicated worker scoped compute/persistence/source/push permissions, never
# upstream login secrets."
#
# The name is fixed rather than generated, because modules/deploy-target writes
# it into the push role's trust policy before this role exists.

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "worker" {
  name               = var.role_name
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = local.tags
}

# Everything the worker may do to the deployment target, written once in
# modules/deploy-target.
resource "aws_iam_role_policy_attachment" "deploy" {
  count      = length(var.deploy_policy_arns)
  role       = aws_iam_role.worker.name
  policy_arn = var.deploy_policy_arns[count.index]
}

moved {
  from = aws_iam_role_policy_attachment.deploy
  to   = aws_iam_role_policy_attachment.deploy[0]
}

data "aws_iam_policy_document" "worker" {
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
    sid    = "AppendAuditEvents"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:TransactWriteItems",
    ]
    resources = [var.audit_table_arn]
  }

  statement {
    sid     = "ReadOwnConfiguration"
    effect  = "Allow"
    actions = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = concat([
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter${var.apphub_config_parameter}",
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter${var.aws_config_parameter}",
      ], var.rds_ca_parameter == null ? [] : [
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter${var.rds_ca_parameter}",
    ])
  }

  # The admin-managed GitHub App key. The worker holds internal/ghappkey's
  # Reader; the API is only ever handed the write-only Store. The path is
  # derived by cmd/apphub from the table name and is not configurable.
  statement {
    sid     = "ReadGitHubAppKey"
    effect  = "Allow"
    actions = ["ssm:GetParameter"]
    resources = [
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter/apphub/${var.table_name}/github-app/private-key",
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
  # Application secret handoff. The matching kms:Encrypt grant, and the
  # explicit deny on this worker's own action, belong to the API
  # (modules/control-plane). This is the only principal that can turn the
  # ciphertext back into a plaintext value, which it then writes as an SSM
  # SecureString under secret_path_prefix (the deploy policy's
  # ManageApplicationParameters statement in modules/deploy-target).
  # ------------------------------------------------------------------------
  dynamic "statement" {
    for_each = var.handoff_kms_key_arn == "" ? [] : [1]

    content {
      sid       = "DecryptApplicationSecrets"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = [var.handoff_kms_key_arn]

      # The same exact-context requirement as the API's encrypt grant
      # (modules/control-plane): a ciphertext decrypts only if it is bound to
      # an application, a secret and a deployment, and to nothing else.
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

  # ------------------------------------------------------------------------
  # Builds.
  #
  # RunTask is scoped to the build task definition families, the build cluster
  # and an immutable-at-launch marker. StopTask requires that marker on the
  # task; a separate tag-on-create grant cannot tag an existing task.
  # ListTasks and DescribeTasks are read-only reconciliation surfaces.
  # ------------------------------------------------------------------------
  statement {
    sid     = "RunBuilds"
    effect  = "Allow"
    actions = ["ecs:RunTask"]
    resources = [
      for family in var.build_task_definition_families :
      "arn:${local.partition}:ecs:${local.region}:${local.account}:task-definition/${family}:*"
    ]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.build_cluster_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/apphub:build-task"
      values   = ["true"]
    }
  }

  # Tagging during RunTask is atomic: ECS refuses the launch if the tag cannot
  # be attached. There is no permission to tag an existing task, so the worker
  # cannot add this marker to an API or ingress task to gain StopTask access.
  statement {
    sid       = "TagBuildsOnLaunch"
    effect    = "Allow"
    actions   = ["ecs:TagResource"]
    resources = ["arn:${local.partition}:ecs:${local.region}:${local.account}:task/${var.build_cluster_name}/*"]

    condition {
      test     = "StringEquals"
      variable = "ecs:CreateAction"
      values   = ["RunTask"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/apphub:build-task"
      values   = ["true"]
    }
  }

  statement {
    sid       = "ListBuildsForSlotReconciliation"
    effect    = "Allow"
    actions   = ["ecs:ListTasks"]
    resources = ["*"]
  }

  statement {
    sid       = "DescribeBuilds"
    effect    = "Allow"
    actions   = ["ecs:DescribeTasks"]
    resources = ["arn:${local.partition}:ecs:${local.region}:${local.account}:task/${var.build_cluster_name}/*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.build_cluster_arn]
    }
  }

  statement {
    sid       = "StopTaggedBuilds"
    effect    = "Allow"
    actions   = ["ecs:StopTask"]
    resources = ["arn:${local.partition}:ecs:${local.region}:${local.account}:task/${var.build_cluster_name}/*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.build_cluster_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "ecs:ResourceTag/apphub:build-task"
      values   = ["true"]
    }
  }

  # Read back, so the runner can refuse a build task definition that carries a
  # task role or mounts no access point. DescribeTaskDefinition takes no
  # resource-level ARN.
  statement {
    sid       = "InspectBuildTaskDefinitions"
    effect    = "Allow"
    actions   = ["ecs:DescribeTaskDefinition"]
    resources = ["*"]
  }

  # RunTask passes the build task's execution role to ECS. Only that role, and
  # only to ECS: the worker can start a build, not mint an identity for
  # something else.
  statement {
    sid       = "PassTheBuildExecutionRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [var.build_execution_role_arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }

  # The builder's output, read back and handed to the caller's log writer. Read
  # only: the build task writes its own stream through the ECS agent.
  statement {
    sid       = "ReadTheBuildLog"
    effect    = "Allow"
    actions   = ["logs:GetLogEvents"]
    resources = ["${var.build_log_group_arn}:*"]
  }

  statement {
    sid       = "WriteOwnLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.worker.arn}:*"]
  }

  # ------------------------------------------------------------------------
  # Per-application traffic tracking. Every five minutes the worker runs a
  # Logs Insights query over the Traefik access-log group and turns the
  # result into per-application traffic counters -- read-only, and never a
  # grant on any other log group. Gated on traffic_log_group_arn so an
  # environment that leaves modules/config's traffic_log_group empty (the
  # feature off) grants neither statement.
  # ------------------------------------------------------------------------
  dynamic "statement" {
    for_each = var.traffic_log_group_arn == "" ? [] : [1]

    content {
      sid       = "QueryIngressAccessLogs"
      effect    = "Allow"
      actions   = ["logs:StartQuery"]
      resources = ["${var.traffic_log_group_arn}:*"]
    }
  }

  dynamic "statement" {
    for_each = var.traffic_log_group_arn == "" ? [] : [1]

    content {
      sid    = "ReadIngressQueryResults"
      effect = "Allow"
      actions = [
        "logs:GetQueryResults",
        "logs:StopQuery",
      ]
      # GetQueryResults and StopQuery take a query id, not a log group, so
      # neither action supports resource-level permissions -- "*" is the only
      # resource AWS accepts for them, not a broadening of what the worker
      # can query. What log group a query may run against is scoped entirely
      # by QueryIngressAccessLogs above.
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "worker" {
  name   = "${var.name_prefix}-worker"
  role   = aws_iam_role.worker.id
  policy = data.aws_iam_policy_document.worker.json
}

locals {
  partition = data.aws_partition.current.partition
  account   = data.aws_caller_identity.current.account_id
  region    = data.aws_region.current.region
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
