# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The authority the deployment worker operates the target with.
#
# It is deliberately one file for one principal, rather than grants spread
# across the modules that happen to own each resource: this file *is* the
# answer to "what can a deploy do", and that question should have one place to
# read it. IAM caps a managed policy at 6,144 characters, so this file
# renders core, network and optional-port grants as separate managed policies.
#
# Scoping follows what each API can express. Resource-level ARNs are confined
# to application prefixes; EC2 describes, ECS list/describe calls without
# resource-level authorization and ECR authorization tokens remain read-only on
# "*". ECS registrations use task-definition ARNs, not "*".

data "aws_iam_policy_document" "deploy" {
  # --------------------------------------------------------------------------
  # Container services. The service ARN is the only grant for service mutation;
  # task-definition registration and RunTask use the application's task family.
  # ECS task ARNs carry an opaque ID rather than a family, so no StopTask or
  # ExecuteCommand grant is safe on a cluster shared with the control plane.
  statement {
    sid    = "ManageApplicationServices"
    effect = "Allow"
    actions = [
      "ecs:CreateService",
      "ecs:UpdateService",
      "ecs:DeleteService",
      "ecs:DescribeServices",
      "ecs:TagResource",
      "ecs:UntagResource",
      "ecs:ListTagsForResource",
    ]
    resources = [
      "arn:${local.partition}:ecs:${local.region}:${local.account}:service/${var.cluster_name}/${var.container_name_prefix}*",
    ]
  }

  statement {
    sid       = "RegisterApplicationTaskDefinitions"
    effect    = "Allow"
    actions   = ["ecs:RegisterTaskDefinition", "ecs:TagResource", "ecs:ListTagsForResource"]
    resources = ["arn:${local.partition}:ecs:${local.region}:${local.account}:task-definition/${var.container_name_prefix}*:*"]
  }

  statement {
    sid       = "RunApplicationTasks"
    effect    = "Allow"
    actions   = ["ecs:RunTask"]
    resources = ["arn:${local.partition}:ecs:${local.region}:${local.account}:task-definition/${var.container_name_prefix}*:*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = ["arn:${local.partition}:ecs:${local.region}:${local.account}:cluster/${var.cluster_name}"]
    }
  }

  statement {
    sid       = "ReadApplicationTaskDefinitions"
    effect    = "Allow"
    actions   = ["ecs:DescribeTaskDefinition", "ecs:ListServices", "ecs:ListTasks", "ecs:DescribeClusters"]
    resources = ["*"]
  }

  # An explicit backstop even if the operator chooses a broader application
  # prefix. RegisterTaskDefinition accepts a task-definition ARN; unlike the
  # historical assumption above, it no longer needs a grant on "*".
  statement {
    sid    = "NeverMutateControlPlaneServices"
    effect = "Deny"
    actions = [
      "ecs:CreateService",
      "ecs:UpdateService",
      "ecs:DeleteService",
      "ecs:TagResource",
      "ecs:UntagResource",
      "ecs:RegisterTaskDefinition",
    ]
    resources = concat(
      [for suffix in ["api", "worker", "traefik", "oauth2-proxy"] :
      "arn:${local.partition}:ecs:${local.region}:${local.account}:service/${var.cluster_name}/${var.control_plane_name_prefix}${suffix}"],
      [for suffix in ["api", "worker", "traefik", "oauth2-proxy"] :
      "arn:${local.partition}:ecs:${local.region}:${local.account}:task-definition/${var.control_plane_name_prefix}${suffix}:*"],
    )
  }

  # --------------------------------------------------------------------------
  # Workload identity.
  #
  # The condition on CreateRole is the load-bearing line in this file. Without
  # it the permissions boundary is advisory: the worker could create a role
  # without one and then attach anything it is itself allowed to attach. With
  # it, every role AppHub creates is capped by modules/deploy-target's boundary
  # or is not created at all.
  # --------------------------------------------------------------------------
  statement {
    sid       = "CreateBoundedWorkloadRoles"
    effect    = "Allow"
    actions   = ["iam:CreateRole"]
    resources = [local.workload_role_arn_pattern, local.execution_role_arn_pattern]

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [aws_iam_policy.workload_boundary.arn]
    }
  }

  # GetRole before the role exists is matched on the name, without the path.
  # See workload_role_name_arn_pattern.
  statement {
    sid     = "ReadRolesBeforeTheyExist"
    effect  = "Allow"
    actions = ["iam:GetRole"]
    resources = [
      local.workload_role_name_arn_pattern,
      local.execution_role_name_arn_pattern,
    ]
  }

  statement {
    sid    = "ManageWorkloadRoles"
    effect = "Allow"
    actions = [
      "iam:GetRole",
      "iam:DeleteRole",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:ListRoleTags",
      "iam:UpdateAssumeRolePolicy",
      "iam:PutRolePolicy",
      "iam:GetRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:ListRolePolicies",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies",
    ]
    resources = [local.workload_role_arn_pattern, local.execution_role_arn_pattern]
  }

  # The push role is Terraform-owned, not a workload role. Deny by exact ARN,
  # including its former workload-path ARN during an upgrade. Even a broader
  # identity/execution prefix must not let the worker rewrite a role it can
  # assume.
  statement {
    sid     = "NeverMutatePushRole"
    effect  = "Deny"
    actions = ["iam:*"]
    resources = [
      aws_iam_role.push.arn,
      "arn:${local.partition}:iam::${local.account}:role${var.identity_path_prefix}${var.name_prefix}-ecr-push",
    ]
  }

  # ECS is the only service allowed to be handed one of these roles, so a
  # compromised worker cannot pass a role it created to a service that would
  # run arbitrary code under it somewhere else.
  statement {
    sid       = "PassWorkloadRolesToECS"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [local.workload_role_arn_pattern, local.execution_role_arn_pattern]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com", "scheduler.amazonaws.com"]
    }
  }

  # --------------------------------------------------------------------------
  # Image registry.
  # --------------------------------------------------------------------------
  statement {
    sid       = "RegistryAuthorization"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "ManageApplicationRepositories"
    effect = "Allow"
    actions = [
      "ecr:CreateRepository",
      "ecr:DeleteRepository",
      "ecr:DescribeRepositories",
      "ecr:DescribeImages",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:ListTagsForResource",
      "ecr:TagResource",
      "ecr:UntagResource",
      "ecr:PutImageScanningConfiguration",
      "ecr:PutImageTagMutability",
      "ecr:GetLifecyclePolicy",
      "ecr:PutLifecyclePolicy",
      # An empty retention spec converges by deleting the policy. A repository
      # that never had one still receives DeleteLifecyclePolicy, and a denial
      # there is the image-repository failure.
      "ecr:DeleteLifecyclePolicy",
      "ecr:SetRepositoryPolicy",
      "ecr:GetRepositoryPolicy",
    ]
    resources = [local.repository_arn_pattern]
  }

  # The build's own push credential. Nothing else: this is the only assumption
  # the worker is allowed to make, so a build cannot chain into another role.
  statement {
    sid       = "AssumePushRole"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.push.arn]
  }

  # --------------------------------------------------------------------------
  # Application secrets. The provider writes a database password or an
  # operator-supplied value under its own parameter hierarchy and reads it back
  # to bind it to a task definition.
  # --------------------------------------------------------------------------
  statement {
    sid    = "ManageApplicationParameters"
    effect = "Allow"
    actions = [
      "ssm:PutParameter",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:DeleteParameter",
      "ssm:AddTagsToResource",
      "ssm:ListTagsForResource",
    ]
    resources = [
      "arn:${local.partition}:ssm:${local.region}:${local.account}:parameter${var.secret_path_prefix}/*",
    ]
  }

  statement {
    sid       = "DescribeParameters"
    effect    = "Allow"
    actions   = ["ssm:DescribeParameters"]
    resources = ["*"]
  }

  # --------------------------------------------------------------------------
  # Application log groups, created per application under the configured
  # prefix.
  # --------------------------------------------------------------------------
  statement {
    sid    = "ManageApplicationLogGroups"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:DescribeLogGroups",
      "logs:PutRetentionPolicy",
      "logs:TagResource",
      "logs:ListTagsForResource",
    ]
    resources = [
      "arn:${local.partition}:logs:${local.region}:${local.account}:log-group:${var.app_log_group_prefix}*",
    ]
  }

  # --------------------------------------------------------------------------
  # Scheduled execution. compute.ExecutionScheduled installs an EventBridge
  # schedule that runs the task; removing the schedule stops future dispatch
  # and nothing else.
  # --------------------------------------------------------------------------
  statement {
    sid    = "ManageApplicationSchedules"
    effect = "Allow"
    actions = [
      "scheduler:CreateSchedule",
      "scheduler:UpdateSchedule",
      "scheduler:DeleteSchedule",
      "scheduler:GetSchedule",
      "scheduler:ListSchedules",
      "scheduler:TagResource",
      "scheduler:ListTagsForResource",
    ]
    resources = [
      "arn:${local.partition}:scheduler:${local.region}:${local.account}:schedule/*/${var.container_name_prefix}*",
    ]
  }

  # Deployment authority must never manage either Terraform-owned state table.
  # Do not deny worker data-plane access: its own IAM policy must still read and
  # write control-plane records and append audit events. This explicit deny
  # remains a backstop if a prefix is broadened during an upgrade.
  statement {
    sid    = "NeverManageControlPlaneTables"
    effect = "Deny"
    actions = [
      "dynamodb:CreateTable",
      "dynamodb:DeleteTable",
      "dynamodb:UpdateTable",
      "dynamodb:UpdateTimeToLive",
      "dynamodb:TagResource",
      "dynamodb:UntagResource",
    ]
    resources = [var.control_plane_table_arn, var.audit_table_arn]
  }
}

# Security-group grants live in their own managed policy so the core policy
# stays under IAM's 6,144-character limit after the service/table denials.
data "aws_iam_policy_document" "deploy_network" {
  # --------------------------------------------------------------------------
  # Per-application networking.
  # Both EC2 adapters tag new groups in CreateSecurityGroup. Standalone
  # CreateTags must never be able to mark an unowned group as owned: that would
  # turn the mutation grant below into authority over Terraform-owned groups.
  statement {
    sid    = "DescribeNetwork"
    effect = "Allow"
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeAvailabilityZones",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "CreateOwnedSecurityGroups"
    effect    = "Allow"
    actions   = ["ec2:CreateSecurityGroup"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account}:security-group/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${var.resource_tag_key}"
      values   = [var.resource_tag_value]
    }
  }

  # EC2 evaluates CreateSecurityGroup against both the new group and its VPC.
  # RequestTag exists on the former; the existing VPC must be allowed separately.
  statement {
    sid       = "CreateGroupsOnlyInTargetVpc"
    effect    = "Allow"
    actions   = ["ec2:CreateSecurityGroup"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account}:vpc/${var.vpc_id}"]
  }

  statement {
    sid     = "TagNewGroupsAndRules"
    effect  = "Allow"
    actions = ["ec2:CreateTags"]
    resources = [
      "arn:${local.partition}:ec2:${local.region}:${local.account}:security-group/*",
      "arn:${local.partition}:ec2:${local.region}:${local.account}:security-group-rule/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSecurityGroup", "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${var.resource_tag_key}"
      values   = [var.resource_tag_value]
    }
  }

  statement {
    sid       = "RetagOwnedSecurityGroups"
    effect    = "Allow"
    actions   = ["ec2:CreateTags", "ec2:DeleteTags"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account}:security-group/*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/${var.resource_tag_key}"
      values   = [var.resource_tag_value]
    }
  }

  statement {
    sid       = "RetagOwnedSecurityGroupRules"
    effect    = "Allow"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account}:security-group-rule/*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/${var.resource_tag_key}"
      values   = [var.resource_tag_value]
    }
  }

  statement {
    sid    = "ManageApplicationSecurityGroups"
    effect = "Allow"
    actions = [
      "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifySecurityGroupRules",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/${var.resource_tag_key}"
      values   = [var.resource_tag_value]
    }
  }

}

# ------------------------------------------------------------------------------
# Optional ports. Each is off unless the provider configuration offers the
# matching capability, because a grant for a port nobody configured is
# authority nothing can account for.
# ------------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy_ports" {
  dynamic "statement" {
    for_each = var.enable_key_value_port ? [1] : []

    content {
      sid    = "ManageApplicationTables"
      effect = "Allow"
      actions = [
        "dynamodb:CreateTable",
        "dynamodb:DeleteTable",
        "dynamodb:DescribeTable",
        "dynamodb:UpdateTable",
        "dynamodb:UpdateTimeToLive",
        "dynamodb:DescribeTimeToLive",
        "dynamodb:TagResource",
        "dynamodb:UntagResource",
        "dynamodb:ListTagsOfResource",
      ]
      resources = [
        "arn:${local.partition}:dynamodb:${local.region}:${local.account}:table/${var.key_value_name_prefix}*",
      ]
    }
  }

  dynamic "statement" {
    for_each = var.enable_object_store_port ? [1] : []

    content {
      sid    = "ManageApplicationBuckets"
      effect = "Allow"
      actions = [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:GetBucketTagging",
        "s3:PutBucketTagging",
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        "s3:PutEncryptionConfiguration",
        "s3:GetEncryptionConfiguration",
        "s3:PutBucketVersioning",
        "s3:GetBucketVersioning",
        "s3:ListBucketVersions",
      ]
      resources = [
        "arn:${local.partition}:s3:::${var.object_store_name_prefix}*",
      ]
    }
  }

  # Deleting an application empties its bucket (compute.ObjectStore.EmptyBucket)
  # before deleting it, including every noncurrent version. Object-level
  # actions take the object ARN, not the bucket's.
  dynamic "statement" {
    for_each = var.enable_object_store_port ? [1] : []

    content {
      sid    = "EmptyApplicationBuckets"
      effect = "Allow"
      actions = [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
      ]
      resources = [
        "arn:${local.partition}:s3:::${var.object_store_name_prefix}*/*",
      ]
    }
  }

  dynamic "statement" {
    for_each = var.enable_relational_port ? [1] : []

    content {
      sid    = "ManageApplicationDatabases"
      effect = "Allow"
      actions = [
        "rds:CreateDBCluster",
        "rds:DeleteDBCluster",
        "rds:DescribeDBClusters",
        "rds:ModifyDBCluster",
        "rds:CreateDBInstance",
        "rds:DeleteDBInstance",
        "rds:DescribeDBInstances",
        "rds:CreateDBSubnetGroup",
        "rds:DeleteDBSubnetGroup",
        "rds:DescribeDBSubnetGroups",
        "rds:AddTagsToResource",
        "rds:ListTagsForResource",
      ]
      resources = [
        "arn:${local.partition}:rds:${local.region}:${local.account}:cluster:${var.relational_name_prefix}*",
        "arn:${local.partition}:rds:${local.region}:${local.account}:db:${var.relational_name_prefix}*",
        "arn:${local.partition}:rds:${local.region}:${local.account}:subgrp:${var.relational_name_prefix}*",
      ]
    }
  }

  dynamic "statement" {
    for_each = var.enable_function_port ? [1] : []

    content {
      sid    = "ManageApplicationFunctions"
      effect = "Allow"
      actions = [
        "lambda:CreateFunction",
        "lambda:DeleteFunction",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:TagResource",
        "lambda:ListTags",
        "lambda:AddPermission",
        "lambda:RemovePermission",
      ]
      resources = [
        "arn:${local.partition}:lambda:${local.region}:${local.account}:function:${var.function_name_prefix}*",
      ]
    }
  }

  # ELBv2 authorizes CreateListener on its parent load balancer, whereas
  # DeleteListener authorizes the listener ARN. No listener grant is on "*".
  dynamic "statement" {
    for_each = var.enable_function_port ? [1] : []

    content {
      sid       = "ManageApplicationLoadBalancers"
      effect    = "Allow"
      actions   = ["elasticloadbalancing:CreateLoadBalancer", "elasticloadbalancing:DeleteLoadBalancer", "elasticloadbalancing:CreateListener"]
      resources = [local.endpoint_load_balancer_arn_pattern]
    }
  }

  dynamic "statement" {
    for_each = var.enable_function_port ? [1] : []

    content {
      sid       = "ManageApplicationTargetGroups"
      effect    = "Allow"
      actions   = ["elasticloadbalancing:CreateTargetGroup", "elasticloadbalancing:DeleteTargetGroup", "elasticloadbalancing:RegisterTargets", "elasticloadbalancing:DeregisterTargets"]
      resources = [local.endpoint_target_group_arn_pattern]
    }
  }

  dynamic "statement" {
    for_each = var.enable_function_port ? [1] : []

    content {
      sid       = "DeleteApplicationListeners"
      effect    = "Allow"
      actions   = ["elasticloadbalancing:DeleteListener"]
      resources = [local.endpoint_listener_arn_pattern]
    }
  }

  # ELBv2 evaluates AddTags separately for tags passed to CreateLoadBalancer
  # and CreateTargetGroup. Creation-time tags are allowed only for those
  # actions and only under the application's own ARN namespace.
  dynamic "statement" {
    for_each = var.enable_function_port ? [1] : []

    content {
      sid       = "TagNewApplicationEndpoints"
      effect    = "Allow"
      actions   = ["elasticloadbalancing:AddTags"]
      resources = [local.endpoint_load_balancer_arn_pattern, local.endpoint_target_group_arn_pattern]

      condition {
        test     = "StringEquals"
        variable = "elasticloadbalancing:CreateAction"
        values   = ["CreateLoadBalancer", "CreateTargetGroup"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_function_port ? [1] : []

    content {
      sid       = "RetagApplicationEndpoints"
      effect    = "Allow"
      actions   = ["elasticloadbalancing:AddTags"]
      resources = [local.endpoint_load_balancer_arn_pattern, local.endpoint_target_group_arn_pattern]
    }
  }

  dynamic "statement" {
    for_each = var.enable_function_port ? [1] : []

    content {
      sid    = "DescribeApplicationEndpoints"
      effect = "Allow"
      actions = [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeTags",
      ]
      resources = ["*"]
    }
  }
}

resource "aws_iam_policy" "deploy" {
  name        = "${var.name_prefix}-deploy"
  path        = var.identity_path_prefix
  description = "Authority the AppHub deployment worker operates this target with"
  policy      = data.aws_iam_policy_document.deploy.json

  tags = local.tags
}

resource "aws_iam_policy" "deploy_network" {
  name        = "${var.name_prefix}-deploy-network"
  path        = var.identity_path_prefix
  description = "Security-group authority the AppHub deployment worker operates this target with"
  policy      = data.aws_iam_policy_document.deploy_network.json

  tags = local.tags
}

resource "aws_iam_policy" "deploy_ports" {
  count       = local.any_optional_port ? 1 : 0
  name        = "${var.name_prefix}-deploy-ports"
  path        = var.identity_path_prefix
  description = "Optional-port authority the AppHub deployment worker operates this target with"
  policy      = data.aws_iam_policy_document.deploy_ports.json

  tags = local.tags
}
