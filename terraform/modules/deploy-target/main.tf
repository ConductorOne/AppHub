# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# What AppHub deploys *into*: the IAM ceiling around every role it creates and
# the credential its builds push with.
#
# None of this is AppHub's own infrastructure. It is the account-owned boundary
# the deployment worker operates inside, and every value here appears in the
# rendered provider configuration as an identifier the provider is *told*
# rather than one it discovers -- which is the rule compute/aws/config.go
# exists to enforce.
#
# Application log groups, ECR repositories, task roles, security groups and
# tables are deliberately absent: AppHub creates each of them per application
# at deploy time, and a Terraform resource with the same name would race it.

locals {
  tags      = { Environment = var.environment }
  partition = data.aws_partition.current.partition
  account   = data.aws_caller_identity.current.account_id
  region    = data.aws_region.current.region

  # Every ECR repository AppHub may create or push to. The provider prepends
  # registry.namePrefix to an application's logical name, so this one pattern
  # covers the whole namespace without naming a repository that does not exist
  # yet.
  repository_arn_pattern = "arn:${local.partition}:ecr:${local.region}:${local.account}:repository/${var.registry_name_prefix}*"

  # Path-qualified ARNs. Once a role exists, IAM authorizes it under its path.
  workload_role_arn_pattern  = "arn:${local.partition}:iam::${local.account}:role${var.identity_path_prefix}${var.identity_name_prefix}*"
  execution_role_arn_pattern = "arn:${local.partition}:iam::${local.account}:role${var.execution_role_path_prefix}*"

  # Pathless ARNs. iam:GetRole on a role that does not exist yet is authorized
  # against the role name alone. A policy that names only the path-qualified
  # ARN above answers that lookup with AccessDenied instead of NoSuchEntity,
  # and the provider stops before CreateRole. execution_role_name_prefix is
  # execRoleNameInfix in compute/aws/execrole.go.
  execution_role_name_prefix      = "exec-"
  workload_role_name_arn_pattern  = "arn:${local.partition}:iam::${local.account}:role/${var.identity_name_prefix}*"
  execution_role_name_arn_pattern = "arn:${local.partition}:iam::${local.account}:role/${local.execution_role_name_prefix}*"

  worker_role_arn = "arn:${local.partition}:iam::${local.account}:role/${var.worker_role_name}"

  # ELBv2 names are derived by compute/aws's Endpoint.NamePrefix and retain the
  # prefix even on the digested path; listeners include their parent LB name.
  endpoint_load_balancer_arn_pattern = "arn:${local.partition}:elasticloadbalancing:${local.region}:${local.account}:loadbalancer/app/${var.endpoint_name_prefix}*/*"
  endpoint_target_group_arn_pattern  = "arn:${local.partition}:elasticloadbalancing:${local.region}:${local.account}:targetgroup/${var.endpoint_name_prefix}*/*"
  endpoint_listener_arn_pattern      = "arn:${local.partition}:elasticloadbalancing:${local.region}:${local.account}:listener/app/${var.endpoint_name_prefix}*/*/*"

  # The optional ports' policy exists only when at least one port is enabled:
  # IAM rejects a policy document with no statements.
  any_optional_port = anytrue([
    var.enable_key_value_port,
    var.enable_object_store_port,
    var.enable_relational_port,
    var.enable_function_port,
  ])
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
