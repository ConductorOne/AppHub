# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

output "deploy_policy_arns" {
  description = "Policies the deployment worker attaches to operate this target."
  value       = concat([aws_iam_policy.deploy.arn], aws_iam_policy.deploy_ports[*].arn, [aws_iam_policy.deploy_network.arn])
}

output "workload_boundary_arn" {
  description = "Permissions boundary applied to every role AppHub creates; identity.permissionsBoundary in the provider configuration."
  value       = aws_iam_policy.workload_boundary.arn
}

output "push_role_arn" {
  description = "Role a build's image push assumes; build.pushRoleArn in the provider configuration."
  value       = aws_iam_role.push.arn
}

output "identity_path_prefix" {
  description = "identity.pathPrefix in the provider configuration."
  value       = var.identity_path_prefix
}

output "identity_name_prefix" {
  description = "identity.namePrefix in the provider configuration."
  value       = var.identity_name_prefix
}

output "execution_role_path_prefix" {
  description = "container.executionRolePathPrefix in the provider configuration."
  value       = var.execution_role_path_prefix
}

output "registry_name_prefix" {
  description = "registry.namePrefix in the provider configuration."
  value       = var.registry_name_prefix
}

output "container_name_prefix" {
  description = "container.namePrefix in the provider configuration."
  value       = var.container_name_prefix
}

output "secret_path_prefix" {
  description = "secrets.pathPrefix in the provider configuration."
  value       = var.secret_path_prefix
}

output "app_log_group_prefix" {
  description = "container.logGroupPrefix in the provider configuration."
  value       = var.app_log_group_prefix
}

output "key_value_name_prefix" {
  description = "keyValue.namePrefix in the provider configuration, when the port is enabled."
  value       = var.key_value_name_prefix
}

output "object_store_name_prefix" {
  description = "objectStore.namePrefix in the provider configuration, when the port is enabled."
  value       = var.object_store_name_prefix
}

output "relational_name_prefix" {
  description = "relational.namePrefix in the provider configuration, when the port is enabled."
  value       = var.relational_name_prefix
}

output "function_name_prefix" {
  description = "function.namePrefix in the provider configuration when the function port is enabled."
  value       = var.function_name_prefix
}

output "endpoint_name_prefix" {
  description = "endpoint.namePrefix in the provider configuration when the function port is enabled."
  value       = var.endpoint_name_prefix
}

output "enabled_ports" {
  description = "Which optional compute ports this target's IAM authority covers."
  value = {
    key_value    = var.enable_key_value_port
    object_store = var.enable_object_store_port
    relational   = var.enable_relational_port
    function     = var.enable_function_port
  }
}
