# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

output "task_definition_families" {
  description = "One family per slot; build.task.taskDefinitions in the provider configuration."
  value       = aws_ecs_task_definition.build[*].family
}

output "task_definition_arns" {
  description = "ARNs of the build task definitions, for scoping the worker's ecs:RunTask."
  value       = aws_ecs_task_definition.build[*].arn
}

output "execution_role_arn" {
  description = "Role the ECS agent assumes to start a build task; the worker must be able to pass it."
  value       = aws_iam_role.execution.arn
}

output "container_name" {
  description = "Container whose command the runner overrides; build.task.containerName."
  value       = var.container_name
}

output "slot_path" {
  description = "Where a build task sees its own slot; build.task.slotPath."
  value       = local.slot_path
}

output "slots" {
  description = "Number of concurrent builds this target can run."
  value       = var.slots
}

output "worker_file_system_ids" {
  description = "One EFS file system per build slot, in task definition order; the worker mounts each at sharePath/<slot index>."
  value       = aws_efs_file_system.slot[*].id
  depends_on  = [aws_efs_mount_target.slot, aws_efs_file_system_policy.slot]
}

output "worker_access_point_ids" {
  description = "Worker access points paired by index with worker_file_system_ids."
  value       = aws_efs_access_point.worker[*].id
  depends_on  = [aws_efs_mount_target.slot, aws_efs_file_system_policy.slot]
}

output "slot_security_group_ids" {
  description = "NFS client security group for each task definition slot, in task definition order; attach only its own group."
  value       = aws_security_group.slot_build[*].id
  depends_on  = [aws_vpc_security_group_egress_rule.slot_nfs, aws_vpc_security_group_ingress_rule.slot_from_build]
}

output "log_group" {
  description = "CloudWatch log group builds write to; build.task.logGroup."
  value       = aws_cloudwatch_log_group.build.name
}

output "log_group_arn" {
  value = aws_cloudwatch_log_group.build.arn
}

output "log_stream_prefix" {
  description = "awslogs stream prefix; build.task.logStreamPrefix."
  value       = var.log_stream_prefix
}
