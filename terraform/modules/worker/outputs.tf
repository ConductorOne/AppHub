# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

output "service_name" {
  description = "ECS service name; `aws ecs update-service --force-new-deployment` targets it."
  value       = aws_ecs_service.worker.name
}

output "role_arn" {
  description = "IAM role the worker runs as; the only principal allowed to assume the push role."
  value       = aws_iam_role.worker.arn
}

output "log_group" {
  description = "CloudWatch log group the worker writes to."
  value       = aws_cloudwatch_log_group.worker.name
}

output "log_group_arn" {
  value = aws_cloudwatch_log_group.worker.arn
}

output "work_dir" {
  description = "The worker's private checkout directory; worker.workDir in the rendered configuration."
  value       = local.work_dir
}

output "share_path" {
  description = "Where the worker sees the build share; build.task.sharePath in the provider configuration."
  value       = local.share_path
}

output "secret_dir" {
  description = "Unused by the ECS path; source credentials are environment variables."
  value       = var.secret_dir
}
