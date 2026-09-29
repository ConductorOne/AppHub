# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

output "portal_url" {
  description = "The portal's canonical origin."
  value       = "https://${var.portal_domain}"
}

output "load_balancer_dns_name" {
  description = "DNS name of the portal load balancer."
  value       = aws_lb.portal.dns_name
}

output "task_role_arn" {
  description = "IAM role the API runs as."
  value       = aws_iam_role.task.arn
}

output "service_name" {
  description = "ECS service name; `aws ecs update-service --force-new-deployment` targets it."
  value       = aws_ecs_service.api.name
}

output "log_group" {
  description = "CloudWatch log group the API writes to."
  value       = aws_cloudwatch_log_group.api.name
}

output "log_group_arn" {
  value = aws_cloudwatch_log_group.api.arn
}

output "oidc_callback_urls" {
  description = "Exact redirect URIs to register with each identity provider."
  value       = { for id in var.auth_provider_ids : id => "https://${var.portal_domain}/auth/${id}/callback" }
}

output "github_app_key_parameter" {
  description = "Derived location of the admin-managed GitHub App private key. The API may write it and never read it."
  value       = local.github_app_key_parameter
}
