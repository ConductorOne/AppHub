# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

output "cluster_arn" {
  description = "ECS cluster ARN; PlacementConfig.ClusterARN in the rendered provider configuration."
  value       = aws_ecs_cluster.main.arn
}

output "cluster_id" {
  description = "ECS cluster ID."
  value       = aws_ecs_cluster.main.id
}

output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.main.name
}

output "namespace_id" {
  description = "Cloud Map private DNS namespace ID."
  value       = aws_service_discovery_private_dns_namespace.main.id
}

output "namespace_name" {
  description = "Cloud Map private DNS namespace name; service names resolve as <service>.<namespace>."
  value       = aws_service_discovery_private_dns_namespace.main.name
}

output "execution_role_arn" {
  description = "Task execution role ECS assumes to start AppHub's own tasks."
  value       = aws_iam_role.execution.arn
}

output "server_repository_url" {
  description = "ECR repository for the AppHub API image."
  value       = aws_ecr_repository.server.repository_url
}

output "worker_repository_url" {
  description = "ECR repository for the AppHub worker image."
  value       = aws_ecr_repository.worker.repository_url
}

output "builder_repository_url" {
  description = "ECR repository for the AppHub builder (Kaniko OSS) image."
  value       = aws_ecr_repository.builder.repository_url
}

output "server_repository_arn" {
  description = "ARN of the AppHub API image repository."
  value       = aws_ecr_repository.server.arn
}

output "worker_repository_arn" {
  description = "ARN of the AppHub worker image repository."
  value       = aws_ecr_repository.worker.arn
}

output "builder_repository_arn" {
  description = "ARN of the AppHub builder image repository."
  value       = aws_ecr_repository.builder.arn
}
