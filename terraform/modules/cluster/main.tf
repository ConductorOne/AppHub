# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The ECS substrate shared by AppHub's own services, the platform ingress, and
# every application AppHub deploys.
#
# One cluster, named by PlacementConfig.ClusterARN in the rendered provider
# configuration. Traefik discovers application tasks by reading this cluster,
# so a second cluster would need a second ingress; see modules/ingress.

locals {
  tags = { Environment = var.environment }
}

resource "aws_ecs_cluster" "main" {
  name = var.name_prefix

  setting {
    name  = "containerInsights"
    value = var.container_insights ? "enabled" : "disabled"
  }

  tags = merge(local.tags, { Name = var.name_prefix })
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ------------------------------------------------------------------------------
# Service discovery.
#
# Traefik's ForwardAuth middleware addresses oauth2-proxy by name, and a task
# address changes on every replacement, so the name has to resolve to whatever
# is running now.
# ------------------------------------------------------------------------------

resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = "${var.name_prefix}.internal"
  description = "Internal service discovery for ${var.name_prefix}"
  vpc         = var.vpc_id

  tags = local.tags
}

# ------------------------------------------------------------------------------
# Image repositories for AppHub's own three images.
#
# Application images are NOT here: AppHub creates one repository per
# application at deploy time under the registry name prefix the provider
# configuration carries, and Terraform must not race it for the name.
# ------------------------------------------------------------------------------

resource "aws_ecr_repository" "server" {
  name                 = "${var.name_prefix}/server"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.tags
}

resource "aws_ecr_repository" "worker" {
  name                 = "${var.name_prefix}/worker"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.tags
}

resource "aws_ecr_repository" "builder" {
  name                 = "${var.name_prefix}/builder"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.tags
}

resource "aws_ecr_lifecycle_policy" "server" {
  repository = aws_ecr_repository.server.name
  policy     = local.lifecycle_policy
}

resource "aws_ecr_lifecycle_policy" "worker" {
  repository = aws_ecr_repository.worker.name
  policy     = local.lifecycle_policy
}

resource "aws_ecr_lifecycle_policy" "builder" {
  repository = aws_ecr_repository.builder.name
  policy     = local.lifecycle_policy
}

locals {
  lifecycle_policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the ${var.image_retention_count} most recent images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = var.image_retention_count
      }
      action = { type = "expire" }
    }]
  })
}
