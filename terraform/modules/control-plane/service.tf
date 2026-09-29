# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The API service.
#
# # Why an init container
#
# `apphub serve` reads a YAML file, and the runtime image is distroless with
# no shell, no writable layer worth using and no AWS client. The two
# configuration documents can exceed the 8 KiB environment-variable budget,
# so they cannot be injected as env vars. IDs and secrets can, and they are:
# the ECS `secrets` block below, filled from Parameter Store by the execution
# role, never by this task role.
#
# So one short-lived container with a shell and the AWS CLI writes the two
# YAML documents into a volume shared with the API container, and the API
# container does not start until it exits successfully. The API container
# never has the credentials or the tooling to fetch the documents itself.

resource "aws_cloudwatch_log_group" "api" {
  name              = "${var.log_group_prefix}/api"
  retention_in_days = var.log_retention_days

  tags = local.tags
}

locals {
  config_dir = var.config_dir

  bootstrap_script = <<-SCRIPT
    set -eu
    umask 077

    get() {
      aws ssm get-parameter --name "$1" --with-decryption \
        --query Parameter.Value --output text
    }

    get '${var.apphub_config_parameter}' > '${local.config_dir}/apphub.yaml'
    get '${var.aws_config_parameter}'    > '${local.config_dir}/aws.yaml'

    # The API runs unprivileged (65532 in the image). Readable by it and by
    # nothing else in the task.
    chown -R 65532:65532 '${local.config_dir}'
    chmod 0500 '${local.config_dir}'
    chmod 0400 '${local.config_dir}'/*

    # Fail loudly here rather than as an unexplained startup error one
    # container later.
    test -s '${local.config_dir}/apphub.yaml'
    test -s '${local.config_dir}/aws.yaml'
  SCRIPT

  log_configuration = {
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = aws_cloudwatch_log_group.api.name
      "awslogs-region"        = local.region
      "awslogs-stream-prefix" = "api"
    }
  }
}

resource "aws_service_discovery_service" "api" {
  name = "apphub-api"

  dns_config {
    namespace_id   = var.namespace_id
    routing_policy = "MULTIVALUE"

    dns_records {
      ttl  = 10
      type = "A"
    }
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = local.tags
}

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name_prefix}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # Task-scoped ephemeral storage. The configuration lives for exactly as long
  # as the task does and is never written to a host path or a persistent volume.
  volume {
    name = "config"
  }

  container_definitions = jsonencode([
    {
      name       = "config"
      image      = var.aws_cli_image
      essential  = false
      entryPoint = ["/bin/sh", "-c"]
      command    = [local.bootstrap_script]

      mountPoints = [{
        sourceVolume  = "config"
        containerPath = local.config_dir
        readOnly      = false
      }]

      logConfiguration = local.log_configuration
    },
    {
      name      = "apphub"
      image     = var.server_image
      essential = true
      command   = ["serve", "--config", "${local.config_dir}/apphub.yaml"]

      dependsOn = [{
        containerName = "config"
        condition     = "SUCCESS"
      }]

      portMappings = [{
        containerPort = 8080
        protocol      = "tcp"
      }]

      mountPoints = [{
        sourceVolume  = "config"
        containerPath = local.config_dir
        readOnly      = true
      }]

      environment = var.environment_variables
      secrets     = var.injected_secrets

      # The image is distroless: no shell, no health-check binary. Liveness is
      # the load balancer's /healthz probe against the target group.
      logConfiguration = local.log_configuration
    },
  ])

  tags = local.tags
}

resource "aws_ecs_service" "api" {
  name            = "${var.name_prefix}-api"
  cluster         = var.cluster_id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  # A deployment that never becomes healthy rolls itself back rather than
  # leaving the service half replaced.
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  health_check_grace_period_seconds = 60
  wait_for_steady_state             = true

  # Break-glass only. It is off by default: an operator shell inside the task
  # that holds the control plane's persistence credentials is not something to
  # leave enabled.
  enable_execute_command = var.enable_execute_command

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.service_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.portal.arn
    container_name   = "apphub"
    container_port   = 8080
  }

  service_registries {
    registry_arn   = aws_service_discovery_service.api.arn
    container_name = "apphub"
  }

  depends_on = [aws_lb_listener.portal_https]

  tags = local.tags
}
