# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The deployment worker.
#
# A Fargate service, like the API. It used to be a dedicated EC2 instance
# because the builder ran in a container on a Docker daemon this process drove
# through a socket -- which meant a host with user-namespace remapping,
# project-quota-backed overlay2 on XFS, and an operator-installed egress
# firewall the code could only take on trust.
#
# None of that is here any more. A build runs in its own ECS task
# (modules/build), launched through the ECS API, so the worker needs no socket,
# no privileged host and no AMI. What it does need is what any of AppHub's
# services needs: an image, a role, and its configuration.
#
# # What it still is
#
# The credential-bearing half of AppHub. It holds the deploy target's whole IAM
# authority, every source credential, and the only principal allowed to assume
# the registry push role. The API holds none of those, and the two roles here
# and in modules/control-plane are where that separation is written down.
#
# # One task
#
# desired_count is 1 by default and that is a deliberate default rather than a
# limit. Two workers are safe for two separate reasons: the control plane's
# claim is a fenced transaction, so a second worker loses the race for a
# deployment rather than duplicating it; and a build slot is leased through
# the control-plane store (internal/worker/slotlease.go), so two workers never
# build in one slot's share directory at once. The slot lease is the one that
# matters for isolation: before it, each worker kept its own in-process slot
# list, and two workers could empty or read back each other's builds.
#
# It is 1 because the failure mode of losing a worker mid-deploy is already
# modelled -- the attempt becomes `interrupted`, keeps its execution lock, and
# never reruns until an administrator resolves it -- and a second worker does
# not make that case rarer. More workers add deploy concurrency only up to the
# build slots; see var.desired_count.

locals {
  tags = { Environment = var.environment }

  work_dir   = var.work_dir
  share_path = var.share_path
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
    %{if var.rds_ca_parameter != null~}
    get '${var.rds_ca_parameter}' > '${local.config_dir}/rds-ca.pem'
    %{endif~}

    chown -R 65532:65532 '${local.config_dir}'
    chmod 0500 '${local.config_dir}'
    find '${local.config_dir}' -type f -exec chmod 0400 {} +

    test -s '${local.config_dir}/apphub.yaml'
    test -s '${local.config_dir}/aws.yaml'
    %{if var.rds_ca_parameter != null~}
    test -s '${local.config_dir}/rds-ca.pem'
    %{endif~}

    # The worker creates one directory per checkout here, and runs as 65532.
    # A task volume is created root-owned, so without this the worker cannot
    # write to its own work directory and refuses to start.
    chown 65532:65532 '${local.work_dir}'
    chmod 0700 '${local.work_dir}'
  SCRIPT

  log_configuration = {
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = aws_cloudwatch_log_group.worker.name
      "awslogs-region"        = data.aws_region.current.region
      "awslogs-stream-prefix" = "worker"
    }
  }
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "${var.log_group_prefix}/worker"
  retention_in_days = var.log_retention_days

  tags = local.tags
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.name_prefix}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = aws_iam_role.worker.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # Room for a checkout. A build's own scratch space is the build task's
  # ephemeral storage, not this: what lands here is one shallow clone per
  # concurrent deployment.
  ephemeral_storage {
    size_in_gib = var.ephemeral_storage_gib
  }

  # Configuration documents and the RDS CA, for as long as the task lives.
  # IDs and source credentials are injected as environment variables, not
  # files on this volume.
  volume {
    name = "config"
  }

  # The worker's own checkout directory. Ephemeral for the same reason the API's
  # configuration is: nothing here outlives the task, and git wants local disk.
  volume {
    name = "work"
  }

  # One EFS filesystem per slot. Mount each at sharePath/N so the runner sees
  # its existing slot layout without sharing a filesystem with another build.
  # Build tasks have no task role, so network SGs enforce which slot they can
  # mount even if repository code opens a second NFS connection.
  dynamic "volume" {
    for_each = range(length(var.build_file_system_ids))
    content {
      name = "build-${volume.value}"

      efs_volume_configuration {
        file_system_id     = var.build_file_system_ids[volume.value]
        transit_encryption = "ENABLED"

        authorization_config {
          access_point_id = var.build_access_point_ids[volume.value]
          iam             = "DISABLED"
        }
      }
    }
  }

  container_definitions = jsonencode([
    {
      name       = "config"
      image      = var.aws_cli_image
      essential  = false
      entryPoint = ["/bin/sh", "-c"]
      command    = [local.bootstrap_script]

      mountPoints = [
        {
          sourceVolume  = "config"
          containerPath = local.config_dir
          readOnly      = false
        },
        # Mounted only so the bootstrap can hand it to the worker's user. The
        # init container writes nothing here.
        {
          sourceVolume  = "work"
          containerPath = local.work_dir
          readOnly      = false
        },
      ]

      logConfiguration = local.log_configuration
    },
    {
      name      = "apphub"
      image     = var.worker_image
      essential = true
      command   = ["worker", "--config", "${local.config_dir}/apphub.yaml"]

      dependsOn = [{
        containerName = "config"
        condition     = "SUCCESS"
      }]

      mountPoints = concat([
        {
          sourceVolume  = "config"
          containerPath = local.config_dir
          readOnly      = true
        },
        {
          sourceVolume  = "work"
          containerPath = local.work_dir
          readOnly      = false
        },
        ], [
        for slot in range(length(var.build_file_system_ids)) : {
          sourceVolume  = "build-${slot}"
          containerPath = "${local.share_path}/${slot}"
          readOnly      = false
        }
      ])

      environment = var.environment_variables
      secrets     = var.injected_secrets

      logConfiguration = local.log_configuration
    },
  ])

  tags = local.tags
}

resource "aws_ecs_service" "worker" {
  name            = "${var.name_prefix}-worker"
  cluster         = var.cluster_id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # Replace rather than overlap. Two workers are safe -- deployments are
  # claimed and build slots leased through the control-plane store -- but a
  # rollout that doubles them only adds workers queueing for the same fixed
  # set of slots.
  deployment_maximum_percent         = 100
  deployment_minimum_healthy_percent = 0

  wait_for_steady_state = true

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.security_group_id]
    assign_public_ip = false
  }

  tags = local.tags
}

data "aws_region" "current" {}
