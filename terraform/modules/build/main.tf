# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Where a build runs.
#
# One ECS task per build, launched by the worker through the ECS API. The task
# runs kaniko and nothing else, holds no credential of any kind, and exchanges
# the build context and the finished image with the worker through a per-slot
# filesystem.
#
# # Credential boundary
#
# **A build task definition carries no task role.** On Fargate every container
# in a task shares one network namespace, so the task credentials endpoint is
# reachable from the container executing the Dockerfile -- a role attached for
# any container's benefit is a credential repository-authored code can read.
# There is no sidecar arrangement that survives it.
#
# `aws_ecs_task_definition.build` below therefore sets no `task_role_arn`, and
# the runner refuses to start a worker whose task definitions have one
# (compute/aws's BuildTaskRunner.Validate, on every worker start). The execution
# role is a different thing and is fine: it belongs to the ECS agent, which
# pulls the image and creates the log stream, and is not reachable from inside
# the container.
#
# # Slots
#
# Each slot has a separate EFS file system and an NFS security group that only
# admits its corresponding build task security group (plus the trusted worker).
# Merely mounting an access point on a shared file system is not isolation: a
# compromised anonymous NFS client could choose another slot's access point.
# The worker mounts each slot's file system at sharePath/<slot index>. `slots`
# is the runner's concurrency limit and must be at least the worker's
# maxConcurrentDeployments, or builds queue.

locals {
  tags = { Environment = var.environment }

  # Each task definition mounts its own file system at the same path.
  # The worker's slot N mount and the build's mount share the same /slot root.
  slot_path = "/build"
}

resource "aws_cloudwatch_log_group" "build" {
  name              = "${var.log_group_prefix}/build"
  retention_in_days = var.log_retention_days

  tags = local.tags
}

# Each slot's share carries the context in and the image out. A build task has
# no credential, so it has no other way to receive a file or return one -- a
# signed URL would be credential material in the environment of the process
# running the Dockerfile. See docs/decisions/.
# ------------------------------------------------------------------------------

resource "aws_efs_file_system" "slot" {
  count = var.slots

  creation_token = "${var.name_prefix}-build-${count.index}"
  encrypted      = true

  # Elastic throughput fits bursty context writes and image reads.
  throughput_mode = "elastic"

  tags = merge(local.tags, { Name = "${var.name_prefix}-build-${count.index}" })
}

# The task's security group grants NFS egress only to its own file system.
# The caller also attaches the shared build security group for public package
# downloads and DNS; it must not grant NFS to another file system.
resource "aws_security_group" "slot_build" {
  count = var.slots

  name        = "${var.name_prefix}-build-slot-${count.index}"
  description = "Build slot ${count.index} NFS client"
  vpc_id      = var.vpc_id

  tags = merge(local.tags, { Name = "${var.name_prefix}-build-slot-${count.index}" })
}

resource "aws_security_group" "slot_efs" {
  count = var.slots

  name        = "${var.name_prefix}-build-share-${count.index}"
  description = "Build slot ${count.index} EFS mount targets"
  vpc_id      = var.vpc_id

  tags = merge(local.tags, { Name = "${var.name_prefix}-build-share-${count.index}" })
}

resource "aws_vpc_security_group_egress_rule" "slot_nfs" {
  count = var.slots

  security_group_id            = aws_security_group.slot_build[count.index].id
  description                  = "NFS only to the corresponding build slot"
  referenced_security_group_id = aws_security_group.slot_efs[count.index].id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "slot_from_build" {
  count = var.slots

  security_group_id            = aws_security_group.slot_efs[count.index].id
  description                  = "NFS only from the corresponding build task"
  referenced_security_group_id = aws_security_group.slot_build[count.index].id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "slot_from_worker" {
  count = var.slots

  security_group_id            = aws_security_group.slot_efs[count.index].id
  description                  = "NFS from the worker preparing and clearing this slot"
  referenced_security_group_id = var.worker_security_group_id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
}

resource "aws_efs_mount_target" "slot" {
  count = var.slots * length(var.private_subnet_ids)

  file_system_id  = aws_efs_file_system.slot[floor(count.index / length(var.private_subnet_ids))].id
  subnet_id       = var.private_subnet_ids[count.index % length(var.private_subnet_ids)]
  security_groups = [aws_security_group.slot_efs[floor(count.index / length(var.private_subnet_ids))].id]
}

# APs impose a non-root POSIX identity even if repository code runs as root.
# The worker and the build both see /slot, but the worker's trusted task mounts
# all file systems while each build task can only reach its own NFS endpoint.
resource "aws_efs_access_point" "worker" {
  count = var.slots

  file_system_id = aws_efs_file_system.slot[count.index].id

  posix_user {
    uid = 65532
    gid = 65532
  }

  root_directory {
    path = "/slot"

    creation_info {
      owner_uid   = 65532
      owner_gid   = 65532
      permissions = "0755"
    }
  }

  tags = merge(local.tags, { Name = "${var.name_prefix}-build-worker-${count.index}" })
}

resource "aws_efs_access_point" "slot" {
  count = var.slots

  file_system_id = aws_efs_file_system.slot[count.index].id

  posix_user {
    uid = 65532
    gid = 65532
  }

  root_directory {
    path = "/slot"

    creation_info {
      owner_uid   = 65532
      owner_gid   = 65532
      permissions = "0755"
    }
  }

  tags = merge(local.tags, { Name = "${var.name_prefix}-build-slot-${count.index}" })
}

# Anonymous EFS access is needed because the build task deliberately has no
# task role. This policy denies root mounts and any AP other than the two APs
# for this slot. AP IDs are not secrets: the *network* boundary above is what
# prevents a compromised build from selecting a sibling slot's valid AP.
resource "aws_efs_file_system_policy" "slot" {
  count = var.slots

  file_system_id = aws_efs_file_system.slot[count.index].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSlotAccessPoints"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite",
        ]
        Resource = aws_efs_file_system.slot[count.index].arn
        Condition = {
          StringEquals = {
            "elasticfilesystem:AccessPointArn" = [
              aws_efs_access_point.slot[count.index].arn,
              aws_efs_access_point.worker[count.index].arn,
            ]
          }
          Bool = {
            "elasticfilesystem:AccessedViaMountTarget" = "true"
            "aws:SecureTransport"                      = "true"
          }
        }
      },
      {
        Sid       = "DenyMountWithoutAccessPoint"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite", "elasticfilesystem:ClientRootAccess"]
        Resource  = aws_efs_file_system.slot[count.index].arn
        Condition = { Null = { "elasticfilesystem:AccessPointArn" = "true" } }
      },
      {
        Sid       = "DenyOtherAccessPoints"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite", "elasticfilesystem:ClientRootAccess"]
        Resource  = aws_efs_file_system.slot[count.index].arn
        Condition = {
          StringNotEquals = {
            "elasticfilesystem:AccessPointArn" = [
              aws_efs_access_point.slot[count.index].arn,
              aws_efs_access_point.worker[count.index].arn,
            ]
          }
        }
      },
      {
        Sid       = "RequireEncryptedTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "*"
        Resource  = aws_efs_file_system.slot[count.index].arn
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}

# ------------------------------------------------------------------------------
# The task definitions, one per slot.
# ------------------------------------------------------------------------------

resource "aws_ecs_task_definition" "build" {
  count = var.slots

  family                   = "${var.name_prefix}-build-${count.index}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn

  # Deliberately absent: task_role_arn. The execution role belongs to the ECS
  # agent, not the untrusted builder. The runner refuses a task role, while the
  # file system policy and slot-specific network groups enforce NFS isolation.

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # kaniko unpacks every layer of the image it is building into this.
  ephemeral_storage {
    size_in_gib = var.ephemeral_storage_gib
  }

  volume {
    name = "slot"

    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.slot[count.index].id
      transit_encryption = "ENABLED"

      authorization_config {
        access_point_id = aws_efs_access_point.slot[count.index].id
        # The mount is authorised by network position and the file system
        # policy, not by an IAM identity -- which is what lets this task have no
        # task role at all.
        iam = "DISABLED"
      }
    }
  }

  container_definitions = jsonencode([{
    name      = var.container_name
    image     = var.builder_image
    essential = true

    # The official Kaniko OSS image's ENTRYPOINT is /kaniko/executor. ECS
    # command overrides replace CMD, not ENTRYPOINT, so the runner sends flags
    # only. Declaring it here keeps a retagged pin honest if the image config
    # ever drifts.
    entryPoint = ["/kaniko/executor"]

    # Overridden per build by the runner with the builder flags. The
    # placeholder is a refusal rather than a build: a task started without an
    # override should fail, not do something.
    command = ["--help"]

    # No environment. The runner forwards none either: a build that cannot be
    # handed anything cannot be handed a credential.
    environment = []

    mountPoints = [{
      sourceVolume  = "slot"
      containerPath = local.slot_path
      readOnly      = false
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.build.name
        "awslogs-region"        = data.aws_region.current.region
        "awslogs-stream-prefix" = var.log_stream_prefix
      }
    }
  }])

  # An ECS definition can otherwise be registered before the mount targets,
  # AP policy, or NFS rules are ready, leaving first-run builds unable to mount.
  depends_on = [
    aws_efs_mount_target.slot,
    aws_efs_file_system_policy.slot,
    aws_vpc_security_group_egress_rule.slot_nfs,
    aws_vpc_security_group_ingress_rule.slot_from_build,
    aws_vpc_security_group_ingress_rule.slot_from_worker,
  ]

  tags = local.tags

  # The image is promoted by `make promote-builder`, which registers a new
  # revision with a digest pin. Terraform creates the family and the isolation
  # properties; it must not revert a promotion on the next apply.
  lifecycle {
    ignore_changes = [container_definitions]

    # Variable validation allows empty so `terraform apply -target=module.cluster`
    # can create ECR before the first push. Registering a task definition with
    # that empty string is a 400 from ECS, so refuse here — this resource is
    # not in a cluster-only plan.
    precondition {
      condition     = var.builder_image != ""
      error_message = "builder_image is empty. Run make tf-up, or make push-builder then apply, so builder_image.auto.tfvars contains a digest pin."
    }
  }
}

data "aws_region" "current" {}
