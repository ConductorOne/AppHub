# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Traefik's ACME account key and issued certificates. Created only when
# ingress_tls_mode is strict: alb-wildcard terminates TLS at the ALB and
# Traefik has no ACME store.
#
# They have to survive a task replacement. Without durable storage every
# Traefik restart registers a new ACME account and re-issues every certificate,
# and Let's Encrypt's rate limits are low enough that a few deploys in an hour
# turn into an outage on every published application hostname at once.
#
# EFS rather than an EBS volume because the task is on Fargate, and Fargate has
# no attachable block storage.

resource "aws_efs_file_system" "acme" {
  count = local.tls_strict ? 1 : 0

  creation_token = "${var.name_prefix}-acme"
  encrypted      = true

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = merge(local.tags, { Name = "${var.name_prefix}-acme" })
}

resource "aws_efs_mount_target" "acme" {
  count = local.tls_strict ? length(var.private_subnet_ids) : 0

  file_system_id  = aws_efs_file_system.acme[0].id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [var.efs_security_group_id]
}

# An access point rather than the file system root, so the task is confined to
# one directory with one identity and cannot be given a path traversal out of
# it by a future volume definition.
resource "aws_efs_access_point" "acme" {
  count = local.tls_strict ? 1 : 0

  file_system_id = aws_efs_file_system.acme[0].id

  posix_user {
    uid = 0
    gid = 0
  }

  root_directory {
    path = "/acme"

    creation_info {
      owner_uid   = 0
      owner_gid   = 0
      permissions = "0700"
    }
  }

  tags = merge(local.tags, { Name = "${var.name_prefix}-acme" })
}

# Attaching a policy at all replaces the default, which allows any client in the
# VPC to mount. So the Allow below is not redundant with the absence of a Deny:
# without it every mount is denied, Traefik's included.
resource "aws_efs_file_system_policy" "acme" {
  count = local.tls_strict ? 1 : 0

  file_system_id = aws_efs_file_system.acme[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowTraefikThroughAccessPoint"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.traefik.arn }
        Action = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite",
          "elasticfilesystem:ClientRootAccess",
        ]
        Resource = aws_efs_file_system.acme[0].arn
        Condition = {
          StringEquals = {
            "elasticfilesystem:AccessPointArn" = aws_efs_access_point.acme[0].arn
          }
        }
      },
      {
        Sid       = "RequireEncryptedTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "*"
        Resource  = aws_efs_file_system.acme[0].arn
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}
