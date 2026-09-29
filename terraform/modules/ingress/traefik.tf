# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Traefik: the platform ingress AppHub's compute.Route compiles onto.
#
# AppHub never calls this service. It writes Docker labels onto the ECS task
# definitions it creates (compute/aws/routes.go) and Traefik's ECS provider
# reads them back out of the cluster. The label vocabulary below -- the
# entrypoint names `web` and `websecure`, the `/ping` health endpoint -- is
# therefore a contract with that file, not a local style choice.
#
# ingress_tls_mode selects who terminates TLS:
#
#   alb-wildcard  web only, /ping on web, no ACME. Matches Union Station.
#                 compute/aws ContainerConfig.tlsTermination=edge puts
#                 published routers on web with no certresolver.
#
#   strict        web + websecure, /ping on :8080, ACME DNS-01, state on EFS.
#                 tlsTermination=ingress puts published routers on websecure.

resource "aws_cloudwatch_log_group" "traefik" {
  name              = "${var.log_group_prefix}/traefik"
  retention_in_days = var.log_retention_days

  tags = local.tags
}

# ------------------------------------------------------------------------------
# Task role
#
# Always: read the cluster to discover application tasks.
# strict only: answer ACME's DNS-01 challenge and mount the ACME EFS volume.
# ------------------------------------------------------------------------------

data "aws_iam_policy_document" "traefik_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "traefik" {
  name               = "${var.name_prefix}-traefik"
  assume_role_policy = data.aws_iam_policy_document.traefik_assume.json

  tags = local.tags
}

data "aws_iam_policy_document" "traefik" {
  statement {
    sid    = "DiscoverApplicationTasks"
    effect = "Allow"
    actions = [
      "ecs:ListClusters",
      "ecs:ListTasks",
      "ecs:DescribeClusters",
      "ecs:DescribeTasks",
      "ecs:DescribeTaskDefinition",
      "ecs:DescribeContainerInstances",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "DiscoverContainerInstanceAddresses"
    effect    = "Allow"
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = local.tls_strict ? [1] : []
    content {
      sid       = "ACMEDNSChallenge"
      effect    = "Allow"
      actions   = ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets"]
      resources = ["arn:${data.aws_partition.current.partition}:route53:::hostedzone/${var.hosted_zone_id}"]
    }
  }

  dynamic "statement" {
    for_each = local.tls_strict ? [1] : []
    content {
      sid       = "ACMEDNSChallengePropagation"
      effect    = "Allow"
      actions   = ["route53:GetChange", "route53:ListHostedZonesByName"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = local.tls_strict ? [1] : []
    content {
      sid    = "ACMEStateVolume"
      effect = "Allow"
      actions = [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite",
        "elasticfilesystem:ClientRootAccess",
      ]
      resources = [aws_efs_file_system.acme[0].arn]

      condition {
        test     = "StringEquals"
        variable = "elasticfilesystem:AccessPointArn"
        values   = [aws_efs_access_point.acme[0].arn]
      }
    }
  }
}

resource "aws_iam_role_policy" "traefik" {
  name   = "${var.name_prefix}-traefik"
  role   = aws_iam_role.traefik.id
  policy = data.aws_iam_policy_document.traefik.json
}

# ------------------------------------------------------------------------------
# Task definition
# ------------------------------------------------------------------------------

locals {
  traefik_command_common = concat([
    "--global.checknewversion=false",
    "--global.sendanonymoususage=false",

    # Local plugin source is baked into the required AppHub Traefik image at
    # /plugins-local/src/github.com/conductorone/apphub/terraform/plugins/cookiestrip. Never
    # fetch an unaudited plugin from the network when the task starts. If the
    # image lacks it, routers referencing the strip middleware fail closed.
    "--experimental.localplugins.apphubcookiestrip.modulename=github.com/conductorone/apphub/terraform/plugins/cookiestrip",

    "--entrypoints.web.address=:80",
    "--entrypoints.web.forwardedHeaders.trustedIPs=${local.trusted_ips}",
    ],
    # The internal entrypoint. Same shape in both TLS modes: the internal ALB
    # always terminates TLS itself and forwards plaintext HTTP here, so this
    # entrypoint carries no certificate resolver and no TLS labels of its own
    # -- see compute/aws/routes.go's Route.Internal handling, which never
    # writes a certresolver for it.
    var.internal_ingress_enabled ? [
      "--entrypoints.internal.address=:${local.internal_traefik_port}",
    ] : [],
    [
      "--providers.ecs=true",
      "--providers.ecs.autoDiscoverClusters=false",
      "--providers.ecs.clusters=${var.cluster_name}",
      "--providers.ecs.region=${data.aws_region.current.region}",
      "--providers.ecs.exposedByDefault=false",
      "--providers.ecs.refreshSeconds=${var.discovery_refresh_seconds}",

      "--log.level=${var.log_level}",
      "--accesslog=true",
      "--accesslog.format=json",
      "--accesslog.fields.defaultmode=keep",
      "--accesslog.fields.headers.defaultmode=drop",
    ],
  )

  # alb-wildcard: HTTP only. The ALB terminates TLS and health-checks /ping
  # on this entrypoint. No PROXY protocol: the ALB speaks X-Forwarded-*.
  traefik_command_edge = concat(local.traefik_command_common, [
    "--ping=true",
    "--ping.entryPoint=web",
  ])

  # strict: Traefik terminates TLS. PROXY protocol from the NLB, HTTP
  # redirected to HTTPS, ACME DNS-01, health check on a side entrypoint so
  # the probe is not caught by the redirect.
  traefik_command_strict = concat(
    local.traefik_command_common,
    [
      "--entrypoints.web.proxyProtocol.trustedIPs=${local.trusted_ips}",
      "--entrypoints.web.http.redirections.entryPoint.to=websecure",
      "--entrypoints.web.http.redirections.entryPoint.scheme=https",
      "--entrypoints.web.http.redirections.entryPoint.permanent=true",

      "--entrypoints.websecure.address=:443",
      "--entrypoints.websecure.proxyProtocol.trustedIPs=${local.trusted_ips}",
      "--entrypoints.websecure.forwardedHeaders.trustedIPs=${local.trusted_ips}",

      "--entrypoints.ping.address=:8080",
      "--ping=true",
      "--ping.entryPoint=ping",

      "--certificatesresolvers.${var.certificate_resolver}.acme.email=${var.acme_email}",
      "--certificatesresolvers.${var.certificate_resolver}.acme.storage=/acme/acme.json",
      "--certificatesresolvers.${var.certificate_resolver}.acme.dnschallenge=true",
      "--certificatesresolvers.${var.certificate_resolver}.acme.dnschallenge.provider=route53",
    ],
    var.acme_ca_server == "" ? [] : [
      "--certificatesresolvers.${var.certificate_resolver}.acme.caserver=${var.acme_ca_server}",
    ],
  )

  traefik_command = local.tls_edge ? local.traefik_command_edge : local.traefik_command_strict

  traefik_environment = concat(
    [{ name = "AWS_REGION", value = data.aws_region.current.region }],
    local.tls_strict ? [{ name = "AWS_HOSTED_ZONE_ID", value = var.hosted_zone_id }] : [],
  )

  traefik_port_mappings = concat(
    local.tls_edge ? [
      { containerPort = 80, protocol = "tcp" },
      ] : [
      { containerPort = 80, protocol = "tcp" },
      { containerPort = 443, protocol = "tcp" },
      { containerPort = 8080, protocol = "tcp" },
    ],
    var.internal_ingress_enabled ? [
      { containerPort = local.internal_traefik_port, protocol = "tcp" },
    ] : [],
  )

  traefik_load_balancers = {
    for item in concat(
      [for tg in aws_lb_target_group.traefik_alb : { key = "http", arn = tg.arn, port = 80 }],
      [for tg in aws_lb_target_group.traefik_http : { key = "http", arn = tg.arn, port = 80 }],
      [for tg in aws_lb_target_group.traefik_https : { key = "https", arn = tg.arn, port = 443 }],
      [for tg in aws_lb_target_group.traefik_internal : { key = "internal", arn = tg.arn, port = local.internal_traefik_port }],
    ) : item.key => { arn = item.arn, port = item.port }
  }
}

resource "aws_ecs_task_definition" "traefik" {
  family                   = "${var.name_prefix}-traefik"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.traefik_cpu
  memory                   = var.traefik_memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = aws_iam_role.traefik.arn

  dynamic "volume" {
    for_each = local.tls_strict ? [1] : []
    content {
      name = "acme"

      efs_volume_configuration {
        file_system_id     = aws_efs_file_system.acme[0].id
        transit_encryption = "ENABLED"

        authorization_config {
          access_point_id = aws_efs_access_point.acme[0].id
          iam             = "ENABLED"
        }
      }
    }
  }

  container_definitions = jsonencode([{
    name      = "traefik"
    image     = var.traefik_image
    essential = true
    command   = local.traefik_command

    environment = local.traefik_environment

    portMappings = local.traefik_port_mappings

    mountPoints = local.tls_strict ? [{
      sourceVolume  = "acme"
      containerPath = "/acme"
      readOnly      = false
    }] : []

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.traefik.name
        "awslogs-region"        = data.aws_region.current.region
        "awslogs-stream-prefix" = "traefik"
      }
    }
  }])

  tags = local.tags
}

# ------------------------------------------------------------------------------
# Service
#
# alb-wildcard: two replicas, rolling 200/100. No ACME file to race.
#
# strict: one replica. Traefik stores its ACME account and certificates in a
# single JSON file and has no leader election around it. Two replicas sharing
# this EFS volume race each other into duplicate issuance and, under Let's
# Encrypt's per-hostname rate limits, into failed issuance for hostnames that
# were working. Raising traefik_desired_count is only safe with an issuance
# path that coordinates. The availability this costs is a rolling replacement's
# worth: max percent 100 and a minimum healthy percent of zero mean the new
# task starts, the load balancer drains the old one, and published applications
# are unreachable for that window.
# ------------------------------------------------------------------------------

resource "aws_ecs_service" "traefik" {
  name            = "${var.name_prefix}-traefik"
  cluster         = var.cluster_id
  task_definition = aws_ecs_task_definition.traefik.arn
  desired_count   = local.traefik_desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_maximum_percent         = local.tls_edge ? 200 : 100
  deployment_minimum_healthy_percent = local.tls_edge ? 100 : 0

  # First create pulls the Traefik image (and, in strict mode, mounts EFS).
  # Without a grace period the load balancer health check marks the target
  # unhealthy during that window, the circuit breaker tries to roll back, and
  # there is no previous deployment to roll back to.
  health_check_grace_period_seconds = 180

  wait_for_steady_state = true

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.traefik_security_group_id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = local.traefik_load_balancers
    content {
      target_group_arn = load_balancer.value.arn
      container_name   = "traefik"
      container_port   = load_balancer.value.port
    }
  }

  depends_on = [
    aws_lb_listener.apps_http,
    aws_lb_listener.apps_https,
    aws_lb_listener.apps_alb_http,
    aws_lb_listener.apps_alb_https,
    aws_lb_listener.internal_https,
    aws_lb_listener.internal_http,
    aws_efs_mount_target.acme,
  ]

  tags = local.tags
}

data "aws_partition" "current" {}
data "aws_region" "current" {}
