# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Every long-lived security group lives here rather than beside the service it
# belongs to.
#
# That is not organisational taste. AppHub's AWS provider is handed the
# platform-ingress group and the control-plane groups as *configuration*
# (compute/aws/config.go: PlacementConfig.PlatformIngressSecurityGroups,
# PlacementConfig.ControlPlaneSecurityGroups), and that configuration is
# rendered by the config module, which the control plane and the worker then
# consume. Creating each group next to its own service would make the config
# module depend on the services and the services depend on the config module.
# One module owns the VPC's traffic model instead, and everything else
# references it.
#
# The groups a deployed application gets are NOT here: the container port
# creates a per-service group from compute.ServiceSpec.Ingress on every deploy.
# aws_security_group.apps below is the operator's baseline posture that is
# attached in addition to it, and it deliberately carries no ingress rule --
# see PlacementConfig.SecurityGroups.

# ------------------------------------------------------------------------------
# Portal load balancer -> AppHub API
# ------------------------------------------------------------------------------

resource "aws_security_group" "portal_alb" {
  name        = "${var.name_prefix}-portal-alb"
  description = "AppHub portal load balancer"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-portal-alb" })
}

resource "aws_vpc_security_group_ingress_rule" "portal_alb_http" {
  for_each = toset(var.portal_allowed_cidrs)

  security_group_id = aws_security_group.portal_alb.id
  description       = "HTTP, redirected to HTTPS by the listener"
  cidr_ipv4         = each.value
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "portal_alb_https" {
  for_each = toset(var.portal_allowed_cidrs)

  security_group_id = aws_security_group.portal_alb.id
  description       = "HTTPS"
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "portal_alb_all" {
  security_group_id = aws_security_group.portal_alb.id
  description       = "To the API tasks"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "apphub_api" {
  name        = "${var.name_prefix}-api"
  description = "AppHub control plane API tasks"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-api" })
}

resource "aws_vpc_security_group_ingress_rule" "apphub_api_from_alb" {
  security_group_id            = aws_security_group.apphub_api.id
  description                  = "From the portal load balancer"
  referenced_security_group_id = aws_security_group.portal_alb.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

# The applications ingress reaches the API for nothing today. It is here
# because Traefik's ForwardAuth chain is the natural place an operator would
# later add an authorization hop served by the control plane, and adding it
# then should be a rule and not a redesign.
resource "aws_vpc_security_group_ingress_rule" "apphub_api_from_traefik" {
  security_group_id            = aws_security_group.apphub_api.id
  description                  = "From Traefik, for ForwardAuth"
  referenced_security_group_id = aws_security_group.traefik.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "apphub_api_all" {
  security_group_id = aws_security_group.apphub_api.id
  description       = "DynamoDB, SSM, CloudWatch Logs and the identity provider"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ------------------------------------------------------------------------------
# Applications ingress: load balancer -> Traefik -> oauth2-proxy
#
# alb-wildcard: the ALB terminates TLS. Traefik is reachable only from the
# load balancer's security group on port 80. Client IPs arrive in
# X-Forwarded-For, not as the TCP source.
#
# strict: the NLB passes TCP through. Traefik sees either the client address
# (client IP preservation) or the load balancer's own address in this VPC.
# Both are covered: allowed client CIDRs for the first, the VPC CIDR for the
# second and for health checks.
# ------------------------------------------------------------------------------

resource "aws_security_group" "apps_nlb" {
  name        = "${var.name_prefix}-apps-nlb"
  description = "Applications load balancer"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-apps-lb" })
}

resource "aws_vpc_security_group_ingress_rule" "apps_nlb_http" {
  for_each = toset(var.apps_allowed_cidrs)

  security_group_id = aws_security_group.apps_nlb.id
  description       = "HTTP"
  cidr_ipv4         = each.value
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "apps_nlb_https" {
  for_each = toset(var.apps_allowed_cidrs)

  security_group_id = aws_security_group.apps_nlb.id
  description       = "HTTPS"
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "apps_nlb_all" {
  security_group_id = aws_security_group.apps_nlb.id
  description       = "To Traefik"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "-1"
}

resource "aws_security_group" "traefik" {
  name        = "${var.name_prefix}-traefik"
  description = "Traefik reverse proxy, the platform ingress"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-traefik" })
}

resource "aws_vpc_security_group_ingress_rule" "traefik_http" {
  for_each = var.ingress_tls_mode == "strict" ? toset(concat(var.apps_allowed_cidrs, [var.vpc_cidr])) : toset([])

  security_group_id = aws_security_group.traefik.id
  description       = "HTTP entrypoint"
  cidr_ipv4         = each.value
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "traefik_http_from_lb" {
  count = var.ingress_tls_mode == "alb-wildcard" ? 1 : 0

  security_group_id            = aws_security_group.traefik.id
  description                  = "HTTP from the applications ALB"
  referenced_security_group_id = aws_security_group.apps_nlb.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "traefik_https" {
  for_each = var.ingress_tls_mode == "strict" ? toset(concat(var.apps_allowed_cidrs, [var.vpc_cidr])) : toset([])

  security_group_id = aws_security_group.traefik.id
  description       = "HTTPS entrypoint"
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "traefik_ping" {
  count = var.ingress_tls_mode == "strict" ? 1 : 0

  security_group_id = aws_security_group.traefik.id
  description       = "Load balancer health check on the ping entrypoint"
  cidr_ipv4         = var.vpc_cidr
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "traefik_all" {
  security_group_id = aws_security_group.traefik.id
  description       = "Application tasks, oauth2-proxy, ECS discovery, ACME and EFS"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ------------------------------------------------------------------------------
# Internal applications ingress: an ALB, private-subnet-only, that always
# terminates TLS with its own ACM certificate and forwards plaintext HTTP to
# Traefik's `internal` entrypoint (modules/ingress/traefik.tf). This is
# independent of ingress_tls_mode -- unlike the public path, which is either
# an ALB or an NLB depending on that mode, the internal load balancer is
# always an ALB, because its whole purpose is keeping a private application's
# traffic inside Traefik's access log while never reaching the internet.
#
# Traefik admits this port only from the internal ALB's security group,
# exactly the same shape as traefik_http_from_lb above for the public
# alb-wildcard path.
# ------------------------------------------------------------------------------

resource "aws_security_group" "internal_alb" {
  count = var.internal_ingress_enabled ? 1 : 0

  name        = "${var.name_prefix}-internal-alb"
  description = "Internal applications load balancer"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-internal-alb" })
}

resource "aws_vpc_security_group_ingress_rule" "internal_alb_https" {
  count = var.internal_ingress_enabled ? 1 : 0

  security_group_id = aws_security_group.internal_alb[0].id
  description       = "HTTPS, from inside the VPC only -- this load balancer is never reachable from the internet"
  cidr_ipv4         = var.vpc_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "internal_alb_http" {
  count = var.internal_ingress_enabled ? 1 : 0

  security_group_id = aws_security_group.internal_alb[0].id
  description       = "HTTP, redirected to HTTPS by the listener"
  cidr_ipv4         = var.vpc_cidr
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "internal_alb_all" {
  count = var.internal_ingress_enabled ? 1 : 0

  security_group_id = aws_security_group.internal_alb[0].id
  description       = "To Traefik"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "-1"
}

resource "aws_vpc_security_group_ingress_rule" "traefik_internal_from_lb" {
  count = var.internal_ingress_enabled ? 1 : 0

  security_group_id            = aws_security_group.traefik.id
  description                  = "The internal entrypoint, from the internal ALB only"
  referenced_security_group_id = aws_security_group.internal_alb[0].id
  from_port                    = 8081
  to_port                      = 8081
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "oauth2_proxy" {
  name        = "${var.name_prefix}-oauth2-proxy"
  description = "oauth2-proxy, reached only through Traefik"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-oauth2-proxy" })
}

resource "aws_vpc_security_group_ingress_rule" "oauth2_proxy_from_traefik" {
  security_group_id            = aws_security_group.oauth2_proxy.id
  description                  = "From Traefik only"
  referenced_security_group_id = aws_security_group.traefik.id
  from_port                    = 4180
  to_port                      = 4180
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "oauth2_proxy_all" {
  security_group_id = aws_security_group.oauth2_proxy.id
  description       = "To the identity provider"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ------------------------------------------------------------------------------
# EFS, which holds Traefik's ACME account and certificates.
# ------------------------------------------------------------------------------

resource "aws_security_group" "efs" {
  name        = "${var.name_prefix}-efs"
  description = "Traefik ACME state"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-efs" })
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_traefik" {
  security_group_id            = aws_security_group.efs.id
  description                  = "NFS from Traefik"
  referenced_security_group_id = aws_security_group.traefik.id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
}

# ------------------------------------------------------------------------------
# The deployment worker.
#
# No ingress. Nothing in this system calls the worker: it claims work by reading
# the control-plane table and reports by writing it. It holds the deploy
# target's IAM authority and every source credential, so nothing on the network
# is allowed to start a conversation with it.
# ------------------------------------------------------------------------------

resource "aws_security_group" "worker" {
  name        = "${var.name_prefix}-worker"
  description = "AppHub deployment worker"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-worker" })
}

resource "aws_vpc_security_group_egress_rule" "worker_all" {
  security_group_id = aws_security_group.worker.id
  description       = "AWS APIs, the build share, and the source host"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ------------------------------------------------------------------------------
# Build tasks.
#
# This baseline group is only the public egress half of the build boundary.
#
# A build runs repository-authored code. It needs the public internet -- a
# package mirror, a module proxy, the registry its base image comes from -- and
# it must not reach anything in this VPC: not the control plane, not the state
# store, not another application, not another build.
#
# No ingress rule reaches a build; no VPC resource admits this baseline group.
# The selected slot's separate group (modules/build) is the only NFS route to
# that slot's own EFS mount targets. Security-group permissions are a union, so
# shared NFS egress here would defeat per-slot filesystem isolation.
#
# The metadata service is not a hole here, and it is worth saying why it is not
# handled with a rule. Fargate exposes no EC2 instance metadata at all, and the
# task credentials endpoint serves a task role -- which the build task
# definitions in modules/build deliberately do not have.
# ------------------------------------------------------------------------------

resource "aws_security_group" "build" {
  name        = "${var.name_prefix}-build"
  description = "AppHub build tasks; runs repository-authored code"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-build" })
}

resource "aws_vpc_security_group_egress_rule" "build_public" {
  for_each = toset(["80", "443"])

  security_group_id = aws_security_group.build.id
  description       = "Package mirrors, module proxies and public registries"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "build_dns" {
  for_each = toset(["tcp", "udp"])

  security_group_id = aws_security_group.build.id
  description       = "DNS resolution"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 53
  to_port           = 53
  ip_protocol       = each.value
}


# ------------------------------------------------------------------------------
# Deployed applications: the operator's baseline posture.
#
# Egress only, deliberately. Every reachability claim about a deployed
# application is made by the per-service group AppHub creates from that
# application's compute.ServiceSpec.Ingress. A blanket ingress rule here would
# apply to every application at once and could not be revoked per application,
# which is the fail-open shape PlacementConfig.SecurityGroups warns against.
# ------------------------------------------------------------------------------

resource "aws_security_group" "apps" {
  name        = "${var.name_prefix}-apps"
  description = "Baseline posture attached to every deployed application task"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-apps" })
}

resource "aws_vpc_security_group_egress_rule" "apps_all" {
  security_group_id = aws_security_group.apps.id
  description       = "Outbound traffic from deployed applications"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# The internal ALB's health check. The `internal` entrypoint does not answer
# /ping, so the target group checks Traefik's ping on the entrypoint that does:
# `web` (80) in alb-wildcard mode. Without this rule every internal target
# fails its check and internal routes serve nothing. Strict mode needs no rule
# here: its ping entrypoint (8080) already admits the VPC CIDR above. The
# internal ALB forwards requests only to 8081; this admits its health checker,
# not its listeners, to the public entrypoint.
resource "aws_vpc_security_group_ingress_rule" "traefik_health_from_internal_lb" {
  count = var.internal_ingress_enabled && var.ingress_tls_mode == "alb-wildcard" ? 1 : 0

  security_group_id            = aws_security_group.traefik.id
  description                  = "Internal ALB health check on the ping entrypoint"
  referenced_security_group_id = aws_security_group.internal_alb[0].id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
}
