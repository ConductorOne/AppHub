# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Strict TLS: a network load balancer that passes TCP through to Traefik, which
# terminates TLS with per-host ACME certificates.
#
# Created only when ingress_tls_mode is strict. The alb-wildcard path is alb.tf:
# the ALB holds an ACM wildcard and Traefik sees HTTP.
#
# Why TCP passthrough exists as an option: public exposure still builds a route
# with a certificate reference (internal/controlplane/input.go), and with
# container.tlsTermination=ingress the AWS provider compiles that into Traefik
# labels on the websecure entrypoint with tls.certresolver. A router configured
# that way is served by Traefik's own TLS, so Traefik has to be the thing
# holding a certificate.
#
# The portal is always an ALB with an ACM certificate in modules/control-plane.
# That split is independent of this mode: the control plane does not depend on
# the ingress it manages.

resource "aws_lb" "apps_nlb" {
  count = local.tls_strict ? 1 : 0

  name               = "${var.name_prefix}-apps"
  internal           = false
  load_balancer_type = "network"
  security_groups    = [var.apps_lb_security_group_id]
  subnets            = var.public_subnet_ids

  enable_cross_zone_load_balancing = true

  tags = local.tags
}

# Two target groups, one per entrypoint, both with the PROXY protocol turned
# on. Without it Traefik's idea of the client address is the load balancer's
# own interface, which would make every access log line and every
# client-address-based decision -- rate limiting, IP allowlisting in a
# middleware an operator adds later -- wrong in the same direction.
resource "aws_lb_target_group" "traefik_http" {
  count = local.tls_strict ? 1 : 0

  name        = "${var.name_prefix}-traefik-http"
  port        = 80
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  proxy_protocol_v2    = true
  deregistration_delay = 30

  health_check {
    protocol            = "HTTP"
    port                = "8080"
    path                = "/ping"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    matcher             = "200"
  }

  tags = local.tags
}

resource "aws_lb_target_group" "traefik_https" {
  count = local.tls_strict ? 1 : 0

  name        = "${var.name_prefix}-traefik-https"
  port        = 443
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  proxy_protocol_v2    = true
  deregistration_delay = 30

  health_check {
    protocol            = "HTTP"
    port                = "8080"
    path                = "/ping"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    matcher             = "200"
  }

  tags = local.tags
}

resource "aws_lb_listener" "apps_http" {
  count = local.tls_strict ? 1 : 0

  load_balancer_arn = aws_lb.apps_nlb[0].arn
  port              = 80
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.traefik_http[0].arn
  }
}

resource "aws_lb_listener" "apps_https" {
  count = local.tls_strict ? 1 : 0

  load_balancer_arn = aws_lb.apps_nlb[0].arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.traefik_https[0].arn
  }
}
