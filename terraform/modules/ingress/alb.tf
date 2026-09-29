# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Union Station's applications ingress: an ALB terminates TLS with an ACM
# wildcard and forwards HTTP to Traefik. Traefik never holds a certificate.
#
# Created only when ingress_tls_mode is alb-wildcard. The strict path is
# nlb.tf: TCP passthrough, Traefik ACME.

resource "aws_lb" "apps_alb" {
  count = local.tls_edge ? 1 : 0

  name               = "${var.name_prefix}-apps"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.apps_lb_security_group_id]
  subnets            = var.public_subnet_ids

  tags = local.tags
}

resource "aws_lb_target_group" "traefik_alb" {
  count = local.tls_edge ? 1 : 0

  name        = "${var.name_prefix}-traefik"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  deregistration_delay = 30

  health_check {
    path                = "/ping"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = local.tags
}

resource "aws_lb_listener" "apps_alb_http" {
  count = local.tls_edge ? 1 : 0

  load_balancer_arn = aws_lb.apps_alb[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "apps_alb_https" {
  count = local.tls_edge ? 1 : 0

  load_balancer_arn = aws_lb.apps_alb[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.apps_wildcard[0].certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.traefik_alb[0].arn
  }
}
