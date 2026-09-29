# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Internal applications ingress: a private-subnet-only ALB that terminates
# TLS with an ACM certificate for *.internal.<apps_domain> (dns.tf) and
# forwards plaintext HTTP to Traefik's `internal` entrypoint.
#
# Unlike alb.tf/nlb.tf this load balancer exists in both ingress_tls_mode
# values. Its whole purpose is letting a private application's requests pass
# through Traefik -- so they show up in its JSON access log -- while never
# being reachable from the internet, and that purpose does not depend on how
# the public path terminates TLS. See modules/network's aws_security_group.
# internal_alb: it admits 443 (and 80, redirected) from the VPC CIDR only.

resource "aws_lb" "internal" {
  count = var.internal_ingress_enabled ? 1 : 0

  name               = "${var.name_prefix}-internal"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [var.internal_alb_security_group_id]
  subnets            = var.private_subnet_ids

  tags = local.tags
}

resource "aws_lb_target_group" "traefik_internal" {
  count = var.internal_ingress_enabled ? 1 : 0

  name        = "${var.name_prefix}-traefik-internal"
  port        = local.internal_traefik_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  deregistration_delay = 30

  health_check {
    path     = "/ping"
    port     = local.tls_edge ? "80" : "8080"
    protocol = "HTTP"

    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = local.tags
}

resource "aws_lb_listener" "internal_http" {
  count = var.internal_ingress_enabled ? 1 : 0

  load_balancer_arn = aws_lb.internal[0].arn
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

resource "aws_lb_listener" "internal_https" {
  count = var.internal_ingress_enabled ? 1 : 0

  load_balancer_arn = aws_lb.internal[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.internal[0].certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.traefik_internal[0].arn
  }
}
