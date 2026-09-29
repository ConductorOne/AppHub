# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The portal's own load balancer, with its own ACM certificate.
#
# Separate from the applications ingress on purpose. The portal is one fixed
# hostname known at apply time, which is exactly the case ACM and an ALB handle
# best; and keeping it off the ingress means the control plane does not depend
# on the thing it manages. A Traefik rollout, an ACME failure, or a mistake in
# a route label cannot take the portal -- and with it the ability to fix any of
# them -- down.

locals {
  tags = { Environment = var.environment }
}

resource "aws_acm_certificate" "portal" {
  domain_name       = var.portal_domain
  validation_method = "DNS"

  tags = merge(local.tags, { Name = var.portal_domain })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "portal_validation" {
  for_each = {
    for option in aws_acm_certificate.portal.domain_validation_options :
    option.domain_name => {
      name   = option.resource_record_name
      type   = option.resource_record_type
      record = option.resource_record_value
    }
  }

  zone_id         = var.hosted_zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record]
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "portal" {
  certificate_arn         = aws_acm_certificate.portal.arn
  validation_record_fqdns = [for record in aws_route53_record.portal_validation : record.fqdn]
}

resource "aws_lb" "portal" {
  name               = "${var.name_prefix}-portal"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_security_group_id]
  subnets            = var.public_subnet_ids

  drop_invalid_header_fields = true

  tags = local.tags
}

resource "aws_lb_target_group" "portal" {
  name        = "${var.name_prefix}-portal"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  deregistration_delay = 30

  health_check {
    path                = "/healthz"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 15
    matcher             = "200"
  }

  tags = local.tags
}

resource "aws_lb_listener" "portal_http" {
  load_balancer_arn = aws_lb.portal.arn
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

resource "aws_lb_listener" "portal_https" {
  load_balancer_arn = aws_lb.portal.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = aws_acm_certificate_validation.portal.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.portal.arn
  }
}

resource "aws_route53_record" "portal" {
  zone_id = var.hosted_zone_id
  name    = var.portal_domain
  type    = "A"

  alias {
    name                   = aws_lb.portal.dns_name
    zone_id                = aws_lb.portal.zone_id
    evaluate_target_health = true
  }
}
