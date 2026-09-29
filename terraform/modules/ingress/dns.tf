# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# One wildcard record covers every application hostname AppHub will ever
# publish under the route domain.
#
# It has to be a wildcard. Hostnames are chosen by users at deploy time and
# reserved by the control plane before anything exists to point at; a
# per-application record would mean Terraform learning about a deployment that
# has not happened yet.
#
# alb-wildcard also issues an ACM certificate for the same name. The ALB
# HTTPS listener holds it; Traefik does not.

resource "aws_route53_record" "apps_wildcard" {
  zone_id = var.hosted_zone_id
  name    = "*.${var.apps_domain}"
  type    = "A"

  alias {
    name                   = local.apps_lb.dns_name
    zone_id                = local.apps_lb.zone_id
    evaluate_target_health = true
  }
}

# The apex of the route domain, so that the domain itself resolves rather than
# returning NXDOMAIN while every name under it works.
resource "aws_route53_record" "apps_apex" {
  count = var.create_apps_apex_record ? 1 : 0

  zone_id = var.hosted_zone_id
  name    = var.apps_domain
  type    = "A"

  alias {
    name                   = local.apps_lb.dns_name
    zone_id                = local.apps_lb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_acm_certificate" "apps_wildcard" {
  count = local.tls_edge ? 1 : 0

  domain_name       = "*.${var.apps_domain}"
  validation_method = "DNS"

  tags = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "apps_cert_validation" {
  for_each = local.tls_edge ? {
    for dvo in aws_acm_certificate.apps_wildcard[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  } : {}

  zone_id         = var.hosted_zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record]
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "apps_wildcard" {
  count = local.tls_edge ? 1 : 0

  certificate_arn         = aws_acm_certificate.apps_wildcard[0].arn
  validation_record_fqdns = [for r in aws_route53_record.apps_cert_validation : r.fqdn]
}

# ------------------------------------------------------------------------------
# Internal applications ingress.
#
# One wildcard record and one ACM certificate for *.internal.<apps_domain>,
# both in this module's public hosted zone -- there is no private zone here.
# The internal ALB is reachable only from inside the VPC (its security group
# enforces that; see modules/network), so a public DNS answer for it is not a
# reachability leak, and putting the record in a private zone instead would
# have needed a second zone associated with the VPC and bought nothing.
#
# Unlike apps_wildcard, this certificate and record exist in both
# ingress_tls_mode values: the internal ALB always terminates TLS itself.
# ------------------------------------------------------------------------------

resource "aws_acm_certificate" "internal" {
  count = var.internal_ingress_enabled ? 1 : 0

  domain_name       = "*.internal.${var.apps_domain}"
  validation_method = "DNS"

  tags = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "internal_cert_validation" {
  for_each = var.internal_ingress_enabled ? {
    for dvo in aws_acm_certificate.internal[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  } : {}

  zone_id         = var.hosted_zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record]
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "internal" {
  count = var.internal_ingress_enabled ? 1 : 0

  certificate_arn         = aws_acm_certificate.internal[0].arn
  validation_record_fqdns = [for r in aws_route53_record.internal_cert_validation : r.fqdn]
}

resource "aws_route53_record" "internal_wildcard" {
  count = var.internal_ingress_enabled ? 1 : 0

  zone_id = var.hosted_zone_id
  name    = "*.internal.${var.apps_domain}"
  type    = "A"

  alias {
    name                   = aws_lb.internal[0].dns_name
    zone_id                = aws_lb.internal[0].zone_id
    evaluate_target_health = true
  }
}
