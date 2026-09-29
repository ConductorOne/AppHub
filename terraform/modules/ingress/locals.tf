# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

locals {
  tags = { Environment = var.environment }

  tls_edge   = var.ingress_tls_mode == "alb-wildcard"
  tls_strict = var.ingress_tls_mode == "strict"

  # Exactly one of the two load balancers exists. one() rather than a ternary:
  # Terraform evaluates both branches of a ternary, and aws_lb.apps_alb[0]
  # is an invalid index when count is 0.
  apps_lb = one(concat(aws_lb.apps_alb, aws_lb.apps_nlb))

  # Two replicas are safe only when Traefik is not racing an ACME JSON file.
  traefik_desired_count = coalesce(var.traefik_desired_count, local.tls_edge ? 2 : 1)

  # Trusted sources for PROXY protocol and X-Forwarded-*. Only the load
  # balancer's interfaces speak to Traefik, and they are in this VPC.
  trusted_ips = var.vpc_cidr

  oauth2_entrypoint = local.tls_edge ? "web" : "websecure"

  # The internal entrypoint's container port. Not a variable: web (80),
  # websecure (443) and ping (8080) are literals for the same reason -- an
  # entrypoint name and its port are a Traefik-label contract, not an operator
  # tuning knob, and modules/network's security group rule admitting this port
  # from the internal ALB has to match it by hand regardless.
  internal_traefik_port = 8081
}
