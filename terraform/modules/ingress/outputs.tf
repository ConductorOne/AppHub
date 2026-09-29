# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

output "load_balancer_dns_name" {
  description = "DNS name of the applications load balancer."
  value       = local.apps_lb.dns_name
}

output "auth_host" {
  description = "Hostname oauth2-proxy answers the OAuth callback on; register it with the identity provider."
  value       = local.auth_host
}

output "redirect_url" {
  description = "Exact redirect URI to register with the identity provider for oauth2-proxy."
  value       = "https://${local.auth_host}/oauth2/callback"
}

output "certificate_resolver" {
  description = "Traefik certificate resolver name; what deployConfig.routeCertificate must resolve to."
  value       = var.certificate_resolver
}

output "ingress_auth_middleware" {
  description = "ForwardAuth middleware name; container.ingressAuthMiddleware in the provider configuration."
  value       = var.ingress_auth_middleware
}

output "ingress_cookie_strip_middleware" {
  description = "Middleware applied last to EVERY application router (including public paths); container.ingressCookieStripMiddleware."
  value       = local.ingress_cookie_strip_middleware
}

output "tls_termination" {
  description = "container.tlsTermination in the provider configuration: edge or ingress."
  value       = local.tls_edge ? "edge" : "ingress"
}

output "client_id_parameter_name" {
  description = "SSM parameter holding the oauth2-proxy client id. Set it with `aws ssm put-parameter --overwrite`."
  value       = aws_ssm_parameter.client_id.name
}

output "client_secret_parameter_name" {
  description = "SSM parameter holding the oauth2-proxy client secret. Set it with `aws ssm put-parameter --overwrite`."
  value       = aws_ssm_parameter.client_secret.name
}

output "traefik_log_group" {
  description = "CloudWatch log group Traefik writes to."
  value       = aws_cloudwatch_log_group.traefik.name
}

output "traefik_log_group_arn" {
  description = "ARN of the CloudWatch log group Traefik writes to; the worker's traffic_log_group_arn."
  value       = aws_cloudwatch_log_group.traefik.arn
}

output "oauth2_proxy_log_group" {
  description = "CloudWatch log group oauth2-proxy writes to."
  value       = aws_cloudwatch_log_group.oauth2_proxy.name
}

output "internal_load_balancer_dns_name" {
  description = "DNS name of the internal applications load balancer. Null when internal_ingress_enabled is false."
  value       = try(aws_lb.internal[0].dns_name, null)
}

output "internal_apps_domain" {
  description = "DNS suffix private application hostnames live under: internal.<apps_domain>. Null when internal_ingress_enabled is false."
  value       = var.internal_ingress_enabled ? "internal.${var.apps_domain}" : null
}

output "internal_certificate_arn" {
  description = <<-EOT
    ACM certificate for *.internal.<apps_domain>, for modules/config's
    placement.certificates map. Null when internal_ingress_enabled is false.
  EOT
  value       = try(aws_acm_certificate_validation.internal[0].certificate_arn, null)
}
