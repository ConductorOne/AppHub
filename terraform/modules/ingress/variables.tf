# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

variable "name_prefix" {
  description = "Prefix for every resource name this module creates."
  type        = string
}

variable "environment" {
  description = "Environment tag applied to every resource."
  type        = string
}

variable "apps_domain" {
  description = <<-EOT
    DNS suffix published application hostnames live under, without a leading
    dot. An application whose route hostname is "reports" is reachable at
    reports.<apps_domain>. This is deployConfig.routeDomain in AppHub's
    configuration and the two must be the same string.
  EOT
  type        = string
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone that contains apps_domain. Used for the wildcard DNS record and, in strict mode, Traefik's ACME DNS-01 challenge."
  type        = string
}

variable "create_apps_apex_record" {
  description = "Also point the route domain itself at the ingress. Leave off when the apex is already in use."
  type        = bool
  default     = false
}

# ------------------------------------------------------------------------------
# Network
# ------------------------------------------------------------------------------

variable "vpc_id" {
  type        = string
  description = "VPC the target groups and mount targets live in."
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR. Traefik trusts X-Forwarded-* (and, in strict mode, the PROXY protocol header) from it and nowhere else."
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Subnets the applications load balancer is placed in."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Subnets Traefik, oauth2-proxy and (in strict mode) the ACME EFS mount targets live in."
}

variable "apps_lb_security_group_id" {
  type        = string
  description = "Security group of the applications load balancer (ALB or NLB)."
}

variable "traefik_security_group_id" {
  type        = string
  description = "Security group of the Traefik tasks."
}

variable "internal_alb_security_group_id" {
  type        = string
  description = <<-EOT
    Security group of the internal applications load balancer. Required when
    internal_ingress_enabled is true; ignored otherwise.
  EOT
  default     = null
}

variable "oauth2_proxy_security_group_id" {
  type        = string
  description = "Security group of the oauth2-proxy tasks."
}

variable "efs_security_group_id" {
  type        = string
  description = "Security group of the EFS mount targets."
}

# ------------------------------------------------------------------------------
# Cluster
# ------------------------------------------------------------------------------

variable "cluster_id" {
  type        = string
  description = "ECS cluster the ingress services run in."
}

variable "cluster_name" {
  type        = string
  description = "ECS cluster name Traefik's ECS provider discovers application tasks in."
}

variable "namespace_id" {
  type        = string
  description = "Cloud Map namespace the oauth2-proxy service registers in."
}

variable "namespace_name" {
  type        = string
  description = "Cloud Map namespace name, used to address oauth2-proxy from the ForwardAuth middleware."
}

variable "execution_role_arn" {
  type        = string
  description = "Task execution role for the ingress tasks."
}

# ------------------------------------------------------------------------------
# Parameters and logs
# ------------------------------------------------------------------------------

variable "parameter_prefix" {
  type        = string
  description = "SSM parameter hierarchy this deployment owns, leading slash and no trailing slash."
}

variable "kms_key_id" {
  type        = string
  description = "KMS key encrypting the SecureString parameters. Null uses the AWS-managed SSM key."
  default     = null
}

variable "log_group_prefix" {
  type        = string
  description = "CloudWatch log group prefix for the ingress services, e.g. /apphub/prod."
}

variable "log_retention_days" {
  type        = number
  description = "Retention for the ingress log groups."
  default     = 90
}

variable "log_level" {
  type        = string
  description = "Traefik log level."
  default     = "INFO"
}

# ------------------------------------------------------------------------------
# TLS
# ------------------------------------------------------------------------------

variable "ingress_tls_mode" {
  description = <<-EOT
    Who terminates TLS for published applications.

    alb-wildcard (default): an application load balancer holds an ACM
    certificate for *.apps_domain and forwards HTTP to Traefik. Traefik has no
    ACME store and can run two replicas. Matches Union Station.

    strict: a network load balancer passes TCP through and Traefik terminates
    TLS with per-host Let's Encrypt certificates over DNS-01. One Traefik
    replica, ACME state on EFS.

    Switching modes replaces the load balancer and requires redeploying every
    published application so its Traefik labels match the new entrypoint.
  EOT
  type        = string
  default     = "alb-wildcard"

  validation {
    condition     = contains(["alb-wildcard", "strict"], var.ingress_tls_mode)
    error_message = "ingress_tls_mode must be alb-wildcard or strict."
  }
}

variable "internal_ingress_enabled" {
  description = <<-EOT
    Create the internal applications load balancer, Traefik's `internal`
    entrypoint, and the *.internal.apps_domain certificate and DNS record.

    Independent of ingress_tls_mode: the internal load balancer always
    terminates TLS with its own ACM certificate and hands Traefik plaintext
    HTTP, in both alb-wildcard and strict deployments. That is what lets a
    private application's requests reach Traefik -- and so appear in its JSON
    access log -- while never being reachable from the internet.
  EOT
  type        = bool
  default     = true
}

variable "certificate_resolver" {
  description = <<-EOT
    Name of Traefik's ACME certificate resolver, used only when
    ingress_tls_mode is strict.

    It is also the value deployConfig.routeCertificate resolves to through the
    placement's `certificates` map. In alb-wildcard the map still exists so a
    public route's certificate reference resolves; compute/aws does not write
    it into a certresolver label.
  EOT
  type        = string
  default     = "platform"
}

variable "acme_email" {
  description = "Registration address for the ACME account. Required when ingress_tls_mode is strict. Expiry notices go here."
  type        = string
  default     = ""

  validation {
    condition     = var.ingress_tls_mode != "strict" || var.acme_email != ""
    error_message = "acme_email is required when ingress_tls_mode is strict."
  }
}

variable "acme_ca_server" {
  description = <<-EOT
    ACME directory URL. Empty uses Let's Encrypt production. Point it at the
    staging directory while working on the ingress: production issuance limits
    are low enough that a few rebuilds exhaust them for a week.
  EOT
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# Traefik
# ------------------------------------------------------------------------------

variable "traefik_image" {
  description = <<-EOT
    Required immutable image built from terraform/plugins/cookiestrip/Dockerfile.traefik,
    containing the first-party local cookie-strip plugin. Build and push it
    before applying, then provide REGISTRY/apphub-traefik@sha256:DIGEST.
    A stock Traefik image has no plugin and cannot safely forward app traffic.
  EOT
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.traefik_image))
    error_message = "traefik_image must be the digest-pinned AppHub Traefik image with the local cookie-strip plugin."
  }
}

variable "traefik_cpu" {
  type    = number
  default = 512
}

variable "traefik_memory" {
  type    = number
  default = 1024
}

variable "traefik_desired_count" {
  description = <<-EOT
    Traefik replicas. Null (the default) is 2 for alb-wildcard and 1 for
    strict. Keep strict at 1 unless certificate issuance has been moved
    somewhere that coordinates: Traefik's ACME store is one JSON file with no
    leader election, and two replicas race into duplicate and then rate-limited
    issuance. See the comment on the service.
  EOT
  type        = number
  default     = null
  nullable    = true
}

variable "discovery_refresh_seconds" {
  description = "How often Traefik re-reads the cluster for application tasks."
  type        = number
  default     = 15
}

# ------------------------------------------------------------------------------
# oauth2-proxy
# ------------------------------------------------------------------------------

variable "ingress_auth_middleware" {
  description = <<-EOT
    Name of the ForwardAuth middleware. It must be the same string as
    container.ingressAuthMiddleware in AppHub's provider configuration: that is
    what gets written into an authenticated route's `middlewares` label, and a
    name Traefik does not know is a route that fails to load rather than one
    that serves unauthenticated.
  EOT
  type        = string
  default     = "oauth-auth"
}

variable "oauth2_proxy_image" {
  type    = string
  default = "quay.io/oauth2-proxy/oauth2-proxy:v7.14.3"
}

variable "oauth2_proxy_provider" {
  description = "oauth2-proxy provider, e.g. google or oidc."
  type        = string
  default     = "google"
}

variable "oauth2_proxy_oidc_issuer_url" {
  description = "Issuer URL, required when oauth2_proxy_provider is oidc and ignored otherwise."
  type        = string
  default     = ""
}

variable "oauth2_proxy_email_domains" {
  description = <<-EOT
    Exact email domains admitted to every application published behind the
    middleware. "*" admits every address the provider will authenticate, which
    is almost never what an operator means.

    There is no empty default. oauth2-proxy treats a missing --email-domain as
    a configuration error and refuses to start, so an empty list does not fail
    closed -- it takes the whole ingress auth layer down instead. Failing here,
    at plan time, is the fail-closed direction.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.oauth2_proxy_email_domains) > 0
    error_message = "oauth2_proxy_email_domains must name at least one domain, or \"*\" to admit every address the provider authenticates."
  }
}

variable "oauth2_proxy_cpu" {
  type    = number
  default = 256
}

variable "oauth2_proxy_memory" {
  type    = number
  default = 512
}

variable "oauth2_proxy_desired_count" {
  type    = number
  default = 2
}
