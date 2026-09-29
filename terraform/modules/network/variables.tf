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

variable "vpc_cidr" {
  description = "IPv4 CIDR for the VPC. Subnets are carved from it with cidrsubnet(cidr, 8, n)."
  type        = string
  default     = "10.60.0.0/16"
}

variable "availability_zone_count" {
  description = <<-EOT
    How many availability zones to spread public and private subnets across.
    Two is the floor: an application load balancer requires subnets in two
    zones and so does an Aurora subnet group, both of which AppHub's compute
    provider can be asked for.
  EOT
  type        = number
  default     = 2

  validation {
    condition     = var.availability_zone_count >= 2
    error_message = "availability_zone_count must be at least 2."
  }
}

variable "nat_gateway_count" {
  description = <<-EOT
    NAT gateways to create, one per public subnet. One is cheap and is a
    single zone's failure away from taking private egress with it; set it to
    availability_zone_count for production.
  EOT
  type        = number
  default     = 1
}

variable "portal_allowed_cidrs" {
  description = "CIDRs allowed to reach the portal load balancer on 80/443."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "apps_allowed_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach the applications ingress on 80/443. This is the
    network boundary in front of oauth2-proxy, not a replacement for it:
    published application hostnames are unauthenticated unless the route asks
    for the ingress auth middleware.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "ingress_tls_mode" {
  description = "alb-wildcard or strict. Selects whether Traefik is reachable from the load balancer only (ALB) or from client CIDRs (NLB client-IP preservation)."
  type        = string
  default     = "alb-wildcard"

  validation {
    condition     = contains(["alb-wildcard", "strict"], var.ingress_tls_mode)
    error_message = "ingress_tls_mode must be alb-wildcard or strict."
  }
}

variable "internal_ingress_enabled" {
  description = <<-EOT
    Create the internal applications load balancer and its security group.
    It is independent of ingress_tls_mode: the internal load balancer always
    terminates TLS with its own ACM certificate and forwards plaintext HTTP
    to Traefik, the same way the public alb-wildcard path does, so that a
    private application's requests still show up in Traefik's access log
    without ever being reachable from the internet.
  EOT
  type        = bool
  default     = true
}
