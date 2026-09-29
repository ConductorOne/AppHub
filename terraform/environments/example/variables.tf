# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

variable "aws_region" {
  description = "Region the whole deployment lives in. One region per deployment; a second region is a second target."
  type        = string
}

variable "environment" {
  description = "Environment name, e.g. dev or prod. It appears in resource names and in the parameter hierarchy."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for every resource name and IAM path."
  type        = string
  default     = "apphub"
}

# ------------------------------------------------------------------------------
# DNS
# ------------------------------------------------------------------------------

variable "hosted_zone_name" {
  description = "Route53 hosted zone, with a trailing dot, e.g. example.com."
  type        = string
}

variable "portal_subdomain" {
  description = "Label the portal is published under, within hosted_zone_name."
  type        = string
  default     = "apphub"
}

variable "apps_subdomain" {
  description = <<-EOT
    Label deployed applications are published under. Every application gets one
    label beneath it: reports.<apps_subdomain>.<zone>.

    Keep it distinct from portal_subdomain. They are served by different load
    balancers, and an application is not permitted to take the portal's name.
  EOT
  type        = string
  default     = "apps"
}

variable "create_apps_apex_record" {
  description = "Point the application domain itself at the ingress, not only the names beneath it."
  type        = bool
  default     = false
}

# ------------------------------------------------------------------------------
# Network
# ------------------------------------------------------------------------------

variable "vpc_cidr" {
  type    = string
  default = "10.60.0.0/16"
}

variable "availability_zone_count" {
  type    = number
  default = 2
}

variable "nat_gateway_count" {
  description = "One is enough for a development deployment. Match availability_zone_count for production."
  type        = number
  default     = 1
}

variable "portal_allowed_cidrs" {
  description = "CIDRs allowed to reach the portal. The portal authenticates every request, but there is no reason to offer it to the whole internet if it need not be."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "apps_allowed_cidrs" {
  description = "CIDRs allowed to reach published applications."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# ------------------------------------------------------------------------------
# Ingress
# ------------------------------------------------------------------------------

variable "ingress_tls_mode" {
  description = <<-EOT
    Who terminates TLS for published applications.

    alb-wildcard (default): ALB + ACM certificate for *.apps.<zone>, Traefik
    HTTP-only. Matches Union Station. No ACME email.

    strict: NLB TCP passthrough, Traefik issues a Let's Encrypt certificate
    per hostname. Requires acme_email. One Traefik replica.
  EOT
  type        = string
  default     = "alb-wildcard"

  validation {
    condition     = contains(["alb-wildcard", "strict"], var.ingress_tls_mode)
    error_message = "ingress_tls_mode must be alb-wildcard or strict."
  }
}

variable "acme_email" {
  description = "Registration address for Traefik's ACME account. Required when ingress_tls_mode is strict."
  type        = string
  default     = ""
}

variable "acme_ca_server" {
  description = <<-EOT
    ACME directory URL. Empty is Let's Encrypt production.

    Use https://acme-staging-v02.api.letsencrypt.org/directory while bringing
    the ingress up. Production issuance limits are low enough that a handful of
    rebuilds exhausts them for a week, and the failure lands on every published
    hostname at once.
  EOT
  type        = string
  default     = ""
}

variable "certificate_resolver" {
  description = <<-EOT
    Traefik's ACME resolver name when ingress_tls_mode is strict. It is also
    deployConfig.routeCertificate and the value the placement's certificates
    map resolves it to -- one string in three places, because the provider
    writes it verbatim into a Traefik label in strict mode.
  EOT
  type        = string
  default     = "platform"
}

variable "ingress_auth_middleware" {
  description = "ForwardAuth middleware name; container.ingressAuthMiddleware in the provider configuration."
  type        = string
  default     = "oauth-auth"
}

variable "oauth2_proxy_provider" {
  description = "oauth2-proxy provider for the applications ingress: google or oidc."
  type        = string
  default     = "google"
}

variable "oauth2_proxy_oidc_issuer_url" {
  description = "Issuer URL, required when oauth2_proxy_provider is oidc."
  type        = string
  default     = ""
}

variable "internal_ingress_enabled" {
  description = <<-EOT
    Create the internal applications load balancer, Traefik's internal
    entrypoint, and *.internal.<apps_subdomain>.<zone>'s certificate and DNS
    record, so a private application still passes through Traefik -- and so
    appears in its access log -- while staying unreachable from the internet.

    On (the default): every environment gets it, since it costs one more ALB
    and one more ACM certificate and nothing depends on it being off. Turn it
    off only for a deployment that will never publish an internal route.
  EOT
  type        = bool
  default     = true
}

variable "oauth2_proxy_email_domains" {
  description = <<-EOT
    Exact email domains admitted to applications published behind the ingress
    middleware. No default: oauth2-proxy refuses to start without at least one,
    so an unset value is a failed deployment rather than a closed door.
  EOT
  type        = list(string)
}

# ------------------------------------------------------------------------------
# Identity for the portal itself
# ------------------------------------------------------------------------------

variable "auth_providers" {
  description = <<-EOT
    Identity providers the portal admits users from. Register
    https://<portal>/auth/<id>/callback with each, and set each client secret
    into the parameter Terraform creates for it.
  EOT
  type = list(object({
    id              = string
    label           = string
    kind            = string
    issuer          = optional(string, "")
    client_id       = string
    allowed_emails  = optional(list(string), [])
    allowed_domains = optional(list(string), [])
  }))
}

variable "auth_admins" {
  description = <<-EOT
    Administrators by exact (provider, subject) pair.

    A first apply has none. Sign in, read the Subject at /settings/sessions,
    add it here, apply again. There is deliberately no way to become an
    administrator by email address.
  EOT
  type = list(object({
    provider_id = string
    subject     = string
  }))
  default = []
}

variable "auth_clients" {
  description = "Additional public OAuth clients. apphub-cli is pre-registered and must not be listed."
  type = list(object({
    id            = string
    redirect_uris = list(string)
  }))
  default = []
}

variable "c1_directory_tenant_url" {
  description = <<-EOT
    ConductorOne tenant base URL for directory sync (group lookups, role
    mapping). Empty leaves the integration off. Must be set together with
    c1_directory_client_id. The client secret is a Parameter Store
    SecureString set out of band; see terraform output secrets_to_set.
  EOT
  type        = string
  default     = ""
}

variable "c1_directory_client_id" {
  description = "ConductorOne directory OAuth client id. Not a secret."
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# What may be deployed
# ------------------------------------------------------------------------------

variable "source_repositories" {
  description = "Optional extra allowlist of exact repository URLs. Empty means the Workspace GitHub App installation is the allowlist."
  type = list(object({
    url                    = string
    auth                   = string
    github_app_id          = optional(number, 0)
    github_installation_id = optional(number, 0)
    github_key_basename    = optional(string, "")
  }))
  default = []
}

variable "allowed_source_hosts" {
  type    = list(string)
  default = ["github.com"]
}

variable "resource_sizes" {
  description = "Approved CPU/memory pairs: CPU millicores, memory MiB."
  type = list(object({
    cpu    = number
    memory = number
  }))
  default = [
    { cpu = 256, memory = 512 },
    { cpu = 512, memory = 1024 },
    { cpu = 1024, memory = 2048 },
    { cpu = 2048, memory = 4096 },
  ]
}

variable "max_replicas" {
  type    = number
  default = 4
}

variable "relational_max_capacity_units" {
  description = "Operator ceiling on Aurora capacity requests, in abstract units (2 ACUs per unit by default)."
  type        = number
  default     = 2

  validation {
    condition     = var.relational_max_capacity_units >= 0.25 && var.relational_max_capacity_units <= 128
    error_message = "relational_max_capacity_units must be between 0.25 and 128 units (0.5–256 ACUs)."
  }
}

variable "execution_modes" {
  type    = list(string)
  default = ["service", "scheduled"]
}

variable "public_exposure" {
  description = "Whether applications may publish a hostname. A published hostname is unauthenticated unless the application authenticates its own requests."
  type        = bool
  default     = true
}

variable "enable_key_value_port" {
  type    = bool
  default = true
}

variable "enable_object_store_port" {
  type    = bool
  default = true
}

variable "enable_relational_port" {
  description = "Offer Aurora PostgreSQL 18 alongside DynamoDB. Requires an operator-supplied RDS CA PEM."
  type        = bool
  default     = true
}

variable "rds_ca_pem_file" {
  description = "Absolute path to an existing RDS regional CA PEM bundle (not the global bundle); required when enable_relational_port is true. Terraform publishes it to SSM and the worker mounts it for verify-full TLS."
  type        = string
  default     = ""

  validation {
    condition     = !var.enable_relational_port || (startswith(var.rds_ca_pem_file, "/") && try(length(regexall("(?s)-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----", file(var.rds_ca_pem_file))) > 0, false))
    error_message = "Set rds_ca_pem_file to an existing absolute path containing an RDS regional CA PEM certificate when enable_relational_port is true, or set enable_relational_port = false."
  }

  validation {
    condition     = !var.enable_relational_port || try(length(file(var.rds_ca_pem_file)) <= 8192, true)
    error_message = "rds_ca_pem_file exceeds the 8 KiB Parameter Store limit; use the RDS regional bundle for aws_region, not the global bundle."
  }
}

variable "enable_function_port" {
  type    = bool
  default = false
}

variable "function_runtimes" {
  description = "Operator-approved Lambda runtimes when the optional function port is enabled."
  type        = list(string)
  default     = []

  validation {
    condition     = !var.enable_function_port || length(var.function_runtimes) > 0
    error_message = "function_runtimes must list approved runtimes when enable_function_port is true."
  }
}

# ------------------------------------------------------------------------------
# Images
# ------------------------------------------------------------------------------

variable "server_image" {
  description = <<-EOT
    AppHub API image. Empty (the default) runs the cluster ECR server
    repository's :latest tag. Pushing a new image and rolling it onto ECS is
    `make push-server` then `make promote-api`, not a terraform apply.
  EOT
  type        = string
  default     = ""
}

variable "worker_image" {
  description = <<-EOT
    AppHub worker image. Empty (the default) runs the cluster ECR worker
    repository's :latest tag. Pushing a new image and rolling it onto ECS is
    `make push-worker` then `make promote-worker`, not a terraform apply.
  EOT
  type        = string
  default     = ""
}

variable "builder_image" {
  description = <<-EOT
    The builder image, pinned by digest, for the first `terraform apply` that
    creates the build task families. Empty (the default) is filled by
    `make push-builder` writing builder_image.auto.tfvars. Later pins are
    `make promote-builder`: the runner refuses a tag, and Terraform ignores
    container_definitions after create so an apply cannot revert a promotion.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.builder_image == "" || can(regex("@sha256:[0-9a-f]{64}$", var.builder_image))
    error_message = "builder_image must be empty (make push-builder writes the first digest) or pinned by a SHA-256 digest."
  }
}

variable "traefik_image" {
  description = "Required digest-pinned Traefik image built from terraform/plugins/cookiestrip/Dockerfile.traefik and published before deployment."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.traefik_image))
    error_message = "traefik_image must pin the published first-party ingress image by SHA-256 digest."
  }
}

variable "cpu_architecture" {
  description = "Architecture server_image was built for: X86_64 or ARM64."
  type        = string
  default     = "X86_64"
}

# ------------------------------------------------------------------------------
# Sizing
# ------------------------------------------------------------------------------

variable "api_cpu" {
  type    = number
  default = 1024
}

variable "api_memory" {
  type    = number
  default = 2048
}

variable "api_desired_count" {
  type    = number
  default = 2
}

variable "api_environment_variables" {
  description = "Extra non-secret environment for the API container. Secrets and operator IDs are injected from Parameter Store."
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "worker_cpu" {
  type    = number
  default = 1024
}

variable "worker_memory" {
  type    = number
  default = 2048
}

variable "worker_desired_count" {
  description = <<-EOT
    Worker tasks. One is enough: the control plane claims work in a fenced
    transaction, so a second worker loses the race rather than duplicating a
    deployment, and every worker draws on the same fixed set of build slots.
  EOT
  type        = number
  default     = 1
}

variable "worker_max_concurrent_deployments" {
  description = "Deployments one worker runs at once. Must not exceed build_slots, or builds queue."
  type        = number
  default     = 2
}

variable "build_slots" {
  description = <<-EOT
    Concurrent builds, and therefore the number of build task definitions and
    EFS access points. Each build is confined to its own slot by its access
    point's root directory, which is why this is a provisioned set rather than
    a number the runner picks.
  EOT
  type        = number
  default     = 2
}

variable "build_cpu" {
  description = "Task size for one build. A build is CPU bound far more than memory bound."
  type        = number
  default     = 2048
}

variable "build_memory" {
  type    = number
  default = 8192
}

variable "build_ephemeral_storage_gib" {
  description = <<-EOT
    Scratch space for one build. kaniko unpacks every layer of the image it is
    building into it, so this bounds the largest image this deployment can
    build.
  EOT
  type        = number
  default     = 50
}

variable "worker_deployment_timeout" {
  type    = string
  default = "45m"
}

variable "worker_environment_variables" {
  description = "Extra non-secret environment for the worker container. Secrets and operator IDs are injected from Parameter Store."
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

# ------------------------------------------------------------------------------
# State and logs
# ------------------------------------------------------------------------------

variable "point_in_time_recovery" {
  type    = bool
  default = true
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "secret_handoff_key_deletion_window_days" {
  description = <<-EOT
    Waiting period before the application-secret handoff key is actually
    deleted, if it is ever scheduled for deletion. See
    modules/state's variable of the same name.
  EOT
  type        = number
  default     = 30
}

variable "log_retention_days" {
  type    = number
  default = 90
}
