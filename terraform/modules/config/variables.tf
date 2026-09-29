# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

variable "environment" {
  description = "Environment tag applied to every parameter."
  type        = string
}

variable "aws_region" {
  description = "Region for the store, the compute provider and CloudWatch Logs reads."
  type        = string
}

variable "parameter_prefix" {
  description = "SSM parameter hierarchy this deployment owns, leading slash and no trailing slash."
  type        = string
}

variable "kms_key_id" {
  description = "KMS key encrypting the SecureString parameters. Null uses the AWS-managed SSM key."
  type        = string
  default     = null
}

# ------------------------------------------------------------------------------
# Where each process materialises what it reads
# ------------------------------------------------------------------------------

variable "api_config_dir" {
  description = "Absolute directory both task init containers write configuration documents into; the worker also writes the RDS CA here."
  type        = string
  default     = "/config"
}

variable "worker_secret_dir" {
  description = <<-EOT
    Unused by the ECS path: source credentials are injected as environment
    variables from Parameter Store. Kept so an existing environment copy that
    still passes it does not break.
  EOT
  type        = string
  default     = "/var/lib/apphub/secrets"
}

# ------------------------------------------------------------------------------
# The portal
# ------------------------------------------------------------------------------

variable "public_origin" {
  description = <<-EOT
    Canonical HTTPS origin: lowercase host, no default port, path, query or
    fragment. It is used for cookies, CSRF, OIDC callbacks, the OAuth issuer
    and resource audiences alike, so it is one value and not a set of them.
  EOT
  type        = string
}

variable "listen_address" {
  description = "Address the API binds. TLS is terminated at the load balancer in front of it."
  type        = string
  default     = "0.0.0.0:8080"
}

variable "static_dir" {
  description = "Built frontend directory inside the API image."
  type        = string
  default     = "/app/frontend/dist"
}

variable "table_name" {
  description = "Control-plane DynamoDB table."
  type        = string
}

variable "audit_table_name" {
  description = "Separate DynamoDB table for immutable audit events."
  type        = string
}

variable "handoff_kms_key_arn" {
  description = <<-EOT
    Application-secret handoff key (modules/state's output of the same
    name), rendered as secrets.handoffKmsKeyArn. Empty leaves the whole
    `secrets` block out of the document, which is how AppHub itself decides
    the per-application secrets feature is off.
  EOT
  type        = string
  default     = ""
}

variable "traffic_log_group" {
  description = <<-EOT
    Name (not ARN) of the Traefik access-log group the worker queries for
    per-application traffic, rendered as traffic.logGroup. Empty leaves the
    whole `traffic` block out of the document, which is how both serve and
    worker decide the per-application traffic-tracking feature is off.
  EOT
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# Identity
# ------------------------------------------------------------------------------

variable "auth_providers" {
  description = <<-EOT
    Identity providers the portal admits users from.

    allowed_emails and allowed_domains are exact: no wildcards, no patterns.
    Equal email addresses across two providers are two different users, because
    identity is (issuer, subject) and never an email claim.

    Register {public_origin}/auth/{id}/callback with each provider.
  EOT
  type = list(object({
    id              = string
    label           = string
    kind            = string # google | oidc
    issuer          = optional(string, "")
    client_id       = string
    allowed_emails  = optional(list(string), [])
    allowed_domains = optional(list(string), [])
  }))

  validation {
    condition     = length(var.auth_providers) > 0
    error_message = "At least one identity provider is required."
  }

  validation {
    condition     = alltrue([for p in var.auth_providers : contains(["google", "oidc"], p.kind)])
    error_message = "Each provider kind must be google or oidc."
  }

  validation {
    condition     = alltrue([for p in var.auth_providers : p.kind != "oidc" || p.issuer != ""])
    error_message = "A provider of kind oidc requires an issuer."
  }

  validation {
    condition = alltrue([
      for p in var.auth_providers : length(p.allowed_emails) + length(p.allowed_domains) > 0
    ])
    error_message = "Each provider needs at least one exact email or domain admission rule."
  }
}

variable "auth_admins" {
  description = <<-EOT
    Administrators, by exact (provider, subject) pair. Email is never an
    administrator identifier.

    A fresh deployment has none that match a real person. Sign in once, read
    the Subject shown at /settings/sessions, put it here, and apply again.
  EOT
  type = list(object({
    provider_id = string
    subject     = string
  }))
  default = []
}

variable "auth_clients" {
  description = "Additional public OAuth clients. The native apphub-cli client is pre-registered."
  type = list(object({
    id            = string
    redirect_uris = list(string)
  }))
  default = []
}

# ------------------------------------------------------------------------------
# Optional ConductorOne directory (group/entitlement sync)
# ------------------------------------------------------------------------------

variable "c1_directory_tenant_url" {
  description = <<-EOT
    ConductorOne tenant base URL for directory sync. Empty leaves the
    integration off. Must be set together with c1_directory_client_id.
  EOT
  type        = string
  default     = ""
}

variable "c1_directory_client_id" {
  description = "ConductorOne directory OAuth client id. Not a secret."
  type        = string
  default     = ""

  validation {
    condition     = (var.c1_directory_tenant_url == "") == (var.c1_directory_client_id == "")
    error_message = "c1_directory_tenant_url and c1_directory_client_id must be set together, or both left empty."
  }
}

# ------------------------------------------------------------------------------
# Source
# ------------------------------------------------------------------------------

variable "source_repositories" {
  description = <<-EOT
    Optional extra allowlist of exact repository URLs. Empty (the default)
    means the Workspace GitHub App installation is the allowlist: any
    repository in an installed, non-suspended account may be deployed.

    github_key_basename names the PEM file on the build host for a
    per-repository GitHub App override; the matching parameter is created
    for the operator to fill in.
  EOT
  type = list(object({
    url                    = string
    auth                   = string # public | githubApp
    github_app_id          = optional(number, 0)
    github_installation_id = optional(number, 0)
    github_key_basename    = optional(string, "")
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.source_repositories : contains(["public", "githubApp"], r.auth)])
    error_message = "Each repository auth must be public or githubApp."
  }

  validation {
    condition = alltrue([
      for r in var.source_repositories :
      r.auth != "githubApp" || (r.github_app_id > 0 && r.github_installation_id > 0 && r.github_key_basename != "")
    ])
    error_message = "A githubApp repository requires github_app_id, github_installation_id and github_key_basename."
  }
}

variable "allowed_source_hosts" {
  description = "Exact lowercase DNS hosts an application's source may be fetched from."
  type        = list(string)
  default     = ["github.com"]
}

# ------------------------------------------------------------------------------
# The deployment target
# ------------------------------------------------------------------------------

variable "target_id" {
  description = "Stable identifier applications select this target by. Immutable after an application is created."
  type        = string
  default     = "primary"
}

variable "target_label" {
  description = "Human-readable name of the target, shown in the portal."
  type        = string
  default     = "Primary"
}

variable "resource_prefix" {
  description = "Prefix on every name the deployment module asks a provider to create."
  type        = string
}

variable "apps_domain" {
  description = "DNS suffix published application hostnames live under; deployConfig.routeDomain."
  type        = string
}

variable "route_certificate" {
  description = <<-EOT
    Certificate reference published routes are served with, as the compute
    provider knows it. It is resolved through the placement's `certificates`
    map to the Traefik certificate resolver's name.
  EOT
  type        = string
  default     = "platform"
}

variable "certificate_resolver" {
  description = "Traefik ACME resolver name route_certificate resolves to."
  type        = string
  default     = "platform"
}

variable "internal_ingress_enabled" {
  description = <<-EOT
    Render internalRouteDomain, internalRouteCertificate and
    container.internalEntrypoint. Must agree with modules/ingress's variable
    of the same name: when it is false there is no internal ALB, no internal
    Traefik entrypoint and no internal ACM certificate for
    internal_certificate_arn to name.
  EOT
  type        = bool
  default     = true
}

variable "internal_certificate_arn" {
  description = <<-EOT
    ACM certificate for the internal ingress's *.internal.apps_domain
    (modules/ingress's internal_certificate_arn output), placed in the
    placement's certificates map under the internalRouteCertificate ref key.
    Required when internal_ingress_enabled is true; ignored otherwise.
  EOT
  type        = string
  default     = ""
}

variable "secret_store_name" {
  description = <<-EOT
    Name the credential layer uses for this provider's secret store. Unset is
    fail-closed: a credential reference naming a store is then refused, because
    nothing establishes that the store it names is the one this provider backs.
  EOT
  type        = string
  default     = "aws-ssm"
}

variable "deploy_wait_timeout" {
  description = "How long a deployment waits for a rollout to converge."
  type        = string
  default     = "20m"
}

variable "resource_sizes" {
  description = "Approved CPU/memory pairs, in the compute port's units: CPU millicores, memory MiB."
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
  description = "Ceiling on replicas an application may request."
  type        = number
  default     = 4
}

variable "relational_max_capacity_units" {
  description = "Operator ceiling for both relational capacity limits, in abstract units (2 ACUs per unit by default)."
  type        = number
  default     = 2

  validation {
    condition     = var.relational_max_capacity_units >= 0.25 && var.relational_max_capacity_units <= 128
    error_message = "relational_max_capacity_units must be between 0.25 and 128 units (0.5–256 ACUs)."
  }
}

variable "execution_modes" {
  description = "Enabled execution modes: service, scheduled, or both."
  type        = list(string)
  default     = ["service", "scheduled"]
}

variable "public_exposure" {
  description = <<-EOT
    Whether applications may publish a hostname at all.

    A published hostname is unauthenticated unless the application authenticates
    its own requests: signing into the portal does not protect it, and the
    ingress auth middleware is applied per route.
  EOT
  type        = bool
  default     = true
}

# ------------------------------------------------------------------------------
# Provider coordinates
# ------------------------------------------------------------------------------

variable "provider_name" {
  description = "Name this provider reports; every compute.Ref records it."
  type        = string
  default     = "aws"
}

variable "placement_name" {
  description = "Name of the single configured placement."
  type        = string
  default     = "default"
}

variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "cluster_arn" { type = string }
variable "apps_security_group_id" { type = string }
variable "traefik_security_group_id" { type = string }
variable "control_plane_security_group_ids" { type = list(string) }

variable "identity_path_prefix" { type = string }
variable "identity_name_prefix" { type = string }
variable "execution_role_path_prefix" { type = string }
variable "workload_boundary_arn" { type = string }
variable "registry_name_prefix" { type = string }
variable "container_name_prefix" { type = string }
variable "secret_path_prefix" { type = string }
variable "app_log_group_prefix" { type = string }
variable "push_role_arn" { type = string }
variable "ingress_auth_middleware" { type = string }
variable "ingress_cookie_strip_middleware" {
  description = "ECS middleware that removes the shared oauth2-proxy session cookie before any application receives the request."
  type        = string

  validation {
    condition     = trimspace(var.ingress_cookie_strip_middleware) != ""
    error_message = "ingress_cookie_strip_middleware must name an installed cookie-strip middleware."
  }
}
variable "enable_function_port" {
  description = "Render the Lambda runtime and endpoint config when the function port is enabled."
  type        = bool
  default     = false
}
variable "function_name_prefix" {
  description = "Name prefix for application Lambda functions; must match the deploy-target policy."
  type        = string
}
variable "endpoint_name_prefix" {
  description = "Name prefix for application ELBv2 endpoints; must match the deploy-target policy."
  type        = string
}
variable "function_runtimes" {
  description = "Operator-approved Lambda runtimes when the function port is enabled."
  type        = list(string)
  default     = []

  validation {
    condition     = !var.enable_function_port || length(var.function_runtimes) > 0
    error_message = "function_runtimes must name at least one runtime when enable_function_port is true."
  }
}
variable "mcp_auth_backend_url" {
  description = "Private AppHub API origin Traefik uses for hosted MCP ForwardAuth and discovery."
  type        = string
}

variable "tls_termination" {
  description = "container.tlsTermination: ingress (Traefik ACME) or edge (ALB wildcard)."
  type        = string
  default     = "ingress"

  validation {
    condition     = contains(["ingress", "edge"], var.tls_termination)
    error_message = "tls_termination must be ingress or edge."
  }
}

variable "build_executor_path" {
  description = "Absolute path of the kaniko executor inside the build container."
  type        = string
  default     = "/kaniko/executor"
}

variable "build_pusher_path" {
  description = <<-EOT
    Absolute path of the binary that uploads what the build produced. It runs
    in a process that never executed the Dockerfile, which is the whole point:
    a builder that pushes is a builder holding a live registry credential while
    running repository-authored code.
  EOT
  type        = string
  default     = "/usr/local/bin/crane"
}

variable "build_session_duration" {
  description = "Lifetime of a build's push credential. Fifteen minutes is the floor STS will issue."
  type        = string
  default     = "15m"
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
  type    = bool
  default = false
}

variable "rds_ca_pem_file" {
  description = "Existing operator-supplied regional RDS CA PEM file; published for the worker when relational is enabled."
  type        = string
  default     = ""

  validation {
    condition     = !var.enable_relational_port || (startswith(var.rds_ca_pem_file, "/") && try(length(regexall("(?s)-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----", file(var.rds_ca_pem_file))) > 0, false))
    error_message = "rds_ca_pem_file must be an existing absolute path containing an RDS CA PEM certificate when enable_relational_port is true."
  }

  validation {
    condition     = !var.enable_relational_port || try(length(file(var.rds_ca_pem_file)) <= 8192, true)
    error_message = "rds_ca_pem_file exceeds the 8 KiB Parameter Store limit; use the RDS regional bundle for aws_region, not the global bundle."
  }
}

variable "key_value_name_prefix" {
  type    = string
  default = "apphub-"
}

variable "object_store_name_prefix" {
  type    = string
  default = ""
}

variable "relational_name_prefix" {
  type    = string
  default = "apphub-"
}

variable "relational_engine_versions" {
  description = "Major engine versions this deployment will provision, per engine."
  type        = map(list(string))
  default     = { postgres = ["16", "18"] }
}

# ------------------------------------------------------------------------------
# Where a build runs
#
# Every value here is also a Terraform resource in modules/build or
# modules/network. They are passed rather than looked up because the rendered
# document is what the provider is *told*: compute/aws's Config exists so that
# no identifier belonging to a deployment is discovered or compiled in.
# ------------------------------------------------------------------------------

variable "build_cluster_arn" {
  description = "Cluster build tasks run in."
  type        = string
}

variable "build_task_definitions" {
  description = <<-EOT
    Build task definition families, one per concurrency slot. Each is bound to
    its own EFS access point, and that access point's root directory is what
    confines a build to its own slot -- so the number of them is the number of
    builds that can run at once, and it must be at least
    worker_max_concurrent_deployments.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.build_task_definitions) > 0
    error_message = "At least one build task definition is required."
  }
}

variable "build_container_name" {
  description = "Container in each build task definition whose command the runner overrides."
  type        = string
  default     = "builder"
}

variable "build_security_group_id" {
  description = "Public HTTP(S)/DNS egress group shared by build tasks; it must not allow NFS."
  type        = string
}
variable "build_slot_security_group_ids" {
  description = "One slot-only NFS egress group per build task definition, in the same order."
  type        = list(string)

  validation {
    condition     = length(var.build_slot_security_group_ids) == length(var.build_task_definitions)
    error_message = "build_slot_security_group_ids must match build_task_definitions one-for-one."
  }
}

variable "build_share_path" {
  description = "Where the worker sees the build share."
  type        = string
  default     = "/var/lib/apphub/build"
}

variable "build_slot_path" {
  description = "Where a build task sees its own slot."
  type        = string
  default     = "/build"
}

variable "build_log_group" {
  description = "CloudWatch log group builds write to and the worker reads back."
  type        = string
}

variable "build_log_stream_prefix" {
  description = "awslogs stream prefix on the build task definitions; the runner composes stream names from it."
  type        = string
  default     = "build"
}

# ------------------------------------------------------------------------------
# The worker's execution limits
# ------------------------------------------------------------------------------

variable "worker_work_dir" {
  type    = string
  default = "/var/lib/apphub/work"
}

variable "worker_max_concurrent_deployments" {
  type    = number
  default = 2
}

variable "worker_deployment_timeout" {
  type    = string
  default = "45m"
}

variable "worker_heartbeat_interval" {
  type    = string
  default = "30s"
}

variable "worker_stale_after" {
  description = <<-EOT
    How long without a heartbeat before an attempt is interrupted. An
    interrupted attempt never reruns on its own and keeps its execution lock
    until an administrator resolves it, so this is not a retry interval.
  EOT
  type        = string
  default     = "5m"
}

# ------------------------------------------------------------------------------
# Observability
# ------------------------------------------------------------------------------

variable "observability_log_groups" {
  description = <<-EOT
    CloudWatch log groups an administrator may read from the Workspace. Empty
    disables that surface entirely rather than defaulting to whatever a name
    happens to resolve to.
  EOT
  type = list(object({
    name      = string
    log_group = string
  }))
  default = []
}
