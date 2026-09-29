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

variable "portal_domain" {
  description = "Fully-qualified portal hostname. It must be the host of the configured publicOrigin."
  type        = string
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone holding portal_domain and its certificate validation records."
  type        = string
}

variable "ssl_policy" {
  description = "Listener TLS policy."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

# ------------------------------------------------------------------------------
# Network and cluster
# ------------------------------------------------------------------------------

variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "private_subnet_ids" { type = list(string) }
variable "alb_security_group_id" { type = string }
variable "service_security_group_id" { type = string }
variable "cluster_id" { type = string }
variable "execution_role_arn" { type = string }
variable "namespace_id" {
  description = "Cloud Map private DNS namespace in which the API registers as apphub-api."
  type        = string
}

# ------------------------------------------------------------------------------
# State
# ------------------------------------------------------------------------------

variable "table_name" {
  description = "Control-plane table name. The GitHub App key parameter path is derived from it."
  type        = string
}

variable "table_arn" { type = string }

variable "table_index_arns" {
  description = "Index ARNs, which a Query on GSI1 is authorised against separately from the table."
  type        = list(string)
}

variable "audit_table_arn" {
  description = "Separate audit event table; the API can append and query events."
  type        = string
}

# ------------------------------------------------------------------------------
# Configuration published by modules/config
# ------------------------------------------------------------------------------

variable "parameter_prefix" {
  description = "SSM hierarchy this deployment owns, leading slash and no trailing slash."
  type        = string
}

variable "apphub_config_parameter" {
  description = "SSM parameter holding the shared operator configuration."
  type        = string
}

variable "aws_config_parameter" {
  description = "SSM parameter holding the compute provider configuration."
  type        = string
}

variable "auth_provider_ids" {
  description = "Identity provider ids, used to publish the OIDC callback URLs to register."
  type        = list(string)
}

variable "injected_secrets" {
  description = <<-EOT
    ECS secrets block for the API container: name/valueFrom pairs whose
    valueFrom is an SSM parameter ARN. IDs and secrets, never the YAML
    documents (those exceed the environment-variable budget and stay files).
  EOT
  type = list(object({
    name      = string
    valueFrom = string
  }))
}

variable "config_dir" {
  description = "Absolute directory the init container writes configuration documents into."
  type        = string
  default     = "/config"
}

variable "kms_key_arn" {
  description = "KMS key encrypting the SecureString parameters, if one is configured."
  type        = string
  default     = null
}

variable "handoff_kms_key_arn" {
  description = <<-EOT
    Application-secret handoff key (modules/state's output of the same name).
    The API's task role gets kms:Encrypt on it and an explicit deny on
    kms:Decrypt; the worker holds the matching decrypt grant instead
    (modules/worker). Empty disables the feature: the API gets neither
    statement, and secrets.handoffKmsKeyArn is omitted from the rendered
    configuration.
  EOT
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# Images and sizing
# ------------------------------------------------------------------------------

variable "server_image" {
  description = "AppHub API image, built from the repository's Dockerfile."
  type        = string
}

variable "aws_cli_image" {
  description = <<-EOT
    Image the init container runs. It needs a shell, the AWS CLI, and
    coreutils; nothing in this deployment depends on which one. Pin it by
    digest for a deployment you intend to keep: it runs with the API's task
    role and writes the YAML documents the API trusts. IDs and secrets are
    injected by the execution role, not this.
  EOT
  type        = string
  default     = "public.ecr.aws/aws-cli/aws-cli:latest"
}

variable "cpu" {
  type    = number
  default = 1024
}

variable "memory" {
  type    = number
  default = 2048
}

variable "cpu_architecture" {
  description = "Must match the architecture server_image was built for."
  type        = string
  default     = "X86_64"
}

variable "desired_count" {
  type    = number
  default = 2
}

variable "enable_execute_command" {
  description = <<-EOT
    Break-glass ECS Exec into the API task. Off by default: a shell inside the
    task that holds the control plane's persistence credentials is not
    something to leave enabled.
  EOT
  type        = bool
  default     = false
}

variable "environment_variables" {
  description = <<-EOT
    Extra environment variables for the API container, as ECS name/value pairs.

    Never put a secret here -- a task definition's environment is readable by
    anyone who can describe it. Secrets and operator IDs come from
    injected_secrets (Parameter Store via the ECS secrets block).
  EOT
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

# ------------------------------------------------------------------------------
# Logs
# ------------------------------------------------------------------------------

variable "log_group_prefix" {
  description = "CloudWatch log group prefix, e.g. /apphub/prod."
  type        = string
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "observability_log_group_arns" {
  description = <<-EOT
    ARNs of the log groups the Workspace log viewer may read. Empty leaves the
    API with no CloudWatch read permission at all, which is what an empty
    observability.logGroups means.
  EOT
  type        = list(string)
  default     = []
}
