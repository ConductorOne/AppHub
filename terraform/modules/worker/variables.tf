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

variable "role_name" {
  description = <<-EOT
    Exact IAM role name for the worker. modules/deploy-target writes it into the
    push role's trust policy before this role exists, so both are given the same
    value by the environment rather than one reading the other.
  EOT
  type        = string
}

# ------------------------------------------------------------------------------
# Placement
# ------------------------------------------------------------------------------

variable "cluster_id" {
  description = "ECS cluster the worker service runs in."
  type        = string
}

variable "execution_role_arn" {
  description = "Task execution role the ECS agent uses to start the worker."
  type        = string
}

variable "private_subnet_ids" {
  description = "Subnets the worker task runs in."
  type        = list(string)
}

variable "security_group_id" {
  description = "Security group of the worker task. It has no ingress rule; nothing calls the worker."
  type        = string
}

variable "desired_count" {
  description = <<-EOT
    Worker tasks. One by default.

    More than one is safe: the control plane claims each deployment in a
    fenced transaction, and each build slot is leased through the control-plane
    store, so two workers neither run one deployment nor share one slot. Every
    worker draws on the same fixed set of build slots, though, so raising this
    without raising the slot count only moves the queue.
  EOT
  type        = number
  default     = 1
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
  description = "Must match the architecture worker_image was built for."
  type        = string
  default     = "X86_64"
}

variable "ephemeral_storage_gib" {
  description = <<-EOT
    Task scratch space for source checkouts. One shallow clone per concurrent
    deployment lands here; a build's own scratch space is the build task's, not
    this.
  EOT
  type        = number
  default     = 50
}

# ------------------------------------------------------------------------------
# Images and configuration
# ------------------------------------------------------------------------------

variable "worker_image" {
  description = "AppHub worker image, built from the repository's worker.Dockerfile."
  type        = string
}

variable "aws_cli_image" {
  description = <<-EOT
    Image the init container runs to materialise the two configuration
    documents and, when relational is enabled, the RDS CA PEM. It needs a shell,
    the AWS CLI and coreutils. Pin it by digest for a deployment you intend to
    keep: it runs with the worker's task role.
    IDs and source credentials are injected by the execution role, not this.
  EOT
  type        = string
  default     = "public.ecr.aws/aws-cli/aws-cli:latest"
}

variable "config_dir" {
  description = "Absolute directory the init container writes configuration into."
  type        = string
  default     = "/config"
}

variable "work_dir" {
  description = <<-EOT
    The worker's private checkout directory, and worker.workDir in the rendered
    configuration. Task-local ephemeral storage rather than the build share: git
    on a network filesystem is slow, and a checkout is the worker's own
    business. Only the build context crosses to the share.
  EOT
  type        = string
  default     = "/var/lib/apphub/work"
}

variable "share_path" {
  description = <<-EOT
    Parent directory of the per-slot EFS mounts; build.task.sharePath in the
    provider configuration. Slot N is mounted at share_path/N.
  EOT
  type        = string
  default     = "/var/lib/apphub/build"
}

variable "secret_dir" {
  description = <<-EOT
    Unused by the ECS path: source credentials are injected as environment
    variables from Parameter Store. Kept so an existing environment copy that
    still passes it does not break.
  EOT
  type        = string
  default     = "/var/lib/apphub/secrets"
}

variable "parameter_prefix" {
  type = string
}

variable "apphub_config_parameter" {
  type = string
}

variable "aws_config_parameter" {
  type = string
}

variable "rds_ca_parameter" {
  description = "SSM parameter containing the RDS CA PEM, or null if relational databases are disabled."
  type        = string
  default     = null
}

variable "github_key_parameters" {
  description = "Unused. Source credentials are injected via injected_secrets."
  type        = map(string)
  default     = {}
}

variable "injected_secrets" {
  description = <<-EOT
    ECS secrets block for the worker container: name/valueFrom pairs whose
    valueFrom is an SSM parameter ARN. IDs and source credentials, never
    upstream login secrets.
  EOT
  type = list(object({
    name      = string
    valueFrom = string
  }))
  default = []
}

variable "environment_variables" {
  description = <<-EOT
    Extra non-secret environment for the worker container. Never a secret: a
    task definition's environment is readable by anyone who can describe it.
    Secrets and operator IDs come from injected_secrets.
  EOT
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "kms_key_arn" {
  description = "KMS key encrypting the SecureString parameters, if one is configured."
  type        = string
  default     = null
}

variable "handoff_kms_key_arn" {
  description = <<-EOT
    Application-secret handoff key (modules/state's output of the same name).
    The worker's task role gets kms:Decrypt on it; the API holds the matching
    encrypt grant instead, with an explicit deny on decrypt
    (modules/control-plane). Empty disables the feature: the worker gets no
    statement, and secrets.handoffKmsKeyArn is omitted from the rendered
    configuration.
  EOT
  type        = string
  default     = ""
}

variable "traffic_log_group_arn" {
  description = <<-EOT
    ARN of the Traefik access-log group (modules/ingress's traefik_log_group_arn
    output) the worker runs its periodic CloudWatch Logs Insights query
    against. Empty disables the feature: the worker gets neither IAM
    statement, matching modules/config's traffic_log_group being empty.
  EOT
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# State
# ------------------------------------------------------------------------------

variable "table_name" {
  type = string
}

variable "table_arn" {
  type = string
}

variable "table_index_arns" {
  type = list(string)
}

variable "audit_table_arn" {
  description = "Separate audit event table; the worker may append and probe readiness but not list events."
  type        = string
}

variable "deploy_policy_arns" {
  description = "Policies from modules/deploy-target carrying everything the worker may do to the target."
  type        = list(string)
}

# ------------------------------------------------------------------------------
# Builds
# ------------------------------------------------------------------------------

variable "build_cluster_arn" {
  description = "Cluster build tasks run in. Every build grant is conditioned on it."
  type        = string
}

variable "build_cluster_name" {
  description = "Name of that cluster, for the task ARN pattern DescribeTasks and StopTask are scoped to."
  type        = string
}

variable "build_task_definition_families" {
  description = <<-EOT
    Build task definition families, one per slot. Scoped by family rather than
    by revision so that registering a new revision does not need an IAM change
    to become runnable.
  EOT
  type        = list(string)
}

variable "build_execution_role_arn" {
  description = "The build task's execution role, which RunTask passes to ECS. The only role the worker may pass."
  type        = string
}

variable "build_file_system_ids" {
  description = "One EFS filesystem per build slot, in task-definition order."
  type        = list(string)

  validation {
    condition     = length(var.build_file_system_ids) == length(var.build_task_definition_families)
    error_message = "build_file_system_ids must match build_task_definition_families one-for-one."
  }
}

variable "build_access_point_ids" {
  description = "Worker access points paired with build_file_system_ids."
  type        = list(string)

  validation {
    condition     = length(var.build_access_point_ids) == length(var.build_file_system_ids)
    error_message = "build_access_point_ids must match build_file_system_ids one-for-one."
  }
}

variable "build_log_group_arn" {
  description = "Log group builds write to and the worker reads back."
  type        = string
}

# ------------------------------------------------------------------------------
# Logs
# ------------------------------------------------------------------------------

variable "log_group_prefix" {
  type = string
}

variable "log_retention_days" {
  type    = number
  default = 90
}
