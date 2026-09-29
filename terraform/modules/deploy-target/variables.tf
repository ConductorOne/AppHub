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

variable "cluster_name" {
  description = "ECS cluster applications are deployed into."
  type        = string
}

variable "vpc_id" {
  description = "VPC into which the worker may create application security groups."
  type        = string
}

variable "worker_role_name" {
  description = <<-EOT
    Name of the deployment worker's IAM role. It is the only principal allowed
    to assume the push role.

    A name rather than an ARN so that this module does not have to wait for the
    worker module: the two would otherwise depend on each other through the
    rendered configuration. The name is constructed the same way in both
    places, so a change has to be made in the environment that passes it.
  EOT
  type        = string
}

variable "control_plane_table_arn" {
  description = "AppHub's own control-plane table. The workload boundary denies every deployed role access to it."
  type        = string
}

variable "control_plane_name_prefix" {
  description = "Prefix shared by the Terraform-owned API, worker, Traefik and oauth2-proxy ECS service names and task-definition families, including its trailing hyphen."
  type        = string

  validation {
    condition     = length(trimspace(var.control_plane_name_prefix)) > 0 && endswith(var.control_plane_name_prefix, "-")
    error_message = "control_plane_name_prefix must be nonempty and end in a hyphen."
  }
}

variable "audit_table_arn" {
  description = "AppHub's audit event table. Deployed workloads have no access, and the worker cannot manage its schema."
  type        = string
}

variable "control_plane_parameter_prefix" {
  description = <<-EOT
    AppHub's own SSM parameter hierarchy, leading slash and no trailing slash.
    The workload boundary denies every deployed role access to it; application
    secrets live under secret_path_prefix instead.
  EOT
  type        = string
}

# ------------------------------------------------------------------------------
# Naming. Every prefix here also appears in the rendered provider
# configuration, and the IAM scoping above is written against it: a prefix
# changed in one place and not the other produces a deploy that fails with an
# access denial rather than a validation error.
# ------------------------------------------------------------------------------

variable "identity_path_prefix" {
  description = "IAM path every workload role is created under, with leading and trailing slashes."
  type        = string
  default     = "/apphub/"

  validation {
    condition     = startswith(var.identity_path_prefix, "/") && endswith(var.identity_path_prefix, "/") && var.identity_path_prefix != "/"
    error_message = "identity_path_prefix must be a non-root IAM path with leading and trailing /."
  }
}

variable "identity_name_prefix" {
  description = "Prefix on every workload role name."
  type        = string
  default     = "apphub-"
}

variable "execution_role_path_prefix" {
  description = <<-EOT
    IAM path the per-service task execution roles are created under. Separate
    from identity_path_prefix because the two roles have different blast radii:
    a task role is the workload, an execution role is the agent that starts it.
  EOT
  type        = string
  default     = "/apphub-execution/"

  validation {
    condition     = startswith(var.execution_role_path_prefix, "/") && endswith(var.execution_role_path_prefix, "/") && var.execution_role_path_prefix != "/"
    error_message = "execution_role_path_prefix must be a non-root IAM path with leading and trailing /."
  }
}

variable "registry_name_prefix" {
  description = "Prefix on every application ECR repository name, e.g. apphub/apps/."
  type        = string
  default     = "apphub/apps/"
}

variable "container_name_prefix" {
  description = "Prefix on every ECS service name and task-definition family; must not match a Terraform-owned service."
  type        = string
  default     = "apphub-apps-"

  validation {
    condition = length(trimspace(var.container_name_prefix)) > 0 && alltrue([
      for suffix in ["api", "worker", "traefik", "oauth2-proxy"] :
      !startswith("${var.control_plane_name_prefix}${suffix}", var.container_name_prefix)
    ])
    error_message = "container_name_prefix must be nonempty and disjoint from the API, worker, Traefik and oauth2-proxy ECS names."
  }
}

variable "secret_path_prefix" {
  description = "SSM hierarchy application secrets live under, leading slash and no trailing slash."
  type        = string

  validation {
    condition     = startswith(var.secret_path_prefix, "/") && !endswith(var.secret_path_prefix, "/")
    error_message = "secret_path_prefix must start with / and must not end with /."
  }
}

variable "app_log_group_prefix" {
  description = "CloudWatch log group prefix for application tasks, with a trailing slash."
  type        = string
  default     = "/apphub/apps/"
}

variable "key_value_name_prefix" {
  description = "Prefix on every application DynamoDB table name; must not include the control-plane or audit table."
  type        = string
  default     = "apphub-apps-"

  validation {
    condition = length(trimspace(var.key_value_name_prefix)) > 0 && (
      !var.enable_key_value_port || alltrue([
        for arn in [var.control_plane_table_arn, var.audit_table_arn] :
        !startswith(element(split("/", arn), length(split("/", arn)) - 1), var.key_value_name_prefix)
      ])
    )
    error_message = "key_value_name_prefix must be nonempty and exclude the control-plane and audit tables when the port is enabled."
  }
}

variable "object_store_name_prefix" {
  description = "Prefix on every application S3 bucket name; required when the object-store port is enabled, so no bucket policy can render as arn:s3:::*."
  type        = string
  default     = ""

  validation {
    condition     = !var.enable_object_store_port || (length(var.object_store_name_prefix) > 0 && can(regex("^[a-z0-9][a-z0-9.-]*$", var.object_store_name_prefix)))
    error_message = "object_store_name_prefix must be nonempty and contain only lowercase bucket-name characters when enable_object_store_port is true."
  }
}

variable "relational_name_prefix" {
  description = "Prefix on every Aurora cluster, instance and subnet group name."
  type        = string
  default     = "apphub-"
}

variable "function_name_prefix" {
  description = "Prefix on every Lambda function name."
  type        = string
  default     = "apphub-"
}

variable "endpoint_name_prefix" {
  description = "Prefix on application endpoint load balancers, target groups and security groups; must match Config.Endpoint.NamePrefix. Keep it short (at most 13 characters) to leave space for digested ELBv2 names."
  type        = string

  validation {
    condition     = length(var.endpoint_name_prefix) >= 1 && (!var.enable_function_port || length(var.endpoint_name_prefix) <= 13) && can(regex("^(?:[a-z0-9]+-?)*$", var.endpoint_name_prefix))
    error_message = "endpoint_name_prefix must be nonempty lowercase alphanumeric/hyphen without adjacent hyphens, and at most 13 characters when the function port is enabled."
  }
}

variable "resource_tag_key" {
  description = <<-EOT
    Ownership tag AppHub writes on everything it creates. It is the marker
    compute.ErrNotOwned is decided by (compute/aws/names.go), and the security
    group statements are conditioned on it, so it must match what the provider
    actually writes.
  EOT
  type        = string
  default     = "apphub:managed-by"
}

variable "resource_tag_value" {
  description = "Value of the ownership tag. It names the project, never a deployment."
  type        = string
  default     = "apphub"
}

# ------------------------------------------------------------------------------
# Optional ports
# ------------------------------------------------------------------------------

variable "enable_key_value_port" {
  description = "Grant the worker authority over application DynamoDB tables (compute.CapKeyValueTable)."
  type        = bool
  default     = true
}

variable "enable_object_store_port" {
  description = "Grant the worker authority over application S3 buckets (compute.CapObjectStore)."
  type        = bool
  default     = true
}

variable "enable_relational_port" {
  description = "Grant the worker authority over application Aurora clusters (compute.CapRelationalDatabase)."
  type        = bool
  default     = false
}

variable "enable_function_port" {
  description = "Grant the worker authority over Lambda functions and their load balancers (compute.CapFunction)."
  type        = bool
  default     = false
}
