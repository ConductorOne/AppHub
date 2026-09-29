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

variable "vpc_id" {
  description = "VPC the service discovery namespace is associated with."
  type        = string
}

variable "parameter_prefix" {
  description = <<-EOT
    SSM parameter hierarchy this deployment owns, leading slash and no trailing
    slash. The task execution role may read parameters under it and nowhere
    else.
  EOT
  type        = string

  validation {
    condition     = startswith(var.parameter_prefix, "/") && !endswith(var.parameter_prefix, "/")
    error_message = "parameter_prefix must start with / and must not end with /."
  }
}

variable "container_insights" {
  description = "Enable ECS Container Insights on the cluster."
  type        = bool
  default     = true
}

variable "image_retention_count" {
  description = "How many images to keep in each of AppHub's own ECR repositories."
  type        = number
  default     = 20
}
