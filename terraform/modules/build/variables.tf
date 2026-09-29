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

variable "private_subnet_ids" {
  description = "Subnets where each slot's file system has a mount target. Build tasks run in the same subnets."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) > 0
    error_message = "private_subnet_ids must contain at least one subnet."
  }
}

variable "vpc_id" {
  description = "VPC where the slot-specific NFS client and mount-target security groups live."
  type        = string
}

variable "worker_security_group_id" {
  description = "Worker security group permitted to mount all slot file systems."
  type        = string
}

variable "slots" {
  description = <<-EOT
    Concurrent builds, and therefore the number of isolated file systems, task
    definitions, access points, and client security groups. Must be at least
    the worker's maxConcurrentDeployments: the runner blocks for a free slot
    rather than failing, so a smaller number is a queue and not an error.
  EOT
  type        = number
  default     = 2

  validation {
    condition     = var.slots >= 1
    error_message = "slots must be at least 1."
  }
}

variable "builder_image" {
  description = <<-EOT
    The builder image, pinned by SHA-256 digest. The runner refuses a tag: the
    builder is the process that executes repository-authored code, and
    "whatever is at that tag today" is not a thing to run it in.

    make tf-up / push-builder publish this repository's builder.Dockerfile
    (ghcr.io/osscontainertools/kaniko, not the archived gcr.io/kaniko-project
    image) for the first apply. Later digest pins are `make promote-builder`,
    not a terraform apply: this resource ignores container_definitions after
    create so an apply cannot roll the pin back.
  EOT
  type        = string

  validation {
    condition     = var.builder_image == "" || can(regex("@sha256:[0-9a-f]{64}$", var.builder_image))
    error_message = "builder_image must be empty (not yet pushed) or pinned by a SHA-256 digest."
  }
}

variable "builder_repository_arn" {
  description = <<-EOT
    ECR repository the builder image is pulled from, when it is mirrored into
    this account. Empty means a public registry, which needs no credential and
    therefore gets no grant.
  EOT
  type        = string
  default     = ""
}

variable "container_name" {
  description = "Name of the builder container. The runner overrides this container's command."
  type        = string
  default     = "builder"
}

variable "cpu" {
  description = "Task size for a build. A build is CPU bound far more than it is memory bound."
  type        = number
  default     = 2048
}

variable "memory" {
  type    = number
  default = 8192
}

variable "cpu_architecture" {
  description = "Architecture builds run on. It decides the architecture of the images they produce."
  type        = string
  default     = "X86_64"
}

variable "ephemeral_storage_gib" {
  description = <<-EOT
    Task scratch space. kaniko unpacks every layer of the image it is building
    into it, so this bounds the largest image this deployment can build.
    Fargate's own floor is 21 and the runner refuses less.
  EOT
  type        = number
  default     = 50

  validation {
    condition     = var.ephemeral_storage_gib >= 21 && var.ephemeral_storage_gib <= 200
    error_message = "ephemeral_storage_gib must be between 21 and 200."
  }
}

variable "log_group_prefix" {
  description = "CloudWatch log group prefix, e.g. /apphub/prod."
  type        = string
}

variable "log_stream_prefix" {
  description = <<-EOT
    awslogs stream prefix. The runner composes the stream name as
    <prefix>/<container>/<task id> to read a build's output back, so this and
    container_name must match what the runner is configured with.
  EOT
  type        = string
  default     = "build"
}

variable "log_retention_days" {
  type    = number
  default = 30
}
