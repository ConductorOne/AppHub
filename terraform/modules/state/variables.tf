# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

variable "table_name" {
  description = <<-EOT
    DynamoDB table name. It is also the namespace of the derived GitHub App key
    parameter (/apphub/<tableName>/github-app/private-key), so two deployments
    sharing a region and account must not share it.
  EOT
  type        = string
}

variable "environment" {
  description = "Environment tag applied to the table."
  type        = string
}

variable "point_in_time_recovery" {
  description = "Enable DynamoDB point-in-time recovery."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Enable DynamoDB deletion protection."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = <<-EOT
    Customer-managed KMS key for the table. Null uses the AWS-owned key, which
    is still encryption at rest but is not separately authorised: any principal
    granted the DynamoDB actions can read.
  EOT
  type        = string
  default     = null
}

variable "secret_handoff_key_deletion_window_days" {
  description = <<-EOT
    Waiting period before the application-secret handoff key is actually
    deleted, if it is ever scheduled for deletion. Every ciphertext already
    stored in the control-plane table becomes permanently unreadable once the
    key is gone, so this is a safety margin to notice and cancel a deletion,
    not a retention policy.
  EOT
  type        = number
  default     = 30

  validation {
    condition     = var.secret_handoff_key_deletion_window_days >= 7 && var.secret_handoff_key_deletion_window_days <= 30
    error_message = "secret_handoff_key_deletion_window_days must be between 7 and 30, the range KMS accepts."
  }
}
