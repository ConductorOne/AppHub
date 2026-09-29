# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

output "table_name" {
  description = "Control-plane table name; store.tableName in the rendered configuration."
  value       = aws_dynamodb_table.main.name
}

output "table_arn" {
  description = "Control-plane table ARN."
  value       = aws_dynamodb_table.main.arn
}

output "table_index_arns" {
  description = "ARNs of the table's indexes, which a DynamoDB Query on GSI1 is authorised against separately."
  value       = ["${aws_dynamodb_table.main.arn}/index/*"]
}

output "audit_table_name" {
  description = "Audit event table name; store.auditTableName in the rendered configuration."
  value       = aws_dynamodb_table.audit.name
}

output "audit_table_arn" {
  description = "Audit event table ARN (no indexes)."
  value       = aws_dynamodb_table.audit.arn
}

output "handoff_kms_key_arn" {
  description = <<-EOT
    Application-secret handoff key. Wired into the API's kms:Encrypt grant
    (modules/control-plane), the worker's kms:Decrypt grant (modules/worker),
    and secrets.handoffKmsKeyArn in the rendered configuration
    (modules/config).
  EOT
  value       = aws_kms_key.secret_handoff.arn
}
