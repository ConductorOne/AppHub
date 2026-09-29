# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# AppHub's control-plane state and audit event tables.
#
# The mutable state table's schema is not a choice made here. It is exactly what
# store/cmd/devdb's `init` creates and what its `ensureControlPlaneSchema`
# accepts: PK/SK string keys, one global secondary index GSI1 over
# GSI1PK/GSI1SK projecting ALL, and TTL on the `TTL` attribute. A table with a
# different index shape is rejected at startup rather than used, so the two
# definitions have to agree.
#
# It is also the namespace for the GitHub App private key: cmd/apphub derives
# that parameter's path as /apphub/<tableName>/github-app/private-key with no
# operator toggle, which is why the table name is an output.

resource "aws_dynamodb_table" "main" {
  name         = var.table_name
  billing_mode = "PAY_PER_REQUEST"

  # hash_key/range_key rather than key_schema: the provider deprecates these in
  # favour of it but does not yet accept it (hashicorp/aws 6.64), so the
  # deprecation warning stands until it does.
  hash_key  = "PK"
  range_key = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  attribute {
    name = "GSI1PK"
    type = "S"
  }

  attribute {
    name = "GSI1SK"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "GSI1PK"
    range_key       = "GSI1SK"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "TTL"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = var.point_in_time_recovery
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  deletion_protection_enabled = var.deletion_protection

  tags = {
    Name        = var.table_name
    Environment = var.environment
  }

  # The control plane's operation locks, idempotency records and hostname
  # reservations all live in this one table. Replacing it silently would strand
  # every application AppHub has ever deployed, with no way to reconcile them
  # back: refuse instead, and make an operator who really means it remove the
  # table from state by hand.
  lifecycle {
    prevent_destroy = true
  }
}

# Immutable audit events live apart from mutable control-plane state. A single
# partition supports descending chronological Query on SK (UTC time + unique
# ID); expiresAt is a Unix-seconds TTL, set 400 days after the event. DynamoDB
# TTL removal is asynchronous, not a precise deletion deadline.
resource "aws_dynamodb_table" "audit" {
  name         = "${var.table_name}-audit"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "PK"
  range_key = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = var.point_in_time_recovery
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  deletion_protection_enabled = var.deletion_protection

  tags = {
    Name        = "${var.table_name}-audit"
    Environment = var.environment
  }

  lifecycle {
    prevent_destroy = true
  }
}
