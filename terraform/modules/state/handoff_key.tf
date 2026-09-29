# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The application-secret handoff key.
#
# Per-application secrets travel API -> DynamoDB -> worker as ciphertext only:
# the API's task role holds kms:Encrypt on this key and nothing else
# (modules/control-plane), the worker's task role holds the matching
# kms:Decrypt (modules/worker), and both grants are conditioned on the same
# encryption context so a ciphertext produced for one application, secret and
# deployment cannot be decrypted under another's name.
#
# This is a separate key from var.kms_key_arn above: that one (if configured)
# encrypts Terraform-managed operator parameters that Terraform itself can
# read back through the AWS provider's state; this one exists specifically so
# that no principal -- including the API that writes the ciphertext -- can
# ever decrypt an application secret except the worker. Sharing a key would
# mean widening one trust boundary widens the other.
#
# The key policy grants the account root full administration, the
# convention this repository already follows for identity documents whose
# real authorization boundary is expressed through attached IAM policies
# rather than the resource policy itself (see modules/deploy-target's
# workload boundary and deploy policy). Usage authority lives entirely in the
# IAM statements modules/control-plane and modules/worker attach to their own
# roles.

data "aws_iam_policy_document" "secret_handoff_key" {
  statement {
    sid       = "EnableAccountRootAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "secret_handoff" {
  description = "AppHub application-secret handoff: the API encrypts, the worker decrypts, nothing else may"

  # Annual rotation of the underlying key material. Existing ciphertexts
  # remain decryptable under prior material; nothing in the encrypt/decrypt
  # path pins a key version.
  enable_key_rotation = true

  deletion_window_in_days = var.secret_handoff_key_deletion_window_days
  policy                  = data.aws_iam_policy_document.secret_handoff_key.json

  tags = { Environment = var.environment }
}

resource "aws_kms_alias" "secret_handoff" {
  # Derived from table_name (already "<name_prefix>-<environment>") rather
  # than from a new name_prefix variable this module does not otherwise take.
  name          = "alias/${var.table_name}-secret-handoff"
  target_key_id = aws_kms_key.secret_handoff.key_id
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
