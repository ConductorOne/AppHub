# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Publication. Both documents go to Parameter Store rather than into the
# images, because the images are built from a public repository and the
# documents name this deployment's account, network and identity provider.
#
# Intelligent-Tiering rather than Standard: the Standard tier stops at 4 KiB
# and a target with a few resource sizes and a few repositories crosses it. The
# tier change would otherwise arrive as a failed apply on the day somebody adds
# a repository.

resource "aws_ssm_parameter" "apphub_config" {
  name        = "${var.parameter_prefix}/config/apphub.yaml"
  description = "AppHub operator configuration, shared by serve and worker"
  type        = "String"
  tier        = "Intelligent-Tiering"
  value       = yamlencode(local.apphub_config)

  tags = local.tags
}

resource "aws_ssm_parameter" "aws_config" {
  name        = "${var.parameter_prefix}/config/aws.yaml"
  description = "AppHub AWS compute provider configuration"
  type        = "String"
  tier        = "Intelligent-Tiering"
  value       = yamlencode(local.aws_config)

  tags = local.tags
}

# The RDS CA is public trust material, not a credential. Publishing the
# operator-provided regional bundle here keeps it in sync with the worker's
# read-only configuration volume; the API never needs to read the PEM.
resource "aws_ssm_parameter" "rds_ca" {
  count       = var.enable_relational_port ? 1 : 0
  name        = "${var.parameter_prefix}/config/rds-ca.pem"
  description = "RDS regional CA PEM for AppHub worker PostgreSQL verify-full connections"
  type        = "String"
  tier        = "Intelligent-Tiering"
  value       = file(var.rds_ca_pem_file)

  tags = local.tags
}

# ------------------------------------------------------------------------------
# The session transaction key.
#
# Exactly 32 raw bytes, per internal/serverconfig. It is stored base64-encoded
# because Parameter Store holds text, and decoded by apphub serve from
# APPHUB_AUTH_TRANSACTION_KEY (ECS injects the parameter into that variable).
#
# Terraform generates it, which means it is in state. That is the honest trade:
# the alternative is an operator generating it by hand and a deployment that
# cannot start until they do. State lives in an encrypted, versioned bucket;
# treat it accordingly.
#
# Rotating it invalidates every in-flight sign-in transaction. Sessions
# themselves survive.
# ------------------------------------------------------------------------------

resource "random_bytes" "transaction_key" {
  length = 32
}

resource "aws_ssm_parameter" "transaction_key" {
  name        = "${var.parameter_prefix}/auth/transaction-key"
  description = "AppHub session transaction key, base64 of exactly 32 raw bytes"
  type        = "SecureString"
  value       = random_bytes.transaction_key.base64
  key_id      = var.kms_key_id

  tags = local.tags
}

# ------------------------------------------------------------------------------
# The GitHub App webhook HMAC secret.
#
# Generated here, like the transaction key, because AppHub and GitHub must
# share it and a placeholder would be a secret an attacker can guess. The
# value is the standard base64 of 32 random bytes. Paste that string into
# the GitHub App's webhook secret; serve compares it to X-Hub-Signature-256
# and does not decode it further.
#
# ECS injects the parameter into the API container only. The task role cannot
# read it back: the execution role does, through the task definition's
# secrets block, the same way as every other injected secret.
# ------------------------------------------------------------------------------

resource "random_bytes" "github_webhook_secret" {
  length = 32
}

resource "aws_ssm_parameter" "github_webhook_secret" {
  name        = "${var.parameter_prefix}/github/webhook-secret"
  description = "GitHub App webhook HMAC secret. Copy the value into the App's webhook secret."
  type        = "SecureString"
  value       = random_bytes.github_webhook_secret.base64
  key_id      = var.kms_key_id

  tags = local.tags
}

# ------------------------------------------------------------------------------
# One client secret per configured identity provider.
#
# The identity provider issues these, so Terraform creates the parameter and
# then never reads or writes the value again. Set each one with:
#
#   aws ssm put-parameter --overwrite --type SecureString \
#     --name <name> --value "<secret>"
#
# A parameter still holding the placeholder is a sign-in that fails at the
# token exchange, not one that succeeds without a secret.
# ------------------------------------------------------------------------------

resource "aws_ssm_parameter" "client_secret" {
  for_each = { for p in var.auth_providers : p.id => p }

  name        = "${var.parameter_prefix}/auth/${each.key}/client-secret"
  description = "OAuth client secret for the ${each.key} provider, set out of band"
  type        = "SecureString"
  value       = "replace-me"
  key_id      = var.kms_key_id

  lifecycle {
    ignore_changes = [value, insecure_value]
  }

  tags = local.tags
}

resource "aws_ssm_parameter" "client_id" {
  for_each = { for p in var.auth_providers : p.id => p }

  name        = "${var.parameter_prefix}/auth/${each.key}/client-id"
  description = "OAuth client id for the ${each.key} provider"
  type        = "String"
  value       = each.value.client_id

  tags = local.tags
}

# ------------------------------------------------------------------------------
# One GitHub App private key per repository configured for githubApp
# acquisition.
#
# Worker-only: the API is never given one, and internal/ghappkey exists to make
# that a compile-time property rather than a policy somebody has to remember.
#
# This is not the admin-managed key the Workspace GitHub App flow stores.
# cmd/apphub derives that one's location from the table name with no operator
# configuration at all; see modules/control-plane and modules/worker for the
# grants it needs.
# ------------------------------------------------------------------------------

resource "aws_ssm_parameter" "github_app_key" {
  for_each = { for r in var.source_repositories : r.github_key_basename => r if r.auth == "githubApp" }

  name        = "${var.parameter_prefix}/source/${replace(each.key, ".", "-")}"
  description = "GitHub App private key PEM for a configured source repository, set out of band"
  type        = "SecureString"
  value       = "replace-me"
  key_id      = var.kms_key_id

  lifecycle {
    ignore_changes = [value, insecure_value]
  }

  tags = local.tags
}

resource "aws_ssm_parameter" "github_app_id" {
  for_each = { for r in var.source_repositories : r.github_key_basename => r if r.auth == "githubApp" }

  name        = "${var.parameter_prefix}/source/${replace(each.key, ".", "-")}/app-id"
  description = "GitHub App id for a configured source repository"
  type        = "String"
  value       = tostring(each.value.github_app_id)

  tags = local.tags
}

resource "aws_ssm_parameter" "github_installation_id" {
  for_each = { for r in var.source_repositories : r.github_key_basename => r if r.auth == "githubApp" }

  name        = "${var.parameter_prefix}/source/${replace(each.key, ".", "-")}/installation-id"
  description = "GitHub App installation id for a configured source repository"
  type        = "String"
  value       = tostring(each.value.github_installation_id)

  tags = local.tags
}

# ------------------------------------------------------------------------------
# Optional ConductorOne directory. Tenant URL and client id are operator
# configuration (String); the client secret is issued by ConductorOne and set
# out of band (SecureString), same as a portal client secret.
# ------------------------------------------------------------------------------

resource "aws_ssm_parameter" "c1_directory_tenant_url" {
  count = local.c1_directory_configured ? 1 : 0

  name        = "${var.parameter_prefix}/c1directory/tenant-url"
  description = "ConductorOne directory tenant URL"
  type        = "String"
  value       = var.c1_directory_tenant_url

  tags = local.tags
}

resource "aws_ssm_parameter" "c1_directory_client_id" {
  count = local.c1_directory_configured ? 1 : 0

  name        = "${var.parameter_prefix}/c1directory/client-id"
  description = "ConductorOne directory OAuth client id"
  type        = "String"
  value       = var.c1_directory_client_id

  tags = local.tags
}

resource "aws_ssm_parameter" "c1_directory_client_secret" {
  count = local.c1_directory_configured ? 1 : 0

  name        = "${var.parameter_prefix}/c1directory/client-secret"
  description = "ConductorOne directory OAuth client secret, set out of band"
  type        = "SecureString"
  value       = "replace-me"
  key_id      = var.kms_key_id

  lifecycle {
    ignore_changes = [value, insecure_value]
  }

  tags = local.tags
}
