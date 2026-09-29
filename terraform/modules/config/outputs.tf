# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

output "apphub_config_parameter_name" {
  description = "SSM parameter holding the shared operator configuration."
  value       = aws_ssm_parameter.apphub_config.name
}

output "apphub_config_parameter_arn" {
  value = aws_ssm_parameter.apphub_config.arn
}

output "aws_config_parameter_name" {
  description = "SSM parameter holding the compute provider configuration."
  value       = aws_ssm_parameter.aws_config.name
}

output "aws_config_parameter_arn" {
  value = aws_ssm_parameter.aws_config.arn
}

output "rds_ca_parameter_name" {
  description = "SSM parameter containing the regional RDS CA PEM, or null when relational is disabled."
  value       = var.enable_relational_port ? aws_ssm_parameter.rds_ca[0].name : null
}

output "transaction_key_parameter_name" {
  description = "SSM parameter holding the base64 session transaction key."
  value       = aws_ssm_parameter.transaction_key.name
}

output "transaction_key_parameter_arn" {
  value = aws_ssm_parameter.transaction_key.arn
}

output "client_secret_parameters" {
  description = "Provider id to the SSM parameter holding its client secret. Set each one out of band."
  value       = { for id, p in aws_ssm_parameter.client_secret : id => p.name }
}

output "client_secret_parameter_arns" {
  value = { for id, p in aws_ssm_parameter.client_secret : id => p.arn }
}

output "github_app_key_parameters" {
  description = "PEM basename to the SSM parameter holding it. Set each one out of band."
  value       = { for k, p in aws_ssm_parameter.github_app_key : k => p.name }
}

output "github_app_key_parameter_arns" {
  value = { for k, p in aws_ssm_parameter.github_app_key : k => p.arn }
}

output "c1_directory_client_secret_parameter_name" {
  description = "SSM parameter holding the ConductorOne directory client secret, if configured."
  value       = local.c1_directory_configured ? aws_ssm_parameter.c1_directory_client_secret[0].name : null
}

output "api_config_dir" {
  description = "Directory the API's init container writes configuration documents into."
  value       = var.api_config_dir
}

output "api_config_file" {
  description = "Path `apphub serve --config` is given."
  value       = "${var.api_config_dir}/apphub.yaml"
}

output "worker_work_dir" {
  description = "The worker's private checkout directory; it must match what the worker task mounts."
  value       = var.worker_work_dir
}

output "build_share_path" {
  description = "Where the worker sees the build share; it must match what the worker task mounts."
  value       = var.build_share_path
}

locals {
  c1_directory_secrets = local.c1_directory_configured ? [
    { name = local.c1_directory_env.tenant_url, valueFrom = aws_ssm_parameter.c1_directory_tenant_url[0].arn },
    { name = local.c1_directory_env.client_id, valueFrom = aws_ssm_parameter.c1_directory_client_id[0].arn },
    { name = local.c1_directory_env.client_secret, valueFrom = aws_ssm_parameter.c1_directory_client_secret[0].arn },
  ] : []

  auth_id_secrets = [
    for id, p in aws_ssm_parameter.client_id : {
      name      = local.auth_provider_env[id].client_id
      valueFrom = p.arn
    }
  ]

  github_id_secrets = concat(
    [
      for key, p in aws_ssm_parameter.github_app_id : {
        name      = local.github_source_env[key].app_id
        valueFrom = p.arn
      }
    ],
    [
      for key, p in aws_ssm_parameter.github_installation_id : {
        name      = local.github_source_env[key].installation_id
        valueFrom = p.arn
      }
    ],
  )
}

output "github_webhook_secret_parameter_name" {
  description = "SSM parameter holding the GitHub webhook HMAC secret. Read it and paste the value into the GitHub App; this output is the name, not the secret."
  value       = aws_ssm_parameter.github_webhook_secret.name
}

output "github_webhook_url" {
  description = "URL to register as the GitHub App webhook."
  value       = "${var.public_origin}/api/v1/github/webhook"
}

output "api_injected_secrets" {
  description = <<-EOT
    ECS secrets block for the API (portal) container. IDs and secrets from
    Parameter Store, including the transaction key, the GitHub webhook HMAC
    secret, and every provider's client id and client secret. GitHub App
    private keys are not here: the API never holds source credentials.
  EOT
  value = concat(
    [
      {
        name      = local.transaction_key_env
        valueFrom = aws_ssm_parameter.transaction_key.arn
      },
      {
        name      = local.github_webhook_secret_env
        valueFrom = aws_ssm_parameter.github_webhook_secret.arn
      },
    ],
    local.auth_id_secrets,
    [
      for id, p in aws_ssm_parameter.client_secret : {
        name      = local.auth_provider_env[id].client_secret
        valueFrom = p.arn
      }
    ],
    local.github_id_secrets,
    local.c1_directory_secrets,
  )
}

output "worker_injected_secrets" {
  description = <<-EOT
    ECS secrets block for the worker container. Client ids (needed to
    validate the shared document), GitHub App ids and private keys, and the
    optional ConductorOne directory credential. Upstream login secrets are
    not here: the worker never holds them.
  EOT
  value = concat(
    local.auth_id_secrets,
    local.github_id_secrets,
    [
      for key, p in aws_ssm_parameter.github_app_key : {
        name      = local.github_source_env[key].private_key
        valueFrom = p.arn
      }
    ],
    local.c1_directory_secrets,
  )
}
