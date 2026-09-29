# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

output "aws_region" {
  description = "Region this deployment lives in."
  value       = var.aws_region
}

output "portal_url" {
  description = "Sign in here. It is the configured publicOrigin."
  value       = module.control_plane.portal_url
}

output "apps_domain" {
  description = "Suffix published application hostnames live under."
  value       = local.apps_domain
}

output "internal_apps_domain" {
  description = "Suffix private application hostnames live under. Null when internal_ingress_enabled is false."
  value       = module.ingress.internal_apps_domain
}

output "internal_load_balancer_dns_name" {
  description = "DNS name of the internal applications load balancer. Null when internal_ingress_enabled is false."
  value       = module.ingress.internal_load_balancer_dns_name
}

output "register_with_identity_provider" {
  description = <<-EOT
    Every redirect URI that must be registered before anyone can sign in: one
    per portal provider, plus oauth2-proxy's for the applications ingress.
  EOT
  value = merge(
    module.control_plane.oidc_callback_urls,
    { "ingress (oauth2-proxy)" = module.ingress.redirect_url },
  )
}

output "github_webhook" {
  description = <<-EOT
    Register this URL as the GitHub App webhook, and paste the Parameter
    Store value into the webhook secret. The value is not in this output:

      aws ssm get-parameter --with-decryption --name "<parameter>" \
        --query Parameter.Value --output text
  EOT
  value = {
    url       = module.config.github_webhook_url
    parameter = module.config.github_webhook_secret_parameter_name
  }
}

output "secrets_to_set" {
  description = <<-EOT
    Parameters Terraform created and will never write again. Each holds a
    placeholder until an operator sets it:

      aws ssm put-parameter --overwrite --type SecureString \
        --name <name> --value "<value>"

    A placeholder is a sign-in that fails at the token exchange, not one that
    succeeds without a secret.
  EOT
  value = merge(
    { for id, name in module.config.client_secret_parameters : "portal/${id}" => name },
    { for key, name in module.config.github_app_key_parameters : "source/${key}" => name },
    module.config.c1_directory_client_secret_parameter_name != null ? {
      "c1directory/client-secret" = module.config.c1_directory_client_secret_parameter_name
    } : {},
    {
      "ingress/client-id"     = module.ingress.client_id_parameter_name
      "ingress/client-secret" = module.ingress.client_secret_parameter_name
    },
  )
}

output "image_repositories" {
  description = "ECR repositories `make tf-up` / `make push` publish the API, worker, and builder images to."
  value = {
    server  = module.cluster.server_repository_url
    worker  = module.cluster.worker_repository_url
    builder = module.cluster.builder_repository_url
  }
}

output "api_service_name" {
  description = "ECS service to force a new deployment of after pushing a server image."
  value       = module.control_plane.service_name
}

output "cluster_name" {
  value = module.cluster.cluster_name
}

output "worker_service_name" {
  description = "ECS service to force a new deployment of after pushing a worker image."
  value       = module.worker.service_name
}

output "build_task_definition_families" {
  description = "Build task definition families; `make promote-builder` registers a new digest-pinned revision of each."
  value       = module.build.task_definition_families
}

output "build_container_name" {
  description = "Builder container name whose image `make promote-builder` replaces."
  value       = module.build.container_name
}

output "build_slots" {
  description = <<-EOT
    Concurrent builds this deployment can run. Each has its own task definition
    and its own EFS access point, and a build can neither name nor reach
    another's slot.
  EOT
  value       = module.build.slots
}

output "log_groups" {
  description = "Log groups the admin Workspace can read, and that `aws logs tail` can follow."
  value       = local.log_groups
}

output "table_name" {
  description = "Control-plane table. The GitHub App key parameter path is derived from it."
  value       = module.state.table_name
}

output "audit_table_name" {
  description = "Separate audit event table; events are eligible for asynchronous TTL removal after 400 days."
  value       = module.state.audit_table_name
}

output "config_parameters" {
  description = "The rendered configuration documents, for reading back what a process will actually load."
  value = {
    apphub = module.config.apphub_config_parameter_name
    aws    = module.config.aws_config_parameter_name
  }
}

output "push_role_arn" {
  description = "Role a build's image push assumes. Nothing but the worker may assume it."
  value       = module.deploy_target.push_role_arn
}

output "workload_boundary_arn" {
  description = "Permissions ceiling on every IAM role AppHub creates."
  value       = module.deploy_target.workload_boundary_arn
}

output "handoff_kms_key_arn" {
  description = "Application-secret handoff key. The API may only encrypt with it; only the worker may decrypt."
  value       = module.state.handoff_kms_key_arn
}
