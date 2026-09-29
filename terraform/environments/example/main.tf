# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# One AppHub deployment.
#
# Copy this directory per environment. The modules take no defaults from the
# environment they run in and compose in one direction only:
#
#   network -> cluster ---------------------------> ingress
#           \                                    \
#            -> state -> deploy-target -----------> config -> control-plane
#                                                          \-> worker
#
# The direction is what keeps the configuration renderable. modules/config
# writes a document naming the cluster, the ingress security group, the
# permissions boundary and the push role, and the two processes that read that
# document come last -- so nothing it names can depend on it.

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "apphub"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_route53_zone" "main" {
  name         = var.hosted_zone_name
  private_zone = false
}

locals {
  name_prefix = var.name_prefix

  # Disjoint from Terraform-owned api/worker/traefik/oauth2-proxy services and
  # the control-plane table; the IAM grants use these exact provider prefixes.
  application_name_prefix = "${var.name_prefix}-${var.environment}-apps-"
  endpoint_name_prefix    = "${var.name_prefix}-${var.environment}-"

  # One hierarchy this deployment owns. The task execution role may read under
  # it and the workload permissions boundary denies every deployed application
  # access to it.
  parameter_prefix = "/${var.name_prefix}/${var.environment}"

  # Application secrets are a sibling of, never a child of, the hierarchy
  # above: the boundary's denial is written against that path, and a nested
  # application tree would inherit it.
  secret_path_prefix = "/${var.name_prefix}-apps/${var.environment}"

  log_group_prefix     = "/${var.name_prefix}/${var.environment}"
  app_log_group_prefix = "/${var.name_prefix}/${var.environment}/apps/"

  table_name       = "${var.name_prefix}-${var.environment}"
  worker_role_name = "${var.name_prefix}-${var.environment}-worker"

  portal_domain = "${var.portal_subdomain}.${trimsuffix(var.hosted_zone_name, ".")}"
  apps_domain   = "${var.apps_subdomain}.${trimsuffix(var.hosted_zone_name, ".")}"

  # Log group names are derived rather than read back from the modules that
  # create them: modules/config has to name them for the Workspace log viewer,
  # and two of the three modules that own them read modules/config's output.
  log_groups = {
    api          = "${local.log_group_prefix}/api"
    worker       = "${local.log_group_prefix}/worker"
    build        = "${local.log_group_prefix}/build"
    traefik      = "${local.log_group_prefix}/traefik"
    oauth2_proxy = "${local.log_group_prefix}/oauth2-proxy"
  }

  log_group_arns = [
    for name in values(local.log_groups) :
    "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${name}:*"
  ]

  # Empty vars resolve to the cluster's ECR :latest. Image rollouts are
  # `make promote`, not a terraform apply of a new tag.
  server_image = var.server_image != "" ? var.server_image : "${module.cluster.server_repository_url}:latest"
  worker_image = var.worker_image != "" ? var.worker_image : "${module.cluster.worker_repository_url}:latest"
}

# ------------------------------------------------------------------------------

module "network" {
  source = "../../modules/network"

  name_prefix             = local.name_prefix
  environment             = var.environment
  vpc_cidr                = var.vpc_cidr
  availability_zone_count = var.availability_zone_count
  nat_gateway_count       = var.nat_gateway_count
  portal_allowed_cidrs    = var.portal_allowed_cidrs
  apps_allowed_cidrs      = var.apps_allowed_cidrs
  ingress_tls_mode        = var.ingress_tls_mode

  internal_ingress_enabled = var.internal_ingress_enabled
}

module "cluster" {
  source = "../../modules/cluster"

  name_prefix      = local.name_prefix
  environment      = var.environment
  vpc_id           = module.network.vpc_id
  parameter_prefix = local.parameter_prefix
}

module "state" {
  source = "../../modules/state"

  table_name             = local.table_name
  environment            = var.environment
  point_in_time_recovery = var.point_in_time_recovery
  deletion_protection    = var.deletion_protection

  secret_handoff_key_deletion_window_days = var.secret_handoff_key_deletion_window_days
}

module "ingress" {
  source = "../../modules/ingress"

  name_prefix = local.name_prefix
  environment = var.environment

  apps_domain             = local.apps_domain
  hosted_zone_id          = data.aws_route53_zone.main.zone_id
  create_apps_apex_record = var.create_apps_apex_record

  vpc_id                         = module.network.vpc_id
  vpc_cidr                       = module.network.vpc_cidr
  public_subnet_ids              = module.network.public_subnet_ids
  private_subnet_ids             = module.network.private_subnet_ids
  apps_lb_security_group_id      = module.network.apps_nlb_security_group_id
  traefik_security_group_id      = module.network.traefik_security_group_id
  oauth2_proxy_security_group_id = module.network.oauth2_proxy_security_group_id
  efs_security_group_id          = module.network.efs_security_group_id
  internal_alb_security_group_id = module.network.internal_alb_security_group_id

  cluster_id         = module.cluster.cluster_id
  cluster_name       = module.cluster.cluster_name
  namespace_id       = module.cluster.namespace_id
  namespace_name     = module.cluster.namespace_name
  execution_role_arn = module.cluster.execution_role_arn

  parameter_prefix   = local.parameter_prefix
  log_group_prefix   = local.log_group_prefix
  log_retention_days = var.log_retention_days

  certificate_resolver     = var.certificate_resolver
  ingress_tls_mode         = var.ingress_tls_mode
  acme_email               = var.acme_email
  acme_ca_server           = var.acme_ca_server
  ingress_auth_middleware  = var.ingress_auth_middleware
  traefik_image            = var.traefik_image
  internal_ingress_enabled = var.internal_ingress_enabled

  oauth2_proxy_provider        = var.oauth2_proxy_provider
  oauth2_proxy_oidc_issuer_url = var.oauth2_proxy_oidc_issuer_url
  oauth2_proxy_email_domains   = var.oauth2_proxy_email_domains
}

module "deploy_target" {
  source = "../../modules/deploy-target"

  name_prefix      = local.name_prefix
  environment      = var.environment
  cluster_name     = module.cluster.cluster_name
  vpc_id           = module.network.vpc_id
  worker_role_name = local.worker_role_name

  control_plane_table_arn        = module.state.table_arn
  audit_table_arn                = module.state.audit_table_arn
  control_plane_parameter_prefix = local.parameter_prefix
  control_plane_name_prefix      = "${var.name_prefix}-"

  identity_path_prefix       = "/${var.name_prefix}/"
  identity_name_prefix       = "${var.name_prefix}-"
  execution_role_path_prefix = "/${var.name_prefix}-execution/"
  registry_name_prefix       = "${var.name_prefix}/apps/"
  container_name_prefix      = local.application_name_prefix
  secret_path_prefix         = local.secret_path_prefix
  function_name_prefix       = local.application_name_prefix
  app_log_group_prefix       = local.app_log_group_prefix

  # An S3 bucket name is globally unique across every AWS account, so the
  # prefix carries the account's own distinctness or the first create fails as
  # an authorization error against somebody else's bucket.
  object_store_name_prefix = "${var.name_prefix}-${var.environment}-${data.aws_caller_identity.current.account_id}-"
  key_value_name_prefix    = local.application_name_prefix
  relational_name_prefix   = "${var.name_prefix}-"
  endpoint_name_prefix     = local.endpoint_name_prefix

  enable_key_value_port    = var.enable_key_value_port
  enable_object_store_port = var.enable_object_store_port
  enable_relational_port   = var.enable_relational_port
  enable_function_port     = var.enable_function_port
}

module "build" {
  source = "../../modules/build"

  name_prefix = local.name_prefix
  environment = var.environment

  private_subnet_ids       = module.network.private_subnet_ids
  vpc_id                   = module.network.vpc_id
  worker_security_group_id = module.network.worker_security_group_id

  slots                  = var.build_slots
  builder_image          = var.builder_image
  builder_repository_arn = module.cluster.builder_repository_arn
  cpu                    = var.build_cpu
  memory                 = var.build_memory
  cpu_architecture       = var.cpu_architecture
  ephemeral_storage_gib  = var.build_ephemeral_storage_gib

  log_group_prefix   = local.log_group_prefix
  log_retention_days = var.log_retention_days
}

module "config" {
  source = "../../modules/config"

  environment      = var.environment
  aws_region       = var.aws_region
  parameter_prefix = local.parameter_prefix

  public_origin    = "https://${local.portal_domain}"
  table_name       = module.state.table_name
  audit_table_name = module.state.audit_table_name

  auth_providers = var.auth_providers
  auth_admins    = var.auth_admins
  auth_clients   = var.auth_clients

  c1_directory_tenant_url = var.c1_directory_tenant_url
  c1_directory_client_id  = var.c1_directory_client_id

  source_repositories  = var.source_repositories
  allowed_source_hosts = var.allowed_source_hosts

  resource_prefix   = "${var.name_prefix}-${var.environment}"
  apps_domain       = local.apps_domain
  route_certificate = var.certificate_resolver

  resource_sizes                = var.resource_sizes
  max_replicas                  = var.max_replicas
  relational_max_capacity_units = var.relational_max_capacity_units
  execution_modes               = var.execution_modes
  public_exposure               = var.public_exposure

  vpc_id                           = module.network.vpc_id
  private_subnet_ids               = module.network.private_subnet_ids
  cluster_arn                      = module.cluster.cluster_arn
  apps_security_group_id           = module.network.apps_security_group_id
  traefik_security_group_id        = module.network.traefik_security_group_id
  control_plane_security_group_ids = module.network.control_plane_security_group_ids
  certificate_resolver             = module.ingress.certificate_resolver
  ingress_auth_middleware          = module.ingress.ingress_auth_middleware
  ingress_cookie_strip_middleware  = module.ingress.ingress_cookie_strip_middleware
  mcp_auth_backend_url             = "http://apphub-api.${module.cluster.namespace_name}:8080"
  tls_termination                  = module.ingress.tls_termination

  internal_ingress_enabled = var.internal_ingress_enabled
  internal_certificate_arn = module.ingress.internal_certificate_arn

  identity_path_prefix       = module.deploy_target.identity_path_prefix
  identity_name_prefix       = module.deploy_target.identity_name_prefix
  execution_role_path_prefix = module.deploy_target.execution_role_path_prefix
  workload_boundary_arn      = module.deploy_target.workload_boundary_arn
  registry_name_prefix       = module.deploy_target.registry_name_prefix
  container_name_prefix      = module.deploy_target.container_name_prefix
  secret_path_prefix         = module.deploy_target.secret_path_prefix
  app_log_group_prefix       = module.deploy_target.app_log_group_prefix
  push_role_arn              = module.deploy_target.push_role_arn
  handoff_kms_key_arn        = module.state.handoff_kms_key_arn
  traffic_log_group          = local.log_groups.traefik

  enable_key_value_port    = var.enable_key_value_port
  enable_object_store_port = var.enable_object_store_port
  enable_relational_port   = var.enable_relational_port
  rds_ca_pem_file          = var.rds_ca_pem_file
  key_value_name_prefix    = module.deploy_target.key_value_name_prefix
  object_store_name_prefix = module.deploy_target.object_store_name_prefix
  relational_name_prefix   = module.deploy_target.relational_name_prefix
  endpoint_name_prefix     = module.deploy_target.endpoint_name_prefix
  enable_function_port     = var.enable_function_port
  function_name_prefix     = module.deploy_target.function_name_prefix
  function_runtimes        = var.function_runtimes

  build_cluster_arn             = module.cluster.cluster_arn
  build_task_definitions        = module.build.task_definition_families
  build_container_name          = module.build.container_name
  build_security_group_id       = module.network.build_security_group_id
  build_slot_security_group_ids = module.build.slot_security_group_ids
  build_slot_path               = module.build.slot_path
  build_log_group               = module.build.log_group

  worker_max_concurrent_deployments = var.worker_max_concurrent_deployments
  worker_deployment_timeout         = var.worker_deployment_timeout

  observability_log_groups = [
    { name = "AppHub API", log_group = local.log_groups.api },
    { name = "AppHub worker", log_group = local.log_groups.worker },
    { name = "Builds", log_group = local.log_groups.build },
    { name = "Ingress (Traefik)", log_group = local.log_groups.traefik },
    { name = "Ingress auth (oauth2-proxy)", log_group = local.log_groups.oauth2_proxy },
  ]
}

module "control_plane" {
  source = "../../modules/control-plane"

  name_prefix    = local.name_prefix
  environment    = var.environment
  portal_domain  = local.portal_domain
  hosted_zone_id = data.aws_route53_zone.main.zone_id

  vpc_id                    = module.network.vpc_id
  public_subnet_ids         = module.network.public_subnet_ids
  private_subnet_ids        = module.network.private_subnet_ids
  alb_security_group_id     = module.network.portal_alb_security_group_id
  service_security_group_id = module.network.apphub_api_security_group_id
  cluster_id                = module.cluster.cluster_id
  execution_role_arn        = module.cluster.execution_role_arn
  namespace_id              = module.cluster.namespace_id

  table_name       = module.state.table_name
  table_arn        = module.state.table_arn
  table_index_arns = module.state.table_index_arns

  audit_table_arn = module.state.audit_table_arn

  parameter_prefix        = local.parameter_prefix
  apphub_config_parameter = module.config.apphub_config_parameter_name
  aws_config_parameter    = module.config.aws_config_parameter_name
  auth_provider_ids       = [for p in var.auth_providers : p.id]
  injected_secrets        = module.config.api_injected_secrets
  config_dir              = module.config.api_config_dir
  handoff_kms_key_arn     = module.state.handoff_kms_key_arn

  server_image     = local.server_image
  cpu              = var.api_cpu
  memory           = var.api_memory
  cpu_architecture = var.cpu_architecture
  desired_count    = var.api_desired_count

  log_group_prefix             = local.log_group_prefix
  log_retention_days           = var.log_retention_days
  observability_log_group_arns = local.log_group_arns

  environment_variables = var.api_environment_variables
}

module "worker" {
  source = "../../modules/worker"

  name_prefix = local.name_prefix
  environment = var.environment
  role_name   = local.worker_role_name

  cluster_id         = module.cluster.cluster_id
  execution_role_arn = module.cluster.execution_role_arn
  private_subnet_ids = module.network.private_subnet_ids
  security_group_id  = module.network.worker_security_group_id

  worker_image     = local.worker_image
  cpu              = var.worker_cpu
  memory           = var.worker_memory
  cpu_architecture = var.cpu_architecture
  desired_count    = var.worker_desired_count

  work_dir   = module.config.worker_work_dir
  config_dir = module.config.api_config_dir
  share_path = module.config.build_share_path

  parameter_prefix        = local.parameter_prefix
  apphub_config_parameter = module.config.apphub_config_parameter_name
  aws_config_parameter    = module.config.aws_config_parameter_name
  rds_ca_parameter        = module.config.rds_ca_parameter_name
  injected_secrets        = module.config.worker_injected_secrets
  handoff_kms_key_arn     = module.state.handoff_kms_key_arn
  traffic_log_group_arn   = module.ingress.traefik_log_group_arn

  table_name       = module.state.table_name
  table_arn        = module.state.table_arn
  table_index_arns = module.state.table_index_arns

  audit_table_arn    = module.state.audit_table_arn
  deploy_policy_arns = module.deploy_target.deploy_policy_arns

  build_cluster_arn              = module.cluster.cluster_arn
  build_cluster_name             = module.cluster.cluster_name
  build_task_definition_families = module.build.task_definition_families
  build_execution_role_arn       = module.build.execution_role_arn
  build_file_system_ids          = module.build.worker_file_system_ids
  build_access_point_ids         = module.build.worker_access_point_ids
  build_log_group_arn            = module.build.log_group_arn

  log_group_prefix   = local.log_group_prefix
  log_retention_days = var.log_retention_days

  environment_variables = var.worker_environment_variables
}
