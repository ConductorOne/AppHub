# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The two operator configuration documents, rendered once and published to
# Parameter Store for both processes to read.
#
# # Why one document for serve and worker
#
# Because AppHub refuses a mismatch. The API and the worker must agree on every
# nonsecret target descriptor or submission is blocked
# (internal/serverconfig, and the README's operator configuration table), and
# two hand-maintained documents drift. internal/serverconfig/load.go validates
# the serve-only fields only in serve mode and the worker-only fields only in
# worker mode, so one document satisfies both: `apphub serve` ignores the
# `worker` section and `apphub worker` ignores `staticDir`, `listenAddress` and
# the transaction key.
#
# # Why yamlencode and not a template
#
# A template with a loop over providers is a template that can emit a document
# that does not parse, and the failure surfaces as a container that will not
# start. yamlencode cannot: the structure is built as Terraform values and
# serialised by something that knows the grammar. The cost is that the output
# is alphabetically ordered and carries no comments, which is the right trade
# for a generated artifact nobody hand-edits.
#
# # What is NOT here
#
# Secrets. The transaction key is generated below because it is ours to
# generate; every client secret is a parameter Terraform creates and then stops
# looking at. See the lifecycle blocks.

locals {
  tags = { Environment = var.environment }

  # Both tasks mount their own configuration volume at this path. Relative
  # paths in AppHub's configuration resolve against the configuration file's
  # directory; absolute paths keep the shared document unambiguous.
  api_config_dir = var.api_config_dir

  transaction_key_env       = "APPHUB_AUTH_TRANSACTION_KEY"
  github_webhook_secret_env = "APPHUB_GITHUB_WEBHOOK_SECRET"

  # ECS-injected names. YAML names these rather than holding values, and the
  # task definition's secrets block is how Parameter Store becomes a process
  # environment. Provider ids are [a-z][a-z0-9-]*; hyphens become underscores.
  auth_provider_env = {
    for p in var.auth_providers : p.id => {
      client_id     = "APPHUB_AUTH_${upper(replace(p.id, "-", "_"))}_CLIENT_ID"
      client_secret = "APPHUB_AUTH_${upper(replace(p.id, "-", "_"))}_CLIENT_SECRET"
    }
  }

  github_source_env = {
    for r in var.source_repositories : r.github_key_basename => {
      app_id          = "APPHUB_SOURCE_${upper(replace(replace(trimsuffix(r.github_key_basename, ".pem"), ".", "_"), "-", "_"))}_APP_ID"
      installation_id = "APPHUB_SOURCE_${upper(replace(replace(trimsuffix(r.github_key_basename, ".pem"), ".", "_"), "-", "_"))}_INSTALLATION_ID"
      private_key     = "APPHUB_SOURCE_${upper(replace(replace(trimsuffix(r.github_key_basename, ".pem"), ".", "_"), "-", "_"))}_PRIVATE_KEY"
    } if r.auth == "githubApp"
  }

  c1_directory_configured = var.c1_directory_tenant_url != ""

  c1_directory_env = {
    tenant_url    = "APPHUB_C1_DIRECTORY_TENANT_URL"
    client_id     = "APPHUB_C1_DIRECTORY_CLIENT_ID"
    client_secret = "APPHUB_C1_DIRECTORY_CLIENT_SECRET"
  }

  # Ref key for the internal ingress's certificate, the same shape as
  # var.route_certificate for the public one. Not a variable: unlike the
  # public certificate reference, an application never selects or sees this
  # name -- deployConfig.internalRouteCertificate and this placement's
  # certificates map are the only two places it has to match, and both are
  # rendered right here.
  internal_route_certificate = "internal"

  # --------------------------------------------------------------------------
  # The compute provider's configuration.
  #
  # Every identifier in it is supplied rather than discovered. compute/aws's
  # Config exists to enforce exactly that -- "no identifier belonging to any
  # deployment of apphub is compiled in" -- so this is the file that makes a
  # generic binary into this deployment.
  # --------------------------------------------------------------------------
  placement = {
    vpc        = var.vpc_id
    clusterArn = var.cluster_arn

    # Both spellings, because the two ports read different fields: the
    # container runtime places tasks with `subnets`, the function endpoint
    # places a load balancer with `subnetIds`.
    subnets   = var.private_subnet_ids
    subnetIds = var.private_subnet_ids

    # The operator's baseline posture. The per-application group AppHub
    # creates from compute.ServiceSpec.Ingress is attached in addition to
    # this one, and is where every reachability claim lives.
    securityGroups = [var.apps_security_group_id]

    # compute.PeerPlatformIngress. Empty would be fail-closed -- a route
    # naming the peer would be refused -- rather than fail-open, which is the
    # behaviour compute/aws/config.go singles out as the most important
    # difference from the system it replaced.
    platformIngressSecurityGroupId = var.traefik_security_group_id
    platformIngressSecurityGroups  = [var.traefik_security_group_id]

    # compute.PeerControlPlane: AppHub's own API and worker, and nothing
    # wider.
    controlPlaneSecurityGroups = var.control_plane_security_group_ids

    # What deployConfig.routeCertificate resolves to. In strict mode the
    # value is written into traefik.http.routers.<router>.tls.certresolver,
    # so it is the name of Traefik's ACME resolver. In alb-wildcard
    # (tlsTermination=edge) the map still has to resolve the reference the
    # control plane puts on every public route; compute/aws does not write
    # a certresolver label.
    certificates = merge(
      { (var.route_certificate) = var.certificate_resolver },
      # The internal route's certificate reference has to resolve for the
      # same reason the public one does (compute/aws/routes.go refuses an
      # unresolvable ref outright) even though Traefik's internal entrypoint
      # never terminates TLS with it -- the ALB in front of it does. See
      # modules/ingress/internal_alb.tf.
      var.internal_ingress_enabled ? { (local.internal_route_certificate) = var.internal_certificate_arn } : {},
    )

    assignPublicIp = false
  }

  aws_config_base = {
    name             = var.provider_name
    region           = var.aws_region
    defaultPlacement = var.placement_name
    placements       = { (var.placement_name) = local.placement }

    identity = {
      pathPrefix          = var.identity_path_prefix
      namePrefix          = var.identity_name_prefix
      permissionsBoundary = var.workload_boundary_arn
    }

    registry = {
      namePrefix = var.registry_name_prefix
      # Must stay false: the deployment module moves a `latest` tag, and the
      # provider refuses an immutable registry outright rather than failing on
      # the first push.
      immutableTags = false
    }

    build = {
      executorPath    = var.build_executor_path
      pusherPath      = var.build_pusher_path
      pushRoleArn     = var.push_role_arn
      sessionDuration = var.build_session_duration

      # Where a build runs. There is no other shape: the provider refuses a
      # configuration with no task, because the alternative is running the
      # builder as a process of the worker -- which is what USOSS-41 closed.
      task = {
        cluster         = var.build_cluster_arn
        taskDefinitions = var.build_task_definitions
        containerName   = var.build_container_name
        subnets         = var.private_subnet_ids
        # The build's whole network boundary, and the reason nothing in the VPC
        # is reachable from a build.
        securityGroups     = [var.build_security_group_id]
        slotSecurityGroups = var.build_slot_security_group_ids
        sharePath          = var.build_share_path
        slotPath           = var.build_slot_path
        logGroup           = var.build_log_group
        logStreamPrefix    = var.build_log_stream_prefix
      }
    }

    secrets = {
      pathPrefix = var.secret_path_prefix
    }

    container = merge(
      {
        namePrefix                       = var.container_name_prefix
        executionRolePathPrefix          = var.execution_role_path_prefix
        executionRolePermissionsBoundary = var.workload_boundary_arn
        logGroupPrefix                   = var.app_log_group_prefix
        ingressAuthMiddleware            = var.ingress_auth_middleware
        ingressCookieStripMiddleware     = var.ingress_cookie_strip_middleware
        mcpAuthBackendUrl                = var.mcp_auth_backend_url
        tlsTermination                   = var.tls_termination
      },
      # Empty (the zero value ContainerConfig.InternalEntrypoint already has)
      # rather than an absent key: compute/aws/config.go always expects this
      # field, and empty is what makes it refuse a route asking to be
      # internal (compute/aws/routes.go) instead of silently publishing it.
      var.internal_ingress_enabled ? { internalEntrypoint = "internal" } : {},
    )
  }

  aws_config = merge(
    local.aws_config_base,
    var.enable_key_value_port ? {
      keyValue = { namePrefix = var.key_value_name_prefix }
    } : {},
    var.enable_object_store_port ? {
      objectStore = { namePrefix = var.object_store_name_prefix }
    } : {},
    var.enable_relational_port ? {
      relational = {
        namePrefix       = var.relational_name_prefix
        engineVersions   = var.relational_engine_versions
        maxCapacityUnits = var.relational_max_capacity_units
      }
    } : {},
    var.enable_function_port ? {
      function = {
        namePrefix = var.function_name_prefix
        runtimes   = var.function_runtimes
      }
    } : {},
    var.enable_function_port ? {
      endpoint = {
        namePrefix = var.endpoint_name_prefix
      }
    } : {},
  )

  # --------------------------------------------------------------------------
  # AppHub's own configuration.
  # --------------------------------------------------------------------------
  providers_yaml = [
    for p in var.auth_providers : merge(
      {
        id              = p.id
        label           = p.label
        kind            = p.kind
        clientIdEnv     = local.auth_provider_env[p.id].client_id
        clientSecretEnv = local.auth_provider_env[p.id].client_secret
      },
      p.kind == "oidc" ? { issuer = p.issuer } : {},
      length(p.allowed_emails) > 0 ? { allowedEmails = p.allowed_emails } : {},
      length(p.allowed_domains) > 0 ? { allowedDomains = p.allowed_domains } : {},
    )
  ]

  repositories_yaml = [
    for r in var.source_repositories : merge(
      {
        url  = r.url
        auth = r.auth
      },
      r.auth == "githubApp" ? {
        githubApp = {
          appIdEnv          = local.github_source_env[r.github_key_basename].app_id
          installationIdEnv = local.github_source_env[r.github_key_basename].installation_id
          # Worker-only. The API never reads it, and validation only requires
          # it in worker mode. ECS injects the PEM into this environment
          # variable from Parameter Store; the API task is never given it.
          privateKeyEnv = local.github_source_env[r.github_key_basename].private_key
        }
      } : {},
    )
  ]

  apphub_config = merge(
    {
      publicOrigin  = var.public_origin
      listenAddress = var.listen_address
      staticDir     = var.static_dir

      store = {
        region         = var.aws_region
        tableName      = var.table_name
        auditTableName = var.audit_table_name
      }

      auth = {
        transactionKeyEnv = local.transaction_key_env
        providers         = local.providers_yaml
        admins = [
          for a in var.auth_admins : { providerId = a.provider_id, subject = a.subject }
        ]
        clients = [
          for c in var.auth_clients : { id = c.id, redirectUris = c.redirect_uris }
        ]
      }

      targets = {
        (var.target_id) = {
          label         = var.target_label
          awsConfigFile = "${local.api_config_dir}/aws.yaml"

          deployConfig = merge(
            {
              resourcePrefix       = var.resource_prefix
              routeDomain          = var.apps_domain
              routeCertificate     = var.route_certificate
              allowedSourceHosts   = var.allowed_source_hosts
              secretStoreName      = var.secret_store_name
              placement            = { name = var.placement_name }
              waitTimeout          = var.deploy_wait_timeout
              workloadIdentityMode = "native"
              postgresRootCertPath = var.enable_relational_port ? "${local.api_config_dir}/rds-ca.pem" : ""
            },
            # Both unset is "no internal ingress" to internal/serverconfig's
            # loader (load.go requires either both or neither); rendering
            # them as empty strings rather than omitting the keys keeps this
            # merge the same shape as the container block above.
            var.internal_ingress_enabled ? {
              internalRouteDomain      = "internal.${var.apps_domain}"
              internalRouteCertificate = local.internal_route_certificate
              } : {
              internalRouteDomain      = ""
              internalRouteCertificate = ""
            },
          )

          policy = {
            resourceSizes              = [for s in var.resource_sizes : { cpu = s.cpu, memory = s.memory }]
            maxReplicas                = var.max_replicas
            maxRelationalCapacityUnits = var.relational_max_capacity_units
            executionModes             = var.execution_modes
            publicExposure             = var.public_exposure
          }
        }
      }

      source = { repositories = local.repositories_yaml }

      # The webhook HMAC secret. The YAML names the variable; the value is
      # the SecureString in parameters.tf, injected into the API task only.
      github = {
        webhookSecretEnv = local.github_webhook_secret_env
      }

      # The worker's own execution limits, and nothing about build isolation:
      # a build runs in a task the provider launches, so the cluster, the task
      # definitions, the subnets and the security groups are all in build.task
      # above.
      worker = {
        workDir                  = var.worker_work_dir
        maxConcurrentDeployments = var.worker_max_concurrent_deployments
        deploymentTimeout        = var.worker_deployment_timeout
        heartbeatInterval        = var.worker_heartbeat_interval
        staleAfter               = var.worker_stale_after
      }
    },
    length(var.observability_log_groups) == 0 ? {} : {
      observability = {
        awsRegion = var.aws_region
        logGroups = [for g in var.observability_log_groups : { name = g.name, logGroup = g.log_group }]
      }
    },
    # Per-application secrets. Absent, not present-and-empty, when unset:
    # internal/serverconfig reads an empty handoffKmsKeyArn as the feature
    # being off, and omitting the block entirely is the same signal with no
    # partially-configured state to validate against.
    var.handoff_kms_key_arn == "" ? {} : {
      secrets = {
        handoffKmsKeyArn = var.handoff_kms_key_arn
      }
    },
    # Per-application traffic tracking. Same absent-not-empty rule as
    # secrets above: an empty traffic_log_group leaves the `traffic` block
    # out entirely, which is how serve and worker both read the feature as
    # off.
    var.traffic_log_group == "" ? {} : {
      traffic = {
        logGroup = var.traffic_log_group
      }
    },
  )
}
