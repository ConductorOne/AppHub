# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# oauth2-proxy, reached only through Traefik's ForwardAuth middleware.
#
# This is what compute.Route.RequireAuth resolves to. AppHub's provider
# configuration names the ForwardAuth middleware by string
# (ContainerConfig.IngressAuthMiddleware). The separate cookie-strip
# middleware is applied AFTER auth on every application router, including
# public-path and MCP routers (ContainerConfig.IngressCookieStripMiddleware).
# The shared cookie is required on application requests so ForwardAuth can
# check it; the local Traefik plugin removes it before forwarding upstream.
# Neither middleware belongs on oauth2-proxy's auth-host/callback routers.
#
# Every identity the provider admits can reach every application published
# behind this middleware. The portal asks the user to acknowledge that.

resource "aws_cloudwatch_log_group" "oauth2_proxy" {
  name              = "${var.log_group_prefix}/oauth2-proxy"
  retention_in_days = var.log_retention_days

  tags = local.tags
}

# ------------------------------------------------------------------------------
# Secrets
#
# The cookie secret is generated here because it is ours to generate and
# nothing outside this deployment needs to know it. The client credentials are
# issued by the identity provider, so Terraform creates the parameters and
# deliberately never looks at their values again -- see the lifecycle block.
# ------------------------------------------------------------------------------

resource "random_bytes" "cookie_secret" {
  length = 32
}

resource "aws_ssm_parameter" "cookie_secret" {
  name        = "${var.parameter_prefix}/oauth2-proxy/cookie-secret"
  description = "oauth2-proxy cookie encryption secret"
  type        = "SecureString"

  # oauth2-proxy decodes this with base64.RawURLEncoding and, if that fails,
  # uses the string's own bytes as the AES key. Standard base64 of 32 bytes is
  # 44 padded characters, which is neither decodable that way nor a legal key
  # length, so the process exits at startup demanding 16, 24 or 32. URL-safe
  # and unpadded is 43 characters and decodes back to the 32 bytes above.
  value = trimsuffix(
    replace(replace(random_bytes.cookie_secret.base64, "+", "-"), "/", "_"),
    "=",
  )

  key_id = var.kms_key_id

  tags = local.tags
}

resource "aws_ssm_parameter" "client_id" {
  name        = "${var.parameter_prefix}/oauth2-proxy/client-id"
  description = "oauth2-proxy OAuth client id, set out of band"
  type        = "String"
  value       = "replace-me"

  lifecycle {
    ignore_changes = [value, insecure_value]
  }

  tags = local.tags
}

resource "aws_ssm_parameter" "client_secret" {
  name        = "${var.parameter_prefix}/oauth2-proxy/client-secret"
  description = "oauth2-proxy OAuth client secret, set out of band"
  type        = "SecureString"
  value       = "replace-me"
  key_id      = var.kms_key_id

  # The identity provider issues this, not Terraform. Writing the real value
  # here would put it in state; the parameter is created empty-shaped and set
  # with `aws ssm put-parameter --overwrite`, and Terraform stops reading it.
  lifecycle {
    ignore_changes = [value, insecure_value]
  }

  tags = local.tags
}

# ------------------------------------------------------------------------------
# Service discovery
#
# ForwardAuth addresses this service by name. A task address changes on every
# replacement, so the middleware cannot hold one.
#
# No health_check_custom_config. An empty block is ForceNew, and provider 6
# only persists the block when failure_threshold is set. The zero value is
# never written, so every plan adds the block and replaces the service. Cloud
# Map then refuses the delete while ECS still has an instance registered.
# failure_threshold = 1 is the value AWS stores, and it is deprecated; setting
# it on this service would replace it once.
# ------------------------------------------------------------------------------

resource "aws_service_discovery_service" "oauth2_proxy" {
  name = "oauth2-proxy"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  tags = local.tags
}

# ------------------------------------------------------------------------------
# Task definition
# ------------------------------------------------------------------------------

locals {
  auth_host     = "auth.${var.apps_domain}"
  cookie_domain = ".${var.apps_domain}"

  # ECS provider middleware names are qualified @ecs in the AppHub provider
  # configuration. Do not reuse the auth name: even public paths need this.
  ingress_cookie_strip_middleware = "apphub-strip-sso-cookie@ecs"

  oauth2_proxy_command = concat(
    [
      "--provider=${var.oauth2_proxy_provider}",
      "--http-address=0.0.0.0:4180",
      "--redirect-url=https://${local.auth_host}/oauth2/callback",
      # A 202 upstream, because nothing is proxied through here. Traefik
      # forwards the request itself once this service has said who the caller
      # is; oauth2-proxy only ever answers the sign-in flow and the auth check.
      "--upstream=static://202",
      "--reverse-proxy=true",
      "--set-xauthrequest=true",
      "--cookie-name=_oauth2_proxy",
      "--cookie-domain=${local.cookie_domain}",
      "--whitelist-domain=${local.cookie_domain}",
      "--cookie-secure=true",
      "--cookie-samesite=lax",
      "--skip-provider-button=true",
    ],
    [for domain in var.oauth2_proxy_email_domains : "--email-domain=${domain}"],
    var.oauth2_proxy_oidc_issuer_url == "" ? [] : [
      "--oidc-issuer-url=${var.oauth2_proxy_oidc_issuer_url}",
    ],
  )

  # Every router is on the same entrypoint the application routers use.
  # alb-wildcard: web, no TLS labels — the ALB already terminated TLS.
  # strict: websecure with the same certificate resolver Traefik issues
  # application certificates from, because the sign-in redirect's target has
  # to be served over HTTPS like everything else here.
  oauth2_proxy_labels = merge(
    {
      "traefik.enable" = "true"

      "traefik.http.routers.oauth2-proxy.rule"                      = "Host(`${local.auth_host}`)"
      "traefik.http.routers.oauth2-proxy.entrypoints"               = local.oauth2_entrypoint
      "traefik.http.services.oauth2-proxy.loadbalancer.server.port" = "4180"

      # The sign-in flow lands back on the application's own hostname, so
      # /oauth2/ has to be answered on every published host. The priority beats
      # any application router for the same host; AppHub's own public-path
      # routers use 5000 (compute/aws/routes.go), so this sits well above them.
      "traefik.http.routers.oauth2-catchall.rule"        = "PathPrefix(`/oauth2/`)"
      "traefik.http.routers.oauth2-catchall.entrypoints" = local.oauth2_entrypoint
      "traefik.http.routers.oauth2-catchall.priority"    = "10000"
      "traefik.http.routers.oauth2-catchall.service"     = "oauth2-proxy"

      # Root path rather than /oauth2/auth: the root answers an unauthenticated
      # request with a 302 to the identity provider. /oauth2/auth answers with
      # a bare 401. authResponseHeaders names exactly the two headers this
      # middleware establishes; Traefik deletes each listed header from the
      # incoming request and re-adds it only from the auth response.
      "traefik.http.middlewares.${var.ingress_auth_middleware}.forwardauth.address"             = "http://oauth2-proxy.${var.namespace_name}:4180/"
      "traefik.http.middlewares.${var.ingress_auth_middleware}.forwardauth.trustForwardHeader"  = "true"
      "traefik.http.middlewares.${var.ingress_auth_middleware}.forwardauth.authResponseHeaders" = "X-Auth-Request-User,X-Auth-Request-Email"
      "traefik.http.middlewares.${var.ingress_auth_middleware}.forwardauth.maxResponseBodySize" = "4096"

      # The plugin is packaged in the pinned Traefik image, not downloaded
      # at runtime. It rejects malformed Cookie fields rather than allowing a
      # second parser to reinterpret a shared credential after filtering.
      "traefik.http.middlewares.apphub-strip-sso-cookie.plugin.apphubcookiestrip.enabled" = "true"
    },
    local.tls_strict ? {
      "traefik.http.routers.oauth2-proxy.tls"                 = "true"
      "traefik.http.routers.oauth2-proxy.tls.certresolver"    = var.certificate_resolver
      "traefik.http.routers.oauth2-catchall.tls"              = "true"
      "traefik.http.routers.oauth2-catchall.tls.certresolver" = var.certificate_resolver
    } : {},
  )
}

resource "aws_ecs_task_definition" "oauth2_proxy" {
  family                   = "${var.name_prefix}-oauth2-proxy"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.oauth2_proxy_cpu
  memory                   = var.oauth2_proxy_memory
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([{
    name         = "oauth2-proxy"
    image        = var.oauth2_proxy_image
    essential    = true
    command      = local.oauth2_proxy_command
    dockerLabels = local.oauth2_proxy_labels

    secrets = [
      { name = "OAUTH2_PROXY_CLIENT_ID", valueFrom = aws_ssm_parameter.client_id.arn },
      { name = "OAUTH2_PROXY_CLIENT_SECRET", valueFrom = aws_ssm_parameter.client_secret.arn },
      { name = "OAUTH2_PROXY_COOKIE_SECRET", valueFrom = aws_ssm_parameter.cookie_secret.arn },
    ]

    portMappings = [{
      containerPort = 4180
      protocol      = "tcp"
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.oauth2_proxy.name
        "awslogs-region"        = data.aws_region.current.region
        "awslogs-stream-prefix" = "oauth2-proxy"
      }
    }
  }])

  tags = local.tags
}

resource "aws_ecs_service" "oauth2_proxy" {
  name            = "${var.name_prefix}-oauth2-proxy"
  cluster         = var.cluster_id
  task_definition = aws_ecs_task_definition.oauth2_proxy.arn
  desired_count   = var.oauth2_proxy_desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.oauth2_proxy_security_group_id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.oauth2_proxy.arn
  }

  tags = local.tags
}
