# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

output "vpc_id" {
  description = "VPC every other module places resources in."
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "The VPC's IPv4 CIDR."
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "Subnets the load balancers and NAT gateways live in."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Subnets every task and instance that runs code lives in."
  value       = aws_subnet.private[*].id
}

output "portal_alb_security_group_id" {
  description = "Security group of the portal load balancer."
  value       = aws_security_group.portal_alb.id
}

output "apphub_api_security_group_id" {
  description = "Security group of the AppHub API tasks."
  value       = aws_security_group.apphub_api.id
}

output "apps_nlb_security_group_id" {
  description = "Security group of the applications load balancer (ALB or NLB)."
  value       = aws_security_group.apps_nlb.id
}

output "traefik_security_group_id" {
  description = "Security group of the platform ingress; compute.PeerPlatformIngress resolves to it."
  value       = aws_security_group.traefik.id
}

output "internal_alb_security_group_id" {
  description = "Security group of the internal applications load balancer. Null when internal_ingress_enabled is false."
  value       = try(aws_security_group.internal_alb[0].id, null)
}

output "oauth2_proxy_security_group_id" {
  description = "Security group of oauth2-proxy."
  value       = aws_security_group.oauth2_proxy.id
}

output "efs_security_group_id" {
  description = "Security group of the EFS mount targets holding Traefik's ACME state."
  value       = aws_security_group.efs.id
}

output "worker_security_group_id" {
  description = "Security group of the deployment worker task."
  value       = aws_security_group.worker.id
}

output "build_security_group_id" {
  description = <<-EOT
    Shared public egress for build tasks. The task also receives its slot-only
    NFS security group from modules/build; this group cannot reach EFS.
  EOT
  value       = aws_security_group.build.id
}


output "apps_security_group_id" {
  description = "Baseline security group attached to every deployed application task."
  value       = aws_security_group.apps.id
}

output "control_plane_security_group_ids" {
  description = <<-EOT
    What compute.PeerControlPlane resolves to: the groups AppHub's own API and
    worker run in. An application asking for a control-plane ingress rule gets
    exactly these, and nothing wider -- in particular not the build group, which
    is not the control plane and has no business being reachable as it.
  EOT
  value       = [aws_security_group.apphub_api.id, aws_security_group.worker.id]
}
