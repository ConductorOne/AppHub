# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# State lives in S3, with locking.
#
# It holds the session transaction key and the oauth2-proxy cookie secret --
# the two values Terraform generates rather than an operator supplying -- so
# the bucket must be encrypted, versioned, and readable by the people who may
# operate this deployment and nobody else.
#
# The values below are intentionally not filled in: a backend block takes no
# variables, so it is edited per deployment. `make tf-init` passes
# -backend-config for the same reason, if you would rather keep this file
# generic:
#
#   make tf-init TF_ENV=example \
#     TF_BACKEND_ARGS='-backend-config=bucket=... -backend-config=key=...'

terraform {
  backend "s3" {
    # bucket       = "<terraform state bucket>"
    # key          = "apphub/<environment>/terraform.tfstate"
    # region       = "<region>"
    encrypt      = true
    use_lockfile = true
  }
}
