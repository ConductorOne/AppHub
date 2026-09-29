# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
