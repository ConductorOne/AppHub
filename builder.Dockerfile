# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The image a build task runs. It is the supported Kaniko OSS executor, not
# the archived GoogleContainerTools image (gcr.io/kaniko-project/*, archived
# June 2025). osscontainertools does not support copying /kaniko/executor
# into another base — kaniko unpacks the image it is building over its own
# rootfs — so this file is a pin, not a wrapper.
#
# Index digest resolved from ghcr.io on 2026-09-18 for v1.28.2.

FROM ghcr.io/osscontainertools/kaniko:v1.28.2@sha256:4ea0e7301e3f6806de15150e4982c73018351e28c1dca6947bd3b4afb5ae3c60
