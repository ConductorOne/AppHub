# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS go-base
ENV GOTOOLCHAIN=local CGO_ENABLED=0

# Independent modules: tool dependencies never modify AppHub's go.mod/go.sum.
# Exact stable versions resolved from proxy.golang.org on 2026-09-10; downloads
# are authenticated by Go's public checksum database.
FROM go-base AS tools
WORKDIR /tools
RUN GOBIN=/out go install -trimpath github.com/google/go-containerregistry/cmd/crane@v0.22.1 \
    && GOBIN=/out go install -trimpath github.com/awslabs/amazon-ecr-credential-helper/ecr-login/cli/docker-credential-ecr-login@v0.12.0

FROM go-base AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w" -o /out/apphub ./cmd/apphub

# Git 2.54.0-r0 and its shared libraries, plus CA certificates. The worker
# shells out to git for every checkout (internal/source), which is why this is
# not a distroless image like the API's.
#
# It is still the Docker CLI image, and the CLI in it is now dead weight: the
# worker drives no container runtime since builds moved into their own ECS task.
# The base is kept for one reason -- every runtime package in it is fixed by the
# index digest, with no apk install or update at build time -- and swapping it
# for a smaller base that installs git from a package index at build time would
# trade a pinned package set for an unpinned one. Removing the CLI is worth
# doing when a digest-pinned base that carries git alone is available; the CLI
# is inert in the meantime, because no socket is mounted and the worker has no
# code path that looks for one.
FROM docker:29.8.0-cli@sha256:eccaacfeed644c7de222ff047483568cb988dde95476fbaaf10ea2d04921bb66
# /var/lib/apphub/work is created here, owned, rather than left to the task
# volume mounted over it. An empty volume takes its ownership from the image
# path it is mounted at. /var/lib/apphub/build is the parent of the per-slot
# EFS mountpoints; the worker needs to traverse it as uid 65532.
RUN addgroup -S -g 65532 apphub \
    && adduser -S -D -u 65532 -G apphub -h /home/apphub apphub \
    && mkdir -p /var/lib/apphub/work /var/lib/apphub/build \
    && chown -R 65532:65532 /var/lib/apphub
COPY --from=backend /out/apphub /usr/local/bin/apphub
COPY --from=tools /out/crane /out/docker-credential-ecr-login /usr/local/bin/
ENV HOME=/home/apphub
WORKDIR /var/lib/apphub
USER 65532:65532
# Mount worker-only configuration and source credentials at deployment. No
# container runtime socket: a build runs in its own ECS task, which this process
# launches through the ECS API and never through a local daemon.
#
# This is the trusted controller and pusher, NEVER the image a repository is
# built in. crane here holds the scoped push credential; the builder named by
# build.task runs somewhere this image cannot reach and holds nothing.
ENTRYPOINT ["/usr/local/bin/apphub"]
CMD ["worker"]
