# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0

# Multi-platform release index digests resolved from Docker Hub on 2026-09-10.
FROM node:24.21.0-bookworm-slim@sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
COPY docs/guide/ /src/docs/guide/
RUN npm run build

FROM golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110 AS backend
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w" -o /out/apphub ./cmd/apphub

# No shell, runtime client, build tools, source checkout, or operator secrets.
# Mount server configuration separately; configure staticDir=/app/frontend/dist.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
WORKDIR /app
COPY --from=backend /out/apphub /usr/local/bin/apphub
COPY --from=frontend /src/frontend/dist/ /app/frontend/dist/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/apphub"]
CMD ["serve"]
