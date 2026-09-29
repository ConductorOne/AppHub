# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# CI runs these targets. It does not reimplement them.
#
# That is the whole point of this file: if the workflow ran `go test` directly
# and this file ran it with different flags, the two would drift and the green
# check would stop meaning "it passes locally". Every gate in .github/workflows
# is a `make` target you can run yourself, with the same tool versions, pinned
# below.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# Tool versions. Pinned so a green build stays green for a reason, and so
# upgrading a linter is a reviewable one-line diff rather than a surprise.
GOLANGCI_LINT_VERSION ?= v2.13.2
GOVULNCHECK_VERSION   ?= v1.7.0
GO_LICENSES_VERSION   ?= v2.0.1
GITLEAKS_VERSION      ?= v8.30.1

# Dependency licences we accept. Anything outside this set fails the build and
# has to be argued for. Apache-2.0 is our own licence; the rest are the
# permissive ones it composes with cleanly.
ALLOWED_LICENSES ?= Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC

# The compatibility matrix: the build configurations `make boundary` compiles the
# tree against, and the definition of which build constraints a file may carry --
# one list, so the two cannot drift.
#
# This is NOT what proves the import boundary. That is a union import graph over
# every declared import with build constraints ignored, which does not depend on
# this matrix at all (docs/decisions/, USOSS-28). Narrowing this weakens the
# compatibility checks and leaves the proof intact.
BOUNDARY_GOOS   ?= linux,darwin,windows
BOUNDARY_GOARCH ?= amd64,arm64

# The platforms `make lint` analyses, and it is a list for one reason: a linter
# sees only the files its GOOS selects, so a single-platform run reports
# differently depending on whose machine it is. That is the drift this file
# exists to prevent -- a green check in CI stopped meaning "it passes locally"
# the moment a //go:build !linux file carried a finding nobody on Linux could
# see, which is exactly what happened.
#
# Linux is where the worker runs and where CI runs; darwin is where it is
# developed. Windows is deliberately absent: nothing here runs on it, its
# portability is `make boundary`'s question rather than this one's, and its test
# tree does not currently compile (internal/astaudit's walk_test.go uses
# syscall.Mkfifo). Adding it means fixing that first.
LINT_GOOS ?= linux,darwin

# What `make dco` diffs against when checking sign-offs locally.
DCO_BASE ?= origin/main

# History the secret scan walks. Everything reachable from HEAD -- which is this
# branch plus all of main behind it, exactly the history that would become
# public if this branch merged.
#
# Not every ref: gitleaks defaults to scanning them all, so an unmerged branch
# belonging to somebody else's pull request would fail this one. Each branch is
# scanned by its own pull request, which is where a finding can actually be
# fixed.
SECRETS_LOG_OPTS ?= HEAD

TOOLS_DIR := $(CURDIR)/.tools
export PATH := $(TOOLS_DIR):$(PATH)

GO ?= go

# Container images. `make server` / `make builder` / `make worker-image` build
# locally; `make push-*` retags those onto this environment's ECR repositories.
#
# Docker Desktop/Buildx attaches provenance attestations by default. Pushing
# that extra manifest list to ECR is a 403 on the blob HEAD. These flags keep
# a single-platform image, which is also what the digest-pinned builder needs.
IMAGE_TAG     ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf '%s' latest)
PLATFORM      ?= linux/amd64
DOCKER_BUILD_FLAGS ?= --provenance=false --sbom=false
SERVER_IMAGE  ?= apphub/server
WORKER_IMAGE  ?= apphub/worker
BUILDER_IMAGE ?= apphub/builder

# Every Go invocation below uses exactly the toolchain go.mod names, and CI's
# setup-go reads the same file -- so a local run and the CI job cannot analyse
# different standard libraries.
#
# This is not housekeeping. With GOTOOLCHAIN left at its default, a developer
# whose Go is newer than the floor gets a `make vuln` that reports standard
# library advisories CI never sees (verified: eight of them, attributed to the
# module's declared toolchain rather than the one doing the work). A security
# check that disagrees with CI is a security check people stop reading.
#
# It also keeps `.tools/` binaries built by the same toolchain as the module,
# which is what stops go-licenses reporting every standard library package as
# missing module info.
GO_TOOLCHAIN := $(shell awk '/^toolchain /{print $$2}' go.mod)
ifeq ($(GO_TOOLCHAIN),)
$(error no toolchain directive in go.mod: refusing to run with an unpinned toolchain)
endif
export GOTOOLCHAIN := $(GO_TOOLCHAIN)

# Local development defaults. The endpoint is deliberately explicit so nothing
# using these targets can accidentally reach AWS. The host port is offset from
# DynamoDB Local's default 8000 so this stack can run beside another instance.
DEV_COMPOSE_FILE  ?= compose.dev.yml
DEV_ENV_FILE      ?= .env.local
DYNAMODB_DATA_DIR ?= $(CURDIR)/.dynamodb
DYNAMODB_ENDPOINT ?= http://127.0.0.1:18000
DYNAMODB_REGION   ?= us-east-1
DYNAMODB_TABLE    ?= apphub-local

# API and worker use separate operator-mounted configuration. These variables
# may be supplied in the environment or on the make command line; no credentials
# or target infrastructure are inferred from the local DynamoDB defaults above.
APPHUB_CONFIG        ?=
APPHUB_WORKER_CONFIG ?=
LOCAL_CONFIG_DIR     ?= $(CURDIR)/.local
FRONTEND_HOST        ?= 127.0.0.1
FRONTEND_PORT        ?= 5173

DEVDB_ARGS = -endpoint "$(DYNAMODB_ENDPOINT)" -region "$(DYNAMODB_REGION)" -table "$(DYNAMODB_TABLE)"

# Signing values come from .env.local. The endpoint is forced afterward so a
# leftover AWS_ENDPOINT_URL (another DynamoDB Local on :8000, or AWS itself)
# cannot steal these targets. Cloud session tokens are dropped for the same
# reason: DynamoDB Local rejects them as an unrecognized client.
DEVDB_ENV = set -a; source "$(DEV_ENV_FILE)"; \
	AWS_ENDPOINT_URL="$(DYNAMODB_ENDPOINT)"; \
	AWS_ENDPOINT_URL_DYNAMODB="$(DYNAMODB_ENDPOINT)"; \
	unset AWS_SESSION_TOKEN AWS_SECURITY_TOKEN AWS_PROFILE; \
	set +a;
DEVDB_RUN = $(DEVDB_ENV) $(GO) run ./store/cmd/devdb

.PHONY: dynamo-env
dynamo-env: ## Create private local-only DynamoDB credentials when absent or unusable.
	@$(GO) run ./store/cmd/devdb env -file "$(DEV_ENV_FILE)" -endpoint "$(DYNAMODB_ENDPOINT)"

.PHONY: config-init
config-init: ## Write a gitignored loopback serve skeleton under .local/.
	$(GO) run ./hack/localconfig -dir "$(LOCAL_CONFIG_DIR)" -static-dir "$(CURDIR)/frontend/dist" \
		-endpoint "$(DYNAMODB_ENDPOINT)" -region "$(DYNAMODB_REGION)" -table "$(DYNAMODB_TABLE)"

.PHONY: infra-up
infra-up: ## Start local DynamoDB and its admin UI, and initialise AppHub state and audit tables.
	mkdir -p "$(DYNAMODB_DATA_DIR)"
	docker compose -f "$(DEV_COMPOSE_FILE)" up -d
	$(MAKE) --no-print-directory dynamo-init

.PHONY: infra-down
infra-down: ## Stop local development infrastructure without deleting its data.
	docker compose -f "$(DEV_COMPOSE_FILE)" down

.PHONY: infra-reset
infra-reset: ## Delete all local DynamoDB data and recreate the state and audit tables.
	docker compose -f "$(DEV_COMPOSE_FILE)" down --volumes --remove-orphans
	rm -rf "$(DYNAMODB_DATA_DIR)"
	$(MAKE) --no-print-directory infra-up

.PHONY: dynamo-init
dynamo-init: dynamo-env ## Create the local AppHub state and audit tables if absent.
	@$(DEVDB_RUN) init $(DEVDB_ARGS)

.PHONY: dynamo-reset
dynamo-reset: dynamo-env ## Recreate the local AppHub state and audit tables.
	@$(DEVDB_RUN) reset $(DEVDB_ARGS)

.PHONY: dynamo-seed
dynamo-seed: dynamo-init ## Insert idempotent non-secret lifecycle examples.
	@$(DEVDB_RUN) seed $(DEVDB_ARGS)

# Demo data for screenshots and UI review. APPHUB_CONFIG's target must allow
# scheduled jobs, public and internal routes, and the demo repositories;
# `go run ./store/cmd/devseed -repositories` prints the repository list.
DEMO_OWNER_EMAIL ?=

.PHONY: demo-seed
demo-seed: dynamo-init ## Seed demo users and deployed-looking applications (APPHUB_CONFIG, DEMO_OWNER_EMAIL).
	@test -n "$(APPHUB_CONFIG)" -a -n "$(DEMO_OWNER_EMAIL)" || { printf '%s\n' 'APPHUB_CONFIG and DEMO_OWNER_EMAIL are required.' >&2; exit 2; }
	@$(DEVDB_ENV) cd "$(dir $(APPHUB_CONFIG))" && $(GO) run $(CURDIR)/store/cmd/devseed -config "$(APPHUB_CONFIG)" -owner-email "$(DEMO_OWNER_EMAIL)"

.PHONY: demo-remove
demo-remove: dynamo-env ## Delete the demo users and applications demo-seed wrote (APPHUB_CONFIG).
	@test -n "$(APPHUB_CONFIG)" || { printf '%s\n' 'APPHUB_CONFIG is required.' >&2; exit 2; }
	@$(DEVDB_ENV) cd "$(dir $(APPHUB_CONFIG))" && $(GO) run $(CURDIR)/store/cmd/devseed -config "$(APPHUB_CONFIG)" -remove

.PHONY: dynamo-scan
dynamo-scan: dynamo-env ## Print every item in the local AppHub state table as JSON.
	@$(DEVDB_RUN) scan $(DEVDB_ARGS)

.PHONY: dynamo-tables
dynamo-tables: dynamo-env ## List local DynamoDB tables as JSON.
	@$(DEVDB_RUN) tables $(DEVDB_ARGS)

.PHONY: run
run: serve ## Run the HTTP backend using APPHUB_CONFIG.

.PHONY: serve
serve: ## Run the HTTP backend (APPHUB_CONFIG=/absolute/path/server.yaml). Sources .env.local (DEV_ENV_FILE) when present.
	@test -n "$(APPHUB_CONFIG)" || { printf '%s\n' 'APPHUB_CONFIG must name the server configuration file.' >&2; exit 2; }
	if [ -f "$(DEV_ENV_FILE)" ]; then set -a; . "$(DEV_ENV_FILE)"; set +a; fi; \
	$(GO) run ./cmd/apphub serve --config "$(APPHUB_CONFIG)"

.PHONY: worker
worker: ## Run the deployment worker (APPHUB_WORKER_CONFIG=/absolute/path/worker.yaml). Sources .env.local (DEV_ENV_FILE) when present.
	@test -n "$(APPHUB_WORKER_CONFIG)" || { printf '%s\n' 'APPHUB_WORKER_CONFIG must name the worker configuration file.' >&2; exit 2; }
	if [ -f "$(DEV_ENV_FILE)" ]; then set -a; . "$(DEV_ENV_FILE)"; set +a; fi; \
	$(GO) run ./cmd/apphub worker --config "$(APPHUB_WORKER_CONFIG)"

.PHONY: providers
providers: ## Report configured credential-provider capabilities.
	$(GO) run ./cmd/apphub providers

.PHONY: frontend
frontend: ## Run Vite on the explicit local frontend host/port (install with npm --prefix frontend ci).
	npm --prefix frontend run dev -- --host "$(FRONTEND_HOST)" --port "$(FRONTEND_PORT)" --strictPort

.PHONY: dev
dev: ## Run backend and frontend together; start infra and the credential-bearing worker separately.
	@test -n "$(APPHUB_CONFIG)" || { printf '%s\n' 'APPHUB_CONFIG must name the server configuration file.' >&2; exit 2; }
	$(MAKE) --no-print-directory --jobs=2 serve frontend

.PHONY: help
help: ## Show this help.
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## --- build and test -------------------------------------------------------

.PHONY: build
build: ## Compile every package.
	$(GO) build ./...

## --- container images -----------------------------------------------------

.PHONY: server
server: ## Build the API container image locally (Dockerfile).
	docker build --platform "$(PLATFORM)" $(DOCKER_BUILD_FLAGS) -f Dockerfile -t "$(SERVER_IMAGE):$(IMAGE_TAG)" -t "$(SERVER_IMAGE):latest" .

.PHONY: worker-image
worker-image: ## Build the worker container image locally (worker.Dockerfile). `make worker` runs the process.
	docker build --platform "$(PLATFORM)" $(DOCKER_BUILD_FLAGS) -f worker.Dockerfile -t "$(WORKER_IMAGE):$(IMAGE_TAG)" -t "$(WORKER_IMAGE):latest" .

.PHONY: builder
builder: ## Build the Kaniko OSS builder image locally (builder.Dockerfile).
	docker build --platform "$(PLATFORM)" $(DOCKER_BUILD_FLAGS) -f builder.Dockerfile -t "$(BUILDER_IMAGE):$(IMAGE_TAG)" -t "$(BUILDER_IMAGE):latest" .

.PHONY: images
images: server worker-image builder ## Build the API, worker, and builder images locally.

.PHONY: vet
vet: ## Run go vet.
	$(GO) vet ./...

.PHONY: test
test: ## Run the test suite with the race detector and coverage.
	$(GO) test -race -cover ./...

.PHONY: cover
cover: ## Run tests and write coverage.out / coverage.html.
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

.PHONY: fmt
fmt: ## Format the tree.
	$(GO) fmt ./...

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum.
	$(GO) mod tidy

## --- correctness gates ----------------------------------------------------

.PHONY: lint
lint: $(TOOLS_DIR)/golangci-lint ## Run golangci-lint for each platform in $(LINT_GOOS).
	# USOSS-72: golangci-lint has been seen exiting 2 ("linters did not run")
	# while still printing "0 issues". The wrapper makes that exit code loud
	# and unmistakable instead of relying on whoever is reading the transcript
	# to check $$? rather than the tail of stdout.
	@for goos in $$(printf '%s' "$(LINT_GOOS)" | tr ',' ' '); do \
		printf 'golangci-lint: GOOS=%s\n' "$$goos"; \
		GOOS="$$goos" ./hack/lint.sh $(TOOLS_DIR)/golangci-lint run || exit $$?; \
	done

.PHONY: headers
headers: ## Check every Go file carries the Apache-2.0 SPDX header.
	./hack/check-license-headers.sh

.PHONY: boundary
boundary: ## Enforce the import boundaries (c1 optional, DynamoDB fenced, no undeclared build tags).
	# The check runs with GOPROXY=off so it cannot resolve a dependency over the
	# network mid-run: module directories and the union graph both come from what
	# is already on disk. Populate the module cache first, here, where fetching is
	# expected.
	$(GO) mod download
	$(GO) run ./hack/boundarycheck -goos $(BOUNDARY_GOOS) -goarch $(BOUNDARY_GOARCH)

.PHONY: decisions
decisions: ## Check the decision record's structure (see internal/decisions).
	$(GO) run ./hack/decisionslint

.PHONY: citations
citations: ## Check that file:line citations in comments and docs resolve (see internal/citations).
	$(GO) run ./hack/citationlint

.PHONY: disclosure
disclosure: ## Check publication-disclosure shapes that do not belong in the public tree.
	$(GO) run ./hack/disclosurecheck

.PHONY: oss-sync
oss-sync: ## Build the public snapshot of origin/main and describe it; PUSH=1 publishes it.
	./hack/oss-sync.sh $(if $(PUSH),--push)

.PHONY: dco
dco: ## Check every commit on this branch is signed off by its author.
	./hack/check-dco.sh $(DCO_BASE) HEAD

## --- security and supply chain --------------------------------------------

.PHONY: hermetic
hermetic: ## Assert CI needs no cloud credentials.
	$(GO) run ./hack/hermeticcheck

.PHONY: secrets
secrets: secrets-selftest ## Scan the tree, the git history, and file names for secrets and disclosures.
	$(TOOLS_DIR)/gitleaks dir . --config .gitleaks.toml --redact --no-banner
	./hack/check-paths.sh
	$(TOOLS_DIR)/gitleaks git . --config .gitleaks.toml --redact --no-banner --log-opts="$(SECRETS_LOG_OPTS)"

.PHONY: secrets-selftest
secrets-selftest: $(TOOLS_DIR)/gitleaks ## Prove the disclosure rules still fire, on synthetic examples.
	./hack/check-secret-rules.sh

.PHONY: vuln
vuln: $(TOOLS_DIR)/govulncheck ## Check dependencies against the Go vulnerability database.
	@echo "govulncheck under $(GO_TOOLCHAIN) (the toolchain go.mod pins, and the one CI uses)"
	$(TOOLS_DIR)/govulncheck ./...

.PHONY: licenses
licenses: $(TOOLS_DIR)/go-licenses ## Fail on any dependency licence outside $(ALLOWED_LICENSES).
	# GOROOT is passed explicitly because go-licenses classifies a package as
	# standard library by comparing its directory against GOROOT, and when the
	# toolchain pinned in go.mod is newer than the locally installed one the
	# toolchain -- and therefore the whole standard library -- lives in the
	# module cache instead. Without this the tool aborts on "net/url does not
	# have module info" before it checks a single dependency. It does not
	# change what is accepted: $(ALLOWED_LICENSES) is unchanged and every
	# dependency is still checked.
	GOROOT=$$($(GO) env GOROOT) $(TOOLS_DIR)/go-licenses check ./... --allowed_licenses=$(ALLOWED_LICENSES)

## --- aggregate ------------------------------------------------------------

.PHONY: check
check: build vet lint headers boundary hermetic decisions citations disclosure test ## Everything CI runs that does not need a base branch to diff against.
	@echo "note: CI also runs 'make dco' against the pull request's base commit."


.PHONY: check-all
check-all: check secrets vuln licenses ## `check` plus the supply-chain scans.

## --- deployment (terraform) ------------------------------------------------
#
# One environment per directory under terraform/environments. TF_ENV selects
# it, and nothing here reads AWS configuration out of this repository: the
# credentials and the backend are the operator's, exactly as `make hermetic`
# requires of everything CI runs.
#
# These targets are not run by CI and never will be. A terraform apply is a
# change to a real account, and the gate on it is a person.

TF_ENV          ?= example
TF_DIR          ?= terraform/environments/$(TF_ENV)
TF              ?= terraform
TF_BACKEND_ARGS ?=
TF_ARGS         ?=

# Refuse early and legibly, rather than letting terraform report a missing
# directory as a confusing parse error.
define tf_env_guard
@test -d "$(TF_DIR)" || { \
	printf '%s\n' "no such environment: $(TF_DIR)" >&2; \
	printf '%s\n' "environments are: $$(ls terraform/environments | tr '\n' ' ')" >&2; \
	exit 2; \
}
endef

.PHONY: tf-init
tf-init: ## Initialize Terraform (TF_ENV=example, TF_BACKEND_ARGS='-backend-config=...').
	$(tf_env_guard)
	cd $(TF_DIR) && $(TF) init $(TF_BACKEND_ARGS)

.PHONY: tf-fmt
tf-fmt: ## Format every Terraform file.
	$(TF) fmt -recursive terraform/

.PHONY: tf-fmt-check
tf-fmt-check: ## Fail if any Terraform file is unformatted.
	$(TF) fmt -check -recursive terraform/

.PHONY: tf-validate
tf-validate: ## Validate the configuration (TF_ENV=example).
	$(tf_env_guard)
	cd $(TF_DIR) && $(TF) validate

.PHONY: tf-plan
tf-plan: ## Plan changes (does not apply).
	$(tf_env_guard)
	cd $(TF_DIR) && $(TF) plan $(TF_ARGS)

.PHONY: tf-apply
tf-apply: ## Apply this environment. Terraform plans interactively; no saved plan file is required.
	$(tf_env_guard)
	cd $(TF_DIR) && $(TF) apply $(TF_ARGS)

.PHONY: tf-output
tf-output: ## Show outputs: portal URL, redirect URIs to register, secrets still to set.
	$(tf_env_guard)
	@cd $(TF_DIR) && $(TF) output

.PHONY: tf-destroy
tf-destroy: ## Destroy the environment. The control-plane table is protected and survives.
	$(tf_env_guard)
	cd $(TF_DIR) && $(TF) destroy $(TF_ARGS)

.PHONY: tf-check
tf-check: tf-fmt-check tf-validate ## Formatting and validation, the two checks that need no credentials.

## --- deployment (images and rollout) ---------------------------------------
#
# The images the deployment runs are built from this repository's Dockerfile,
# worker.Dockerfile, and builder.Dockerfile (Kaniko OSS, digest-pinned).
# Terraform creates the ECR repositories and, unless server_image / worker_image
# are pinned, runs each repository's :latest tag. Image promotion is `make
# promote`, not a terraform apply. The builder's first digest is written to
# builder_image.auto.tfvars for the apply that creates the families;
# `make promote-builder` registers later digest-pinned revisions.

TF_OUTPUT = cd $(TF_DIR) && $(TF) output -raw

.PHONY: tf-up
tf-up: ## Create ECR, build and push images, apply infra, and promote onto ECS.
	$(tf_env_guard)
	cd $(TF_DIR) && $(TF) apply -target=module.cluster $(TF_ARGS)
	$(MAKE) ecr-login
	$(MAKE) push
	@test -s "$(TF_DIR)/builder_image.auto.tfvars" || { \
		printf '%s\n' "push-builder did not write $(TF_DIR)/builder_image.auto.tfvars" >&2; \
		exit 1; \
	}
	cd $(TF_DIR) && $(TF) apply $(TF_ARGS)
	$(MAKE) promote

.PHONY: ecr-login
ecr-login: ## Log the local Docker client into this environment's ECR registry.
	$(tf_env_guard)
	@set -eu; \
	registry="$$(cd $(TF_DIR) && $(TF) output -json image_repositories | \
		sed -n 's|.*"server": *"\([^/]*\)/.*|\1|p')"; \
	region="$$(cd $(TF_DIR) && $(TF) output -raw aws_region 2>/dev/null || \
		printf '%s' "$${AWS_REGION:-us-west-2}")"; \
	aws ecr get-login-password --region "$$region" | \
		docker login --username AWS --password-stdin "$$registry"

.PHONY: push-server
push-server: ecr-login server ## Build the API image and push it to this environment's ECR repository.
	$(tf_env_guard)
	@set -eu; \
	repo="$$(cd $(TF_DIR) && $(TF) output -json image_repositories | \
		sed -n 's|.*"server": *"\([^"]*\)".*|\1|p')"; \
	docker tag "$(SERVER_IMAGE):$(IMAGE_TAG)" "$$repo:$(IMAGE_TAG)"; \
	docker tag "$(SERVER_IMAGE):latest" "$$repo:latest"; \
	docker push "$$repo:$(IMAGE_TAG)"; docker push "$$repo:latest"; \
	printf 'server_image = "%s:%s"\n' "$$repo" "$(IMAGE_TAG)"

.PHONY: push-worker
push-worker: ecr-login worker-image ## Build the worker image and push it to this environment's ECR repository.
	$(tf_env_guard)
	@set -eu; \
	repo="$$(cd $(TF_DIR) && $(TF) output -json image_repositories | \
		sed -n 's|.*"worker": *"\([^"]*\)".*|\1|p')"; \
	docker tag "$(WORKER_IMAGE):$(IMAGE_TAG)" "$$repo:$(IMAGE_TAG)"; \
	docker tag "$(WORKER_IMAGE):latest" "$$repo:latest"; \
	docker push "$$repo:$(IMAGE_TAG)"; docker push "$$repo:latest"; \
	printf 'worker_image = "%s:%s"\n' "$$repo" "$(IMAGE_TAG)"

.PHONY: push-builder
push-builder: ecr-login builder ## Build the Kaniko OSS builder image, push it, and write builder_image.auto.tfvars.
	$(tf_env_guard)
	@set -eu; \
	repo="$$(cd $(TF_DIR) && $(TF) output -json image_repositories | \
		sed -n 's|.*"builder": *"\([^"]*\)".*|\1|p')"; \
	docker tag "$(BUILDER_IMAGE):$(IMAGE_TAG)" "$$repo:$(IMAGE_TAG)"; \
	docker tag "$(BUILDER_IMAGE):latest" "$$repo:latest"; \
	docker push "$$repo:$(IMAGE_TAG)"; docker push "$$repo:latest"; \
	digest="$$(docker inspect --format='{{index .RepoDigests 0}}' "$$repo:$(IMAGE_TAG)")"; \
	printf '%s' "$$digest" | grep -Eq '@sha256:[0-9a-f]{64}$$' || { \
		printf 'could not resolve a digest pin for %s:%s (got %s)\n' "$$repo" "$(IMAGE_TAG)" "$$digest" >&2; \
		exit 1; \
	}; \
	printf 'builder_image = "%s"\n' "$$digest" > "$(TF_DIR)/builder_image.auto.tfvars"; \
	printf 'builder_image = "%s"\n' "$$digest"

.PHONY: push
push: push-server push-worker push-builder ## Build and push the API, worker, and builder images to ECR.

.PHONY: promote-api
promote-api: ## Roll the API ECS service onto the current :latest image.
	$(tf_env_guard)
	@set -eu; \
	cluster="$$($(TF_OUTPUT) cluster_name)"; \
	service="$$($(TF_OUTPUT) api_service_name)"; \
	region="$$($(TF_OUTPUT) aws_region)"; \
	aws ecs update-service --no-cli-pager --region "$$region" \
		--cluster "$$cluster" --service "$$service" \
		--force-new-deployment >/dev/null; \
	printf 'promoting %s\n' "$$service"; \
	aws ecs wait services-stable --region "$$region" --cluster "$$cluster" --services "$$service"; \
	printf 'stable %s\n' "$$service"

.PHONY: promote-worker
promote-worker: ## Roll the worker ECS service onto the current :latest image. It revalidates build tasks on start.
	$(tf_env_guard)
	@set -eu; \
	cluster="$$($(TF_OUTPUT) cluster_name)"; \
	service="$$($(TF_OUTPUT) worker_service_name)"; \
	region="$$($(TF_OUTPUT) aws_region)"; \
	aws ecs update-service --no-cli-pager --region "$$region" \
		--cluster "$$cluster" --service "$$service" \
		--force-new-deployment >/dev/null; \
	printf 'promoting %s\n' "$$service"; \
	aws ecs wait services-stable --region "$$region" --cluster "$$cluster" --services "$$service"; \
	printf 'stable %s\n' "$$service"

.PHONY: promote-ingress
promote-ingress: ## Roll Traefik and oauth2-proxy so new tasks re-read Parameter Store.
	$(tf_env_guard)
	@set -eu; \
	cluster="$$($(TF_OUTPUT) cluster_name)"; \
	region="$$($(TF_OUTPUT) aws_region)"; \
	traefik="$$cluster-traefik"; \
	oauth2="$$cluster-oauth2-proxy"; \
	for service in "$$traefik" "$$oauth2"; do \
		aws ecs update-service --no-cli-pager --region "$$region" \
			--cluster "$$cluster" --service "$$service" \
			--force-new-deployment >/dev/null; \
		printf 'promoting %s\n' "$$service"; \
	done; \
	aws ecs wait services-stable --region "$$region" --cluster "$$cluster" --services "$$traefik" "$$oauth2"; \
	printf 'stable %s %s\n' "$$traefik" "$$oauth2"

.PHONY: promote-builder
promote-builder: ## Register digest-pinned revisions of the build task families. Does not terraform apply.
	$(tf_env_guard)
	@set -eu; \
	command -v python3 >/dev/null || { printf '%s\n' 'python3 is required to promote the builder' >&2; exit 2; }; \
	repo="$$(cd $(TF_DIR) && $(TF) output -json image_repositories | \
		sed -n 's|.*"builder": *"\([^"]*\)".*|\1|p')"; \
	region="$$($(TF_OUTPUT) aws_region)"; \
	name="$${repo#*/}"; \
	digest="$$(aws ecr describe-images --region "$$region" \
		--repository-name "$$name" --image-ids imageTag="$(IMAGE_TAG)" \
		--query 'imageDetails[0].imageDigest' --output text 2>/dev/null || true)"; \
	if [ -z "$$digest" ] || [ "$$digest" = "None" ]; then \
		digest="$$(aws ecr describe-images --region "$$region" \
			--repository-name "$$name" --image-ids imageTag=latest \
			--query 'imageDetails[0].imageDigest' --output text)"; \
	fi; \
	image="$$repo@$$digest"; \
	case "$$image" in *@sha256:*) ;; *) \
		printf '%s\n' "builder image is not digest-pinned: $$image" >&2; exit 2; ;; \
	esac; \
	container="$$($(TF_OUTPUT) build_container_name)"; \
	printf 'promoting builder %s\n' "$$image"; \
	cd $(TF_DIR) && $(TF) output -json build_task_definition_families | python3 -c 'import json,sys; [print(x) for x in json.load(sys.stdin)]' | \
	while IFS= read -r family; do \
		tmp="$$(mktemp)"; \
		aws ecs describe-task-definition --region "$$region" --task-definition "$$family" \
			--query taskDefinition --output json | \
		python3 -c 'import json,sys; td=json.load(sys.stdin); image,name=sys.argv[1],sys.argv[2]; cs=[c for c in td["containerDefinitions"] if c.get("name")==name]; assert cs, "no container %r" % (name,); \
[c.__setitem__("image", image) for c in cs]; \
[td.pop(k, None) for k in ("taskDefinitionArn","revision","status","requiresAttributes","compatibilities","registeredAt","registeredBy","deregisteredAt","tags")]; \
json.dump(td, sys.stdout)' "$$image" "$$container" > "$$tmp"; \
		aws ecs register-task-definition --region "$$region" --cli-input-json "file://$$tmp" >/dev/null; \
		rm -f "$$tmp"; \
		printf 'registered %s\n' "$$family"; \
	done

# promote-services rolls both services at once and waits for both in one
# waiter, so a release takes as long as the slower rollout rather than the sum
# of the two. The worker is usually the slower: it drains in-flight operations
# before it stops.
.PHONY: promote-services
promote-services: ## Roll the API and worker onto :latest together; waits until both are stable.
	$(tf_env_guard)
	@set -eu; \
	cluster="$$($(TF_OUTPUT) cluster_name)"; \
	region="$$($(TF_OUTPUT) aws_region)"; \
	api="$$($(TF_OUTPUT) api_service_name)"; \
	worker="$$($(TF_OUTPUT) worker_service_name)"; \
	for service in "$$api" "$$worker"; do \
		aws ecs update-service --no-cli-pager --region "$$region" \
			--cluster "$$cluster" --service "$$service" \
			--force-new-deployment >/dev/null; \
		printf 'promoting %s\n' "$$service"; \
	done; \
	if ! aws ecs wait services-stable --region "$$region" --cluster "$$cluster" --services "$$api" "$$worker"; then \
		printf '%s\n' "a service did not become stable; current rollouts:" >&2; \
		aws ecs describe-services --no-cli-pager --region "$$region" --cluster "$$cluster" \
			--services "$$api" "$$worker" --output table \
			--query 'services[].{service:serviceName,rollout:deployments[0].rolloutState,reason:deployments[0].rolloutStateReason,running:runningCount,desired:desiredCount}' >&2; \
		exit 1; \
	fi; \
	printf 'stable %s %s\n' "$$api" "$$worker"

.PHONY: promote
promote: ## Promote builder revisions, then roll the API and worker services together.
	$(MAKE) promote-builder
	$(MAKE) promote-services

# release-* builds and pushes an image, then rolls that ECS service onto it.
# release pushes both images before either service rolls, so a restart cannot
# pick up one new binary while the other is still the previous build, then
# rolls both together. None of these run terraform apply, and none of them
# touch the builder image.

.PHONY: release-api
release-api: ## Build, push, and roll the API. Does not apply Terraform.
	$(MAKE) push-server
	$(MAKE) promote-api

.PHONY: release-worker
release-worker: ## Build, push, and roll the worker. Does not apply Terraform.
	$(MAKE) push-worker
	$(MAKE) promote-worker

.PHONY: release
release: ## Build and push the API and worker, then roll both together. Does not apply Terraform.
	$(MAKE) push-server
	$(MAKE) push-worker
	$(MAKE) promote-services

.PHONY: tf-redeploy-api
tf-redeploy-api: promote-api ## Deprecated name for promote-api.

.PHONY: tf-redeploy-worker
tf-redeploy-worker: promote-worker ## Deprecated name for promote-worker.

.PHONY: tf-logs-api
tf-logs-api: ## Follow the API log group.
	$(tf_env_guard)
	@aws logs tail "$$(cd $(TF_DIR) && $(TF) output -json log_groups | \
		sed -n 's|.*"api": *"\([^"]*\)".*|\1|p')" --follow

.PHONY: tf-logs-worker
tf-logs-worker: ## Follow the worker log group.
	$(tf_env_guard)
	@aws logs tail "$$(cd $(TF_DIR) && $(TF) output -json log_groups | \
		sed -n 's|.*"worker": *"\([^"]*\)".*|\1|p')" --follow

.PHONY: tf-logs-build
tf-logs-build: ## Follow the build log group: what kaniko wrote, for every build.
	$(tf_env_guard)
	@aws logs tail "$$(cd $(TF_DIR) && $(TF) output -json log_groups | \
		sed -n 's|.*"build": *"\([^"]*\)".*|\1|p')" --follow

.PHONY: tf-logs-ingress
tf-logs-ingress: ## Follow the Traefik log group.
	$(tf_env_guard)
	@aws logs tail "$$(cd $(TF_DIR) && $(TF) output -json log_groups | \
		sed -n 's|.*"traefik": *"\([^"]*\)".*|\1|p')" --follow

## --- tooling --------------------------------------------------------------

.PHONY: tools
tools: $(TOOLS_DIR)/golangci-lint $(TOOLS_DIR)/govulncheck $(TOOLS_DIR)/go-licenses $(TOOLS_DIR)/gitleaks ## Install pinned tools into .tools/.

# Each tool is installed at its pinned version into .tools/, which is gitignored.
# `go install pkg@version` ignores this module's go.mod, so a linter upgrade
# cannot perturb the dependency graph of the library we ship.
# Refresh a cached linter when its pin changes with the supported Go toolchain.
$(TOOLS_DIR)/golangci-lint: Makefile
	GOBIN=$(TOOLS_DIR) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(TOOLS_DIR)/govulncheck:
	GOBIN=$(TOOLS_DIR) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

$(TOOLS_DIR)/go-licenses:
	GOBIN=$(TOOLS_DIR) $(GO) install github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)

$(TOOLS_DIR)/gitleaks:
	GOBIN=$(TOOLS_DIR) $(GO) install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)

.PHONY: clean
clean: ## Remove build and tool output.
	rm -rf $(TOOLS_DIR) coverage.out coverage.html
