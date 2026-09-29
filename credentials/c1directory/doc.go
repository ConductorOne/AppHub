// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package c1directory reads ConductorOne directory data and optionally
// provisions C1 applications and GoLinks for AppHub deployments.
//
// It is deliberately independent of credentials/c1, which vends
// service-principal credentials. docs/design/credential-vending.md §3.1 records
// why the two are not one package: directory sync and deployment provisioning
// are a different trust relationship from minting credentials, should be able
// to hold a differently-scoped credential, and sharing code across two packages
// would put ConductorOne in two places instead of one. This package is the
// "own package" that decision anticipated, and internal/boundary/idiom.go's
// c1-idiom-fenced rule now names it alongside credentials/c1 as the only two
// places in this repository permitted to know ConductorOne exists.
//
// Like credentials/c1, exactly one composition root may import this package:
// github.com/conductorone/apphub/cmd/apphub. Every other package reaches synced
// directory data through internal/controlplane's DirectoryEntitlementKind
// records, populated by internal/worker's DirectorySyncer -- which depends on
// a narrow local interface this package's Client satisfies, never on this
// package directly, so internal/worker carries no ConductorOne idiom either.
//
// # Directory reads
//
// The org-wide entitlement catalog, verified against the source system's own
// ConductorOne client (backend/internal/conductorone/client.go): a single
// endpoint, POST {TenantURL}/api/v1/search/entitlements, paginated via
// pageToken/nextPageToken, returning an "appEntitlement" per row. The request's
// isAutomated filter is the one distinction the API itself draws: set true, it
// returns the subset ConductorOne's own automation can grant programmatically
// (the source system calls this "groups"); omitted, it returns the full catalog
// including directory-synced entries. ListGroups and ListEntitlements are that
// same filter, named for what a caller gets back. DirectorySyncer persists
// ListGroups: role assignment and feature-flag targeting are group
// membership, not the full entitlement catalog.
//
// ListUserGroupIDs reads a second shape from the same tenant: which
// entitlements one specific user holds, via POST /api/v1/search/users (email
// to user ID) then POST /api/v1/search/grants (user ID to held entitlement
// IDs), both verified against the source system's own client
// (GetUserByEmail, listUserGrants). Eligibility does not crawl every grant
// a busy user holds: it asks ListUserHeldEntitlementIDs for the currently
// synced groups only, filtered with entitlementRefs (appId + id) --
// SearchGrants' own filter -- so membership stays a handful of pages instead
// of tens of thousands of grants. A cancelled lookup returns
// an error rather than a truncated list, because Eligibility caches a
// successful result per email for GroupMembershipCacheTTL.
//
// # Optional deployment provisioning
//
// NewProvisioner exposes ProvisionApplication, DeleteApplication, and
// ProvisionGoLink. ProvisionApplication reconciles an AppHub-owned manual C1 app,
// its application resource, and general Access and Admin entitlements. The
// stable AppHub ID is stored in the app's apphub.app_id annotation and its
// current non-empty public URL in apphub.public_url, so a later deployment
// resumes a partial create rather than duplicating it while reconciling the
// current AppHub display name. ProvisionGoLink uses the stable AppHub ID in an
// ownership marker, creates or updates the exact requested alias, and
// redirects it to the supplied public URL. C1 requires that redirect target to
// be HTTPS; aliases C1 would normalize and aliases owned by another C1 GoLink
// are explicit errors, never silently changed or repointed.
//
// DeleteApplication looks up the apphub.app_id annotation and removes the C1 app
// before AppHub discards its own application record. It is idempotent and runs
// regardless of the creation flag's current state, provided the directory
// integration is configured. It does not remove separately provisioned GoLinks.
//
// Constructing either client does not write. Deployments call provisioning
// methods only behind their feature flags. Deletion checks for an owned C1 app
// even after the creation flag is disabled. These operations manage catalog
// objects only; they never grant, request, revoke, or approve user access.
//
// A provisioning credential needs these C1 API EDITOR roles, or equivalent
// permissions:
//
//   - role/c1.api.app.v1.Apps:editor
//   - role/c1.api.app.v1.AppResourceTypeService:editor
//   - role/c1.api.app.v1.AppResourceService:editor
//   - role/c1.api.app.v1.AppEntitlements:editor
//   - role/c1.api.golink.v1.GoLinkService:editor
//
// The first four cover Apps.Create, Apps.Update, Apps.Delete,
// CreateManuallyManagedResourceType, CreateManuallyManagedAppResource, and
// AppEntitlements.Create. GoLinkService.Create permits VIEWER, but its
// reconcile Update requires EDITOR, so its EDITOR role is the minimum for
// idempotent GoLink provisioning. Apps.Create assigns its caller as an initial
// app owner, so the OAuth subject must resolve to a C1 principal eligible to
// own applications and must remain an owner for Apps.Update and Apps.Delete.
// entitlement updates likewise require object-management permission. C1's Go
// Links tenant feature must be enabled before the GoLink method can create,
// list, or update a link.
//
// # How an adopter configures it
//
// Four environment variables, none shared with credentials/c1's own,
// mirroring the isolation the design doc asked for:
//
//	APPHUB_C1_DIRECTORY_TENANT_URL         required   the tenant base URL, https only
//	APPHUB_C1_DIRECTORY_CLIENT_ID          required   the OAuth client id; not a secret
//	APPHUB_C1_DIRECTORY_CLIENT_SECRET_REF  required*  a secret-store reference to the client secret
//	APPHUB_C1_DIRECTORY_CLIENT_SECRET      required*  the client secret itself (ECS Parameter Store injection)
//	APPHUB_C1_DIRECTORY_REQUEST_TIMEOUT    optional   per-call timeout, a Go duration; default 30s
//
// *exactly one of CLIENT_SECRET_REF or CLIENT_SECRET.
//
// With none of these set, ConfigFromEnv returns ErrNotConfigured and the
// composition root constructs neither a DirectorySyncer nor a Provisioner. A
// deployment that does not enable either optional C1 feature builds and runs
// exactly as before.
//
// The OAuth client-credentials grant is the only grant, and the secret is
// posted as client_secret — including a ConductorOne personal-client
// credential (`secret-token:conductorone.com:v1:` plus a JWK). That is how
// Union Station's own ConductorOne client authenticates
// (backend/internal/conductorone/client.go getAccessToken). credentials/c1's
// federated_jwt mode remains a different, unverified operator mode and is
// not used here.
package c1directory
