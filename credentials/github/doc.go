// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package github vends GitHub App installation access tokens.
//
// This is a dynamic-only provider. GitHub caps an installation token at one
// hour and expires it itself, so the platform never has to tear one down -- and
// cannot revoke one either, which is the interesting property of this provider
// and the reason credentials.ErrRevokeNotSupported exists.
//
// The provider is cloud-neutral: it uses internal/githubapp, which is net/http,
// encoding/json and crypto from the standard library. No cloud SDK, and nothing
// here knows about ConductorOne.
//
// # Configuration
//
// Everything comes from credentials.Metadata, resolved per request by the
// caller's lifecycle.ProviderMetadataSource:
//
//	app_id           required  the numeric GitHub App ID
//	private_key      required  the app's RSA private key, PEM
//	installation_id  required  which installation to mint a token from
//	api_base_url     optional  GitHub Enterprise Server API root (https only)
//	repositories     optional  comma-separated repository names
//	repository_ids   optional  comma-separated numeric repository IDs
//	permissions      optional  JSON object, e.g. {"contents":"read"}
//
// The three optional scoping keys are how a token gets narrowed. Any of them
// present but resolving to nothing is refused rather than ignored -- including a
// key that is present and blank, which is the distinction review found missing:
// in GitHub's API an absent scoping field means the full installation grant, so
// treating a blank value as an absent one turns a request for two repositories
// into a token for all of them.
//
// Supplying no scoping key at all is still the ordinary "vend me a token for this
// installation" request and still works, but the provider now states it rather
// than arriving at it: internal/githubapp refuses a token request that restricts
// nothing unless the caller sets FullInstallationGrant, so no parsing mistake in
// any caller can widen a token by omission.
//
// # HTTP policy is not configurable
//
// A caller may supply a http.RoundTripper (WithTransport) and nothing more. Every
// request here carries an app JWT, which is higher privilege than the
// installation token it buys; redirect refusal and transport-error classification
// live in internal/credhttp, where no caller can reach them. See
// docs/DECISIONS.md.
//
// An operator wiring this provider into lifecycle.AnnotationRegistry will want
// lifecycle.AnnotationInstallationID declared: which installation minted a token
// is durable, non-secret, and not recoverable from anything else on the record.
//
// Ported from the internal implementation by USOSS-7, along with the minimum
// GitHub App plumbing it needs. The differences from the source are listed on
// Provider.
package github
