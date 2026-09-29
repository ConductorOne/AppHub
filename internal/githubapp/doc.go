// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package githubapp is the GitHub App plumbing this repository's consumers
// need: mint an app-level RS256 JWT from an App ID and an RSA private key,
// exchange it for a scoped installation access token, and list or look up the
// accounts that have installed the app.
//
// # Why this package started small, and grew deliberately
//
// The source system's equivalent package is ~4,900 lines across fifteen
// files: installation caching, owner->installation resolution, repository
// listing, tarball fetching, pull-request helpers, a repo auditor, and
// webhook signature verification. When this package was ported (USOSS-7),
// the credential provider used exactly one of those capabilities, so
// everything else was deliberately left behind rather than dragging an
// entire GitHub integration into a repository with no other GitHub consumer.
//
// A second consumer appeared alongside the first, though later:
// internal/source.Checkout, which fetches a repository's exact commit for a
// deploy or an advisory scan using the original mint-a-token path. A third
// consumer, internal/worker's admin GitHub App sync (which lists and looks
// up installations for the Workspace UI's read-only status view), is why
// ListInstallations and GetInstallationByOwner exist: it needed exactly
// those two additions and nothing past them. Webhook signature verification
// is the later addition, and it exists because serve has a receiver that
// checks X-Hub-Signature-256 and nothing else: the package still does not
// fetch tarballs, open pull requests, or apply a delivery to installation
// records. Grow it the same way the next time: one concrete caller, one
// deliberate addition, not a wholesale port.
//
// It is internal because it is an implementation detail of this
// repository's own GitHub consumers, not a GitHub client offered to
// adopters.
//
// # What is stricter here than in the source
//
// Two changes, both fail-closed, both because this code sends credentials to a
// host that comes from configuration:
//
//   - The API base URL must be an absolute https URL with a host and no
//     userinfo, query or fragment. The source accepted any string, so a
//     mistyped or hostile api_base_url would send an app JWT -- which is
//     credential material -- to whatever it named.
//   - Redirects are refused rather than followed. Go strips the Authorization
//     header across hosts, but it does not refuse the request, and a redirect
//     off the configured host is never something this client should follow
//     silently.
//
// Credential material in this package is credentials.Secret, never a string:
// both the app JWT and the installation token are material, and the type is
// what keeps them out of a log line or a wrapped error.
package githubapp
