// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package datadog vends Datadog API keys through the Key Management API v2.
//
// Datadog API keys do not expire, so this is a static-only provider: the
// platform is what eventually tears a key down, which is why the provider
// declares Static and Revoke through credentials.CapabilityReporter rather than
// leaving them to be inferred. An undeclared provider is inferred as
// static-incapable, and a static-only provider that declared nothing would be
// refused at admission for every credential type it can actually vend.
//
// The provider is cloud-neutral: net/http and encoding/json against a Datadog
// API host, no cloud SDK of any kind, and nothing here knows about
// ConductorOne.
//
// # Configuration
//
// Everything comes from credentials.Metadata, resolved per request by the
// caller's lifecycle.ProviderMetadataSource:
//
//	admin_api_key  required  a Datadog API key with key-management rights
//	admin_app_key  required  the matching Datadog application key
//	dd_site        optional  the Datadog API host; defaults to api.datadoghq.com
//
// dd_site is checked against a fixed allowlist of Datadog API hosts. That is not
// tidiness: this provider sends an admin API key in a request header, and a
// dd_site free to name any host is a way to have that key delivered somewhere
// else. Adding a Datadog region is a one-line change to allowedSites that a
// reviewer can see; accepting an arbitrary host is not.
//
// # HTTP policy is not configurable
//
// A caller may supply a http.RoundTripper (WithTransport) and nothing more. It
// may not supply an *http.Client, because redirect refusal is a field on one --
// review of the first port verified an ordinary replacement client following a
// synthetic 302 and sending DD-API-KEY to the second host. Redirect refusal and
// transport-error classification live in internal/credhttp, where no caller can
// reach them. docs/DECISIONS.md records why.
//
// An operator wiring this provider into lifecycle.AnnotationRegistry will
// probably want to declare no annotation keys at all. There is nothing
// non-secret and durable here worth keeping on the record: the site is operator
// configuration that the metadata source can re-resolve, and the key ID is
// already Record.PlatformKeyID.
//
// Ported from the internal implementation by USOSS-7. The differences from it
// are listed on Provider.
package datadog
