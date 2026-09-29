// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package lifecycle is the half of the credential contract that outlives a
// single vend call: what the platform remembers about a credential it handed
// out, and who drives that credential from issued to gone.
//
// The split matters. github.com/conductorone/apphub/credentials is stateless -- a
// provider mints material and forgets it. Everything about the credential
// *after* that (does it still exist, when does it expire, has someone asked for
// it back, did the upstream revoke actually land) is state, and in the source
// system that state lived in three places that had never been named as one
// thing: a DynamoDB record type, an HTTP handler that wrote it, and a scheduler
// goroutine that reconciled it. A provider that can mint but whose expiry and
// revocation live somewhere unspecified is a half-designed contract, so this
// package specifies the other half:
//
//   - Record is what is stored. It holds metadata and secret-store locators, and
//     it is structurally incapable of holding credential material.
//   - Records is the persistence port. store/ implements it (USOSS-5); nothing
//     here knows what a table is.
//   - Issuer is the policy layer: clamp the TTL, check the caller's scope, write
//     the intent down, call the provider, record what came back.
//   - Reconciler is the drive: it is what makes expiry and revocation happen
//     without a user watching, and what closes the window where an upstream
//     credential exists that the platform failed to record.
//
// Nothing in this package imports a cloud SDK, a database, or ConductorOne.
//
// Contract designed in USOSS-3. Implementations: Issuer and Reconciler in
// USOSS-7, Records in USOSS-5.
package lifecycle
