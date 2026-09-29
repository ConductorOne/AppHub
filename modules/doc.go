// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package modules defines the Module contract: the interface every AppHub
// capability implements, the parameter schema it publishes, the result it
// returns, and the progress channel it reports on.
//
// This package holds the framework only. Concrete modules belong in
// subdirectories -- modules/review and modules/fix are ported (USOSS-17),
// modules/deploy is still a skeleton -- and import this package for the
// interface; nothing here may import them, so the dependency arrow always
// points inward and no import cycle is possible.
//
// What was ported and how faithfully (USOSS-6): [Module], [Result],
// [JSONSchema], [JSONSchemaProperty], [BaseModule] and the three progress
// helpers are verbatim apart from their comments. [Registry] carries three
// deliberate behaviour changes -- ordered listings, and refusal of a nil module
// or an empty ID -- and [ValidateDeclaredParams] is verbatim. [Missing] and
// [ErrNotConfigured] are new here. docs/decisions/ has the reasoning for each.
//
// Keep the interface general: it must still fit capabilities that are not in
// the v1 set without being reopened. In particular Execute takes an untyped
// parameter map rather than a per-module Go type, which is what lets a module be
// selected and invoked by ID from a request without the caller knowing which
// module it is -- the source's own dispatch reads an ID from the request path,
// looks it up in the registry, and hands the decoded parameter object straight
// through. See docs/decisions/ for why that shape is deliberate.
//
// # How a module gets its dependencies
//
// A module needs collaborators — a store, a cloud provider, a token minter, an
// AI client. Two rules govern how it gets them, and together they are what
// keeps this tree portable.
//
// # 1. A module declares the interface it needs, and never imports its supplier
//
// The narrow interface or func type belongs to the module's own package, and
// whatever satisfies it belongs to the caller: a module asks for a
// FindingsWriter it declared rather than importing the thing that writes
// findings. This is the load-bearing rule, and it is what a reviewer should
// look for first in a new module.
//
// It is the rule the port inherited, and it is worth counting how far it
// reached, because the answer is the standard to beat rather than the standard
// already met. Counts are out of the 28 production (non-test) files in the
// source's module tree, and out of the 87 in its service layer:
//
//   - Module files importing the service layer: 0 of 28. None could, because
//     the dependency runs the other way -- 7 of the 87 service-layer files
//     import the framework package itself, and 25 of 87 import somewhere under
//     the module tree, so the reverse would be a cycle.
//   - Module files importing the persistence package directly, for its domain
//     types: 16 of 28. By package rather than by file that is 6 of the 8
//     packages under the tree; the two that do not are types, which is the
//     framework, and vendor. The root package's single one is in the
//     registration helper this port leaves out, so the framework itself is
//     clean and its wiring was not.
//   - Module files importing a cloud SDK directly: 10 of 28, eight in deploy
//     and two in paved.
//
// So the service-layer half of the rule held completely and the layer below it
// did not.
//
// Here the rule is the wider one: nothing under modules/ imports a store, a
// service layer, or a cloud SDK. Persistence is reached through store/ and
// cloud APIs through a compute provider. Both of those packages are still
// skeletons as this is written, so treat the rule as the constraint the modules
// are being ported under rather than as a property already demonstrated.
//
// Be exact about what holds that line, because the three parts are held by
// different things.
//
// internal/boundary carries three import rules -- ConductorOne reachable only
// from credentials/c1, DynamoDB only from store/, and compute/ext only from an
// allowlist that includes modules/deploy. USOSS-28 changed what enforcing them
// proves: it checks a single *union* import graph with build constraints ignored,
// and since any concrete build can only select edges from that union, a union
// with no forbidden path covers every configuration rather than an enumerated
// list of them. The concrete targets still run, as compatibility checks. Read its
// package comment before repeating any claim about it -- this sentence described
// an enumeration until the rebase that took USOSS-28, which is the hazard of
// describing a neighbouring mechanism at all.
//
// Two of those three touch this tree: the DynamoDB fence is what "persistence
// through store/" rests on, and the compute/ext allowlist bounds which packages
// may see substrate-specific ports. The broader rule that a module reaches cloud
// APIs only through a compute provider is **not** among them. It is checked, but
// by a different mechanism and over a smaller population: USOSS-17 added
// modules/review/portability_test.go, which walks every package under this
// directory and fails on an import from a cloud SDK's publishing organisation.
// That is a check on this tree's own source rather than a proof over an import
// graph, so it sees a direct import and not a transitive one -- which is why the
// same file separately holds modules/review and modules/fix to importing nothing
// but the standard library and this tree, where a closure argument does the rest.
//
// This framework package needs none of them, importing nothing outside the
// standard library at all.
//
// # 2. Dependencies arrive through the constructor
//
// NewXModule takes what it needs and returns an error naming anything absent;
// use [Missing] to build that error so every module in the tree fails the same
// recognisable way. A module with a missing dependency is therefore never
// constructed, a registered module is always usable, and "is this wired yet?"
// is not a question Execute has to answer.
//
// The source this was ported from wired four of its nine modules the other way:
// it constructed them empty, registered them, and pushed dependencies in
// afterwards through 16 exported Set* methods. That is deliberately not carried
// over — see docs/decisions/, USOSS-6, for the reasoning and for what it
// costs. [Missing] and [ErrNotConfigured] exist so the fail-closed behaviour
// that pattern provided survives the change of mechanism.
package modules
