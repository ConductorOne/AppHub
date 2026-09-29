// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package matrix derives a provider's capability support matrix from the
// provider itself.
//
// # Why derivation rather than a document
//
// "Which capabilities does each provider support" is a factual claim about code,
// and this repository has already paid five times for the class of defect where
// an artifact and the thing it describes drift apart silently. A hand-written
// table in the public documentation is exactly that shape: correct on the day it
// is written, and unfalsifiable afterwards. So the table is computed — from
// [compute.Provider]'s reflected method set, from [compute.AllCapabilities], and
// from what the provider's own accessors actually return.
//
// The intended consumer is the public documentation (USOSS-20) and any admin
// surface that wants to tell an operator what a configured provider can do
// before they ask it to do something.
//
// # The three failure modes this package is built around
//
// **A derivation that returns nothing passes every check written over it.** So
// [Derive] fails rather than returning an empty matrix: no reflected accessors,
// no capability constants, or no rows is an error, not a result. A caller that
// renders a Matrix is therefore rendering something that was non-empty when it
// was built.
//
// **A port that exists but is unimplemented can hide, and probing only narrows
// that.** [compute.Provider] is written so that a refusal happens at acquisition
// — the accessor returns [compute.ErrUnsupported] and the caller never receives a
// port. The failure mode it is designed to prevent is a provider that returns a
// port whose methods refuse, moving the refusal from acquisition (discoverable)
// to call time (not). Nothing in the type system forbids that, and a capability
// set can agree with the accessors while the port behind one of them is a shell.
// With [Options.ProbePorts] set, [Derive] calls every method of every port it
// obtained and reports one whose every method refuses as [SupportStub], and one
// where only some refuse as [SupportPartial].
//
// **This package originally claimed more than that, and the claim was
// falsified.** It said a port that exists but is unimplemented *cannot* hide. A
// reviewer built one that does: refuse every realistic call, but answer
// [compute.ErrInvalidSpec] to the single zero-argument call the probe makes, and
// it was published as available. [SupportPartial] catches that specific port —
// five of its six methods refuse — but the general statement is now the weaker
// and true one: **a zero-argument probe is negative evidence only.** It can show
// that a port refuses; it cannot show that a port works, because the one input it
// knows how to construct is the input every well-written port rejects on
// validation grounds. Closing that would mean driving each port with a valid
// specification, which is what [compute/conformance] does and is not this
// package's job.
//
// **A restatement of a set drifts from the set.** The accessor list is not
// written down here: it is the subset of [compute.Provider]'s methods that
// return (interface, error), read out of the interface type at run time. Adding
// a port to [compute.Provider] adds a row without anybody editing this package,
// and [TestAccessorsAreDerivedNotListed] pins that the derivation finds the
// ports that exist today rather than an empty set.
//
// # What probing costs, and why it is opt-in
//
// [Options.ProbePorts] calls every method of every port with zero-valued
// arguments. On the providers in this repository that is inert — a zero spec
// fails validation and a zero [compute.Ref] fails the provider's own ownership
// check, both before anything is written — but "inert" is a property of an
// implementation, not of the interface, and this package cannot verify it for a
// provider it has never seen. So probing is off by default, and a caller that
// turns it on is asserting that the provider it passed is pointed at a
// disposable substrate.
package matrix
