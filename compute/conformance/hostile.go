// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Demanding a hostile mode (USOSS-61).
//
// Four checks in this suite scan a channel for material that only arrives if the
// provider puts it there. Every one of them reported the same green whether the
// provider was correct or the channel was empty, and USOSS-39 found out the hard
// way: the credential-egress check passed against compute/aws, and bypassing that
// provider's redacting writer entirely did not turn it red, because the
// in-memory build runner wrote its own arguments and nothing else. The check ran,
// the build succeeded, the scan found nothing — every signal individually honest
// and the whole thing vacuous.
//
//	A benign fixture and a correct implementation are indistinguishable.
//	A check with an input it cannot receive reports the same green as a
//	correct provider.
//
// So a scan is not allowed to stand on its own here. Before searching a channel
// for material, a check requires the provider to carry a marker *of the suite's
// choosing* into *that channel*, and verifies it arrived. Only then does the real
// scan mean anything, because only then is the channel known to be observable.
//
// # Why a marker rather than a declaration
//
// The obvious design is a capability a provider declares — a boolean, or a hook
// that reports "yes, I can be hostile". Both are claims, and a claim a provider
// can make falsely reproduces the vacuity one level out: the check would then be
// verifying the declaration rather than the channel.
//
// The next design, and the one this project reached first, is exercise-and-verify
// on the *fixture*: ask the provider to emit, then confirm the provider says it
// did. That is what fake.Harness.InjectionFired does for the failure injector,
// and for an injector it is sufficient, because consumption of an arming *is* the
// failure. It is not sufficient here. A runner can be asked to emit, report that
// it did, and write somewhere the check never reads — so "did you emit" is still
// a claim about the fixture rather than an observation of the channel.
//
// A marker is neither. "Here is a string only I know; make it appear where a leak
// would appear" cannot be satisfied without actually wiring the channel the check
// reads, and the suite verifies it by looking. It is a positive control for the
// scan itself, which nothing in this suite had before.
//
// # What this cannot do, stated rather than papered over
//
// It works only for a channel the suite owns or is handed: a writer it supplied,
// an error it received, a status field it read back. It does **not** work for a
// provider-supplied *enumeration* — contract rule 9 — because a hostile mode can
// put a marker into an artefact and nothing stops the provider omitting that
// artefact from what it enumerates. The scan then sees a non-empty set, a marker
// that arrived through some other artefact, and the leaking item silently absent.
//
// The USOSS-61 derivation counted the split: **4 checks read a channel the suite
// owns, 12 read Options.Rendered.** The four are constructed here. USOSS-48
// closed one of the twelve, security/secret-material-does-not-appear-in-
// rendered-artefacts, with [Options.RenderedRef] -- a per-resource
// correspondence hook that asks about one [compute.Ref] rather than trusting
// an enumeration to be complete; see checkEveryPlantedResourceIsRendered and
// security/every-planted-resource-has-a-rendered-artefact. The remaining
// eleven still stand on the aggregate scan alone and are recorded below in
// unverifiableByMarker.

// Channel names a place a provider can put something that a check then reads.
//
// Each one is owned or directly received by the suite. There is deliberately no
// Channel for [Options.Rendered]: see the package comment above for why a marker
// cannot settle an enumeration, and unverifiedObligations for what can.
type Channel string

// The channels a check scans.
const (
	// ChannelBuildLog is the io.Writer the suite passes as
	// [compute.BuildRequest.Logs].
	ChannelBuildLog Channel = "build-log"
	// ChannelBuildError is the error a build returns.
	ChannelBuildError Channel = "build-error"
	// ChannelBuildResult is the [compute.BuildResult] a build returns.
	//
	// It is settleable because [compute.BuildResult.Digest] is documented as
	// optional and opaque -- "Empty otherwise; callers must not require it" -- so
	// a provider can carry a marker there without violating anything else.
	ChannelBuildResult Channel = "build-result"
	// ChannelStatusMessage is [compute.Status.Message] on a read-back.
	ChannelStatusMessage Channel = "status-message"
	// ChannelCallError is the error an ordinary port call returns when it fails.
	//
	// No check currently scans it, and that is worth stating rather than leaving
	// to be inferred from a grep. [checkSecretsNotInErrors] did, and USOSS-66
	// took it back out: it read the foreign-[compute.Ref] refusal, which is the
	// call both reference providers wire their emission into, while the errors
	// that check actually searches for material come from Put, EnsureRelational
	// and EnsureService. Establishing one error and scanning five others is the
	// defect [Env.scanChannels] exists to close, and the scan of the established
	// error could find nothing because that call had never been handed any
	// material. So that check now plants a marker of the suite's own choosing in
	// each spec it drives into failure and requires the refusal to name it,
	// which settles every error it reads rather than one it does not.
	//
	// The channel stays because a provider's ability to put an arbitrary string
	// into a call error is real, both reference providers implement it, and it
	// is the only construction available to a check that reads an error it
	// cannot seed. What it must not be used for is establishing one error on
	// behalf of another.
	ChannelCallError Channel = "call-error"
	// ChannelImageMetadata is the metadata a provider recorded for a pushed
	// image, read back through [Options.ImageMetadata].
	//
	// It is the fourth credential-egress channel USOSS-39 named and did not
	// build, and it does not fit the other three as cleanly: those are read
	// straight back from what [compute.ImageBuilder.Build] returns, so
	// establishing them needs only the write half, [Options.EmitInto].
	// [compute.BuildResult] carries no image metadata at all, so this channel
	// needs a read hook of its own -- [Options.ImageMetadata] -- and a nil
	// EmitInto or a nil ImageMetadata both leave it unverified rather than
	// scanned.
	ChannelImageMetadata Channel = "image-metadata"
)

// channels returns every channel, so a check cannot be added against one this
// file does not know about and so the coverage test has a population.
func channels() []Channel {
	return []Channel{
		ChannelBuildLog,
		ChannelBuildError,
		ChannelBuildResult,
		ChannelStatusMessage,
		ChannelCallError,
		ChannelImageMetadata,
	}
}

// ErrChannelNotHostile is what [Options.EmitInto] returns when the provider has
// no way to put anything into the named channel.
//
// It is a refusal rather than a failure: whether a substrate's builder can be
// made to print is a fact about the substrate, not a conformance question. What
// it is not is a pass — the check that wanted the channel reports NOT VERIFIED.
var ErrChannelNotHostile = errors.New("conformance: the provider cannot emit into this channel")

// marker returns the string a check demands the provider carry into a channel.
//
// It is per-run and per-channel so that a marker arriving in the wrong channel is
// not mistaken for the right one, and it deliberately does not look like
// credential material: a provider redacting its own secrets from a log must not
// redact this too, or an honest provider would look unwired.
func (e *Env) marker(c Channel) string {
	return fmt.Sprintf("conformance-observability-marker-%s-%s", c, e.Name("m"))
}

// scanChannels establishes that every channel in scans carries what the provider
// puts there, and then searches each for material.
//
// The two halves are one call on purpose. The first version had a separate gate a
// check called before scanning, plus a table naming which channels each check
// established, and a reviewer defeated both in one sitting:
//
//   - the credential check scanned THREE channels -- the log, the error and the
//     result -- and gated ONE. With a hook that genuinely emitted into the log
//     and silently accepted the error channel, the check passed while claiming
//     credentials appear in no log, error or result. **A scan that reads three
//     channels and establishes one has established nothing about the other two.**
//   - nothing compared the table against the call sites. Deleting a channel from
//     an entry passed. Naming a check that does not exist passed. **Validating
//     that a name is well-formed is not validating that it denotes what it
//     claims.**
//
// Both are the defect this file exists to close, one level in. So there is no
// table and no separate gate: the set of channels established and the set scanned
// are the same map, so a channel cannot be added to one without the other or
// removed from one without the other.
//
// Each reader is called twice: once with a marker armed for its channel, to
// establish the channel carries anything at all, and once unarmed for the scan.
// The emission is cleared in between, because a persistent one poisons the real
// run -- an armed build-error makes every later build fail, which would turn the
// material scan into a skip and hand back the vacuous green by another route.
//
// Outcomes, and there is no fourth:
//
//   - the hook is nil, or refuses a channel: NOT VERIFIED, naming the channel.
//     No scan runs, because a clean scan of a channel nothing can reach is not
//     evidence about the provider.
//   - the hook accepts a channel and the marker does not arrive: FAIL. A hook
//     that reports success without wiring the channel buys a green for every scan
//     standing on it, which is worse than one that refuses.
//   - every marker arrives: each channel is scanned and a clean result means
//     something.
func (e *Env) scanChannels(tb TB, port, inv string, material []string, scans map[Channel]func() string) {
	tb.Helper()
	if len(scans) == 0 {
		fail(tb, port, inv, "this check scans no channel at all, so it asserts nothing; a suite "+
			"bug rather than a provider one")
		return
	}
	if len(material) == 0 {
		fail(tb, port, inv, "this check was given no material to search for, so every channel "+
			"would come back clean whatever the provider did with it")
		return
	}
	for i, m := range material {
		if m == "" {
			fail(tb, port, inv, "material %d of %d is the empty string, which matches everything "+
				"and would make this check pass or fail at random", i+1, len(material))
			return
		}
	}

	// Establish first, every channel, in a stable order so a failure reproduces.
	for _, c := range sortedChannels(scans) {
		if !e.establish(tb, inv, c, scans[c]) {
			return
		}
	}

	// Then scan, the same set.
	for _, c := range sortedChannels(scans) {
		got := scans[c]()
		for i, secret := range material {
			if !strings.Contains(got, secret) {
				continue
			}
			// The contents are never printed: they contain the material.
			fail(tb, port, inv, "material %d of %d reached the %s channel. An operator, a support "+
				"engineer or an audit log reads that channel, and this run has already "+
				"established that the provider's own output reaches it", i+1, len(material), c)
		}
	}
}

// establish is one channel's positive control.
func (e *Env) establish(tb TB, inv string, c Channel, read func() string) bool {
	tb.Helper()
	if e.Options.EmitInto == nil {
		skipBecause(tb, e, inv, fmt.Sprintf("Options.EmitInto is not supplied, so the %s channel "+
			"cannot be shown to carry anything. A scan of a channel nothing can reach finds "+
			"nothing whatever the provider does with the material, which is the same green a "+
			"correct provider produces", c))
		return false
	}
	want := e.marker(c)
	switch err := e.Options.EmitInto(e.ctx, e.Provider, c, want); {
	case errors.Is(err, ErrChannelNotHostile):
		skipBecause(tb, e, inv, fmt.Sprintf("this provider cannot emit into the %s channel (%v), "+
			"so a clean scan of it is not evidence. Whether a substrate can be made to print is a "+
			"fact about the substrate rather than a conformance question, which is why this is "+
			"unverified and not a failure", c, err))
		return false
	case err != nil:
		fatal(tb, "provider", inv, "Options.EmitInto(%s) failed: %v", c, err)
		return false
	}

	got := read()
	// Cleared before the verdict, so a failure does not leave the provider armed
	// for whatever runs next.
	if err := e.Options.EmitInto(e.ctx, e.Provider, c, ""); err != nil {
		fatal(tb, "provider", inv, "clearing the %s emission failed: %v", c, err)
		return false
	}
	if !strings.Contains(got, want) {
		fail(tb, "provider", inv, "the provider accepted a request to emit into the %s channel "+
			"and the marker did not arrive there. Either the hook writes somewhere this check "+
			"does not read, or it does nothing -- and a hook that reports success without wiring "+
			"the channel buys a green for every scan standing on it, which is worse than one that "+
			"refuses", c)
		return false
	}
	return true
}

// sortedChannels is for reproducible ordering.
func sortedChannels(m map[Channel]func() string) []Channel {
	out := make([]Channel, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// unverifiableByMarker records the checks a marker cannot settle, and why.
//
// These are the eleven of the USOSS-61 derivation's twelve category-B checks
// that remain: every one reads [Options.Rendered], which is an enumeration the
// provider composes rather than a channel the suite holds. A hostile mode can
// put a marker into an artefact; what it cannot do is stop the provider
// leaving that artefact out of the list. So the construction in this file
// does not apply to them, and saying so here is better than a green that
// implies it does.
//
// The twelfth, security/secret-material-does-not-appear-in-rendered-
// artefacts, is not here: USOSS-48 gave it a sibling check,
// security/every-planted-resource-has-a-rendered-artefact, that asks about one
// [compute.Ref] rather than trusting the enumeration, and that is what closes
// the gap for this invariant. checkSecretsNotInRendered itself is unchanged
// and still cannot be settled by a marker on its own -- it is the pairing with
// the correspondence check that closes the invariant, not a change to this
// mechanism -- so its own check name would no longer belong in a table of
// checks with no remedy.
func unverifiableByMarker() map[string]string {
	const why = "reads Options.Rendered, which the provider enumerates rather than the suite " +
		"holding it. A marker can be carried into an artefact and the artefact then omitted from " +
		"the enumeration, so the marker's arrival would prove the list is non-empty rather than " +
		"that it is complete. Contract rule 9."
	out := map[string]string{
		"security/tls-listener-requires-a-resolvable-certificate": why,
	}
	for _, pt := range ports() {
		out["port/"+pt.Name+"/ensure-converges-rather-than-accumulating"] = why
	}
	return out
}
