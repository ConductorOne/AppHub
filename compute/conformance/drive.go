// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/ext"
)

// This file derives two sets the suite used to restate by hand. Both
// restatements had drifted, and in both cases the drift was invisible because
// the check that depended on it went green:
//
//   - **What a check can drive.** checkTransientIsNotTerminal tested one
//     hand-written condition — [compute.CapSecretStore], "because a secret Put
//     is the cheapest write on any provider" — and then drove exactly one call.
//     That condition is a restatement of "what can I write with", so a provider
//     without a secret store got no coverage of the substrate-error mapping at
//     all, and a provider with one got coverage of a single method: an
//     implementation that reached [compute.ErrTransient] from its registry and
//     [compute.ErrFailed] from its identity service passed.
//   - **What can be handed secret material.** checkSecretsNotInRendered planted
//     its sentinel only for CapSecretStore+CapContainerService, or
//     CapRelationalDatabase. For any other provider it searched the rendered
//     artefacts for a sentinel nobody had planted, found none, and reported a
//     pass — a security check counted as coverage while proving nothing.
//
// Both sets are now derived from the port interfaces in [compute] itself: the
// method set comes from the interface type, and "can be handed secret material"
// comes from whether a method's argument transitively contains a
// [compute.SecretValue] (material itself) or a [compute.SecretBinding] (material
// by reference). The interfaces themselves are derived from [compute.Provider],
// so a port added there cannot be missed.
//
// A derivation that returns nothing passes every check over it, so every caller
// here asserts non-emptiness, and every restatement that remains — a method the
// suite does not drive, a port whose spec does not carry the material its
// interface could — is named with a reason and pinned generatively by
// TestEveryPortMethodIsDrivenOrNamed.

// portOp names one of the uniform operations [portOps] exposes. The transient
// gate drives every one a port has, rather than picking one.
type portOp string

// The uniform operations.
const (
	opEnsure   portOp = "Ensure"
	opDescribe portOp = "Describe"
	opWait     portOp = "Wait"
	opGrant    portOp = "Grant"
	opRevoke   portOp = "Revoke"

	// opDescribeGrant is [compute.Granter]'s read-back. It is a separate op
	// rather than folded into opDescribe because opDescribe is the port's own
	// resource read-back and the two answer about different things: one about the
	// resource, one about an (identity, resource) edge. Folding them would credit
	// one method's coverage to the other.
	opDescribeGrant portOp = "DescribeGrant"
	opScale         portOp = "Scale"
	opDelete        portOp = "Delete"

	// opEmpty is [compute.ObjectStore.EmptyBucket]: the destructive call that
	// removes a resource's data and leaves the resource. Separate from opDelete
	// for the reason the two methods are separate -- crediting one's coverage to
	// the other would leave the more destructive of the two unverified.
	opEmpty portOp = "Empty"

	// The optional image-pull grant surface. It belongs to
	// [compute.ImagePullGranter] rather than to the port that vends it, which
	// is why opOwner exists.
	opGrantPull  portOp = "GrantPull"
	opRevokePull portOp = "RevokePull"

	// opBuild belongs to no port in the table. See portlessDriven.
	opBuild portOp = "Build"
)

// pullGranterType is the interface the pull-grant ops belong to.
var pullGranterType = reflect.TypeOf((*compute.ImagePullGranter)(nil)).Elem()

// opOwner returns the interface an operation's method belongs to.
//
// It is pt.Iface for every op but the two pull-grant ones: a registry that also
// implements [compute.ImagePullGranter] drives methods of a *second* interface,
// and crediting them to ImageRegistry would leave ImagePullGranter's own methods
// looking undriven while ImageRegistry looked to have methods it does not have.
func opOwner(op portOp, pt Port) reflect.Type {
	switch op {
	case opGrantPull, opRevokePull:
		return pullGranterType
	default:
		return pt.Iface
	}
}

// driveOrder is the order a check drives the operations in. Delete is last
// because it removes the resource the others address.
func driveOrder() []portOp {
	return []portOp{
		opEnsure, opDescribe, opWait,
		opGrant, opDescribeGrant, opRevoke, opGrantPull, opRevokePull,
		opScale, opEmpty, opDelete,
	}
}

// Call is one method of one port, bound to a resource and ready to invoke.
type Call struct {
	// Port is the port's name, for the failure message.
	Port string
	// Op is the uniform operation.
	Op portOp
	// Method is the name of the [compute] interface method Do calls. A failure
	// names it rather than the suite's own vocabulary, because the provider
	// author has to go and look at that method.
	Method string
	// Do invokes it and returns the provider's error.
	Do func() error
}

// String names the call as a provider author would look for it.
func (c Call) String() string { return c.Port + "/" + c.Method }

// present reports whether o has this operation.
func (op portOp) present(o *portOps) bool {
	switch op {
	case opEnsure:
		return o.Ensure != nil
	case opDescribe:
		return o.Describe != nil
	case opWait:
		return o.Wait != nil
	case opGrant, opRevoke, opDescribeGrant:
		return o.Granter != nil
	case opGrantPull, opRevokePull:
		return o.PullGranter != nil
	case opScale:
		return o.Scale != nil
	case opDelete:
		return o.Delete != nil
	case opEmpty:
		return o.Empty != nil
	default:
		return false
	}
}

// optionalUnder reports the capability that gates an operation, empty for an
// operation every implementation of its port has.
//
// Only the pull-grant surface is optional in this sense: [compute.ImageRegistry]
// may also implement [compute.ImagePullGranter], and most registries cannot, so
// a port naming those methods with no operation behind them is a provider
// without the capability rather than a drifted table.
func (op portOp) optionalUnder() compute.Capability {
	switch op {
	case opGrantPull, opRevokePull:
		return compute.CapImagePullGrants
	default:
		return ""
	}
}

// drivableCalls returns every method of pt that a check can invoke against ref.
//
// It is the enumeration the transient gate needed and did not have. The pairing
// of an operation with the interface method it calls is the one restatement left
// here, and it is checked in both directions: an operation with no name and a
// name with no operation are both errors, because either means the table has
// drifted from the port.
func drivableCalls(pt Port, o *portOps, e *Env, ref, identity compute.Ref) ([]Call, error) {
	for op := range pt.Methods {
		if op.present(o) {
			continue
		}
		// An optional op is absent when the provider does not advertise the
		// capability that gates it, which is a fact about the provider rather
		// than drift in the table. Anything else is drift, and drift is how this
		// gate came to drive one call in the first place.
		if gate := op.optionalUnder(); gate != "" && !e.Provider.Capabilities().Has(gate) {
			continue
		}
		return nil, fmt.Errorf("conformance: port %q names a %s method (%q) in Port.Methods "+
			"and portOps has no %s operation; the table has drifted from the port",
			pt.Name, op, pt.Methods[op], op)
	}

	var out []Call
	add := func(op portOp, do func() error) error {
		name, ok := pt.Methods[op]
		if !ok || name == "" {
			return fmt.Errorf("conformance: port %q has a %s operation with no entry in "+
				"Port.Methods, so a check cannot name the interface method it drove; every "+
				"operation a port exposes has to be nameable or it goes silently undriven",
				pt.Name, op)
		}
		out = append(out, Call{Port: pt.Name, Op: op, Method: name, Do: do})
		return nil
	}

	// CapWorkloadGrants decides whether the grant surface is usable at all — a
	// Granter port's substrate may be able to authorise a workload identity in
	// principle and not in a given deployment. grantChecks gates on the same
	// capability for the same reason; driving Grant without it would be asking
	// for behaviour the provider has said it does not have, and the refusal is
	// already checked by grants/<port>/refused-without-the-capability.
	grants := e.Provider.Capabilities().Has(compute.CapWorkloadGrants)

	for _, op := range driveOrder() {
		if !op.present(o) {
			continue
		}
		if (op == opGrant || op == opRevoke || op == opDescribeGrant) && !grants {
			continue
		}
		if (op == opGrantPull || op == opRevokePull) &&
			!e.Provider.Capabilities().Has(compute.CapImagePullGrants) {
			continue
		}
		var err error
		switch op {
		case opEnsure:
			err = add(op, func() error {
				_, _, e2 := o.Ensure(e.Name("drive-"+pt.Name), Base)
				return e2
			})
		case opDescribe:
			err = add(op, func() error {
				_, e2 := o.Describe(ref)
				return e2
			})
		case opWait:
			err = add(op, func() error {
				_, e2 := o.Wait(ref, compute.WaitOptions{Timeout: e.Options.WaitTimeout})
				return e2
			})
		case opGrant:
			err = add(op, func() error {
				return o.Granter.Grant(e.ctx, ref, identity, compute.AccessRead)
			})
		case opRevoke:
			err = add(op, func() error {
				return o.Granter.Revoke(e.ctx, ref, identity)
			})
		case opDescribeGrant:
			err = add(op, func() error {
				_, e2 := o.Granter.DescribeGrant(e.ctx, ref, identity)
				return e2
			})
		case opGrantPull:
			err = add(op, func() error { return o.PullGranter.GrantPull(e.ctx, ref, identity) })
		case opRevokePull:
			err = add(op, func() error { return o.PullGranter.RevokePull(e.ctx, ref, identity) })
		case opScale:
			err = add(op, func() error { return o.Scale(ref, 1) })
		case opEmpty:
			err = add(op, func() error { return o.Empty(ref) })
		case opDelete:
			err = add(op, func() error { return o.Delete(ref) })
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// portlessDriven names the methods the suite drives on interfaces that have no
// entry in the port table, keyed by interface name.
//
// [compute.ImageBuilder] is the only one, and it is here rather than in ports()
// because a build provisions nothing: it has no Ref, no phase, no read-back and
// no lifecycle, so putting it in the port table would schedule a dozen checks
// about a resource it never creates — idempotency, convergence, PhaseGone after
// delete, foreign-Ref refusal on a Describe it does not have.
//
// This is the third population in this file, and the reason each exists is worth
// keeping straight: portInterfaces() is what a Provider vends, lookupPorts() is
// what a lookup helper vends, and this is what has no resource to vend. All
// three feed allPortInterfaces, and TestEveryExportedInterfaceIsClassified is
// what stops a fourth appearing unnoticed.
func portlessDriven() map[string][]string {
	return map[string][]string{
		"ImageBuilder": {"Build"},
	}
}

// portlessCalls builds the calls for portlessDriven, so the transient gate
// reaches them along with everything else.
//
// The fixtures — a build context on disk and a repository to push to — are
// created by the caller before any failure is induced, for the same reason the
// port fixtures are: with the setup inside the armed window the induced failure
// lands on the setup and the check proves nothing about Build.
func portlessCalls(tb TB, e *Env, fixture *BuildFixture) ([]Call, error) {
	if fixture == nil {
		return nil, nil
	}
	calls := []Call{{
		Port:   "image-build",
		Op:     opBuild,
		Method: "Build",
		Do: func() error {
			_, err := fixture.Build(tb, e, nil)
			return err
		},
	}}
	// The one restatement here, checked rather than trusted: the calls built
	// have to be exactly the methods portlessDriven claims.
	want := map[string]bool{}
	for _, m := range portlessDriven()["ImageBuilder"] {
		want[m] = true
	}
	for _, c := range calls {
		if !want[c.Method] {
			return nil, fmt.Errorf("conformance: a portless call drives ImageBuilder.%s, which "+
				"portlessDriven does not name", c.Method)
		}
		delete(want, c.Method)
	}
	for m := range want {
		return nil, fmt.Errorf("conformance: portlessDriven names ImageBuilder.%s and nothing "+
			"builds a call for it, so it goes undriven while the table says otherwise", m)
	}
	return calls, nil
}

// --- derivation from the interfaces ---------------------------------------

// portInterfaces derives the port interfaces from [compute.Provider]: every
// accessor's first result is one.
//
// Deriving it is the point. A hand-written list of ports is exactly the artefact
// that drifted from what the provider actually vends, and a port added to the
// interface has to appear here without anybody remembering to add it.
func portInterfaces() []reflect.Type {
	p := reflect.TypeOf((*compute.Provider)(nil)).Elem()
	seen := map[reflect.Type]bool{}
	var out []reflect.Type
	for i := range p.NumMethod() {
		sig := p.Method(i).Type
		if sig.NumOut() == 0 {
			continue
		}
		t := sig.Out(0)
		if t.Kind() != reflect.Interface || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// lookupPorts are the port interfaces reached through a *lookup helper* rather
// than through a [compute.Provider] accessor.
//
// They are the twelve methods the USOSS-39 audit found outside the population:
// portInterfaces derives from Provider's accessors, and these four ports are not
// reachable that way, so they were neither driven nor named and nothing said so.
//
// Each entry is the first result of the helper that vends it, so the *type* is
// derived rather than named — a helper whose return type changes follows
// automatically. What remains restated is the set of helpers, and that is what
// TestEveryExportedInterfaceIsClassified is for: it parses compute and
// compute/ext and fails on an exported interface no table here has heard of, so
// a helper added later cannot repeat the omission.
func lookupPorts() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(compute.ImagePullGrants).Out(0),
		reflect.TypeOf(ext.TableBuckets).Out(0),
		reflect.TypeOf(ext.VectorBuckets).Out(0),
		reflect.TypeOf(ext.ExternalAccess).Out(0),
	}
}

// allPortInterfaces is every port interface the suite knows of, from both
// routes. This is the population every coverage claim in this file is made
// against.
func allPortInterfaces() []reflect.Type {
	out := append([]reflect.Type(nil), portInterfaces()...)
	out = append(out, lookupPorts()...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// methodNames returns an interface's method names.
func methodNames(iface reflect.Type) []string {
	out := make([]string, 0, iface.NumMethod())
	for i := range iface.NumMethod() {
		out = append(out, iface.Method(i).Name)
	}
	sort.Strings(out)
	return out
}

// exclusion is why a port method is not driven, and what should make this entry
// wrong.
//
// USOSS-32 shipped this table with one field, a reason. The USOSS-39 audit then
// asked the two questions a bare reason cannot answer, and both changed the
// disposition of an entry:
//
//   - **Is it legitimate?** "No provider implements this" is true today and
//     stops being true on a named event. "Nobody got to it" is a hole. The two
//     look identical in a list of reasons and want opposite treatment. All three
//     of USOSS-32's entries turned out to be the second kind.
//   - **When does it expire?** An exclusion with no expiry is where an
//     obligation goes to be forgotten. Every entry here names the event after
//     which it is wrong, and Expires is required, so an eternal exclusion is not
//     a thing this table can express.
//   - **Can a machine tell?** Requiring Expires to be *present* is not requiring
//     it to be *evaluable*. Replacing an Expires with "banana" left the audit
//     green, because prose is prose: the gate could not distinguish an
//     unambiguous condition from an ambiguous one from a fruit. RetiredWhen is
//     the evaluable half, and it is also required.
type exclusion struct {
	// Reason is why the enumeration does not drive the method.
	Reason string
	// Expires names the event after which this entry is wrong — a ticket, a
	// pull request, a capability appearing. Required, and **for the reader**:
	// nothing evaluates it, which is why RetiredWhen exists beside it.
	Expires string
	// RetiredWhen is a fragment of a check name, and it is the half a machine
	// evaluates. TestNoExclusionOutlivesItsRetirementCondition fails once any
	// check registered in this package has a name containing it: the entry
	// deletes itself by turning red the moment it stops being necessary, so the
	// merge order of two unrelated pull requests stops mattering.
	//
	// A fragment rather than a whole name because port check names are computed
	// — "port/" + portName + suffix — so no literal of the whole name exists to
	// match against. The distinguishing suffix does.
	//
	// Two things the audit requires of the fragment, both learned rather than
	// designed:
	//
	//   - it must contain the kebab-case form of the method this entry excludes,
	//     which is what rules out "banana" without a hand-maintained vocabulary
	//     of acceptable strings;
	//   - it must be **longer** than that form alone. A fragment as coarse as
	//     the method name retires the entry when *any* check mentioning the
	//     method lands, and the check this entry waits for is a specific one.
	//     Retiring on the wrong event is the same defect as not retiring.
	//
	// Note the direction, which is the unusual part: this fires when something
	// **succeeds**. A tripwire that fires on breakage is watched; one that fires
	// on an obligation being met is not, and that is how a "not yet" becomes
	// permanent.
	RetiredWhen string
	// Legitimate reports that nothing can drive this method today, as opposed to
	// nothing has. A legitimate exclusion is still expected to expire.
	Legitimate bool
	// CoveredBy names a check that does exercise the method, when one does.
	// Without it a reader counts a named exclusion as no coverage at all, which
	// is the reading error this whole table exists to prevent.
	//
	// The claim is bound in two places, because one of them alone was read as
	// more than it was. TestEveryCoveredByClaimIsBoundToACall resolves the name
	// to the registered function and requires its source to mention a call to the
	// method -- that is SYNTAX, and an identifier in a position that never runs
	// satisfies it. Whether the call actually executes is a separate, behavioural
	// test per claim. Neither binds what the call asserts.
	CoveredBy string
}

// undrivenPortMethods names the port methods the suite's method-level
// enumeration does not drive, keyed by interface name and then method name.
//
// Everything here is a method a provider implements and this enumeration never
// calls, so a mapping mistake in it reaches production uncaught. Naming one is
// not the same as covering it. TestEveryPortMethodIsDrivenOrNamed fails if the
// list drifts in either direction, including a stale entry left behind by a
// rename, and TestEveryExportedInterfaceIsClassified fails if a port exists that
// this table has never heard of — which is how twelve methods were missing from
// it until the USOSS-39 audit.
func undrivenPortMethods() map[string]map[string]exclusion {
	return map[string]map[string]exclusion{
		"SecretStore": {
			"Get": {
				Reason: "the transient gate now asks Describe whether a secret exists, because " +
					"establishing liveness with the operation that returns the material was a " +
					"suite reading secret values for a question that is not about them. Get is " +
					"exercised by the secret port's Observed, which compares values without " +
					"printing them, so every port/secret lifecycle check drives it -- but not " +
					"under an induced failure, so its error mapping is unverified.",
				Expires: "a lifecycle check driving Get under injected failure, or Get losing its " +
					"last caller",
				// NOT "get", which every port/secret check name contains a
				// dozen ways and which would retire this entry on a check that
				// drives Get exactly as the ones that already do -- without an
				// induced failure, which is the half that is missing. The other
				// event Expires names, Get losing its last caller, retires this
				// entry through the driven-or-named audit instead: a method no
				// port drives is not in that table's population at all.
				RetiredWhen: "get-under-an-induced-failure",
				// The primary drivers are the port/secret lifecycle checks, whose
				// Observed calls Get -- but their names are computed ("port/" +
				// pt.Name + "/...") and their Fn a call expression, so no claim
				// naming them can be bound: the AST binding needs a literal
				// registration, and an exemption would be a lie because those
				// checks EXIST. The claim therefore names the literally-registered
				// check that also genuinely drives Get (three times: twice asserting
				// the deleted scope is gone, once asserting the neighbour survived).
				CoveredBy: "port/secret/delete-scope-removes-the-scope-and-nothing-else",
			},
			// "Error mapping" was doing two jobs in this entry, and only one of
			// them is missing. USOSS-26's checks assert ErrInvalidSpec on
			// DeleteScope("") — a caller-bug mapping, and the one that matters
			// most on this method, since an empty scope read as "everything"
			// deletes a deployment's credentials. What no conformance check drives
			// is DeleteScope under an induced *substrate* failure, which is what
			// Reason below is about.
			//
			// The tense mattered less than the ambiguity it created. Written as
			// "growing an error-mapping case", the expiry condition was already
			// met by a check that exists and not met by the one this exclusion is
			// about, so an auditor could conclude either from the same two
			// sentences. **An ambiguous expiry condition has no truth value**: it
			// can never retire and can never be shown not to have retired, which
			// is worse than a stale one, because a stale one at least resolves.
			// Reported by USOSS-26, who verified the claim about their own checks
			// and left the sentence to its owner.
			"DeleteScope": {
				Reason: "deleting a scope removes every secret in it, including the fixtures the " +
					"rest of the run depends on. Driving it under an induced failure needs a scope " +
					"of its own, which is a fixture change rather than a check change.",
				Expires: "a per-check secret scope, or USOSS-26's lifecycle checks growing an " +
					"induced-failure case",
				// NOT "delete-scope", which is the fragment PR #35's exemption
				// uses for its own subject and the wrong one for this entry.
				// USOSS-26's two checks both contain "delete-scope" and neither
				// drives the method under an induced failure, so that fragment
				// would retire this exclusion on the wrong event -- the same
				// error this entry was corrected for in the first place, where
				// "error mapping" covered a driven caller-bug mapping and an
				// undriven substrate-failure one. One word, two questions.
				RetiredWhen: "delete-scope-under-an-induced-failure",
				CoveredBy: "port/secret/delete-scope-* (USOSS-26, PR #19, merged) exercises its " +
					"behaviour and its empty-scope refusal; no conformance check drives it under " +
					"an induced substrate failure",
			},
		},
		// --- ports reached by a lookup helper rather than a Provider accessor.
		//
		// These twelve methods were outside the population this table was
		// checked against until the USOSS-39 audit, so they were neither driven
		// nor named and nothing said so. That was the same defect USOSS-32
		// closed, in the machinery USOSS-32 shipped: a derivation whose
		// population is narrower than the claim made over it. Non-emptiness
		// proves a derivation found something, never that it looked everywhere.
		"TableBucketProvisioner": {
			// PR #20 (USOSS-13, commit 77aa0f6, "AWS object storage on S3, with IAM
			// grants and the ext bucket ports (#20)") merged, which was this entry's
			// own stated Expires condition ("PR #20 merging"). USOSS-44 is that expiry
			// coming due: compute/aws has implemented all four of these methods since
			// before this comment did, and the ticket's job was to drive them, not to
			// take the merge as done and re-excuse the gap under a new reason.
			//
			// Legitimate is FALSE. Something can drive these now -- and does, in
			// checks_ext.go -- so "nothing can drive this" would be false the same way
			// USOSS-37 found it false for ExternalAccessGranter's GrantExternal. What
			// keeps the four methods named here rather than deleted is a different
			// fact: this port is reached through ext.TableBuckets, a lookup helper,
			// not a compute.Provider accessor, so ports() and the transient gate that
			// walks it structurally cannot see these methods at all --
			// TestEveryPortMethodIsDrivenOrNamed requires every interface method to be
			// either driven by that gate or named here, and this one never will be
			// the first without ports() growing a lookup-helper-reached entry, which
			// is a larger change than this ticket's scope.
			//
			// RetiredWhen is deliberately narrower than the coarse "ensure-table-bucket"
			// this entry used to carry before PR #20 landed: a fragment that broad
			// would have matched the very checks added to close this gap and asked a
			// reader to delete an entry that TestEveryPortMethodIsDrivenOrNamed still
			// requires -- the same one-word ambiguity DeleteScope's "error mapping" was
			// corrected for. "-under-an-induced-failure" names the one thing still
			// missing: checkExtBucketLifecycle and checkExtBucketGrant exercise the
			// happy path, not the substrate-error-mapping the transient gate checks
			// for a Provider-accessor-reached method.
			"EnsureTableBucket": {
				Reason: "reached through ext.TableBuckets rather than a compute.Provider accessor, " +
					"so the transient gate's structural walk of ports() cannot drive it regardless " +
					"of implementation status. compute/aws implements it (PR #20, merged); " +
					"checkExtBucketLifecycle (USOSS-44) drives the happy path positively.",
				Expires: "ports() gaining a lookup-helper-reached entry for ext.TableBucketProvisioner, " +
					"so the transient gate can drive this under an induced substrate failure",
				Legitimate:  false,
				CoveredBy:   "ext/table-bucket/ensure-table-bucket-and-delete-table-bucket-round-trip",
				RetiredWhen: "ensure-table-bucket-under-an-induced-failure",
			},
			"DeleteTableBucket": {
				Reason:      "as EnsureTableBucket: reached through a lookup helper, implemented, and driven positively by checkExtBucketLifecycle (USOSS-44).",
				Expires:     "as EnsureTableBucket",
				Legitimate:  false,
				CoveredBy:   "ext/table-bucket/ensure-table-bucket-and-delete-table-bucket-round-trip",
				RetiredWhen: "delete-table-bucket-under-an-induced-failure",
			},
			"Grant": {
				Reason: "as EnsureTableBucket: reached through a lookup helper. Mirrors compute.Granter " +
					"exactly, and compute/aws inherits its general-purpose Grant for this port rather " +
					"than reimplementing it. checkExtBucketGrant (USOSS-44) drives idempotence and " +
					"revoke-of-absent; it does not assert that a grant authorises access, since no " +
					"Options hook performs a data-plane read or write through this port.",
				Expires:     "as EnsureTableBucket",
				Legitimate:  false,
				CoveredBy:   "ext/table-bucket/table-bucket-grant-then-table-bucket-revoke",
				RetiredWhen: "table-bucket-grant-under-an-induced-failure",
			},
			"Revoke": {
				Reason:      "as Grant.",
				Expires:     "as EnsureTableBucket",
				Legitimate:  false,
				CoveredBy:   "ext/table-bucket/table-bucket-grant-then-table-bucket-revoke",
				RetiredWhen: "table-bucket-revoke-under-an-induced-failure",
			},
			"DescribeGrant": {
				// Legitimate is FALSE, and getting that right matters more than the
				// prose: Legitimate means *nothing can drive this*, and something
				// does. The first draft of this entry said true, written against
				// the tree one commit before USOSS-44 gave these ports a positive
				// check to be driven by -- which is exactly the state the
				// ExternalAccessGranter comment below warns about, where the
				// sentence gets fixed and the field is left standing.
				Reason: "as this port's Grant and Revoke: reached through a lookup helper, so the " +
					"transient gate's structural walk of ports() cannot drive it. Added by " +
					"USOSS-73; it mirrors compute.Granter.DescribeGrant exactly, and compute/aws " +
					"serves all three of its bucket ports with one implementation. " +
					"checkTableBucketGrant (USOSS-44) drives it positively -- and it is what makes that " +
					"check able to assert that a Revoke removed something, which without a " +
					"read-back needed a data-plane hook this port has on no provider.",
				Expires:     "as this port's Grant",
				Legitimate:  false,
				CoveredBy:   "ext/table-bucket/table-bucket-grant-then-table-bucket-revoke",
				RetiredWhen: "table-bucket-describe-grant-under-an-induced-failure",
			},
		},
		"ExternalAccessGranter": {
			// USOSS-37 was this entry's stated expiry and it arrived, so both the
			// reason and the classification are rewritten rather than left
			// standing. It said "no provider implements this port"; compute/fake
			// does, with a compile-time assertion and driving both methods.
			//
			// Legitimate is FALSE, and that correction matters more than the
			// prose one. Legitimate means *nothing can drive this*; something
			// can. The first pass fixed the sentence and left the field true,
			// which is the worse state of the two: tools read the field and
			// humans read the sentence, so a structured classification
			// contradicting its own prose gives two audiences different answers
			// and shows neither a conflict.
			//
			// CoveredBy names the check that calls both methods -- and "calls" is
			// established by running it against a granter that records every
			// call, not by finding the method's name in its source. The source
			// search came first and was read as proof of execution; replacing
			// both revokes with an uninvoked closure kept it green. The
			// behavioural test is TestEveryCoveredByClaimIsBoundToAnExecutedCall.
			//
			// What that check could not assert was the no-mutation half of the
			// contract -- observing whether a refused call changed stored state
			// needed a read-back the compute interface did not offer for an
			// external grant, so compute/fake asserted it against its own private
			// store and the obligation entry below enumerated seven numbered gaps.
			//
			// USOSS-73 added ext.ExternalAccessGranter.ExternalGrants and the
			// check drives it, so six of those seven are portable assertions now
			// and the entry below records the residue instead of the list. The
			// warning it replaced is narrower and still worth making: the check
			// establishes that a grant is RECORDED as asked, not that it
			// authorises anybody.
			"GrantExternal": {
				Reason: "the method-level transient enumeration does not drive it: no production " +
					"provider implements the port, by decision (USOSS-37 keeps the seam without " +
					"one), so there is usually nothing behind it to fail. compute/fake does " +
					"implement it, which is why this is not legitimate.",
				Expires:     "the method-level enumeration driving it, which becomes worthwhile when a production provider implements the port",
				Legitimate:  false,
				CoveredBy:   "grants/bucket/an-external-grant-is-constrained-and-reads-back",
				RetiredWhen: "grant-external",
			},
			"RevokeExternal": {
				Reason: "as GrantExternal: drivable against compute/fake, not driven by the " +
					"method-level transient enumeration.",
				Expires:     "as GrantExternal",
				Legitimate:  false,
				CoveredBy:   "grants/bucket/an-external-grant-is-constrained-and-reads-back",
				RetiredWhen: "revoke-external",
			},
			"ExternalGrants": {
				Reason: "as GrantExternal, and for the same structural reason: the method-level " +
					"transient enumeration reaches ports through compute.Provider and an ext port " +
					"is reached by a lookup helper instead. USOSS-73 added it, and the check that " +
					"drives the other two drives this one on every assertion it makes -- because " +
					"every assertion it makes is a read-back.",
				Expires:     "as GrantExternal",
				Legitimate:  false,
				CoveredBy:   "grants/bucket/an-external-grant-is-constrained-and-reads-back",
				RetiredWhen: "external-grants",
			},
		},
		// VectorBucketProvisioner is TableBucketProvisioner's shape exactly --
		// EnsureVectorBucket/DeleteVectorBucket instead of the table forms, Grant
		// and Revoke identical -- and PR #20 implemented and merged both ports in
		// the same commit, so every word of TableBucketProvisioner's entry above
		// applies here unchanged; only the method and check names differ.
		"VectorBucketProvisioner": {
			"EnsureVectorBucket": {
				Reason: "reached through ext.VectorBuckets rather than a compute.Provider accessor, " +
					"so the transient gate's structural walk of ports() cannot drive it regardless " +
					"of implementation status. compute/aws implements it (PR #20, merged); " +
					"checkExtBucketLifecycle (USOSS-44) drives the happy path positively.",
				Expires: "ports() gaining a lookup-helper-reached entry for ext.VectorBucketProvisioner, " +
					"so the transient gate can drive this under an induced substrate failure",
				Legitimate:  false,
				CoveredBy:   "ext/vector-bucket/ensure-vector-bucket-and-delete-vector-bucket-round-trip",
				RetiredWhen: "ensure-vector-bucket-under-an-induced-failure",
			},
			"DeleteVectorBucket": {
				Reason:      "as EnsureVectorBucket: reached through a lookup helper, implemented, and driven positively by checkExtBucketLifecycle (USOSS-44).",
				Expires:     "as EnsureVectorBucket",
				Legitimate:  false,
				CoveredBy:   "ext/vector-bucket/ensure-vector-bucket-and-delete-vector-bucket-round-trip",
				RetiredWhen: "delete-vector-bucket-under-an-induced-failure",
			},
			"Grant": {
				Reason: "as EnsureVectorBucket: reached through a lookup helper. Mirrors compute.Granter " +
					"exactly, as TableBucketProvisioner.Grant does, and compute/aws inherits its " +
					"general-purpose Grant for this port too. checkExtBucketGrant (USOSS-44) drives " +
					"idempotence and revoke-of-absent; it does not assert that a grant authorises " +
					"access, since no Options hook performs a data-plane read or write through this port.",
				Expires:     "as EnsureVectorBucket",
				Legitimate:  false,
				CoveredBy:   "ext/vector-bucket/vector-bucket-grant-then-vector-bucket-revoke",
				RetiredWhen: "vector-bucket-grant-under-an-induced-failure",
			},
			"Revoke": {
				Reason:      "as Grant.",
				Expires:     "as EnsureVectorBucket",
				Legitimate:  false,
				CoveredBy:   "ext/vector-bucket/vector-bucket-grant-then-vector-bucket-revoke",
				RetiredWhen: "vector-bucket-revoke-under-an-induced-failure",
			},
			"DescribeGrant": {
				// Legitimate is FALSE, and getting that right matters more than the
				// prose: Legitimate means *nothing can drive this*, and something
				// does. The first draft of this entry said true, written against
				// the tree one commit before USOSS-44 gave these ports a positive
				// check to be driven by -- which is exactly the state the
				// ExternalAccessGranter comment below warns about, where the
				// sentence gets fixed and the field is left standing.
				Reason: "as this port's Grant and Revoke: reached through a lookup helper, so the " +
					"transient gate's structural walk of ports() cannot drive it. Added by " +
					"USOSS-73; it mirrors compute.Granter.DescribeGrant exactly, and compute/aws " +
					"serves all three of its bucket ports with one implementation. " +
					"checkVectorBucketGrant (USOSS-44) drives it positively -- and it is what makes that " +
					"check able to assert that a Revoke removed something, which without a " +
					"read-back needed a data-plane hook this port has on no provider.",
				Expires:     "as this port's Grant",
				Legitimate:  false,
				CoveredBy:   "ext/vector-bucket/vector-bucket-grant-then-vector-bucket-revoke",
				RetiredWhen: "vector-bucket-describe-grant-under-an-induced-failure",
			},
		},
	}
}

// obligation is a documented requirement in [compute] that this suite does not
// check, with what checking it would need.
//
// It exists because a claim of coverage that has none is worse than an
// acknowledged gap. USOSS-39 said it drove four credential-egress channels; it
// drove three, and `rg BuildArgs compute/conformance compute/fake compute/k8s`
// returned nothing — no planting, no read-back hook, no provider storage, no
// defect. The fourth was a claim with no observation behind it, which a reviewer
// found by searching rather than by reading. USOSS-49 built it —
// checkBuildCredentialsNotInImageMetadata drives the fourth channel, and
// checkBuildCacheDefaultIsBounded closed the sibling gap this same audit named
// for compute.BuildCache.MaxAge — so both entries this file used to carry for
// them are gone rather than left standing as a stale claim of a gap that closed.
//
// So an obligation the suite cannot see is recorded here rather than described in
// prose that drifts, and TestEveryUnverifiedObligationIsAccountedFor requires
// each entry to name what it would take and where it is tracked. This is not
// coverage. It is the opposite, written down where a reader of the suite meets
// it.
type obligation struct {
	// Where names the documented requirement, as an interface member.
	Where string
	// Requirement is the obligation, in the interface's own terms.
	Requirement string
	// Needs is what checking it would take — the missing observation.
	Needs string
	// TrackedBy names the ticket. Required: an unchecked obligation with nowhere
	// to be picked up is the same as an undocumented one.
	TrackedBy string
}

// unverifiedObligations are the documented requirements this suite does not
// check. Every one is a gap; none of them is covered by anything here.
func unverifiedObligations() []obligation {
	return []obligation{
		{
			Where: "ext.ExternalAccessGranter",
			Requirement: "a cross-domain grant AUTHORISES the external principal at the stated " +
				"level, and a revoked one stops authorising it",
			Needs: "a cross-account access performed as an external principal. Nothing in this " +
				"repository can do that: it needs a second trust domain, a real principal in it, " +
				"and a credential this platform does not hold. So what the suite establishes is " +
				"that the grant is RECORDED as asked -- which USOSS-73's read-back made portable, " +
				"and which is a real floor rather than a consolation, since a GrantExternal that " +
				"did nothing and a RevokeExternal that removed nothing both conformed before it -- " +
				"and not that the record has any effect. That is the same division as the core " +
				"grant ports, where Options.Read and Options.Write supply the enforcement half " +
				"compute.Granter.DescribeGrant cannot reach; there is no equivalent hook here, and " +
				"a provider supplying one would be supplying a cross-account integration test. " +
				"Six of the seven properties this entry used to enumerate are now checked by " +
				"grants/bucket/an-external-grant-is-constrained-and-reads-back: stored existence, " +
				"removal on revoke, replacement rather than accumulation of a repeated grant, " +
				"preservation of every constraint through creation AND replacement, " +
				"last-write-wins on level, and no mutation from a refused call. The seventh, " +
				"ErrNotOwned on a grant this platform did not create, is observable through " +
				"ext.ExternalGrant.Managed but is not driven HERE: planting a foreign grant needs " +
				"a provider-specific hook, and a suite that required one would be requiring every " +
				"provider to be able to forge a stranger's trust statement. compute/fake drives it " +
				"against its own harness (CreateUnownedExternalGrant), which is not portable and " +
				"is not this suite -- the same boundary the entry above this one describes",
			TrackedBy: "USOSS-37 decision entry",
		},
		{
			Where:       "compute.ImagePullGranter",
			Requirement: "GrantPull authorises identity to pull from repository",
			Needs: "a hook that performs a pull as a workload identity, the way Options.Read " +
				"and Options.Write do for the core grant ports. Without one, a provider whose " +
				"GrantPull and RevokePull both return nil and do nothing satisfies every " +
				"pull-grant check: they establish the calls are shaped as documented and " +
				"nothing about the authorisation behind them",
			TrackedBy: "USOSS-39 report, section 10",
		},
		{
			Where: "ext.TableBucketProvisioner.Grant",
			Requirement: "Grant gives identity resource the stated access level, mirroring " +
				"compute.Granter; Revoke removes it",
			Needs: "a hook that performs a data-plane read or write against a table bucket as a " +
				"workload identity, the way Options.Read and Options.Write do for the core bucket " +
				"and key-value ports. compute/aws inherits its general-purpose Grant/Revoke for " +
				"this port (ext.go), so the core " +
				"grants/bucket/access-level-decides-what-succeeds check exercises the same code " +
				"path through the ordinary bucket port -- which is evidence about the " +
				"implementation, not coverage of this port's own contract, since a suite change to " +
				"the ordinary path could regress this one silently. " +
				"NARROWED by USOSS-73: this entry used to say that \"a provider whose Grant and " +
				"Revoke both return nil and do nothing would satisfy\" checkTableBucketGrant. " +
				"That is no longer true. DescribeGrant on this port needs no Options hook, so the " +
				"check now asserts that the level granted is the level standing and that a Revoke " +
				"removed it. What remains unverified is strictly the authorisation half -- that " +
				"the recorded grant has any effect on what the external caller can reach -- which " +
				"is the same residue the core ports carry when their data-plane hooks are absent",
			TrackedBy: "USOSS-44",
		},
		{
			Where:       "ext.VectorBucketProvisioner.Grant",
			Requirement: "as ext.TableBucketProvisioner.Grant",
			Needs:       "as ext.TableBucketProvisioner.Grant, for checkVectorBucketGrant (USOSS-44)",
			TrackedBy:   "USOSS-44",
		},
	}
}

// notPorts names the exported interfaces in compute and compute/ext that are not
// ports, with the reason.
//
// It exists so that "every exported interface is a port the suite accounts for"
// can be enforced without the enforcement quietly ignoring what it cannot
// classify. An interface that is neither driven, nor named as undriven, nor
// named here, fails the audit.
func notPorts() map[string]string {
	return map[string]string{
		"Provider": "vends the ports rather than being one. Its own accessors are checked by " +
			"provider/capability-accessor-agreement and provider/refusals-are-typed-and-named.",
		"Granter": "a shape embedded by ObjectStore and KeyValueProvisioner rather than a port of " +
			"its own. Its Grant and Revoke are driven through both, and compute.WorkloadGrantPorts " +
			"is what pins which ports carry it.",
	}
}

// --- derivation of where secret material can enter -------------------------

var (
	secretValueType   = reflect.TypeOf(compute.SecretValue{})
	secretBindingType = reflect.TypeOf(compute.SecretBinding{})
)

// materialReach reports how secret material can reach a port through the
// methods that port drives: directly, as a [compute.SecretValue] somewhere
// inside an argument, and/or by reference, as a [compute.SecretBinding].
//
// It is scoped to the port's own methods rather than to the whole interface
// because two ports can share one. [compute.FunctionRuntime] carries a binding
// through EnsureFunction and nothing through EnsureEndpoint, so asking the
// interface would say both the function and the function-endpoint port can be
// handed material, and the endpoint port would then be expected to plant
// something it has no field for. A method no port drives is covered from the
// other side, by undrivenPortMethods and the test that pins it.
//
// Only arguments are walked. A [compute.SecretValue] coming *out* of a port is
// material leaving apphub for its own use — [compute.SecretStore.Get] is the
// one place that is legitimate — and says nothing about whether that port can be
// handed material to render.
//
// It returns an error rather than a false negative for anything it cannot walk.
// A recogniser that shrugs at an input it does not understand turns that input
// into one nothing checks, which is the shape three of this project's gates were
// defeated by; here it would silently declare a material-carrying port
// materialless and put the check back where it started.
func materialReach(pt Port) (direct, byRef bool, err error) {
	if pt.Iface == nil {
		return false, false, fmt.Errorf("conformance: port %q names no Iface, so nothing can "+
			"derive what its methods carry", pt.Name)
	}
	for op, name := range pt.Methods {
		owner := opOwner(op, pt)
		m, ok := owner.MethodByName(name)
		if !ok {
			return false, false, fmt.Errorf("conformance: port %q maps %s onto %s.%s, which is "+
				"not a method of that interface", pt.Name, op, owner.Name(), name)
		}
		d, r, err := methodReach(m.Type)
		if err != nil {
			return false, false, fmt.Errorf("conformance: port %q, %s.%s: %w",
				pt.Name, owner.Name(), name, err)
		}
		direct = direct || d
		byRef = byRef || r
	}
	return direct, byRef, nil
}

// methodMaterialReach is materialReach for one named method of an interface. It
// exists so the coverage test can ask the same question about a method no port
// drives.
func methodMaterialReach(iface reflect.Type, name string) (direct, byRef bool, err error) {
	m, ok := iface.MethodByName(name)
	if !ok {
		return false, false, fmt.Errorf("conformance: %s has no method %q", iface.Name(), name)
	}
	return methodReach(m.Type)
}

// methodReach walks one method signature's arguments.
func methodReach(sig reflect.Type) (direct, byRef bool, err error) {
	for j := range sig.NumIn() {
		d, r, err := containsSecret(sig.In(j), map[reflect.Type]bool{})
		if err != nil {
			return false, false, err
		}
		direct = direct || d
		byRef = byRef || r
	}
	return direct, byRef, nil
}

// interfaceDecisions records what the walk does with each interface type that
// appears in a compute method argument, and why.
//
// Deciding them one at a time is the point. An interface is opaque to a
// structural walk, so treating an unrecognised one as "carries nothing" would be
// the tolerant input path this whole file exists to remove: the walk would report
// a material-carrying port as materialless and the check would go back to
// scanning for a sentinel nobody planted. Anything not named here is fatal, so a
// new interface argument in compute fails the derivation rather than quietly
// widening it. There is no list of interfaces to keep in sync — the walk finds
// them, and this is where each one's decision is written down.
func interfaceDecisions() map[reflect.Type]string {
	return map[reflect.Type]string{
		// A context carries cancellation and deadlines. Nothing in compute puts
		// a spec in one, and a Value-carried secret would be a defect the type
		// system cannot express an opinion about.
		reflect.TypeOf((*context.Context)(nil)).Elem(): "a context carries no spec",

		// compute.BuildRequest.Logs. A caller-supplied sink is an egress channel,
		// not a way to hand the provider material: nothing the suite could plant
		// into it would reach the provider.
		//
		// It is worth being explicit that this is a decision about *ingress*
		// only. A build log is exactly where the source system leaks a
		// credential — kaniko shares a PID namespace with the commands it runs,
		// so repository-authored code can print the executor's ECR push token,
		// and compute.ImageBuilder carries a documented obligation not to put
		// builder output in an error because of it. Nothing in this suite
		// observes what a provider writes to this writer: ImageBuilder.Build is
		// not driven at all (see undrivenPortMethods), so the obligation is
		// unchecked. That is a gap, and it is a bigger one than this file
		// closes.
		reflect.TypeOf((*io.Writer)(nil)).Elem(): "a caller-supplied sink is egress, not ingress",
	}
}

// containsSecret walks a type for the two secret-carrying types.
//
// Every kind is handled explicitly and anything else is an error. The scalar
// kinds are a decision rather than a shrug — a string cannot contain a struct —
// and an interface other than a context is a hole the walk genuinely cannot see
// through, so it says so instead of returning "no secrets here". The visited set
// is what makes a self-referential spec terminate.
func containsSecret(t reflect.Type, visited map[reflect.Type]bool) (direct, byRef bool, err error) {
	if t == nil {
		return false, false, errors.New("nil type in a method signature")
	}
	if visited[t] {
		return false, false, nil
	}
	visited[t] = true
	switch t {
	case secretValueType:
		return true, false, nil
	case secretBindingType:
		return false, true, nil
	}
	if _, decided := interfaceDecisions()[t]; decided {
		return false, false, nil
	}

	recur := func(types ...reflect.Type) (bool, bool, error) {
		var d, r bool
		for _, sub := range types {
			sd, sr, err := containsSecret(sub, visited)
			if err != nil {
				return false, false, err
			}
			d = d || sd
			r = r || sr
		}
		return d, r, nil
	}

	switch t.Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
		reflect.String:
		// A scalar cannot contain a struct. Nothing to walk.
		return false, false, nil
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return recur(t.Elem())
	case reflect.Map:
		return recur(t.Key(), t.Elem())
	case reflect.Struct:
		fields := make([]reflect.Type, 0, t.NumField())
		for i := range t.NumField() {
			fields = append(fields, t.Field(i).Type)
		}
		return recur(fields...)
	case reflect.Func:
		// A callback — compute.WaitOptions.OnUpdate is the only one. Material
		// crossing the boundary in either direction would count, so both halves
		// are walked rather than assumed empty.
		sides := make([]reflect.Type, 0, t.NumIn()+t.NumOut())
		for i := range t.NumIn() {
			sides = append(sides, t.In(i))
		}
		for i := range t.NumOut() {
			sides = append(sides, t.Out(i))
		}
		return recur(sides...)
	default:
		// An interface with no entry in interfaceDecisions, a channel, an unsafe
		// pointer. The walk cannot see through it, so it refuses rather than
		// reporting the absence of something it never looked for.
		return false, false, fmt.Errorf("cannot walk %s (kind %s) for secret material; a type "+
			"this derivation cannot see through would be reported as carrying none",
			t.String(), t.Kind())
	}
}

// unplantedMaterialPorts names ports whose interface can carry secret material
// and whose spec *in this suite* does not, with the reason.
//
// This is the honest half of the derivation. The interface says a scheduled job
// and a function can both bind a secret; the specs the suite drives for them do
// not, so planting material there would change what a dozen unrelated
// convergence checks assert. Recording it means the gap is visible instead of
// looking like coverage, which is the whole defect this file exists to close.
func unplantedMaterialPorts() map[string]string {
	return map[string]string{
		"scheduled-job": "Env.ScheduledJobSpec binds no secret, so planting material through " +
			"this port would mean changing the spec every other scheduled-job check asserts on. " +
			"compute.ScheduledJobSpec.Secrets can carry one: worth a ticket.",
		"function": "Env.FunctionSpec binds no secret, for the same reason. " +
			"compute.FunctionSpec.Secrets can carry one: worth a ticket.",
	}
}

// materialPorts returns the available ports this suite can hand secret material
// to, derived from the port interfaces rather than from a capability condition.
//
// A port that carries material by reference needs a secret store to make a
// reference with: without one there is no material in play, and pretending
// otherwise is how the rendered-artefact check came to search for a sentinel
// nobody had planted.
func materialPorts(e *Env) ([]Port, error) {
	caps := e.Provider.Capabilities()
	hasStore := caps.Has(compute.CapSecretStore)
	unplanted := unplantedMaterialPorts()
	var out []Port
	for _, pt := range availablePorts(e) {
		if !pt.PlantsSecretMaterial {
			continue
		}
		if _, skipped := unplanted[pt.Name]; skipped {
			continue
		}
		direct, byRef, err := materialReach(pt)
		if err != nil {
			return nil, err
		}
		switch {
		case direct:
			out = append(out, pt)
		case byRef && hasStore:
			out = append(out, pt)
		}
	}
	return out, nil
}
