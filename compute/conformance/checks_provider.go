// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// foreignProvider is the provider name the suite claims when it hands a provider
// a reference it did not issue.
const foreignProvider = "conformance-other-provider"

// fail reports a violation in a form the six implementations that follow can act
// on: it names the port, quotes the invariant, and then says what happened.
func fail(tb TB, port, invariant, format string, args ...any) {
	tb.Helper()
	tb.Errorf("conformance: [%s] violates %q: %s", port, invariant, fmt.Sprintf(format, args...))
}

// fatal is fail for a violation that makes the rest of the check meaningless.
func fatal(tb TB, port, invariant, format string, args ...any) {
	tb.Helper()
	tb.Fatalf("conformance: [%s] violates %q: %s", port, invariant, fmt.Sprintf(format, args...))
}

// accessor pairs a capability with the [compute.Provider] method that vends its
// port, for the capability/accessor agreement invariant.
//
// Not every capability has an accessor: scheduled jobs, function endpoints,
// zonal buckets, workload exec, and model inference are gated on a spec field or
// a method of an already-acquired port rather than on their own accessor. Those
// are covered by the capability-negative checks instead, and the split is stated
// here so a reader can see that neither set is claiming to cover the other.
type accessor struct {
	capability compute.Capability
	name       string
	get        func(p compute.Provider) (any, error)
}

func accessors() []accessor {
	return []accessor{
		{compute.CapImageRegistry, "Registry", func(p compute.Provider) (any, error) { return p.Registry() }},
		{compute.CapImageBuild, "Builder", func(p compute.Provider) (any, error) { return p.Builder() }},
		{compute.CapContainerService, "Containers", func(p compute.Provider) (any, error) { return p.Containers() }},
		{compute.CapFunction, "Functions", func(p compute.Provider) (any, error) { return p.Functions() }},
		{compute.CapObjectStore, "ObjectStores", func(p compute.Provider) (any, error) { return p.ObjectStores() }},
		{compute.CapRelationalDatabase, "Relational", func(p compute.Provider) (any, error) { return p.Relational() }},
		{compute.CapKeyValueTable, "KeyValues", func(p compute.Provider) (any, error) { return p.KeyValues() }},
		{compute.CapSecretStore, "Secrets", func(p compute.Provider) (any, error) { return p.Secrets() }},
	}
}

func providerChecks(e *Env) []Check {
	checks := []Check{
		{
			Name:      "provider/name-is-non-empty-and-stable",
			Invariant: "Name() is stable and non-empty",
			Fn: func(tb TB, e *Env) {
				name := e.Provider.Name()
				if name == "" {
					fatal(tb, "provider", "Name() is stable and non-empty",
						"Name() returned the empty string; every Ref this provider issues records "+
							"it, and a Ref persisted last year is compared against it")
				}
				if again := e.Provider.Name(); again != name {
					fail(tb, "provider", "Name() is stable and non-empty",
						"two calls returned %q then %q", name, again)
				}
				other := e.Factory(tb)
				if other.Name() != name {
					fail(tb, "provider", "Name() is stable and non-empty",
						"a second instance over the same substrate reported %q where the first "+
							"reported %q; a Ref issued by one would be foreign to the other",
						other.Name(), name)
				}
			},
		},
		{
			Name:      "provider/identities-are-always-available",
			Invariant: "every provider can give what it runs an identity",
			Fn: func(tb TB, e *Env) {
				if e.Provider.Identities() == nil {
					fail(tb, "workload-identity", "every provider can give what it runs an identity",
						"Identities() returned nil; workload identity is not capability-gated, "+
							"because a workload with no identity cannot be granted access to anything")
				}
			},
		},
		{
			Name:      "provider/capability-accessor-agreement",
			Invariant: "Capabilities().Has(c) if and only if c's accessor returns a nil error",
			Fn: func(tb TB, e *Env) {
				const inv = "Capabilities().Has(c) if and only if c's accessor returns a nil error"
				caps := e.Provider.Capabilities()
				for _, a := range accessors() {
					port, err := a.get(e.Provider)
					has := caps.Has(a.capability)
					switch {
					case has && err != nil:
						fail(tb, a.name, inv,
							"the provider advertises %q but %s() refused with %v; a provider whose "+
								"advertised capabilities disagree with what its accessors hand out is "+
								"lying about itself, and no other test catches it",
							a.capability, a.name, err)
					case has && port == nil:
						fail(tb, a.name, inv,
							"the provider advertises %q and %s() returned no error, but the port is "+
								"nil; the first caller to forget a nil check gets a panic instead of a "+
								"diagnosis", a.capability, a.name)
					case !has && err == nil:
						fail(tb, a.name, inv,
							"the provider does not advertise %q but %s() handed out a port anyway; "+
								"its capability set is not describing what it does (advertised: %v)",
							a.capability, a.name, sortedCaps(caps))
					}
				}
			},
		},
		{
			Name:      "provider/a-retryable-failure-is-ErrTransient",
			Invariant: "a substrate failure that would succeed on retry surfaces as ErrTransient, not ErrFailed",
			Fn:        checkTransientIsNotTerminal,
		},
		{
			Name:      "provider/an-authorization-failure-is-ErrNotPermitted",
			Invariant: "a substrate authorization failure surfaces as ErrNotPermitted, not as ErrFailed or ErrInvalidSpec",
			Fn:        checkDenialIsNotAResourceFailure,
		},
		{
			Name:      "provider/refusals-are-typed-and-named",
			Invariant: "a refusal wraps ErrUnsupported and names the provider and the capability",
			Fn: func(tb TB, e *Env) {
				const inv = "a refusal wraps ErrUnsupported and names the provider and the capability"
				caps := e.Provider.Capabilities()
				refused := 0
				for _, a := range accessors() {
					if caps.Has(a.capability) {
						continue
					}
					refused++
					_, err := a.get(e.Provider)
					if err == nil {
						continue // reported by the agreement check
					}
					if !errors.Is(err, compute.ErrUnsupported) {
						fail(tb, a.name, inv,
							"%s() refused with %v, which does not match compute.ErrUnsupported; a "+
								"caller that already branches on the sentinel silently misses this and "+
								"may retry a refusal that can never succeed", a.name, err)
					}
					var typed *compute.UnsupportedError
					if !errors.As(err, &typed) {
						tb.Logf("conformance: [%s] %s() refused with %v, which is not a "+
							"*compute.UnsupportedError; that is permitted, but compute.Unsupported() "+
							"exists so the refusal is uniform across implementations", a.name, a.name, err)
					}
					msg := err.Error()
					if !strings.Contains(msg, e.Provider.Name()) || !strings.Contains(msg, string(a.capability)) {
						fail(tb, a.name, inv,
							"the refusal %q names neither the provider %q nor the capability %q; an "+
								"operator reading it cannot tell which of the two to change",
							msg, e.Provider.Name(), a.capability)
					}
				}
				if refused == 0 {
					// Not a failure: a provider may legitimately have everything.
					// Worth saying, because it means this run proved nothing about
					// refusal and some other configuration has to.
					tb.Logf("conformance: provider %q advertises every accessor-gated capability, "+
						"so no refusal was exercised here; run the suite against a provider "+
						"configured with a subset to cover it", e.Provider.Name())
				}
			},
		},
	}

	for _, pt := range availablePorts(e) {
		pt := pt
		checks = append(checks, Check{
			Name:      "port/" + pt.Name + "/refs-carry-the-provider-and-kind",
			Port:      pt.Name,
			Class:     pt.Class,
			Invariant: "every Ref the provider issues carries its name and the resource's kind",
			Fn: withPort(pt, func(tb TB, e *Env, o *portOps) {
				const inv = "every Ref the provider issues carries its name and the resource's kind"
				ref, _, err := o.Ensure(e.Name(pt.Name), Base)
				if err != nil {
					fatal(tb, pt.Name, inv, "Ensure failed: %v", err)
				}
				if ref.Provider != e.Provider.Name() {
					fail(tb, pt.Name, inv, "Ref.Provider is %q, want %q; a provider handed this Ref "+
						"back could not tell it was its own", ref.Provider, e.Provider.Name())
				}
				if ref.Kind != pt.Kind {
					fail(tb, pt.Name, inv, "Ref.Kind is %q, want %q; a wiring mistake would reach a "+
						"method as a confusing provider-side failure instead of an error",
						ref.Kind, pt.Kind)
				}
				if ref.ID == "" {
					fail(tb, pt.Name, inv, "Ref.ID is empty, so the Ref addresses nothing")
				}
				if ref.IsZero() {
					fail(tb, pt.Name, inv, "the Ref reports IsZero, which means 'never provisioned'")
				}
				// A Ref is what a caller persists, so it has to survive the round
				// trip through storage that String and ParseRef exist for.
				parsed, err := compute.ParseRef(ref.String())
				if err != nil || parsed != ref {
					fail(tb, pt.Name, inv, "the Ref did not survive a String/ParseRef round trip "+
						"(%q -> %#v, err=%v); a caller cannot persist it", ref.String(), parsed, err)
				}
			}),
		})

		checks = append(checks, Check{
			Name:      "port/" + pt.Name + "/foreign-refs-are-refused",
			Port:      pt.Name,
			Class:     pt.Class,
			Invariant: "a Ref issued by another provider is ErrForeignRef, never ErrNotFound",
			Fn: withPort(pt, func(tb TB, e *Env, o *portOps) {
				const inv = "a Ref issued by another provider is ErrForeignRef, never ErrNotFound"
				foreign := compute.Ref{Provider: foreignProvider, Kind: pt.Kind, ID: "some-other-substrate-id"}

				check := func(method string, err error) {
					if err == nil {
						fail(tb, pt.Name, inv, "%s accepted a Ref issued by %q; a platform "+
							"reconfigured from one substrate to another would hand this provider "+
							"another one's identifiers and get an unpredictable failure at an "+
							"unpredictable depth", method, foreignProvider)
						return
					}
					if errors.Is(err, compute.ErrNotFound) {
						fail(tb, pt.Name, inv, "%s reported a foreign Ref as ErrNotFound (%v); a "+
							"caller would conclude the resource had been deleted and move on to "+
							"recreate it somewhere it does not belong", method, err)
					}
					if !errors.Is(err, compute.ErrForeignRef) {
						fail(tb, pt.Name, inv, "%s refused a foreign Ref with %v, which does not "+
							"match compute.ErrForeignRef", method, err)
					}
				}

				if o.Describe != nil {
					_, err := o.Describe(foreign)
					check("Describe", err)
				}
				if o.Wait != nil {
					_, err := o.Wait(foreign, compute.WaitOptions{Timeout: e.Options.WaitTimeout})
					check("Wait", err)
				}
				check("Delete", o.Delete(foreign))
			}),
		})

		checks = append(checks, Check{
			Name:      "port/" + pt.Name + "/wrong-kind-refs-are-refused",
			Port:      pt.Name,
			Class:     pt.Class,
			Invariant: "a Ref of the wrong Kind is refused rather than attempted",
			Fn: withPort(pt, func(tb TB, e *Env, o *portOps) {
				const inv = "a Ref of the wrong Kind is refused rather than attempted"
				wrong := compute.Ref{Provider: e.Provider.Name(), Kind: mismatchedKind(pt.Kind), ID: "whatever"}

				if o.Describe != nil {
					if _, err := o.Describe(wrong); err == nil {
						fail(tb, pt.Name, inv, "Describe accepted a %q Ref; the Kind field exists so "+
							"a Ref read back out of persistence can be checked against the method it "+
							"is about to be passed to", wrong.Kind)
					}
				}
				if err := o.Delete(wrong); err == nil {
					fail(tb, pt.Name, inv, "Delete accepted a %q Ref and reported success; Delete is "+
						"idempotent for its own kind, not for every kind", wrong.Kind)
				}
			}),
		})
	}

	return checks
}

// mismatchedKind returns a kind that is not the one given, so a check can hand a
// method the wrong sort of reference.
func mismatchedKind(k compute.Kind) compute.Kind {
	if k == compute.KindSecret {
		return compute.KindBucket
	}
	return compute.KindSecret
}

// withPort acquires a port and hands its operations to a check, failing clearly
// if a provider that advertises the capability cannot vend the port.
func withPort(pt Port, fn func(tb TB, e *Env, o *portOps)) func(TB, *Env) {
	return func(tb TB, e *Env) {
		tb.Helper()
		o, err := pt.ops(tb, e, e.Provider)
		if err != nil {
			fatal(tb, pt.Name, "an advertised capability's port can be acquired",
				"the provider advertises %q but the port could not be acquired: %v", pt.Capability, err)
		}
		fn(tb, e, o)
	}
}

// checkTransientIsNotTerminal is the gate [compute.ErrTransient] did not have.
//
// The sentinel existed and nothing checked that anybody used it. That was
// defensible when one provider existed and is not with six about to be written:
// each writes its own mapping from a substrate's errors onto this taxonomy, and
// the one that maps a throttle onto [compute.ErrFailed] tells its caller the
// spec must change when the deploy would have succeeded unchanged. A caller
// acting on that abandons a working deploy.
//
// The distinction is worth stating precisely, because the failure mode is a
// provider being *conservative* in the wrong direction: ErrFailed is the safe
// answer when you are unsure whether something is retryable, and it is exactly
// the answer that turns a transient outage into a failed deploy.
//
// USOSS-32 rewrote how the check chooses what to drive. It used to skip unless
// the provider advertised [compute.CapSecretStore] — "because a secret Put is
// the cheapest write on any provider" — and then drive that one Put. Two
// defects in one condition: it is a hand-maintained restatement of "what can I
// write with", so five of the six AWS ports got no coverage at all; and a
// single call cannot see a per-service mapping, so a provider that reached
// ErrTransient from its registry and ErrFailed from its identity service
// passed. It now drives every method of every port the provider has, derived
// from the port interfaces (see drive.go), and every port has at least the
// workload-identity one — so skipping is no longer reachable by omitting a
// capability. Where it can still prove nothing, it fails instead of passing.
//
// USOSS-42 gave [Options.InduceTransient] the kind parameter
// [Options.InduceDenial] already had, and moved the arming inside this loop:
// one hook call per port's group of calls, rather than one call armed once for
// the whole provider. A provider whose hook cannot reach one kind now has that
// port named as undrivable and the others still driven, the same shape
// [checkDenialIsNotAResourceFailure] already reports; before, a hook that could
// not answer for any single kind had no way to say so, because it was never
// told which kind was about to be driven.
//
// Arming per port also stopped crediting a port for a call it does not
// actually make: compute/aws's key-value-table port routes Grant and Revoke
// through IAM rather than DynamoDB, so arming only DynamoDB (this port's own
// kind) leaves Revoke unexercised where the old provider-wide arm — which
// happened to also arm IAM — reported it verified. That was never evidence
// about the key-value-table port's own mapping; it was IAM's mapping, already
// covered by the workload-identity port, read onto the wrong tally.
func checkTransientIsNotTerminal(tb TB, e *Env) {
	const inv = "a substrate failure that would succeed on retry surfaces as ErrTransient, not ErrFailed"
	if e.Options.InduceTransient == nil {
		skip(tb, e, inv, "Options.InduceTransient, which has to make the provider's own substrate "+
			"fail in a way a retry would fix — only the provider knows how to throttle its own API")
		return
	}

	// driveGroup is every call the suite can make against one kind, so the hook
	// can be armed once per kind rather than once for the whole provider. That
	// is the fix USOSS-42 makes: [Options.InduceTransient] now takes the kind,
	// the same treatment [Options.InduceDenial] already has, so a provider that
	// cannot throttle its own secret store still gets its other ports armed and
	// driven instead of the whole check going dark for want of one port.
	type driveGroup struct {
		kind  compute.Kind
		name  string
		calls []Call
	}

	// Every fixture is created before its group is armed. With the setup inside
	// the armed window the induced failure lands on the setup and the check
	// proves nothing about the method it names — the same split compute/aws's
	// own version of this test makes.
	identity := e.ContainerIdentity(tb, e.Provider)
	var groups []driveGroup
	for _, pt := range availablePorts(e) {
		o, err := pt.ops(tb, e, e.Provider)
		if err != nil {
			fatal(tb, pt.Name, inv, "the provider advertises %q but the port could not be "+
				"acquired: %v", pt.Capability, err)
		}
		ref, _, err := o.Ensure(e.Name("transient-"+pt.Name), Base)
		if err != nil {
			fail(tb, pt.Name, inv, "the fixture this port's methods are driven against could not "+
				"be created, so its error mapping went unexercised: %v", redact(err))
			continue
		}
		cs, err := drivableCalls(pt, o, e, ref, identity)
		if err != nil {
			// A suite bug, not a provider one, and it has to be loud: the port
			// table having drifted from the port is how this check came to
			// drive one call in the first place.
			fatal(tb, pt.Name, inv, "%v", err)
		}
		if len(cs) > 0 {
			groups = append(groups, driveGroup{kind: pt.Kind, name: pt.Name, calls: cs})
		}
	}

	// The ports that provision nothing, and so have no entry in the port table.
	// Their fixtures are built here, before anything is armed, for the same
	// reason the port fixtures are. A build has no Kind of its own; it pushes to
	// a repository, so it is armed alongside that port.
	portless, err := portlessCalls(tb, e, buildFixture(tb, e))
	if err != nil {
		fatal(tb, "image-build", inv, "%v", err)
	}
	if len(portless) > 0 {
		groups = append(groups, driveGroup{kind: compute.KindImageRepository, name: "image-build", calls: portless})
	}

	var calls []Call
	for _, g := range groups {
		calls = append(calls, g.calls...)
	}

	// A derivation that returns nothing passes every check over it. Every
	// provider has the workload-identity port, so reaching this means something
	// is wrong with the suite or with the provider's accessors — either way the
	// mapping is unverified, and saying so in a skip nobody reads is what this
	// check is being fixed for.
	if len(calls) == 0 {
		fail(tb, "provider", inv, "no port could be driven, so the substrate-error mapping was "+
			"not exercised at all; the provider advertises %v and Options.InduceTransient is "+
			"supplied, so this is a failure rather than something to skip", sortedCaps(e.Provider.Capabilities()))
		return
	}

	// Coverage is tallied per port and reported *positively*: the methods whose
	// mapping was actually observed, as a count against the methods driven.
	//
	// The first version of this printed only the exclusions, and a reader counts
	// what is printed. "not exercised: Describe, Wait, Delete" reads as three
	// caveats on a verified port; "verified 1 of 4" reads as what it is. Same
	// information, in the direction people read it.
	tally := map[string]*coverage{}
	var undrivable []string
	for _, g := range groups {
		// Returning an error means "I cannot induce a transient failure for this
		// kind", the same contract [Options.InduceDenial] has -- not that the
		// harness is broken. A provider that cannot throttle one port still has
		// its other ports armed and driven below; only a port that declines is
		// named and skipped.
		stop, err := e.Options.InduceTransient(e.ctx, e.Provider, g.kind)
		if err != nil {
			undrivable = append(undrivable, fmt.Sprintf("%s (%v)", g.name, err))
			continue
		}

		for _, c := range g.calls {
			if tally[c.Port] == nil {
				tally[c.Port] = &coverage{}
			}
			t := tally[c.Port]
			t.driven = append(t.driven, c.Method)

			err := c.Do()
			switch {
			case err == nil:
				// The contract allows a provider to absorb a retryable failure
				// entirely — that is what a retry loop inside the provider looks
				// like from outside. It also means this call observed nothing, so it
				// is counted as unexercised rather than as a pass.
				t.unexercised = append(t.unexercised, c.Method)
			case errors.Is(err, compute.ErrTransient):
				// The obligation says a provider must not retry past the caller's
				// deadline; it says nothing about how far short of it to stop. What
				// matters is that the caller is told it may try again.
				t.verified = append(t.verified, c.Method)
			case errors.Is(err, compute.ErrFailed):
				fail(tb, c.Port, inv, "%s surfaced a retryable substrate failure as "+
					"compute.ErrFailed, which is documented as not retryable without changing the "+
					"spec. A caller that believes that abandons a deploy that would have worked; %v",
					c.Method, redact(err))
			case c.Op == opWait && errors.Is(err, compute.ErrTimeout):
				// A Wait that meets a retryable failure is entitled to keep polling
				// and then report its own deadline. That is not a mapping mistake,
				// and it is not evidence about the mapping either.
				t.unexercised = append(t.unexercised, c.Method)
			default:
				fail(tb, c.Port, inv, "%s surfaced a retryable substrate failure as %v, which matches "+
					"neither compute.ErrTransient nor any sentinel that would make sense for it",
					c.Method, redact(err))
			}
		}
		stop()
	}

	if len(undrivable) > 0 {
		e.note("provider: a transient failure could not be induced on %s, so the substrate-error "+
			"mapping is unverified for %s -- an inert hook and a correct mapping look identical "+
			"from here", strings.Join(undrivable, "; "), pluralPorts(len(undrivable)))
	}

	verified := 0
	for _, t := range tally {
		verified += len(t.verified)
	}

	// The assertion the old check did not have. A provider whose hook induces
	// nothing, or that absorbs everything, used to be indistinguishable from one
	// whose mapping is right — and a check that cannot tell those apart is
	// counted as coverage while proving nothing.
	if verified == 0 {
		fail(tb, "provider", inv, "the mapping was verified for 0 of the %d method(s) driven "+
			"across %d port(s): none of them surfaced compute.ErrTransient while "+
			"Options.InduceTransient was armed. Either the hook induces nothing — it has to make "+
			"every substrate call fail until its stop function is called, not only the next one — "+
			"or the provider absorbs every retryable failure, in which case nothing here observed "+
			"its mapping", len(calls), len(tally))
		return
	}

	// What was reached, stated as a fraction, on every run including a clean one.
	// A caller who reads one line of this check's output should read the one that
	// says how much of the mapping it saw.
	tb.Logf("conformance: the substrate-error mapping is verified for %d of %d method(s) driven "+
		"across %d port(s) of provider %q", verified, len(calls), len(tally), e.Provider.Name())

	// Per port, positively, and only where something was missed: a hook that
	// only fails writes leaves every read-back's mapping unchecked, and that is
	// invisible in a green run otherwise.
	for _, port := range sortedPorts(tally) {
		t := tally[port]
		if len(t.unexercised) == 0 {
			continue
		}
		e.note("provider %q: the substrate-error mapping is verified for %d of %d driven method(s) "+
			"at %s [verified: %s]; %s did not surface the induced failure, so their mapping was "+
			"not exercised and Options.InduceTransient has to reach them for it to be",
			e.Provider.Name(), len(t.verified), len(t.driven), port,
			joinOrNone(t.verified), strings.Join(t.unexercised, ", "))
	}
}

// coverage is what one port's methods yielded under an induced failure.
type coverage struct {
	driven      []string
	verified    []string
	unexercised []string
}

// joinOrNone renders a method list, saying "none" rather than nothing at all —
// an empty list printed as an empty string is the reading problem this tally
// exists to avoid.
func joinOrNone(methods []string) string {
	if len(methods) == 0 {
		return "none"
	}
	return strings.Join(methods, ", ")
}

// sortedPorts is for stable notes.
func sortedPorts(m map[string]*coverage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkDenialIsNotAResourceFailure is the gate on [compute.ErrNotPermitted].
//
// # Why the sentinel needs a check at all
//
// Before it existed a denial had nowhere to go but [compute.ErrFailed], whose
// documentation is false for one: no resource reached a terminal phase, and no
// spec change helps. The consequence was not cosmetic -- a surface above this
// interface could not route a permission failure to the operator and a resource
// failure to the application owner, because the two arrived as the same sentinel.
// Adding a sentinel without a check would leave every provider free to keep
// mapping denials to ErrFailed, which is where they all are today.
//
// # It drives every port the provider has, not one
//
// A mapping is per-service. On AWS one provider talks to five services that spell
// a denial with five different types, and a check that drove one call would pass
// on a provider that gets S3 right and IAM wrong -- which is the concrete finding
// USOSS-13 reported against its own port and then, on review, had to apply to this
// check. [checkTransientIsNotTerminal] is the cautionary case: it is pinned to a
// secret store, so the only gate on the transient mapping does not run at all for
// five of the six AWS providers.
//
// So this asks the provider what it has and drives all of it. The
// workload-identity port is never capability-gated, so there is always at least
// one; a provider with none is reported rather than skipped.
func checkDenialIsNotAResourceFailure(tb TB, e *Env) {
	const inv = "a substrate authorization failure surfaces as ErrNotPermitted, not as ErrFailed or ErrInvalidSpec"
	if e.Options.InduceDenial == nil {
		skip(tb, e, inv, "Options.InduceDenial, which has to make the provider's own substrate "+
			"refuse a call for authorization reasons -- only the provider knows how to be denied "+
			"by its own service")
		return
	}
	ports := availablePorts(e)
	if len(ports) == 0 {
		fatal(tb, "provider", inv, "this provider advertises no port at all, so there is nothing "+
			"to be denied; the workload-identity port is never capability-gated and should always "+
			"be here")
		return
	}
	var driven, undrivable []string
	for _, pt := range ports {
		if reason := checkDenialOnPort(tb, e, pt, inv); reason != "" {
			undrivable = append(undrivable, pt.Name+" ("+reason+")")
			continue
		}
		driven = append(driven, pt.Name)
	}

	// Reported rather than assumed, in both directions. "Drives every port" is
	// the property that distinguishes this check from the transient one, and a run
	// that quietly exercised one port -- or none -- would look identical in the
	// output to one that exercised ten.
	tb.Logf("conformance: induced a denial through %d of %d port(s): %s",
		len(driven), len(ports), strings.Join(driven, ", "))
	if len(undrivable) > 0 {
		e.note("provider: a denial could not be induced on %s, so the taxonomy mapping is "+
			"unverified for %s -- an inert hook and a correct mapping look identical from here",
			strings.Join(undrivable, "; "), pluralPorts(len(undrivable)))
	}
	if len(driven) == 0 {
		// Not a pass. Every port refused to be driven, so nothing about the
		// mapping was established, and saying so is the whole point of counting.
		skip(tb, e, inv, "a port this hook can induce a denial on; it declined all "+
			fmt.Sprint(len(ports))+" of them, so no mapping was exercised")
	}
}

func pluralPorts(n int) string {
	if n == 1 {
		return "that port"
	}
	return "those ports"
}

// checkDenialOnPort drives one port, and reports why it could not rather than
// failing the whole check.
//
// The return value is the reason the port could not be driven, empty when it was.
// A hook that cannot induce a denial on one port is not a provider defect and not
// a broken harness: it is one port whose mapping is unverified, and the caller
// above records it by name. Failing here would stop the other ports being driven
// at all, which is how a partial gate becomes no gate.
func checkDenialOnPort(tb TB, e *Env, pt Port, inv string) string {
	tb.Helper()
	ops, err := pt.ops(tb, e, e.Provider)
	if err != nil {
		fatal(tb, pt.Name, inv, "the provider advertises %q but the port could not be acquired: %v",
			pt.Capability, err)
		return ""
	}
	stop, err := e.Options.InduceDenial(e.ctx, e.Provider, pt.Kind)
	if err != nil {
		return err.Error()
	}
	defer stop()

	_, _, err = ops.Ensure(e.Name("denied"), Base)
	switch {
	case err == nil:
		// Two things produce this, and the message names both because they live
		// in different files. USOSS-32 found that one of the reference
		// provider's own ports never reached its injection point, so a harness
		// can accept an armed failure and ignore it -- and the symptom is
		// identical to a provider that does not map denials at all.
		fail(tb, pt.Name, inv, "the provider reported success for an operation its substrate was "+
			"told to refuse. Either it does not surface authorization failures, or the "+
			"Options.InduceDenial hook never reached this port's Ensure -- check that this port's "+
			"write path consults the harness's injection point before concluding the provider is "+
			"at fault")
	case errors.Is(err, compute.ErrNotPermitted):
		// The one right answer. It must not *also* match the sentinels it exists
		// to be distinguishable from, or a caller branching on those still cannot
		// tell a denial apart.
		for _, wrong := range []struct {
			err  error
			name string
			who  string
		}{
			{compute.ErrFailed, "ErrFailed", "the resource, which never reached a phase"},
			{compute.ErrInvalidSpec, "ErrInvalidSpec", "the caller's request, which is not wrong"},
			{compute.ErrTransient, "ErrTransient", "a retry, which cannot succeed unchanged"},
		} {
			if errors.Is(err, wrong.err) {
				fail(tb, pt.Name, inv, "the denial also matches %s, so a caller branching on that "+
					"is sent to %s: %v", wrong.name, wrong.who, err)
			}
		}
	case errors.Is(err, compute.ErrFailed):
		fail(tb, pt.Name, inv, "an authorization failure surfaced as compute.ErrFailed, which is "+
			"documented as a resource reaching a terminal failed phase and as not retryable "+
			"without changing the spec. Neither is true of a denial: no resource reached a phase, "+
			"and what has to change is the permissions the platform itself runs with. An operator "+
			"reading this cannot tell 'apphub is misconfigured' from 'the resource broke': %v", err)
	case errors.Is(err, compute.ErrInvalidSpec):
		fail(tb, pt.Name, inv, "an authorization failure surfaced as compute.ErrInvalidSpec, which "+
			"sends the reader to the request they made. The request is fine; the platform's own "+
			"permissions are not: %v", err)
	case errors.Is(err, compute.ErrTransient):
		fail(tb, pt.Name, inv, "an authorization failure surfaced as compute.ErrTransient, so a "+
			"caller will retry a call that cannot succeed until somebody changes an IAM policy: %v",
			err)
	default:
		fail(tb, pt.Name, inv, "an authorization failure surfaced as %v, which matches no sentinel "+
			"in the taxonomy", err)
	}
	return ""
}
