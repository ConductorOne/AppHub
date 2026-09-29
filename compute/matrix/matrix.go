// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package matrix

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// Support is what a provider does with one port.
type Support string

const (
	// SupportAvailable means the accessor returned a port and at least one of
	// its methods does something other than refuse.
	SupportAvailable Support = "available"

	// SupportDeclined means the accessor refused with [compute.ErrUnsupported].
	// This is the shape [compute.Provider] is designed around: the caller never
	// receives a port it cannot use, and the refusal names the capability.
	SupportDeclined Support = "declined"

	// SupportStub means the accessor returned a port whose every probed method
	// refused with [compute.ErrUnsupported].
	//
	// It is reported separately from [SupportDeclined] because it is the defect
	// the accessor-returns-an-error design exists to prevent: the provider
	// advertises the capability, hands out a port, and refuses at call time. It
	// is only ever reported when [Options.ProbePorts] is set; without probing
	// such a port is indistinguishable from a working one.
	SupportStub Support = "stub"

	// SupportPartial means some but not all of the port's probed methods refused
	// with [compute.ErrUnsupported].
	//
	// It exists because a reviewer falsified the classification this package
	// originally claimed. A port whose methods all refuse is caught as a
	// [SupportStub]; a port that refuses *most* of them and answers
	// [compute.ErrInvalidSpec] on the one zero-argument call the probe happens to
	// make was published as [SupportAvailable]. Six methods, five of them
	// refusing, rendered as a working port.
	//
	// A partial port is not automatically a defect — a port may legitimately
	// refuse a specific spec — but it is never something to publish as "this
	// provider can do this", so it gets its own answer and names the methods that
	// refused. See [Port.Methods] and the limits on [Options.ProbePorts].
	SupportPartial Support = "partial"

	// SupportUnknown means the accessor returned neither a usable port nor a
	// [compute.ErrUnsupported] refusal — a nil port with a nil error, or an
	// error of some other kind. Either is a provider bug, and naming it is
	// better than folding it into one of the answers above.
	SupportUnknown Support = "unknown"
)

// Method is one port method's response to a probe.
type Method struct {
	// Name is the method's name on the port interface.
	Name string
	// Refuses reports whether the call returned [compute.ErrUnsupported].
	Refuses bool
	// Err is the error the probe saw, rendered, or "" if there was none. It is
	// diagnostic only: a zero-argument probe is expected to fail, usually with
	// [compute.ErrInvalidSpec], and that failure is not interesting.
	Err string
}

// Port is one row of the matrix: what a provider does with one of
// [compute.Provider]'s capability-gated accessors.
type Port struct {
	// Accessor is the method name on [compute.Provider] — "Registry",
	// "ObjectStores", "KeyValues".
	Accessor string
	// Interface is the port interface the accessor returns, as
	// "compute.ImageRegistry".
	Interface string
	// Support is what the provider did.
	Support Support
	// Capability is the capability named by the refusal, when the accessor
	// declined with an [compute.UnsupportedError]. Empty otherwise: a provider
	// that supplies a port does not tell us which capability gated it, and
	// inventing the mapping here would be the hand-maintained restatement this
	// package exists to avoid. The accessor-to-capability binding is checked by
	// the conformance suite's provider/capability-accessor-agreement invariant.
	Capability compute.Capability
	// Detail is the refusal's explanation, when it carried one.
	Detail string
	// Methods is the probe result per method, when [Options.ProbePorts] was set
	// and a port was obtained. Nil otherwise.
	Methods []Method
}

// Capability is one capability and whether the provider advertises it.
type Capability struct {
	// Capability is the capability, from [compute.AllCapabilities].
	Capability compute.Capability
	// Present reports whether [compute.Provider.Capabilities] contains it.
	Present bool
}

// Matrix is a provider's derived support matrix.
type Matrix struct {
	// Provider is [compute.Provider.Name].
	Provider string
	// Probed records whether the ports were probed, so a reader can tell
	// "no stub found" from "stubs were not looked for".
	Probed bool
	// Capabilities covers the whole of [compute.AllCapabilities], in that
	// order, present and absent alike. An absent capability is a fact worth
	// publishing, which is why this is not a filtered list.
	Capabilities []Capability
	// Ports covers every capability-gated accessor on [compute.Provider],
	// sorted by accessor name.
	Ports []Port
}

// Options configures [Derive].
type Options struct {
	// ProbePorts makes Derive call every method of every port it obtains, with
	// zero-valued arguments, and classify what comes back: a port whose every
	// probed method refuses is [SupportStub], and one where only some refuse is
	// [SupportPartial].
	//
	// # What probing does not establish, stated because the stronger claim was
	// falsified
	//
	// This package originally claimed that "a port that exists but is
	// unimplemented cannot hide". A reviewer disproved it: a port that refuses
	// every realistic call but answers [compute.ErrInvalidSpec] to the one
	// zero-argument call the probe makes was published as available. A
	// zero-argument probe is **negative evidence only** — it can show that a port
	// refuses, and it cannot show that a port works, because the one input it
	// knows how to construct is the input every well-written port rejects on
	// validation grounds.
	//
	// [SupportPartial] narrows the gap rather than closing it: the reviewer's port
	// now reports partial, because five of its six methods refuse. A port that
	// refused *only* on realistic inputs and validated all of them would still
	// read as available, and nothing short of driving it with real specifications
	// would catch that. So [SupportAvailable] means "the accessor succeeded and no
	// probed method refused", which is what the matrix now says it means.
	//
	// Setting it also asserts that the provider is pointed at a substrate whose
	// mutation does not matter. See the package documentation for why that cannot
	// be checked from here.
	ProbePorts bool
}

// errAccessorType is returned when the reflected accessor set is empty, which
// would make every assertion over the result vacuous.
var errNothingDerived = errors.New("compute/matrix: the derivation produced nothing")

// Derive builds the matrix for p.
//
// It returns an error rather than a partial matrix when any of its three
// populations comes back empty, because a table derived from nothing renders as
// a provider that supports nothing.
func Derive(ctx context.Context, p compute.Provider, opts Options) (*Matrix, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: no provider was supplied", errNothingDerived)
	}

	accessors, err := portAccessors()
	if err != nil {
		return nil, err
	}

	all := compute.AllCapabilities()
	if len(all) == 0 {
		return nil, fmt.Errorf("%w: compute.AllCapabilities() is empty, so no capability row "+
			"could be built", errNothingDerived)
	}

	have := p.Capabilities()
	caps := make([]Capability, 0, len(all))
	for _, c := range all {
		caps = append(caps, Capability{Capability: c, Present: have.Has(c)})
	}

	value := reflect.ValueOf(p)
	ports := make([]Port, 0, len(accessors))
	for _, a := range accessors {
		ports = append(ports, describePort(ctx, value, a, opts))
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Accessor < ports[j].Accessor })

	if len(ports) == 0 {
		return nil, fmt.Errorf("%w: no capability-gated accessor was found on compute.Provider",
			errNothingDerived)
	}
	return &Matrix{Provider: p.Name(), Probed: opts.ProbePorts, Capabilities: caps, Ports: ports}, nil
}

// accessor is one capability-gated method of [compute.Provider].
type accessor struct {
	name string
	// port is the interface type the accessor returns.
	port reflect.Type
}

var (
	providerType = reflect.TypeOf((*compute.Provider)(nil)).Elem()
	errorType    = reflect.TypeOf((*error)(nil)).Elem()
	contextType  = reflect.TypeOf((*context.Context)(nil)).Elem()
)

// portAccessors reads the capability-gated accessors out of
// [compute.Provider]'s method set.
//
// The rule is structural rather than a list of names: a method taking no
// arguments and returning (some interface, error) is an accessor whose refusal
// is the interface's documented mechanism. That excludes Name (returns a
// string), Capabilities (returns a map), and Identities (returns one value, and
// is documented as never refused) without naming any of them, so adding a port
// to compute.Provider adds a row here with no edit to this package.
func portAccessors() ([]accessor, error) {
	var out []accessor
	for i := range providerType.NumMethod() {
		m := providerType.Method(i)
		mt := m.Type
		if mt.NumIn() != 0 || mt.NumOut() != 2 {
			continue
		}
		if mt.Out(0).Kind() != reflect.Interface || mt.Out(1) != errorType {
			continue
		}
		out = append(out, accessor{name: m.Name, port: mt.Out(0)})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: compute.Provider has no method returning (interface, error), "+
			"so no port row could be derived; either the interface changed shape or this "+
			"reflection is looking at the wrong type", errNothingDerived)
	}
	return out, nil
}

// describePort calls one accessor and classifies what came back.
func describePort(ctx context.Context, provider reflect.Value, a accessor, opts Options) Port {
	row := Port{Accessor: a.name, Interface: typeName(a.port)}

	results := provider.MethodByName(a.name).Call(nil)
	port, errValue := results[0], results[1]

	if !errValue.IsNil() {
		err, _ := errValue.Interface().(error)
		row.Detail = errText(err)
		if !errors.Is(err, compute.ErrUnsupported) {
			row.Support = SupportUnknown
			return row
		}
		row.Support = SupportDeclined
		var unsupported *compute.UnsupportedError
		if errors.As(err, &unsupported) {
			row.Capability = unsupported.Capability
			row.Detail = unsupported.Detail
		}
		return row
	}

	if port.IsNil() {
		// A nil port with a nil error is the failure mode compute.Provider's
		// documentation calls out by name: "the first caller to forget a nil
		// check gets a panic instead of a diagnosis".
		row.Support = SupportUnknown
		row.Detail = "the accessor returned a nil port and a nil error"
		return row
	}

	row.Support = SupportAvailable
	if !opts.ProbePorts {
		return row
	}

	row.Methods = probe(ctx, port, a.port)
	refused := refusingMethods(row.Methods)
	switch {
	case len(row.Methods) == 0:
		// Nothing to classify from. An interface with no methods is not a port.
		row.Support = SupportUnknown
		row.Detail = "this port has no methods, so probing establishes nothing"
	case len(refused) == len(row.Methods):
		row.Support = SupportStub
		row.Detail = "every method of this port refused with compute.ErrUnsupported, so the " +
			"refusal happens at call time rather than at acquisition"
	case len(refused) > 0:
		// The case a reviewer found by refusing everything except the one
		// zero-argument call the probe makes. Reporting it as available published
		// a capability the port does not have.
		row.Support = SupportPartial
		row.Detail = fmt.Sprintf("%d of %d probed methods refused with compute.ErrUnsupported "+
			"(%s), so this port is not usable as a whole even though its accessor succeeded",
			len(refused), len(row.Methods), strings.Join(refused, ", "))
	}
	return row
}

// refusingMethods names the probed methods that refused, in order.
func refusingMethods(methods []Method) []string {
	var out []string
	for _, m := range methods {
		if m.Refuses {
			out = append(out, m.Name)
		}
	}
	return out
}

// probe calls every method of iface on port with zero-valued arguments.
//
// A zero-argument call is expected to fail. What matters is *how*: a port that
// validates its input answers compute.ErrInvalidSpec, and a port that is a
// shell answers compute.ErrUnsupported from everything. Distinguishing the two
// is the whole purpose.
func probe(ctx context.Context, port reflect.Value, iface reflect.Type) []Method {
	out := make([]Method, 0, iface.NumMethod())
	for i := range iface.NumMethod() {
		m := iface.Method(i)
		out = append(out, probeOne(ctx, port, m))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// probeOne calls one method and reports what it returned.
//
// A panic is recovered and reported as the method's error rather than taken down
// the stack: this package's whole job is to describe a provider it did not
// write, and a provider that panics on a zero spec is a finding to publish, not
// a reason for the matrix to be unobtainable.
func probeOne(ctx context.Context, port reflect.Value, m reflect.Method) (result Method) {
	result = Method{Name: m.Name}
	defer func() {
		if r := recover(); r != nil {
			result.Err = fmt.Sprintf("panicked: %v", r)
			result.Refuses = false
		}
	}()

	mt := m.Type
	in := make([]reflect.Value, 0, mt.NumIn())
	for i := range mt.NumIn() {
		argType := mt.In(i)
		if argType == contextType {
			in = append(in, reflect.ValueOf(ctx))
			continue
		}
		in = append(in, reflect.Zero(argType))
	}

	fn := port.MethodByName(m.Name)
	var results []reflect.Value
	if mt.IsVariadic() {
		results = fn.CallSlice(in)
	} else {
		results = fn.Call(in)
	}

	for _, r := range results {
		if r.Type() != errorType || r.IsNil() {
			continue
		}
		err, _ := r.Interface().(error)
		result.Err = errText(err)
		result.Refuses = errors.Is(err, compute.ErrUnsupported)
	}
	return result
}

// typeName renders an interface type as "compute.ImageRegistry".
func typeName(t reflect.Type) string {
	if t.Name() == "" {
		return t.String()
	}
	pkg := t.PkgPath()
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}
	if pkg == "" {
		return t.Name()
	}
	return pkg + "." + t.Name()
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
