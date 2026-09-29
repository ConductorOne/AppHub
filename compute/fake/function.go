// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// functionRuntime implements [compute.FunctionRuntime].
type functionRuntime struct{ p *Provider }

// Substrate limits, present so that the interface's "a provider must return
// ErrInvalidSpec naming its limit rather than truncate" is a reachable branch.
const (
	maxInlineBundleBytes = 64 * 1024
	maxFunctionMemoryMiB = 10240
	maxFunctionTimeout   = 15 * time.Minute
)

// EnsureFunction implements [compute.FunctionRuntime].
func (f functionRuntime) EnsureFunction(_ context.Context, spec compute.FunctionSpec) (*compute.FunctionStatus, error) {
	if err := f.p.validateName("function", spec.Name); err != nil {
		return nil, err
	}
	placement, err := f.p.resolvePlacement(spec.Placement)
	if err != nil {
		return nil, err
	}
	if err := f.validateRuntime(spec.Runtime); err != nil {
		return nil, fmt.Errorf("fake: function %q: %w", spec.Name, err)
	}
	if spec.Handler == "" {
		return nil, fmt.Errorf("fake: function %q has no handler: %w", spec.Name, compute.ErrInvalidSpec)
	}
	if err := f.validateCode(spec.Code); err != nil {
		return nil, fmt.Errorf("fake: function %q: %w", spec.Name, err)
	}
	switch spec.Architecture {
	case "", compute.ArchAMD64, compute.ArchARM64:
	default:
		return nil, fmt.Errorf("fake: function %q names architecture %q: %w",
			spec.Name, spec.Architecture, compute.ErrInvalidSpec)
	}
	if spec.Resources.MemoryMiB <= 0 || spec.Resources.MemoryMiB > maxFunctionMemoryMiB {
		return nil, fmt.Errorf("fake: function %q asks for %d MiB; this substrate allows 1 to %d: %w",
			spec.Name, spec.Resources.MemoryMiB, maxFunctionMemoryMiB, compute.ErrInvalidSpec)
	}
	if spec.Resources.CPUMillicores < 0 {
		return nil, fmt.Errorf("fake: function %q asks for %dm CPU: %w",
			spec.Name, spec.Resources.CPUMillicores, compute.ErrInvalidSpec)
	}
	if spec.Timeout <= 0 || spec.Timeout > maxFunctionTimeout {
		return nil, fmt.Errorf("fake: function %q asks for a %s timeout; this substrate allows up "+
			"to %s: %w", spec.Name, spec.Timeout, maxFunctionTimeout, compute.ErrInvalidSpec)
	}
	if err := f.p.validateEnv(placement, spec.Env, spec.Secrets); err != nil {
		return nil, fmt.Errorf("fake: function %q: %w", spec.Name, err)
	}
	if err := f.p.requireIdentity(spec.Identity, compute.RuntimeFunction); err != nil {
		return nil, fmt.Errorf("fake: function %q: %w", spec.Name, err)
	}
	if err := f.p.validateWorkloadCapabilities(spec.Capabilities); err != nil {
		return nil, fmt.Errorf("fake: function %q: %w", spec.Name, err)
	}

	effective := spec
	effective.Placement = compute.Placement{Name: placement}

	rec, _, err := ensureRecord(f.p, f.p.store.functions, compute.KindFunction, spec.Name, effective, true, mergeFunctionSpec)
	if err != nil {
		return nil, err
	}
	return f.status(rec, statusOf(f.p, rec)), nil
}

func mergeFunctionSpec(old, updated compute.FunctionSpec) compute.FunctionSpec {
	// Keeping the old allocation makes the revision stable across a
	// configuration change, which is what the convergence invariant detects.
	updated.Resources = old.Resources
	updated.Env = append(append([]compute.EnvVar{}, old.Env...), updated.Env...)
	return updated
}

func (f functionRuntime) validateRuntime(runtime string) error {
	if runtime == "" {
		return fmt.Errorf("no runtime named: %w", compute.ErrInvalidSpec)
	}
	for _, r := range f.p.cfg.FunctionRuntimes {
		if r == runtime {
			return nil
		}
	}
	// Naming the legal set is the whole obligation the interface puts on this
	// field: the vocabulary is not portable, so a refusal has to be actionable.
	return fmt.Errorf("runtime %q is not one this provider supports (%s): %w",
		runtime, strings.Join(f.p.cfg.FunctionRuntimes, ", "), compute.ErrInvalidSpec)
}

func (f functionRuntime) validateCode(code compute.CodeSource) error {
	hasInline := len(code.Inline) > 0
	hasObject := code.Object != nil
	switch {
	case hasInline && hasObject:
		return fmt.Errorf("code names both an inline bundle and an object: %w", compute.ErrInvalidSpec)
	case !hasInline && !hasObject:
		return fmt.Errorf("code names no bundle: %w", compute.ErrInvalidSpec)
	case hasInline && len(code.Inline) > maxInlineBundleBytes:
		return fmt.Errorf("inline bundle is %d bytes; this substrate allows %d: %w",
			len(code.Inline), maxInlineBundleBytes, compute.ErrInvalidSpec)
	case hasObject:
		if _, err := f.p.resolve(code.Object.Bucket, compute.KindBucket); err != nil {
			return err
		}
		if code.Object.Key == "" {
			return fmt.Errorf("object code source has no key: %w", compute.ErrInvalidSpec)
		}
		// A key that climbs out of the bucket namespace is refused for the same
		// reason a Dockerfile path is confined to its context.
		if strings.HasPrefix(code.Object.Key, "/") || strings.Contains(code.Object.Key, "../") {
			return fmt.Errorf("object key %q traverses outside the bucket namespace: %w",
				code.Object.Key, compute.ErrInvalidSpec)
		}
	}
	return nil
}

// DescribeFunction implements [compute.FunctionRuntime].
func (f functionRuntime) DescribeFunction(_ context.Context, ref compute.Ref) (*compute.FunctionStatus, error) {
	rec, st, err := describeAsync(f.p, f.p.store.functions, ref, compute.KindFunction)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return &compute.FunctionStatus{Status: st}, nil
	}
	return f.status(rec, st), nil
}

// WaitForFunction implements [compute.FunctionRuntime].
func (f functionRuntime) WaitForFunction(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.FunctionStatus, error) {
	var out *compute.FunctionStatus
	_, err := waitFor(ctx, f.p, "function", ref, opts,
		func() (compute.Status, error) {
			st, err := f.DescribeFunction(ctx, ref)
			if err != nil {
				return compute.Status{}, err
			}
			out = st
			return st.Status, nil
		},
		func(st compute.Status) bool { return st.Phase == compute.PhaseReady },
	)
	return out, err
}

// DeleteFunction implements [compute.FunctionRuntime].
func (f functionRuntime) DeleteFunction(_ context.Context, ref compute.Ref) error {
	return deleteAsync(f.p, f.p.store.functions, ref, compute.KindFunction)
}

func (f functionRuntime) status(rec *record[compute.FunctionSpec], st compute.Status) *compute.FunctionStatus {
	f.p.store.mu.Lock()
	defer f.p.store.mu.Unlock()
	return &compute.FunctionStatus{Status: st, Spec: deepCopy(rec.spec), Revision: rec.revision}
}

// --- endpoints -------------------------------------------------------------

// EnsureEndpoint implements [compute.FunctionRuntime].
//
// The invoke permission is granted here rather than in a separate call, because
// an endpoint that cannot invoke its target is not partially working. The source
// system splits the two and tolerates the grant failing with a logged warning
// (lambda.go:461-467), which produces exactly that state.
func (f functionRuntime) EnsureEndpoint(_ context.Context, spec compute.EndpointSpec) (*compute.EndpointStatus, error) {
	if err := f.p.require(compute.CapFunctionEndpoint); err != nil {
		return nil, err
	}
	if err := f.p.validateName("endpoint", spec.Name); err != nil {
		return nil, err
	}
	placement, err := f.p.resolvePlacement(spec.Placement)
	if err != nil {
		return nil, err
	}
	targetID, err := f.p.resolve(spec.Target, compute.KindFunction)
	if err != nil {
		return nil, fmt.Errorf("fake: endpoint %q target: %w", spec.Name, err)
	}
	f.p.store.mu.Lock()
	target, ok := f.p.store.functions[targetID]
	f.p.store.mu.Unlock()
	if !ok || target.async.deleted {
		return nil, fmt.Errorf("fake: endpoint %q targets %s, which does not exist: %w",
			spec.Name, spec.Target, compute.ErrNotFound)
	}
	if len(spec.Listeners) == 0 {
		return nil, fmt.Errorf("fake: endpoint %q has no listeners: %w", spec.Name, compute.ErrInvalidSpec)
	}
	if err := f.validateListeners(spec.Listeners); err != nil {
		return nil, fmt.Errorf("fake: endpoint %q: %w", spec.Name, err)
	}
	if err := f.p.validateIngress(spec.Ingress); err != nil {
		return nil, fmt.Errorf("fake: endpoint %q: %w", spec.Name, err)
	}

	effective := spec
	effective.Placement = compute.Placement{Name: placement}

	rec, _, err := ensureRecord(f.p, f.p.store.endpoints, compute.KindFunctionEndpoint, spec.Name, effective, true, nil)
	if err != nil {
		return nil, err
	}
	// The endpoint may invoke its target. Recorded as an ordinary grant so that
	// a test can observe it rather than take it on trust.
	f.p.store.mu.Lock()
	f.p.store.grants[grantKey{resource: targetID, subject: rec.ref.ID}] = compute.AccessReadWrite
	f.p.store.mu.Unlock()

	return f.endpointStatus(rec, statusOf(f.p, rec)), nil
}

// validateListeners enforces the certificate requirement.
//
// The source system selects the HTTPS protocol enum for any listener port other
// than 80 (lambda.go:487-490) and never populates a Certificates field
// (lambda.go:696-708), so every HTTPS listener it creates has no certificate.
// Here a listener that asks for TLS must name a certificate this provider can
// resolve, and a provider may not invent one.
func (f functionRuntime) validateListeners(listeners []compute.ListenerSpec) error {
	seen := map[int]bool{}
	for i, l := range listeners {
		if l.Port <= 0 || l.Port > 65535 {
			return fmt.Errorf("listener %d names port %d: %w", i, l.Port, compute.ErrInvalidSpec)
		}
		if seen[l.Port] {
			return fmt.Errorf("port %d has two listeners: %w", l.Port, compute.ErrInvalidSpec)
		}
		seen[l.Port] = true

		protocol := l.Protocol
		if protocol == "" {
			protocol = compute.ListenerHTTP
		}
		switch protocol {
		case compute.ListenerHTTP:
			if l.TLS != nil {
				return fmt.Errorf("listener %d on port %d is plaintext but carries a certificate; "+
					"the two states are distinct now and a provider must not guess which was "+
					"meant: %w", i, l.Port, compute.ErrInvalidSpec)
			}
			continue
		case compute.ListenerHTTPS:
		default:
			return fmt.Errorf("listener %d names protocol %q: %w", i, protocol, compute.ErrInvalidSpec)
		}

		if f.p.broken(DefectTLSWithoutCertificate) {
			continue
		}
		if l.TLS == nil {
			return fmt.Errorf("listener %d on port %d asks for TLS and carries no certificate at "+
				"all; this is the source system's defect stated literally, and it is now "+
				"representable so that it can be refused: %w", i, l.Port, compute.ErrInvalidSpec)
		}
		if l.TLS.CertificateRef == "" {
			return fmt.Errorf("listener %d on port %d asks for TLS with no certificate; serving "+
				"TLS without one is the defect this requirement exists to prevent: %w",
				i, l.Port, compute.ErrInvalidSpec)
		}
		if !f.p.resolvesCertificate(l.TLS.CertificateRef) {
			return fmt.Errorf("listener %d names certificate %q, which this provider cannot "+
				"resolve (have %s): %w", i, l.TLS.CertificateRef,
				strings.Join(f.p.cfg.Certificates, ", "), compute.ErrInvalidSpec)
		}
	}
	return nil
}

func (p *Provider) resolvesCertificate(ref string) bool {
	for _, c := range p.cfg.Certificates {
		if c == ref {
			return true
		}
	}
	return false
}

// DescribeEndpoint implements [compute.FunctionRuntime].
func (f functionRuntime) DescribeEndpoint(_ context.Context, ref compute.Ref) (*compute.EndpointStatus, error) {
	if err := f.p.require(compute.CapFunctionEndpoint); err != nil {
		return nil, err
	}
	rec, st, err := describeAsync(f.p, f.p.store.endpoints, ref, compute.KindFunctionEndpoint)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return &compute.EndpointStatus{Status: st}, nil
	}
	return f.endpointStatus(rec, st), nil
}

// WaitForEndpoint implements [compute.FunctionRuntime].
func (f functionRuntime) WaitForEndpoint(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.EndpointStatus, error) {
	var out *compute.EndpointStatus
	_, err := waitFor(ctx, f.p, "endpoint", ref, opts,
		func() (compute.Status, error) {
			st, err := f.DescribeEndpoint(ctx, ref)
			if err != nil {
				return compute.Status{}, err
			}
			out = st
			return st.Status, nil
		},
		func(st compute.Status) bool { return st.Phase == compute.PhaseReady },
	)
	return out, err
}

// DeleteEndpoint implements [compute.FunctionRuntime].
func (f functionRuntime) DeleteEndpoint(_ context.Context, ref compute.Ref) error {
	if err := f.p.require(compute.CapFunctionEndpoint); err != nil {
		return err
	}
	return deleteAsync(f.p, f.p.store.endpoints, ref, compute.KindFunctionEndpoint)
}

func (f functionRuntime) endpointStatus(rec *record[compute.EndpointSpec], st compute.Status) *compute.EndpointStatus {
	f.p.store.mu.Lock()
	defer f.p.store.mu.Unlock()
	// The hostname is the one output a caller consumes. It is derived from the
	// logical name so it is stable across deploys, and it uses a reserved TLD so
	// nothing resolves.
	host := ""
	if st.Phase == compute.PhaseReady || st.Phase == compute.PhasePending {
		host = rec.name + "." + f.p.cfg.Name + ".endpoint.invalid"
	}
	return &compute.EndpointStatus{Status: st, Spec: deepCopy(rec.spec), Hostname: host}
}

var _ compute.FunctionRuntime = functionRuntime{}
