// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// containerRuntime implements [compute.ContainerRuntime]. Both of its resources
// are asynchronous: Ensure accepts a spec and returns promptly, and readiness is
// a separate Wait with a caller-chosen deadline.
type containerRuntime struct{ p *Provider }

// maxCPUMillicores and maxMemoryMiB are this substrate's ceiling. They exist so
// that "a capacity request with no legal equivalent" is a refusal a caller can
// actually hit.
const (
	maxCPUMillicores = 16000
	maxMemoryMiB     = 122880
)

// EnsureService implements [compute.ContainerRuntime].
func (c containerRuntime) EnsureService(_ context.Context, spec compute.ServiceSpec) (*compute.ServiceStatus, error) {
	if err := c.p.validateName("service", spec.Name); err != nil {
		return nil, err
	}
	placement, err := c.p.resolvePlacement(spec.Placement)
	if err != nil {
		return nil, err
	}
	if spec.Image == "" {
		return nil, fmt.Errorf("fake: service %q has no image: %w", spec.Name, compute.ErrInvalidSpec)
	}
	rounded, note, err := roundResources(spec.Resources)
	if err != nil {
		return nil, fmt.Errorf("fake: service %q: %w", spec.Name, err)
	}
	if spec.Replicas < 0 {
		return nil, fmt.Errorf("fake: service %q asks for %d replicas: %w",
			spec.Name, spec.Replicas, compute.ErrInvalidSpec)
	}
	if err := validatePorts(spec.Ports); err != nil {
		return nil, fmt.Errorf("fake: service %q: %w", spec.Name, err)
	}
	if err := c.p.validateEnv(placement, spec.Env, spec.Secrets); err != nil {
		return nil, fmt.Errorf("fake: service %q: %w", spec.Name, err)
	}
	if err := c.p.requireIdentity(spec.Identity, compute.RuntimeContainer); err != nil {
		return nil, fmt.Errorf("fake: service %q: %w", spec.Name, err)
	}
	if err := c.p.validateWorkloadCapabilities(spec.Capabilities); err != nil {
		return nil, fmt.Errorf("fake: service %q: %w", spec.Name, err)
	}
	if spec.ExecEnabled && !c.p.caps.Has(compute.CapWorkloadExec) {
		return nil, fmt.Errorf("fake: service %q asks for interactive session access, which "+
			"requires %q: %w", spec.Name, compute.CapWorkloadExec, compute.ErrUnsupported)
	}
	if err := c.p.validateIngress(spec.Ingress); err != nil {
		return nil, fmt.Errorf("fake: service %q: %w", spec.Name, err)
	}
	if err := c.p.validateRoutes(spec.Routes, spec.Ports); err != nil {
		return nil, fmt.Errorf("fake: service %q: %w", spec.Name, err)
	}

	effective := spec
	effective.Resources = rounded
	effective.Placement = compute.Placement{Name: placement}

	imageRegistry(c).ensurePullAccess(spec.Image, spec.Identity)
	rec, _, err := ensureRecord(c.p, c.p.store.services, compute.KindService, spec.Name, effective, true, mergeServiceSpec)
	if err != nil {
		return nil, err
	}
	if note != "" {
		c.p.store.mu.Lock()
		rec.async.message = note
		c.p.store.mu.Unlock()
	}
	return c.status(rec), nil
}

// mergeServiceSpec is the additive Ensure a correct provider must not implement:
// it keeps declarative elements the new spec omitted. Only reachable through
// [DefectCreateOrAdd].
func mergeServiceSpec(old, updated compute.ServiceSpec) compute.ServiceSpec {
	updated.Ingress = append(append([]compute.IngressRule{}, old.Ingress...), updated.Ingress...)
	updated.Env = append(append([]compute.EnvVar{}, old.Env...), updated.Env...)
	seen := map[compute.WorkloadCapability]bool{}
	var caps []compute.WorkloadCapability
	for _, c := range append(append([]compute.WorkloadCapability{}, old.Capabilities...), updated.Capabilities...) {
		if !seen[c] {
			seen[c] = true
			caps = append(caps, c)
		}
	}
	updated.Capabilities = caps
	return updated
}

// DescribeService implements [compute.ContainerRuntime].
func (c containerRuntime) DescribeService(_ context.Context, ref compute.Ref) (*compute.ServiceStatus, error) {
	rec, st, err := describeAsync(c.p, c.p.store.services, ref, compute.KindService)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return &compute.ServiceStatus{Status: st}, nil
	}
	return c.statusFrom(rec, st), nil
}

// WaitForService implements [compute.ContainerRuntime].
func (c containerRuntime) WaitForService(ctx context.Context, ref compute.Ref, minReady int, opts compute.WaitOptions) (*compute.ServiceStatus, error) {
	if minReady < 0 {
		return nil, fmt.Errorf("fake: WaitForService asked for %d ready instances: %w",
			minReady, compute.ErrInvalidSpec)
	}
	var out *compute.ServiceStatus
	_, err := waitFor(ctx, c.p, "service", ref, opts,
		func() (compute.Status, error) {
			st, err := c.DescribeService(ctx, ref)
			if err != nil {
				return compute.Status{}, err
			}
			out = st
			return st.Status, nil
		},
		func(compute.Status) bool { return out != nil && out.ReadyReplicas >= minReady },
	)
	if err != nil {
		return out, err
	}
	return out, nil
}

// ScaleService implements [compute.ContainerRuntime].
func (c containerRuntime) ScaleService(_ context.Context, ref compute.Ref, replicas int) error {
	if replicas < 0 {
		return fmt.Errorf("fake: cannot scale to %d replicas: %w", replicas, compute.ErrInvalidSpec)
	}
	rec, err := lookup(c.p, c.p.store.services, ref, compute.KindService)
	if err != nil {
		return err
	}
	c.p.store.mu.Lock()
	defer c.p.store.mu.Unlock()
	if rec.async.deleted {
		return fmt.Errorf("fake: service %s was deleted: %w", ref, compute.ErrNotFound)
	}
	if c.p.broken(DefectScaleRewritesTheSpec) {
		// A scale implemented as an Ensure of the spec the scale path carries.
		// Everything it does not carry is lost, silently, because the caller
		// asked only for a different instance count.
		rec.spec = compute.ServiceSpec{
			Name:      rec.spec.Name,
			Placement: rec.spec.Placement,
			Image:     rec.spec.Image,
			Resources: rec.spec.Resources,
			Replicas:  replicas,
			Identity:  rec.spec.Identity,
		}
		rec.revision = revisionOf(rec.spec)
		rec.updatedAt = c.p.store.now()
		return nil
	}
	rec.spec.Replicas = replicas
	rec.revision = revisionOf(rec.spec)
	rec.updatedAt = c.p.store.now()
	if replicas == 0 {
		if c.p.broken(DefectScaleToZeroDeletes) {
			// A provider that maps "no instances" onto "remove the workload".
			// The caller asked for a pause and finds the service gone.
			rec.async.deleted = true
			rec.async.phase = compute.PhaseGone
			return nil
		}
		// Zero is paused, not failed: the definition and the network identity
		// persist and nothing runs.
		rec.async.phase = compute.PhaseReady
		rec.async.message = "paused"
		return nil
	}
	if rec.async.phase == compute.PhaseReady && rec.async.message == "paused" {
		rec.async.phase = compute.PhasePending
		rec.async.observations = 0
		rec.async.message = "resuming"
	}
	return nil
}

// DeleteService implements [compute.ContainerRuntime].
func (c containerRuntime) DeleteService(_ context.Context, ref compute.Ref) error {
	return deleteAsync(c.p, c.p.store.services, ref, compute.KindService)
}

func (c containerRuntime) status(rec *record[compute.ServiceSpec]) *compute.ServiceStatus {
	return c.statusFrom(rec, statusOf(c.p, rec))
}

func (c containerRuntime) statusFrom(rec *record[compute.ServiceSpec], st compute.Status) *compute.ServiceStatus {
	c.p.store.mu.Lock()
	defer c.p.store.mu.Unlock()
	ready := 0
	if st.Phase == compute.PhaseReady {
		ready = rec.spec.Replicas
	}
	return &compute.ServiceStatus{
		Status: st,
		Spec:   deepCopy(rec.spec),
		// The platform's ingress answers on one address here, reported only once
		// the service is serving and only when it asked for a route.
		RouteAddresses:  routeAddresses(c.p, rec.spec.Routes, st.Phase),
		DesiredReplicas: rec.spec.Replicas,
		ReadyReplicas:   ready,
		Revision:        rec.revision,
	}
}

// routeAddresses reports where the platform's ingress answers for a service's
// routes. It is empty until the service is serving and empty when it asked for
// no routes, because an address a caller cannot use yet is worse than none: it
// would be published in DNS before anything answered on it.
func routeAddresses(p *Provider, routes []compute.Route, phase compute.Phase) []string {
	if len(routes) == 0 || phase != compute.PhaseReady {
		return nil
	}
	return []string{"ingress." + p.cfg.Name + ".invalid"}
}

// --- scheduled jobs --------------------------------------------------------

// EnsureScheduledJob implements [compute.ContainerRuntime].
func (c containerRuntime) EnsureScheduledJob(_ context.Context, spec compute.ScheduledJobSpec) (*compute.ScheduledJobStatus, error) {
	if err := c.p.require(compute.CapScheduledJob); err != nil {
		return nil, err
	}
	if err := c.p.validateName("scheduled job", spec.Name); err != nil {
		return nil, err
	}
	placement, err := c.p.resolvePlacement(spec.Placement)
	if err != nil {
		return nil, err
	}
	if err := validateSchedule(spec.Schedule); err != nil {
		return nil, fmt.Errorf("fake: scheduled job %q: %w", spec.Name, err)
	}
	if spec.Image == "" {
		return nil, fmt.Errorf("fake: scheduled job %q has no image: %w", spec.Name, compute.ErrInvalidSpec)
	}
	rounded, _, err := roundResources(spec.Resources)
	if err != nil {
		return nil, fmt.Errorf("fake: scheduled job %q: %w", spec.Name, err)
	}
	if err := c.p.validateEnv(placement, spec.Env, spec.Secrets); err != nil {
		return nil, fmt.Errorf("fake: scheduled job %q: %w", spec.Name, err)
	}
	if err := c.p.requireIdentity(spec.Identity, compute.RuntimeContainer); err != nil {
		return nil, fmt.Errorf("fake: scheduled job %q: %w", spec.Name, err)
	}
	if err := c.p.validateWorkloadCapabilities(spec.Capabilities); err != nil {
		return nil, fmt.Errorf("fake: scheduled job %q: %w", spec.Name, err)
	}
	if err := c.p.validateIngress(spec.Ingress); err != nil {
		return nil, fmt.Errorf("fake: scheduled job %q: %w", spec.Name, err)
	}

	effective := spec
	effective.Resources = rounded
	effective.Placement = compute.Placement{Name: placement}

	// Synchronous: a cron entry is live the moment the substrate accepts it.
	imageRegistry(c).ensurePullAccess(spec.Image, spec.Identity)
	rec, _, err := ensureRecord(c.p, c.p.store.jobs, compute.KindScheduledJob, spec.Name, effective, false, mergeJobSpec)
	if err != nil {
		return nil, err
	}
	return c.jobStatus(rec), nil
}

func mergeJobSpec(old, updated compute.ScheduledJobSpec) compute.ScheduledJobSpec {
	// The schedule is the observable declarative field, so an additive
	// implementation keeps the old one.
	updated.Schedule = old.Schedule
	updated.Env = append(append([]compute.EnvVar{}, old.Env...), updated.Env...)
	return updated
}

// DescribeScheduledJob implements [compute.ContainerRuntime].
func (c containerRuntime) DescribeScheduledJob(_ context.Context, ref compute.Ref) (*compute.ScheduledJobStatus, error) {
	if err := c.p.require(compute.CapScheduledJob); err != nil {
		return nil, err
	}
	rec, err := lookup(c.p, c.p.store.jobs, ref, compute.KindScheduledJob)
	if err != nil {
		return nil, err
	}
	return c.jobStatus(rec), nil
}

// DeleteScheduledJob implements [compute.ContainerRuntime].
func (c containerRuntime) DeleteScheduledJob(_ context.Context, ref compute.Ref) error {
	if err := c.p.require(compute.CapScheduledJob); err != nil {
		return err
	}
	return deleteSync(c.p, c.p.store.jobs, ref, compute.KindScheduledJob)
}

func (c containerRuntime) jobStatus(rec *record[compute.ScheduledJobSpec]) *compute.ScheduledJobStatus {
	c.p.store.mu.Lock()
	defer c.p.store.mu.Unlock()
	return &compute.ScheduledJobStatus{Ref: rec.ref, Spec: deepCopy(rec.spec), Schedule: rec.spec.Schedule}
}

var _ compute.ContainerRuntime = containerRuntime{}

// --- shared spec checks ----------------------------------------------------

// roundResources maps a request onto this substrate's discrete sizes.
//
// It rounds *up*, and says so. Rounding down would turn a capacity decision
// into a silent, intermittent out-of-memory failure at runtime, which is why the
// interface makes the direction normative rather than leaving it to taste.
func roundResources(r compute.Resources) (compute.Resources, string, error) {
	if r.CPUMillicores <= 0 || r.MemoryMiB <= 0 {
		return r, "", fmt.Errorf("resources must be positive, got %dm CPU and %d MiB: %w",
			r.CPUMillicores, r.MemoryMiB, compute.ErrInvalidSpec)
	}
	if r.CPUMillicores > maxCPUMillicores || r.MemoryMiB > maxMemoryMiB {
		return r, "", fmt.Errorf("this substrate offers at most %dm CPU and %d MiB, and cannot "+
			"satisfy %dm / %d MiB: %w", maxCPUMillicores, maxMemoryMiB,
			r.CPUMillicores, r.MemoryMiB, compute.ErrInvalidSpec)
	}
	out := compute.Resources{
		CPUMillicores: roundUp(r.CPUMillicores, 256),
		MemoryMiB:     roundUp(r.MemoryMiB, 512),
	}
	if out == r {
		return out, "", nil
	}
	return out, fmt.Sprintf("rounded up from %dm/%dMiB to %dm/%dMiB to reach a size this "+
		"substrate offers", r.CPUMillicores, r.MemoryMiB, out.CPUMillicores, out.MemoryMiB), nil
}

func roundUp(v, step int) int {
	if v%step == 0 {
		return v
	}
	return ((v / step) + 1) * step
}

func validatePorts(ports []compute.PortSpec) error {
	seen := map[int]bool{}
	names := map[string]bool{}
	for _, p := range ports {
		if p.Number <= 0 || p.Number > 65535 {
			return fmt.Errorf("port %d is out of range: %w", p.Number, compute.ErrInvalidSpec)
		}
		if seen[p.Number] {
			return fmt.Errorf("port %d is declared twice: %w", p.Number, compute.ErrInvalidSpec)
		}
		seen[p.Number] = true
		if p.Name != "" {
			if names[p.Name] {
				return fmt.Errorf("two ports are both named %q: %w", p.Name, compute.ErrInvalidSpec)
			}
			names[p.Name] = true
		}
		switch p.Protocol {
		case "", compute.ProtocolTCP, compute.ProtocolUDP:
		default:
			return fmt.Errorf("port %d names protocol %q: %w", p.Number, p.Protocol, compute.ErrInvalidSpec)
		}
	}
	return nil
}

// validateEnv rejects a duplicate variable name and, more importantly, a
// collision between a visible variable and a secret one. A substrate that
// resolved both would pick one arbitrarily, and which one it picked would decide
// whether a credential ended up in a place the caller was told was visible.
func (p *Provider) validateEnv(placement string, env []compute.EnvVar, secrets []compute.SecretBinding) error {
	seen := map[string]bool{}
	for _, e := range env {
		if e.Name == "" {
			return fmt.Errorf("an environment variable has no name: %w", compute.ErrInvalidSpec)
		}
		if seen[e.Name] {
			return fmt.Errorf("environment variable %q is set twice: %w", e.Name, compute.ErrInvalidSpec)
		}
		seen[e.Name] = true
	}
	for _, b := range secrets {
		if seen[b.EnvName] {
			return fmt.Errorf("%q is set both as a visible environment variable and as a secret "+
				"binding: %w", b.EnvName, compute.ErrInvalidSpec)
		}
		seen[b.EnvName] = true
	}
	return p.validateSecretBindings(placement, secrets)
}

func (p *Provider) validateRoutes(routes []compute.Route, ports []compute.PortSpec) error {
	declared := map[int]bool{}
	for _, p := range ports {
		declared[p.Number] = true
	}
	for i, r := range routes {
		if r.Host == "" {
			return fmt.Errorf("route %d has no host: %w", i, compute.ErrInvalidSpec)
		}
		if strings.Contains(r.Host, "/") || strings.HasPrefix(r.Host, ".") {
			return fmt.Errorf("route %d host %q is not a hostname: %w", i, r.Host, compute.ErrInvalidSpec)
		}
		if !declared[r.TargetPort] {
			return fmt.Errorf("route %d targets port %d, which the workload does not declare: %w",
				i, r.TargetPort, compute.ErrInvalidSpec)
		}
		if !r.RequireAuth && len(r.PublicPaths) > 0 {
			return fmt.Errorf("route %d lists public paths but does not require authentication, "+
				"so the exception has nothing to except: %w", i, compute.ErrInvalidSpec)
		}
		if r.RequireAuth && !p.caps.Has(compute.CapIngressAuth) {
			return &compute.UnsupportedError{
				Provider:   p.cfg.Name,
				Capability: compute.CapIngressAuth,
				Detail: "this provider's ingress cannot authenticate a request, and routing it " +
					"unauthenticated to a workload that asked not to receive it is not an option",
			}
		}
		if r.MCPAuthApplicationID != "" && !p.caps.Has(compute.CapMCPAuth) {
			return &compute.UnsupportedError{
				Provider:   p.cfg.Name,
				Capability: compute.CapMCPAuth,
				Detail:     "this provider's ingress cannot install app-specific MCP OAuth and discovery routes",
			}
		}
		if err := p.validateRouteTLS(i, r); err != nil {
			return err
		}
	}
	return nil
}

// validateRouteTLS enforces the fail-closed rule Route states.
//
// A public application hostname served over HTTP is the same defect class as the
// source system's certificate-less HTTPS listener, one layer down. The interface
// now carries the certificate, so refusing is the contract rather than one
// provider's judgement.
func (p *Provider) validateRouteTLS(i int, r compute.Route) error {
	if p.broken(DefectTLSWithoutCertificate) || p.broken(DefectPlaintextRoute) {
		return nil
	}
	switch {
	case r.TLS != nil && r.TLS.CertificateRef == "":
		return fmt.Errorf("route %d asks for TLS and names no certificate: %w",
			i, compute.ErrInvalidSpec)
	case r.TLS != nil && !p.resolvesCertificate(r.TLS.CertificateRef):
		return fmt.Errorf("route %d names certificate %q, which this provider cannot resolve "+
			"(have %s), and no provider may invent one: %w",
			i, r.TLS.CertificateRef, strings.Join(p.cfg.Certificates, ", "), compute.ErrInvalidSpec)
	case r.TLS == nil && !r.AllowPlaintext:
		return fmt.Errorf("route %d names no certificate and does not set AllowPlaintext; "+
			"publishing an application over HTTP has to be something somebody asked for: %w",
			i, compute.ErrInvalidSpec)
	}
	return nil
}

var (
	cronField = regexp.MustCompile(`^[0-9*,/-]+$`)
	rateExpr  = regexp.MustCompile(`^rate\((\d+) (minute|minutes|hour|hours|day|days)\)$`)
)

// validateSchedule pins the cron grammar the interface states: five-field POSIX
// cron, or "rate(n unit)".
//
// The source system passes the operator's string straight through to EventBridge
// Scheduler (source system @ backend/internal/modules/deploy/container.go),
// which means the accepted dialect is whatever
// that service happens to take. Validating here is what makes a schedule
// portable: a provider translates a stated grammar instead of each substrate
// accepting a different one.
func validateSchedule(s compute.Schedule) error {
	if s.Expression == "" {
		return fmt.Errorf("a schedule needs an expression: %w", compute.ErrInvalidSpec)
	}
	if strings.HasPrefix(s.Expression, "rate(") {
		m := rateExpr.FindStringSubmatch(s.Expression)
		if m == nil {
			return fmt.Errorf("rate expression %q is not of the form \"rate(<n> <unit>)\": %w",
				s.Expression, compute.ErrInvalidSpec)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil || n <= 0 {
			return fmt.Errorf("rate expression %q has a non-positive interval: %w",
				s.Expression, compute.ErrInvalidSpec)
		}
	} else {
		fields := strings.Fields(s.Expression)
		if len(fields) != 5 {
			return fmt.Errorf("cron expression %q has %d fields; the interface pins five-field "+
				"POSIX cron: %w", s.Expression, len(fields), compute.ErrInvalidSpec)
		}
		for i, f := range fields {
			if !cronField.MatchString(f) {
				return fmt.Errorf("cron expression %q field %d (%q) is not a five-field POSIX "+
					"cron field: %w", s.Expression, i+1, f, compute.ErrInvalidSpec)
			}
		}
	}
	if s.Timezone != "" {
		if _, err := time.LoadLocation(s.Timezone); err != nil {
			return fmt.Errorf("timezone %q is not an IANA name this provider can resolve: %w",
				s.Timezone, compute.ErrInvalidSpec)
		}
	}
	return nil
}
