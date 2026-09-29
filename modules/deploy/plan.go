// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials/workload"
	"github.com/conductorone/apphub/postgres"
)

// Plan is an [Application] translated into the specifications that realise it,
// with no I/O performed and none required.
//
// Splitting it out is what makes the interesting half of this package testable
// without a provider: everything that decides *what* to create is here and is a
// pure function of an application and a configuration, and [Module] is the part
// that decides in what order to ask for it.
//
// Not everything can be static. An image tag is known after the build, a
// database endpoint after the database exists, and a secret binding after the
// secret is stored — so the workload specification is completed by [Plan.Service]
// and its siblings, which take the resolved values as arguments rather than
// reading them from anywhere.
type Plan struct {
	// Name is the logical name every resource is created under.
	Name string
	// Labels are attached to everything, and carry the application's
	// human-readable name — which is where a mutable display string belongs,
	// since nothing's identity depends on a label.
	Labels map[string]string

	// Source is the application's source location, canonicalised and already
	// checked against [Config.AllowedSourceHosts].
	Source Source
	// Identity is the workload's runtime identity.
	Identity compute.WorkloadIdentitySpec
	// Repository is the image repository.
	Repository compute.RepositorySpec

	// Relational, KeyValue and Bucket are nil when the application asked for
	// none.
	Relational *compute.RelationalSpec
	KeyValue   *compute.KeyValueSpec
	Bucket     *compute.BucketSpec
	// BucketAccess is the level the workload's identity gets on Bucket.
	BucketAccess compute.AccessLevel

	// Routes are the published routes, with hostnames already composed from
	// [Config.RouteDomain].
	Routes []compute.Route
	// Ingress is what may reach the workload.
	Ingress []compute.IngressRule

	// Required is every provider capability this plan needs, sorted. It is
	// checked before anything is created: a deploy that discovers halfway
	// through that the provider cannot run scheduled jobs has already created a
	// repository, an image, an identity and a database.
	Required []compute.Capability

	// Secrets are the workload's secret bindings from the application record,
	// already checked against the provider that will receive them.
	Secrets []compute.SecretBinding
	// EnvSecrets are the owner's environment secret names, checked against
	// every variable this module and the bindings above already set.
	EnvSecrets []string

	// application and config are kept so the completion methods do not take
	// eleven arguments each.
	app *Application
	cfg Config
	// provider is the name of the provider this plan will be applied to. It is
	// a string rather than the provider itself so that planning stays a pure
	// function; what it is for is refusing a [compute.Ref] the provider did not
	// issue, before anything is created.
	provider string
}

// newPlan translates an application, or refuses it.
//
// Every refusal here is [ErrInvalidApplication] or [ErrNotConfigured] and
// happens before a provider is touched, which is the difference between "this
// application record is wrong" and "the deploy failed".
func newPlan(cfg Config, app *Application, providerName string) (*Plan, error) {
	if app == nil {
		return nil, fmt.Errorf("%w: no application", ErrInvalidApplication)
	}
	if providerName == "" {
		return nil, fmt.Errorf("%w: the provider this plan is for was not named, so a secret "+
			"reference issued by some other provider could not be told apart from one of its own",
			ErrNotConfigured)
	}
	name, err := resourceName(cfg.ResourcePrefix, app)
	if err != nil {
		return nil, err
	}
	p := &Plan{
		Name:     name,
		Labels:   planLabels(app),
		app:      app,
		cfg:      cfg,
		provider: providerName,
	}

	if err := p.planWorkloadType(); err != nil {
		return nil, err
	}
	// Before anything reads a field: a record that sets a field outside the
	// circumstance it applies to is not deployable, and finding that out from a
	// provider halfway through a deploy is finding it out too late.
	if err := checkApplicability(app); err != nil {
		return nil, err
	}
	if err := p.planSource(); err != nil {
		return nil, err
	}
	if err := p.planIdentity(); err != nil {
		return nil, err
	}
	p.planRepository()
	if err := p.planData(); err != nil {
		return nil, err
	}
	if err := p.planRouting(); err != nil {
		return nil, err
	}
	if err := p.planSecrets(); err != nil {
		return nil, err
	}
	p.planRequired()
	return p, nil
}

// planSecrets checks the workload's secret bindings and the environment they
// share with everything else this module sets.
//
// Every failure here used to be a failure during the deploy. A binding this
// module cannot make is a workload that starts without a credential it was
// promised, and the interesting property is not that it is refused but WHEN:
// before the record is marked deploying and before the first resource exists.
func (p *Plan) planSecrets() error {
	// The names this module will set itself, so a record cannot claim one and
	// have its value silently win or lose. Derived from the plan rather than
	// listed, so a resource added above brings its variables with it.
	taken := map[string]string{}
	for _, e := range dataEnvNames(p) {
		taken[e] = "this module sets it for a resource the application asked for"
	}
	if p.Relational != nil {
		taken[EnvDatabasePassword] = "this module binds the database's own password to it"
	}

	for i, b := range p.app.Secrets {
		switch {
		case strings.TrimSpace(b.EnvName) == "":
			return fmt.Errorf("%w: secret binding %d names no environment variable, so there "+
				"is nothing to bind it to", ErrInvalidApplication, i)
		case b.Secret.IsZero():
			return fmt.Errorf("%w: secret binding %d for %q names no secret",
				ErrInvalidApplication, i, b.EnvName)
		case b.Secret.Kind != compute.KindSecret:
			return fmt.Errorf("%w: secret binding %d for %q references a %s rather than a "+
				"secret", ErrInvalidApplication, i, b.EnvName, b.Secret.Kind)
		case b.Secret.Provider != p.provider:
			// A provider handed a Ref it did not issue answers ErrForeignRef;
			// saying so here means it is said before anything is created, and
			// with the two provider names in the message.
			return fmt.Errorf("%w: secret binding %d for %q references a secret issued by "+
				"provider %q, and this deploy is against %q", compute.ErrForeignRef,
				i, b.EnvName, b.Secret.Provider, p.provider)
		}
		if why, clash := taken[b.EnvName]; clash {
			return fmt.Errorf("%w: secret binding %d wants environment variable %q, and %s",
				ErrInvalidApplication, i, b.EnvName, why)
		}
		taken[b.EnvName] = fmt.Sprintf("secret binding %d already binds it", i)
		p.Secrets = append(p.Secrets, compute.SecretBinding{EnvName: b.EnvName, Secret: b.Secret})
	}
	for _, name := range p.app.EnvSecrets {
		if err := ValidateEnvSecretName(name); err != nil {
			return err
		}
		if why, clash := taken[name]; clash {
			return fmt.Errorf("%w: environment secret %s is already set: %s", ErrInvalidApplication, name, why)
		}
		taken[name] = "another environment secret already has that name"
		p.EnvSecrets = append(p.EnvSecrets, name)
	}
	return nil
}

// The label keys this module sets on everything it creates.
//
// A caller's own labels are carried through and these are written after them,
// so an application record cannot displace the two keys an operator uses to
// find a resource in a console.
const (
	// LabelApplication carries the application's identifier.
	LabelApplication = "apphub.application"
	// LabelDisplayName carries the application's display name. It is a label
	// rather than part of any resource name, which is the whole reason a rename
	// does not orphan anything: see resourceName.
	//
	// The spelling is constrained from two directions and neither is a style
	// preference. A hyphen in the segment after the dot is the shape
	// internal/disclosure refuses anywhere in the module tree, because that is
	// what a scanner's check identifier looks like. A segment after the dot that
	// is a registrable domain suffix is the shape the repository's disclosure
	// scanner reads as a hostname — and neither spelling may be written out
	// here either, since a comment is a publication surface exactly as a string
	// literal is. Renaming is the settled response to a shape rule catching
	// something innocent; loosening either rule is not.
	LabelDisplayName = "apphub.displayname"
)

// planLabels is the non-secret metadata every resource carries.
func planLabels(app *Application) map[string]string {
	labels := map[string]string{}
	for k, v := range app.Labels {
		labels[k] = v
	}
	// Set after the caller's, so an application cannot overwrite the two labels
	// an operator uses to find a resource in a console.
	//
	labels[LabelApplication] = app.ID
	if app.Name != "" {
		labels[LabelDisplayName] = app.Name
	}
	return labels
}

// planWorkloadType checks the runtime choice and the fields that go with it.
func (p *Plan) planWorkloadType() error {
	switch p.app.Workload {
	case WorkloadContainer:
		switch p.app.Execution {
		case ExecutionService, ExecutionScheduled:
		case "":
			return fmt.Errorf("%w: a container application must say whether it runs as a "+
				"service or on a schedule; there is no default, because guessing wrong either "+
				"leaves a scheduled job running continuously or stops a service from running "+
				"at all", ErrInvalidApplication)
		default:
			return fmt.Errorf("%w: unknown execution mode %q", ErrInvalidApplication, p.app.Execution)
		}
		if p.app.Execution == ExecutionScheduled && strings.TrimSpace(p.app.Schedule.Expression) == "" {
			return fmt.Errorf("%w: a scheduled application carries no schedule expression",
				ErrInvalidApplication)
		}
		if p.app.Port <= 0 || p.app.Port > 65535 {
			return fmt.Errorf("%w: container port %d is outside 1-65535. The source clamped an "+
				"out-of-range port to 80 (container.go:104-106); a port silently replaced with "+
				"a different one is a workload nothing can reach, so it is refused instead",
				ErrInvalidApplication, p.app.Port)
		}
	case WorkloadFunction:
		// NOT PORTED, deliberately, and refused here rather than left to fail
		// somewhere less legible.
		//
		// A function is not an image workload with a different accessor. Its
		// specification carries code — inline bytes or an object location — and
		// no image at all, so it needs a second build-and-publish pipeline that
		// shares nothing with this one, plus an endpoint to reach it through.
		// USOSS-15 makes it optional ("containers can land first with function
		// support following") and it is following: this branch is where it
		// arrives, and until it does an application configured as one is told
		// so instead of being deployed as something else.
		return fmt.Errorf("%w: this application is a function workload, and this module "+
			"deploys container workloads. Function support is tracked as its own change; "+
			"a function is built and published differently and is reached through an "+
			"endpoint rather than a route, so there is nothing here to run it with",
			compute.ErrUnsupported)
	case "":
		return fmt.Errorf("%w: the application does not say what kind of workload it is",
			ErrInvalidApplication)
	default:
		return fmt.Errorf("%w: unknown workload type %q", ErrInvalidApplication, p.app.Workload)
	}
	return nil
}

// planSource canonicalises and checks the application's source location.
//
// Here rather than at the point of use, so that every refusal an application
// record can provoke happens in one place and before any resource exists. A
// source that will be refused is a deploy that cannot succeed, and finding that
// out after the identity and the repository are created is finding it out for
// no reason.
func (p *Plan) planSource() error {
	canonical, err := ValidateSourceURL(p.app.Source.URL, p.cfg.AllowedSourceHosts)
	if err != nil {
		return err
	}
	p.Source = p.app.Source
	p.Source.URL = canonical
	return nil
}

// Build is the build request for this deploy, given a materialised context
// directory and the references to push.
func (p *Plan) Build(contextDir string, destinations []compute.ImageRef) compute.BuildRequest {
	return compute.BuildRequest{
		Source: compute.BuildSource{
			ContextDir: contextDir,
			Dockerfile: p.Source.Dockerfile,
		},
		Destinations: destinations,
	}
}

// planIdentity builds the runtime-identity specification.
func (p *Plan) planIdentity() error {
	// Container, always: planWorkloadType has already refused everything else,
	// so a second branch here would be a branch no input reaches.
	runsOn := compute.RuntimeContainer
	for _, c := range p.app.Capabilities {
		if c.Requires() == "" {
			return fmt.Errorf("%w: workload capability %q is not one this repository defines",
				ErrInvalidApplication, c)
		}
	}
	p.Identity = compute.WorkloadIdentitySpec{
		Name:      p.Name,
		Placement: p.cfg.Placement,
		RunsOn:    runsOn,
		Labels:    p.Labels,
	}
	return nil
}

// planRepository builds the image-repository specification.
//
// ScanOnPush is on. The source did not ask for it, and turning it on is the
// fail-closed reading of a field whose two values are "the registry looks at
// what you pushed" and "it does not"; a provider whose registry cannot scan is
// free to ignore it.
func (p *Plan) planRepository() {
	p.Repository = compute.RepositorySpec{
		Name:       p.Name,
		ScanOnPush: true,
		Labels:     p.Labels,
	}
}

// planData builds the database and bucket specifications.
func (p *Plan) planData() error {
	if extensions := p.app.Database.Extensions; len(extensions) != 0 {
		if p.app.Database.Kind != DatabaseRelational || p.app.Database.Engine != compute.EnginePostgres {
			return fmt.Errorf("%w: database extensions require a PostgreSQL relational database", ErrInvalidApplication)
		}
		seen := make(map[string]bool, len(extensions))
		for _, name := range extensions {
			if !postgres.IsAllowedExtension(name) {
				return fmt.Errorf("%w: database extension %q is not allowed", ErrInvalidApplication, name)
			}
			if seen[name] {
				return fmt.Errorf("%w: database extension %q is listed more than once", ErrInvalidApplication, name)
			}
			seen[name] = true
		}
		if p.cfg.PostgresRootCertPath == "" {
			return fmt.Errorf("%w: PostgreSQL extensions require an operator-configured root CA certificate", ErrNotConfigured)
		}
	}
	switch p.app.Database.Kind {
	case DatabaseNone:
	case DatabaseRelational:
		db := p.app.Database
		if db.Engine == "" {
			return fmt.Errorf("%w: a relational database with no engine; which SQL dialect the "+
				"application speaks is not something to default", ErrInvalidApplication)
		}
		if strings.TrimSpace(db.DatabaseName) == "" || strings.TrimSpace(db.AdminUsername) == "" {
			return fmt.Errorf("%w: a relational database needs both a database name and an "+
				"administrative username", ErrInvalidApplication)
		}
		// Checked here rather than where the rule is built: an engine whose
		// port is unknown makes the database unreachable, and finding that out
		// after the database, the image and the workload exist is finding it
		// out too late.
		if _, err := enginePort(db.Engine); err != nil {
			return err
		}
		p.Relational = &compute.RelationalSpec{
			Name:          p.Name,
			Engine:        db.Engine,
			EngineVersion: db.EngineVersion,
			DatabaseName:  db.DatabaseName,
			AdminUsername: db.AdminUsername,
			Capacity:      db.Capacity,
			Placement:     p.cfg.Placement,
			Labels:        p.Labels,
			// Empty, deliberately, and filled in by a second Ensure once the
			// workload exists. See [Plan.RelationalIngress]: the only peer this
			// database should ever accept is a workload that does not exist yet
			// on a first deploy, and a database reachable by nothing is the
			// right state to leave it in until it does.
			Ingress: nil,
		}
	case DatabaseKeyValue:
		if strings.TrimSpace(p.app.Database.PartitionKey) == "" {
			return fmt.Errorf("%w: a key-value table needs a partition key", ErrInvalidApplication)
		}
		p.KeyValue = &compute.KeyValueSpec{
			Name:         p.Name,
			PartitionKey: p.app.Database.PartitionKey,
			SortKey:      p.app.Database.SortKey,
			Placement:    p.cfg.Placement,
			Labels:       p.Labels,
		}
	default:
		return fmt.Errorf("%w: unknown database kind %q", ErrInvalidApplication, p.app.Database.Kind)
	}

	switch p.app.Bucket.Kind {
	case BucketNone:
	case BucketStandard, BucketZonal:
		name := strings.TrimSpace(p.app.Bucket.Name)
		if name == "" {
			name = p.Name
		}
		class := compute.ObjectClassStandard
		if p.app.Bucket.Kind == BucketZonal {
			class = compute.ObjectClassZonal
			if strings.TrimSpace(p.app.Bucket.Zone) == "" {
				return fmt.Errorf("%w: a zonal bucket needs a zone", ErrInvalidApplication)
			}
		}
		p.Bucket = &compute.BucketSpec{
			Name:  name,
			Class: class,
			Zone:  p.app.Bucket.Zone,
			// Never. An application bucket is reached by the application's own
			// identity, which is granted below; a bucket the internet can read
			// is a decision nobody should be able to make by leaving a field
			// unset.
			PublicAccess: false,
			Labels:       p.Labels,
		}
		access, err := bucketAccess(p.app.Bucket.Access)
		if err != nil {
			return err
		}
		p.BucketAccess = access
	default:
		return fmt.Errorf("%w: bucket kind %q is not portable. The source offered analytic "+
			"table storage and vector storage, which one substrate has and no other does, and "+
			"an application configured for one is an application of that substrate. Reaching "+
			"for it goes through compute/ext, where the refusal names the port",
			ErrInvalidApplication, p.app.Bucket.Kind)
	}
	return nil
}

// applicationBucketAccess is the closed set of levels an application record may
// ask for on its own bucket, and the reason each of compute's levels is in it
// or not.
//
// It is a DECIDED subset of [github.com/conductorone/apphub/compute.AccessLevel],
// not a copy of it: an application does not administer its own bucket, so the
// admin level is excluded on purpose rather than missing. Stating the exclusion
// is what makes it a decision — and a test derives compute's levels from the
// package with go/types and fails if one of them is neither accepted nor
// excluded here, so a level added upstream stops this build until somebody
// rules on it.
//
// Review reproduced why this needs a closed set at all: the previous form
// refused the admin level and accepted every other string, so an undefined
// level travelled into a Grant call and was refused by the provider after five
// resources existed.
var applicationBucketAccess = map[compute.AccessLevel]string{
	compute.AccessRead:      "", // accepted
	compute.AccessReadWrite: "", // accepted
	compute.AccessAdmin: "an application does not administer its own bucket; administering it " +
		"is the platform's job and granting it to the workload is a privilege nobody asked for",
}

// bucketAccess resolves the level for a bucket, or refuses it.
//
// Empty means read-write, which is what an application storing its own objects
// needs. An application that only reads says so, and least privilege is then
// the record's to state rather than this module's to assume.
func bucketAccess(asked compute.AccessLevel) (compute.AccessLevel, error) {
	if asked == "" {
		return compute.AccessReadWrite, nil
	}
	why, known := applicationBucketAccess[asked]
	switch {
	case !known:
		return "", fmt.Errorf("%w: bucket access level %q is not one this interface defines; "+
			"an application record may ask for %s", ErrInvalidApplication, asked,
			strings.Join(acceptedBucketAccess(), " or "))
	case why != "":
		return "", fmt.Errorf("%w: bucket access level %q: %s", ErrInvalidApplication, asked, why)
	}
	return asked, nil
}

// acceptedBucketAccess lists the levels an application may ask for, sorted.
func acceptedBucketAccess() []string {
	var out []string
	for level, excluded := range applicationBucketAccess {
		if excluded == "" {
			out = append(out, string(level))
		}
	}
	sort.Strings(out)
	return out
}

// routeTarget is the domain and certificate a route is published with:
// the internal pair for an internal route, the public pair otherwise.
func (p *Plan) routeTarget(r Route) (string, string, error) {
	if r.Internal {
		domain, err := p.cfg.internalRouteDomain()
		return domain, p.cfg.InternalRouteCertificate, err
	}
	domain, err := p.cfg.routeDomain()
	return domain, p.cfg.RouteCertificate, err
}

// planRouting composes route hostnames and the ingress that lets traffic reach
// the workload.
func (p *Plan) planRouting() error {
	if p.app.Execution == ExecutionScheduled && len(p.app.Routes) > 0 {
		// A scheduled job has no routes to carry: compute.ScheduledJobSpec has
		// no Routes field, because a workload that only exists while it is
		// running is not something a hostname can point at. Planning them and
		// then dropping them on the way into the specification would publish
		// nothing while the record said otherwise, so it is refused.
		return fmt.Errorf("%w: this application runs on a schedule and also asks to be "+
			"published on %d route(s); a scheduled workload is not running between "+
			"executions and there is nothing for a hostname to reach",
			ErrInvalidApplication, len(p.app.Routes))
	}
	if len(p.app.Routes) == 0 {
		// No route means nothing outside reaches it. There is deliberately no
		// ingress rule at all in that case: a workload nobody publishes is a
		// workload nobody should be able to open a connection to.
		return nil
	}
	seen := map[string]bool{}
	for i, r := range p.app.Routes {
		domain, certificate, err := p.routeTarget(r)
		if err != nil {
			return err
		}
		host := strings.TrimSpace(strings.ToLower(r.Hostname))
		if host == "" {
			return fmt.Errorf("%w: route %d asks to be published and names no hostname. The "+
				"source derived one from the application name here, and stopped, because a "+
				"derived hostname is one nobody reserved (container.go:1341-1348)",
				ErrInvalidApplication, i)
		}
		if strings.ContainsAny(host, "./ ") {
			return fmt.Errorf("%w: route hostname %q must be a single label; it is published "+
				"under the configured domain, and a label containing a dot would publish it "+
				"somewhere else", ErrInvalidApplication, r.Hostname)
		}
		full := host + "." + domain
		if seen[full] {
			return fmt.Errorf("%w: two routes both publish %q", ErrInvalidApplication, full)
		}
		seen[full] = true
		route := compute.Route{
			Host: full,
			// The application's own port, always. compute.Route can target any
			// port the workload declares; this module declares exactly one, so
			// a settable target here would offer a choice the model cannot
			// honour -- and review reproduced that: a route targeting a port the
			// workload does not declare reached the provider and was refused
			// there, after four resources existed. The field is gone rather than
			// checked.
			TargetPort:           p.app.Port,
			AllowPlaintext:       r.AllowPlaintext,
			RequireAuth:          r.RequireAuth,
			PublicPaths:          append([]string(nil), r.PublicPaths...),
			MCPAuthApplicationID: r.MCPAuthApplicationID,
			Internal:             r.Internal,
		}
		if !r.AllowPlaintext {
			cert := strings.TrimSpace(certificate)
			if cert == "" {
				return fmt.Errorf("%w: route %q is served over TLS and no route certificate is "+
					"configured. Serving it in the clear instead is the one thing this must not "+
					"do silently, so set the certificate or set AllowPlaintext on the route",
					ErrNotConfigured, full)
			}
			route.TLS = &compute.TLSConfig{CertificateRef: cert}
		}
		p.Routes = append(p.Routes, route)
	}
	// One rule, from the platform's own ingress proxy. The source put the
	// application's port on a security group whose source was the VPC
	// (build.go:820-848: the platform's proxy when an operator had configured
	// one, and 0.0.0.0/0 when they had not). PeerPlatformIngress says what was meant,
	// and a provider with no ingress proxy refuses it rather than widening it
	// to the internet.
	p.Ingress = []compute.IngressRule{{
		From:        compute.Peer{Kind: compute.PeerPlatformIngress},
		Port:        p.app.Port,
		Protocol:    compute.ProtocolTCP,
		Description: "the platform ingress proxy, which is what publishes this application",
	}}
	return nil
}

// planRequired derives every provider capability this plan needs.
//
// Derived from the plan rather than listed: each entry is produced by the same
// field that produced the specification needing it, so a specification added
// without its capability is a compile-time edit in one place instead of two
// lists to keep in step.
func (p *Plan) planRequired() {
	need := map[compute.Capability]struct{}{
		compute.CapImageRegistry: {},
		compute.CapImageBuild:    {},
	}
	need[compute.CapContainerService] = struct{}{}
	if p.app.Execution == ExecutionScheduled {
		need[compute.CapScheduledJob] = struct{}{}
	}
	if p.Relational != nil {
		need[compute.CapRelationalDatabase] = struct{}{}
		need[compute.CapSecretStore] = struct{}{}
	}
	if p.KeyValue != nil {
		need[compute.CapKeyValueTable] = struct{}{}
	}
	if p.Bucket != nil {
		need[compute.CapObjectStore] = struct{}{}
		if p.Bucket.Class == compute.ObjectClassZonal {
			need[compute.CapObjectStoreZonal] = struct{}{}
		}
	}
	if len(p.app.Secrets) > 0 || len(p.EnvSecrets) > 0 {
		need[compute.CapSecretStore] = struct{}{}
	}
	// Only the ports that embed compute.Granter, which compute.WorkloadGrantPorts
	// names: a relational database is reached with credentials rather than with
	// a grant, so requiring the capability for one would refuse a provider that
	// is perfectly able to do what this application asked.
	if p.KeyValue != nil || p.Bucket != nil {
		need[compute.CapWorkloadGrants] = struct{}{}
	}
	if len(p.Routes) > 0 {
		need[compute.CapPlatformIngress] = struct{}{}
		for _, r := range p.Routes {
			if r.RequireAuth {
				need[compute.CapIngressAuth] = struct{}{}
			}
			if r.MCPAuthApplicationID != "" {
				need[compute.CapMCPAuth] = struct{}{}
			}
		}
	}
	for _, c := range p.app.Capabilities {
		if req := c.Requires(); req != "" {
			need[req] = struct{}{}
		}
	}
	p.Required = make([]compute.Capability, 0, len(need))
	for c := range need {
		p.Required = append(p.Required, c)
	}
	sort.Slice(p.Required, func(i, j int) bool { return p.Required[i] < p.Required[j] })
}

// checkCapabilities reports every capability the plan needs that the provider
// does not advertise, before anything is created.
func (p *Plan) checkCapabilities(caps compute.CapabilitySet) error {
	var missing []string
	for _, c := range p.Required {
		if !caps.Has(c) {
			missing = append(missing, string(c))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: provider %q does not offer %s, which this application needs",
			compute.ErrUnsupported, p.provider, strings.Join(missing, ", "))
	}
	return nil
}

// ValidateApplication checks an application against nonsecret target metadata
// without constructing a provider or acquiring worker credentials.
func ValidateApplication(cfg Config, app *Application, providerName string, capabilities compute.CapabilitySet) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	plan, err := newPlan(cfg, app, providerName)
	if err != nil {
		return err
	}
	return plan.checkCapabilities(capabilities)
}

// resolved is what a deploy learns as it goes: values a specification needs and
// a plan cannot know.
type resolved struct {
	image    compute.ImageRef
	identity compute.Ref
	env      []compute.EnvVar
	secrets  []compute.SecretBinding
}

// Service completes the long-running-workload specification.
func (p *Plan) Service(r resolved) compute.ServiceSpec {
	replicas := p.app.Replicas
	if replicas < 1 {
		replicas = 1
	}
	return compute.ServiceSpec{
		Name:      p.Name,
		Placement: p.cfg.Placement,
		Image:     r.image,
		Resources: p.app.Resources,
		Replicas:  replicas,
		Ports: []compute.PortSpec{{
			Number:   p.app.Port,
			Protocol: compute.ProtocolTCP,
			Name:     "app",
		}},
		Env:          r.env,
		Secrets:      r.secrets,
		Identity:     r.identity,
		Capabilities: append([]compute.WorkloadCapability(nil), p.app.Capabilities...),
		// Off. The source turned ECS Exec on for every service it created
		// (container.go:879 and :901), which is an interactive shell
		// in every application container in the fleet. It is a debugging
		// affordance, and a debugging affordance that is on by default is a
		// standing capability.
		ExecEnabled: false,
		Ingress:     p.Ingress,
		Routes:      p.Routes,
		Labels:      p.Labels,
	}
}

// ScheduledJob completes the scheduled-workload specification.
func (p *Plan) ScheduledJob(r resolved) compute.ScheduledJobSpec {
	return compute.ScheduledJobSpec{
		Name:         p.Name,
		Schedule:     p.app.Schedule,
		Placement:    p.cfg.Placement,
		Image:        r.image,
		Resources:    p.app.Resources,
		Env:          r.env,
		Secrets:      r.secrets,
		Identity:     r.identity,
		Capabilities: append([]compute.WorkloadCapability(nil), p.app.Capabilities...),
		Ingress:      p.Ingress,
		Labels:       p.Labels,
	}
}

// enginePort is the port a SQL engine listens on.
//
// The default port of a protocol is not a cloud identifier — every Postgres in
// the world is on 5432 — so it is a constant rather than configuration. What it
// must not be is a guess: an engine this function does not recognise is refused,
// because the alternative is an ingress rule on the wrong port, which is a
// database the application cannot reach and an operator debugging the
// application instead of the rule.
func enginePort(engine compute.SQLEngine) (int, error) {
	switch engine {
	case compute.EnginePostgres:
		return 5432, nil
	case compute.EngineMySQL:
		return 3306, nil
	default:
		return 0, fmt.Errorf("%w: no default port is known for engine %q, and guessing one "+
			"would authorise the wrong port", ErrInvalidApplication, engine)
	}
}

// RelationalIngress is the complete inbound rule set for the application's
// database, once the workload that reaches it exists.
//
// The set is declarative: whatever a provider had before is replaced by exactly
// this. One rule, one peer, one port. The source authorised the control plane
// onto the database as well, so that deploy-time SQL could run
// (container.go:349 calling database.go:206); nothing in this module issues SQL,
// so that rule would be an opening with nothing behind it.
func (p *Plan) RelationalIngress(workloadRef compute.Ref) ([]compute.IngressRule, error) {
	if p.Relational == nil {
		return nil, nil
	}
	port, err := enginePort(p.Relational.Engine)
	if err != nil {
		return nil, err
	}
	if workloadRef.IsZero() {
		return nil, fmt.Errorf("%w: the database's only permitted peer is the application's own "+
			"workload, and no workload reference was recorded", ErrInvalidApplication)
	}
	return []compute.IngressRule{{
		From:        compute.Peer{Kind: compute.PeerWorkload, Workload: workloadRef},
		Port:        port,
		Protocol:    compute.ProtocolTCP,
		Description: "the application workload, and nothing else",
	}}, nil
}

// attestation is the identity policy this deploy persists for the workload.
//
// The subject is the identity the provider issued, read back from what it
// returned rather than composed here: composing it would make this module a
// second opinion about a provider's own naming, which is the thing the port was
// written to remove.
func attestation(identity *compute.WorkloadIdentity) workload.ExpectedAttestation {
	if identity == nil {
		return workload.ExpectedAttestation{}
	}
	return identity.Attestation
}
