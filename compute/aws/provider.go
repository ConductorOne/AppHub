// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/conductorone/apphub/compute"
)

// Provider implements [compute.Provider] on AWS.
type Provider struct {
	sub  *Substrate
	cfg  Config
	name string
	caps compute.CapabilitySet

	// secret is the SSM-backed secret store, nil when Config.Secrets is nil.
	secret *secretStore

	// emitMu guards emissions, which are markers a test asked this provider to
	// put into a named channel so that a check scanning that channel can first
	// establish it carries anything at all. See [Harness.EmitInto]. Nothing in
	// the ordinary path writes it.
	emitMu    sync.Mutex
	emissions map[string]string
}

// emission returns what a test asked this provider to emit into channel, as a
// string safe to append to whatever the channel carries. Empty when nothing was
// asked for, so the ordinary path is unchanged.
func (p *Provider) emission(channel string) string {
	p.emitMu.Lock()
	defer p.emitMu.Unlock()
	if m := p.emissions[channel]; m != "" {
		return " " + m
	}
	return ""
}

var _ compute.Provider = (*Provider)(nil)

// New constructs a provider over sub with cfg.
//
// It validates the configuration rather than deferring every mistake to the
// first call, because a provider that cannot work is better discovered by the
// operator who configured it than by the deploy that needed it. The errors name
// the field.
func New(sub *Substrate, cfg Config) (*Provider, error) {
	if sub == nil {
		return nil, errors.New("aws: a provider needs a substrate; see aws.NewMemorySubstrate " +
			"for tests and aws.NewSDKSubstrate for a real account")
	}
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, errors.New("aws: Config.Region is required and has no default; every " +
			"deployment-specific identifier in this package is configuration")
	}
	if strings.Contains(cfg.Name, ":") {
		// A Ref renders as "provider:kind:id" and [compute.ParseRef] splits only
		// twice, which accounts for colons in the ID and cannot account for one
		// in the provider name. Measured rather than reasoned about: a Ref with
		// Provider "aws:prod" renders as "aws:prod:secret:parameter/…" and parses
		// back as Provider "aws", Kind "prod" — WITHOUT AN ERROR. So a persisted
		// reference silently becomes one this provider then rejects as foreign,
		// and the resource it names can no longer be found or torn down.
		//
		// Refused here because that is the only place it can be refused: the
		// damage happens in a caller's storage, long after the Ref was issued,
		// and nothing downstream can tell a mangled reference from a foreign one.
		return nil, errors.New("aws: Config.Name may not contain a colon; a compute.Ref renders " +
			"as \"provider:kind:id\" and parses by splitting twice, so a colon in the provider " +
			"name makes every reference this provider issues parse back as a different one")
	}
	if sub.IAM == nil {
		return nil, errors.New("aws: Substrate.IAM is required; workload identity is not " +
			"capability-gated, because a workload with no identity cannot be granted access " +
			"to anything")
	}
	if len(cfg.Placements) == 0 {
		return nil, errors.New("aws: Config.Placements is empty, so every spec would be refused; " +
			"configure at least one placement")
	}
	if cfg.DefaultPlacement != "" {
		if _, ok := cfg.Placements[cfg.DefaultPlacement]; !ok {
			return nil, fmt.Errorf("aws: Config.DefaultPlacement %q is not in Config.Placements %v",
				cfg.DefaultPlacement, cfg.placementNames())
		}
	}
	if cfg.Registry != nil && sub.ECR == nil {
		return nil, errors.New("aws: Config.Registry is set and Substrate.ECR is nil, so the " +
			"provider would advertise a capability it cannot serve")
	}
	if cfg.ObjectStore != nil {
		switch {
		case sub.S3 == nil:
			return nil, errors.New("aws: Config.ObjectStore is set and Substrate.S3 is nil, so " +
				"the provider would advertise a capability it cannot serve")
		case cfg.ObjectStore.TableBuckets && sub.S3Tables == nil:
			return nil, errors.New("aws: Config.ObjectStore.TableBuckets is set and " +
				"Substrate.S3Tables is nil; the ext port would be advertised through " +
				"Options.ImplementsExt and then refuse every call")
		case cfg.ObjectStore.VectorBuckets && sub.S3Vectors == nil:
			return nil, errors.New("aws: Config.ObjectStore.VectorBuckets is set and " +
				"Substrate.S3Vectors is nil; same reason as TableBuckets")
		}
	}
	if cfg.Build != nil {
		switch {
		case cfg.Registry == nil:
			return nil, errors.New("aws: Config.Build is set without Config.Registry; this " +
				"builder pushes only to repositories this provider issued, so a builder with " +
				"no registry could never be given a legal destination")
		case sub.STS == nil || sub.Builder == nil || sub.Pusher == nil:
			return nil, errors.New("aws: Config.Build is set and Substrate.STS, " +
				"Substrate.Builder or Substrate.Pusher is nil, so a build could not mint a " +
				"scoped credential, run, or publish what it produced")
		case strings.TrimSpace(cfg.Build.ExecutorPath) == "":
			return nil, errors.New("aws: Config.Build.ExecutorPath is required and has no " +
				"default; where the builder binary lives is a property of the image apphub runs in")
		case strings.TrimSpace(cfg.Build.PusherPath) == "":
			// Refused rather than defaulted to the executor, which would put the
			// push back in the process that ran the Dockerfile -- the whole of
			// what USOSS-41 removed. See BuildConfig.PusherPath.
			return nil, errors.New("aws: Config.Build.PusherPath is required and has no " +
				"default: this provider builds with no push credential and publishes from a " +
				"separate process, so there is nothing sensible to fall back to")
		case cfg.Build.validateSessionDuration() != nil:
			return nil, fmt.Errorf("aws: %w", cfg.Build.validateSessionDuration())
		case strings.TrimSpace(cfg.Build.PushRoleARN) == "":
			// The source system's fail-closed refusal, moved to construction.
			// See BuildConfig.PushRoleARN for why there is no fallback.
			return nil, errors.New("aws: Config.Build.PushRoleARN is required and has no " +
				"default: refusing to configure a builder that would run a repository-authored " +
				"build with apphub's own credentials")
		}
	}
	if cfg.Function != nil {
		switch {
		case sub.Lambda == nil:
			return nil, errors.New("aws: Config.Function is set and Substrate.Lambda is nil, so " +
				"the provider would advertise a capability it cannot serve")
		case len(cfg.Function.Runtimes) == 0:
			// No default, and no "accept whatever the caller sends" either. See
			// FunctionConfig.Runtimes.
			return nil, errors.New("aws: Config.Function.Runtimes is empty, so every function " +
				"spec would be refused; list the runtimes this deployment allows")
		}
		if err := validateNamePrefix("Config.Function.NamePrefix", cfg.Function.NamePrefix); err != nil {
			return nil, err
		}
		switch cfg.Function.DefaultArchitecture {
		case "", compute.ArchAMD64, compute.ArchARM64:
		default:
			return nil, fmt.Errorf("aws: Config.Function.DefaultArchitecture %q is not an "+
				"architecture the interface defines", cfg.Function.DefaultArchitecture)
		}
	}
	if cfg.Endpoint != nil {
		switch {
		case cfg.Function == nil:
			return nil, errors.New("aws: Config.Endpoint is set without Config.Function; an " +
				"endpoint is reached through the function port and fronts a function, so an " +
				"endpoint configuration with no function runtime could never be used")
		case sub.ELBv2 == nil || sub.EndpointEC2 == nil:
			return nil, errors.New("aws: Config.Endpoint is set and Substrate.ELBv2 or " +
				"Substrate.EndpointEC2 is nil; an endpoint is a load balancer plus the security " +
				"group that fronts it, and neither can be created without both")
		}
		if err := validateNamePrefix("Config.Endpoint.NamePrefix", cfg.Endpoint.NamePrefix); err != nil {
			return nil, err
		}
		// Checked at construction because a placement carrying SOME subnets but
		// fewer than an application load balancer needs can never carry an
		// endpoint, and the operator who configured the placement is the person
		// who can fix it. A placement's *contents* are still checked again at
		// Ensure against what EC2 reports — this only catches the absence.
		//
		// A placement with NO subnets at all is not refused here. A placement
		// may legitimately exist for another capability only -- USOSS-26's
		// secret store keeps parameters per region with no network footprint at
		// all, and USOSS-11's container port and USOSS-14's relational port
		// each refuse their own half-configured placements independently
		// rather than requiring every placement to serve every capability a
		// Config advertises. Refusing an EMPTY placement here would be the same
		// shape of false refusal TestANonContainerPlacementIsNotRefusedButAHalfConfiguredOneIs
		// pins for the container port: a guard aimed at a half-configured
		// placement firing on a legitimate one that configures nothing here at
		// all.
		for _, name := range cfg.placementNames() {
			n := len(cfg.Placements[name].SubnetIDs)
			if n > 0 && n < minEndpointSubnets {
				return nil, fmt.Errorf("aws: Config.Endpoint is set and placement %q has %d "+
					"subnets; an application load balancer needs at least %d, in at least %d "+
					"availability zones", name, n, minEndpointSubnets, minEndpointZones)
			}
		}
	}
	if cfg.Secrets != nil && sub.Parameters == nil {
		return nil, errors.New("aws: Config.Secrets is set and Substrate.Parameters is nil, so " +
			"the provider would advertise a secret store it cannot serve — and if this were " +
			"allowed to default to the in-memory store, a production deployment would write " +
			"credentials into RAM and report success")
	}
	if err := validateRelationalConfig(sub, cfg); err != nil {
		return nil, err
	}
	if err := validateKeyValueConfig(sub, cfg); err != nil {
		return nil, err
	}
	if cfg.Container != nil {
		if sub.ECS == nil {
			return nil, errors.New("aws: Config.Container is set and Substrate.ECS is nil, so the " +
				"provider would advertise a container runtime it cannot serve")
		}
		if sub.EC2 == nil {
			return nil, errors.New("aws: Config.Container is set and Substrate.EC2 is nil; the " +
				"container port writes ServiceSpec.Ingress onto a per-service security group, and " +
				"a runtime that could not would have to ignore a reachability rule")
		}
		if err := validateTLSTermination(cfg.Container); err != nil {
			return nil, err
		}
		// Every placement that is MEANT for containers, not every placement.
		//
		// The original rule was every placement, on the reasoning that a
		// half-configured one would be accepted at construction and refused at
		// deploy, and the operator who mis-configured it is not the person who
		// would see that. That reasoning still holds for a half-configured
		// placement and it was wrong about a placement with nothing at all.
		//
		// USOSS-26's #49 has the counter-example: a placement that exists only
		// to hold secrets in another region has no ECS cluster, no subnets and
		// no VPC, and is a perfectly good placement. Refusing it at construction
		// is a FALSE REFUSAL of a legal configuration — the mirror of the defect
		// this check exists to prevent, and the same shape as the ICMP bound
		// that refused a legal wildcard because it had been written to catch a
		// sentinel.
		//
		// So a placement carrying NONE of the three is a non-container placement
		// and is skipped; a service that names it is refused at Ensure, where
		// the error can say which field is missing. A placement carrying SOME of
		// them is still refused here, because that is the half-configured case
		// the check was written for and the one an operator cannot see.
		//
		// Checked in sorted order so the error is deterministic.
		for _, name := range cfg.placementNames() {
			pc := cfg.Placements[name]
			if strings.TrimSpace(pc.ClusterARN) == "" && len(pc.Subnets) == 0 &&
				strings.TrimSpace(pc.VPC) == "" {
				continue
			}
			if strings.TrimSpace(pc.ClusterARN) == "" {
				return nil, fmt.Errorf("aws: placement %q has no ClusterARN and a container "+
					"runtime is configured; every placement a service can name needs one", name)
			}
			if len(pc.Subnets) == 0 {
				return nil, fmt.Errorf("aws: placement %q has no Subnets and a container "+
					"runtime is configured; an awsvpc task cannot be placed without one", name)
			}
			if strings.TrimSpace(pc.VPC) == "" {
				return nil, fmt.Errorf("aws: placement %q has no VPC and a container runtime is "+
					"configured; a security group cannot be created without one", name)
			}
		}
	}

	caps := cfg.capabilities()
	if cfg.Container != nil && sub.Scheduler != nil {
		caps[compute.CapScheduledJob] = struct{}{}
	}
	p := &Provider{sub: sub, cfg: cfg, name: cfg.name(), caps: caps}
	if cfg.Secrets != nil {
		store, err := newSecretStore(p, *cfg.Secrets)
		if err != nil {
			return nil, fmt.Errorf("aws: Config.Secrets: %w", err)
		}
		p.secret = store
	}
	return p, nil
}

// Name reports the provider name recorded in every [compute.Ref] it issues.
func (p *Provider) Name() string { return p.name }

// Capabilities reports what this instance can do, derived from its
// configuration.
func (p *Provider) Capabilities() compute.CapabilitySet { return p.caps }

// Identities vends the workload-identity port. Never refused.
func (p *Provider) Identities() compute.IdentityService { return &identityService{p: p} }

// Registry vends the image-repository port.
func (p *Provider) Registry() (compute.ImageRegistry, error) {
	if !p.caps.Has(compute.CapImageRegistry) {
		return nil, p.unsupported(compute.CapImageRegistry,
			"no container registry is configured on this provider")
	}
	return &imageRegistry{p: p}, nil
}

// Functions vends the function-runtime port.
//
// The endpoint half of it is gated separately, inside the port, because
// [compute.FunctionRuntime] is one interface covering two capabilities: a
// deployment can run functions with no load balancer configured at all, which is
// what the source system does whenever its needsAlb parameter is false
// (lambda.go:123). So this accessor answers for [compute.CapFunction] and
// [functionRuntime.EnsureEndpoint] answers for [compute.CapFunctionEndpoint].
func (p *Provider) Functions() (compute.FunctionRuntime, error) {
	if !p.caps.Has(compute.CapFunction) {
		return nil, p.unsupported(compute.CapFunction,
			"no function runtime is configured on this provider")
	}
	return &functionRuntime{p: p}, nil
}

// Builder vends the image-build port.
func (p *Provider) Builder() (compute.ImageBuilder, error) {
	if !p.caps.Has(compute.CapImageBuild) {
		return nil, p.unsupported(compute.CapImageBuild,
			"no image builder is configured on this provider")
	}
	return &imageBuilder{p: p}, nil
}

// Containers vends the container-runtime port, backed by ECS on Fargate.
func (p *Provider) Containers() (compute.ContainerRuntime, error) {
	if !p.caps.Has(compute.CapContainerService) {
		return nil, p.unsupported(compute.CapContainerService,
			"no container runtime is configured on this provider")
	}
	return &containerRuntime{p: p}, nil
}

// ObjectStores vends the object-storage port. Not implemented here.
func (p *Provider) ObjectStores() (compute.ObjectStore, error) {
	if p.cfg.ObjectStore == nil {
		return nil, p.unsupported(compute.CapObjectStore,
			"set Config.ObjectStore to enable general-purpose object storage")
	}
	if p.sub.S3 == nil {
		return nil, p.unsupported(compute.CapObjectStore,
			"Config.ObjectStore is set but the substrate has no S3 client")
	}
	return &objectStore{p: p}, nil
}

// Relational vends the managed-SQL port.
func (p *Provider) Relational() (compute.RelationalProvisioner, error) {
	if !p.caps.Has(compute.CapRelationalDatabase) {
		return nil, p.unsupported(compute.CapRelationalDatabase,
			"no relational database is configured on this provider")
	}
	return &relationalProvisioner{p: p}, nil
}

// KeyValues vends the key-value-table port.
func (p *Provider) KeyValues() (compute.KeyValueProvisioner, error) {
	if !p.caps.Has(compute.CapKeyValueTable) {
		return nil, p.unsupported(compute.CapKeyValueTable,
			"no key-value table service is configured on this provider")
	}
	return &keyValueProvisioner{p: p}, nil
}

// Secrets vends the secret-store port, backed by SSM Parameter Store.
func (p *Provider) Secrets() (compute.SecretStore, error) {
	if p.secret == nil {
		return nil, p.unsupported(compute.CapSecretStore,
			"no Config.Secrets is configured on this provider")
	}
	return p.secret, nil
}

func (p *Provider) unsupported(c compute.Capability, detail string) error {
	return &compute.UnsupportedError{Provider: p.name, Capability: c, Detail: detail}
}

// --- reference handling ------------------------------------------------------

// resourceOf names the substrate resource behind each kind this provider
// issues. A [compute.Ref] whose ID does not start with the right one addresses
// something this provider did not create.
var resourceOf = map[compute.Kind]string{
	compute.KindImageRepository:  "repository",
	compute.KindWorkloadIdentity: "role",
	compute.KindFunction:         "function",
	compute.KindFunctionEndpoint: "endpoint",
	compute.KindSecret:           "parameter",
	compute.KindRelational:       "cluster",
	compute.KindKeyValueTable:    "table",

	compute.KindService:      "service",
	compute.KindScheduledJob: "schedule",
	compute.KindBucket:       "bucket",
}

// ref builds a reference for a resource this provider owns.
//
// The ID is "<resource>/<name>" and not an ARN.
//
// For a secret that reads as "parameter//apphub/…", with two slashes, and the
// second one is the parameter name's own leading slash surviving intact. It has
// to survive: an SSM parameter name begins with a slash, and a Ref that dropped
// it would resolve back to a name the service rejects. The ID is opaque to
// callers, so the only property that matters is that resolve returns exactly
// what ref was given -- which the uniform "<resource>/" prefix gives, without
// this kind needing a special case in either direction. An ARN would be the obvious
// choice and is the source system's (bucket.go:194-215), and it is the wrong
// one here for two reasons: it embeds the account identifier in every reference
// the deploy layer persists, and it makes a Ref valid only while the account
// and region it was issued against are the ones configured. The name is what
// this provider actually looks a resource up by; the ARN is read back from the
// substrate when a policy needs one.
func (p *Provider) ref(kind compute.Kind, name string) compute.Ref {
	return compute.Ref{Provider: p.name, Kind: kind, ID: resourceOf[kind] + "/" + name}
}

// Bucket flavours.
//
// Three different services provision something this interface calls a bucket,
// and [compute.KindBucket] is the only kind available for all three. So the
// flavour lives in the Ref's ID, which is what makes a table bucket's Ref
// distinguishable from a general-purpose bucket's.
//
// It has to be. [ext.TableBucketProvisioner.Grant] has the same signature as
// [compute.Granter.Grant] and takes the same kind, so a single Grant
// implementation serving all three cannot know which service to check ownership
// against unless the Ref says. Without the flavour, granting on a table bucket
// would read the *general-purpose* bucket of that name -- a different resource,
// possibly somebody else's -- and two buckets with one logical name would also
// contend for one inline-policy name, so a grant on one would silently overwrite
// the grant on the other.
const (
	flavourBucket       = "bucket"
	flavourTableBucket  = "tablebucket"
	flavourVectorBucket = "vectorbucket"
)

// flavouredRef addresses one of the three bucket flavours.
func (p *Provider) flavouredRef(flavour, name string) compute.Ref {
	return compute.Ref{Provider: p.name, Kind: compute.KindBucket, ID: flavour + "/" + name}
}

// resolveFlavoured resolves a bucket Ref and requires it to be the named flavour.
//
// A flavour mismatch is [compute.ErrInvalidSpec] rather than [compute.ErrNotFound]:
// the resource may well exist, and the caller has reached the wrong port for it.
// Reporting "not found" would send them looking for a missing bucket.
func (p *Provider) resolveFlavoured(ref compute.Ref, flavour string) (string, error) {
	if ref.Provider != p.name {
		return "", fmt.Errorf("%w: %s was issued by %q, this provider is %q",
			compute.ErrForeignRef, ref, ref.Provider, p.name)
	}
	if ref.Kind != compute.KindBucket {
		return "", fmt.Errorf("%w: %s addresses a %q, this call takes a %q",
			compute.ErrInvalidSpec, ref, ref.Kind, compute.KindBucket)
	}
	name, ok := strings.CutPrefix(ref.ID, flavour+"/")
	if !ok || name == "" {
		return "", fmt.Errorf("%w: %s does not address a %s issued by this provider",
			compute.ErrInvalidSpec, ref, flavour)
	}
	return name, nil
}

// bucketFlavour reports which of the three a Ref addresses.
func bucketFlavour(ref compute.Ref) (string, error) {
	for _, f := range []string{flavourTableBucket, flavourVectorBucket, flavourBucket} {
		if strings.HasPrefix(ref.ID, f+"/") {
			return f, nil
		}
	}
	return "", fmt.Errorf("%w: %s does not name a bucket flavour this provider issues",
		compute.ErrInvalidSpec, ref)
}

// resolve checks a [compute.Ref] belongs to this provider and addresses the
// expected kind, and returns the substrate name inside it.
func (p *Provider) resolve(ref compute.Ref, kind compute.Kind) (string, error) {
	if ref.Provider != p.name {
		return "", fmt.Errorf("%w: %s was issued by %q, this provider is %q%s",
			compute.ErrForeignRef, ref, ref.Provider, p.name, p.emission(ChannelCallError))
	}
	if ref.Kind != kind {
		return "", fmt.Errorf("%w: %s addresses a %q, this call takes a %q",
			compute.ErrInvalidSpec, ref, ref.Kind, kind)
	}
	prefix := resourceOf[kind] + "/"
	name, ok := strings.CutPrefix(ref.ID, prefix)
	if !ok || name == "" {
		return "", fmt.Errorf("%w: %s does not address a resource this provider issued",
			compute.ErrInvalidSpec, ref)
	}
	return name, nil
}

// --- error mapping ------------------------------------------------------------

// substrateError maps a substrate error onto the [compute] taxonomy.
//
// The taxonomy is the whole point of the boundary. The source system branches
// on AWS error shapes directly and in three different styles — a substring
// match for "RepositoryNotFoundException" (build.go:434-441), errors.As against
// a typed exception (bucket.go:232), a smithy error code (build.go:872-878) —
// and every one of those is a provider dependency hiding in a conditional above
// the boundary.
//
// The mapping that matters most is [ErrThrottled]. Six AWS providers are being
// written against this taxonomy, and the one that maps a throttle to
// [compute.ErrFailed] tells its caller the spec has to change when the deploy
// would have succeeded on a retry. That is not a mistake a reviewer reliably
// spots in a switch with twenty arms, so it has a test of its own.
//
// NO ARM RETURNS THE INCOMING err. Every member of [Substrate] -- ECR, IAM,
// STS, Builder and the rest alike -- is an interface a caller can supply its
// own adapter for (see [Substrate]'s own doc comment: the seam exists for
// testability AND so a reviewer can name every credential-bearing call site by
// reading one interface). That means the text of err is written by whoever
// supplied THAT adapter, in-house SDK code or not, and none of it is text this
// package can show to a caller without having verified it first -- which it
// has not. [secretStore.wrap] hit the identical shape on the one substrate
// port (Parameters) that handles secret material and was fixed in #19 by
// classifying without retaining: match the sentinel with errors.Is, then
// answer with a fixed, taxonomy-only message this package owns. The fix here
// is the same pattern applied to every arm of this switch, not just the ones
// that happen to run over a substrate this package also implements itself:
// the in-memory and SDK substrates are foreign-text sources too (ssmError, for
// instance, carries the AWS SDK's own message on every arm), so "our own
// substrate" is not a safe category to exempt.
//
// [TestNoArmOfSubstrateErrorReturnsTheIncomingError] asserts this structurally,
// the same way [TestNoArmOfWrapReturnsTheIncomingError] does for wrap: it reads
// this function's own AST rather than a table of inputs, so an arm added later
// without updating a test cannot slip past it.
func (p *Provider) substrateError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrNoSuchResource):
		return fmt.Errorf("%w: the substrate reported no such resource", compute.ErrNotFound)
	case errors.Is(err, ErrThrottled):
		return fmt.Errorf("%w: the substrate throttled this request", compute.ErrTransient)
	case errors.Is(err, ErrNameTaken):
		// A global namespace, and the name is somebody else's. Not
		// ErrAlreadyExists' transient reading: that one is this account racing
		// itself and the loser adopts on the next pass, while this one never
		// resolves however many times it is retried. compute.ErrNotOwned is its
		// definition -- "the desired name is taken by a resource this platform
		// does not own" -- and it sends the operator to the name, which is the
		// only thing that can change the outcome.
		return fmt.Errorf("%w: the requested name belongs to another account", compute.ErrNotOwned)
	case errors.Is(err, ErrAlreadyExists):
		// Two callers raced to create the same resource. That is not
		// ErrNotOwned — the name was not taken by somebody else's
		// infrastructure — and it is not terminal: the loser re-reads and
		// adopts on the next attempt.
		return fmt.Errorf("%w: the resource already exists", compute.ErrTransient)
	case errors.Is(err, ErrConflict):
		// Another mutation of the same resource is still in flight. Transient
		// for the same reason ErrAlreadyExists is: nothing about the spec has to
		// change, and the retry succeeds once the substrate settles. Lambda
		// serialises a configuration update against a code update on one
		// function, so this is the ordinary outcome of a redeploy that changes
		// both — see [functionRuntime.EnsureFunction].
		return fmt.Errorf("%w: another update to this resource is still in progress", compute.ErrTransient)
	case errors.Is(err, ErrDenied):
		// A denial is the credentials this provider runs with lacking a
		// permission, which is neither of the two things ErrFailed promises: no
		// resource reached a terminal phase, and nothing about the spec will
		// change the outcome. It routed here because compute.ErrNotPermitted did
		// not exist when this mapping was written; it merged in #24, which is
		// this commit's own parent.
		//
		// The practical difference is who gets paged. ErrFailed sends an operator
		// to the resource; ErrNotPermitted sends them to the platform's IAM role,
		// which is the only place the fix can be applied.
		return fmt.Errorf("%w: the substrate denied this request", compute.ErrNotPermitted)
	case errors.Is(err, ErrMalformed):
		// Not ErrFailed, and emphatically not ErrNotFound. An input the service
		// could not parse is a spec error the caller must fix; absence is a
		// state the caller may create, and conflating the two is what made a
		// malformed identifier read back as "no ingress rules". See
		// [ErrMalformed].
		return fmt.Errorf("%w: the substrate could not parse this input", compute.ErrInvalidSpec)
	case errors.Is(err, context.Canceled):
		// The caller asked to stop. Answering with the canonical sentinel rather
		// than the incoming err matters twice over: "try again" (ErrTransient)
		// inverts the instruction the caller just gave, and the incoming err is
		// only known to WRAP context.Canceled -- an adapter reports its own
		// cancellation as e.g. fmt.Errorf("whatever: %w", context.Canceled), so
		// returning err verbatim (the previous behaviour) would still be the
		// seventh, self-inflicted foreign-text arm that [secretStore.wrap]'s
		// history warns about: a correct classification followed by returning
		// the thing just recognised, rather than a sentinel this package owns.
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		// Separate from cancellation because they are different facts to act on:
		// a deadline is the caller's own budget. Same reasoning as above for
		// answering with the sentinel rather than the incoming err.
		return context.DeadlineExceeded
	case p.cfg.IsRetryable != nil && p.cfg.IsRetryable(err):
		// The operator hook, consulted last on purpose. Every case above it is
		// one this hook must not be able to reach: it can widen what would
		// otherwise be terminal, and it cannot narrow anything, reclassify a
		// denial or an unparseable input, or answer "try again" to a cancelled
		// context. See
		// [Config.IsRetryable] for why the direction is one-way.
		return fmt.Errorf("%w: the substrate reported a failure the operator's hook classified as retryable", compute.ErrTransient)
	default:
		return fmt.Errorf("%w: the substrate reported an unclassified failure", compute.ErrFailed)
	}
}
