// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/compute/conformance"
)

// fullConfig is an account with a registry and a builder configured.
//
// Every value here is site-specific configuration, and none of it is an AWS
// identifier: the region is a placeholder word rather than a region slug, the
// push role's ARN carries a word where an account number would be, and there is
// no registry host at all because the provider reads one back from the registry
// rather than composing it. That is the property this package was asked to
// hold, and this function is the evidence for it — it is the complete set of
// things an operator must supply.
func fullConfig() aws.Config {
	return aws.Config{
		Region:           aws.MemoryRegion,
		DefaultPlacement: "default",
		Placements: map[string]aws.PlacementConfig{
			// ONE placement per name carrying every port's coordinates, not one
			// per port. A placement is a place, and the relational, container
			// and function-endpoint ports put things in the same one -- so a
			// fixture with a database-only "default" and a container-only
			// "default" would be two fixtures for a configuration an operator
			// cannot write.
			//
			// The cluster, subnets and security groups are operator-supplied
			// substrate identifiers, and they are words rather than AWS-shaped
			// IDs for the same reason every other fixture here is: a fixture
			// that imitates the real shape is one somebody eventually fills in
			// with a real value.
			"default":   fullPlacement(""),
			"secondary": fullPlacement("-secondary"),
		},
		Identity: aws.IdentityConfig{
			PathPrefix: "/apphub/",
			NamePrefix: "apphub-",
			// A boundary an operator would supply. The account position holds a
			// word for the same reason every other fixture here does.
			PermissionsBoundary: "arn:aws:iam::" + aws.MemoryAccount + ":policy/apphub-boundary",
		},
		Registry: &aws.RegistryConfig{NamePrefix: "apphub/"},
		Secrets: &aws.SecretConfig{
			// A prefix an operator would supply. No account identifier appears
			// here for the same reason none appears anywhere else in this file:
			// the provider reads every ARN back from the substrate rather than
			// composing one, so it never needs to be told what account it is in.
			PathPrefix: "/apphub/conformance",
		},
		Container: &aws.ContainerConfig{
			NamePrefix:                   "apphub-",
			LogGroupPrefix:               "/apphub/",
			MCPAuthBackendURL:            "http://127.0.0.1:8080",
			IngressCookieStripMiddleware: "apphub-strip-sso-cookie@ecs",
			// No Secrets. Nil composes this provider's OWN secret store, which
			// is the composition the two ports were written for and the one the
			// conformance suite has to run against: with a stub resolver here,
			// security/secrets-do-not-cross-placements could not pass for the
			// right reason, because a stub does not know where a secret is
			// stored. The tests that need an adversarial or a broken resolver
			// set this field explicitly.
		},
		ObjectStore: &aws.ObjectStoreConfig{
			// A prefix, because an S3 bucket name is globally unique across
			// every AWS account: an unprefixed logical name would collide with
			// somebody else's bucket and the failure would arrive as an
			// authorization error rather than a name collision.
			NamePrefix:    "apphub-",
			TableBuckets:  true,
			VectorBuckets: true,
		},
		Build: &aws.BuildConfig{
			ExecutorPath: "/kaniko/executor",
			// The push runs somewhere else, which is the whole of USOSS-41. Two
			// paths in the fixture because there are two binaries in the design.
			PusherPath:  "/usr/bin/crane",
			PushRoleARN: "arn:aws:iam::" + aws.MemoryAccount + ":role/apphub-ecr-push",
		},
		Function: &aws.FunctionConfig{
			// A runtime an operator allowed, not a list this package believes in.
			Runtimes: []string{testRuntime, "nodejs20.x"},
		},
		// No NamePrefix on the endpoint, and that is a fixture decision worth
		// stating: the ELBv2 ceiling is 32 characters and the conformance suite's
		// generated names are already 22 to 24 of them, so a prefix here would
		// push the suite's own names onto the digested path as its counter grew
		// and make a passing run depend on how many checks ran before it. The
		// prefixed path is covered by TestTheFunctionPortsNamesAreInjective,
		// which quantifies over prefixes on purpose.
		Endpoint: &aws.EndpointConfig{},
		Relational: &aws.RelationalConfig{
			NamePrefix:       "apphub-",
			MaxCapacityUnits: 4, // The conformance suite changes a 2-unit range to 4.
			EngineVersions: map[compute.SQLEngine][]string{
				compute.EnginePostgres: {"15", "16"},
			},
		},
		KeyValue: &aws.KeyValueConfig{NamePrefix: "apphub-"},
		// A hermetic suite needs a fast one. It lives here, in the test's
		// configuration, rather than in the provider's default — test speed is
		// not a substrate contract, and the production default is seconds
		// precisely because the SDK's retryer bounds failures rather than
		// successful reads. See aws.DefaultPollInterval.
		PollInterval: time.Millisecond,
	}
}

// testRuntime is the runtime identifier the suite deploys with. A custom-runtime
// name, because it is the one whose handler convention this package does not
// pretend to know.
const testRuntime = "provided.al2023"

// endpointPlacement is the network configuration a placement needs to carry an
// endpoint.
//
// Every value is a placeholder from the in-memory substrate rather than anything
// AWS-shaped: the subnet identifiers are words, the availability zones are not
// real zone slugs, and the certificate ARN carries [aws.MemoryAccount] where an
// account number would go. That is the same rule the rest of this file follows,
// and it matters most here — a subnet identifier and a security group identifier
// are two of the things CONTRACT.md names explicitly as never-commit.
func endpointPlacement() aws.PlacementConfig {
	return aws.PlacementConfig{
		SubnetIDs:                      []string{aws.MemorySubnetA, aws.MemorySubnetB},
		PlatformIngressSecurityGroupID: aws.MemoryIngressGroup,
		Certificates:                   map[string]string{testCertificateRef: testCertificateARN},
	}
}

// The certificate reference the suite asks for, and what an operator configured
// it to mean.
const (
	testCertificateRef = "apphub-test-certificate"
	testCertificateARN = "arn:aws:acm:" + aws.MemoryRegion + ":" + aws.MemoryAccount +
		":certificate/placeholder"
)

// The network coordinates a placement needs to hold a database.
//
// Every value is a placeholder word rather than the real AWS shape — no
// "vpc-" followed by hex, no "subnet-" followed by hex — for the reason the
// memory substrate's own fixtures are: a synthetic identifier that imitates the
// real shape is indistinguishable from a real one to every scanner and every
// reader, and a fixture is exactly where a real one gets pasted "just for the
// test". Nothing in this package parses one.
func databasePlacement() aws.PlacementConfig {
	return aws.PlacementConfig{
		VPC: aws.MemoryVPC,
		Subnets: []string{
			"apphub-test-subnet-one",
			"apphub-test-subnet-two",
		},
		ControlPlaneSecurityGroups: []string{"apphub-test-control-plane-sg"},
	}
}

// containerPlacement adds the container port's coordinates to a placement that
// already carries the relational port's.
//
// Composed rather than written out twice, because the overlap is the point: VPC
// is one field both ports read, and a fixture that declared it twice could
// declare it differently and still pass.
func containerPlacement(pc aws.PlacementConfig, suffix string) aws.PlacementConfig {
	pc.VPC = aws.MemoryVPC + suffix
	pc.ClusterARN = aws.MemoryCluster + suffix
	pc.SecurityGroups = []string{"group-baseline"}
	pc.PlatformIngressSecurityGroups = []string{"group-platform-ingress"}
	return pc
}

// fullPlacement is a placement carrying every port's network configuration at
// once — the function-endpoint's, the relational port's, and the container
// port's — because [Config.Placements] is one map serving every port this
// provider vends, and a conformance run against fullConfig drives all three.
//
// suffix distinguishes "default" from "secondary" the same way
// containerPlacement does: two placements sharing one VPC and one cluster
// would not be two placements an operator could tell apart.
func fullPlacement(suffix string) aws.PlacementConfig {
	ep := endpointPlacement()
	pc := containerPlacement(databasePlacement(), suffix)
	ep.VPC = pc.VPC
	ep.Subnets = pc.Subnets
	ep.ControlPlaneSecurityGroups = pc.ControlPlaneSecurityGroups
	ep.ClusterARN = pc.ClusterARN
	ep.SecurityGroups = pc.SecurityGroups
	ep.PlatformIngressSecurityGroups = pc.PlatformIngressSecurityGroups
	return ep
}

// secretStoreConfig is the full account, named for what the secret-store tests
// use it for.
//
// It is fullConfig rather than a narrower fixture on purpose: a secret store
// configured beside a registry and a builder is the shape a real deployment has,
// and running the secret tests against a provider that has nothing else would
// hide any interaction between the ports -- shared naming, shared tag budget,
// shared ownership vocabulary.
func secretStoreConfig() aws.Config { return fullConfig() }

// noSecretConfig is the full account with the secret store removed, for the
// tests that assert the typed refusal rather than the behaviour.
func noSecretConfig() aws.Config {
	cfg := fullConfig()
	cfg.Secrets = nil
	return cfg
}

// paramOf is the substrate parameter name inside a Ref this provider issued.
//
// A Ref ID is "<resource>/<name>" for every kind, so for a secret it is
// "parameter/" followed by the parameter name -- which keeps its own leading
// slash, hence the doubled slash in the middle. The prefix comes off and nothing
// else changes.
//
// A test that used ref.ID directly as a substrate name would be asserting
// against the reference rather than against what SSM holds. The two were the same
// string while this package had its own provider spine, and stopped being the
// same when USOSS-10's landed with a uniform resource prefix on every kind -- so
// this exists to make the difference explicit rather than to paper over it.
func paramOf(t *testing.T, ref compute.Ref) string {
	t.Helper()
	name, ok := strings.CutPrefix(ref.ID, "parameter/")
	if !ok || name == "" {
		t.Fatalf("aws_test: %s does not carry a parameter name", ref)
	}
	return name
}

// providerOver builds a provider over a caller-supplied substrate and config.
//
// Distinct from newProvider, which mutates the standard config over a fresh
// substrate: the secret-store tests need to hold onto the substrate they passed
// in, because half of what they assert is what ended up in it.
func providerOver(t *testing.T, sub *aws.Substrate, cfg aws.Config) *aws.Provider {
	t.Helper()
	p, err := aws.New(sub, cfg)
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	return p
}

// registrylessConfig is the same account with neither a registry nor a builder:
// a provider that can do nothing but issue identities.
//
// It exists because a suite only ever run against the full configuration never
// shows that a refusal is typed, named, and loud. This is the run in which
// every capability accessor refuses.
func registrylessConfig() aws.Config {
	cfg := fullConfig()
	cfg.Name = "aws-no-registry"
	cfg.Registry = nil
	cfg.Build = nil
	cfg.Function = nil
	cfg.Endpoint = nil
	// The secret store goes too, so this run is the one in which Secrets()
	// refuses. Leaving it configured would mean no run ever exercises the
	// refusal, and a typed refusal nobody exercises is a claim rather than a
	// behaviour.
	cfg.Secrets = nil
	cfg.Relational = nil
	cfg.KeyValue = nil
	cfg.ObjectStore = nil
	return cfg
}

// endpointlessConfig is an account that can run functions and cannot put one
// behind a hostname.
//
// It exists for one invariant that neither other configuration can reach.
// conformance.checkFunctionEndpointCapability needs a provider that advertises
// CapFunction and *not* CapFunctionEndpoint — with both, there is no refusal to
// observe; with neither, there is no function port to reach EnsureEndpoint
// through. It is also the configuration the source system actually runs in
// whenever its needsAlb parameter is false, so it is not a synthetic shape.
func endpointlessConfig() aws.Config {
	cfg := fullConfig()
	cfg.Name = "aws-no-endpoint"
	cfg.Endpoint = nil
	return cfg
}

// implementsExt is what every Options in this package declares about the ext
// ports, from ONE place.
//
// The two S3-shaped ports are implemented; the cross-domain grant port is not,
// and that is a ruling rather than an omission -- see
// docs/decisions/usoss-13-cross-domain-object-access-is-not-ported.md. Declaring
// it false is what makes the suite check the refusal instead of skipping the port.
//
// # Why one function and not a literal per Options
//
// Because it was a literal per Options, and the defect fixtures carried an empty
// one. That was true while this provider had no ext port and became false the
// moment it had two: the lookup succeeded on a provider whose Options said the
// port was not documented, so every defect fixture tripped an invariant it was
// not written to be about. **A per-fixture literal describing the provider is a
// restatement, and it goes stale in whichever fixture nobody is editing.**
//
// Every Options that drives THIS package's provider takes it from here, so the
// next ext port is declared once.
//
// hasObjectStore gates both S3-shaped ports rather than a literal true: the
// ext ports are reached through ObjectStores(), and registrylessConfig unsets
// Config.ObjectStore entirely, so that provider has no CapObjectStore and
// cannot implement either lookup helper regardless of what this package's own
// objectStore type asserts at compile time. USOSS-44's positive drive
// (conformance's checkExtBucketLifecycle) found this: TestConformanceWithoutRegistry
// declared both ports implemented via a bare call to this function while
// running a provider with no object store at all, and
// checkExtLookup's unconditional skip on a missing CapObjectStore had hidden
// the mismatch -- a skip reports nothing either way, so a false ImplementsExt
// entry behind it never surfaced. See USOSS-13's own object-store capability
// gate at config.go:730 for the parallel: a port reached through a capability
// accessor is only ever "implemented" for a provider that has the capability.
func implementsExt(hasObjectStore bool) map[string]bool {
	return map[string]bool{
		"ext.TableBucketProvisioner":  hasObjectStore,
		"ext.VectorBucketProvisioner": hasObjectStore,
		"ext.ExternalAccessGranter":   false,
	}
}

func conformanceOptions(hasObjectStore bool) conformance.Options {
	return conformance.Options{
		Placement:       "default",
		SecondPlacement: "secondary",
		FunctionRuntime: testRuntime,
		CertificateRef:  testCertificateRef,
		// Required once the provider advertises CapRelationalDatabase, and
		// deliberately a version the configuration declares: the suite cannot
		// invent one, and a provider that accepted an undeclared version would
		// be substituting a major version the caller did not ask for.
		Engine:        compute.EnginePostgres,
		EngineVersion: "16",
		// SSM keeps parameter history and honours a "name:version" selector on
		// both GetParameter and an ECS valueFrom, so this provider honours a pin
		// rather than refusing one.
		HonoursSecretVersions: true,
		ImplementsExt:         implementsExt(hasObjectStore),
		AnonymousRead: func(ctx context.Context, p compute.Provider, bucket compute.Ref) error {
			a, ok := p.(*aws.Provider)
			if !ok {
				return errWrongProvider
			}
			return a.Harness().AnonymousRead(ctx, bucket)
		},
		CreateUnowned: func(ctx context.Context, p compute.Provider, ref compute.Ref) error {
			a, ok := p.(*aws.Provider)
			if !ok {
				return errWrongProvider
			}
			return a.Harness().CreateUnowned(ctx, ref)
		},
		InduceTransient: func(ctx context.Context, p compute.Provider, kind compute.Kind) (func(), error) {
			a, ok := p.(*aws.Provider)
			if !ok {
				return nil, errWrongProvider
			}
			return a.Harness().InduceTransientKind(ctx, kind, aws.ErrThrottled)
		},
		// The material AWS hands a build, so the credential-egress check can
		// assert it appears in no log, error or result. Without this the check
		// reports NOT VERIFIED against the one provider known to have had the
		// bug it detects.
		// The hostile mode USOSS-61 requires. The mapping from the suite's channel
		// vocabulary onto this provider's is here, so compute/aws does not depend
		// on the suite that tests it.
		//
		// The status-message channel is mapped by USOSS-11. This comment used to
		// say there was none "because this provider has no container service" --
		// true when written, and this port is what makes it false. Its absence
		// was what made security/secret-bindings-travel-by-reference, the
		// invariant about this port's own headline feature, report NOT VERIFIED.
		EmitInto: func(ctx context.Context, p compute.Provider, c conformance.Channel, marker string) error {
			a, ok := p.(*aws.Provider)
			if !ok {
				return errWrongProvider
			}
			channel, known := map[conformance.Channel]string{
				conformance.ChannelBuildLog:    aws.ChannelBuildLog,
				conformance.ChannelBuildError:  aws.ChannelBuildError,
				conformance.ChannelBuildResult: aws.ChannelBuildResult,
				conformance.ChannelCallError:   aws.ChannelCallError,

				conformance.ChannelStatusMessage: aws.ChannelStatusMessage,
			}[c]
			if !known {
				return fmt.Errorf("%w: %s", conformance.ErrChannelNotHostile, c)
			}
			if err := a.Harness().EmitInto(ctx, channel, marker); err != nil {
				return fmt.Errorf("%w: %w", conformance.ErrChannelNotHostile, err)
			}
			return nil
		},
		BuildCredentials: func(ctx context.Context, p compute.Provider) ([]string, error) {
			a, ok := p.(*aws.Provider)
			if !ok {
				return nil, errWrongProvider
			}
			return a.Harness().BuildCredentials(ctx)
		},
		InduceDenial: func(ctx context.Context, p compute.Provider, kind compute.Kind) (func(), error) {
			a, ok := p.(*aws.Provider)
			if !ok {
				return nil, errWrongProvider
			}
			return a.Harness().InduceDenial(ctx, kind)
		},
		Rendered: func(ctx context.Context, p compute.Provider) ([]string, error) {
			a, ok := p.(*aws.Provider)
			if !ok {
				return nil, errWrongProvider
			}
			return a.Harness().Rendered(ctx)
		},
		// Supplied for the first time here. USOSS-10's ports were all in the
		// synchronous class, so nothing needed a stall; the function, endpoint and
		// relational ports are asynchronous, and without these hooks several of
		// their invariants — that a Wait honours its deadline, that a Wait with no
		// deadline is refused, that a timeout is distinguishable from a failure,
		// the admin-password invariant, and every grant invariant — are recorded as
		// unverified rather than passing.
		//
		// Read and Write are one pair for both Granter ports this provider vends:
		// USOSS-13's object store needs the same two hooks, and [aws.Harness]
		// dispatches on the resource's kind rather than the suite choosing.
		Stall: func(ctx context.Context, p compute.Provider, ref compute.Ref) error {
			a, ok := p.(*aws.Provider)
			if !ok {
				return errWrongProvider
			}
			return a.Harness().Stall(ctx, ref)
		},
		RelationalLogin: func(ctx context.Context, p compute.Provider, ref compute.Ref,
			username string, password compute.SecretValue,
		) error {
			a, ok := p.(*aws.Provider)
			if !ok {
				return errWrongProvider
			}
			return a.Harness().Authenticate(ctx, ref, username, password)
		},
		Read: func(ctx context.Context, p compute.Provider, resource, identity compute.Ref) error {
			a, ok := p.(*aws.Provider)
			if !ok {
				return errWrongProvider
			}
			return a.Harness().Read(ctx, resource, identity)
		},
		Write: func(ctx context.Context, p compute.Provider, resource, identity compute.Ref) error {
			a, ok := p.(*aws.Provider)
			if !ok {
				return errWrongProvider
			}
			return a.Harness().Write(ctx, resource, identity)
		},
		// Without this, security/exec-does-not-widen-the-workload-identity
		// reports NOT VERIFIED against a provider that advertises
		// CapWorkloadExec and ships the ssmmessages grant -- an unmeasured
		// security invariant for a capability the provider claims. See
		// aws.Harness.CanExecInto for why the channel grants are not the answer.
		CanExecInto: func(ctx context.Context, p compute.Provider, identity, target compute.Ref) (bool, error) {
			a, ok := p.(*aws.Provider)
			if !ok {
				return false, errWrongProvider
			}
			return a.Harness().CanExecInto(ctx, identity, target)
		},
	}
}

// newSuite returns a factory and options over one substrate. Every provider the
// factory hands back addresses the same services, which is what the determinism
// invariant needs.
func newSuite(t *testing.T, cfg aws.Config) (conformance.Factory, conformance.Options) {
	t.Helper()
	sub := aws.NewMemorySubstrate()
	factory := func(tb conformance.TB) compute.Provider {
		p, err := aws.New(sub, cfg)
		if err != nil {
			tb.Fatalf("aws_test: constructing the provider: %v", err)
		}
		return p
	}
	return factory, conformanceOptions(cfg.ObjectStore != nil)
}

// TestConformanceFullAccount runs the suite against a provider with a registry
// and a builder.
func TestConformanceFullAccount(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(t, fullConfig())
	conformance.Run(t, factory, opts)
}

// TestConformanceWithALeakingPusher runs the whole suite against a substrate
// whose pusher prints the credential it was handed, and whose builder prints the
// environment it was given.
//
// It exists because the credential-egress check was passing for no reason. The
// default fixtures are benign — they write their own arguments and nothing else —
// so the check scanned a log that could never have contained the material, and
// bypassing the provider's redacting writer entirely did not turn it red. A
// benign fixture and a correct implementation are indistinguishable, which is
// exactly what PR #18's review found on the provider side.
//
// So this configuration gives the check an input, and since USOSS-41 it takes two
// fixtures to do it:
//
//   - the pusher leaks the credential, which is the phase that has one. The
//     provider's redacting writer removes it, and removing that writer turns this
//     run red.
//   - the builder leaks its whole environment, which is what a hostile RUN line
//     does. Nothing is redacted out of it, because the provider puts no material
//     in it — so this half of the run goes red if a credential ever reappears in
//     the build phase's environment, which is the property the split exists for.
//
// The leak that used to be here — the *builder* printing the credential it was
// handed — is not expressible any more: [aws.BuildCommand] has no such field.
func TestConformanceWithALeakingPusher(t *testing.T) {
	t.Parallel()
	sub := aws.NewMemorySubstrate()
	runner := aws.NewRecordingBuilder()
	runner.LeakEnvironment = true
	sub.Builder = runner
	pusher := aws.NewRecordingPusher()
	pusher.LeakCredentials = true
	sub.Pusher = pusher

	cfg := fullConfig()
	factory := func(tb conformance.TB) compute.Provider {
		p, err := aws.New(sub, cfg)
		if err != nil {
			tb.Fatalf("aws_test: constructing the provider: %v", err)
		}
		return p
	}
	conformance.Run(t, factory, conformanceOptions(cfg.ObjectStore != nil))
}

// TestConformanceWithoutRegistry runs the suite against a provider configured
// with neither a registry nor a builder.
//
// This is the run that exercises the refusals. It is not redundant with the
// other one: the capability/accessor agreement invariant only proves something
// about a capability the provider does not have when there is one.
func TestConformanceWithoutRegistry(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(t, registrylessConfig())
	conformance.Run(t, factory, opts)
}

// TestConformanceWithoutAnEndpoint runs the suite against a provider that can
// run functions and cannot expose one.
//
// This is the run in which EnsureEndpoint refuses, and it is the only one that
// can be: see endpointlessConfig.
func TestConformanceWithoutAnEndpoint(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(t, endpointlessConfig())
	conformance.Run(t, factory, opts)
}

// harness is the same narrowing as the hooks above, for the defect fixtures that
// build their own Options and want a panic rather than a returned error: a
// fixture handed the wrong provider is a broken fixture, not a finding.
func harness(p compute.Provider) *aws.Harness {
	a, ok := p.(*aws.Provider)
	if !ok {
		panic("aws_test: the conformance suite was handed a provider this test did not construct")
	}
	return a.Harness()
}

// errWrongProvider is what a hook returns when it is handed a provider this
// file did not construct.
var errWrongProvider = errProvider("aws_test: the hook was handed a provider this test did not construct")

type errProvider string

func (e errProvider) Error() string { return string(e) }

// newProvider builds a provider over a fresh in-memory substrate, for the tests
// that assert on the substrate rather than on the interface.
func newProvider(t *testing.T, mutate func(*aws.Config)) (*aws.Provider, *aws.Substrate) {
	t.Helper()
	cfg := fullConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	sub := aws.NewMemorySubstrate()
	p, err := aws.New(sub, cfg)
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	return p, sub
}

// newProviderOver builds a second provider over an existing substrate, so that a
// test can change configuration without changing the resources.
//
// It exists for the convergence assertions. Removing a control-plane security
// group from a placement is a configuration change, and what has to be checked is
// that the *same* resource reconciles — which needs one substrate and two
// configurations, and is the same thing the conformance suite's determinism
// invariant needs a factory for.
func newProviderOver(t *testing.T, sub *aws.Substrate, mutate func(*aws.Config)) *aws.Provider {
	t.Helper()
	cfg := fullConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := aws.New(sub, cfg)
	if err != nil {
		t.Fatalf("constructing the provider: %v", err)
	}
	return p
}
