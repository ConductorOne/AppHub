// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/conformance"
	"github.com/conductorone/apphub/compute/ext"
	"github.com/conductorone/apphub/compute/fake"
)

// harness reaches the substrate hooks. Every conformance hook needs them, and a
// provider that is not a *fake.Provider — or a wrapper around one this file
// built — has no business being passed to this file's options.
//
// The unwrap exists for the defect fixtures that need to change one method's
// behaviour without reimplementing a provider: they embed compute.Provider and
// declare themselves here, so a provider that arrived from anywhere else still
// panics rather than being quietly tolerated.
func harness(p compute.Provider) *fake.Harness {
	// A fixture may wrap the provider to give one port a deliberately wrong error
	// mapping, or to make its store report no revisions, which is the only way to
	// express "this one thing is wrong and the rest are right". The hooks still
	// have to reach the substrate under it.
	if w, ok := p.(interface{ underlying() *fake.Provider }); ok {
		return w.underlying().Harness()
	}
	f, ok := p.(*fake.Provider)
	if !ok {
		panic("fake_test: the conformance suite was handed a provider this test did not construct")
	}
	return f.Harness()
}

// conformanceOptions wires the fake's substrate hooks into the suite.
//
// Every hook here is supplied on purpose: a nil hook makes the suite skip the
// invariant that depends on it, and the fake is the one provider that has no
// excuse — it is the reference implementation, so it should be the run with the
// fewest unverified invariants.
func conformanceOptions(cfg fake.Config) conformance.Options {
	return conformance.Options{
		// The fake honours version pinning: it is the reference implementation, so
		// it exercises the full contract rather than the easier half of it.
		HonoursSecretVersions: true,
		Placement:             "default",
		SecondPlacement:       "secondary",
		Zone:                  "zone-a",
		FunctionRuntime:       "nodejs20.x",
		CertificateRef:        "cert-default",
		Engine:                compute.EnginePostgres,
		EngineVersion:         "16",
		ImplementsExt: map[string]bool{
			"ext.TableBucketProvisioner":  cfg.ExtPorts,
			"ext.VectorBucketProvisioner": cfg.ExtPorts,
			"ext.ExternalAccessGranter":   cfg.ExtPorts,
		},
		Stall: func(ctx context.Context, p compute.Provider, ref compute.Ref) error {
			return harness(p).Stall(ctx, ref)
		},
		CreateUnowned: func(ctx context.Context, p compute.Provider, ref compute.Ref) error {
			return harness(p).CreateUnowned(ctx, ref)
		},
		// A throttle on every substrate call until the gate is done. The fake has
		// no real API to throttle, so it injects the error a real one would map —
		// which is the whole content of the check: does the provider's mapping
		// reach ErrTransient rather than ErrFailed.
		//
		// It was FailNext(OpEnsure, KindSecret) — one call, one kind — which was
		// enough for a gate that drove one secret Put and is not enough for one
		// that drives every method of every port. A mapping is written per
		// service, so arming one service would pass on a provider that gets its
		// secret store right and its identity service wrong.
		//
		// USOSS-42 added the kind parameter this hook now takes, the same
		// treatment InduceDenial below already had. It is accepted and not
		// branched on: the fake has one substrate behind every kind, so
		// FailEvery already arms the whole thing and there is nothing narrower
		// to scope to.
		InduceTransient: func(_ context.Context, p compute.Provider, _ compute.Kind) (func(), error) {
			return harness(p).FailEvery(
				fmt.Errorf("fake: the substrate throttled this call: %w", compute.ErrTransient)), nil
		},
		// A denial on whichever port the suite chose to drive. The fake has no
		// real service to be refused by, so it injects the error a real one would
		// map -- which is the whole content of the check: does the provider's
		// mapping reach ErrNotPermitted rather than collapsing into ErrFailed.
		InduceDenial: func(_ context.Context, p compute.Provider, kind compute.Kind) (func(), error) {
			harness(p).FailNext(fake.OpEnsure, kind,
				fmt.Errorf("fake: the substrate refused this call: %w", compute.ErrNotPermitted))
			return func() {}, nil
		},
		Read: func(ctx context.Context, p compute.Provider, resource, identity compute.Ref) error {
			return harness(p).Read(ctx, resource, identity)
		},
		Write: func(ctx context.Context, p compute.Provider, resource, identity compute.Ref) error {
			return harness(p).Write(ctx, resource, identity)
		},
		AnonymousRead: func(ctx context.Context, p compute.Provider, bucket compute.Ref) error {
			return harness(p).AnonymousRead(ctx, bucket)
		},
		RelationalLogin: func(ctx context.Context, p compute.Provider, ref compute.Ref, user string, password compute.SecretValue) error {
			return harness(p).Login(ctx, ref, user, password)
		},
		CanExecInto: func(ctx context.Context, p compute.Provider, identity, target compute.Ref) (bool, error) {
			return harness(p).CanExecInto(ctx, identity, target)
		},
		Rendered: func(ctx context.Context, p compute.Provider) ([]string, error) {
			return harness(p).Rendered(ctx)
		},
		RenderedRef: func(ctx context.Context, p compute.Provider, ref compute.Ref) (string, bool, error) {
			return harness(p).RenderedRef(ctx, ref)
		},
		// The hostile mode USOSS-61 requires. The mapping from the suite's
		// channel vocabulary onto the provider's is here rather than in the
		// provider, so compute/fake does not depend on the suite that tests it.
		EmitInto: func(ctx context.Context, p compute.Provider, c conformance.Channel, marker string) error {
			channel, ok := map[conformance.Channel]string{
				conformance.ChannelBuildLog:      fake.ChannelBuildLog,
				conformance.ChannelBuildError:    fake.ChannelBuildError,
				conformance.ChannelBuildResult:   fake.ChannelBuildResult,
				conformance.ChannelStatusMessage: fake.ChannelStatusMessage,
				conformance.ChannelCallError:     fake.ChannelCallError,
				conformance.ChannelImageMetadata: fake.ChannelImageMetadata,
			}[c]
			if !ok {
				return fmt.Errorf("%w: %s", conformance.ErrChannelNotHostile, c)
			}
			if err := harness(p).EmitInto(ctx, channel, marker); err != nil {
				return fmt.Errorf("%w: %w", conformance.ErrChannelNotHostile, err)
			}
			return nil
		},
		BuildCredentials: func(ctx context.Context, p compute.Provider) ([]string, error) {
			return harness(p).BuildCredentials(ctx)
		},
		ImageMetadata: func(_ context.Context, p compute.Provider, image compute.ImageRef) (string, error) {
			s, _ := harness(p).ImageMetadata(image)
			return s, nil
		},
		BuildCacheDefaultMaxAge: func(ctx context.Context, p compute.Provider) (time.Duration, error) {
			return harness(p).BuildCacheDefaultMaxAge(ctx)
		},
	}
}

// newSuite returns a factory and options for a provider with cfg, over a fresh
// substrate. The factory hands back providers over the *same* store, which is
// what the determinism invariant requires.
func newSuite(cfg fake.Config) (conformance.Factory, conformance.Options) {
	store := fake.NewStore()
	factory := func(conformance.TB) compute.Provider { return fake.New(store, cfg) }
	opts := conformanceOptions(cfg)
	proxyless := cfg
	proxyless.NoIngressProxy = true
	opts.WithoutIngressProxy = func(conformance.TB) compute.Provider {
		return fake.New(store, proxyless)
	}
	return factory, opts
}

// TestConformanceFullProvider runs the suite against a provider that advertises
// everything, which is the configuration a module test uses when it wants the
// fake to stand in for a substrate that can do it all.
func TestConformanceFullProvider(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(fake.Config{ExtPorts: true})
	conformance.Run(t, factory, opts)
}

// TestConformanceMinimalProvider runs the suite against a provider shaped like
// the Kubernetes falsification exercise in the design doc: no key-value tables,
// no functions, no zonal buckets, no scheduled jobs, no model inference, and no
// non-portable ports.
//
// This is the configuration the capability-negative checks exist for. Against a
// provider that advertises everything they have nothing to bite on, so a suite
// only ever run that way would never have shown that a refusal is typed, named,
// and loud.
func TestConformanceMinimalProvider(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(fake.Config{
		Name: "fake-minimal",
		Capabilities: []compute.Capability{
			compute.CapImageRegistry,
			compute.CapImageBuild,
			compute.CapContainerService,
			compute.CapWorkloadExec,
			compute.CapObjectStore,
			compute.CapRelationalDatabase,
			compute.CapSecretStore,
		},
	})
	conformance.Run(t, factory, opts)
}

// TestConformanceProviderWithNoSecretStore covers the third interesting shape: a
// provider that cannot hold secrets at all, so no workload can be given a bound
// one. It exists because several security checks route through a secret fixture,
// and a provider without one must skip them rather than fail.
func TestConformanceProviderWithNoSecretStore(t *testing.T) {
	t.Parallel()
	factory, opts := newSuite(fake.Config{
		Name: "fake-no-secrets",
		Capabilities: []compute.Capability{
			compute.CapContainerService,
			compute.CapObjectStore,
		},
	})
	conformance.Run(t, factory, opts)
}

// --- unit tests on behaviour the suite cannot reach ------------------------

func TestNewRequiresAStore(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("fake.New accepted a nil store; every provider instance must address a substrate")
		}
	}()
	_ = fake.New(nil, fake.Config{})
}

func TestBuildConfinesTheDockerfileToItsContext(t *testing.T) {
	t.Parallel()
	p := fake.New(fake.NewStore(), fake.Config{})
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	repo, err := reg.EnsureRepository(context.Background(), compute.RepositorySpec{Name: "app"})
	if err != nil {
		t.Fatalf("EnsureRepository(): %v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture Dockerfile: %v", err)
	}
	// A file outside the context, which a repository-supplied path must not be
	// able to reach. The source system checks this and losing the check would
	// reintroduce a path-traversal escape from the build context.
	outside := filepath.Join(t.TempDir(), "secrets.txt")
	if err := os.WriteFile(outside, []byte("not yours"), 0o600); err != nil {
		t.Fatalf("writing the out-of-context fixture: %v", err)
	}

	dest := compute.ImageRef(repo.Prefix + ":v1")
	for _, path := range []string{
		"../" + filepath.Base(filepath.Dir(outside)) + "/" + filepath.Base(outside),
		"../../etc/passwd",
		outside,
	} {
		_, err := builder.Build(context.Background(), compute.BuildRequest{
			Source:       compute.BuildSource{ContextDir: dir, Dockerfile: path},
			Destinations: []compute.ImageRef{dest},
		})
		if err == nil {
			t.Errorf("Build accepted Dockerfile path %q, which resolves outside the build context", path)
			continue
		}
		if !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("Build rejected %q with %v, want compute.ErrInvalidSpec", path, err)
		}
	}

	var logs bytes.Buffer
	res, err := builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: dir},
		Destinations: []compute.ImageRef{dest},
		Logs:         &logs,
	})
	if err != nil {
		t.Fatalf("Build with a legal context: %v", err)
	}
	if len(res.Images) != 1 || res.Images[0] != dest {
		t.Errorf("Build returned %v, want the requested destination %q", res.Images, dest)
	}
	if res.Digest == "" {
		t.Error("Build reported no digest")
	}
	if logs.Len() == 0 {
		t.Error("Build wrote nothing to the log writer, which is a build's only progress signal")
	}
	if _, ok := p.Store().PulledDigest(dest); !ok {
		t.Errorf("nothing recorded %q as pushed, so a runtime could not pull it", dest)
	}
}

func TestBuildRefusesADestinationNoRepositoryHosts(t *testing.T) {
	t.Parallel()
	p := fake.New(fake.NewStore(), fake.Config{})
	builder, err := p.Builder()
	if err != nil {
		t.Fatalf("Builder(): %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture Dockerfile: %v", err)
	}
	_, err = builder.Build(context.Background(), compute.BuildRequest{
		Source:       compute.BuildSource{ContextDir: dir},
		Destinations: []compute.ImageRef{"registry.invalid/fake/never-created:v1"},
	})
	if !errors.Is(err, compute.ErrNotFound) {
		t.Errorf("Build to an unprovisioned repository returned %v, want compute.ErrNotFound", err)
	}
}

func TestSecretsAreBoundByReferenceAndNeverRendered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{})
	const material = "unit-test-secret-material-a91f"

	store, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets(): %v", err)
	}
	ref, err := store.Put(ctx, compute.SecretSpec{
		Name:  "db-password",
		Scope: "app-1",
		Value: compute.NewSecretValue(material),
	})
	if err != nil {
		t.Fatalf("Put(): %v", err)
	}

	identity, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name:   "app",
		RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(): %v", err)
	}
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers(): %v", err)
	}
	if _, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name:      "app",
		Placement: compute.Placement{Name: "default"},
		Image:     "registry.invalid/fake/app:v1",
		Resources: compute.Resources{CPUMillicores: 256, MemoryMiB: 512},
		Replicas:  1,
		Ports:     []compute.PortSpec{{Number: 8080}},
		Secrets:   []compute.SecretBinding{{EnvName: "DB_PASSWORD", Secret: ref.Ref}},
		Identity:  identity.Ref,
	}); err != nil {
		t.Fatalf("EnsureService(): %v", err)
	}

	rendered, err := p.Harness().Rendered(ctx)
	if err != nil {
		t.Fatalf("Rendered(): %v", err)
	}
	joined := strings.Join(rendered, "\n")
	if strings.Contains(joined, material) {
		t.Error("the rendered substrate state contains the secret material; a binding must travel " +
			"as a reference the runtime resolves at launch")
	}
	if !strings.Contains(joined, "DB_PASSWORD->"+ref.Ref.String()) {
		t.Errorf("the rendered service does not bind DB_PASSWORD by reference:\n%s", joined)
	}

	// Get is the one place material comes back, and only for apphub's own use.
	got, err := store.Get(ctx, ref.Ref)
	if err != nil {
		t.Fatalf("Get(): %v", err)
	}
	if compute.RevealSecret(got) != material {
		t.Error("Get did not return the stored material")
	}
	// Through fmt rather than through a String method: SecretValue has no String
	// method any more, because an exported no-arg string method is exactly what a
	// template can call by name. Format covers every verb.
	if strings.Contains(fmt.Sprintf("%v %s %q %#v", got, got, got, got), material) {
		t.Error("a SecretValue printed its material")
	}
}

func TestDeleteScopeRemovesEveryScopedSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{})
	store, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets(): %v", err)
	}
	var refs []compute.Ref
	for _, name := range []string{"one", "two", "three"} {
		ref, err := store.Put(ctx, compute.SecretSpec{
			Name:  name,
			Scope: "app-1",
			Value: compute.NewSecretValue("v"),
		})
		if err != nil {
			t.Fatalf("Put(%q): %v", name, err)
		}
		refs = append(refs, ref.Ref)
	}
	keep, err := store.Put(ctx, compute.SecretSpec{
		Name:  "other",
		Scope: "app-2",
		Value: compute.NewSecretValue("v"),
	})
	if err != nil {
		t.Fatalf("Put(other): %v", err)
	}

	if err := store.DeleteScope(ctx, "app-1"); err != nil {
		t.Fatalf("DeleteScope(): %v", err)
	}
	for _, ref := range refs {
		if _, err := store.Get(ctx, ref); !errors.Is(err, compute.ErrNotFound) {
			t.Errorf("after DeleteScope, Get(%s) returned %v, want compute.ErrNotFound", ref, err)
		}
	}
	if _, err := store.Get(ctx, keep.Ref); err != nil {
		t.Errorf("DeleteScope removed a secret in another scope: %v", err)
	}
	if err := store.DeleteScope(ctx, ""); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("DeleteScope(\"\") returned %v, want compute.ErrInvalidSpec; an empty scope would "+
			"delete everything", err)
	}
}

func TestScaleServicePausesAndResumes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{})
	identity, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name:   "app",
		RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(): %v", err)
	}
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers(): %v", err)
	}
	spec := compute.ServiceSpec{
		Name:      "app",
		Placement: compute.Placement{Name: "default"},
		Image:     "registry.invalid/fake/app:v1",
		Resources: compute.Resources{CPUMillicores: 256, MemoryMiB: 512},
		Replicas:  3,
		Identity:  identity.Ref,
	}
	st, err := rt.EnsureService(ctx, spec)
	if err != nil {
		t.Fatalf("EnsureService(): %v", err)
	}

	// Pause is ScaleService(ref, 0), not a Pause method: that is what it means,
	// and a substrate with no notion of "paused" can still express it.
	if err := rt.ScaleService(ctx, st.Ref, 0); err != nil {
		t.Fatalf("ScaleService(0): %v", err)
	}
	paused, err := rt.DescribeService(ctx, st.Ref)
	if err != nil {
		t.Fatalf("DescribeService(): %v", err)
	}
	if paused.DesiredReplicas != 0 || paused.ReadyReplicas != 0 {
		t.Errorf("after pausing, desired=%d ready=%d, want 0 and 0",
			paused.DesiredReplicas, paused.ReadyReplicas)
	}
	if paused.Phase == compute.PhaseGone {
		t.Error("pausing reported the service as gone; the definition and network identity persist")
	}

	if err := rt.ScaleService(ctx, st.Ref, 2); err != nil {
		t.Fatalf("ScaleService(2): %v", err)
	}
	resumed, err := rt.WaitForService(ctx, st.Ref, 2, compute.WaitOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("WaitForService(): %v", err)
	}
	if resumed.ReadyReplicas != 2 {
		t.Errorf("after resuming, ready=%d, want 2", resumed.ReadyReplicas)
	}
	if err := rt.ScaleService(ctx, st.Ref, -1); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("ScaleService(-1) returned %v, want compute.ErrInvalidSpec", err)
	}
}

func TestExtPortsAreReachableOnlyWhenConfigured(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	with, err := fake.New(fake.NewStore(), fake.Config{ExtPorts: true}).ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	tables, err := ext.TableBuckets("fake", with)
	if err != nil {
		t.Fatalf("a provider configured with the ext ports refused the table-bucket lookup: %v", err)
	}
	b, err := tables.EnsureTableBucket(ctx, compute.BucketSpec{Name: "analytics"})
	if err != nil {
		t.Fatalf("EnsureTableBucket(): %v", err)
	}
	if b.Ref.Kind != compute.KindBucket || b.Name == "" {
		t.Errorf("EnsureTableBucket returned %#v, which addresses nothing usable", b)
	}

	without, err := fake.New(fake.NewStore(), fake.Config{}).ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	if _, err := ext.TableBuckets("fake", without); !errors.Is(err, compute.ErrUnsupported) {
		t.Errorf("the table-bucket lookup against a provider without the ports returned %v, want "+
			"an error wrapping compute.ErrUnsupported", err)
	}
}

func TestExternalGrantsRequireConstraintsAndRefuseForeignGrants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{ExtPorts: true})
	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	granter, err := ext.ExternalAccess("fake", store)
	if err != nil {
		t.Fatalf("ExternalAccess(): %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "shared"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}

	// A cross-domain grant constrained only by the principal lets in every other
	// tenant reachable through that principal.
	err = granter.GrantExternal(ctx, bucket.Ref,
		ext.ExternalPrincipal{ID: "caller-supplied-principal"}, compute.AccessRead)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("GrantExternal with no constraints returned %v, want compute.ErrInvalidSpec", err)
	}

	principal := ext.ExternalPrincipal{
		ID:          "caller-supplied-principal",
		Constraints: []string{"agreed-correlation-value"},
	}
	if err := granter.GrantExternal(ctx, bucket.Ref, principal, compute.AccessRead); err != nil {
		t.Fatalf("GrantExternal(): %v", err)
	}
	// Idempotent, and revocable.
	if err := granter.GrantExternal(ctx, bucket.Ref, principal, compute.AccessRead); err != nil {
		t.Errorf("a repeated GrantExternal returned %v", err)
	}
	if err := granter.RevokeExternal(ctx, bucket.Ref, principal); err != nil {
		t.Errorf("RevokeExternal(): %v", err)
	}
	if err := granter.RevokeExternal(ctx, bucket.Ref, principal); err != nil {
		t.Errorf("RevokeExternal on an absent grant returned %v, want nil", err)
	}
}

// TestAnExternalGrantSurvivesARefusedRegrant is the enforced half of
// GrantExternal's no-mutation rule.
//
// The rule: a grant carrying no constraints is refused **and nothing is
// mutated**. An error return that also changes a grant is a worse contract than
// either half, and the interface says so.
//
// # Three rounds of this test, and what each one missed
//
//  1. It compared the constraints and the grant count. A reviewer changed the
//     grant's *level* ahead of the refusal and it passed -- the assertion made an
//     unobservable contract observable and then observed a subset.
//  2. It compared a %+v rendering of the whole record, so a field added later was
//     covered without anybody remembering. A reviewer split one constraint into
//     two -- ["tenant one"] into ["tenant","one"] -- and it passed, because %+v
//     joins a []string with spaces and **a space inside an element is
//     indistinguishable from a boundary between elements.** The evidence and the
//     comparison were the same artefact, so any two states the renderer conflated
//     were equal by construction.
//  3. This one. The snapshot is the record, deep-copied, compared with
//     reflect.DeepEqual: lossless, structural, no delimiter to collide on, and
//     still covered by construction for a field added later.
//
// # The fixture is plural, and that is a fix rather than a detail
//
// Every earlier fixture supplied exactly ONE constraint, so mutating GrantExternal
// to persist only Constraints[:1] was invisible -- the whole package passed. The
// interface's contract says the field is plural and says not to collapse it to a
// scalar, and **a contract that says plural, tested only with singletons, is an
// unasserted contract.** Two elements with content that cannot be confused for one
// another, and content chosen so the round-2 collision would still be caught.
func TestAnExternalGrantSurvivesARefusedRegrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{ExtPorts: true})
	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	granter, err := ext.ExternalAccess("fake", store)
	if err != nil {
		t.Fatalf("ExternalAccess(): %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "shared"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}

	const id = "caller-supplied-principal"
	principal := ext.ExternalPrincipal{ID: id, Constraints: pluralConstraints()}
	if err := granter.GrantExternal(ctx, bucket.Ref, principal, compute.AccessRead); err != nil {
		t.Fatalf("GrantExternal(): %v", err)
	}

	// Snapshot after establishing the state and validating it, not before: a
	// snapshot taken first reports the test's own setup as a mutation.
	before, err := p.Harness().ExternalGrants(bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants(): %v", err)
	}
	if _, ok := before[id]; !ok {
		t.Fatalf("the grant did not take; ExternalGrants reported %v", before)
	}

	// The refused call. A configuration edit is how a constraint list becomes
	// empty, so this is the realistic shape of the mistake -- the same principal,
	// the same resource, and the constraints gone.
	err = granter.GrantExternal(ctx, bucket.Ref,
		ext.ExternalPrincipal{ID: id}, compute.AccessRead)
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("GrantExternal with no constraints returned %v, want compute.ErrInvalidSpec", err)
	}

	after, err := p.Harness().ExternalGrants(bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants() after the refusal: %v", err)
	}
	if !maps.EqualFunc(before, after, reflect.DeepEqual) {
		t.Errorf("a refused GrantExternal changed stored state.\n before: %#v\n  after: %#v\n"+
			"The refusal must not mutate anything: removing a grant the caller no longer intends "+
			"is the reconciling caller's job, through RevokeExternal, because a per-principal call "+
			"cannot see that a principal has vanished from a set it was never given", before, after)
	}
}

// pluralConstraints is the shared plural fixture, and every property of its
// content is load-bearing.
//
//   - **Two elements**, so truncating the list to one is visible. Every earlier
//     fixture had one, which is why persisting only Constraints[:1] was invisible.
//   - **Distinguishable from each other**, so keeping the wrong one is visible too.
//   - **Each containing a space**, which is the property I first got backwards.
//
// The third is what exercises the collision that defeated the %+v comparison. A
// space-free pair makes a split-an-element mutation a **no-op** -- ["a","b"] splits
// to ["a","b"] -- so it proves nothing about the comparison. A whitespace-bearing
// pair is a real mutation that the old renderer could not see and the structural
// comparison can:
//
//	["tenant one","tenant two"]              %+v -> [tenant one tenant two]
//	["tenant","one","tenant","two"]          %+v -> [tenant one tenant two]   collides
//	                                   reflect.DeepEqual -> differs
//
// And whitespace is not a contrived input: these are opaque caller-supplied
// correlation values, so a space is legal content rather than a pathological case.
//
// A function rather than a literal in each test, so the plurality is one thing to
// change rather than several to remember.
func pluralConstraints() []string {
	return []string{"tenant one", "tenant two"}
}

// TestAGrantStoresEveryConstraintItWasGiven is the plural axis, asserted directly.
//
// The preservation test above would catch a truncation only as a difference
// between two snapshots. This catches it at the point it happens, and over more
// than one length -- because "it kept both" and "it keeps all of them" are
// different claims, and a fixture of exactly two cannot distinguish a correct
// implementation from one that keeps the first two.
func TestAGrantStoresEveryConstraintItWasGiven(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, n := range []int{1, 2, 3, 5} {
		t.Run(fmt.Sprintf("%d-constraints", n), func(t *testing.T) {
			t.Parallel()
			p := fake.New(fake.NewStore(), fake.Config{ExtPorts: true})
			store, err := p.ObjectStores()
			if err != nil {
				t.Fatalf("ObjectStores(): %v", err)
			}
			granter, err := ext.ExternalAccess("fake", store)
			if err != nil {
				t.Fatalf("ExternalAccess(): %v", err)
			}
			bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "shared"})
			if err != nil {
				t.Fatalf("EnsureBucket(): %v", err)
			}

			// Generated rather than listed, so the assertion is over the length
			// rather than over a pair somebody typed.
			want := make([]string, n)
			for i := range want {
				want[i] = fmt.Sprintf("correlation-%02d", i)
			}
			const id = "caller-supplied-principal"
			if err := granter.GrantExternal(ctx, bucket.Ref,
				ext.ExternalPrincipal{ID: id, Constraints: want}, compute.AccessRead); err != nil {
				t.Fatalf("GrantExternal(): %v", err)
			}

			got, err := p.Harness().ExternalGrants(bucket.Ref)
			if err != nil {
				t.Fatalf("ExternalGrants(): %v", err)
			}
			stored := reflect.ValueOf(got[id]).FieldByName("constraints")
			if !stored.IsValid() {
				t.Fatalf("the stored grant has no constraints field; got %#v", got[id])
			}
			// Element by element against what was supplied, in order.
			//
			// An earlier version compared only the LENGTH. **Len asserts the
			// population's size, not its content**, so storing N copies of the
			// first constraint satisfied it — the plural axis traversed and
			// nothing read where it went. Round one's finding was a fixture of
			// one element; the fix made it N; and the assertion still could not
			// tell N distinct values from N copies of one.
			if stored.Len() != n {
				t.Fatalf("granted %d constraints and %d were stored", n, stored.Len())
			}
			for i := range n {
				if got := stored.Index(i).String(); got != want[i] {
					t.Errorf("constraint %d is %q and %q was supplied. The contract says the field "+
						"is plural and must not be collapsed; a length check cannot tell %d "+
						"distinct values from %d copies of one", i, got, want[i], n, n)
				}
			}
		})
	}
}

// TestExternalGrantsDistinguishesEmptyFromUnreadable is the (b1) property: a
// resolve failure must not read as "no grants".
func TestExternalGrantsDistinguishesEmptyFromUnreadable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{ExtPorts: true})
	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "empty"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}

	// A real bucket with no grants: empty, and no error.
	got, err := p.Harness().ExternalGrants(bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants on a grantless bucket returned %v, want no error", err)
	}
	if len(got) != 0 {
		t.Errorf("ExternalGrants on a grantless bucket = %v, want empty", got)
	}

	// A ref this provider never issued: an error, not an empty map. Under len and
	// range the two are identical, so a test addressing the wrong resource would
	// otherwise pass while checking nothing.
	foreign := compute.Ref{Provider: "somebody-else", Kind: compute.KindBucket, ID: "bucket/x"}
	if _, err := p.Harness().ExternalGrants(foreign); err == nil {
		t.Error("ExternalGrants on a foreign ref returned no error, so \"nothing was there\" and " +
			"\"I could not look\" are indistinguishable to a caller")
	}
}

// TestTheExternalGrantCopyHandlesEveryReferenceField is the precondition
// [fake.Harness.ExternalGrants] depends on.
//
// The snapshot has to be independent of the store: one sharing a slice with the
// live grant is not a snapshot, because an in-place mutation would change the
// "before" too and the comparison would pass for the same reason a snapshot taken
// before the setup does.
//
// So every reference-typed field of the stored grant must be deep-copied. That
// cannot be verified mechanically -- reflection can see that a field is a slice,
// not that some function copies it -- so the obligation is a named list with a
// **fatal default**: a reference-typed field absent from
// [fake.ExternalGrantReferenceFields] fails here. A list whose omissions are fatal
// is the only kind worth having.
//
// This replaces a test that asserted no field was a map, which was the
// precondition of the %+v rendering the comparison used to be. reflect.DeepEqual
// handles maps, so determinism is free now and the live risk moved.
func TestTheExternalGrantCopyHandlesEveryReferenceField(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(fake.ExternalGrantShape())
	if typ.Kind() != reflect.Struct {
		t.Fatalf("the stored grant is a %s, not a struct", typ.Kind())
	}
	if typ.NumField() == 0 {
		t.Fatal("the stored grant has no fields, so this proves nothing")
	}
	handled := fake.ExternalGrantReferenceFields()
	seen := 0
	for i := range typ.NumField() {
		f := typ.Field(i)
		switch f.Type.Kind() {
		case reflect.Slice, reflect.Map, reflect.Pointer, reflect.Interface, reflect.Chan:
			seen++
			if _, ok := handled[f.Name]; !ok {
				t.Errorf("field %s is a %s and is not named in ExternalGrantReferenceFields, so a "+
					"snapshot from ExternalGrants may alias live store state. Deep-copy it in "+
					"copyExternalGrant and name it there", f.Name, f.Type)
			}
		}
	}
	for name := range handled {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("ExternalGrantReferenceFields names %s and the stored grant has no such "+
				"field; the list has outlived what it described", name)
		}
	}
	if seen == 0 {
		t.Log("the stored grant currently has no reference-typed field; this check is a tripwire " +
			"for when one is added")
	}
}

// TestAnExternalGrantSnapshotReflectsARealChange asserts that a snapshot is not
// frozen — and deliberately does NOT claim to test independence.
//
// It used to be called ...SnapshotIsIndependentOfTheStore and it could not test
// that: it re-grants with different constraints, and **replacing a slice produces
// a new backing array whether or not the snapshot copied.** Deleting
// copyExternalGrant left it green. A test that replaces can never detect aliasing;
// only mutation in place can, which needs the unexported field and therefore an
// internal test — see TestAnExternalGrantSnapshotSurvivesAnInPlaceMutation.
//
// What remains here is still worth asserting, and is the converse: a snapshot must
// be able to *see* a real change. A snapshot mechanism that returned a constant, or
// cached the first answer, would pass every no-mutation test for the worst reason.
func TestAnExternalGrantSnapshotReflectsARealChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{ExtPorts: true})
	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	granter, err := ext.ExternalAccess("fake", store)
	if err != nil {
		t.Fatalf("ExternalAccess(): %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "shared"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	const id = "caller-supplied-principal"
	if err := granter.GrantExternal(ctx, bucket.Ref,
		ext.ExternalPrincipal{ID: id, Constraints: pluralConstraints()}, compute.AccessRead); err != nil {
		t.Fatalf("GrantExternal(): %v", err)
	}

	first, err := p.Harness().ExternalGrants(bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants(): %v", err)
	}
	// Re-grant with different constraints: the store changes, the earlier
	// snapshot must not.
	if err := granter.GrantExternal(ctx, bucket.Ref,
		ext.ExternalPrincipal{ID: id, Constraints: []string{"correlation-gamma"}},
		compute.AccessReadWrite); err != nil {
		t.Fatalf("re-GrantExternal(): %v", err)
	}
	second, err := p.Harness().ExternalGrants(bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants() again: %v", err)
	}
	if reflect.DeepEqual(first[id], second[id]) {
		t.Error("two snapshots taken either side of a real change are equal, so ExternalGrants is " +
			"either aliasing the store or returning something that cannot see the change — and a " +
			"snapshot that cannot detect a real mutation cannot detect a wrongful one")
	}
	// No aliasing assertion here: this operation cannot support one. See the
	// internal test named above.
}

func TestAttestationUsesTheSharedVocabulary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{})
	id, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name:   "app",
		RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(): %v", err)
	}
	if id.Attestation.Method != fake.FakeAttestationMethod {
		t.Errorf("Attestation.Method is %q, want %q", id.Attestation.Method, fake.FakeAttestationMethod)
	}
	if id.Attestation.Subject == "" {
		t.Error("Attestation.Subject is empty; a verifier has nothing to compare a proof against")
	}
	// The fake does not attest with the AWS scheme, deliberately: it is what most
	// tests run against, and attesting with MethodAWSSTSCallerIdentity would make
	// that scheme structurally privileged everywhere downstream.
	if strings.Contains(string(id.Attestation.Method), "aws") {
		t.Errorf("the fake attests with %q; a fake that claims the AWS scheme teaches every "+
			"downstream test to assume it", id.Attestation.Method)
	}

	// A function identity is a different identity: on some substrates a role
	// trusted by one runtime cannot be assumed by another.
	fn, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name:   "app",
		RunsOn: compute.RuntimeFunction,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(function): %v", err)
	}
	if fn.Ref == id.Ref {
		t.Error("the same logical name produced one identity for both runtimes; an AWS role trusted " +
			"by ecs-tasks cannot be assumed by Lambda")
	}
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers(): %v", err)
	}
	_, err = rt.EnsureService(ctx, compute.ServiceSpec{
		Name:      "app",
		Placement: compute.Placement{Name: "default"},
		Image:     "registry.invalid/fake/app:v1",
		Resources: compute.Resources{CPUMillicores: 256, MemoryMiB: 512},
		Identity:  fn.Ref,
	})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a container service running as a function identity returned %v, want "+
			"compute.ErrInvalidSpec", err)
	}
}

func TestResourcesRoundUpAndSaySo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{})
	identity, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name:   "app",
		RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(): %v", err)
	}
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers(): %v", err)
	}
	st, err := rt.EnsureService(ctx, compute.ServiceSpec{
		Name:      "app",
		Placement: compute.Placement{Name: "default"},
		Image:     "registry.invalid/fake/app:v1",
		// Neither value is a size this substrate offers.
		Resources: compute.Resources{CPUMillicores: 300, MemoryMiB: 600},
		Replicas:  1,
		Identity:  identity.Ref,
	})
	if err != nil {
		t.Fatalf("EnsureService(): %v", err)
	}
	// Rounding down turns a capacity decision into an intermittent runtime OOM,
	// so the direction is normative and the provider has to say what it did.
	if !strings.Contains(st.Message, "rounded up") {
		t.Errorf("Status.Message is %q; a provider that cannot honour a resource request exactly "+
			"must round up and say so", st.Message)
	}
	_, err = rt.EnsureService(ctx, compute.ServiceSpec{
		Name:      "huge",
		Placement: compute.Placement{Name: "default"},
		Image:     "registry.invalid/fake/app:v1",
		Resources: compute.Resources{CPUMillicores: 1 << 20, MemoryMiB: 1 << 20},
		Identity:  identity.Ref,
	})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("a resource request beyond the substrate's ceiling returned %v, want "+
			"compute.ErrInvalidSpec", err)
	}
}

func TestScheduleGrammarIsPinned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{})
	identity, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name:   "job",
		RunsOn: compute.RuntimeContainer,
	})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(): %v", err)
	}
	rt, err := p.Containers()
	if err != nil {
		t.Fatalf("Containers(): %v", err)
	}
	spec := func(expr string) compute.ScheduledJobSpec {
		return compute.ScheduledJobSpec{
			Name:      "job",
			Schedule:  compute.Schedule{Expression: expr},
			Placement: compute.Placement{Name: "default"},
			Image:     "registry.invalid/fake/job:v1",
			Resources: compute.Resources{CPUMillicores: 256, MemoryMiB: 512},
			Identity:  identity.Ref,
		}
	}
	for _, ok := range []string{"*/5 * * * *", "0 3 * * 1", "rate(15 minutes)", "rate(1 day)"} {
		if _, err := rt.EnsureScheduledJob(ctx, spec(ok)); err != nil {
			t.Errorf("EnsureScheduledJob(%q) returned %v, want success", ok, err)
		}
	}
	// A six-field expression is the AWS dialect, which is exactly what pinning a
	// grammar is meant to stop from spreading.
	for _, bad := range []string{"", "* * * *", "cron(0 3 * * ? *)", "0 3 * * ? *", "rate(0 minutes)", "rate(5 fortnights)"} {
		if _, err := rt.EnsureScheduledJob(ctx, spec(bad)); !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("EnsureScheduledJob(%q) returned %v, want compute.ErrInvalidSpec", bad, err)
		}
	}
}

// TestFailureInjectionLeavesAPartialDeploy covers the capability carried over
// from the source system's own tests: nothing across this interface is
// transactional, so a deploy that provisions several resources can fail in the
// middle, and a module test needs to be able to make that happen.
func TestFailureInjectionLeavesAPartialDeploy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{})
	h := p.Harness()

	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	kv, err := p.KeyValues()
	if err != nil {
		t.Fatalf("KeyValues(): %v", err)
	}

	// The bucket succeeds; the table does not. That is the shape of a deploy that
	// leaves two of three resources behind.
	injected := errors.New("substrate said no")
	h.FailNext(fake.OpEnsure, compute.KindKeyValueTable, injected)

	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "app-data"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	if _, err := kv.EnsureKeyValueTable(ctx, compute.KeyValueSpec{
		Name:         "app-table",
		PartitionKey: "pk",
	}); !errors.Is(err, injected) {
		t.Fatalf("EnsureKeyValueTable() returned %v, want the injected error", err)
	}
	if n := h.PendingFailures(); n != 0 {
		t.Errorf("%d injected failure(s) went unconsumed", n)
	}

	// The failure fired before anything was created, so a retry converges rather
	// than tripping over a half-made resource.
	table, err := kv.EnsureKeyValueTable(ctx, compute.KeyValueSpec{
		Name:         "app-table",
		PartitionKey: "pk",
	})
	if err != nil {
		t.Fatalf("the retry after an injected failure returned %v", err)
	}
	if table.Name == "" {
		t.Error("the retry produced no table name")
	}
	if _, err := store.DescribeBucket(ctx, bucket.Ref); err != nil {
		t.Errorf("the bucket provisioned before the failure is gone: %v", err)
	}

	// Injection is queued and consumed in order, and a sentinel a caller branches
	// on survives the wrapping.
	h.FailNext(fake.OpDescribe, compute.KindBucket, fmt.Errorf("transient: %w", compute.ErrTimeout))
	h.FailNext(fake.OpDescribe, compute.KindBucket, nil2(t))
	if _, err := store.DescribeBucket(ctx, bucket.Ref); !errors.Is(err, compute.ErrTimeout) {
		t.Errorf("DescribeBucket() returned %v, want an error wrapping compute.ErrTimeout", err)
	}
	if _, err := store.DescribeBucket(ctx, bucket.Ref); err == nil {
		t.Error("the second queued failure was not consumed")
	}
	if _, err := store.DescribeBucket(ctx, bucket.Ref); err != nil {
		t.Errorf("DescribeBucket() still failed after the queue drained: %v", err)
	}
}

// nil2 returns a second distinct error for the injection-queue test. It is a
// function so the test reads as "queue two failures" rather than sharing one
// value.
func nil2(t *testing.T) error {
	t.Helper()
	return errors.New("second injected failure")
}

func TestFailNextRefusesANilError(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("FailNext accepted a nil error, which would queue a failure that asserts nothing")
		}
	}()
	fake.New(fake.NewStore(), fake.Config{}).Harness().FailNext(fake.OpEnsure, compute.KindBucket, nil)
}

// TestTheExternalGrantReadBackReportsAForeignGrantRatherThanHidingIt is the
// property [ext.ExternalGrant.Managed] exists for, and the reason the enumeration
// does not filter.
//
// A cross-domain grant this platform did not create is the one grant a reconciler
// must neither count as satisfying its desired state nor try to remove — the
// removal is refused, and deleting a stranger's trust relationship would not be
// recoverable if it were not. Both facts are useless to a caller that cannot see
// the grant, so returning only this platform's own would hide exactly the entry
// the ownership rule exists for.
//
// It also closes the guard's own test gap: GrantExternal and RevokeExternal have
// always refused a foreign grant with [compute.ErrNotOwned], and until
// [fake.Harness.CreateUnownedExternalGrant] existed nothing in this package could
// produce one, so neither refusal had ever been entered.
func TestTheExternalGrantReadBackReportsAForeignGrantRatherThanHidingIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{ExtPorts: true})
	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	granter, err := ext.ExternalAccess("fake", store)
	if err != nil {
		t.Fatalf("ExternalAccess(): %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "shared"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}

	const stranger = "arn:partner:role/somebody-else"
	if err := p.Harness().CreateUnownedExternalGrant(bucket.Ref, stranger); err != nil {
		t.Fatalf("CreateUnownedExternalGrant(): %v", err)
	}

	// Ours as well, so the assertion is about the flag rather than about the
	// bucket having exactly one grant of either kind.
	mine := ext.ExternalPrincipal{ID: "our-partner", Constraints: []string{"our-tenant"}}
	if err := granter.GrantExternal(ctx, bucket.Ref, mine, compute.AccessReadWrite); err != nil {
		t.Fatalf("GrantExternal(): %v", err)
	}

	grants, err := granter.ExternalGrants(ctx, bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants(): %v", err)
	}
	managed := map[string]bool{}
	for _, g := range grants {
		managed[g.Principal.ID] = g.Managed
	}
	if len(grants) != 2 {
		t.Fatalf("ExternalGrants() reported %d grant(s), want both the foreign one and ours: %v",
			len(grants), grants)
	}
	if _, ok := managed[stranger]; !ok {
		t.Errorf("ExternalGrants() omitted the foreign grant to %q. Filtering it out makes the one "+
			"principal a caller must not revoke, and must not count as its own, invisible to the "+
			"only call that could report it", stranger)
	}
	if managed[stranger] {
		t.Errorf("the foreign grant to %q reports Managed true; RevokeExternal will refuse it, so a "+
			"caller told it is ours learns otherwise one failed revoke at a time", stranger)
	}
	if !managed[mine.ID] {
		t.Errorf("this platform's own grant to %q reports Managed false", mine.ID)
	}

	// And the two refusals the fixture makes reachable for the first time.
	if err := granter.RevokeExternal(ctx, bucket.Ref,
		ext.ExternalPrincipal{ID: stranger}); !errors.Is(err, compute.ErrNotOwned) {
		t.Errorf("RevokeExternal on a foreign grant = %v, want compute.ErrNotOwned", err)
	}
	if err := granter.GrantExternal(ctx, bucket.Ref,
		ext.ExternalPrincipal{ID: stranger, Constraints: []string{"ours"}},
		compute.AccessRead); !errors.Is(err, compute.ErrNotOwned) {
		t.Errorf("GrantExternal over a foreign grant = %v, want compute.ErrNotOwned", err)
	}
	// The refusals left it alone, and left it foreign.
	after, err := granter.ExternalGrants(ctx, bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants() after the refusals: %v", err)
	}
	if len(after) != len(grants) {
		t.Errorf("a refused call changed the grant set: %v became %v", grants, after)
	}
	for _, g := range after {
		if g.Principal.ID == stranger && g.Managed {
			t.Error("a refused GrantExternal claimed ownership of the foreign grant it refused to " +
				"overwrite")
		}
	}
}

// TestTheExternalGrantReadBackDoesNotAliasProviderState is the aliasing rule this
// package applies to every other read-back, applied to this one.
//
// A caller that appends to a slice it was handed must not be editing provider
// state. The constraint list is the only reference-typed field a grant carries and
// it is the one that matters: an extra correlation value silently accepted is an
// extra tenant admitted.
func TestTheExternalGrantReadBackDoesNotAliasProviderState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := fake.New(fake.NewStore(), fake.Config{ExtPorts: true})
	store, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores(): %v", err)
	}
	granter, err := ext.ExternalAccess("fake", store)
	if err != nil {
		t.Fatalf("ExternalAccess(): %v", err)
	}
	bucket, err := store.EnsureBucket(ctx, compute.BucketSpec{Name: "shared"})
	if err != nil {
		t.Fatalf("EnsureBucket(): %v", err)
	}
	principal := ext.ExternalPrincipal{ID: "partner", Constraints: []string{"tenant one", "tenant two"}}
	if err := granter.GrantExternal(ctx, bucket.Ref, principal, compute.AccessRead); err != nil {
		t.Fatalf("GrantExternal(): %v", err)
	}

	first, err := granter.ExternalGrants(ctx, bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants(): %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("ExternalGrants() = %v, want one grant", first)
	}
	// Mutate every element in place as well as appending: an append can reallocate
	// and so may not touch the provider's array at all, while an in-place write to
	// a shared backing array always does.
	for i := range first[0].Principal.Constraints {
		first[0].Principal.Constraints[i] = "attacker-supplied"
	}
	first[0].Principal.Constraints = append(first[0].Principal.Constraints, "extra-tenant")

	second, err := granter.ExternalGrants(ctx, bucket.Ref)
	if err != nil {
		t.Fatalf("ExternalGrants() again: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("ExternalGrants() = %v, want one grant", second)
	}
	if !slices.Equal(second[0].Principal.Constraints, principal.Constraints) {
		t.Errorf("mutating a returned read-back changed what the provider reports next: %v, want "+
			"%v. The read-back shares its backing array with the store, so a caller that edits "+
			"what it was handed edits who may reach the bucket",
			second[0].Principal.Constraints, principal.Constraints)
	}
}
