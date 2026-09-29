// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/conductorone/apphub/compute"
)

// Substrate is everything the provider talks to.
//
// There are four of them, and the fact that there are four is the first
// finding of this probe. [compute.Provider] is written as though one substrate
// vends every port, which is true of AWS and true of the fake, and is not true
// of Kubernetes: a cluster runs workloads and holds secrets, an OCI registry
// holds images, an S3-compatible service holds objects, and an operator runs
// Postgres. They have four identity systems and four failure modes, and
// [compute.Ref.Provider] records one name for all of them.
type Substrate struct {
	// Cluster is the Kubernetes API server.
	Cluster Cluster
	// Registry is the OCI registry, or nil when none is configured.
	Registry Registry
	// Objects is the S3-compatible object store, or nil when none is
	// configured.
	Objects ObjectStore
}

// NewSubstrate returns an in-memory substrate: a cluster with no controllers of
// its own beyond the ones in controllers.go, a registry, and an object store.
//
// This is what keeps the conformance suite hermetic, and it is why [MemoryCluster]
// and the two in-memory backing stores are kept rather than replaced. A
// production deployment assembles the struct itself from a [ClientCluster], an
// [S3ObjectStore], and a registry client for whichever registry it runs; nothing
// above this struct changes, which is the property the three seams exist for.
func NewSubstrate() *Substrate {
	return &Substrate{
		Cluster:  NewMemoryCluster(),
		Registry: NewMemoryRegistry(),
		Objects:  NewMemoryObjectStore(),
	}
}

// Provider implements [compute.Provider] on Kubernetes.
type Provider struct {
	sub   *Substrate
	cfg   Config
	name  string
	caps  compute.CapabilitySet
	clock *logicalClock
}

var _ compute.Provider = (*Provider)(nil)

// New constructs a provider over sub with cfg.
//
// Every site-specific fact is in cfg. There is no default namespace, no default
// registry host, no default certificate, and no compiled-in cluster identity:
// a provider constructed from a zero Config can run nothing, which is the
// intended failure mode for a misconfigured deployment.
func New(sub *Substrate, cfg Config) *Provider {
	return &Provider{
		sub:   sub,
		cfg:   cfg,
		name:  cfg.name(),
		caps:  cfg.capabilities(),
		clock: sub.clock(),
	}
}

// Name reports the provider name recorded in every [compute.Ref] it issues.
func (p *Provider) Name() string { return p.name }

// Capabilities reports what this instance can do, derived from its
// configuration. See [Config.capabilities].
func (p *Provider) Capabilities() compute.CapabilitySet { return p.caps }

// Identities vends the workload-identity port. Never refused.
func (p *Provider) Identities() compute.IdentityService { return &identityService{p: p} }

// Registry vends the image-repository port.
func (p *Provider) Registry() (compute.ImageRegistry, error) {
	if !p.caps.Has(compute.CapImageRegistry) {
		return nil, p.unsupported(compute.CapImageRegistry,
			"no OCI registry is configured; Kubernetes has no registry of its own")
	}
	return &imageRegistry{p: p}, nil
}

// Builder vends the image-build port.
func (p *Provider) Builder() (compute.ImageBuilder, error) {
	if !p.caps.Has(compute.CapImageBuild) {
		return nil, p.unsupported(compute.CapImageBuild, "no in-cluster builder is configured")
	}
	return &imageBuilder{p: p}, nil
}

// Containers vends the container-runtime port.
func (p *Provider) Containers() (compute.ContainerRuntime, error) {
	if !p.caps.Has(compute.CapContainerService) {
		return nil, p.unsupported(compute.CapContainerService, "")
	}
	return &containerRuntime{p: p}, nil
}

// Functions vends the function-runtime port.
func (p *Provider) Functions() (compute.FunctionRuntime, error) {
	if !p.caps.Has(compute.CapFunction) {
		return nil, p.unsupported(compute.CapFunction,
			"Kubernetes has no function runtime; this provider offers one only when the operator "+
				"configures runtime images for it to wrap a bundle in")
	}
	return &functionRuntime{p: p}, nil
}

// ObjectStores vends the object-storage port.
func (p *Provider) ObjectStores() (compute.ObjectStore, error) {
	if !p.caps.Has(compute.CapObjectStore) {
		return nil, p.unsupported(compute.CapObjectStore,
			"Kubernetes has no object storage; this provider offers it only when the operator "+
				"configures an S3-compatible service")
	}
	return &objectStore{p: p}, nil
}

// Relational vends the managed-SQL port.
func (p *Provider) Relational() (compute.RelationalProvisioner, error) {
	if !p.caps.Has(compute.CapRelationalDatabase) {
		return nil, p.unsupported(compute.CapRelationalDatabase,
			"no Postgres operator is configured in this cluster")
	}
	return &relationalProvisioner{p: p}, nil
}

// KeyValues vends the key-value-table port.
//
// It always refuses. Nothing in or beside a Kubernetes cluster has DynamoDB's
// consistency and capacity semantics, and a table silently backed by something
// with different ones would corrupt data rather than fail — which is exactly
// what [compute.KeyValueProvisioner] predicts a Kubernetes provider will say.
func (p *Provider) KeyValues() (compute.KeyValueProvisioner, error) {
	return nil, p.unsupported(compute.CapKeyValueTable,
		"no managed key-value service is configured; a table backed by something with different "+
			"consistency semantics would corrupt data rather than fail")
}

// Secrets vends the secret-store port.
func (p *Provider) Secrets() (compute.SecretStore, error) {
	if !p.caps.Has(compute.CapSecretStore) {
		return nil, p.unsupported(compute.CapSecretStore, "")
	}
	return &secretStore{p: p}, nil
}

func (p *Provider) unsupported(c compute.Capability, detail string) error {
	return &compute.UnsupportedError{Provider: p.name, Capability: c, Detail: detail}
}

// --- reference handling ------------------------------------------------------

// resolve checks a [compute.Ref] belongs to this provider and addresses the
// expected kind, and returns the substrate coordinates inside it.
func (p *Provider) resolve(ref compute.Ref, kind compute.Kind) (namespace, name string, err error) {
	if ref.Provider != p.name {
		return "", "", fmt.Errorf("%w: %s was issued by %q, this provider is %q",
			compute.ErrForeignRef, ref, ref.Provider, p.name)
	}
	if ref.Kind != kind {
		return "", "", fmt.Errorf("%w: %s addresses a %q, this call takes a %q",
			compute.ErrInvalidSpec, ref, ref.Kind, kind)
	}
	resource, ns, n, ok := parseRefID(ref.ID)
	if !ok || resource != resourceOf[kind] {
		return "", "", fmt.Errorf("%w: %s does not address a resource this provider issued",
			compute.ErrInvalidSpec, ref)
	}
	return ns, n, nil
}

// ref builds a reference for a resource this provider owns.
func (p *Provider) ref(kind compute.Kind, namespace, name string) compute.Ref {
	return compute.Ref{Provider: p.name, Kind: kind, ID: refID(resourceOf[kind], namespace, name)}
}

// --- ownership ----------------------------------------------------------------

// claim reads the object that a name would map to and decides whether this
// platform may write it.
//
// Every provider must implement this check ([compute.ErrNotOwned]); on this
// substrate it is a label comparison, and the interesting part is what it must
// *not* do — see the note on ErrOptimisticConcurrency in cluster.go.
func (p *Provider) claim(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error) {
	obj, err := p.sub.Cluster.Get(ctx, gvk, namespace, name)
	if errors.Is(err, ErrObjectNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, p.substrateError(err)
	}
	if metaLabels(obj)[labelManagedBy] != managedByValue {
		return nil, fmt.Errorf("%w: %s %s/%s exists and does not carry %s=%s",
			compute.ErrNotOwned, gvk.Kind, namespace, name, labelManagedBy, managedByValue)
	}
	return obj, nil
}

// substrateError maps an API-server error onto the [compute] taxonomy.
//
// # The 409 problem
//
// This function is where the probe found a name collision the interface will
// have to resolve. Kubernetes has two unrelated 409s: "somebody else owns this
// name" and "your copy of this object is stale, read it again and retry". The
// first is [compute.ErrNotOwned]. The second is the single most common
// retryable error on the substrate — it happens whenever two reconciles
// overlap — and the [compute] taxonomy has no sentinel for a retryable
// failure at all, so a provider that surfaced it would have to choose between
// [compute.ErrNotOwned], which tells the caller to give up because the resource
// belongs to somebody else, and [compute.ErrFailed], which is documented as not
// retryable.
//
// So this provider does not surface it: it retries internally, and a caller
// above the interface can neither see nor bound that retry. That is a
// workaround for a missing part of the contract, and it is recorded as such.
func (p *Provider) substrateError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrObjectNotFound):
		return fmt.Errorf("%w: %w", compute.ErrNotFound, err)
	case errors.Is(err, ErrOptimisticConcurrency):
		// The substrate's other 409, and the most common retryable failure on
		// it: two reconciles overlapped and this copy is stale. It maps to
		// ErrTransient, not to ErrNotOwned — the taxonomy used to have nowhere
		// to put it, which is what made the old ErrConflict name a trap for
		// anybody porting a Kubernetes client (F2).
		return fmt.Errorf("%w: %w", compute.ErrTransient, err)
	case errors.Is(err, ErrClusterDenied):
		// RBAC, or a credential the API server would not accept. Until this arm
		// existed both fell to the default below and reached a caller as
		// compute.ErrFailed, whose documentation is false for them twice over:
		// no object reached a phase, and what has to change is a ClusterRole
		// this platform runs under rather than anything in the caller's spec. An
		// operator reading ErrFailed cannot tell "apphub is under-privileged"
		// from "the resource broke". See [compute.ErrNotPermitted].
		return fmt.Errorf("%w: %w", compute.ErrNotPermitted, err)
	default:
		return fmt.Errorf("%w: %w", compute.ErrFailed, err)
	}
}

// backingError maps an error from one of the non-cluster substrates — the
// registry or the object store — onto the [compute] taxonomy.
//
// # Why it is not the identity function
//
// The in-memory backing stores return compute-taxonomy errors directly, because
// an in-memory map's only failure is "that name is not here". A real client's
// failures are HTTP: a 404, a 403, a 429, a 503, a dialling error, a context
// deadline. Those are not compute errors and must not be handed to a caller as
// [compute.ErrFailed] indiscriminately — a 503 from an object store is a
// transient failure a retry would fix, and telling a caller its spec has to
// change is the same defect [compute.ErrTransient] was added to fix for the
// cluster (F2).
//
// An error that already carries a compute sentinel passes through unchanged, so
// the in-memory stores keep behaving exactly as they did.
func (p *Provider) backingError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, compute.ErrNotFound),
		errors.Is(err, compute.ErrNotOwned),
		errors.Is(err, compute.ErrInvalidSpec),
		errors.Is(err, compute.ErrUnsupported),
		errors.Is(err, compute.ErrTransient),
		errors.Is(err, compute.ErrNotPermitted),
		errors.Is(err, compute.ErrForeignRef),
		errors.Is(err, compute.ErrTimeout):
		return err
	case errors.Is(err, ErrBackingTransient):
		return fmt.Errorf("%w: %w", compute.ErrTransient, err)
	case errors.Is(err, ErrRegistryDenied), errors.Is(err, ErrObjectStoreDenied):
		// The registry's 403 and the object store's. Both sentinels predate this
		// arm and neither was mapped: they fell to the default below, so
		// [S3ObjectStore]'s "refused the credential (HTTP 403)" — a real
		// response from a real store, not only an injected one — reached a
		// caller as compute.ErrFailed. The same reasoning as the cluster's
		// denial in [Provider.substrateError] applies, and it applies here to a
		// path that was already live.
		return fmt.Errorf("%w: %w", compute.ErrNotPermitted, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The caller asked to stop. Returning ErrTransient here would tell it to
		// try again, which inverts the instruction it just gave — the same
		// reasoning as in Provider.apply.
		return err
	default:
		return fmt.Errorf("%w: %w", compute.ErrFailed, err)
	}
}

// storeError maps an object-store error. See [Provider.backingError].
func (p *Provider) storeError(err error) error { return p.backingError(err) }

// registryError maps a registry error. See [Provider.backingError].
func (p *Provider) registryError(err error) error { return p.backingError(err) }

// applyAttempts bounds the provider's own read-modify-write retry.
//
// A provider may retry internally and this one does: a stale-read conflict is
// routine on this substrate and a caller should not have to know that an apply
// is read-modify-write underneath. What changed with ErrTransient is what
// happens when the budget runs out — the caller now gets an error that says
// "retry" instead of one that says "the spec has to change", so it can decide
// for itself rather than abandoning a deploy that would have worked.
const applyAttempts = 5

func (p *Provider) apply(ctx context.Context, gvk schema.GroupVersionKind, obj runtime.Object) error {
	var err error
	for range applyAttempts {
		// The caller's deadline bounds the retry, not the provider's budget:
		// ErrTransient says a provider must not retry past it.
		//
		// The context error is returned as itself rather than wrapped as
		// ErrTransient. A cancelled caller is not a substrate failure that a
		// retry would fix — the caller asked to stop, and telling it "try again"
		// inverts the instruction it just gave. Whether to reissue the call with
		// a fresh context is the caller's decision to make with its own
		// information, not something the provider should recommend.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		err = p.sub.Cluster.Apply(ctx, gvk, obj)
		if !errors.Is(err, ErrOptimisticConcurrency) {
			break
		}
	}
	return p.substrateError(err)
}

// --- clock --------------------------------------------------------------------

// logicalClock supplies [compute.Status.UpdatedAt].
//
// A Kubernetes object has no "when the provider observed this" timestamp — the
// nearest thing is a condition's lastTransitionTime, which is when the
// *controller* wrote it, not when the caller read it. [compute.Status] does not
// say which of the two it wants, or whose clock it is, so two providers will
// differ. This one uses a monotonic logical clock seeded from the substrate, so
// the probe is deterministic and the ambiguity is visible rather than papered
// over with time.Now.
type logicalClock struct {
	base time.Time
	tick func() int64
}

func (c *logicalClock) now() time.Time { return c.base.Add(time.Duration(c.tick()) * time.Millisecond) }
