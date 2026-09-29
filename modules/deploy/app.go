// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials/workload"
)

// WorkloadType says which runtime an application runs on.
//
// The code this was ported from called this AppType and its two values were
// "ECS" and "Lambda" — the names of two AWS services
// (services/application_components.go:299-300), so every branch on it was a
// branch on a cloud service. Above the interface the same choice is a choice
// between a long-running workload and an invoked one, which is a property of
// the application rather than of the substrate, and a provider that offers
// neither refuses at the accessor.
type WorkloadType string

const (
	// WorkloadContainer is a long-running container workload.
	WorkloadContainer WorkloadType = "container"
	// WorkloadFunction is an invoked function.
	WorkloadFunction WorkloadType = "function"
)

// ExecutionMode says whether a container workload runs continuously or on a
// schedule.
type ExecutionMode string

const (
	// ExecutionService keeps replicas running.
	ExecutionService ExecutionMode = "service"
	// ExecutionScheduled runs the workload on a cadence and not otherwise.
	ExecutionScheduled ExecutionMode = "scheduled"
)

// DatabaseKind says what kind of database, if any, an application wants.
type DatabaseKind string

const (
	// DatabaseNone is no database.
	DatabaseNone DatabaseKind = ""
	// DatabaseRelational is a managed SQL database.
	DatabaseRelational DatabaseKind = "relational"
	// DatabaseKeyValue is a key-value table.
	DatabaseKeyValue DatabaseKind = "key-value"
)

// BucketKind says what kind of object storage, if any, an application wants.
//
// The portable kinds are here; the two the source offered that no other
// substrate has — analytic table buckets and vector buckets — are not, and an
// application configured for one is refused with the port named. See the
// decision record: the alternative is provisioning something else and handing
// the application an identifier it cannot connect to.
type BucketKind string

const (
	// BucketNone is no bucket.
	BucketNone BucketKind = ""
	// BucketStandard is ordinary object storage.
	BucketStandard BucketKind = "standard"
	// BucketZonal is object storage pinned to one zone.
	BucketZonal BucketKind = "zonal"
)

// Source locates the application's code.
type Source struct {
	// URL is the repository to fetch. Validated by [ValidateSourceURL] before
	// it reaches anything that would fetch it.
	URL string
	// Ref is the branch, tag or commit to fetch. Empty means the repository's
	// default branch, which is the fetcher's decision and not this module's.
	Ref string
	// Dockerfile is the path to the image definition within the fetched tree,
	// relative to its root. Empty means the fetcher's convention.
	Dockerfile string
}

// Database describes an application's database.
type Database struct {
	// Kind selects the database, or none.
	Kind DatabaseKind
	// Engine and EngineVersion apply to [DatabaseRelational]. An empty engine
	// is refused rather than defaulted: which SQL dialect an application speaks
	// is not something to guess.
	Engine        compute.SQLEngine
	EngineVersion string
	// DatabaseName and AdminUsername apply to [DatabaseRelational].
	DatabaseName  string
	AdminUsername string
	// Capacity applies to [DatabaseRelational].
	Capacity compute.CapacityRange
	// Extensions are exact allowlisted PostgreSQL extension names.
	Extensions []string
	// PartitionKey and SortKey apply to [DatabaseKeyValue].
	PartitionKey string
	SortKey      string
}

// Bucket describes an application's object storage.
type Bucket struct {
	// Kind selects the bucket, or none.
	Kind BucketKind
	// Name is the operator-chosen bucket name. Empty means one derived from the
	// application, which is what the source did for every bucket it created.
	Name string
	// Zone applies to [BucketZonal].
	Zone string
	// Access is the level the application's own identity is granted on it.
	// Empty means [github.com/conductorone/apphub/compute.AccessReadWrite], which
	// is what an application storing its own objects needs; an application that
	// only reads sets it explicitly, and least privilege is then the record's
	// to state rather than this module's to assume.
	Access compute.AccessLevel
}

// Route publishes an application on a hostname.
type Route struct {
	// Hostname is the label the route is published under, within
	// [Config.RouteDomain]. It is required for a route to exist: the source
	// derived one from the application name when it was empty, and then had to
	// stop, because a derived hostname is one nobody reserved and anybody can
	// claim (container.go:1341-1348). Here an application that asks for a route
	// without one is refused.
	Hostname string
	// Internal publishes the route under [Config.InternalRouteDomain] on the
	// platform's internal ingress only: reachable inside the network, never
	// from the internet.
	Internal bool
	// RequireAuth puts the route behind the platform's authenticating proxy.
	RequireAuth bool
	// PublicPaths are paths exempt from RequireAuth. Ignored when RequireAuth
	// is false, and the provider is the one that enforces that.
	PublicPaths []string
	// MCPAuthApplicationID protects /mcp with AppHub OAuth and publishes MCP
	// discovery metadata for this application. Empty leaves the path untouched.
	MCPAuthApplicationID string
	// AllowPlaintext permits serving this route without TLS. False is the
	// fail-closed default and the value an application record should carry;
	// a provider with no certificate for the route refuses rather than serving
	// it in the clear.
	AllowPlaintext bool
}

// SecretBinding names a secret the provider already holds and the environment
// variable to expose it to the workload as.
//
// The reference is a provider-issued [github.com/conductorone/apphub/compute.Ref]
// and not a name, and that is a correction rather than a preference. This field
// was a list of names, documented as "already held in the provider's store
// under this application's scope" — and the deploy path could not resolve one.
// [github.com/conductorone/apphub/compute.SecretStore] has Put, Get, Delete and
// DeleteScope, and Get already needs the Ref; there is no operation that turns
// a scope and a name into one. So a caller could supply exactly the documented
// input and the deploy would fail at binding time, after the identity, the
// repository and the image had been created.
//
// A Ref is resolvable by construction and checkable before anything is created:
// [newPlan] refuses one this provider did not issue, one that is not a secret,
// and a duplicate target variable. That is the shape the interface can honour
// today.
//
// Making a *name* work again needs a provider-side lookup, which is an
// interface question rather than this module's to invent. It is written up in
// the report as a follow-up.
type SecretBinding struct {
	// EnvName is the environment variable the workload sees. Required.
	EnvName string
	// Secret is the reference the provider issued when the secret was stored.
	// Required, and it must have been issued by the provider this module is
	// deploying against.
	Secret compute.Ref
}

// Artifacts is what a deploy created, recorded so the next one can find it and
// a teardown can remove it.
//
// It is written back through [Store] on success and on failure alike. A deploy
// that created a bucket and then failed to start the workload has created a
// bucket, and a record that forgets it is a record that leaks it.
type Artifacts struct {
	// Repository is the image repository.
	Repository compute.Ref
	// Image is the exact image the workload runs.
	Image compute.ImageRef
	// Identity is the workload's runtime identity.
	Identity compute.Ref
	// Workload is the service, scheduled job or function.
	Workload compute.Ref
	// Addresses are HTTPS links to configured TLS route hosts reported by the provider.
	Addresses []string
	// Bucket, Relational and KeyValue are the data resources, when asked for.
	Bucket     compute.Ref
	Relational compute.Ref
	KeyValue   compute.Ref
	// Secrets maps a secret's logical name to the reference the provider issued
	// for it. It is what makes a stored secret findable on the next deploy and
	// removable on teardown.
	Secrets map[string]compute.Ref
	// Attestation is the identity policy a valid workload must prove.
	//
	// Persisting it is this layer's obligation under the workload-identity
	// contract: compute creates the identity and reports what it is,
	// credentials verifies a proof against a policy, and the policy has to be
	// kept by whoever knows both — which is here. It carries no secret material
	// by construction and is safe to store.
	Attestation workload.ExpectedAttestation
	// AttestationRevision is the revision the credential side issued for this
	// deploy, as returned by its Rotate.
	AttestationRevision int
}

// Status is where an application is in its lifecycle.
type Status string

const (
	// StatusDeploying means a deploy is in progress.
	StatusDeploying Status = "deploying"
	// StatusRunning means the service is ready or the schedule is installed.
	StatusRunning Status = "running"
	// StatusFailed means the last deploy did not finish.
	StatusFailed Status = "failed"
)

// Application is the deploy module's view of an application.
//
// It is not a database row and not a wire type. [Store] is the port a caller
// implements over whatever it does keep them in, which is what keeps this
// package free of a persistence dependency — the same rule that keeps it free
// of a cloud SDK, applied to the other side.
type Application struct {
	// ID is the application's stable identifier. It is the scope every secret
	// this module stores is filed under, so teardown can enumerate them.
	ID string
	// Name is the human-readable name resource names are derived from.
	Name string

	// Source locates the code.
	Source Source
	// Workload selects the runtime.
	Workload WorkloadType
	// Execution selects service or scheduled, for [WorkloadContainer].
	Execution ExecutionMode
	// Schedule applies to [ExecutionScheduled].
	Schedule compute.Schedule

	// Resources is the CPU and memory the workload gets.
	Resources compute.Resources
	// Replicas is how many copies run. Zero means one.
	Replicas int
	// Port is the port the workload listens on.
	Port int
	// Runtime and Handler apply to [WorkloadFunction].
	Runtime string
	Handler string

	// Database and Bucket are the data resources.
	Database Database
	Bucket   Bucket

	// Secrets are secrets already held by the provider, bound into the workload
	// by reference. This module does not create them and never reads their
	// values.
	Secrets []SecretBinding
	// EnvSecrets names the owner's environment secrets the workload receives.
	// Values never appear here: those set on a deploy arrive through
	// [SecretValueSource], and the rest are already stored. A stored one no
	// longer listed is deleted by that deploy. See envsecrets.go.
	EnvSecrets []string
	// PinnedImage, when set, is run instead of building one: the source is
	// neither fetched nor built, and everything after the build converges as
	// usual. It is the image of an earlier successful deploy of the same
	// specification, for a deploy that changes only runtime configuration
	// such as secrets. It must be an immutable reference the provider pushed.
	PinnedImage compute.ImageRef
	// Capabilities are platform capabilities the workload is granted, such as
	// model inference. Each is checked against the provider before it is asked
	// for.
	Capabilities []compute.WorkloadCapability

	// Routes publish the application. Empty means it is not published.
	Routes []Route

	// Labels are non-secret metadata attached to everything this deploy
	// creates.
	Labels map[string]string

	// Status, FailedStep and FailureClass record the last deploy's outcome.
	//
	// FailureClass is a classification and not a provider's message, which is a
	// deliberate departure from the source: it persisted err.Error() verbatim
	// (container.go:999), and a provider is free to put anything in an error
	// string. See recordFailure.
	Status Status
	// DeployStep is the module-authored current intent/checkpoint, not provider text.
	DeployStep   string
	FailedStep   string
	FailureClass string
	// LastDeployedAt is when the last successful deploy finished.
	LastDeployedAt time.Time

	// Artifacts is what the last deploy created.
	Artifacts Artifacts
}

// Store is the persistence port this module needs.
//
// It is declared here and implemented by the caller: a module that imported its
// own persistence would carry that dependency into every adopter's build, and
// the point of this tree is that it does not.
type Store interface {
	// GetApplication returns the application, or an error. Returning
	// (nil, nil) for an unknown ID is not permitted: it turns a missing
	// application into a nil dereference several frames away.
	GetApplication(ctx context.Context, id string) (*Application, error)
	// SaveApplication persists the record, including its artifacts and status.
	SaveApplication(ctx context.Context, app *Application) error
}

// SourceFetcher materialises an application's source into a local directory an
// image build can use.
//
// Declared here and implemented by the caller for the same reason as [Store],
// and one more: fetching means running a version-control client with
// credentials for a code host, and neither the process execution nor the
// credentials belong in a package whose claim is that it talks to one
// abstraction. The source did this inline, with a personal access token read
// from the process environment (container.go:167-170).
//
// An implementation is handed a location this module has already validated with
// [ValidateSourceURL], and must not widen it.
type SourceFetcher interface {
	// Fetch places the source at a directory it chooses and returns the path.
	// The directory belongs to the fetcher: this module reads nothing from it
	// and only passes it to the provider's builder.
	Fetch(ctx context.Context, src Source) (dir string, err error)
}

// AttestationProvisioner is the credential side of workload identity, as the
// workload-identity contract defines it: rotate, then ask for materials with
// the revision rotate returned.
//
// It is [github.com/conductorone/apphub/credentials/workload.Provisioner] narrowed
// to nothing — the shapes are identical — and it is declared here so this
// package states what it needs rather than importing a supplier. Anything
// satisfying workload.Provisioner satisfies this.
type AttestationProvisioner interface {
	// Rotate invalidates the current attestation material and issues new
	// material, returning the new revision.
	Rotate(ctx context.Context, ref workload.Ref) (revision int, err error)
	// Materials returns what to inject for this workload.
	Materials(ctx context.Context, ref workload.Ref) (workload.Materials, error)
}
