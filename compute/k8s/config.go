// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"fmt"
	"sort"

	"github.com/conductorone/apphub/compute"
)

// PlacementConfig is what an operator attaches to a [compute.Placement] name.
//
// This is the whole of the network model on this substrate, and it is worth
// listing because the list is the evidence for the claim in
// docs/design/compute-provider.md that no AWS network identifier reaches an
// interface input: everything below is a Kubernetes concept an operator already
// has, and none of it is expressible as, or derivable from, a subnet, VPC,
// security group, or account identifier. The caller supplies a name; the
// operator supplies this.
type PlacementConfig struct {
	// Name is the placement's configured name. It is filled in by the lookup
	// rather than by the operator, so that a resolved placement can be echoed
	// back in an effective spec without the caller's empty "use the default"
	// surviving into a read-back.
	Name string
	// Namespace is where the placement's objects go.
	Namespace string
	// NodeSelector constrains scheduling.
	NodeSelector map[string]string
	// StorageClass is the class a relational endpoint's volumes are cut from.
	StorageClass string
	// IngressClassName selects the ingress controller for a [compute.Route].
	IngressClassName string
}

// PodSelector names a set of pods by namespace and label, which is how a
// Kubernetes NetworkPolicy identifies a peer.
//
// This is the substrate's answer to [compute.PeerKind]: a role in the system
// becomes a namespace plus a label selector, exactly as it becomes a security
// group on AWS. It is operator configuration and never an interface input.
type PodSelector struct {
	// Namespace is the peer's namespace.
	Namespace string
	// Labels select the peer's pods within it.
	Labels map[string]string
}

// IsZero reports whether the selector names nothing.
func (s PodSelector) IsZero() bool { return s.Namespace == "" && len(s.Labels) == 0 }

// RegistryConfig points the provider at an OCI registry with an admin API —
// Harbor, GAR, ECR, Quay.
//
// A registry is not part of Kubernetes. A provider that offers
// [compute.CapImageRegistry] on this substrate is really two systems wearing one
// name, and [compute.ImageRegistry]'s embedded [compute.Granter] is where that
// shows: see registry.go.
type RegistryConfig struct {
	// Host is the registry hostname images are pulled from.
	Host string
	// Project is the namespace within the registry that this platform owns.
	Project string
	// SupportsRetention reports whether the registry has a lifecycle feature.
	// A registry with none must refuse a [compute.RetentionPolicy] rather than
	// accept one it will not apply.
	SupportsRetention bool
	// SupportsScanning reports whether the registry can scan on push.
	SupportsScanning bool

	// FederatesClusterOIDC reports whether the registry can exchange a
	// cluster-issued ServiceAccount token for pull authorisation, so that a
	// grant can name the workload identity instead of a stored credential.
	//
	// Combined with [Config.KubeletCredentialProvider], this is what makes
	// [compute.ImageRegistry]'s embedded [compute.Granter] implementable as an
	// actual grant. Without both, it is not — see registry.go.
	FederatesClusterOIDC bool
}

// ObjectStoreConfig points the provider at an S3-compatible object store —
// MinIO, Ceph RGW, or a cloud bucket service — that authenticates workloads by
// the OIDC token Kubernetes projects into their pods.
//
// The OIDC requirement is not incidental. It is the only thing that makes
// [compute.ObjectStore]'s embedded [compute.Granter] meaningful here: without
// it there is no mapping from a ServiceAccount to a storage principal, and the
// port would be in the same position as the image registry.
type ObjectStoreConfig struct {
	// Endpoint is the S3 API endpoint clients use.
	Endpoint string
	// URIScheme is the scheme the provider reports in [compute.Bucket.URI].
	URIScheme string
	// TrustsClusterOIDC reports whether the store is configured to accept the
	// cluster's projected ServiceAccount tokens as a principal.
	TrustsClusterOIDC bool
}

// PostgresOperatorConfig describes an in-cluster Postgres operator —
// CloudNativePG, Zalando, Crunchy.
type PostgresOperatorConfig struct {
	// APIVersion and Kind are the operator's cluster resource. They are
	// configuration rather than constants because the three operators disagree,
	// and hardcoding one would make "a Kubernetes provider" mean "a
	// CloudNativePG provider".
	APIVersion string
	Kind       string
	// Versions are the major engine versions the operator's images cover.
	Versions []string
	// InstanceMillicoresPerUnit converts a [compute.CapacityRange] unit into a
	// CPU request. See database.go for why this is a translation and not an
	// equivalence.
	InstanceMillicoresPerUnit int
	// InstanceMiBPerUnit converts a unit into a memory request.
	InstanceMiBPerUnit int
}

// Config is everything an operator supplies when constructing the provider.
//
// The shape of this struct is itself a finding. A "Kubernetes provider" that
// satisfies every port of [compute.Provider] is not one substrate: it is a
// cluster, plus a registry, plus an object store, plus a database operator,
// each with its own identity system and its own failure modes. See
// docs/design/k8s-contract-probe.md.
type Config struct {
	// Name is the provider name recorded in every [compute.Ref]. Empty means
	// "kubernetes".
	Name string

	// Placements are the named placements this instance knows. A name absent
	// from this map is [compute.ErrInvalidSpec]; the provider never guesses.
	Placements map[string]PlacementConfig

	// DefaultPlacement is used for the empty placement name. Empty means the
	// provider has no default and refuses an empty name.
	DefaultPlacement string

	// OIDCIssuer and OIDCAudience describe the cluster's ServiceAccount token
	// issuer. They become the [workload.ExpectedAttestation] a workload
	// identity reports.
	OIDCIssuer   string
	OIDCAudience string

	// IngressProxy identifies the ingress controller's pods, so that a
	// [compute.PeerPlatformIngress] rule has something to name. Zero means no
	// proxy is configured, and the provider then rejects such a rule rather
	// than widening it.
	IngressProxy PodSelector

	// ControlPlane identifies apphub's own pods, for [compute.PeerControlPlane].
	ControlPlane PodSelector

	// IngressAddress is where the ingress controller answers, reported back in
	// [compute.ServiceStatus.RouteAddresses] so a caller can point DNS at it.
	// Empty means the operator has not told the provider, and the field is then
	// reported empty rather than guessed.
	IngressAddress string

	// EndpointDomain is the public DNS suffix a function endpoint's hostname is
	// composed under.
	//
	// It exists because compute.EndpointSpec has no hostname field: a
	// compute.Route names its own host, an endpoint does not, so the provider
	// composes one. The domain is operator configuration with no default, as
	// every site-specific identifier in this repository must be.
	EndpointDomain string

	// GatewayAPI reports whether the Gateway API CRDs are installed. It gates
	// [compute.CapFunctionEndpoint], because a listener on an arbitrary port
	// with its own certificate is a Gateway listener and is not expressible as
	// a networking.k8s.io Ingress.
	GatewayAPI bool

	// Certificates maps a [compute.TLSConfig.CertificateRef] to the name of a
	// TLS Secret in the placement's namespace. A reference absent from this map
	// is unresolvable and the listener is refused.
	Certificates map[string]string

	// FunctionRuntimes maps a [compute.FunctionSpec.Runtime] identifier onto
	// the container image that runs bundles for it. Empty means the provider
	// does not offer functions at all, which is one of the three honest answers
	// the design document lists.
	//
	// The keys are the operator's vocabulary, not AWS's. See function.go.
	FunctionRuntimes map[string]string

	// MaxInlineBundleBytes bounds [compute.CodeSource.Inline]. Zero means the
	// ConfigMap limit, which is what a bundle ends up in on this substrate.
	MaxInlineBundleBytes int

	// Registry, ObjectStore, and PostgresOperator are the three non-Kubernetes
	// systems. A nil pointer means the capability is not offered.
	Registry         *RegistryConfig
	ObjectStore      *ObjectStoreConfig
	PostgresOperator *PostgresOperatorConfig

	// BuildKit reports whether the cluster runs a BuildKit daemon the provider
	// may submit builds to.
	BuildKit bool

	// KubeletCredentialProvider reports whether every node runs a kubelet
	// credential-provider plugin configured to receive a pod-bound
	// ServiceAccount token.
	//
	// https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/#service-account-token-for-image-pulls
	//
	// This is the mechanism that lets an image pull be authorised from the
	// workload's own identity on Kubernetes: the kubelet remains the network
	// actor, but the token it hands the plugin is the pod's, so the registry
	// authorises the ServiceAccount. It is a per-node kubelet configuration
	// rather than a cluster API object, it is recent, and it is not the default,
	// which is exactly why the provider has to be told about it rather than
	// discovering it. See registry.go.
	KubeletCredentialProvider bool
}

// pullByWorkloadIdentity reports whether this configuration can authorise an
// image pull from the workload's own identity, with no stored credential in
// between.
//
// Both halves are required and neither is universal: the cluster needs a
// kubelet credential provider that forwards a pod-bound ServiceAccount token,
// and the registry needs to accept one. A cluster with either half missing
// falls back to an imagePullSecret, which is a persisted credential.
func (c *Config) pullByWorkloadIdentity() bool {
	return c.KubeletCredentialProvider && c.Registry != nil && c.Registry.FederatesClusterOIDC
}

// configMapLimitBytes is the Kubernetes limit on the total size of an object,
// and therefore the ceiling on an inline function bundle stored as one.
const configMapLimitBytes = 1 << 20

func (c *Config) name() string {
	if c.Name == "" {
		return "kubernetes"
	}
	return c.Name
}

func (c *Config) maxInlineBundle() int {
	if c.MaxInlineBundleBytes == 0 {
		return configMapLimitBytes
	}
	return c.MaxInlineBundleBytes
}

// placement resolves a [compute.Placement] to its configuration, or refuses.
//
// Refusing is the point: the source system degrades an unusable region to a
// logged warning and a silent fallback, which strands resources somewhere
// nothing addresses.
func (c *Config) placement(p compute.Placement) (PlacementConfig, error) {
	name := p.Name
	if name == "" {
		if c.DefaultPlacement == "" {
			return PlacementConfig{}, fmt.Errorf(
				"%w: provider %q has no default placement, so a spec must name one of %v",
				compute.ErrInvalidSpec, c.name(), c.placementNames())
		}
		name = c.DefaultPlacement
	}
	pc, ok := c.Placements[name]
	if !ok {
		return PlacementConfig{}, fmt.Errorf(
			"%w: placement %q is not configured on provider %q; the configured placements are %v",
			compute.ErrInvalidSpec, name, c.name(), c.placementNames())
	}
	if pc.Namespace == "" {
		return PlacementConfig{}, fmt.Errorf(
			"%w: placement %q is configured with no namespace", compute.ErrInvalidSpec, name)
	}
	pc.Name = name
	return pc, nil
}

// placementForNamespace is the inverse of [Config.placement]: it names the
// placement a namespace belongs to.
//
// A namespace this provider was not configured with is an error rather than a
// guess. Reporting the namespace itself as a placement name would hand a caller
// a value that means nothing to the interface and looks like one that does.
func (c *Config) placementForNamespace(ns string) (string, error) {
	for name, pc := range c.Placements {
		if pc.Namespace == ns {
			return name, nil
		}
	}
	return "", fmt.Errorf("%w: namespace %q belongs to no placement configured on provider %q; "+
		"the configured placements are %v", compute.ErrInvalidSpec, ns, c.name(), c.placementNames())
}

func (c *Config) placementNames() []string {
	out := make([]string, 0, len(c.Placements))
	for k := range c.Placements {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// capabilities derives the capability set from the configuration.
//
// Derived rather than declared, because [compute.Provider.Capabilities] says a
// capability set may legitimately differ between two instances of the same
// implementation. On this substrate almost every capability is a fact about
// what else the operator runs, so a hand-written list would be a second source
// of truth that could disagree with the configuration the accessors read.
func (c *Config) capabilities() compute.CapabilitySet {
	caps := compute.NewCapabilitySet(
		// A Deployment, a CronJob, a Secret, and an exec-able Pod need nothing
		// beyond the cluster itself.
		compute.CapContainerService,
		compute.CapScheduledJob,
		compute.CapSecretStore,
		compute.CapWorkloadExec,
	)
	add := func(ok bool, c compute.Capability) {
		if ok {
			caps[c] = struct{}{}
		}
	}
	add(c.Registry != nil, compute.CapImageRegistry)
	add(c.BuildKit, compute.CapImageBuild)
	add(len(c.FunctionRuntimes) > 0, compute.CapFunction)
	// An endpoint listens on a caller-chosen port with a caller-chosen
	// certificate. networking.k8s.io/v1 Ingress cannot express either, so the
	// capability tracks the Gateway API rather than the cluster.
	add(len(c.FunctionRuntimes) > 0 && c.GatewayAPI, compute.CapFunctionEndpoint)
	add(c.ObjectStore != nil, compute.CapObjectStore)
	add(c.PostgresOperator != nil, compute.CapRelationalDatabase)
	// A configured ingress proxy can be named in NetworkPolicy peers. It does
	// not imply CapIngressAuth: this provider cannot configure any controller
	// to enforce authentication on the Ingress it creates.
	add(!c.IngressProxy.IsZero(), compute.CapPlatformIngress)
	// The object store is this provider's only Granter port, so it decides
	// whether grants work at all. A store that does not federate the cluster's
	// issuer has no principal a ServiceAccount maps to, and Grant is
	// ErrUnsupported — which a caller can now check before provisioning
	// something it will not be able to authorise.
	add(c.ObjectStore != nil && c.ObjectStore.TrustsClusterOIDC, compute.CapWorkloadGrants)
	// Identity-scoped image pulls need both halves: a kubelet credential
	// provider carrying a pod-bound ServiceAccount token, and a registry that
	// federates the cluster's issuer. Absent either, the provider still
	// discharges the ImageRegistry obligation with a per-repository robot
	// credential; it just cannot offer the caller a grant, and says so.
	add(c.pullByWorkloadIdentity(), compute.CapImagePullGrants)
	// Deliberately absent, with reasons, in doc.go:
	//   CapObjectStoreZonal  — no S3-compatible store surveyed offers a
	//                          single-zone durability/latency trade as a bucket
	//                          class.
	//   CapKeyValueTable     — nothing in or beside a cluster has DynamoDB's
	//                          semantics, and something with different ones
	//                          would corrupt data rather than fail.
	//   CapModelInference    — there is no cluster-native managed foundation
	//                          model to grant a ServiceAccount access to.
	return caps
}
