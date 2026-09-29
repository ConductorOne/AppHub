// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"context"
	"time"
)

// Architecture is the CPU architecture a function's code was built for.
type Architecture string

// The architectures the interface admits.
const (
	ArchAMD64 Architecture = "amd64"
	ArchARM64 Architecture = "arm64"
)

// CodeSource is where a function's deployable bundle comes from. Exactly one
// field must be set.
type CodeSource struct {
	// Inline is the bundle itself. Every substrate caps this; a provider must
	// return [ErrInvalidSpec] naming its limit rather than truncate.
	Inline []byte
	// Object points at a bundle already in an object store. Corresponds to the
	// S3Bucket/S3Key path (lambda.go:145-152), generalised: the reference is a
	// [Ref] to a bucket plus a key, not a pair of provider-specific strings.
	Object *ObjectLocation
}

// ObjectLocation addresses one object inside an [ObjectStore] bucket.
type ObjectLocation struct {
	// Bucket is the bucket's [Ref].
	Bucket Ref
	// Key is the object key within the bucket. The provider must reject a key
	// that traverses outside the bucket namespace.
	Key string
}

// FunctionSpec is the desired state of a function.
type FunctionSpec struct {
	// Name is the logical function name, stable across deploys.
	Name string

	// Runtime names the language runtime, in the ecosystem's conventional form
	// — "nodejs20.x", "python3.12", "provided.al2023". These strings originate
	// with AWS and a non-AWS provider will have its own vocabulary, so a
	// provider must validate against the set it supports and return
	// [ErrInvalidSpec] listing them, rather than silently substituting. This is
	// the least portable field in the interface and the design doc says so.
	Runtime string

	// Handler is the entrypoint the runtime invokes within the bundle.
	//
	// Opaque to this interface. "Entrypoint symbol" is a Lambda concept its
	// runtime shim implements; on a container-based runtime a provider can do
	// no more than pass the string to the image and rely on the image honouring
	// the same convention. That makes its meaning a contract between the caller
	// and whatever runtime the operator configured, not something this interface
	// defines or can validate.
	Handler string

	// Code is the deployable bundle.
	Code CodeSource

	// Architecture is what the bundle was built for. Empty means the
	// provider's default.
	Architecture Architecture

	// Resources is the per-invocation allocation.
	//
	// It was MemoryMiB alone, because Lambda charges by memory and derives CPU
	// from it. Any substrate that runs a function as a normal workload needs an
	// explicit CPU request, and with nowhere to put one a provider has to
	// reproduce Lambda's memory-to-CPU ratio — an AWS pricing fact reaching into
	// another substrate's scheduler because the interface had no field for it.
	//
	// [Resources.CPUMillicores] may be zero, meaning "derive it", which is the
	// honest default for a substrate that genuinely does.
	Resources Resources

	// Timeout bounds one invocation.
	Timeout time.Duration

	// Env are non-secret environment variables.
	Env []EnvVar

	// Secrets are secret environment variables.
	Secrets []SecretBinding

	// Identity is the [WorkloadIdentity] the function runs as. Required.
	Identity Ref

	// Capabilities are platform-level grants.
	Capabilities []WorkloadCapability

	// Placement says where to run it. Empty selects the provider default,
	// which for functions is usually correct: the source system deploys Lambda
	// functions with no VPC attachment at all.
	Placement Placement

	// Ingress is the complete set of inbound reachability rules, reconciled to
	// exactly this set on every Ensure — the same contract as [ServiceSpec].
	//
	// Empty is the right answer on Lambda, which has no inbound network surface
	// at all: a function is invoked through the control plane. It is not the
	// right answer on a substrate that implements a function as a workload,
	// where a pod with no policy is reachable by everything around it and the
	// caller had no way to say otherwise. Every other workload spec here carries
	// reachability; this one was the exception by accident.
	//
	// The invoke path is not expressed here. See [FunctionRuntime.EnsureEndpoint].
	Ingress []IngressRule

	// Labels are non-secret metadata.
	Labels map[string]string
}

// FunctionStatus is the observed state of a function.
type FunctionStatus struct {
	Status
	// Spec is the effective desired state, as the provider understood it. See
	// [Status] for why every read-back carries one.
	Spec FunctionSpec
	// Revision identifies the deployed version of the spec. Opaque.
	Revision string
}

// TLSConfig is the certificate an endpoint listener serves.
type TLSConfig struct {
	// CertificateRef names a certificate the provider can resolve. It is
	// operator configuration passed through by the caller; the interface does
	// not manage certificate lifecycle and no provider may invent a default.
	CertificateRef string
}

// ListenerProtocol is what a listener speaks.
type ListenerProtocol string

const (
	// ListenerHTTP is plaintext HTTP. [ListenerSpec.TLS] must be nil.
	ListenerHTTP ListenerProtocol = "http"
	// ListenerHTTPS is HTTP over TLS. [ListenerSpec.TLS] is required.
	ListenerHTTPS ListenerProtocol = "https"
)

// ListenerSpec is one port an endpoint accepts traffic on.
//
// A provider must reject a [ListenerHTTPS] listener with no [TLSConfig], a
// [ListenerHTTPS] listener whose certificate it cannot resolve, and a
// [ListenerHTTP] listener that carries one, each as [ErrInvalidSpec]. That is a
// deliberate divergence from the source system, which creates HTTPS listeners
// with no certificate at all: it picks the HTTPS protocol enum for any port
// other than 80 (lambda.go:487-490) and never populates a Certificates field
// (lambda.go:696-708). Encoding the requirement in the type turns a listener
// that silently does not work into a rejected spec.
//
// Protocol is a field rather than an inference from TLS being nil, and the
// difference matters twice. It makes the certificate-less HTTPS spec above
// *representable*, so the rule can be tested rather than merely asserted — with
// nil-means-plaintext it was unreachable, and the conformance suite had to say
// so instead of checking it. And it matches the substrates that model listeners:
// a Gateway API Listener is {Name, Hostname, Port, Protocol, TLS}, so a provider
// no longer has to guess which of the two a caller meant.
type ListenerSpec struct {
	// Name optionally labels the listener. Substrates that require listener
	// names generate one when this is empty; supplying it makes the generated
	// name stable across deploys.
	Name string
	// Port is the port to listen on.
	Port int
	// Protocol is what the listener speaks. Empty means [ListenerHTTP].
	Protocol ListenerProtocol
	// TLS is the certificate to serve. Required for [ListenerHTTPS], and
	// [ErrInvalidSpec] on any other protocol.
	TLS *TLSConfig
}

// EndpointSpec puts a function behind a stable hostname.
type EndpointSpec struct {
	// Name is the logical endpoint name, stable across deploys.
	Name string
	// Target is the [Ref] of the function to route to.
	Target Ref
	// Listeners are the ports to accept traffic on. At least one is required.
	Listeners []ListenerSpec
	// Hostnames are the names the endpoint should answer on. Empty means
	// provider-assigned, reported in [EndpointStatus.Hostname].
	//
	// Without this the caller chooses the certificate
	// ([TLSConfig.CertificateRef]) and the provider chooses the name it is
	// served under — two decisions that have to agree and that no single party
	// makes. A provider that cannot honour a requested hostname returns
	// [ErrInvalidSpec] rather than substituting its own.
	Hostnames []string
	// Placement says where to put the endpoint.
	Placement Placement
	// Ingress is the complete inbound rule set for the endpoint itself,
	// typically a single [PeerInternet] rule per listener port.
	Ingress []IngressRule
	// Labels are non-secret metadata.
	Labels map[string]string
}

// EndpointStatus is the observed state of an endpoint.
type EndpointStatus struct {
	Status
	// Spec is the effective desired state, as the provider understood it. See
	// [Status] for why every read-back carries one.
	Spec EndpointSpec
	// Hostname is where the endpoint answers. This is the one output the
	// caller actually consumes — everything else the source system threads
	// around (load balancer ARN, target group ARN, security group ID,
	// lambda.go:509-520) is provider bookkeeping that stays behind [Status.Ref].
	Hostname string
}

// FunctionRuntime runs code bundles as invocable functions.
//
// # Sketch: how a Kubernetes provider satisfies this
//
// There is no native equivalent, which is the useful thing to say about it. A
// Kubernetes provider has three honest options: implement it over a serverless
// layer running in-cluster (Knative, OpenFaaS) and advertise [CapFunction];
// implement it as a Deployment wrapping the bundle in a runtime image, which
// changes cold-start and billing behaviour and should be documented as such;
// or advertise neither [CapFunction] nor [CapFunctionEndpoint] and let a
// function deploy fail with a clear [ErrUnsupported]. The third is a legitimate
// answer, and being able to give it cleanly is why the capability exists.
//
// The endpoint half is more portable than the function half: "put this behind a
// hostname on these ports with this certificate" is an Ingress, and the ALB /
// target group / listener triple the source system builds by hand
// (lambda.go:595-710) collapses into one object on most substrates.
type FunctionRuntime interface {
	// EnsureFunction creates or updates a function. Idempotent. Returns without
	// waiting for the function to become invocable.
	EnsureFunction(ctx context.Context, spec FunctionSpec) (*FunctionStatus, error)

	// DescribeFunction returns current state, or [PhaseGone].
	DescribeFunction(ctx context.Context, ref Ref) (*FunctionStatus, error)

	// WaitForFunction blocks until the function is invocable, fails, or the
	// deadline elapses. Substrates that version function configuration and code
	// separately need this between updates; the source system waits twice for
	// exactly that reason (lambda.go:242-245, :261-267).
	WaitForFunction(ctx context.Context, ref Ref, opts WaitOptions) (*FunctionStatus, error)

	// DeleteFunction removes a function. Idempotent.
	DeleteFunction(ctx context.Context, ref Ref) error

	// EnsureEndpoint creates or updates the hostname a function answers on, and
	// grants the endpoint permission to invoke it. Requires
	// [CapFunctionEndpoint].
	//
	// Granting the invoke permission is part of this call rather than a
	// separate step because it has no independent meaning: an endpoint that
	// cannot invoke its target is not a partially-working endpoint, it is a
	// broken one. The source system splits them and then tolerates a failure of
	// the grant with a warning (lambda.go:461-467), which produces exactly that
	// broken state.
	EnsureEndpoint(ctx context.Context, spec EndpointSpec) (*EndpointStatus, error)

	// DescribeEndpoint returns current state, or [PhaseGone].
	DescribeEndpoint(ctx context.Context, ref Ref) (*EndpointStatus, error)

	// WaitForEndpoint blocks until the endpoint is serving, fails, or the
	// deadline elapses.
	WaitForEndpoint(ctx context.Context, ref Ref, opts WaitOptions) (*EndpointStatus, error)

	// DeleteEndpoint removes an endpoint. Idempotent.
	DeleteEndpoint(ctx context.Context, ref Ref) error
}
