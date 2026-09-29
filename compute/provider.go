// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

// Provider is the root of the compute abstraction: one substrate, configured
// once, vending the ports it can supply.
//
// # Why the accessors return errors
//
// The alternative designs both fail. A Provider with every port as a plain
// field forces a substrate that cannot run functions to supply a nil, and the
// first caller to forget a nil check gets a panic instead of a diagnosis. A
// Provider with every method flattened onto one interface forces every
// implementation to write stubs for capabilities it does not have, and the
// stubs are where the misleading behaviour lives.
//
// Returning (port, error) makes the refusal happen at acquisition, once, with
// the provider name and the capability in the message. It also gives the
// conformance suite an invariant it can check exhaustively:
//
//	for every Capability c:
//	    Capabilities().Has(c)  ⟺  the accessor for c returns a nil error
//
// A provider whose advertised capabilities disagree with what its accessors
// hand out is broken in a way no other test would catch.
//
// # Construction and configuration
//
// Constructing a Provider is implementation-specific and deliberately outside
// this interface: compute/aws.New takes AWS configuration, compute/k8s.New
// takes a kubeconfig and a namespace policy. Everything site-specific — cluster
// identifiers, subnet and security-group identifiers, the platform ingress
// proxy's identity, registry hosts, the public DNS suffix, certificate
// references, named [Placement] definitions — is supplied there, by an
// operator, with no defaults compiled in. This package holds no identifier
// belonging to any deployment of it.
type Provider interface {
	// Name identifies the implementation: "aws", "kubernetes", "fake". It is
	// recorded in every [Ref] the provider issues and must be stable across
	// releases, because a Ref persisted last year is compared against it.
	//
	// It names a provider *configuration*, not a substrate. One provider may sit
	// in front of several — a Kubernetes provider satisfying every port is a
	// cluster plus an OCI registry plus an object store plus a database
	// operator, four systems with four identity models — and every [Ref] it
	// issues carries the one name. The consequence is that swapping what sits
	// behind a port invalidates the Refs already issued for it: an operator who
	// replaces the object store keeps bucket Refs that still say "kubernetes"
	// and whose IDs now mean nothing. Splitting [Provider] per substrate would
	// fix that and cost more than it is worth today; treating a name change as a
	// migration is the cheaper discipline.
	Name() string

	// Capabilities reports what this provider can do, in this configuration.
	// It may legitimately differ between two instances of the same
	// implementation — a provider configured with no ingress proxy has fewer
	// capabilities than one that has one.
	Capabilities() CapabilitySet

	// Identities vends the runtime-identity port. Every provider has one.
	Identities() IdentityService

	// Registry vends the image-repository port. Requires [CapImageRegistry].
	Registry() (ImageRegistry, error)

	// Builder vends the image-build port. Requires [CapImageBuild].
	Builder() (ImageBuilder, error)

	// Containers vends the container-runtime port. Requires
	// [CapContainerService].
	Containers() (ContainerRuntime, error)

	// Functions vends the function-runtime port. Requires [CapFunction].
	Functions() (FunctionRuntime, error)

	// ObjectStores vends the object-storage port. Requires [CapObjectStore].
	ObjectStores() (ObjectStore, error)

	// Relational vends the managed-SQL port. Requires [CapRelationalDatabase].
	Relational() (RelationalProvisioner, error)

	// KeyValues vends the key-value-table port. Requires [CapKeyValueTable].
	//
	// Separate from [Provider.Relational] because the two are separate
	// capabilities with separate access-control models, and a single accessor
	// gated on "either" would hand a relational-only provider an interface it
	// can only half implement. See [RelationalProvisioner] for the argument.
	KeyValues() (KeyValueProvisioner, error)

	// Secrets vends the secret-store port. Requires [CapSecretStore].
	Secrets() (SecretStore, error)
}
