// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import "context"

// SQLEngine names the wire protocol and dialect a relational endpoint speaks.
//
// The application connects with a normal driver, so what matters is the
// dialect, not the product. "Aurora Serverless v2 PostgreSQL 16" is an AWS
// answer to "give me Postgres 16"; the caller only ever needed to ask the
// question.
type SQLEngine string

// The SQL engines the interface admits. Only [EnginePostgres] is used today;
// [EngineMySQL] is present so the type is an enumeration rather than a
// single-valued placeholder, and a provider is free to support neither.
const (
	EnginePostgres SQLEngine = "postgres"
	EngineMySQL    SQLEngine = "mysql"
)

// CapacityRange bounds how much compute a relational endpoint may use.
//
// Abstract units, deliberately. The source system pins Aurora Serverless v2 to
// 0.5–4 ACUs (source system @ backend/internal/modules/deploy/database.go),
// and an ACU is an AWS billing construct with
// no meaning anywhere else. A provider maps the range onto its own sizing and
// documents the mapping; a provider with fixed sizing picks the smallest size
// that covers Max and reports it in [Status.Message].
type CapacityRange struct {
	// MinUnits is the floor. One unit is roughly one vCPU with proportionate
	// memory. Zero means the provider's minimum.
	MinUnits float64
	// MaxUnits is the ceiling. Zero means the provider's default ceiling, which
	// must be finite: an unbounded default is a billing incident.
	MaxUnits float64
}

// RelationalSpec is the desired state of a managed SQL endpoint.
type RelationalSpec struct {
	// Name is the logical name, stable across deploys.
	Name string

	// Engine is the dialect.
	Engine SQLEngine

	// EngineVersion is the major version, e.g. "16". Major only: pinning a
	// minor makes provisioning fail the day the substrate retires it, which the
	// source system learned and documented in place (source system @
	// backend/internal/modules/deploy/database.go).
	// A provider must reject a spec whose version it cannot supply rather than
	// substitute a different one.
	EngineVersion string

	// DatabaseName is the initial database to create.
	DatabaseName string

	// AdminUsername is the initial superuser-equivalent account.
	AdminUsername string

	// AdminPassword is that account's password. The caller generates it,
	// stores it in a [SecretStore], and passes it here; the provider uses it to
	// create the endpoint and must not retain, log, or return it.
	//
	// The order matters and is the caller's responsibility: store the secret
	// before provisioning, so that a provisioning failure leaves a recoverable
	// password rather than an endpoint nobody can log into. The source system
	// gets this right, and guards the redeploy case by checking for an existing
	// cluster before generating a new password at all (source system @
	// backend/internal/modules/deploy/container.go) —
	// a provider must likewise never rotate the admin password on a
	// re-Ensure, because the caller's stored copy would silently become wrong.
	AdminPassword SecretValue

	// Capacity bounds the compute allocation.
	Capacity CapacityRange

	// Placement says where to put it.
	Placement Placement

	// Ingress is the complete inbound rule set. In practice: the application's
	// workload, and [PeerControlPlane] so that apphub can connect to create
	// roles and extensions.
	Ingress []IngressRule

	// Labels are non-secret metadata.
	Labels map[string]string
}

// SQLEndpoint is where clients connect to a relational database.
type SQLEndpoint struct {
	// Host is the hostname.
	Host string
	// Port is the port.
	Port int
	// DatabaseName is the initial database.
	DatabaseName string
	// RequireTLS reports whether the provider requires clients to use TLS. It
	// is informational for connection-string assembly; a caller should not
	// disable TLS because a provider reports false.
	RequireTLS bool
}

// RelationalStatus is the observed state of a relational endpoint.
type RelationalStatus struct {
	Status
	// Spec is the effective desired state, as the provider understood it, with
	// AdminPassword zeroed. See [Status] for why every read-back carries one.
	Spec RelationalSpec
	// Endpoint is where to connect. Populated once [PhaseReady]; before that,
	// the host may be empty.
	Endpoint SQLEndpoint
}

// KeyValueSpec is the desired state of a managed key-value table.
type KeyValueSpec struct {
	// Name is the logical table name, stable across deploys.
	Name string

	// PartitionKey is the attribute name that shards the table.
	PartitionKey string

	// SortKey optionally orders items within a partition. Empty means the
	// table is keyed by partition alone.
	SortKey string

	// Placement says where to put it.
	Placement Placement

	// Labels are non-secret metadata.
	Labels map[string]string
}

// KeyValueStatus is the observed state of a key-value table.
//
// It embeds [Status] rather than being a plain descriptor because table
// creation is asynchronous on the substrate this port was derived from: the
// source system polls DescribeTable up to sixty times waiting for ACTIVE
// (source system @ backend/internal/modules/deploy/database.go). A type with
// no phase would have forced either a
// blocking Ensure or a caller that cannot tell "created" from "usable".
type KeyValueStatus struct {
	Status
	// Spec is the effective desired state, as the provider understood it. See
	// [Status] for why every read-back carries one.
	Spec KeyValueSpec
	// Name is the table's actual name after the provider's namespace rules.
	Name string
}

// RelationalProvisioner provisions managed SQL endpoints.
//
// # Why this port has no Granter
//
// Access to a relational database is granted by creating a SQL role and issuing
// GRANT statements, which this package deliberately leaves above the interface
// (see "What is not here" below). There is no general mapping from a substrate
// workload identity to a SQL principal: an AWS IAM role can be mapped to a
// Postgres role only with rds-iam authentication enabled, and a Kubernetes
// ServiceAccount has no Postgres meaning at all.
//
// Embedding [Granter] here would therefore require a provider that offers only
// operator-managed Postgres to implement a method whose sole honest answer is
// [ErrUnsupported] — a required method that cannot be implemented, which is the
// stub-interface failure [Provider] exists to prevent. Callers that need
// database access control use ordinary SQL against the endpoint.
//
// # What is not here
//
// Everything the source system does to a database *after* it exists — creating
// Postgres roles, granting privileges, enabling row-level security, installing
// extensions (source system @ backend/internal/modules/deploy/postgres_roles.go
// and database_extensions.go) — is vanilla SQL over a standard driver and
// belongs above this interface. Those files touch AWS only to fetch the
// admin password from Parameter Store, which
// becomes a [SecretStore.Get].
//
// Two-object provisioning is also gone. Aurora requires creating a cluster and
// then separately creating an instance inside it (source system @
// backend/internal/modules/deploy/database.go); that is
// an Aurora fact, and a caller asking for a Postgres endpoint should not learn
// it. The provider does whatever its substrate requires and reports one
// resource.
//
// # Sketch: how a Kubernetes provider satisfies this
//
// An operator-managed Postgres — CloudNativePG, Zalando, Crunchy — where the
// spec's Capacity becomes resource requests and limits, Placement becomes a
// namespace and storage class, and the endpoint is the operator's Service DNS
// name. Nothing in this port requires a substrate identity system, which is
// exactly why splitting it from the key-value port was worth doing.
type RelationalProvisioner interface {
	// EnsureRelational creates or updates a relational endpoint. Idempotent,
	// and specifically must not rotate AdminPassword on an existing endpoint.
	// Returns without waiting for availability, which on some substrates takes
	// many minutes.
	EnsureRelational(ctx context.Context, spec RelationalSpec) (*RelationalStatus, error)

	// DescribeRelational returns current state, or [PhaseGone].
	DescribeRelational(ctx context.Context, ref Ref) (*RelationalStatus, error)

	// WaitForRelational blocks until the endpoint accepts connections, fails,
	// or the deadline elapses.
	WaitForRelational(ctx context.Context, ref Ref, opts WaitOptions) (*RelationalStatus, error)

	// DeleteRelational removes an endpoint and its data. Idempotent.
	DeleteRelational(ctx context.Context, ref Ref) error
}

// KeyValueProvisioner provisions managed key-value tables.
//
// This port does embed [Granter], because a key-value store of this kind
// authorises by substrate identity: the source system grants the application's
// task role eight DynamoDB actions on the table and its indexes
// (source system @ backend/internal/modules/deploy/database.go), with no
// notion of a database-internal principal. A
// provider whose key-value store authorises some other way is free to translate,
// but every substrate that has this product at all has an identity-based answer.
//
// # Sketch: how a Kubernetes provider satisfies this
//
// It usually does not, and declines [CapKeyValueTable]. An application that
// needs a key-value table then gets an explicit [ErrUnsupported] at deploy
// time — the correct outcome, because a table silently backed by something with
// different consistency semantics would corrupt data rather than fail.
type KeyValueProvisioner interface {
	Granter

	// EnsureKeyValueTable creates or updates a key-value table. Idempotent.
	// Returns without waiting for the table to become usable.
	EnsureKeyValueTable(ctx context.Context, spec KeyValueSpec) (*KeyValueStatus, error)

	// DescribeKeyValueTable returns current state, or [PhaseGone].
	DescribeKeyValueTable(ctx context.Context, ref Ref) (*KeyValueStatus, error)

	// WaitForKeyValueTable blocks until the table is usable, fails, or the
	// deadline elapses.
	WaitForKeyValueTable(ctx context.Context, ref Ref, opts WaitOptions) (*KeyValueStatus, error)

	// DeleteKeyValueTable removes a table and its data. Idempotent.
	DeleteKeyValueTable(ctx context.Context, ref Ref) error
}
