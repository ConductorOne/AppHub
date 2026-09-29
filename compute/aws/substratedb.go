// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"

	"github.com/conductorone/apphub/credentials"
)

// The substrate surfaces the database ports need: RDS for Aurora and DynamoDB
// for the key-value table. The EC2 surface the relational port also needs is in
// network.go, because the supervisor addendum assigns that file to USOSS-12 and
// a whole-file conflict is easier to resolve correctly than a duplicate symbol
// found from a distance.
//
// They live in their own file rather than in substrate.go because that file's
// contract — "every method is one AWS API call, named after it, and nothing here
// composes calls or interprets results" — is the property that makes the
// in-memory and SDK substrates the same contract, and it is easier to hold when
// each service's surface can be read in one sitting.
//
// # Why the databases need three services and not one
//
// An Aurora endpoint is not one object. The source system creates a security
// group, a DB subnet group, a cluster, and then an instance inside the cluster
// (database.go:151-403), and [compute.RelationalProvisioner] says a caller
// asking for a Postgres endpoint should not learn that. So the four-object
// dance is above this seam and below the interface, which is exactly the space
// a provider is for.

// ClusterRecord is what RDS reports about one Aurora cluster.
type ClusterRecord struct {
	// Identifier is the cluster identifier.
	Identifier string
	// ARN is the cluster's ARN, read back rather than composed.
	ARN string
	// Engine is the RDS engine name, e.g. "aurora-postgresql".
	Engine string
	// EngineVersion is the version RDS actually selected, which for a
	// major-only request is a minor this package never asked for and must not
	// compare against the spec.
	EngineVersion string
	// DatabaseName is the initial database.
	DatabaseName string
	// MasterUsername is the master account name. RDS reports this; it never
	// reports the password, which is why the interface can promise a read-back
	// carries no material.
	MasterUsername string
	// Endpoint is the writer hostname, empty until the cluster is available.
	Endpoint string
	// Port is the port the endpoint listens on.
	Port int
	// Status is RDS's own status string, e.g. "creating", "available".
	Status string
	// MinCapacity and MaxCapacity are the Serverless v2 scaling bounds, in
	// ACUs.
	MinCapacity float64
	MaxCapacity float64
	// StorageEncrypted reports whether the cluster's storage is encrypted.
	StorageEncrypted bool
	// SecurityGroupIDs are the VPC security groups attached to the cluster.
	SecurityGroupIDs []string
	// SubnetGroup is the DB subnet group name.
	SubnetGroup string
	// Tags are the cluster's tags.
	Tags map[string]string
}

// InstanceRecord is what RDS reports about one DB instance.
type InstanceRecord struct {
	// Identifier is the instance identifier.
	Identifier string
	// ARN is the instance's ARN, read back rather than composed.
	ARN string
	// ClusterIdentifier is the cluster the instance belongs to.
	ClusterIdentifier string
	// Class is the instance class, e.g. "db.serverless".
	Class string
	// Status is RDS's own status string.
	Status string
	// Tags are the instance's tags.
	Tags map[string]string
}

// RDSAPI is the managed-SQL surface the relational port uses.
type RDSAPI interface {
	// DescribeSubnetGroup returns one DB subnet group, or [ErrNoSuchResource].
	DescribeSubnetGroup(ctx context.Context, name string) (*SubnetGroupRecord, error)
	// CreateSubnetGroup creates one, or returns [ErrAlreadyExists].
	CreateSubnetGroup(ctx context.Context, in CreateSubnetGroupRequest) (*SubnetGroupRecord, error)
	// DeleteSubnetGroup removes one. An absent group is [ErrNoSuchResource].
	DeleteSubnetGroup(ctx context.Context, name string) error

	// DescribeCluster returns one cluster, or [ErrNoSuchResource].
	DescribeCluster(ctx context.Context, id string) (*ClusterRecord, error)
	// CreateCluster creates one, or returns [ErrAlreadyExists].
	CreateCluster(ctx context.Context, in CreateClusterRequest) (*ClusterRecord, error)
	// ModifyClusterCapacity converges the Serverless v2 scaling bounds.
	//
	// Capacity and nothing else. There is deliberately no general modify: a
	// provider that could modify the master password from a reconcile path is a
	// provider one edit away from rotating a credential the caller has stored,
	// and [compute.RelationalSpec.AdminPassword] forbids exactly that. Keeping
	// the substrate unable to express it means the rule holds by construction
	// rather than by review.
	ModifyClusterCapacity(ctx context.Context, id string, minCapacity, maxCapacity float64) error
	// ModifyClusterSecurityGroups converges the attached security groups.
	ModifyClusterSecurityGroups(ctx context.Context, id string, groups []string) error
	// DeleteCluster removes a cluster and its data. An absent cluster is
	// [ErrNoSuchResource].
	DeleteCluster(ctx context.Context, id string) error

	// DescribeInstance returns one instance, or [ErrNoSuchResource].
	DescribeInstance(ctx context.Context, id string) (*InstanceRecord, error)
	// CreateInstance creates one, or returns [ErrAlreadyExists].
	CreateInstance(ctx context.Context, in CreateInstanceRequest) (*InstanceRecord, error)
	// DeleteInstance removes one. An absent instance is [ErrNoSuchResource].
	DeleteInstance(ctx context.Context, id string) error

	// ListTags reads tags by ARN.
	ListTags(ctx context.Context, arn string) (map[string]string, error)
	// TagResource adds or replaces tags by ARN.
	TagResource(ctx context.Context, arn string, tags map[string]string) error
	// UntagResource removes tags by key.
	UntagResource(ctx context.Context, arn string, keys []string) error
}

// SubnetGroupRecord is what RDS reports about one DB subnet group.
type SubnetGroupRecord struct {
	// Name is the subnet group name.
	Name string
	// ARN is the group's ARN, read back rather than composed.
	ARN string
	// SubnetIDs are the subnets in the group.
	SubnetIDs []string
	// Tags are the group's tags.
	Tags map[string]string
}

// CreateSubnetGroupRequest is what it takes to create a DB subnet group.
type CreateSubnetGroupRequest struct {
	// Name is the group name.
	Name string
	// Description is RDS's required description.
	Description string
	// SubnetIDs are the subnets to put in it.
	SubnetIDs []string
	// Tags are the group's tags.
	Tags map[string]string
}

// CreateClusterRequest is what it takes to create an Aurora cluster.
type CreateClusterRequest struct {
	// Identifier is the cluster identifier.
	Identifier string
	// Engine is the RDS engine name.
	Engine string
	// EngineVersion is the major version to request. Major only: pinning a
	// minor makes creation fail the day RDS retires it, which the source system
	// learned and wrote down in place (database.go:296-301).
	EngineVersion string
	// DatabaseName is the initial database.
	DatabaseName string
	// MasterUsername is the master account name.
	MasterUsername string
	// MasterPassword is that account's password.
	//
	// A [credentials.Secret] rather than a string, so that a substrate
	// implementation cannot put it in a log line or an error by formatting the
	// request it was given. This is the only field in any substrate request
	// that carries material.
	MasterPassword credentials.Secret
	// SubnetGroup is the DB subnet group to place it in.
	SubnetGroup string
	// SecurityGroupIDs are the VPC security groups to attach.
	SecurityGroupIDs []string
	// MinCapacity and MaxCapacity are the Serverless v2 scaling bounds, in
	// ACUs.
	MinCapacity float64
	MaxCapacity float64
	// StorageEncrypted asks RDS to encrypt the cluster's storage. This
	// provider always sets it; the field exists so the substrate contract says
	// so rather than leaving it implicit.
	StorageEncrypted bool
	// Tags are the cluster's tags.
	Tags map[string]string
}

// CreateInstanceRequest is what it takes to create an Aurora instance.
type CreateInstanceRequest struct {
	// Identifier is the instance identifier.
	Identifier string
	// ClusterIdentifier is the cluster to create it in.
	ClusterIdentifier string
	// Class is the instance class.
	Class string
	// Engine is the RDS engine name. RDS requires it on the instance as well
	// as on the cluster, and the instance inherits the cluster's version.
	Engine string
	// Tags are the instance's tags.
	Tags map[string]string
}

// TableRecord is what DynamoDB reports about one table.
type TableRecord struct {
	// Name is the table name.
	Name string
	// ARN is the table's ARN, read back rather than composed. It is the
	// resource a grant names, and composing it would mean this package holding
	// an account identifier.
	ARN string
	// PartitionKey is the hash key attribute name.
	PartitionKey string
	// SortKey is the range key attribute name, empty when the table has none.
	SortKey string
	// Status is DynamoDB's own status string, e.g. "CREATING", "ACTIVE".
	Status string
	// Tags are the table's tags.
	Tags map[string]string
}

// DynamoDBAPI is the key-value surface the key-value port uses.
type DynamoDBAPI interface {
	// DescribeTable returns one table, or [ErrNoSuchResource].
	DescribeTable(ctx context.Context, name string) (*TableRecord, error)
	// CreateTable creates one, or returns [ErrAlreadyExists].
	CreateTable(ctx context.Context, in CreateTableRequest) (*TableRecord, error)
	// DeleteTable removes a table and its data. An absent table is
	// [ErrNoSuchResource].
	DeleteTable(ctx context.Context, name string) error
	// ListTags reads a table's tags by ARN.
	ListTags(ctx context.Context, arn string) (map[string]string, error)
	// TagResource adds or replaces tags.
	TagResource(ctx context.Context, arn string, tags map[string]string) error
	// UntagResource removes tags by key.
	UntagResource(ctx context.Context, arn string, keys []string) error
}

// CreateTableRequest is what it takes to create a key-value table.
type CreateTableRequest struct {
	// Name is the table name.
	Name string
	// PartitionKey is the hash key attribute name.
	PartitionKey string
	// SortKey is the range key attribute name, empty for a table keyed by
	// partition alone.
	//
	// The source system hardcodes "PK" and "SK" and always creates both
	// (database.go:67-74). [compute.KeyValueSpec] makes them the caller's, and
	// a sort key is optional there, so this provider has to be able to create a
	// table without one.
	SortKey string
	// Tags are the table's tags.
	Tags map[string]string
}

// RolePolicyAPI is the inline-policy half of [IAMAPI].
//
// It is a separate interface embedded into [IAMAPI] so that a reader asking
// "where can this package change what a workload is permitted to do" gets a
// three-method answer. Every grant this provider makes is one of these calls,
// and the ports that attach a policy own detaching it, because Ensure is
// declarative.
type RolePolicyAPI interface {
	// GetRolePolicy returns an inline policy document, or [ErrNoSuchResource]
	// when the role has no policy under that name.
	GetRolePolicy(ctx context.Context, role, policy string) (string, error)
	// PutRolePolicy creates or replaces an inline policy.
	//
	// Replaces, not merges: an access level narrowed from read-write to read
	// has to narrow, and a provider that added a second statement instead would
	// leave the wider one in force. [compute.Granter] states the rule and this
	// is where it is kept.
	PutRolePolicy(ctx context.Context, role, policy, document string) error
	// DeleteRolePolicy removes an inline policy. An absent policy is
	// [ErrNoSuchResource].
	DeleteRolePolicy(ctx context.Context, role, policy string) error
}
