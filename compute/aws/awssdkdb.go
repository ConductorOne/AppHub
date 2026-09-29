// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	lambdaapi "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3tables"
	"github.com/aws/aws-sdk-go-v2/service/s3vectors"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/conductorone/apphub/credentials"
)

// The SDK adapters for the database ports and hosted provider composition.
// Service adapters translate one API call and error at a time. NewFromConfig is
// the credential-loading composition boundary, not a second implementation of
// any provider operation.

// SDKClients is the set of AWS SDK clients a substrate can be built from.
//
// A struct rather than a positional parameter list, and the reason is
// coordination rather than taste: six tickets are adding ports to this package,
// each needs a client, and a positional constructor makes every one of them a
// signature change that conflicts with the others. A field is additive.
//
// A nil client is legal and means the corresponding capability is not
// available; [New] reports the mismatch if the configuration says otherwise.
type SDKClients struct {
	// ECR is the container registry client.
	ECR *ecr.Client
	// IAM is the identity client.
	IAM *iam.Client
	// STS is the token service client.
	STS *sts.Client
	// RDS is the managed-SQL client.
	RDS *rds.Client
	// EC2 is the network client the relational port's security group uses.
	EC2 *ec2.Client
	// DynamoDB is the key-value client.
	DynamoDB *dynamodb.Client
	// Lambda runs code bundles as functions.
	Lambda *lambdaapi.Client
	// ELBv2 fronts a function with a load balancer.
	ELBv2 *elbv2.Client
	// EndpointEC2 is the network client the function-endpoint port's security
	// group uses. A second EC2 client field alongside [SDKClients.EC2] rather
	// than a shared one: the two ports wrap it in two different adapters over
	// two different primitive interfaces -- see [Substrate.EndpointEC2] -- and
	// giving them the same field would suggest the surfaces are interchangeable
	// when they are not. Both fields are legally the same *ec2.Client.
	EndpointEC2 *ec2.Client
	// S3 is general-purpose object storage. Nil disables
	// [compute.CapObjectStore].
	S3 *s3.Client
	// S3Tables provisions table buckets, reached only through
	// [ext.TableBucketProvisioner]. Nil is the common case.
	S3Tables *s3tables.Client
	// S3Vectors provisions vector buckets, reached only through
	// [ext.VectorBucketProvisioner]. Nil is the common case.
	S3Vectors *s3vectors.Client
	// Scheduler is EventBridge Scheduler. Nil disables [compute.CapScheduledJob].
	Scheduler *scheduler.Client
	// ECS runs container services; SSM backs the parameter/secret store.
	ECS *ecs.Client
	SSM *ssm.Client
}

// NewSDKSubstrateFrom wires the real clients from a named set.
//
// # Retry configuration belongs to whoever builds these clients
//
// This constructor does not check it, install it, or consult it, and the
// reasoning is USOSS-10's rather than this ticket's — arrived at over four guard
// versions, one ownership attempt, and one classifier that read the client's own
// retryer. Two lessons came out of it and both apply to the three services this
// ticket adds:
//
//   - **Owning a behaviour inside somebody else's extensible object is
//     enumerating its disable paths**, and the SDK's set is not closed:
//     `RetryMaxAttempts` is re-applied over an installed retryer, and
//     `APIOptions` survives a client rebuild and runs after the retry middleware
//     is installed, so it can be removed by ID.
//   - **Asking the client's retryer was not exempt from that.**
//     [awssdk.Retryer] does not require wrapper-insensitive classification, so a
//     caller's implementation may classify by concrete type without doing
//     anything wrong — and the answer then depends on how the error was wrapped
//     rather than on what it was. Checking the SDK's own classifiers tells you
//     nothing, because theirs use errors.As.
//
// So classification is [classifier]'s, from signals this package can reason
// about, and an operator who needs it widened says so through
// [Config.IsRetryable]. The consequence is documented rather than defended, and
// it holds for RDS, EC2 and DynamoDB exactly as for the other three:
//
//	A caller who disables retry on these clients gets a provider that does not
//	retry, and this package will not know.
//
// [SDKClients] remains a struct rather than a positional parameter list because
// six tickets are adding clients here, and a field is additive where a parameter
// is a signature change that conflicts with every other one.
func NewSDKSubstrateFrom(c SDKClients) *Substrate {
	// The builder and the pusher are unconditional because neither is an AWS
	// client: they are subprocesses. Two of them rather than one because a build
	// that pushes is a build whose environment holds a push credential -- see
	// [ImagePusher].
	sub := &Substrate{Builder: ExecRunner{}, Pusher: ExecPusher{}}
	if c.ECR != nil {
		sub.ECR = &sdkECR{c: c.ECR}
	}
	if c.IAM != nil {
		sub.IAM = &sdkIAM{c: c.IAM}
	}
	if c.STS != nil {
		sub.STS = &sdkSTS{c: c.STS}
	}
	if c.Lambda != nil {
		sub.Lambda = &sdkLambda{c: c.Lambda}
	}
	if c.ELBv2 != nil {
		sub.ELBv2 = &sdkELBv2{c: c.ELBv2}
	}
	if c.EndpointEC2 != nil {
		sub.EndpointEC2 = &sdkEndpointEC2{c: c.EndpointEC2}
	}
	if c.RDS != nil {
		sub.RDS = &sdkRDS{c: c.RDS}
	}
	if c.EC2 != nil {
		sub.EC2 = &sdkEC2{c: c.EC2}
	}
	if c.DynamoDB != nil {
		sub.DynamoDB = &sdkDynamoDB{c: c.DynamoDB}
	}
	if c.Scheduler != nil {
		sub.Scheduler = &sdkScheduler{c: c.Scheduler}
	}
	if c.S3 != nil {
		sub.S3 = &sdkS3{c: c.S3}
	}
	if c.S3Tables != nil {
		sub.S3Tables = &sdkS3Tables{c: c.S3Tables}
	}
	if c.S3Vectors != nil {
		sub.S3Vectors = &sdkS3Vectors{c: c.S3Vectors}
	}
	if c.ECS != nil {
		sub.ECS = &sdkECS{c: c.ECS}
	}
	if c.SSM != nil {
		sub.Parameters = NewSSMParameterStore(c.SSM)
	}
	return sub
}

// NewFromConfig constructs the hosted provider using ambient operator AWS
// credentials. Unlike NewSDKSubstrateFrom, this path never uses ExecRunner.
// The supplied runner must validate its actual runtime isolation before any
// credentials are loaded. Construction performs no AWS resource mutations.
//
// All clients address cfg.Region. A placement in another region is refused;
// configure a separate provider for that region instead of silently dispatching
// regional API calls to the wrong account endpoint.
func NewFromConfig(ctx context.Context, cfg Config, runner BuildRunner) (*Provider, error) {
	if err := validateHostedConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateHostedRunner(ctx, runner); err != nil {
		return nil, err
	}
	base, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, errors.New("aws: loading operator AWS configuration failed")
	}
	p, err := New(configuredSDKSubstrate(base, cfg, runner), cfg)
	if err != nil {
		return nil, err
	}
	if base.Credentials == nil {
		return nil, errors.New("aws: operator AWS credentials are unavailable")
	}
	if _, err := base.Credentials.Retrieve(ctx); err != nil {
		return nil, errors.New("aws: operator AWS credentials are unavailable")
	}
	return p, nil
}

// configuredSDKSubstrate attaches only enabled services. Ingress security-group
// operations use EC2; container routes use the existing ECS/Traefik labels.
// The operator must supply the ingress controller, DNS and TLS termination.
func configuredSDKSubstrate(base awssdk.Config, cfg Config, runner BuildRunner) *Substrate {
	c := SDKClients{IAM: iam.NewFromConfig(base)}
	if cfg.Registry != nil {
		c.ECR = ecr.NewFromConfig(base)
	}
	if cfg.Build != nil {
		c.STS = sts.NewFromConfig(base)
	}
	if cfg.Container != nil || cfg.Relational != nil || cfg.Endpoint != nil {
		network := ec2.NewFromConfig(base)
		if cfg.Container != nil || cfg.Relational != nil {
			c.EC2 = network
		}
		if cfg.Endpoint != nil {
			c.EndpointEC2 = network
			c.ELBv2 = elbv2.NewFromConfig(base)
		}
	}
	if cfg.Container != nil {
		c.ECS = ecs.NewFromConfig(base)
		c.Scheduler = scheduler.NewFromConfig(base)
	}
	if cfg.Secrets != nil {
		c.SSM = ssm.NewFromConfig(base)
	}
	if cfg.Function != nil {
		c.Lambda = lambdaapi.NewFromConfig(base)
	}
	if cfg.Relational != nil {
		c.RDS = rds.NewFromConfig(base)
	}
	if cfg.KeyValue != nil {
		c.DynamoDB = dynamodb.NewFromConfig(base)
	}
	if cfg.ObjectStore != nil {
		c.S3 = s3.NewFromConfig(base)
		if cfg.ObjectStore.TableBuckets {
			c.S3Tables = s3tables.NewFromConfig(base)
		}
		if cfg.ObjectStore.VectorBuckets {
			c.S3Vectors = s3vectors.NewFromConfig(base)
		}
	}
	sub := NewSDKSubstrateFrom(c)
	sub.Builder = runner
	sub.Pusher = ExecPusher{}
	return sub
}

// --- IAM inline policies -----------------------------------------------------

func (s *sdkIAM) GetRolePolicy(ctx context.Context, role, policy string) (string, error) {
	out, err := s.c.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
		RoleName:   awssdk.String(role),
		PolicyName: awssdk.String(policy),
	})
	if err != nil {
		return "", s.err(err)
	}
	// IAM returns an inline policy document URL-encoded. The provider compares
	// what a document *means* rather than its bytes, so decoding is the
	// caller's problem and not this adapter's; what matters here is that the
	// document is returned unaltered.
	return awssdk.ToString(out.PolicyDocument), nil
}

func (s *sdkIAM) PutRolePolicy(ctx context.Context, role, policy, document string) error {
	_, err := s.c.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       awssdk.String(role),
		PolicyName:     awssdk.String(policy),
		PolicyDocument: awssdk.String(document),
	})
	return s.err(err)
}

func (s *sdkIAM) DeleteRolePolicy(ctx context.Context, role, policy string) error {
	_, err := s.c.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
		RoleName:   awssdk.String(role),
		PolicyName: awssdk.String(policy),
	})
	return s.err(err)
}

// --- RDS ---------------------------------------------------------------------

type sdkRDS struct {
	c *rds.Client
	classifier
}

var _ RDSAPI = (*sdkRDS)(nil)

// rdsNotFound recognises RDS's several not-found exceptions.
//
// By type, every one of them, and never by matching text. The source system's
// equivalents match a substring — "does not exist" against any error
// (build.go:436-441) — and the class has now been found three times in that
// codebase. A typed test cannot mistake an unrelated error whose message
// happens to contain a phrase for an absent resource, which is the failure that
// makes the next branch create a duplicate.
func rdsNotFound(err error) bool {
	return isType[*rdstypes.DBClusterNotFoundFault](err) ||
		isType[*rdstypes.DBInstanceNotFoundFault](err) ||
		isType[*rdstypes.DBSubnetGroupNotFoundFault](err)
}

func rdsExists(err error) bool {
	return isType[*rdstypes.DBClusterAlreadyExistsFault](err) ||
		isType[*rdstypes.DBInstanceAlreadyExistsFault](err) ||
		isType[*rdstypes.DBSubnetGroupAlreadyExistsFault](err)
}

// rdsSettling recognises RDS refusing a call because a resource is still moving
// between states -- the faults a teardown meets on its way down.
//
// RDS deletes asynchronously, so [relationalProvisioner.DeleteRelational]'s
// ordinary first pass hits all three: the cluster refuses deletion with
// InvalidDBClusterStateFault while its instance is still "deleting", a repeated
// DeleteInstance on an instance that is already deleting answers
// InvalidDBInstanceState, and the subnet group answers
// InvalidDBSubnetGroupStateFault while the cluster still holds it. Each clears on
// its own within minutes, which is what [ErrConflict] means -- another change to
// this resource is still in flight -- and so each reaches the caller as
// [compute.ErrTransient]. Left unclassified they became [compute.ErrFailed], and
// a teardown loop that retries only ErrTransient gave up on the one outcome that
// needed nothing but waiting.
//
// # The cost, stated
//
// A state fault is not always a wait. An instance stuck in "incompatible-network"
// answers the same fault for as long as nobody fixes it, and this classification
// reads that as "try again" too. The trade is deliberate: the caller's backoff
// budget bounds the stuck case and reports it, while the terminal reading made
// the common case -- every teardown of a live database -- fail on its first
// pass. The fault's own text is kept in the chain so an operator who meets the
// stuck case can read the state RDS named.
//
// By type, for the reason [rdsNotFound] gives. The instance fault's code is
// "InvalidDBInstanceState", without the "Fault" its two siblings carry; a
// code-string match written from the other two would miss it.
func rdsSettling(err error) bool {
	return isType[*rdstypes.InvalidDBClusterStateFault](err) ||
		isType[*rdstypes.InvalidDBInstanceStateFault](err) ||
		isType[*rdstypes.InvalidDBSubnetGroupStateFault](err)
}

func (s *sdkRDS) err(err error) error {
	if rdsSettling(err) {
		return fmt.Errorf("%w: %w", ErrConflict, err)
	}
	return s.classify(err, rdsNotFound, rdsExists)
}

func (s *sdkRDS) DescribeSubnetGroup(ctx context.Context, name string) (*SubnetGroupRecord, error) {
	out, err := s.c.DescribeDBSubnetGroups(ctx, &rds.DescribeDBSubnetGroupsInput{
		DBSubnetGroupName: awssdk.String(name),
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.DBSubnetGroups) == 0 {
		// A filtered describe that matches nothing returns an empty list rather
		// than an exception on some RDS paths, and an empty list is the same
		// fact as a not-found. Translating it here is what keeps the provider
		// from having to know which shape it got.
		return nil, ErrNoSuchResource
	}
	g := out.DBSubnetGroups[0]
	rec := &SubnetGroupRecord{
		Name: awssdk.ToString(g.DBSubnetGroupName),
		ARN:  awssdk.ToString(g.DBSubnetGroupArn),
	}
	for _, sn := range g.Subnets {
		rec.SubnetIDs = append(rec.SubnetIDs, awssdk.ToString(sn.SubnetIdentifier))
	}
	// DescribeDBSubnetGroups carries no tags, unlike the cluster and instance
	// describes, so without this read every group reads back as unowned.
	tags, err := s.ListTags(ctx, rec.ARN)
	if err != nil {
		return nil, err
	}
	rec.Tags = tags
	return rec, nil
}

func (s *sdkRDS) CreateSubnetGroup(ctx context.Context, in CreateSubnetGroupRequest) (*SubnetGroupRecord, error) {
	out, err := s.c.CreateDBSubnetGroup(ctx, &rds.CreateDBSubnetGroupInput{
		DBSubnetGroupName:        awssdk.String(in.Name),
		DBSubnetGroupDescription: awssdk.String(in.Description),
		SubnetIds:                in.SubnetIDs,
		Tags:                     rdsTags(in.Tags),
	})
	if err != nil {
		return nil, s.err(err)
	}
	return &SubnetGroupRecord{
		Name:      awssdk.ToString(out.DBSubnetGroup.DBSubnetGroupName),
		ARN:       awssdk.ToString(out.DBSubnetGroup.DBSubnetGroupArn),
		SubnetIDs: append([]string(nil), in.SubnetIDs...),
		Tags:      copyTags(in.Tags),
	}, nil
}

func (s *sdkRDS) DeleteSubnetGroup(ctx context.Context, name string) error {
	_, err := s.c.DeleteDBSubnetGroup(ctx, &rds.DeleteDBSubnetGroupInput{
		DBSubnetGroupName: awssdk.String(name),
	})
	return s.err(err)
}

func (s *sdkRDS) DescribeCluster(ctx context.Context, id string) (*ClusterRecord, error) {
	out, err := s.c.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: awssdk.String(id),
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.DBClusters) == 0 {
		return nil, ErrNoSuchResource
	}
	return clusterRecord(&out.DBClusters[0]), nil
}

func clusterRecord(c *rdstypes.DBCluster) *ClusterRecord {
	rec := &ClusterRecord{
		Identifier:       awssdk.ToString(c.DBClusterIdentifier),
		ARN:              awssdk.ToString(c.DBClusterArn),
		Engine:           awssdk.ToString(c.Engine),
		EngineVersion:    awssdk.ToString(c.EngineVersion),
		DatabaseName:     awssdk.ToString(c.DatabaseName),
		MasterUsername:   awssdk.ToString(c.MasterUsername),
		Endpoint:         awssdk.ToString(c.Endpoint),
		Port:             int(awssdk.ToInt32(c.Port)),
		Status:           awssdk.ToString(c.Status),
		StorageEncrypted: awssdk.ToBool(c.StorageEncrypted),
		SubnetGroup:      awssdk.ToString(c.DBSubnetGroup),
		Tags:             map[string]string{},
	}
	if sc := c.ServerlessV2ScalingConfiguration; sc != nil {
		rec.MinCapacity = awssdk.ToFloat64(sc.MinCapacity)
		rec.MaxCapacity = awssdk.ToFloat64(sc.MaxCapacity)
	}
	for _, sg := range c.VpcSecurityGroups {
		rec.SecurityGroupIDs = append(rec.SecurityGroupIDs, awssdk.ToString(sg.VpcSecurityGroupId))
	}
	for _, t := range c.TagList {
		rec.Tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return rec
}

func (s *sdkRDS) CreateCluster(ctx context.Context, in CreateClusterRequest) (*ClusterRecord, error) {
	out, err := s.c.CreateDBCluster(ctx, &rds.CreateDBClusterInput{
		DBClusterIdentifier: awssdk.String(in.Identifier),
		Engine:              awssdk.String(in.Engine),
		EngineVersion:       awssdk.String(in.EngineVersion),
		DatabaseName:        awssdk.String(in.DatabaseName),
		MasterUsername:      awssdk.String(in.MasterUsername),
		// The one Reveal in this file, and the only place in the package where
		// a database password crosses into an SDK call.
		MasterUserPassword:  awssdk.String(credentials.Reveal(in.MasterPassword)),
		DBSubnetGroupName:   awssdk.String(in.SubnetGroup),
		VpcSecurityGroupIds: in.SecurityGroupIDs,
		ServerlessV2ScalingConfiguration: &rdstypes.ServerlessV2ScalingConfiguration{
			MinCapacity: awssdk.Float64(in.MinCapacity),
			MaxCapacity: awssdk.Float64(in.MaxCapacity),
		},
		StorageEncrypted: awssdk.Bool(in.StorageEncrypted),
		Tags:             rdsTags(in.Tags),
	})
	if err != nil {
		// The error is returned as classified and nothing is interpolated into
		// it. An error from a call carrying a password is exactly where a
		// provider leaks one, and the input struct formats to something
		// containing the material only if somebody formats it — so nobody does.
		return nil, s.err(err)
	}
	return clusterRecord(out.DBCluster), nil
}

func (s *sdkRDS) ModifyClusterCapacity(ctx context.Context, id string, minCapacity, maxCapacity float64) error {
	_, err := s.c.ModifyDBCluster(ctx, &rds.ModifyDBClusterInput{
		DBClusterIdentifier: awssdk.String(id),
		ServerlessV2ScalingConfiguration: &rdstypes.ServerlessV2ScalingConfiguration{
			MinCapacity: awssdk.Float64(minCapacity),
			MaxCapacity: awssdk.Float64(maxCapacity),
		},
		ApplyImmediately: awssdk.Bool(true),
	})
	return s.err(err)
}

func (s *sdkRDS) ModifyClusterSecurityGroups(ctx context.Context, id string, groups []string) error {
	_, err := s.c.ModifyDBCluster(ctx, &rds.ModifyDBClusterInput{
		DBClusterIdentifier: awssdk.String(id),
		VpcSecurityGroupIds: groups,
		ApplyImmediately:    awssdk.Bool(true),
	})
	return s.err(err)
}

func (s *sdkRDS) DeleteCluster(ctx context.Context, id string) error {
	_, err := s.c.DeleteDBCluster(ctx, &rds.DeleteDBClusterInput{
		DBClusterIdentifier: awssdk.String(id),
		// No final snapshot, and this is a deliberate answer to a question the
		// interface asks: DeleteRelational "removes an endpoint and its data".
		// A provider that took a snapshot would leave the data behind under a
		// name the caller never learns and cannot delete through this
		// interface, which is worse than either honest answer.
		SkipFinalSnapshot: awssdk.Bool(true),
	})
	return s.err(err)
}

func (s *sdkRDS) DescribeInstance(ctx context.Context, id string) (*InstanceRecord, error) {
	out, err := s.c.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: awssdk.String(id),
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.DBInstances) == 0 {
		return nil, ErrNoSuchResource
	}
	inst := out.DBInstances[0]
	rec := &InstanceRecord{
		Identifier:        awssdk.ToString(inst.DBInstanceIdentifier),
		ARN:               awssdk.ToString(inst.DBInstanceArn),
		ClusterIdentifier: awssdk.ToString(inst.DBClusterIdentifier),
		Class:             awssdk.ToString(inst.DBInstanceClass),
		Status:            awssdk.ToString(inst.DBInstanceStatus),
		Tags:              map[string]string{},
	}
	for _, t := range inst.TagList {
		rec.Tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return rec, nil
}

func (s *sdkRDS) CreateInstance(ctx context.Context, in CreateInstanceRequest) (*InstanceRecord, error) {
	out, err := s.c.CreateDBInstance(ctx, &rds.CreateDBInstanceInput{
		DBInstanceIdentifier: awssdk.String(in.Identifier),
		DBClusterIdentifier:  awssdk.String(in.ClusterIdentifier),
		DBInstanceClass:      awssdk.String(in.Class),
		Engine:               awssdk.String(in.Engine),
		Tags:                 rdsTags(in.Tags),
	})
	if err != nil {
		return nil, s.err(err)
	}
	return &InstanceRecord{
		Identifier:        awssdk.ToString(out.DBInstance.DBInstanceIdentifier),
		ARN:               awssdk.ToString(out.DBInstance.DBInstanceArn),
		ClusterIdentifier: awssdk.ToString(out.DBInstance.DBClusterIdentifier),
		Class:             awssdk.ToString(out.DBInstance.DBInstanceClass),
		Status:            awssdk.ToString(out.DBInstance.DBInstanceStatus),
		Tags:              copyTags(in.Tags),
	}, nil
}

func (s *sdkRDS) DeleteInstance(ctx context.Context, id string) error {
	_, err := s.c.DeleteDBInstance(ctx, &rds.DeleteDBInstanceInput{
		DBInstanceIdentifier: awssdk.String(id),
		SkipFinalSnapshot:    awssdk.Bool(true),
	})
	return s.err(err)
}

func (s *sdkRDS) ListTags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := s.c.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{
		ResourceName: awssdk.String(arn),
	})
	if err != nil {
		return nil, s.err(err)
	}
	tags := make(map[string]string, len(out.TagList))
	for _, t := range out.TagList {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return tags, nil
}

func (s *sdkRDS) TagResource(ctx context.Context, arn string, tags map[string]string) error {
	_, err := s.c.AddTagsToResource(ctx, &rds.AddTagsToResourceInput{
		ResourceName: awssdk.String(arn),
		Tags:         rdsTags(tags),
	})
	return s.err(err)
}

func (s *sdkRDS) UntagResource(ctx context.Context, arn string, keys []string) error {
	_, err := s.c.RemoveTagsFromResource(ctx, &rds.RemoveTagsFromResourceInput{
		ResourceName: awssdk.String(arn),
		TagKeys:      keys,
	})
	return s.err(err)
}

func rdsTags(tags map[string]string) []rdstypes.Tag {
	out := make([]rdstypes.Tag, 0, len(tags))
	for _, k := range sortedKeys(tags) {
		out = append(out, rdstypes.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	return out
}

// --- EC2 ---------------------------------------------------------------------

type sdkEC2 struct {
	c *ec2.Client
	classifier
}

var _ EC2API = (*sdkEC2)(nil)

// The EC2 error codes this port can receive, classified into the three answers
// they actually mean.
//
// # Why three sets and not two
//
// EC2 has no typed exceptions in the SDK — every failure is a smithy API error
// with a code — so these are restatements of somebody else's set, which this
// project distrusts. They are bounded the only way available: matched
// **exactly** rather than by substring, and anything unlisted falls through to
// the shared classifier.
//
// The first version had two sets and review found a code in the wrong one.
// `InvalidGroupId.Malformed` sat in the not-found set, so a malformed
// security-group identifier made [Provider.observedIngress] treat the group as
// absent and **`DescribeRelational` returned success with zero ingress rules** —
// a read-back saying nothing may reach a database, produced by a typo. That is
// the same empty-read defect as review's B4, reached through a different door,
// and it is worse: B4 needed a failed call, this needs only a wrong character.
//
// So the audit was done over the whole set rather than by removing one entry.
// **Every code below is placed in exactly one of three classes**, because
// malformed, already-there and absent are three answers. The set of codes is
// hand-maintained and cannot be otherwise — see above — so "every code below" is
// a claim about this list and not about EC2's vocabulary; what carries the codes
// that are not on it is the fail-closed default in the next section.
//
//	code                              means                          class
//	--------------------------------  -----------------------------  ---------
//	InvalidGroup.NotFound             the named group is not there    absent
//	InvalidSecurityGroupID.NotFound   the group ID is not there       absent
//	InvalidPermission.NotFound        the rule is not there           absent
//	InvalidGroup.Duplicate            the name is taken               exists
//	InvalidPermission.Duplicate       the rule is already there       exists
//	InvalidGroupId.Malformed          the ID is not a group ID        malformed
//	InvalidPermission.Malformed       the rule spec is unreadable     malformed
//	InvalidParameterValue             a parameter is unusable         malformed
//
// **Counts, with denominators.** The not-found set held **3** codes and **1 of
// those 3** was misclassified: `InvalidGroupId.Malformed`. The audit also found
// **1 code missing** from it — `InvalidSecurityGroupID.NotFound`, which AWS
// documents for a security-group lookup by ID.
//
// Which of the two absence codes a `DescribeSecurityGroups` by ID actually
// returns is **not something this package should claim to know**: AWS documents
// both, the SDK's own security-group waiters match `InvalidGroup.NotFound`, and
// review pointed out that the current AWS examples do the same. An earlier
// version of this comment asserted the ID/name split as fact, which was more
// than the evidence supports. Listing both is the answer either way, and it is
// the *reason* to list both rather than to pick: they are both absence, the
// classification is identical, and a package that guessed which one arrives
// would have a not-found arm that fires only on the guess being right. That is
// what was wrong before — with only the name code listed, the "an absent group
// is an observation" branch in observedIngress could not fire on the ID code at
// all, and the test for that branch injected [ErrNoSuchResource] directly, so
// the mapping had no coverage either way. Two defects, in opposite directions,
// from one audit.
//
// # And it fails closed on anything it cannot place
//
// An unlisted code reaches the shared classifier and, if that cannot place it
// either, becomes [compute.ErrFailed] with the AWS code in the message. That is
// deliberate: **absence is the one answer that produces an empty read**, so a
// code this package cannot confidently call absent must never be treated as
// absent. Failing the call is the safe direction; the diagnosis names the code.
var (
	ec2AbsentCodes = []string{
		"InvalidGroup.NotFound",
		"InvalidSecurityGroupID.NotFound",
		"InvalidPermission.NotFound",
	}
	ec2ExistsCodes = []string{
		"InvalidGroup.Duplicate",
		"InvalidPermission.Duplicate",
	}
	ec2MalformedCodes = []string{
		"InvalidGroupId.Malformed",
		"InvalidPermission.Malformed",
		"InvalidParameterValue",
	}
)

// err classifies an EC2 error.
//
// Malformed is tested first, because it is the class that must never be allowed
// to reach the not-found arm — see the note above for what that cost.
//
// # And a fourth class, in use, for the same reason the endpoint adapter has it
//
// DependencyViolation and ResourceInUse map to [ErrConflict] and so to
// [compute.ErrTransient], exactly as [sdkEndpointEC2.err] maps them and through
// the same [ec2InUse]. Both teardowns that reach this adapter delete a security
// group straight after deleting what holds it: [relationalProvisioner.DeleteRelational]
// after the cluster, whose network interfaces RDS releases minutes later, and
// [containerRuntime.DeleteService] after the service, whose task interfaces go
// only once ECS has drained the tasks. The DependencyViolation is therefore the
// ordinary first outcome of both, and it clears on its own. Unmapped, it fell
// through to [compute.ErrFailed] and a retrying teardown stopped at the one
// refusal that waiting resolves.
//
// Not added to the three-class table above, because that table is about which
// answer a read means and these two are refusals of a write.
func (s *sdkEC2) err(err error) error {
	if ec2CodeIs(ec2MalformedCodes...)(err) {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if ec2InUse(err) {
		return fmt.Errorf("%w: %w", ErrConflict, err)
	}
	return s.classify(err, ec2CodeIs(ec2AbsentCodes...), ec2CodeIs(ec2ExistsCodes...))
}

func ec2CodeIs(codes ...string) func(error) bool {
	return func(err error) bool {
		var api smithy.APIError
		if !errors.As(err, &api) {
			return false
		}
		for _, c := range codes {
			if api.ErrorCode() == c {
				return true
			}
		}
		return false
	}
}

func (s *sdkEC2) DescribeSecurityGroupByName(ctx context.Context, name, vpc string) (*SecurityGroupRecord, error) {
	out, err := s.c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: awssdk.String("group-name"), Values: []string{name}},
			{Name: awssdk.String("vpc-id"), Values: []string{vpc}},
		},
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.SecurityGroups) == 0 {
		return nil, ErrNoSuchResource
	}
	return securityGroupRecord(&out.SecurityGroups[0])
}

func (s *sdkEC2) DescribeSecurityGroupByID(ctx context.Context, id string) (*SecurityGroupRecord, error) {
	out, err := s.c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{id},
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.SecurityGroups) == 0 {
		return nil, ErrNoSuchResource
	}
	return securityGroupRecord(&out.SecurityGroups[0])
}

// DescribeSecurityGroupsReferencing implements [EC2API].
//
// "ip-permission.group-id" is EC2's own filter for exactly this question --
// which groups' rules name this one as a source -- so the search runs on the
// substrate rather than by paging every group in vpc and re-deriving it from
// [SecurityGroupRecord.Ingress] here.
func (s *sdkEC2) DescribeSecurityGroupsReferencing(ctx context.Context, id, vpc string) ([]*SecurityGroupRecord, error) {
	out, err := s.c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: awssdk.String("ip-permission.group-id"), Values: []string{id}},
			{Name: awssdk.String("vpc-id"), Values: []string{vpc}},
		},
	})
	if err != nil {
		return nil, s.err(err)
	}
	recs := make([]*SecurityGroupRecord, 0, len(out.SecurityGroups))
	for i := range out.SecurityGroups {
		rec, err := securityGroupRecord(&out.SecurityGroups[i])
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// securityGroupRecord flattens EC2's nested permissions into the comparable rule
// values the provider diffs.
//
// One rule per source, since a permission may carry several and each is
// separately revocable. Every axis is kept verbatim — protocol, the optional
// ports, and which of the four source arms it came from — because a rule this
// provider did not write still has to be *removable*, and a revoke is built from
// what is kept here. Nothing is interpreted: the ports' meaning depends on the
// protocol, and -1 is a legal ICMP wildcard rather than a value this package may
// mint.
//
// Such a rule is then not equal to anything the provider asks for, so
// reconciliation revokes it — which is the right outcome for an unexplained hole
// in a group that fronts a database. That was already the intent when this
// reported a wide span as a single marker port; what it lacked was the ability to
// carry out the second half. See [SecurityGroupRule] for both defects.
//
// A permission this package cannot express is an **error**, never zero rules:
// contributing nothing silently leaves whatever EC2 was describing authorised
// with nothing pointing at it.
func securityGroupRecord(g *ec2types.SecurityGroup) (*SecurityGroupRecord, error) {
	rec := &SecurityGroupRecord{
		ID:   awssdk.ToString(g.GroupId),
		Name: awssdk.ToString(g.GroupName),
		VPC:  awssdk.ToString(g.VpcId),
		Tags: map[string]string{},
	}
	for _, t := range g.Tags {
		rec.Tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	for _, p := range g.IpPermissions {
		// Read verbatim, across every arm of the SDK's IpPermission. The axes
		// are taken from types.IpPermission itself -- protocol, an optional
		// FromPort and ToPort, and four source arms -- rather than from the
		// shapes this provider has happened to meet, because the shapes it has
		// met are not the population.
		//
		// A rule with FromPort != ToPort, or a protocol this provider does not
		// write, is still not equal to anything it asks for, so it still lands in
		// the removal set -- and now what goes back to EC2 describes the rule
		// that exists.
		base := SecurityGroupRule{
			Protocol: strings.ToLower(awssdk.ToString(p.IpProtocol)),
			FromPort: optionalPortFrom(p.FromPort),
			ToPort:   optionalPortFrom(p.ToPort),
		}
		// One rule per source, because each is separately revocable. A permission
		// carrying a CIDR and a group and a prefix list is three rules here.
		for _, pair := range p.UserIdGroupPairs {
			r := base
			r.SourceGroup = awssdk.ToString(pair.GroupId)
			r.SourceGroupOwner = awssdk.ToString(pair.UserId)
			r.Description = optionalStringFrom(pair.Description)
			rec.Ingress = append(rec.Ingress, r)
		}
		for _, ip := range p.IpRanges {
			r := base
			r.SourceCIDR = awssdk.ToString(ip.CidrIp)
			r.Description = optionalStringFrom(ip.Description)
			rec.Ingress = append(rec.Ingress, r)
		}
		for _, ip := range p.Ipv6Ranges {
			r := base
			r.SourceCIDR = awssdk.ToString(ip.CidrIpv6)
			r.Description = optionalStringFrom(ip.Description)
			rec.Ingress = append(rec.Ingress, r)
		}
		for _, pl := range p.PrefixListIds {
			r := base
			r.SourcePrefixList = awssdk.ToString(pl.PrefixListId)
			r.Description = optionalStringFrom(pl.Description)
			rec.Ingress = append(rec.Ingress, r)
		}
		if len(p.UserIdGroupPairs) == 0 && len(p.IpRanges) == 0 &&
			len(p.Ipv6Ranges) == 0 && len(p.PrefixListIds) == 0 {
			// A permission with no source arm at all. It cannot be turned into a
			// rule, and the one thing that must not happen is contributing
			// nothing silently: that is a rule left authorised with nothing
			// pointing at it, which is how the prefix-list omission behaved.
			//
			// "This permission cannot be represented" is an acceptable answer.
			// "Zero rules" is not, because zero rules is indistinguishable from
			// an empty group.
			return nil, fmt.Errorf("security group %s holds a permission for protocol %q with no "+
				"source of any kind -- no group pair, no IPv4 or IPv6 range, and no prefix list. "+
				"This package cannot express it, and reporting it as no rules at all would leave "+
				"it authorised with nothing pointing at it",
				awssdk.ToString(g.GroupId), base.Protocol)
		}
	}
	sortRules(rec.Ingress)
	return rec, nil
}

func (s *sdkEC2) CreateSecurityGroup(ctx context.Context, in CreateSecurityGroupRequest) (*SecurityGroupRecord, error) {
	out, err := s.c.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   awssdk.String(in.Name),
		Description: awssdk.String(in.Description),
		VpcId:       awssdk.String(in.VPC),
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeSecurityGroup,
			Tags:         ec2Tags(in.Tags),
		}},
	})
	if err != nil {
		return nil, s.err(err)
	}
	return &SecurityGroupRecord{
		ID:   awssdk.ToString(out.GroupId),
		Name: in.Name,
		VPC:  in.VPC,
		Tags: copyTags(in.Tags),
	}, nil
}

func (s *sdkEC2) DeleteSecurityGroup(ctx context.Context, id string) error {
	_, err := s.c.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
		GroupId: awssdk.String(id),
	})
	return s.err(err)
}

func (s *sdkEC2) AuthorizeIngress(ctx context.Context, id string, rules []SecurityGroupRule) error {
	perms, err := ipPermissions(rules)
	if err != nil {
		// Returned as itself. It carries no substrate sentinel, so it cannot be
		// mistaken for the service's answer -- see [ipPermissions].
		return err
	}
	_, err = s.c.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:       awssdk.String(id),
		IpPermissions: perms,
	})
	return s.err(err)
}

func (s *sdkEC2) RevokeIngress(ctx context.Context, id string, rules []SecurityGroupRule) error {
	perms, err := ipPermissions(rules)
	if err != nil {
		// Returned as itself. It carries no substrate sentinel, so it cannot be
		// mistaken for the service's answer -- see [ipPermissions].
		return err
	}
	_, err = s.c.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId:       awssdk.String(id),
		IpPermissions: perms,
	})
	return s.err(err)
}

// ipPermissions renders rules into EC2 permissions, or refuses.
//
// # Why this can fail, and why the failure is a plain error
//
// It is the last place a rule this package cannot describe can be caught before
// a revoke or an authorise is built from it. A permission that does not describe
// the rule the caller meant is worse than no call at all: on the revoke path the
// service answers something about the permission it was handed rather than about
// the rule that exists, and [Provider.reconcileIngress] tolerates
// [ErrNoSuchResource] there — correctly, because a rule the *service* says is
// already gone is a benign concurrent teardown.
//
// So the refusal must not be able to reach that tolerance. It is a plain error
// carrying no substrate sentinel, deliberately: "I cannot describe your rule"
// and "that rule is already gone" are different answers, and collapsing the
// first into the second turns a failure into evidence of the desired state,
// which is the fail-open direction. Malformed, invalid and absent are three
// answers -- the same distinction this package's EC2 error classification is
// built on, applied to its own output rather than to the service's.
//
// USOSS-11's reviewer found this shape on the port-range sentinel that
// [SecurityGroupRule] documents. The sentinel is gone, so a range is no longer
// unrenderable; a rule with no source and a rule with an impossible span still
// are, and they fail here rather than at AWS.
func ipPermissions(rules []SecurityGroupRule) ([]ec2types.IpPermission, error) {
	out := make([]ec2types.IpPermission, 0, len(rules))
	for i, r := range rules {
		from, err := renderPort(i, "FromPort", r.FromPort)
		if err != nil {
			return nil, err
		}
		to, err := renderPort(i, "ToPort", r.ToPort)
		if err != nil {
			return nil, err
		}
		p := ec2types.IpPermission{
			IpProtocol: awssdk.String(r.Protocol),
			FromPort:   from,
			ToPort:     to,
		}
		switch {
		case r.SourceGroup != "":
			pair := ec2types.UserIdGroupPair{
				GroupId:     awssdk.String(r.SourceGroup),
				Description: renderText(r.Description),
			}
			if r.SourceGroupOwner != "" {
				// Carried through, because a revoke that drops the owner of a
				// cross-account pair revokes a different rule or nothing.
				pair.UserId = awssdk.String(r.SourceGroupOwner)
			}
			p.UserIdGroupPairs = []ec2types.UserIdGroupPair{pair}
		case r.SourcePrefixList != "":
			p.PrefixListIds = []ec2types.PrefixListId{{
				PrefixListId: awssdk.String(r.SourcePrefixList),
				Description:  renderText(r.Description),
			}}
		case strings.Contains(r.SourceCIDR, ":"):
			p.Ipv6Ranges = []ec2types.Ipv6Range{{
				CidrIpv6:    awssdk.String(r.SourceCIDR),
				Description: renderText(r.Description),
			}}
		case r.SourceCIDR != "":
			p.IpRanges = []ec2types.IpRange{{
				CidrIp:      awssdk.String(r.SourceCIDR),
				Description: renderText(r.Description),
			}}
		default:
			// The second instance of the same class, found while fixing the
			// first. This used to fall through to the IPv4 branch and render
			// CidrIp: "" -- a permission describing no source at all, sent to
			// EC2 to be rejected with a code nobody here chose.
			return nil, fmt.Errorf("rule %d names no source: no group, no CIDR and no prefix "+
				"list, so there is no permission that describes it", i)
		}
		out = append(out, p)
	}
	return out, nil
}

// renderPort converts one optional port back to the SDK's *int32.
//
// Absence renders as nil rather than as a pointer to zero, which is the whole
// reason [OptionalPort] exists: an all-protocol permission omits both, and a
// non-nil zero is not the permission EC2 returned.
//
// The bound is -1..65535 and it is checked rather than asserted. -1 is legal --
// it is the documented ICMP and ICMPv6 wildcard for a type or a code -- so
// refusing every negative value, as an earlier version of this function did,
// made a valid rule unrevocable. That was a false refusal introduced by the fix
// for a silent one, from the same missing axis: the meaning of these fields
// depends on the protocol, so nothing here interprets them and only the
// conversion's own range is enforced.
// renderText converts an optional description back to the SDK's *string.
//
// Absence renders as nil, never as a pointer to "". EC2 returning no description
// and EC2 returning an empty one are different permissions, and the description
// is carried into the revoke -- so this is the same defect as a non-nil zero
// port, in another field.
func renderText(s OptionalString) *string {
	if !s.Set {
		return nil
	}
	return awssdk.String(s.Value)
}

func renderPort(i int, field string, p OptionalPort) (*int32, error) {
	if !p.Set {
		return nil, nil
	}
	if p.Value < -1 || p.Value > 65535 {
		return nil, fmt.Errorf("rule %d has %s %d, which is outside the range EC2 states for a "+
			"port, an ICMP type or an ICMP code (-1 to 65535); this is a plain error rather than "+
			"a substrate sentinel so that no caller can read it as the rule already being absent",
			i, field, p.Value)
	}
	// No //nolint, for the second time in this file and for the same reason: the
	// range check above is what the old suppression asserted without having, so
	// gosec sees the bound and there is nothing to suppress.
	return awssdk.Int32(int32(p.Value)), nil
}

func (s *sdkEC2) TagSecurityGroup(ctx context.Context, id string, tags map[string]string) error {
	_, err := s.c.CreateTags(ctx, &ec2.CreateTagsInput{
		Resources: []string{id},
		Tags:      ec2Tags(tags),
	})
	return s.err(err)
}

func (s *sdkEC2) UntagSecurityGroup(ctx context.Context, id string, keys []string) error {
	tags := make([]ec2types.Tag, 0, len(keys))
	for _, k := range keys {
		tags = append(tags, ec2types.Tag{Key: awssdk.String(k)})
	}
	_, err := s.c.DeleteTags(ctx, &ec2.DeleteTagsInput{Resources: []string{id}, Tags: tags})
	return s.err(err)
}

func ec2Tags(tags map[string]string) []ec2types.Tag {
	out := make([]ec2types.Tag, 0, len(tags))
	for _, k := range sortedKeys(tags) {
		out = append(out, ec2types.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	return out
}

// --- DynamoDB ----------------------------------------------------------------

type sdkDynamoDB struct {
	c *dynamodb.Client
	classifier
}

var _ DynamoDBAPI = (*sdkDynamoDB)(nil)

func dynamoNotFound(err error) bool {
	return isType[*dynamodbtypes.ResourceNotFoundException](err) ||
		isType[*dynamodbtypes.TableNotFoundException](err)
}

func dynamoExists(err error) bool {
	return isType[*dynamodbtypes.ResourceInUseException](err) ||
		isType[*dynamodbtypes.TableAlreadyExistsException](err)
}

// isDynamoThrottle recognises the DynamoDB throttle code the shared retryable set
// cannot name.
//
// # Why this exists here rather than in the shared set
//
// The shared retryable set in internal/awscode drops
// `ProvisionedThroughputExceededException` deliberately, and the reason is
// recorded next to it: the code is DynamoDB's, this repository fenced DynamoDB
// into store/, and **the boundary checker rejected the string** — the fence doing
// its job on a list pasted without asking what those clients could return.
//
// USOSS-14 changes the premise. It widens the fence for compute/aws, because
// provisioning a table for a deployed application is the other side of the port
// that fence guards, and it adds a port that makes real DynamoDB calls. So the
// code is now both nameable and reachable, and leaving it out has a live
// consequence: a throttled DynamoDB call would be classified terminal, telling a
// caller its spec has to change when waiting would have worked. That is exactly
// the failure the retryable set exists to prevent.
//
// It is named in this file rather than beside the set because the idiom half of
// the fence exempts **this file only** — the shared set lives in
// internal/awscode, where the string is still correctly refused.
//
// Measured, not assumed. With this check disabled,
// `ProvisionedThroughputExceededException` classifies as [compute.ErrFailed] —
// terminal — which is the gap. `RequestLimitExceeded` already classifies as
// transient without it, because that code IS in the shared set; it is kept here
// anyway as a typed check rather than a string one, since the shared set is
// explicitly hand-maintained and the note beside it says so. One of the two is a
// gap closed and the other is belt and braces, and it is worth writing down
// which.
//
// `TransactionInProgressException`, the SDK's other dropped DynamoDB entry, is
// deliberately **not** here. It belongs to TransactWriteItems, and this port
// issues only control-plane calls — CreateTable, DescribeTable, DeleteTable and
// tagging. Adding a code this port cannot receive would be inventing coverage,
// which is the same mistake in the other direction as pasting the list was.
func isDynamoThrottle(err error) bool {
	return isType[*dynamodbtypes.ProvisionedThroughputExceededException](err) ||
		isType[*dynamodbtypes.RequestLimitExceeded](err)
}

// err classifies a DynamoDB error.
//
// The throttle test runs first, and that ordering is safe rather than convenient:
// the cases [classifier.classify] answers ahead of its own throttle arm are a
// cancelled context, a missing resource, an existing resource, and a denial, and
// none of them can co-occur with a throttle — they are distinct API error codes,
// and a context error is not an smithy.APIError at all.
func (s *sdkDynamoDB) err(err error) error {
	if isDynamoThrottle(err) {
		return fmt.Errorf("%w: %w", ErrThrottled, err)
	}
	return s.classify(err, dynamoNotFound, dynamoExists)
}

func (s *sdkDynamoDB) DescribeTable(ctx context.Context, name string) (*TableRecord, error) {
	out, err := s.c.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: awssdk.String(name)})
	if err != nil {
		return nil, s.err(err)
	}
	if out.Table == nil {
		return nil, ErrNoSuchResource
	}
	rec := &TableRecord{
		Name:   awssdk.ToString(out.Table.TableName),
		ARN:    awssdk.ToString(out.Table.TableArn),
		Status: string(out.Table.TableStatus),
	}
	for _, k := range out.Table.KeySchema {
		switch k.KeyType {
		case dynamodbtypes.KeyTypeHash:
			rec.PartitionKey = awssdk.ToString(k.AttributeName)
		case dynamodbtypes.KeyTypeRange:
			rec.SortKey = awssdk.ToString(k.AttributeName)
		}
	}
	// DescribeTable carries no tags, so without this read every table reads
	// back as unowned and a redeploy refuses the table its first deploy made.
	tags, err := s.ListTags(ctx, rec.ARN)
	if err != nil {
		return nil, err
	}
	rec.Tags = tags
	return rec, nil
}

func (s *sdkDynamoDB) CreateTable(ctx context.Context, in CreateTableRequest) (*TableRecord, error) {
	keys := []dynamodbtypes.KeySchemaElement{
		{AttributeName: awssdk.String(in.PartitionKey), KeyType: dynamodbtypes.KeyTypeHash},
	}
	attrs := []dynamodbtypes.AttributeDefinition{
		{AttributeName: awssdk.String(in.PartitionKey), AttributeType: dynamodbtypes.ScalarAttributeTypeS},
	}
	if in.SortKey != "" {
		keys = append(keys, dynamodbtypes.KeySchemaElement{
			AttributeName: awssdk.String(in.SortKey), KeyType: dynamodbtypes.KeyTypeRange,
		})
		attrs = append(attrs, dynamodbtypes.AttributeDefinition{
			AttributeName: awssdk.String(in.SortKey), AttributeType: dynamodbtypes.ScalarAttributeTypeS,
		})
	}
	out, err := s.c.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: awssdk.String(in.Name),
		// On-demand, which is the source system's choice (database.go:66) and
		// the only billing mode this provider offers: a provisioned-capacity
		// table needs numbers no [compute.KeyValueSpec] carries, and inventing
		// them would be inventing a cost decision on the caller's behalf.
		BillingMode:          dynamodbtypes.BillingModePayPerRequest,
		KeySchema:            keys,
		AttributeDefinitions: attrs,
		Tags:                 dynamoTags(in.Tags),
	})
	if err != nil {
		return nil, s.err(err)
	}
	return &TableRecord{
		Name:         awssdk.ToString(out.TableDescription.TableName),
		ARN:          awssdk.ToString(out.TableDescription.TableArn),
		PartitionKey: in.PartitionKey,
		SortKey:      in.SortKey,
		Status:       string(out.TableDescription.TableStatus),
		Tags:         copyTags(in.Tags),
	}, nil
}

func (s *sdkDynamoDB) DeleteTable(ctx context.Context, name string) error {
	_, err := s.c.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: awssdk.String(name)})
	return s.err(err)
}

func (s *sdkDynamoDB) ListTags(ctx context.Context, arn string) (map[string]string, error) {
	tags := map[string]string{}
	var next *string
	for {
		out, err := s.c.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{
			ResourceArn: awssdk.String(arn),
			NextToken:   next,
		})
		if err != nil {
			return nil, s.err(err)
		}
		for _, t := range out.Tags {
			tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
		}
		// The page token is followed rather than ignored. USOSS-13 found the
		// source system dropping an IsTruncated on a delete path
		// (bucket.go:851-859); a truncated tag listing here would make the
		// ownership check read a resource's tags as absent and refuse a
		// resource this platform owns — or, worse, make the convergence delta
		// think a tag needs writing on every reconcile.
		if next = out.NextToken; next == nil {
			return tags, nil
		}
	}
}

func (s *sdkDynamoDB) TagResource(ctx context.Context, arn string, tags map[string]string) error {
	_, err := s.c.TagResource(ctx, &dynamodb.TagResourceInput{
		ResourceArn: awssdk.String(arn),
		Tags:        dynamoTags(tags),
	})
	return s.err(err)
}

func (s *sdkDynamoDB) UntagResource(ctx context.Context, arn string, keys []string) error {
	_, err := s.c.UntagResource(ctx, &dynamodb.UntagResourceInput{
		ResourceArn: awssdk.String(arn),
		TagKeys:     keys,
	})
	return s.err(err)
}

func dynamoTags(tags map[string]string) []dynamodbtypes.Tag {
	out := make([]dynamodbtypes.Tag, 0, len(tags))
	for _, k := range sortedKeys(tags) {
		out = append(out, dynamodbtypes.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	return out
}
