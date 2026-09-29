// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// This file is the SDK half of the container port: the ECS adapter, and the
// inline-role-policy calls added to the IAM adapter. Like awssdk.go it contains
// no policy — every function is a translation of one API call and one error —
// so that everything above [Substrate] is the same code against an account or
// against memory.

// UseECS attaches a real ECS client to a substrate.
//
// It is a separate call rather than another parameter on [NewSDKSubstrate] so
// that adding the container port does not change the signature every existing
// composition root already calls. Clients are supplied rather than constructed
// here for the same reason they are there: where credentials come from is the
// composition root's decision.
//
// # Retry and its classification are both the caller's
//
// This does not check that the client retries, and the adapter does not consult
// the client's retryer to classify. USOSS-10 removed both, in that order, and
// both removals apply here unchanged. Owning a behaviour inside somebody else's
// extensible object means enumerating its disable paths, and a client's retry
// configuration is not this provider's error taxonomy: an operator who turns
// retry down asked for fewer attempts, not for throttles to become terminal.
//
// So: retry configuration belongs to whoever builds the client, classification
// is a fixed function of the error, and a caller who needs the classification
// widened says so through [Config.IsRetryable] — which is consulted in addition
// and never instead, so it can only move an error from terminal to
// [compute.ErrTransient].
//
// It returns an error rather than nothing only because a nil client is a
// programming mistake worth naming at the call site.
func (s *Substrate) UseECS(client *ecs.Client) error {
	if client == nil {
		return errors.New("aws: UseECS needs a client; pass nil Config.Container instead to run " +
			"without a container runtime")
	}
	s.ECS = &sdkECS{c: client}
	return nil
}

// --- IAM: inline role policies -------------------------------------------------
//
// Put and Delete are [RolePolicyAPI]'s and are implemented in awssdkdb.go
// (USOSS-14). Only the listing is here, because that is the only inline-policy
// call the container port added to [IAMAPI].

// ListRolePolicyNames implements [IAMAPI], following the paginator.
//
// The pagination is not optional. ListRolePolicies truncates, and a caller that
// read one page would compute its "policies to remove" set from a partial list
// — leaving a revoked grant attached and reporting success. That is the exact
// shape of a source-system defect this port was told about
// (bucket.go:851-859 ignores IsTruncated), so it is followed here rather than
// assumed short.
func (s *sdkIAM) ListRolePolicyNames(ctx context.Context, roleName string) ([]string, error) {
	var out []string
	pager := iam.NewListRolePoliciesPaginator(s.c, &iam.ListRolePoliciesInput{
		RoleName: awssdk.String(roleName),
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, s.err(err)
		}
		out = append(out, page.PolicyNames...)
	}
	return out, nil
}

// --- ECS -----------------------------------------------------------------------

type sdkECS struct {
	c *ecs.Client
	classifier
}

var _ ECSAPI = (*sdkECS)(nil)

func ecsNotFound(err error) bool {
	return isType[*ecstypes.ServiceNotFoundException](err) ||
		isType[*ecstypes.ClusterNotFoundException](err) ||
		isType[*ecstypes.TargetNotFoundException](err)
}

func ecsExists(err error) bool { return isType[*ecstypes.ServiceNotActiveException](err) }

func (s *sdkECS) err(err error) error { return s.classify(err, ecsNotFound, ecsExists) }

// The task-definition constants this provider does not vary.
//
// They are here rather than on [TaskDefinitionRequest] because they are facts
// about how this provider runs a container, not choices a caller or the port
// makes: Fargate, awsvpc networking, and one essential container. Every one of
// them appears in the call this replaces (container.go:744-752) as an explicit
// field, and every one is an ECS fact rather than a fact about running a
// container — which is why [compute.ContainerRuntime] deliberately has none of
// them.
var (
	fargateOnly      = []ecstypes.Compatibility{ecstypes.CompatibilityFargate}
	awsvpcNetworking = ecstypes.NetworkModeAwsvpc
)

func (s *sdkECS) RegisterTaskDefinition(ctx context.Context, in TaskDefinitionRequest) (string, error) {
	container := ecstypes.ContainerDefinition{
		Name:  awssdk.String(in.Container.Name),
		Image: awssdk.String(in.Container.Image),
		// One container per task, so it is essential by definition: a task whose
		// only container may exit without the task failing is a task that
		// reports healthy while running nothing.
		Essential: awssdk.Bool(true),
	}
	for _, port := range in.Container.Ports {
		p32, err := narrowToInt32("a container port", port)
		if err != nil {
			return "", err
		}
		container.PortMappings = append(container.PortMappings, ecstypes.PortMapping{
			ContainerPort: awssdk.Int32(p32),
			Protocol:      ecstypes.TransportProtocolTcp,
		})
	}
	for _, kv := range in.Container.Env {
		container.Environment = append(container.Environment, ecstypes.KeyValuePair{
			Name:  awssdk.String(kv.Name),
			Value: awssdk.String(kv.Value),
		})
	}
	for _, sec := range in.Container.Secrets {
		// ValueFrom is an address. The agent resolves it with the execution
		// role's credentials at task start, which is why no secret material
		// passes through this process.
		container.Secrets = append(container.Secrets, ecstypes.Secret{
			Name:      awssdk.String(sec.Name),
			ValueFrom: awssdk.String(sec.ValueFrom),
		})
	}
	if len(in.Container.DockerLabels) > 0 {
		container.DockerLabels = in.Container.DockerLabels
	}
	if in.Container.LogGroup != "" {
		container.LogConfiguration = &ecstypes.LogConfiguration{
			LogDriver: ecstypes.LogDriverAwslogs,
			Options: map[string]string{
				"awslogs-group":         in.Container.LogGroup,
				"awslogs-region":        s.c.Options().Region,
				"awslogs-stream-prefix": in.Container.Name,
				// The agent creates the group on first use, which is why the
				// execution role carries logs:CreateLogGroup. See
				// Provider.logWritePolicy.
				"awslogs-create-group": "true",
			},
		}
	}

	out, err := s.c.RegisterTaskDefinition(ctx, &ecs.RegisterTaskDefinitionInput{
		Family:                  awssdk.String(in.Family),
		RequiresCompatibilities: fargateOnly,
		NetworkMode:             awsvpcNetworking,
		Cpu:                     awssdk.String(strconv.Itoa(in.CPUUnits)),
		Memory:                  awssdk.String(strconv.Itoa(in.MemoryMiB)),
		ExecutionRoleArn:        awssdk.String(in.ExecutionRoleARN),
		TaskRoleArn:             awssdk.String(in.TaskRoleARN),
		ContainerDefinitions:    []ecstypes.ContainerDefinition{container},
		Tags:                    ecsTags(in.Tags),
	})
	if err != nil {
		return "", s.err(err)
	}
	if out.TaskDefinition == nil || out.TaskDefinition.TaskDefinitionArn == nil {
		return "", fmt.Errorf("%w: RegisterTaskDefinition returned no task definition ARN",
			ErrNoSuchResource)
	}
	return awssdk.ToString(out.TaskDefinition.TaskDefinitionArn), nil
}

func (s *sdkECS) DescribeTaskDefinition(ctx context.Context, arn string) (*TaskDefinitionRequest, error) {
	out, err := s.c.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: awssdk.String(arn),
	})
	if err != nil {
		return nil, s.err(err)
	}
	td := out.TaskDefinition
	if td == nil || len(td.ContainerDefinitions) == 0 {
		return nil, fmt.Errorf("%w: task definition %q has no container definitions",
			ErrNoSuchResource, arn)
	}
	cpu, _ := strconv.Atoi(awssdk.ToString(td.Cpu))
	mem, _ := strconv.Atoi(awssdk.ToString(td.Memory))
	def := td.ContainerDefinitions[0]
	req := &TaskDefinitionRequest{
		Family:           awssdk.ToString(td.Family),
		CPUUnits:         cpu,
		MemoryMiB:        mem,
		ExecutionRoleARN: awssdk.ToString(td.ExecutionRoleArn),
		TaskRoleARN:      awssdk.ToString(td.TaskRoleArn),
		Container: ContainerRequest{
			Name:         awssdk.ToString(def.Name),
			Image:        awssdk.ToString(def.Image),
			DockerLabels: def.DockerLabels,
		},
	}
	for _, pm := range def.PortMappings {
		req.Container.Ports = append(req.Container.Ports, int(awssdk.ToInt32(pm.ContainerPort)))
	}
	for _, kv := range def.Environment {
		req.Container.Env = append(req.Container.Env, KeyValue{
			Name:  awssdk.ToString(kv.Name),
			Value: awssdk.ToString(kv.Value),
		})
	}
	for _, sec := range def.Secrets {
		req.Container.Secrets = append(req.Container.Secrets, SecretReference{
			Name:      awssdk.ToString(sec.Name),
			ValueFrom: awssdk.ToString(sec.ValueFrom),
		})
	}
	if def.LogConfiguration != nil {
		req.Container.LogGroup = def.LogConfiguration.Options["awslogs-group"]
	}
	// Tags are NOT read back here. DescribeTaskDefinition returns them only
	// when asked with Include, and the port reads a revision to reconstruct the
	// caller's spec rather than to check ownership -- which it does on the
	// service, where the ownership marker actually lives.
	return req, nil
}

func (s *sdkECS) DescribeService(ctx context.Context, cluster, name string) (*ServiceRecord, error) {
	out, err := s.c.DescribeServices(ctx, &ecs.DescribeServicesInput{
		Cluster:  awssdk.String(cluster),
		Services: []string{name},
		// Tags are asked for here so that the ownership check is one call
		// rather than two. A describe that omitted them would make "no tags"
		// indistinguishable from "not owned".
		Include: []ecstypes.ServiceField{ecstypes.ServiceFieldTags},
	})
	if err != nil {
		return nil, s.err(err)
	}
	for _, svc := range out.Services {
		if awssdk.ToString(svc.ServiceName) != name {
			continue
		}
		return serviceRecordOf(svc), nil
	}
	// Absent from Services means never created. A deleted service comes back
	// with status INACTIVE and is NOT this case, which is the distinction the
	// port needs: an INACTIVE service still holds its name.
	return nil, fmt.Errorf("%w: service %q in cluster %q", ErrNoSuchResource, name, cluster)
}

func serviceRecordOf(svc ecstypes.Service) *ServiceRecord {
	rec := &ServiceRecord{
		Name:              awssdk.ToString(svc.ServiceName),
		ARN:               awssdk.ToString(svc.ServiceArn),
		Status:            awssdk.ToString(svc.Status),
		TaskDefinitionARN: awssdk.ToString(svc.TaskDefinition),
		DesiredCount:      int(svc.DesiredCount),
		RunningCount:      int(svc.RunningCount),
		PendingCount:      int(svc.PendingCount),
		ExecEnabled:       svc.EnableExecuteCommand,
		Tags:              map[string]string{},
	}
	for _, t := range svc.Tags {
		rec.Tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	// The PRIMARY deployment, which is the one running the revision the service
	// was last asked to run. Read rather than discarded: an adapter that keeps
	// only the counts decides that the layers above it cannot tell a completed
	// rollout from one that has not started, because the service-level
	// RunningCount includes the previous revision's tasks. See [ServiceRecord].
	for _, d := range svc.Deployments {
		if !strings.EqualFold(awssdk.ToString(d.Status), "PRIMARY") {
			continue
		}
		rec.PrimaryTaskDefinitionARN = awssdk.ToString(d.TaskDefinition)
		rec.PrimaryDesiredCount = int(d.DesiredCount)
		rec.PrimaryRunningCount = int(d.RunningCount)
		rec.RolloutState = string(d.RolloutState)
		rec.RolloutReason = awssdk.ToString(d.RolloutStateReason)
		break
	}
	// Events arrive newest-first from ECS and are relayed in that order,
	// because the newest is the one that explains why a task is not starting.
	for _, e := range svc.Events {
		if msg := strings.TrimSpace(awssdk.ToString(e.Message)); msg != "" {
			rec.Events = append(rec.Events, msg)
		}
	}
	return rec
}

func (s *sdkECS) CreateService(ctx context.Context, in ServiceRequest) (*ServiceRecord, error) {
	count, err := narrowToInt32("DesiredCount", in.DesiredCount)
	if err != nil {
		return nil, err
	}
	out, err := s.c.CreateService(ctx, &ecs.CreateServiceInput{
		Cluster:              awssdk.String(in.Cluster),
		ServiceName:          awssdk.String(in.Name),
		TaskDefinition:       awssdk.String(in.TaskDefinitionARN),
		DesiredCount:         awssdk.Int32(count),
		LaunchType:           ecstypes.LaunchTypeFargate,
		EnableExecuteCommand: in.ExecEnabled,
		NetworkConfiguration: networkConfig(in),
		Tags:                 ecsTags(in.Tags),
	})
	if err != nil {
		return nil, s.err(err)
	}
	if out.Service == nil {
		return nil, fmt.Errorf("%w: CreateService returned no service", ErrNoSuchResource)
	}
	return serviceRecordOf(*out.Service), nil
}

func (s *sdkECS) UpdateService(ctx context.Context, in ServiceRequest) (*ServiceRecord, error) {
	count, err := narrowToInt32("DesiredCount", in.DesiredCount)
	if err != nil {
		return nil, err
	}
	out, err := s.c.UpdateService(ctx, &ecs.UpdateServiceInput{
		Cluster:              awssdk.String(in.Cluster),
		Service:              awssdk.String(in.Name),
		TaskDefinition:       awssdk.String(in.TaskDefinitionARN),
		DesiredCount:         awssdk.Int32(count),
		EnableExecuteCommand: awssdk.Bool(in.ExecEnabled),
		NetworkConfiguration: networkConfig(in),
	})
	if err != nil {
		return nil, s.err(err)
	}
	if out.Service == nil {
		return nil, fmt.Errorf("%w: UpdateService returned no service", ErrNoSuchResource)
	}
	return serviceRecordOf(*out.Service), nil
}

func (s *sdkECS) SetDesiredCount(ctx context.Context, cluster, name string, count int) error {
	// Only the count. An UpdateService carrying a task definition would roll
	// the service as a side effect of scaling it, which
	// [compute.ContainerRuntime.ScaleService] forbids.
	n32, err := narrowToInt32("the desired count", count)
	if err != nil {
		return err
	}
	_, apiErr := s.c.UpdateService(ctx, &ecs.UpdateServiceInput{
		Cluster:      awssdk.String(cluster),
		Service:      awssdk.String(name),
		DesiredCount: awssdk.Int32(n32),
	})
	return s.err(apiErr)
}

func (s *sdkECS) DeleteService(ctx context.Context, cluster, name string) error {
	// Force, because a service with running tasks cannot otherwise be deleted
	// and the port's contract is "removes a service". The tasks are this
	// service's own, so there is nothing here that belongs to somebody else —
	// unlike a repository delete, which destroys images.
	_, err := s.c.DeleteService(ctx, &ecs.DeleteServiceInput{
		Cluster: awssdk.String(cluster),
		Service: awssdk.String(name),
		Force:   awssdk.Bool(true),
	})
	return s.err(err)
}

func (s *sdkECS) ListServiceTags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := s.c.ListTagsForResource(ctx, &ecs.ListTagsForResourceInput{
		ResourceArn: awssdk.String(arn),
	})
	if err != nil {
		return nil, s.err(err)
	}
	tags := make(map[string]string, len(out.Tags))
	for _, t := range out.Tags {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return tags, nil
}

func (s *sdkECS) TagService(ctx context.Context, arn string, tags map[string]string) error {
	_, err := s.c.TagResource(ctx, &ecs.TagResourceInput{
		ResourceArn: awssdk.String(arn),
		Tags:        ecsTags(tags),
	})
	return s.err(err)
}

func (s *sdkECS) UntagService(ctx context.Context, arn string, keys []string) error {
	_, err := s.c.UntagResource(ctx, &ecs.UntagResourceInput{
		ResourceArn: awssdk.String(arn),
		TagKeys:     keys,
	})
	return s.err(err)
}

// networkConfig renders the awsvpc configuration.
//
// AssignPublicIp is set explicitly in both directions rather than left to the
// SDK's zero value, because the zero value of that enum is the empty string and
// what AWS does with it is not this package's decision to leave open.
func networkConfig(in ServiceRequest) *ecstypes.NetworkConfiguration {
	assign := ecstypes.AssignPublicIpDisabled
	if in.AssignPublicIP {
		assign = ecstypes.AssignPublicIpEnabled
	}
	return &ecstypes.NetworkConfiguration{
		AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{
			Subnets:        in.SubnetIDs,
			SecurityGroups: in.SecurityGroupIDs,
			AssignPublicIp: assign,
		},
	}
}

// ecsTags renders a tag map in ECS's vocabulary, key-sorted so two calls with
// the same map produce the same request.
func ecsTags(tags map[string]string) []ecstypes.Tag {
	if len(tags) == 0 {
		return nil
	}
	out := make([]ecstypes.Tag, 0, len(tags))
	for _, k := range sortedKeys(tags) {
		out = append(out, ecstypes.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	return out
}
