// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	lambdaapi "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go"

	"github.com/conductorone/apphub/compute"
)

// The SDK adapters for the function and function-endpoint ports: Lambda, ELBv2
// and the EC2 primitives this port needs for a load balancer's security group.
//
// Same contract as awssdk.go, which this file extends: every function is a
// translation of one API call and one error, and no policy lives here.
//
// This package's EC2 surface is [EndpointEC2API], not [EC2API] -- see the note
// on [Substrate.EndpointEC2] for why the relational port's primitive layer and
// this port's are two interfaces sharing one AWS client rather than one.

// --- Lambda ---------------------------------------------------------------------------

type sdkLambda struct {
	c *lambdaapi.Client
	classifier
}

var _ LambdaAPI = (*sdkLambda)(nil)

// Lambda reports two different facts through one exception type, and which one
// it means depends on which call raised it.
//
// ResourceConflictException from CreateFunction or AddPermission means "that
// already exists". From UpdateFunctionConfiguration or UpdateFunctionCode it
// means "another update to this function is still in progress". They map to
// different sentinels — [ErrAlreadyExists] and [ErrConflict] — and both reach
// [compute.ErrTransient], so a caller's next move is the same either way; what
// differs is the error it reads, and a caller told "already exists" when the
// truth is "still updating" goes looking for a resource that is not the problem.
//
// The classification is therefore per call and not per service. It cannot be
// derived: the distinction is in the API's semantics and not in anything the
// error carries.
func lambdaNotFound(err error) bool {
	return isType[*lambdatypes.ResourceNotFoundException](err)
}

func lambdaConflict(err error) bool {
	return isType[*lambdatypes.ResourceConflictException](err)
}

// err classifies a read or a delete, where a conflict cannot arise.
func (s *sdkLambda) err(err error) error { return s.classify(err, lambdaNotFound, nil) }

// createErr classifies a call whose conflict means "already exists".
func (s *sdkLambda) createErr(err error) error {
	return s.classify(err, lambdaNotFound, lambdaConflict)
}

// updateErr classifies a call whose conflict means "still updating".
func (s *sdkLambda) updateErr(err error) error {
	if lambdaConflict(err) {
		return fmt.Errorf("%w: %w", ErrConflict, err)
	}
	return s.classify(err, lambdaNotFound, nil)
}

func (s *sdkLambda) GetFunction(ctx context.Context, name string) (*FunctionRecord, error) {
	out, err := s.c.GetFunction(ctx, &lambdaapi.GetFunctionInput{FunctionName: awssdk.String(name)})
	if err != nil {
		return nil, s.err(err)
	}
	if out.Configuration == nil {
		// Absence is reported as an exception, so a nil configuration is a shape
		// the service does not produce. Mapped rather than dereferenced, because
		// a panic here would be a provider crash on a caller's read.
		return nil, fmt.Errorf("%w: function %q", ErrNoSuchResource, name)
	}
	// GetFunction returns the tags alongside the configuration, which is why
	// nothing here makes a second call for them: the ownership check needs the
	// tags on every read, and fetching them separately would double the request
	// count on this port's hottest path.
	return functionRecord(out.Configuration, out.Tags), nil
}

func (s *sdkLambda) CreateFunction(ctx context.Context, in CreateFunctionRequest) (*FunctionRecord, error) {
	arch, err := lambdaArch(in.Architecture)
	if err != nil {
		return nil, err
	}
	memory, err := int32Of("MemoryMiB", in.MemoryMiB)
	if err != nil {
		return nil, err
	}
	timeout, err := int32Of("TimeoutSeconds", in.TimeoutSeconds)
	if err != nil {
		return nil, err
	}
	out, err := s.c.CreateFunction(ctx, &lambdaapi.CreateFunctionInput{
		FunctionName:  awssdk.String(in.Name),
		Runtime:       lambdatypes.Runtime(in.Runtime),
		Handler:       awssdk.String(in.Handler),
		Role:          awssdk.String(in.RoleARN),
		MemorySize:    awssdk.Int32(memory),
		Timeout:       awssdk.Int32(timeout),
		Architectures: []lambdatypes.Architecture{arch},
		Code:          functionCode(in.Code),
		Environment:   &lambdatypes.Environment{Variables: in.Env},
		Description:   awssdk.String(in.Description),
		Tags:          in.Tags,
	})
	if err != nil {
		return nil, s.createErr(err)
	}
	// The tags come from the request rather than from the response, because
	// CreateFunction does not echo them and the provider's next step reads them.
	return functionRecord(&lambdatypes.FunctionConfiguration{
		FunctionName: out.FunctionName, FunctionArn: out.FunctionArn,
		Runtime: out.Runtime, Handler: out.Handler, Role: out.Role,
		MemorySize: out.MemorySize, Timeout: out.Timeout,
		Architectures: out.Architectures, Environment: out.Environment,
		State: out.State, StateReason: out.StateReason,
		LastUpdateStatus: out.LastUpdateStatus, LastUpdateStatusReason: out.LastUpdateStatusReason,
		RevisionId: out.RevisionId, CodeSha256: out.CodeSha256,
	}, in.Tags), nil
}

func (s *sdkLambda) UpdateFunctionConfiguration(ctx context.Context, in UpdateFunctionConfigurationRequest) (*FunctionRecord, error) {
	memory, err := int32Of("MemoryMiB", in.MemoryMiB)
	if err != nil {
		return nil, err
	}
	timeout, err := int32Of("TimeoutSeconds", in.TimeoutSeconds)
	if err != nil {
		return nil, err
	}
	out, err := s.c.UpdateFunctionConfiguration(ctx, &lambdaapi.UpdateFunctionConfigurationInput{
		FunctionName: awssdk.String(in.Name),
		Runtime:      lambdatypes.Runtime(in.Runtime),
		Handler:      awssdk.String(in.Handler),
		Role:         awssdk.String(in.RoleARN),
		MemorySize:   awssdk.Int32(memory),
		Timeout:      awssdk.Int32(timeout),
		// The whole map, every time. Lambda replaces a function's environment
		// rather than merging it, which is what makes the declarative contract
		// implementable at all: a variable dropped from a spec is gone because
		// it was not sent.
		Environment: &lambdatypes.Environment{Variables: in.Env},
		Description: awssdk.String(in.Description),
	})
	if err != nil {
		return nil, s.updateErr(err)
	}
	return functionRecord(&lambdatypes.FunctionConfiguration{
		FunctionName: out.FunctionName, FunctionArn: out.FunctionArn,
		Runtime: out.Runtime, Handler: out.Handler, Role: out.Role,
		MemorySize: out.MemorySize, Timeout: out.Timeout,
		Architectures: out.Architectures, Environment: out.Environment,
		State: out.State, StateReason: out.StateReason,
		LastUpdateStatus: out.LastUpdateStatus, LastUpdateStatusReason: out.LastUpdateStatusReason,
		RevisionId: out.RevisionId, CodeSha256: out.CodeSha256,
	}, nil), nil
}

func (s *sdkLambda) UpdateFunctionCode(ctx context.Context, name, arch string, code FunctionCode) (*FunctionRecord, error) {
	a, err := lambdaArch(arch)
	if err != nil {
		return nil, err
	}
	in := &lambdaapi.UpdateFunctionCodeInput{
		FunctionName:  awssdk.String(name),
		Architectures: []lambdatypes.Architecture{a},
	}
	if code.Zip != nil {
		in.ZipFile = code.Zip
	} else {
		in.S3Bucket = awssdk.String(code.Bucket)
		in.S3Key = awssdk.String(code.Key)
	}
	out, err := s.c.UpdateFunctionCode(ctx, in)
	if err != nil {
		return nil, s.updateErr(err)
	}
	return functionRecord(&lambdatypes.FunctionConfiguration{
		FunctionName: out.FunctionName, FunctionArn: out.FunctionArn,
		Runtime: out.Runtime, Handler: out.Handler, Role: out.Role,
		MemorySize: out.MemorySize, Timeout: out.Timeout,
		Architectures: out.Architectures, Environment: out.Environment,
		State: out.State, StateReason: out.StateReason,
		LastUpdateStatus: out.LastUpdateStatus, LastUpdateStatusReason: out.LastUpdateStatusReason,
		RevisionId: out.RevisionId, CodeSha256: out.CodeSha256,
	}, nil), nil
}

func (s *sdkLambda) DeleteFunction(ctx context.Context, name string) error {
	_, err := s.c.DeleteFunction(ctx, &lambdaapi.DeleteFunctionInput{
		FunctionName: awssdk.String(name),
	})
	return s.err(err)
}

func (s *sdkLambda) AddPermission(ctx context.Context, in AddPermissionRequest) error {
	if strings.TrimSpace(in.SourceARN) == "" {
		// A grant with no source condition authorises the whole service
		// principal — every load balancer in every account it can act for. The
		// provider never composes one, and this is the second line: least
		// privilege enforced at the call and not only where the call is
		// assembled, so a future caller of this adapter inherits it.
		return fmt.Errorf("aws: refusing to grant %q to %q with no source condition; the grant "+
			"would authorise every caller that service principal can act for",
			in.Action, in.Principal)
	}
	_, err := s.c.AddPermission(ctx, &lambdaapi.AddPermissionInput{
		FunctionName: awssdk.String(in.Name),
		StatementId:  awssdk.String(in.StatementID),
		Action:       awssdk.String(in.Action),
		Principal:    awssdk.String(in.Principal),
		SourceArn:    awssdk.String(in.SourceARN),
	})
	return s.createErr(err)
}

func (s *sdkLambda) RemovePermission(ctx context.Context, name, statementID string) error {
	_, err := s.c.RemovePermission(ctx, &lambdaapi.RemovePermissionInput{
		FunctionName: awssdk.String(name),
		StatementId:  awssdk.String(statementID),
	})
	return s.err(err)
}

// ListStatementIDs reads the statement identifiers out of the function's
// resource policy.
//
// The parse is here rather than above [Substrate] deliberately. Lambda's only
// read of a resource policy returns the whole document, and the provider has no
// business understanding a policy language — it needs to know which of its own
// grants exist and nothing more. So the adapter narrows the document to the one
// thing the interface declares, and a statement apphub did not write is
// reported as an identifier and never interpreted.
func (s *sdkLambda) ListStatementIDs(ctx context.Context, name string) ([]string, error) {
	out, err := s.c.GetPolicy(ctx, &lambdaapi.GetPolicyInput{FunctionName: awssdk.String(name)})
	if err != nil {
		return nil, s.err(err)
	}
	var doc struct {
		Statement []struct {
			Sid string `json:"Sid"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(awssdk.ToString(out.Policy)), &doc); err != nil {
		return nil, fmt.Errorf("aws: the resource policy on function %q did not parse: %w", name, err)
	}
	ids := make([]string, 0, len(doc.Statement))
	for _, st := range doc.Statement {
		if st.Sid != "" {
			ids = append(ids, st.Sid)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func (s *sdkLambda) ListTags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := s.c.ListTags(ctx, &lambdaapi.ListTagsInput{Resource: awssdk.String(arn)})
	if err != nil {
		return nil, s.err(err)
	}
	return out.Tags, nil
}

func (s *sdkLambda) TagResource(ctx context.Context, arn string, tags map[string]string) error {
	_, err := s.c.TagResource(ctx, &lambdaapi.TagResourceInput{
		Resource: awssdk.String(arn), Tags: tags,
	})
	return s.err(err)
}

func (s *sdkLambda) UntagResource(ctx context.Context, arn string, keys []string) error {
	_, err := s.c.UntagResource(ctx, &lambdaapi.UntagResourceInput{
		Resource: awssdk.String(arn), TagKeys: keys,
	})
	return s.err(err)
}

// int32Of narrows an int for an API that takes an int32, refusing a value that
// would not survive the conversion.
//
// A refusal rather than a suppressed lint. The provider above this adapter
// already bounds both values it passes — Lambda's own memory and timeout limits,
// checked as [compute.ErrInvalidSpec] against the spec — so this is unreachable
// through the port. It is here because the adapter is exported surface and a
// silent wrap is the failure that would follow: a memory allocation that wrapped
// negative would be sent to Lambda as a negative number, and the deploy would
// fail with an error about a value nobody wrote.
func int32Of(field string, v int) (int32, error) {
	if v < 0 || v > math.MaxInt32 {
		return 0, fmt.Errorf("aws: %s is %d, which does not fit the int32 this API takes",
			field, v)
	}
	return int32(v), nil
}

// lambdaArch translates the substrate vocabulary into the SDK's enum, refusing
// anything else rather than passing a string through into an API call.
func lambdaArch(arch string) (lambdatypes.Architecture, error) {
	switch arch {
	case lambdaArchARM64:
		return lambdatypes.ArchitectureArm64, nil
	case lambdaArchAMD64:
		return lambdatypes.ArchitectureX8664, nil
	default:
		return "", fmt.Errorf("aws: %q is not a Lambda architecture", arch)
	}
}

func functionCode(code FunctionCode) *lambdatypes.FunctionCode {
	if code.Zip != nil {
		return &lambdatypes.FunctionCode{ZipFile: code.Zip}
	}
	return &lambdatypes.FunctionCode{
		S3Bucket: awssdk.String(code.Bucket),
		S3Key:    awssdk.String(code.Key),
	}
}

// functionRecord is the one place a Lambda configuration becomes a
// [FunctionRecord]. The three call sites above differ only in unpacking their
// own output type into the shape this reads, so the interesting decisions —
// which architecture, which reason, how an absent environment reads — are made
// once.
func functionRecord(c *lambdatypes.FunctionConfiguration, tags map[string]string) *FunctionRecord {
	rec := &FunctionRecord{
		Name:             awssdk.ToString(c.FunctionName),
		ARN:              awssdk.ToString(c.FunctionArn),
		Runtime:          string(c.Runtime),
		Handler:          awssdk.ToString(c.Handler),
		RoleARN:          awssdk.ToString(c.Role),
		MemoryMiB:        int(awssdk.ToInt32(c.MemorySize)),
		TimeoutSeconds:   int(awssdk.ToInt32(c.Timeout)),
		State:            string(c.State),
		LastUpdateStatus: string(c.LastUpdateStatus),
		Revision:         awssdk.ToString(c.RevisionId),
		CodeDigest:       awssdk.ToString(c.CodeSha256),
		Tags:             tags,
	}
	if len(c.Architectures) > 0 {
		rec.Architecture = string(c.Architectures[0])
	}
	if c.Environment != nil {
		rec.Env = c.Environment.Variables
	}
	// Whichever of the two reasons is populated. Both are operator-facing text
	// and either can be the explanation for a failed phase; reporting only one
	// would leave a failure with no reason attached about half the time.
	rec.StateReason = awssdk.ToString(c.StateReason)
	if rec.StateReason == "" {
		rec.StateReason = awssdk.ToString(c.LastUpdateStatusReason)
	}
	return rec
}

// --- ELBv2 ----------------------------------------------------------------------------

type sdkELBv2 struct {
	c *elbv2.Client
	classifier
}

var _ ELBv2API = (*sdkELBv2)(nil)

func elbNotFound(err error) bool {
	return isType[*elbv2types.LoadBalancerNotFoundException](err) ||
		isType[*elbv2types.TargetGroupNotFoundException](err) ||
		isType[*elbv2types.ListenerNotFoundException](err)
}

func elbExists(err error) bool {
	return isType[*elbv2types.DuplicateLoadBalancerNameException](err) ||
		isType[*elbv2types.DuplicateTargetGroupNameException](err) ||
		isType[*elbv2types.DuplicateListenerException](err)
}

func (s *sdkELBv2) err(err error) error { return s.classify(err, elbNotFound, elbExists) }

func (s *sdkELBv2) DescribeLoadBalancer(ctx context.Context, name string) (*LoadBalancerRecord, error) {
	out, err := s.c.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{
		Names: []string{name},
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.LoadBalancers) == 0 {
		return nil, fmt.Errorf("%w: load balancer %q", ErrNoSuchResource, name)
	}
	lb := out.LoadBalancers[0]
	rec := &LoadBalancerRecord{
		Name:             awssdk.ToString(lb.LoadBalancerName),
		ARN:              awssdk.ToString(lb.LoadBalancerArn),
		DNSName:          awssdk.ToString(lb.DNSName),
		Scheme:           string(lb.Scheme),
		SecurityGroupIDs: lb.SecurityGroups,
	}
	if lb.State != nil {
		rec.State = string(lb.State.Code)
		rec.StateReason = awssdk.ToString(lb.State.Reason)
	}
	for _, az := range lb.AvailabilityZones {
		if id := awssdk.ToString(az.SubnetId); id != "" {
			rec.SubnetIDs = append(rec.SubnetIDs, id)
		}
	}
	// Tags are a separate call on ELBv2, unlike Lambda's GetFunction. That is a
	// second request on the ownership path and there is no way around it: the
	// describe APIs do not carry tags.
	if rec.Tags, err = s.ListTags(ctx, rec.ARN); err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *sdkELBv2) CreateLoadBalancer(ctx context.Context, in CreateLoadBalancerRequest) (*LoadBalancerRecord, error) {
	out, err := s.c.CreateLoadBalancer(ctx, &elbv2.CreateLoadBalancerInput{
		Name:           awssdk.String(in.Name),
		Subnets:        in.SubnetIDs,
		SecurityGroups: in.SecurityGroupIDs,
		Scheme:         elbv2types.LoadBalancerSchemeEnum(in.Scheme),
		Type:           elbv2types.LoadBalancerTypeEnumApplication,
		Tags:           elbTags(in.Tags),
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.LoadBalancers) == 0 {
		// The source system checks for this too (lambda.go:624-626), and it is
		// worth keeping: an empty list from a successful create is a shape
		// nothing should produce, and indexing into it would be a panic.
		return nil, fmt.Errorf("%w: ELBv2 accepted the create and returned no load balancer",
			compute.ErrFailed)
	}
	lb := out.LoadBalancers[0]
	rec := &LoadBalancerRecord{
		Name:             awssdk.ToString(lb.LoadBalancerName),
		ARN:              awssdk.ToString(lb.LoadBalancerArn),
		DNSName:          awssdk.ToString(lb.DNSName),
		Scheme:           string(lb.Scheme),
		SecurityGroupIDs: lb.SecurityGroups,
		Tags:             in.Tags,
	}
	if lb.State != nil {
		rec.State = string(lb.State.Code)
		rec.StateReason = awssdk.ToString(lb.State.Reason)
	}
	for _, az := range lb.AvailabilityZones {
		if id := awssdk.ToString(az.SubnetId); id != "" {
			rec.SubnetIDs = append(rec.SubnetIDs, id)
		}
	}
	return rec, nil
}

func (s *sdkELBv2) DeleteLoadBalancer(ctx context.Context, arn string) error {
	_, err := s.c.DeleteLoadBalancer(ctx, &elbv2.DeleteLoadBalancerInput{
		LoadBalancerArn: awssdk.String(arn),
	})
	return s.err(err)
}

func (s *sdkELBv2) SetSecurityGroups(ctx context.Context, arn string, ids []string) error {
	_, err := s.c.SetSecurityGroups(ctx, &elbv2.SetSecurityGroupsInput{
		LoadBalancerArn: awssdk.String(arn),
		SecurityGroups:  ids,
	})
	return s.err(err)
}

func (s *sdkELBv2) DescribeTargetGroup(ctx context.Context, name string) (*TargetGroupRecord, error) {
	out, err := s.c.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
		Names: []string{name},
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.TargetGroups) == 0 {
		return nil, fmt.Errorf("%w: target group %q", ErrNoSuchResource, name)
	}
	tg := out.TargetGroups[0]
	rec := &TargetGroupRecord{
		Name:       awssdk.ToString(tg.TargetGroupName),
		ARN:        awssdk.ToString(tg.TargetGroupArn),
		TargetType: string(tg.TargetType),
	}
	if rec.Tags, err = s.ListTags(ctx, rec.ARN); err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *sdkELBv2) CreateTargetGroup(ctx context.Context, in CreateTargetGroupRequest) (*TargetGroupRecord, error) {
	out, err := s.c.CreateTargetGroup(ctx, &elbv2.CreateTargetGroupInput{
		Name:       awssdk.String(in.Name),
		TargetType: elbv2types.TargetTypeEnum(in.TargetType),
		Tags:       elbTags(in.Tags),
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.TargetGroups) == 0 {
		return nil, fmt.Errorf("%w: ELBv2 accepted the create and returned no target group",
			compute.ErrFailed)
	}
	tg := out.TargetGroups[0]
	return &TargetGroupRecord{
		Name:       awssdk.ToString(tg.TargetGroupName),
		ARN:        awssdk.ToString(tg.TargetGroupArn),
		TargetType: string(tg.TargetType),
		Tags:       in.Tags,
	}, nil
}

func (s *sdkELBv2) DeleteTargetGroup(ctx context.Context, arn string) error {
	_, err := s.c.DeleteTargetGroup(ctx, &elbv2.DeleteTargetGroupInput{
		TargetGroupArn: awssdk.String(arn),
	})
	return s.err(err)
}

// DescribeTargets reads registrations through target health, which is the only
// place ELBv2 reports them — **and keeps the health.**
//
// An earlier revision called this same API and discarded every state, returning
// only the identifiers. That is the shape of defect worth naming: the question
// "is this endpoint serving" was being asked of the service and then thrown
// away, so the provider above could only treat registration as health, and an
// endpoint whose sole target answers every request with a 502 reported ready.
func (s *sdkELBv2) DescribeTargets(ctx context.Context, arn string) ([]TargetHealth, error) {
	out, err := s.c.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{
		TargetGroupArn: awssdk.String(arn),
	})
	if err != nil {
		return nil, s.err(err)
	}
	health := make([]TargetHealth, 0, len(out.TargetHealthDescriptions))
	for _, d := range out.TargetHealthDescriptions {
		if d.Target == nil {
			continue
		}
		id := awssdk.ToString(d.Target.Id)
		if id == "" {
			continue
		}
		t := TargetHealth{ID: id}
		if d.TargetHealth != nil {
			t.State = string(d.TargetHealth.State)
			// Both fields, whichever is populated: the reason is an enum and the
			// description is prose, and either can be the only explanation ELBv2
			// gives for a target that is not serving.
			t.Reason = string(d.TargetHealth.Reason)
			if desc := awssdk.ToString(d.TargetHealth.Description); desc != "" {
				t.Reason = desc
			}
		}
		health = append(health, t)
	}
	sort.Slice(health, func(i, j int) bool { return health[i].ID < health[j].ID })
	return health, nil
}

func (s *sdkELBv2) RegisterTargets(ctx context.Context, arn string, targets []string) error {
	_, err := s.c.RegisterTargets(ctx, &elbv2.RegisterTargetsInput{
		TargetGroupArn: awssdk.String(arn),
		Targets:        targetDescriptions(targets),
	})
	return s.err(err)
}

func (s *sdkELBv2) DeregisterTargets(ctx context.Context, arn string, targets []string) error {
	_, err := s.c.DeregisterTargets(ctx, &elbv2.DeregisterTargetsInput{
		TargetGroupArn: awssdk.String(arn),
		Targets:        targetDescriptions(targets),
	})
	return s.err(err)
}

func targetDescriptions(ids []string) []elbv2types.TargetDescription {
	out := make([]elbv2types.TargetDescription, 0, len(ids))
	for _, id := range ids {
		out = append(out, elbv2types.TargetDescription{Id: awssdk.String(id)})
	}
	return out
}

func (s *sdkELBv2) DescribeListeners(ctx context.Context, lbARN string) ([]ListenerRecord, error) {
	// Paginated, and paginated properly. A load balancer with more listeners
	// than one page would otherwise report a subset, and a convergence loop
	// handed a subset deletes nothing it cannot see and recreates what it can —
	// which is the same class as the source system's ignored IsTruncated on a
	// different API.
	pager := elbv2.NewDescribeListenersPaginator(s.c, &elbv2.DescribeListenersInput{
		LoadBalancerArn: awssdk.String(lbARN),
	})
	var out []ListenerRecord
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, s.err(err)
		}
		for _, l := range page.Listeners {
			rec := ListenerRecord{
				ARN:      awssdk.ToString(l.ListenerArn),
				Port:     int(awssdk.ToInt32(l.Port)),
				Protocol: string(l.Protocol),
			}
			if len(l.Certificates) > 0 {
				rec.CertificateARN = awssdk.ToString(l.Certificates[0].CertificateArn)
			}
			for _, a := range l.DefaultActions {
				if a.Type == elbv2types.ActionTypeEnumForward && a.TargetGroupArn != nil {
					rec.TargetGroupARN = awssdk.ToString(a.TargetGroupArn)
					break
				}
			}
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

func (s *sdkELBv2) CreateListener(ctx context.Context, in CreateListenerRequest) (*ListenerRecord, error) {
	if in.Protocol == ListenerProtocolHTTPS && strings.TrimSpace(in.CertificateARN) == "" {
		// The second line behind the provider's own refusal, at the call. ELBv2
		// itself will create this listener and it cannot complete a handshake,
		// which is precisely the source system's defect
		// (lambda.go:487-490, :697-708), so the adapter refuses to be the way it
		// gets made.
		return nil, fmt.Errorf("aws: refusing to create a %s listener on port %d with no "+
			"certificate; ELBv2 accepts it and the listener cannot complete a handshake",
			in.Protocol, in.Port)
	}
	port, err := int32Of("Port", in.Port)
	if err != nil {
		return nil, err
	}
	api := &elbv2.CreateListenerInput{
		LoadBalancerArn: awssdk.String(in.LoadBalancerARN),
		Port:            awssdk.Int32(port),
		Protocol:        elbv2types.ProtocolEnum(in.Protocol),
		DefaultActions: []elbv2types.Action{{
			Type:           elbv2types.ActionTypeEnumForward,
			TargetGroupArn: awssdk.String(in.TargetGroupARN),
		}},
	}
	if in.CertificateARN != "" {
		api.Certificates = []elbv2types.Certificate{{
			CertificateArn: awssdk.String(in.CertificateARN),
		}}
	}
	out, err := s.c.CreateListener(ctx, api)
	if err != nil {
		return nil, s.err(err)
	}

	rec := &ListenerRecord{
		Port: in.Port, Protocol: in.Protocol,
		CertificateARN: in.CertificateARN, TargetGroupARN: in.TargetGroupARN,
	}
	if len(out.Listeners) > 0 {
		rec.ARN = awssdk.ToString(out.Listeners[0].ListenerArn)
	}
	return rec, nil
}

func (s *sdkELBv2) DeleteListener(ctx context.Context, arn string) error {
	_, err := s.c.DeleteListener(ctx, &elbv2.DeleteListenerInput{ListenerArn: awssdk.String(arn)})
	return s.err(err)
}

func (s *sdkELBv2) ListTags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := s.c.DescribeTags(ctx, &elbv2.DescribeTagsInput{ResourceArns: []string{arn}})
	if err != nil {
		return nil, s.err(err)
	}
	tags := map[string]string{}
	for _, d := range out.TagDescriptions {
		if awssdk.ToString(d.ResourceArn) != arn {
			continue
		}
		for _, t := range d.Tags {
			tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
		}
	}
	return tags, nil
}

func (s *sdkELBv2) AddTags(ctx context.Context, arn string, tags map[string]string) error {
	_, err := s.c.AddTags(ctx, &elbv2.AddTagsInput{
		ResourceArns: []string{arn}, Tags: elbTags(tags),
	})
	return s.err(err)
}

func (s *sdkELBv2) RemoveTags(ctx context.Context, arn string, keys []string) error {
	_, err := s.c.RemoveTags(ctx, &elbv2.RemoveTagsInput{
		ResourceArns: []string{arn}, TagKeys: keys,
	})
	return s.err(err)
}

func elbTags(tags map[string]string) []elbv2types.Tag {
	out := make([]elbv2types.Tag, 0, len(tags))
	for _, k := range sortedKeys(tags) {
		out = append(out, elbv2types.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	return out
}

// --- EC2 ------------------------------------------------------------------------------

type sdkEndpointEC2 struct {
	c *ec2.Client
	classifier
}

var _ EndpointEC2API = (*sdkEndpointEC2)(nil)

// EC2 is the one service here with no typed exceptions: every error arrives as a
// generic smithy API error carrying a code.
//
// So the classification has to look at codes, and the thing to avoid is an
// enumeration of them — a hand-maintained restatement of somebody else's set
// drifts from it, silently, in the direction that turns a not-found into a
// failure the provider treats as fatal. EC2's codes are systematically
// structured instead: absence is "Invalid<Thing>.NotFound" and a collision is
// "Invalid<Thing>.Duplicate", across security groups, subnets, VPCs and
// permissions. Matching the *suffix* is therefore matching the shape rather than
// listing the instances, and a service that grows a new object type is covered
// without an edit here.
//
// The one code that does not follow the pattern is "InvalidGroup.NotFound"'s
// permission sibling: revoking a rule that is not there returns success, not an
// error, so nothing has to be classified for it.
func ec2NotFound(err error) bool { return ec2CodeHasSuffix(err, ".NotFound") }

func ec2Exists(err error) bool { return ec2CodeHasSuffix(err, ".Duplicate") }

func ec2CodeHasSuffix(err error, suffix string) bool {
	var api smithy.APIError
	return errors.As(err, &api) && strings.HasSuffix(api.ErrorCode(), suffix)
}

// ec2InUse matches the two codes EC2 uses for "this resource is still
// referenced by something else".
//
// They are handled here rather than in [classify] because they are an EC2-shaped
// fact and putting them in the shared classifier would make them a property of
// every service this package talks to — which is exactly what USOSS-10's
// decision record asks the port that needs them not to do.
//
// The codes do not follow the [ec2NotFound] suffix pattern, so this one is an
// enumeration. That is admitted rather than dressed up: there is no structure to
// derive from, the set is two, and the failure mode of it going stale is a
// teardown reporting a terminal error for a condition that clears on its own —
// which the caller can still recover from by re-running an idempotent delete.
func ec2InUse(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "DependencyViolation", "ResourceInUse":
		return true
	default:
		return false
	}
}

// err classifies an EC2 error.
//
// # The DependencyViolation carry-forward, resolved here
//
// USOSS-10's decision record on retry names one divergence to carry forward: the
// source system's hand-rolled loop treats DependencyViolation and ResourceInUse
// as retryable and the SDK's standard retryer does not, and it says the
// difference "stops being harmless the moment USOSS-11 ports that path". This
// port reached the path first — deleting the security group in front of a load
// balancer — so it is resolved here.
//
// A security group cannot be deleted while a network interface still references
// it, and deleting a load balancer releases its interfaces minutes later. So the
// DependencyViolation on the security group is the ordinary first outcome of a
// teardown, and it really does clear on its own. It maps to [ErrConflict] and
// therefore to [compute.ErrTransient]: "another change to this resource is still
// settling; try again".
//
// [ErrConflict] rather than [ErrThrottled], because a dependency is not a rate.
// Both reach the same sentinel, and the error a caller reads should say which
// thing happened.
//
// This is a classification and not a retry loop, which is the division USOSS-10's
// record draws. An operator who wants the SDK itself to absorb it adds the codes
// through a retry.AddWithErrorCodes option on the EC2 client they build; nothing
// in this package needs to change for that, and the two compose rather than
// multiply.
func (s *sdkEndpointEC2) err(err error) error {
	if ec2InUse(err) {
		return fmt.Errorf("%w: %w", ErrConflict, err)
	}
	return s.classify(err, ec2NotFound, ec2Exists)
}

func (s *sdkEndpointEC2) DescribeSecurityGroup(ctx context.Context, vpcID, name string) (*EndpointSecurityGroupRecord, error) {
	// Filtered on both, because a security group name is unique only within its
	// VPC. Filtering on the name alone would find another VPC's group and hand
	// the provider an identifier a load balancer in this VPC cannot use.
	out, err := s.c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: awssdk.String("group-name"), Values: []string{name}},
			{Name: awssdk.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.SecurityGroups) == 0 {
		// A filtered describe reports absence as an empty list rather than as an
		// error, which is the opposite of the other two services here. The source
		// system's equivalent conflates the two — it treats *any* error as
		// absence and then indexes the list (lambda.go:530-541) — so this is one
		// of the places the distinction has to be made explicitly.
		return nil, fmt.Errorf("%w: security group %q in %q", ErrNoSuchResource, name, vpcID)
	}
	g := out.SecurityGroups[0]
	// The permissions on this response are deliberately not read. They carry
	// neither rule identifiers nor rule tags, which are exactly what ownership
	// and revocation need, so the rule set comes from
	// [sdkEndpointEC2.DescribeSecurityGroupRules] instead.
	return &EndpointSecurityGroupRecord{
		ID:    awssdk.ToString(g.GroupId),
		Name:  awssdk.ToString(g.GroupName),
		VpcID: awssdk.ToString(g.VpcId),
		Tags:  ec2TagMap(g.Tags),
	}, nil
}

// FindSecurityGroups implements [EC2API].
//
// One `tag:<key>` filter per tag, which EC2 ANDs, and **no VPC filter** — the
// absence is the point. See [EC2API.FindSecurityGroups]: a read that has to find
// what this package created earlier cannot be scoped by a VPC that comes from
// configuration the operator may since have edited.
//
// Paginated, because a partial answer here is worse than an error: a teardown
// handed the first page would delete what it saw and report success over what it
// did not.
func (s *sdkEndpointEC2) FindSecurityGroups(ctx context.Context, tags map[string]string) ([]EndpointSecurityGroupRecord, error) {
	if len(tags) == 0 {
		// An unfiltered describe returns every security group in the account, and
		// the only caller of this passes ownership tags. Refusing is the second
		// line: an empty map must never become "all of them".
		return nil, fmt.Errorf("%w: no tags were given, and an unfiltered search would return "+
			"every security group in the region", compute.ErrInvalidSpec)
	}
	filters := make([]ec2types.Filter, 0, len(tags))
	for _, k := range sortedKeys(tags) {
		filters = append(filters, ec2types.Filter{
			Name: awssdk.String("tag:" + k), Values: []string{tags[k]},
		})
	}
	pager := ec2.NewDescribeSecurityGroupsPaginator(s.c, &ec2.DescribeSecurityGroupsInput{
		Filters: filters,
	})
	var out []EndpointSecurityGroupRecord
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, s.err(err)
		}
		for _, g := range page.SecurityGroups {
			out = append(out, EndpointSecurityGroupRecord{
				ID:    awssdk.ToString(g.GroupId),
				Name:  awssdk.ToString(g.GroupName),
				VpcID: awssdk.ToString(g.VpcId),
				Tags:  ec2TagMap(g.Tags),
			})
		}
	}
	return out, nil
}

// UpdateSecurityGroupRuleDescriptions implements [EC2API].
func (s *sdkEndpointEC2) UpdateSecurityGroupRuleDescriptions(ctx context.Context, id string, rules []EndpointSecurityGroupRule) error {
	if len(rules) == 0 {
		return nil
	}
	descriptions := make([]ec2types.SecurityGroupRuleDescription, 0, len(rules))
	for _, r := range rules {
		if r.ID == "" {
			// Unreachable through [ruleDelta], which only ever builds this set
			// from rules it read back. Refused rather than skipped, because EC2
			// would otherwise apply the description to nothing and report
			// success.
			return fmt.Errorf("%w: a rule description update carries no rule identifier",
				compute.ErrFailed)
		}
		descriptions = append(descriptions, ec2types.SecurityGroupRuleDescription{
			SecurityGroupRuleId: awssdk.String(r.ID),
			Description:         awssdk.String(r.Description),
		})
	}
	_, err := s.c.UpdateSecurityGroupRuleDescriptionsIngress(ctx,
		&ec2.UpdateSecurityGroupRuleDescriptionsIngressInput{
			GroupId:                       awssdk.String(id),
			SecurityGroupRuleDescriptions: descriptions,
		})
	return s.err(err)
}

// DescribeSecurityGroupRules implements [EC2API].
//
// Paginated properly. A group with more rules than one page would otherwise
// report a subset, and a convergence loop handed a subset revokes nothing it
// cannot see and re-authorises what it can — which on this path means leaving a
// rule open that a spec removed.
//
// Egress rules are filtered out here rather than above the seam: this package
// never writes one (see the Egress note in compute/network.go), so an egress
// rule in the result is always somebody else's, and letting one reach the
// ingress reconciler would put it in the population a revoke considers.
func (s *sdkEndpointEC2) DescribeSecurityGroupRules(ctx context.Context, groupID string) ([]EndpointSecurityGroupRule, error) {
	pager := ec2.NewDescribeSecurityGroupRulesPaginator(s.c, &ec2.DescribeSecurityGroupRulesInput{
		Filters: []ec2types.Filter{
			{Name: awssdk.String("group-id"), Values: []string{groupID}},
		},
	})
	var out []EndpointSecurityGroupRule
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, s.err(err)
		}
		for _, r := range page.SecurityGroupRules {
			if awssdk.ToBool(r.IsEgress) {
				continue
			}
			out = append(out, securityGroupRule(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return endpointRuleKey(out[i]) < endpointRuleKey(out[j]) })
	return out, nil
}

// securityGroupRule maps one EC2 rule object onto this package's form.
//
// A port *range* is reported with its low port and an annotated description, so
// that a group carrying a rule this provider does not model is visible in a
// rendered artefact. It will not match any desired rule, and the ownership tags
// decide whether it may be revoked — so an annotation cannot change an outcome
// here, unlike the description this package used to read.
func securityGroupRule(r ec2types.SecurityGroupRule) EndpointSecurityGroupRule {
	from := awssdk.ToInt32(r.FromPort)
	to := awssdk.ToInt32(r.ToPort)
	out := EndpointSecurityGroupRule{
		ID:          awssdk.ToString(r.SecurityGroupRuleId),
		Protocol:    awssdk.ToString(r.IpProtocol),
		Port:        int(from),
		CIDRv4:      awssdk.ToString(r.CidrIpv4),
		CIDRv6:      awssdk.ToString(r.CidrIpv6),
		Description: awssdk.ToString(r.Description),
		Tags:        ec2TagMap(r.Tags),
	}
	if r.ReferencedGroupInfo != nil {
		out.PeerGroupID = awssdk.ToString(r.ReferencedGroupInfo.GroupId)
	}
	if from != to {
		out.Description += fmt.Sprintf(" [port range %d-%d, not written by apphub]", from, to)
	}
	return out
}

func (s *sdkEndpointEC2) CreateSecurityGroup(ctx context.Context, in EndpointCreateSecurityGroupRequest) (*EndpointSecurityGroupRecord, error) {
	out, err := s.c.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   awssdk.String(in.Name),
		Description: awssdk.String(in.Description),
		VpcId:       awssdk.String(in.VpcID),
		// Tagged in the create call rather than afterwards. A separate CreateTags
		// leaves a window in which the group exists without an ownership marker,
		// and a reconcile landing in that window would refuse to adopt a group
		// this provider had just made.
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeSecurityGroup,
			Tags:         ec2Tags(in.Tags),
		}},
	})
	if err != nil {
		return nil, s.err(err)
	}
	return &EndpointSecurityGroupRecord{
		ID:    awssdk.ToString(out.GroupId),
		Name:  in.Name,
		VpcID: in.VpcID,
		Tags:  in.Tags,
	}, nil
}

func (s *sdkEndpointEC2) DeleteSecurityGroup(ctx context.Context, id string) error {
	_, err := s.c.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: awssdk.String(id)})
	return s.err(err)
}

func (s *sdkEndpointEC2) AuthorizeSecurityGroupIngress(ctx context.Context, id string, rules []EndpointSecurityGroupRule, tags map[string]string) error {
	perms, err := endpointIPPermissions(rules)
	if err != nil {
		return err
	}
	in := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:       awssdk.String(id),
		IpPermissions: perms,
	}
	if len(tags) > 0 {
		// Tagged in the authorise call rather than afterwards. A separate
		// CreateTags would leave a window in which the rule exists carrying no
		// ownership marker, and a reconcile landing in that window would decline
		// to revoke a rule this provider had just created — which is the
		// fail-open direction.
		in.TagSpecifications = []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeSecurityGroupRule,
			Tags:         ec2Tags(tags),
		}}
	}
	_, err = s.c.AuthorizeSecurityGroupIngress(ctx, in)
	return s.err(err)
}

func (s *sdkEndpointEC2) RevokeSecurityGroupIngress(ctx context.Context, id string, ruleIDs []string) error {
	if len(ruleIDs) == 0 {
		return nil
	}
	// By identifier. Reconstructing an IpPermission asks EC2 to *match* a rule,
	// and a match has more than two outcomes: it can miss the rule that was
	// meant, and it can catch one that was not.
	_, err := s.c.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId:              awssdk.String(id),
		SecurityGroupRuleIds: ruleIDs,
	})
	return s.err(err)
}

// endpointIPPermissions is the inverse of [securityGroupRule]: one permission per rule.
//
// One per rule rather than grouped by protocol and port, deliberately. Grouping
// would be fewer bytes on the wire and it would make a partial failure
// ambiguous: EC2 reports a duplicate against the whole permission, so a grouped
// call cannot say which peer was already authorised. One permission per rule
// keeps a failure attributable to a rule.
func endpointIPPermissions(rules []EndpointSecurityGroupRule) ([]ec2types.IpPermission, error) {
	out := make([]ec2types.IpPermission, 0, len(rules))
	for _, r := range rules {
		port, err := int32Of("Port", r.Port)
		if err != nil {
			return nil, err
		}
		perm := ec2types.IpPermission{
			IpProtocol: awssdk.String(r.Protocol),
			// The same value for both ends, because this package never
			// authorises a range. See [EndpointSecurityGroupRule.Port].
			FromPort: awssdk.Int32(port),
			ToPort:   awssdk.Int32(port),
		}
		desc := awssdk.String(r.Description)
		switch {
		case r.CIDRv4 != "":
			perm.IpRanges = []ec2types.IpRange{{CidrIp: awssdk.String(r.CIDRv4), Description: desc}}
		case r.CIDRv6 != "":
			perm.Ipv6Ranges = []ec2types.Ipv6Range{{CidrIpv6: awssdk.String(r.CIDRv6), Description: desc}}
		case r.PeerGroupID != "":
			perm.UserIdGroupPairs = []ec2types.UserIdGroupPair{{
				GroupId: awssdk.String(r.PeerGroupID), Description: desc,
			}}
		}
		out = append(out, perm)
	}
	return out, nil
}

func (s *sdkEndpointEC2) CreateTags(ctx context.Context, resourceID string, tags map[string]string) error {
	_, err := s.c.CreateTags(ctx, &ec2.CreateTagsInput{
		Resources: []string{resourceID}, Tags: ec2Tags(tags),
	})
	return s.err(err)
}

func (s *sdkEndpointEC2) DeleteTags(ctx context.Context, resourceID string, keys []string) error {
	tags := make([]ec2types.Tag, 0, len(keys))
	for _, k := range keys {
		// Key with no value, which is how EC2 spells "delete this key whatever
		// its value is". Sending the value would delete the tag only if the
		// value still matched, so a tag an operator had edited would survive a
		// convergence that meant to remove it.
		tags = append(tags, ec2types.Tag{Key: awssdk.String(k)})
	}
	_, err := s.c.DeleteTags(ctx, &ec2.DeleteTagsInput{
		Resources: []string{resourceID}, Tags: tags,
	})
	return s.err(err)
}

func (s *sdkEndpointEC2) DescribeSubnets(ctx context.Context, ids []string) ([]EndpointSubnetRecord, error) {
	if len(ids) == 0 {
		// An empty SubnetIds list means "every subnet in the account" to EC2,
		// which is the opposite of what a caller asking about no subnets means.
		// The provider never calls this way; refusing is the second line.
		return nil, fmt.Errorf("%w: no subnets were named, and an empty list would describe "+
			"every subnet in the account", compute.ErrInvalidSpec)
	}
	out, err := s.c.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: ids})
	if err != nil {
		return nil, s.err(err)
	}
	recs := make([]EndpointSubnetRecord, 0, len(out.Subnets))
	for _, sn := range out.Subnets {
		recs = append(recs, EndpointSubnetRecord{
			ID:               awssdk.ToString(sn.SubnetId),
			VpcID:            awssdk.ToString(sn.VpcId),
			AvailabilityZone: awssdk.ToString(sn.AvailabilityZone),
		})
	}
	return recs, nil
}

func ec2TagMap(tags []ec2types.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		out[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return out
}
