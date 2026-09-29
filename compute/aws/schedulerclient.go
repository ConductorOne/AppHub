// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	schedulertypes "github.com/aws/aws-sdk-go-v2/service/scheduler/types"
)

// UseScheduler attaches a real EventBridge Scheduler client to a substrate.
func (s *Substrate) UseScheduler(client *scheduler.Client) error {
	if client == nil {
		return fmt.Errorf("aws: a nil Scheduler client cannot back the scheduled-job port")
	}
	s.Scheduler = &sdkScheduler{c: client}
	return nil
}

type sdkScheduler struct {
	c *scheduler.Client
	classifier
}

var _ SchedulerAPI = (*sdkScheduler)(nil)

func schedulerNotFound(err error) bool { return isType[*schedulertypes.ResourceNotFoundException](err) }

func (s *sdkScheduler) err(err error) error { return s.classify(err, schedulerNotFound, nil) }

func (s *sdkScheduler) CreateScheduleGroup(ctx context.Context, in ScheduleGroupRequest) (*ScheduleGroupRecord, error) {
	out, err := s.c.CreateScheduleGroup(ctx, &scheduler.CreateScheduleGroupInput{
		Name: awssdk.String(in.Name),
		Tags: schedulerTags(in.Tags),
	})
	if err != nil {
		return nil, s.err(err)
	}
	return &ScheduleGroupRecord{Name: in.Name, ARN: awssdk.ToString(out.ScheduleGroupArn), Tags: copyTags(in.Tags)}, nil
}

func (s *sdkScheduler) DescribeScheduleGroup(ctx context.Context, name string) (*ScheduleGroupRecord, error) {
	out, err := s.c.GetScheduleGroup(ctx, &scheduler.GetScheduleGroupInput{Name: awssdk.String(name)})
	if err != nil {
		return nil, s.err(err)
	}
	arn := awssdk.ToString(out.Arn)
	tags, err := s.listTags(ctx, arn)
	if err != nil {
		return nil, err
	}
	return &ScheduleGroupRecord{Name: awssdk.ToString(out.Name), ARN: arn, Tags: tags}, nil
}

func (s *sdkScheduler) DeleteScheduleGroup(ctx context.Context, name string) error {
	_, err := s.c.DeleteScheduleGroup(ctx, &scheduler.DeleteScheduleGroupInput{Name: awssdk.String(name)})
	return s.err(err)
}

func (s *sdkScheduler) TagScheduleGroup(ctx context.Context, arn string, tags map[string]string) error {
	_, err := s.c.TagResource(ctx, &scheduler.TagResourceInput{
		ResourceArn: awssdk.String(arn),
		Tags:        schedulerTags(tags),
	})
	return s.err(err)
}

func (s *sdkScheduler) UntagScheduleGroup(ctx context.Context, arn string, keys []string) error {
	_, err := s.c.UntagResource(ctx, &scheduler.UntagResourceInput{
		ResourceArn: awssdk.String(arn),
		TagKeys:     keys,
	})
	return s.err(err)
}

func (s *sdkScheduler) CreateSchedule(ctx context.Context, in ScheduleRequest) (*ScheduleRecord, error) {
	out, err := s.c.CreateSchedule(ctx, createScheduleInput(in))
	if err != nil {
		return nil, s.err(err)
	}
	rec := scheduleRecordFromRequest(in)
	rec.ARN = awssdk.ToString(out.ScheduleArn)
	return rec, nil
}

func (s *sdkScheduler) UpdateSchedule(ctx context.Context, in ScheduleRequest) (*ScheduleRecord, error) {
	_, err := s.c.UpdateSchedule(ctx, updateScheduleInput(in))
	if err != nil {
		return nil, s.err(err)
	}
	return s.DescribeSchedule(ctx, in.GroupName, in.Name)
}

func (s *sdkScheduler) DescribeSchedule(ctx context.Context, group, name string) (*ScheduleRecord, error) {
	out, err := s.c.GetSchedule(ctx, &scheduler.GetScheduleInput{
		GroupName: awssdk.String(group),
		Name:      awssdk.String(name),
	})
	if err != nil {
		return nil, s.err(err)
	}
	rec := &ScheduleRecord{
		GroupName:  awssdk.ToString(out.GroupName),
		Name:       awssdk.ToString(out.Name),
		ARN:        awssdk.ToString(out.Arn),
		Expression: awssdk.ToString(out.ScheduleExpression),
		Timezone:   awssdk.ToString(out.ScheduleExpressionTimezone),
		State:      string(out.State),
	}
	if out.Target != nil {
		rec.Target.RoleARN = awssdk.ToString(out.Target.RoleArn)
		rec.Target.ClusterARN = awssdk.ToString(out.Target.Arn)
		if ecs := out.Target.EcsParameters; ecs != nil {
			rec.Target.TaskDefinitionARN = awssdk.ToString(ecs.TaskDefinitionArn)
			rec.Target.TaskCount = int(awssdk.ToInt32(ecs.TaskCount))
			if net := ecs.NetworkConfiguration; net != nil && net.AwsvpcConfiguration != nil {
				rec.Target.SubnetIDs = append([]string(nil), net.AwsvpcConfiguration.Subnets...)
				rec.Target.SecurityGroupIDs = append([]string(nil), net.AwsvpcConfiguration.SecurityGroups...)
				rec.Target.AssignPublicIP = net.AwsvpcConfiguration.AssignPublicIp == schedulertypes.AssignPublicIpEnabled
			}
		}
	}
	return rec, nil
}

func (s *sdkScheduler) DeleteSchedule(ctx context.Context, group, name string) error {
	_, err := s.c.DeleteSchedule(ctx, &scheduler.DeleteScheduleInput{
		GroupName: awssdk.String(group),
		Name:      awssdk.String(name),
	})
	return s.err(err)
}

func (s *sdkScheduler) listTags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := s.c.ListTagsForResource(ctx, &scheduler.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
	if err != nil {
		return nil, s.err(err)
	}
	return schedulerTagsMap(out.Tags), nil
}

func createScheduleInput(in ScheduleRequest) *scheduler.CreateScheduleInput {
	return &scheduler.CreateScheduleInput{
		GroupName:                  awssdk.String(in.GroupName),
		Name:                       awssdk.String(in.Name),
		ScheduleExpression:         awssdk.String(in.Expression),
		ScheduleExpressionTimezone: awssdk.String(in.Timezone),
		State:                      schedulerState(in.Paused),
		FlexibleTimeWindow:         &schedulertypes.FlexibleTimeWindow{Mode: schedulertypes.FlexibleTimeWindowModeOff},
		Target:                     schedulerTarget(in.Target),
	}
}

func updateScheduleInput(in ScheduleRequest) *scheduler.UpdateScheduleInput {
	return &scheduler.UpdateScheduleInput{
		GroupName:                  awssdk.String(in.GroupName),
		Name:                       awssdk.String(in.Name),
		ScheduleExpression:         awssdk.String(in.Expression),
		ScheduleExpressionTimezone: awssdk.String(in.Timezone),
		State:                      schedulerState(in.Paused),
		FlexibleTimeWindow:         &schedulertypes.FlexibleTimeWindow{Mode: schedulertypes.FlexibleTimeWindowModeOff},
		Target:                     schedulerTarget(in.Target),
	}
}

func schedulerState(paused bool) schedulertypes.ScheduleState {
	if paused {
		return schedulertypes.ScheduleStateDisabled
	}
	return schedulertypes.ScheduleStateEnabled
}

func schedulerTarget(in ScheduleTarget) *schedulertypes.Target {
	count := int32(in.TaskCount) //nolint:gosec // scheduled jobs set the ECS task count internally to 1.
	assign := schedulertypes.AssignPublicIpDisabled
	if in.AssignPublicIP {
		assign = schedulertypes.AssignPublicIpEnabled
	}
	return &schedulertypes.Target{
		Arn:     awssdk.String(in.ClusterARN),
		RoleArn: awssdk.String(in.RoleARN),
		EcsParameters: &schedulertypes.EcsParameters{
			TaskDefinitionArn: awssdk.String(in.TaskDefinitionARN),
			TaskCount:         awssdk.Int32(count),
			LaunchType:        schedulertypes.LaunchTypeFargate,
			NetworkConfiguration: &schedulertypes.NetworkConfiguration{AwsvpcConfiguration: &schedulertypes.AwsVpcConfiguration{
				Subnets:        append([]string(nil), in.SubnetIDs...),
				SecurityGroups: append([]string(nil), in.SecurityGroupIDs...),
				AssignPublicIp: assign,
			}},
		},
	}
}

func schedulerTags(tags map[string]string) []schedulertypes.Tag {
	keys := sortedKeys(tags)
	out := make([]schedulertypes.Tag, 0, len(keys))
	for _, key := range keys {
		out = append(out, schedulertypes.Tag{Key: awssdk.String(key), Value: awssdk.String(tags[key])})
	}
	return out
}

func schedulerTagsMap(tags []schedulertypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[awssdk.ToString(tag.Key)] = awssdk.ToString(tag.Value)
	}
	return out
}
