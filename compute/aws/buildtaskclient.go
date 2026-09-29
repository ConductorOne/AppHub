// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/conductorone/apphub/compute"
)

// This file is the SDK half of the build-task surface. Like awssdk.go and
// ecsclient.go it holds no policy: every method is a translation of one API call
// and one error, so everything above [Substrate] runs the same against an
// account or against a fake.

// NewSDKBuildTaskRunner builds the hosted [BuildRunner] and its clients.
//
// Clients are constructed here rather than passed in, which is the opposite of
// [Substrate.UseECS]'s rule that "where credentials come from is the composition
// root's decision" -- and the exception has a reason. The composition root is
// not permitted to import the AWS SDK (see internal/boundary's aws-sdk-confined
// rule), so a constructor it could call with a client would be a constructor it
// could not build an argument for. The region is the operator's, from the same
// configuration everything else here reads.
//
// It contacts nothing. [BuildTaskRunner.Validate] is what checks the substrate,
// and NewFromConfig calls it.
func NewSDKBuildTaskRunner(ctx context.Context, cfg Config, contextRoot string, leaser SlotLeaser) (*BuildTaskRunner, error) {
	if cfg.Build == nil || cfg.Build.Task == nil {
		return nil, errors.New("aws: a hosted build needs build.task configuration")
	}
	loaded, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, errors.New("aws: the build task runner could not resolve AWS configuration")
	}
	tasks := &sdkBuildTasks{c: ecs.NewFromConfig(loaded)}
	logs := &sdkBuildLogs{c: cloudwatchlogs.NewFromConfig(loaded)}
	return NewBuildTaskRunner(cfg, contextRoot, tasks, logs, leaser)
}

// --- tasks ---------------------------------------------------------------------

type sdkBuildTasks struct {
	c *ecs.Client
	classifier
}

var _ BuildTaskAPI = (*sdkBuildTasks)(nil)

func (s *sdkBuildTasks) err(err error) error {
	return s.classify(err, ecsNotFound, func(error) bool { return false })
}

// RunTask launches exactly one task.
//
// AssignPublicIp is DISABLED and is not configurable. A build task with a public
// address is reachable from the internet subject only to its security groups,
// and a build is the one workload in this system that runs code nobody in this
// system wrote.
func (s *sdkBuildTasks) RunTask(ctx context.Context, in BuildTaskRequest) (string, error) {
	out, err := s.c.RunTask(ctx, &ecs.RunTaskInput{
		Cluster:        awssdk.String(in.Cluster),
		TaskDefinition: awssdk.String(in.TaskDefinition),
		LaunchType:     ecstypes.LaunchTypeFargate,
		Count:          awssdk.Int32(1),
		Tags: []ecstypes.Tag{{
			Key:   awssdk.String("apphub:build-task"),
			Value: awssdk.String("true"),
		}},
		StartedBy: awssdk.String(in.StartedBy),
		NetworkConfiguration: &ecstypes.NetworkConfiguration{
			AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{
				Subnets:        in.Subnets,
				SecurityGroups: in.SecurityGroups,
				AssignPublicIp: ecstypes.AssignPublicIpDisabled,
			},
		},
		Overrides: &ecstypes.TaskOverride{
			ContainerOverrides: []ecstypes.ContainerOverride{{
				Name:    awssdk.String(in.ContainerName),
				Command: in.Command,
			}},
		},
	})
	if err != nil {
		return "", s.err(err)
	}
	// RunTask reports a placement refusal in Failures with a 200, so a caller
	// that only checked err would wait out its deadline on a task that never
	// existed.
	if len(out.Tasks) == 0 {
		if len(out.Failures) > 0 {
			return "", fmt.Errorf("%w: the build task was not placed: %s", compute.ErrFailed,
				awssdk.ToString(out.Failures[0].Reason))
		}
		return "", fmt.Errorf("%w: the build task was not placed", compute.ErrFailed)
	}
	return awssdk.ToString(out.Tasks[0].TaskArn), nil
}

// ListBuildTasks reconciles a slot before it is reused. A new task definition
// revision retains the same EFS access point, so the query covers the family,
// not just the configured revision. ECS changes desiredStatus to STOPPED before
// lastStatus reaches STOPPED; both desired-status sets must be inspected.
func (s *sdkBuildTasks) ListBuildTasks(ctx context.Context, cluster, taskDefinition string) ([]string, error) {
	family := taskDefinition
	if i := strings.LastIndexByte(family, '/'); i >= 0 {
		family = family[i+1:]
	}
	if i := strings.LastIndexByte(family, ':'); i >= 0 {
		family = family[:i]
	}
	if family == "" {
		return nil, fmt.Errorf("%w: a build task definition needs a family", compute.ErrInvalidSpec)
	}

	var active []string
	for _, desired := range []ecstypes.DesiredStatus{
		ecstypes.DesiredStatusRunning,
		ecstypes.DesiredStatusStopped,
	} {
		pages := ecs.NewListTasksPaginator(s.c, &ecs.ListTasksInput{
			Cluster:       awssdk.String(cluster),
			Family:        awssdk.String(family),
			DesiredStatus: desired,
		})
		for pages.HasMorePages() {
			page, err := pages.NextPage(ctx)
			if err != nil {
				return nil, s.err(err)
			}
			if len(page.TaskArns) == 0 {
				continue
			}
			out, err := s.c.DescribeTasks(ctx, &ecs.DescribeTasksInput{
				Cluster: awssdk.String(cluster),
				Tasks:   page.TaskArns,
			})
			if err != nil {
				return nil, s.err(err)
			}
			if len(out.Failures) > 0 || len(out.Tasks) != len(page.TaskArns) {
				return nil, fmt.Errorf("%w: ECS could not describe every build task in slot family", compute.ErrFailed)
			}
			for _, task := range out.Tasks {
				if awssdk.ToString(task.LastStatus) == "STOPPED" {
					continue
				}
				arn := awssdk.ToString(task.TaskArn)
				if arn == "" {
					return nil, fmt.Errorf("%w: ECS returned a build task with no ARN", compute.ErrFailed)
				}
				// A task can cross the desired-status sets during this scan.
				// Report it once rather than asking cleanup to stop it twice.
				seen := false
				for _, previous := range active {
					if previous == arn {
						seen = true
						break
					}
				}
				if !seen {
					active = append(active, arn)
				}
			}
		}
	}
	return active, nil
}

func (s *sdkBuildTasks) DescribeTask(ctx context.Context, cluster, taskARN string) (*BuildTaskRecord, error) {
	out, err := s.c.DescribeTasks(ctx, &ecs.DescribeTasksInput{
		Cluster: awssdk.String(cluster),
		Tasks:   []string{taskARN},
	})
	if err != nil {
		return nil, s.err(err)
	}
	if len(out.Tasks) == 0 {
		return nil, fmt.Errorf("%w: task %q", ErrNoSuchResource, taskARN)
	}
	task := out.Tasks[0]
	record := &BuildTaskRecord{
		ARN:           awssdk.ToString(task.TaskArn),
		LastStatus:    awssdk.ToString(task.LastStatus),
		StopCode:      string(task.StopCode),
		StoppedReason: awssdk.ToString(task.StoppedReason),
	}
	for _, container := range task.Containers {
		status := BuildTaskContainerStatus{
			Name:   awssdk.ToString(container.Name),
			Reason: awssdk.ToString(container.Reason),
		}
		if container.ExitCode != nil {
			code := int(*container.ExitCode)
			status.ExitCode = &code
		}
		record.Containers = append(record.Containers, status)
	}
	return record, nil
}

// StopTask asks ECS to stop a task, and treats an already-gone one as done.
//
// Cleanup calls this on paths where the task's state is unknown -- a cancelled
// build, a deadline, a failed describe -- so "it was not there" is the outcome
// wanted, not an error to report over whatever actually went wrong.
func (s *sdkBuildTasks) StopTask(ctx context.Context, cluster, taskARN, reason string) error {
	_, err := s.c.StopTask(ctx, &ecs.StopTaskInput{
		Cluster: awssdk.String(cluster),
		Task:    awssdk.String(taskARN),
		Reason:  awssdk.String(reason),
	})
	if err != nil {
		mapped := s.err(err)
		if errors.Is(mapped, ErrNoSuchResource) {
			return nil
		}
		return mapped
	}
	return nil
}

func (s *sdkBuildTasks) DescribeBuildTaskDefinition(ctx context.Context, taskDefinition string) (*BuildTaskDefinition, error) {
	out, err := s.c.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: awssdk.String(taskDefinition),
	})
	if err != nil {
		return nil, s.err(err)
	}
	td := out.TaskDefinition
	if td == nil {
		return nil, fmt.Errorf("%w: task definition %q", ErrNoSuchResource, taskDefinition)
	}
	def := &BuildTaskDefinition{
		ARN:         awssdk.ToString(td.TaskDefinitionArn),
		TaskRoleARN: awssdk.ToString(td.TaskRoleArn),
		NetworkMode: string(td.NetworkMode),
	}
	if td.EphemeralStorage != nil {
		def.EphemeralStorageGiB = int(td.EphemeralStorage.SizeInGiB)
	}
	for _, container := range td.ContainerDefinitions {
		def.Containers = append(def.Containers, BuildTaskDefinitionContainer{
			Name:  awssdk.ToString(container.Name),
			Image: awssdk.ToString(container.Image),
		})
	}
	for _, volume := range td.Volumes {
		mapped := BuildTaskVolume{Name: awssdk.ToString(volume.Name)}
		if efs := volume.EfsVolumeConfiguration; efs != nil {
			mapped.FileSystemID = awssdk.ToString(efs.FileSystemId)
			mapped.TransitEncryption = efs.TransitEncryption == ecstypes.EFSTransitEncryptionEnabled
			if auth := efs.AuthorizationConfig; auth != nil {
				mapped.AccessPointID = awssdk.ToString(auth.AccessPointId)
			}
		}
		def.Volumes = append(def.Volumes, mapped)
	}
	return def, nil
}

// --- logs ----------------------------------------------------------------------

type sdkBuildLogs struct {
	c *cloudwatchlogs.Client
	classifier
}

var _ BuildLogAPI = (*sdkBuildLogs)(nil)

// GetLogEvents reads one stream forward.
//
// A missing stream is reported as no events rather than as an error: awslogs
// creates the stream when the container first writes to it, so every build has a
// window at the start where the stream legitimately does not exist and the task
// is fine.
func (s *sdkBuildLogs) GetLogEvents(ctx context.Context, group, stream, token string) ([]BuildLogEvent, string, error) {
	in := &cloudwatchlogs.GetLogEventsInput{
		LogGroupName:  awssdk.String(group),
		LogStreamName: awssdk.String(stream),
		StartFromHead: awssdk.Bool(true),
	}
	if token != "" {
		in.NextToken = awssdk.String(token)
	}
	out, err := s.c.GetLogEvents(ctx, in)
	if err != nil {
		if isType[*cwltypes.ResourceNotFoundException](err) {
			return nil, token, nil
		}
		return nil, token, s.classify(err, func(error) bool { return false }, func(error) bool { return false })
	}
	events := make([]BuildLogEvent, 0, len(out.Events))
	for _, event := range out.Events {
		events = append(events, BuildLogEvent{
			Timestamp: time.UnixMilli(awssdk.ToInt64(event.Timestamp)).UTC(),
			Message:   awssdk.ToString(event.Message),
		})
	}
	return events, awssdk.ToString(out.NextForwardToken), nil
}
