// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import "context"

// This file declares the EventBridge Scheduler half of the ECS scheduled-job
// port. The provider owns policy; the substrate owns one AWS API call per method.

// ScheduleGroupRecord is the substrate's stored EventBridge Scheduler group.
type ScheduleGroupRecord struct {
	Name string
	ARN  string
	Tags map[string]string
}

// ScheduleRecord is the substrate's stored EventBridge schedule.
type ScheduleRecord struct {
	GroupName  string
	Name       string
	ARN        string
	Expression string
	Timezone   string
	State      string
	Target     ScheduleTarget
}

// ScheduleTarget is the ECS task target attached to a schedule.
type ScheduleTarget struct {
	ClusterARN        string
	RoleARN           string
	TaskDefinitionARN string
	TaskCount         int
	SubnetIDs         []string
	SecurityGroupIDs  []string
	AssignPublicIP    bool
}

// ScheduleRequest creates or updates one schedule.
type ScheduleRequest struct {
	GroupName  string
	Name       string
	Expression string
	Timezone   string
	Paused     bool
	Target     ScheduleTarget
}

// ScheduleGroupRequest creates one schedule group with ownership tags.
type ScheduleGroupRequest struct {
	Name string
	Tags map[string]string
}

const (
	scheduleStateEnabled  = "ENABLED"
	scheduleStateDisabled = "DISABLED"
)

// SchedulerAPI is the EventBridge Scheduler seam used by the scheduled-job port.
type SchedulerAPI interface {
	CreateScheduleGroup(ctx context.Context, in ScheduleGroupRequest) (*ScheduleGroupRecord, error)
	DescribeScheduleGroup(ctx context.Context, name string) (*ScheduleGroupRecord, error)
	DeleteScheduleGroup(ctx context.Context, name string) error
	TagScheduleGroup(ctx context.Context, arn string, tags map[string]string) error
	UntagScheduleGroup(ctx context.Context, arn string, keys []string) error

	CreateSchedule(ctx context.Context, in ScheduleRequest) (*ScheduleRecord, error)
	UpdateSchedule(ctx context.Context, in ScheduleRequest) (*ScheduleRecord, error)
	DescribeSchedule(ctx context.Context, group, name string) (*ScheduleRecord, error)
	DeleteSchedule(ctx context.Context, group, name string) error
}
