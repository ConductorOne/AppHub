// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

const (
	componentScheduledJob  = "scheduled-job"
	componentSchedulerRole = "scheduler-runner-role"

	maxScheduleName       = 64
	scheduledJobNameInfix = "job-"
	schedulerRoleInfix    = "sched-"
	policySchedulerRun    = policyPrefix + "scheduler-run"
)

var (
	scheduleNameGrammar = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	scheduleCronField   = regexp.MustCompile(`^[0-9*,/-]+$`)
	scheduleRateExpr    = regexp.MustCompile(`^rate\(([1-9][0-9]*) (minute|minutes|hour|hours|day|days)\)$`)
)

func (p *Provider) scheduleName(logical string) (string, error) {
	prefix := ""
	if p.cfg.Container != nil {
		prefix = p.cfg.Container.NamePrefix
	}
	name, err := sanitize(prefix, logical, maxScheduleName)
	if err != nil {
		return "", fmt.Errorf("%w (check Config.Container.NamePrefix)", err)
	}
	if !scheduleNameGrammar.MatchString(name) {
		return "", fmt.Errorf("%w: the logical name %q derives the EventBridge Scheduler name %q, which admits letters, digits, hyphens, underscores and periods", compute.ErrInvalidSpec, logical, name)
	}
	return name, nil
}

func (p *Provider) scheduledTaskName(scheduleName string) (string, error) {
	name, err := sanitize(scheduledJobNameInfix, scheduleName, maxECSTaskFamily)
	if err != nil {
		return "", err
	}
	if !ecsTaskFamily.MatchString(name) {
		return "", fmt.Errorf("%w: %q is not a legal ECS task-definition family", compute.ErrInvalidSpec, name)
	}
	return name, nil
}

func (p *Provider) schedulerRoleName(scheduleName string) (string, error) {
	name, err := sanitize(schedulerRoleInfix, scheduleName, maxIAMRoleName)
	if err != nil {
		return "", err
	}
	if !iamRoleName.MatchString(name) {
		return "", fmt.Errorf("%w: %q is not a legal IAM role name", compute.ErrInvalidSpec, name)
	}
	return name, nil
}

func validateAWSSchedule(s compute.Schedule) (string, string, error) {
	expr := strings.TrimSpace(s.Expression)
	if expr == "" {
		return "", "", fmt.Errorf("%w: a scheduled job needs a schedule expression", compute.ErrInvalidSpec)
	}
	var out string
	if scheduleRateExpr.MatchString(expr) {
		out = expr
	} else {
		fields := strings.Fields(expr)
		if len(fields) != 5 {
			return "", "", fmt.Errorf("%w: cron expression %q has %d fields; the interface pins five-field POSIX cron", compute.ErrInvalidSpec, expr, len(fields))
		}
		for i, field := range fields {
			if !scheduleCronField.MatchString(field) {
				return "", "", fmt.Errorf("%w: cron expression %q field %d (%q) is not a five-field POSIX cron field", compute.ErrInvalidSpec, expr, i+1, field)
			}
		}
		days, err := eventBridgeDays(expr, fields[2], fields[4])
		if err != nil {
			return "", "", err
		}
		fields[2], fields[4] = days[0], days[1]
		out = "cron(" + strings.Join(fields, " ") + " *)"
	}
	tz := s.Timezone
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return "", "", fmt.Errorf("%w: %q is not an IANA timezone name", compute.ErrInvalidSpec, tz)
	}
	return out, tz, nil
}

// eventBridgeDays renders POSIX day-of-month and day-of-week fields in
// EventBridge's dialect, which differs in two ways that each break a schedule:
// exactly one of the two fields must be "?", and days of the week count from 1
// (Sunday) where POSIX counts from 0. Numbers are rendered as day names so the
// translation reads back without ambiguity.
//
// POSIX runs a job when either restricted field matches. EventBridge cannot say
// that, so an expression restricting both is refused rather than narrowed.
func eventBridgeDays(expr, dom, dow string) ([2]string, error) {
	if dow == "*" {
		return [2]string{dom, "?"}, nil
	}
	if dom != "*" {
		return [2]string{}, fmt.Errorf("%w: cron expression %q restricts both day of month and day of week, "+
			"which POSIX runs when either matches and EventBridge cannot express; restrict one of them",
			compute.ErrInvalidSpec, expr)
	}
	items := strings.Split(dow, ",")
	for i, item := range items {
		lo, hi, isRange := strings.Cut(item, "-")
		first, okFirst := posixWeekday(lo)
		if !isRange {
			if !okFirst {
				return [2]string{}, invalidWeekday(expr, item)
			}
			items[i] = first
			continue
		}
		last, okLast := posixWeekday(hi)
		if !okFirst || !okLast || lo > hi {
			return [2]string{}, invalidWeekday(expr, item)
		}
		items[i] = first + "-" + last
	}
	return [2]string{"?", strings.Join(items, ",")}, nil
}

var weekdayNames = []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}

// posixWeekday names a single POSIX day-of-week digit, 0 (Sunday) to 6.
func posixWeekday(field string) (string, bool) {
	if len(field) != 1 || field[0] < '0' || field[0] > '6' {
		return "", false
	}
	return weekdayNames[field[0]-'0'], true
}

func invalidWeekday(expr, item string) error {
	return fmt.Errorf("%w: cron expression %q has day of week %q; use *, a day 0-6 (0 is Sunday), "+
		"an ascending range such as 1-5, or a comma list of those. Steps and 7 are not supported",
		compute.ErrInvalidSpec, expr, item)
}

// posixDays reverses [eventBridgeDays].
func posixDays(dom, dow string) (string, string, error) {
	if dom == "?" {
		dom = "*"
	}
	if dow == "?" || dow == "*" {
		return dom, "*", nil
	}
	items := strings.Split(dow, ",")
	for i, item := range items {
		ends := strings.Split(item, "-")
		for j, name := range ends {
			day := slices.Index(weekdayNames, name)
			if day < 0 {
				return "", "", fmt.Errorf("day of week %q is not one this provider writes", item)
			}
			ends[j] = strconv.Itoa(day)
		}
		items[i] = strings.Join(ends, "-")
	}
	return dom, strings.Join(items, ","), nil
}

func scheduleFromAWS(expr, tz, state string) (compute.Schedule, error) {
	out := compute.Schedule{Expression: strings.TrimSpace(expr)}
	if strings.HasPrefix(out.Expression, "cron(") && strings.HasSuffix(out.Expression, ")") {
		inner := strings.TrimSuffix(strings.TrimPrefix(out.Expression, "cron("), ")")
		fields := strings.Fields(inner)
		if len(fields) != 6 || fields[5] != "*" {
			return compute.Schedule{}, fmt.Errorf("%w: owned schedule has expression %q, which is not the EventBridge translation of a five-field cron expression", compute.ErrFailed, expr)
		}
		dom, dow, err := posixDays(fields[2], fields[4])
		if err != nil {
			return compute.Schedule{}, fmt.Errorf("%w: owned schedule has expression %q: %w", compute.ErrFailed, expr, err)
		}
		fields[2], fields[4] = dom, dow
		out.Expression = strings.Join(fields[:5], " ")
	}
	if !scheduleRateExpr.MatchString(out.Expression) {
		fields := strings.Fields(out.Expression)
		if len(fields) != 5 {
			return compute.Schedule{}, fmt.Errorf("%w: owned schedule has expression %q, which is not in the interface grammar", compute.ErrFailed, expr)
		}
	}
	if tz != "" && tz != "UTC" {
		out.Timezone = tz
	}
	out.Paused = state == scheduleStateDisabled
	return out, nil
}

func (c *containerRuntime) EnsureScheduledJob(ctx context.Context, spec compute.ScheduledJobSpec) (*compute.ScheduledJobStatus, error) {
	if c.p.sub.Scheduler == nil || !c.p.caps.Has(compute.CapScheduledJob) {
		return nil, c.p.unsupported(compute.CapScheduledJob, "no EventBridge Scheduler substrate is configured")
	}
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(spec.Image)) == "" {
		return nil, fmt.Errorf("%w: a scheduled job needs an image", compute.ErrInvalidSpec)
	}
	expr, tz, err := validateAWSSchedule(spec.Schedule)
	if err != nil {
		return nil, err
	}
	cpuUnits, memoryMiB, _, err := taskSize(spec.Resources)
	if err != nil {
		return nil, err
	}
	pc, err := c.p.cfg.placement(spec.Placement)
	if err != nil {
		return nil, err
	}
	name, err := c.p.scheduleName(spec.Name)
	if err != nil {
		return nil, err
	}
	taskName, err := c.p.scheduledTaskName(name)
	if err != nil {
		return nil, err
	}
	ref := c.p.ref(compute.KindScheduledJob, name)
	taskRoleName, taskRoleARN, err := c.p.resolveIdentity(ctx, spec.Identity)
	if err != nil {
		return nil, err
	}
	secretRefs, err := c.p.resolveSecrets(ctx, pc.Name, spec.Secrets)
	if err != nil {
		return nil, err
	}
	if err := c.p.checkScheduleGroupAvailable(ctx, name, ref); err != nil {
		return nil, err
	}
	if err := c.p.reconcileWorkloadCapabilities(ctx, taskRoleName, pc, spec.Capabilities, false); err != nil {
		return nil, err
	}
	execRoleARN, err := c.p.ensureExecutionRole(ctx, taskName, pc, spec.Image, secretRefs, spec.Labels)
	if err != nil {
		return nil, err
	}
	securityGroups := append([]string(nil), pc.SecurityGroups...)
	if len(spec.Ingress) > 0 {
		groupID, err := c.p.ensureServiceSecurityGroup(ctx, taskName, pc, spec.Ingress, spec.Labels)
		if err != nil {
			return nil, err
		}
		securityGroups = append([]string{groupID}, securityGroups...)
	}
	tags := ownershipTags(name, componentScheduledJob, spec.Labels)
	group, err := c.p.ensureScheduleGroup(ctx, name, tags)
	if err != nil {
		return nil, err
	}
	taskDefARN, err := c.p.sub.ECS.RegisterTaskDefinition(ctx, TaskDefinitionRequest{
		Family:           taskName,
		CPUUnits:         cpuUnits,
		MemoryMiB:        memoryMiB,
		ExecutionRoleARN: execRoleARN,
		TaskRoleARN:      taskRoleARN,
		Container:        c.p.scheduledJobContainerRequest(taskName, spec, secretRefs),
		Tags:             tags,
	})
	if err != nil {
		return nil, c.p.substrateError(err)
	}
	schedulerRoleARN, err := c.p.ensureSchedulerRole(ctx, name, taskDefARN, execRoleARN, taskRoleARN, spec.Labels)
	if err != nil {
		return nil, err
	}
	req := ScheduleRequest{
		GroupName:  group.Name,
		Name:       name,
		Expression: expr,
		Timezone:   tz,
		Paused:     spec.Schedule.Paused,
		Target: ScheduleTarget{
			ClusterARN:        pc.ClusterARN,
			RoleARN:           schedulerRoleARN,
			TaskDefinitionARN: taskDefARN,
			TaskCount:         1,
			SubnetIDs:         pc.Subnets,
			SecurityGroupIDs:  securityGroups,
			AssignPublicIP:    pc.AssignPublicIP,
		},
	}
	if _, err := c.p.sub.Scheduler.DescribeSchedule(ctx, name, name); errors.Is(err, ErrNoSuchResource) {
		if _, err := c.p.sub.Scheduler.CreateSchedule(ctx, req); err != nil {
			return nil, c.p.substrateError(err)
		}
	} else if err != nil {
		return nil, c.p.substrateError(err)
	} else if _, err := c.p.sub.Scheduler.UpdateSchedule(ctx, req); err != nil {
		return nil, c.p.substrateError(err)
	}
	return c.DescribeScheduledJob(ctx, ref)
}

func (p *Provider) checkScheduleGroupAvailable(ctx context.Context, name string, ref compute.Ref) error {
	group, err := p.sub.Scheduler.DescribeScheduleGroup(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		return nil
	}
	if err != nil {
		return p.substrateError(err)
	}
	if group.Tags[tagManagedBy] != managedByValue || group.Tags[tagComponent] != componentScheduledJob {
		return fmt.Errorf("%w: %s names an EventBridge Scheduler group this provider does not own", compute.ErrNotOwned, ref)
	}
	return nil
}

func (p *Provider) ensureScheduleGroup(ctx context.Context, name string, tags map[string]string) (*ScheduleGroupRecord, error) {
	group, err := p.sub.Scheduler.DescribeScheduleGroup(ctx, name)
	switch {
	case errors.Is(err, ErrNoSuchResource):
		group, err = p.sub.Scheduler.CreateScheduleGroup(ctx, ScheduleGroupRequest{Name: name, Tags: tags})
		if err != nil {
			return nil, p.substrateError(err)
		}
		return group, nil
	case err != nil:
		return nil, p.substrateError(err)
	}
	if group.Tags[tagManagedBy] != managedByValue || group.Tags[tagComponent] != componentScheduledJob {
		return nil, fmt.Errorf("%w: the EventBridge Scheduler group %q is not one this provider created", compute.ErrNotOwned, name)
	}
	put, remove := tagDelta(group.Tags, tags)
	if len(remove) > 0 {
		if err := p.sub.Scheduler.UntagScheduleGroup(ctx, group.ARN, remove); err != nil {
			return nil, p.substrateError(err)
		}
	}
	if len(put) > 0 {
		if err := p.sub.Scheduler.TagScheduleGroup(ctx, group.ARN, put); err != nil {
			return nil, p.substrateError(err)
		}
	}
	if len(remove) > 0 || len(put) > 0 {
		group.Tags = copyTags(tags)
	}
	return group, nil
}

func (p *Provider) ensureSchedulerRole(ctx context.Context, scheduleName, taskDefARN, execRoleARN, taskRoleARN string, labels map[string]string) (string, error) {
	roleName, err := p.schedulerRoleName(scheduleName)
	if err != nil {
		return "", err
	}
	trust, err := schedulerTrustPolicy()
	if err != nil {
		return "", err
	}
	tags := ownershipTags(roleName, componentSchedulerRole, labels)
	desiredDoc, err := schedulerRunTaskPolicy(taskDefARN, execRoleARN, taskRoleARN)
	if err != nil {
		return "", err
	}
	rec, err := p.sub.IAM.GetRole(ctx, roleName)
	switch {
	case errors.Is(err, ErrNoSuchResource):
		rec, err = p.sub.IAM.CreateRole(ctx, CreateRoleRequest{
			Name:                roleName,
			Path:                p.cfg.Identity.PathPrefix,
			AssumeRolePolicy:    trust,
			PermissionsBoundary: p.cfg.Identity.PermissionsBoundary,
			Tags:                tags,
		})
		if err != nil {
			return "", p.substrateError(err)
		}
	case err != nil:
		return "", p.substrateError(err)
	default:
		if rec.Tags[tagManagedBy] != managedByValue || rec.Tags[tagComponent] != componentSchedulerRole {
			return "", fmt.Errorf("%w: the IAM role %q is not a scheduler role this provider owns", compute.ErrNotOwned, roleName)
		}
		same, err := samePolicyDocument(rec.AssumeRolePolicy, trust)
		if err != nil {
			return "", fmt.Errorf("%w: the trust policy on IAM role %q cannot be read: %w", compute.ErrFailed, roleName, err)
		}
		if !same {
			if err := p.sub.IAM.UpdateAssumeRolePolicy(ctx, roleName, trust); err != nil {
				return "", p.substrateError(err)
			}
		}
		if err := p.convergeRoleTags(ctx, roleName, rec.Tags, tags); err != nil {
			return "", err
		}
	}
	if err := p.reconcileRolePolicies(ctx, roleName, componentSchedulerRole, map[string]string{policySchedulerRun: desiredDoc}); err != nil {
		return "", err
	}
	return rec.ARN, nil
}

func schedulerTrustPolicy() (string, error) {
	raw, err := json.Marshal(trustPolicy{
		Version: "2012-10-17",
		Statement: []trustStatement{{
			Effect:    "Allow",
			Principal: map[string]string{"Service": "scheduler.amazonaws.com"},
			Action:    []string{"sts:AssumeRole"},
		}},
	})
	if err != nil {
		return "", fmt.Errorf("%w: rendering the scheduler trust policy: %w", compute.ErrFailed, err)
	}
	return string(raw), nil
}

func schedulerRunTaskPolicy(taskDefARN, execRoleARN, taskRoleARN string) (string, error) {
	resource := taskDefinitionFamilyResource(taskDefARN)
	doc := PolicyDocument{Version: policyVersion, Statement: []PolicyStatement{
		{Sid: "RunThisTaskDefinition", Effect: effectAllow, Action: []string{"ecs:RunTask"}, Resource: []string{resource}},
		{Sid: "PassOnlyTaskRoles", Effect: effectAllow, Action: []string{"iam:PassRole"}, Resource: []string{execRoleARN, taskRoleARN}},
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("%w: rendering the scheduler run-task policy: %w", compute.ErrFailed, err)
	}
	return string(raw), nil
}

func taskDefinitionFamilyResource(arn string) string {
	if idx := strings.LastIndex(arn, ":"); idx > 0 {
		return arn[:idx] + ":*"
	}
	return arn
}

func (p *Provider) scheduledJobContainerRequest(name string, spec compute.ScheduledJobSpec, secretRefs []SecretParameterRef) ContainerRequest {
	env := make([]KeyValue, 0, len(spec.Env))
	for _, e := range spec.Env {
		env = append(env, KeyValue{Name: e.Name, Value: e.Value})
	}
	sort.Slice(env, func(i, j int) bool { return env[i].Name < env[j].Name })
	secrets := make([]SecretReference, 0, len(secretRefs))
	for _, r := range secretRefs {
		secrets = append(secrets, SecretReference{Name: r.EnvName, ValueFrom: r.ARN})
	}
	logGroup := ""
	if p.cfg.Container != nil && p.cfg.Container.LogGroupPrefix != "" {
		logGroup = strings.TrimSuffix(p.cfg.Container.LogGroupPrefix, "/") + "/" + name
	}
	return ContainerRequest{Name: name, Image: string(spec.Image), Env: env, Secrets: secrets, LogGroup: logGroup}
}

func (c *containerRuntime) DescribeScheduledJob(ctx context.Context, ref compute.Ref) (*compute.ScheduledJobStatus, error) {
	if c.p.sub.Scheduler == nil || !c.p.caps.Has(compute.CapScheduledJob) {
		return nil, c.p.unsupported(compute.CapScheduledJob, "no EventBridge Scheduler substrate is configured")
	}
	name, err := c.p.resolve(ref, compute.KindScheduledJob)
	if err != nil {
		return nil, err
	}
	group, err := c.p.sub.Scheduler.DescribeScheduleGroup(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		return nil, fmt.Errorf("%w: %s does not exist", compute.ErrNotFound, ref)
	}
	if err != nil {
		return nil, c.p.substrateError(err)
	}
	if group.Tags[tagManagedBy] != managedByValue || group.Tags[tagComponent] != componentScheduledJob {
		return nil, fmt.Errorf("%w: %s names an EventBridge Scheduler group this provider does not own", compute.ErrNotOwned, ref)
	}
	rec, err := c.p.sub.Scheduler.DescribeSchedule(ctx, name, name)
	if errors.Is(err, ErrNoSuchResource) {
		return nil, fmt.Errorf("%w: %s does not exist", compute.ErrNotFound, ref)
	}
	if err != nil {
		return nil, c.p.substrateError(err)
	}
	schedule, err := scheduleFromAWS(rec.Expression, rec.Timezone, rec.State)
	if err != nil {
		return nil, err
	}
	spec, err := c.p.effectiveScheduledJobSpec(ctx, name, rec, group.Tags, schedule)
	if err != nil {
		return nil, err
	}
	return &compute.ScheduledJobStatus{Ref: ref, Spec: spec, Schedule: schedule}, nil
}

func (p *Provider) effectiveScheduledJobSpec(ctx context.Context, name string, rec *ScheduleRecord, tags map[string]string, schedule compute.Schedule) (compute.ScheduledJobSpec, error) {
	spec := compute.ScheduledJobSpec{Name: name, Schedule: schedule, Labels: labelsFromTags(tags)}
	placement, err := p.placementForScheduleTarget(name, rec.Target.ClusterARN)
	if err != nil {
		return compute.ScheduledJobSpec{}, err
	}
	spec.Placement = placement
	if rec.Target.TaskDefinitionARN == "" {
		return spec, nil
	}
	def, err := p.sub.ECS.DescribeTaskDefinition(ctx, rec.Target.TaskDefinitionARN)
	if err != nil {
		return compute.ScheduledJobSpec{}, fmt.Errorf("%w: the schedule %q points at a task definition this provider cannot read", compute.ErrFailed, name)
	}
	spec.Image = compute.ImageRef(def.Container.Image)
	spec.Resources = compute.Resources{CPUMillicores: def.CPUUnits * 1000 / cpuUnitsPerCore, MemoryMiB: def.MemoryMiB}
	for _, kv := range def.Container.Env {
		spec.Env = append(spec.Env, compute.EnvVar{Name: kv.Name, Value: kv.Value})
	}
	for _, sec := range def.Container.Secrets {
		spec.Secrets = append(spec.Secrets, compute.SecretBinding{EnvName: sec.Name})
	}
	if def.TaskRoleARN != "" {
		if roleName := roleNameFromARN(def.TaskRoleARN); roleName != "" {
			spec.Identity = p.ref(compute.KindWorkloadIdentity, roleName)
		}
	}
	return spec, nil
}

func (p *Provider) placementForScheduleTarget(scheduleName, clusterARN string) (compute.Placement, error) {
	if clusterARN != "" {
		for _, name := range p.cfg.placementNames() {
			pc, err := p.cfg.placement(compute.Placement{Name: name})
			if err != nil {
				return compute.Placement{}, err
			}
			if pc.ClusterARN == clusterARN {
				return compute.Placement{Name: pc.Name}, nil
			}
		}
		return compute.Placement{}, fmt.Errorf("%w: the schedule %q targets cluster %q, which is not one of this provider's placements", compute.ErrFailed, scheduleName, clusterARN)
	}
	pc, err := p.cfg.placement(compute.Placement{})
	if err != nil {
		return compute.Placement{}, err
	}
	return compute.Placement{Name: pc.Name}, nil
}

func (c *containerRuntime) DeleteScheduledJob(ctx context.Context, ref compute.Ref) error {
	if c.p.sub.Scheduler == nil || !c.p.caps.Has(compute.CapScheduledJob) {
		return c.p.unsupported(compute.CapScheduledJob, "no EventBridge Scheduler substrate is configured")
	}
	name, err := c.p.resolve(ref, compute.KindScheduledJob)
	if err != nil {
		return err
	}
	group, err := c.p.sub.Scheduler.DescribeScheduleGroup(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		if err := c.p.deleteSchedulerRole(ctx, name); err != nil {
			return err
		}
		return c.p.deleteScheduledExecutionRole(ctx, name)
	}
	if err != nil {
		return c.p.substrateError(err)
	}
	if group.Tags[tagManagedBy] != managedByValue || group.Tags[tagComponent] != componentScheduledJob {
		return fmt.Errorf("%w: %s names an EventBridge Scheduler group this provider does not own", compute.ErrNotOwned, ref)
	}
	if err := c.p.sub.Scheduler.DeleteSchedule(ctx, name, name); err != nil && !errors.Is(err, ErrNoSuchResource) {
		return c.p.substrateError(err)
	}
	if err := c.p.sub.Scheduler.DeleteScheduleGroup(ctx, name); err != nil && !errors.Is(err, ErrNoSuchResource) {
		return c.p.substrateError(err)
	}
	if err := c.p.deleteSchedulerRole(ctx, name); err != nil {
		return err
	}
	return c.p.deleteScheduledExecutionRole(ctx, name)
}

func (p *Provider) deleteScheduledExecutionRole(ctx context.Context, scheduleName string) error {
	taskName, err := p.scheduledTaskName(scheduleName)
	if err != nil {
		return err
	}
	if err := p.deleteExecutionRole(ctx, taskName); err != nil {
		return err
	}
	pc, pcErr := p.cfg.placement(compute.Placement{})
	if pcErr == nil {
		return p.deleteServiceSecurityGroup(ctx, taskName, pc)
	}
	return nil
}

func (p *Provider) deleteSchedulerRole(ctx context.Context, scheduleName string) error {
	roleName, err := p.schedulerRoleName(scheduleName)
	if err != nil {
		return err
	}
	rec, err := p.sub.IAM.GetRole(ctx, roleName)
	if errors.Is(err, ErrNoSuchResource) {
		return nil
	}
	if err != nil {
		return p.substrateError(err)
	}
	if rec.Tags[tagManagedBy] != managedByValue || rec.Tags[tagComponent] != componentSchedulerRole {
		return fmt.Errorf("%w: the IAM role %q is not a scheduler role this provider owns, so teardown will not delete it", compute.ErrNotOwned, roleName)
	}
	if err := p.reconcileRolePolicies(ctx, roleName, componentSchedulerRole, nil); err != nil {
		return err
	}
	if err := p.sub.IAM.DeleteRole(ctx, roleName); err != nil && !errors.Is(err, ErrNoSuchResource) {
		return p.substrateError(err)
	}
	return nil
}
