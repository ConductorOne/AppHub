// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type memoryScheduleGroup struct {
	rec  ScheduleGroupRecord
	tags map[string]string
}

// MemoryScheduler is an in-memory EventBridge Scheduler model.
type MemoryScheduler struct {
	failNext
	mu        sync.Mutex
	groups    map[string]*memoryScheduleGroup
	schedules map[string]*ScheduleRecord
}

var _ SchedulerAPI = (*MemoryScheduler)(nil)

// NewMemoryScheduler returns an empty in-memory scheduler substrate.
func NewMemoryScheduler() *MemoryScheduler {
	return &MemoryScheduler{
		groups:    map[string]*memoryScheduleGroup{},
		schedules: map[string]*ScheduleRecord{},
	}
}

func scheduleGroupARN(name string) string {
	return "arn:aws:scheduler:" + MemoryRegion + ":" + MemoryAccount + ":schedule-group/" + name
}

func scheduleARN(group, name string) string {
	return "arn:aws:scheduler:" + MemoryRegion + ":" + MemoryAccount + ":schedule/" + group + "/" + name
}

func scheduleKey(group, name string) string { return group + "\x00" + name }

// PutUnowned plants a schedule group without AppHub ownership tags.
func (m *MemoryScheduler) PutUnowned(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.groups[name] = &memoryScheduleGroup{
		rec:  ScheduleGroupRecord{Name: name, ARN: scheduleGroupARN(name)},
		tags: map[string]string{"created-by": "somebody-else"},
	}
}

// CreateScheduleGroup implements [SchedulerAPI].
func (m *MemoryScheduler) CreateScheduleGroup(_ context.Context, in ScheduleGroupRequest) (*ScheduleGroupRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[in.Name]; ok {
		return nil, fmt.Errorf("%w: schedule group %q", ErrAlreadyExists, in.Name)
	}
	group := &memoryScheduleGroup{
		rec:  ScheduleGroupRecord{Name: in.Name, ARN: scheduleGroupARN(in.Name)},
		tags: copyTags(in.Tags),
	}
	m.groups[in.Name] = group
	return copyScheduleGroupRecord(&group.rec, group.tags), nil
}

// DescribeScheduleGroup implements [SchedulerAPI].
func (m *MemoryScheduler) DescribeScheduleGroup(_ context.Context, name string) (*ScheduleGroupRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	group, ok := m.groups[name]
	if !ok {
		return nil, fmt.Errorf("%w: schedule group %q", ErrNoSuchResource, name)
	}
	return copyScheduleGroupRecord(&group.rec, group.tags), nil
}

// DeleteScheduleGroup implements [SchedulerAPI].
func (m *MemoryScheduler) DeleteScheduleGroup(_ context.Context, name string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[name]; !ok {
		return fmt.Errorf("%w: schedule group %q", ErrNoSuchResource, name)
	}
	for key := range m.schedules {
		if strings.HasPrefix(key, name+"\x00") {
			return fmt.Errorf("%w: schedule group %q is not empty", ErrConflict, name)
		}
	}
	delete(m.groups, name)
	return nil
}

// TagScheduleGroup implements [SchedulerAPI].
func (m *MemoryScheduler) TagScheduleGroup(_ context.Context, arn string, tags map[string]string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, group := range m.groups {
		if group.rec.ARN == arn {
			for k, v := range tags {
				group.tags[k] = v
			}
			return nil
		}
	}
	return fmt.Errorf("%w: schedule group %q", ErrNoSuchResource, arn)
}

// UntagScheduleGroup implements [SchedulerAPI].
func (m *MemoryScheduler) UntagScheduleGroup(_ context.Context, arn string, keys []string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, group := range m.groups {
		if group.rec.ARN == arn {
			for _, key := range keys {
				delete(group.tags, key)
			}
			return nil
		}
	}
	return fmt.Errorf("%w: schedule group %q", ErrNoSuchResource, arn)
}

// CreateSchedule implements [SchedulerAPI].
func (m *MemoryScheduler) CreateSchedule(_ context.Context, in ScheduleRequest) (*ScheduleRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[in.GroupName]; !ok {
		return nil, fmt.Errorf("%w: schedule group %q", ErrNoSuchResource, in.GroupName)
	}
	key := scheduleKey(in.GroupName, in.Name)
	if _, ok := m.schedules[key]; ok {
		return nil, fmt.Errorf("%w: schedule %q", ErrAlreadyExists, in.Name)
	}
	rec := scheduleRecordFromRequest(in)
	m.schedules[key] = rec
	return copyScheduleRecord(rec), nil
}

// UpdateSchedule implements [SchedulerAPI].
func (m *MemoryScheduler) UpdateSchedule(_ context.Context, in ScheduleRequest) (*ScheduleRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := scheduleKey(in.GroupName, in.Name)
	if _, ok := m.schedules[key]; !ok {
		return nil, fmt.Errorf("%w: schedule %q", ErrNoSuchResource, in.Name)
	}
	rec := scheduleRecordFromRequest(in)
	m.schedules[key] = rec
	return copyScheduleRecord(rec), nil
}

// DescribeSchedule implements [SchedulerAPI].
func (m *MemoryScheduler) DescribeSchedule(_ context.Context, group, name string) (*ScheduleRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.schedules[scheduleKey(group, name)]
	if !ok {
		return nil, fmt.Errorf("%w: schedule %q", ErrNoSuchResource, name)
	}
	return copyScheduleRecord(rec), nil
}

// DeleteSchedule implements [SchedulerAPI].
func (m *MemoryScheduler) DeleteSchedule(_ context.Context, group, name string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := scheduleKey(group, name)
	if _, ok := m.schedules[key]; !ok {
		return fmt.Errorf("%w: schedule %q", ErrNoSuchResource, name)
	}
	delete(m.schedules, key)
	return nil
}

func scheduleRecordFromRequest(in ScheduleRequest) *ScheduleRecord {
	state := scheduleStateEnabled
	if in.Paused {
		state = scheduleStateDisabled
	}
	return &ScheduleRecord{
		GroupName:  in.GroupName,
		Name:       in.Name,
		ARN:        scheduleARN(in.GroupName, in.Name),
		Expression: in.Expression,
		Timezone:   in.Timezone,
		State:      state,
		Target:     copyScheduleTarget(in.Target),
	}
}

func copyScheduleGroupRecord(rec *ScheduleGroupRecord, tags map[string]string) *ScheduleGroupRecord {
	out := *rec
	out.Tags = copyTags(tags)
	return &out
}

func copyScheduleRecord(rec *ScheduleRecord) *ScheduleRecord {
	out := *rec
	out.Target = copyScheduleTarget(rec.Target)
	return &out
}

func copyScheduleTarget(in ScheduleTarget) ScheduleTarget {
	out := in
	out.SubnetIDs = append([]string(nil), in.SubnetIDs...)
	out.SecurityGroupIDs = append([]string(nil), in.SecurityGroupIDs...)
	return out
}

// CurrentTaskDefinitions returns the task definitions referenced by schedules.
func (m *MemoryScheduler) CurrentTaskDefinitions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	arns := make([]string, 0, len(m.schedules))
	for _, rec := range m.schedules {
		if rec.Target.TaskDefinitionARN != "" {
			arns = append(arns, rec.Target.TaskDefinitionARN)
		}
	}
	sort.Strings(arns)
	return arns
}

// Dump returns stable diagnostic lines for every schedule group and schedule.
func (m *MemoryScheduler) Dump() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	groups := make([]string, 0, len(m.groups))
	for name := range m.groups {
		groups = append(groups, name)
	}
	sort.Strings(groups)
	out := make([]string, 0, len(groups)+len(m.schedules))
	for _, name := range groups {
		out = append(out, fmt.Sprintf("scheduler group %s tags[%s]", name, sortedPairs(m.groups[name].tags)))
	}
	keys := make([]string, 0, len(m.schedules))
	for key := range m.schedules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rec := m.schedules[key]
		out = append(out, fmt.Sprintf("scheduler schedule %s/%s expression=%q timezone=%s state=%s taskdef=%s role=%s subnets=%s groups=%s public-ip=%t",
			rec.GroupName, rec.Name, rec.Expression, rec.Timezone, rec.State,
			rec.Target.TaskDefinitionARN, rec.Target.RoleARN, strings.Join(rec.Target.SubnetIDs, ","),
			strings.Join(rec.Target.SecurityGroupIDs, ","), rec.Target.AssignPublicIP))
	}
	return out
}
