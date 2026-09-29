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

// This file holds the in-memory container substrate, and the in-memory half of
// the role-policy calls the container port added to [IAMAPI].
//
// The [MemoryIAM] methods are here rather than in memory.go for the reason
// given at the top of ecs.go: one port's additions stay in one port's files, so
// the two can be reviewed and rebased apart.

// --- IAM: inline role policies -------------------------------------------------

// ListRolePolicyNames implements [IAMAPI].
//
// Put and Delete are [RolePolicyAPI]'s and live with the store they operate on
// (USOSS-14, memorydb.go). This is the one inline-policy call that interface
// does not carry: a [compute.Granter] writes and removes a grant it can name and
// never has to ask what else is attached, whereas the container port's
// declarative reconcile derives its removal set from the role itself.
//
// Sorted, because a caller reconciling against this list makes its calls in the
// order the list arrives, and a map-ordered list would make a recorded run
// incomparable between runs.
func (m *MemoryIAM) ListRolePolicyNames(_ context.Context, roleName string) ([]string, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[roleName]; !ok {
		return nil, fmt.Errorf("%w: role %q", ErrNoSuchResource, roleName)
	}
	out := make([]string, 0, len(m.policies[roleName]))
	for name := range m.policies[roleName] {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// RolePolicies reports the inline policies on a role.
//
// It is [MemoryIAM.Policies] under this port's name, kept because the container
// tests and the harness's rendered dump read it in a dozen places and because
// the two ports arrived at the same accessor independently. It delegates rather
// than duplicating the read, so there is one lock and one copy rule.
func (m *MemoryIAM) RolePolicies(roleName string) map[string]string {
	return m.Policies(roleName)
}

// --- ECS -----------------------------------------------------------------------

// memoryService is one service and the revisions registered for it.
type memoryService struct {
	rec  ServiceRecord
	tags map[string]string
	// stalled suppresses this ONE service's convergence.
	//
	// Separate from MemoryECS.stalled, which suppresses every service's, and the
	// distinction is load-bearing rather than tidy. The conformance suite's
	// Options.Stall hook has no undo -- a resource that resumed on its own would
	// let a deadline check pass without the deadline being reached -- so a
	// substrate-wide stall taken on behalf of ONE ref never lifts, and every
	// later check in the same run then waits on a resource that can no longer
	// converge. Measured: stalling globally for the two wait-deadline
	// invariants turned wait-reports-progress red three checks later.
	stalled bool
}

// MemoryECS is an in-memory container service.
//
// It models the three behaviours of ECS this port actually depends on, and no
// more: a deleted service lingers as INACTIVE rather than disappearing, tags
// are applied on create and converged separately, and a task definition gets a
// new revision number on every registration so that a revision ARN is a stable
// identity for a rendered configuration.
type MemoryECS struct {
	failNext
	mu       sync.Mutex
	services map[string]*memoryService
	// revisions counts registrations per family, so a re-registration of an
	// identical definition still produces a new revision — which is what ECS
	// does, and what makes [compute.ServiceStatus.Revision] change when the
	// configuration does.
	revisions map[string]int
	// definitions holds each registered revision by ARN, so a test can assert
	// what was actually rendered into a task definition — the secrets array in
	// particular, which is where a leak would show.
	definitions map[string]TaskDefinitionRequest
	// emitted is a marker the hostile mode makes every read surface in the
	// service's events, and therefore in [compute.Status.Message].
	//
	// It is the substrate's half of USOSS-61's marker mechanism: a scan of a
	// message field is only evidence if the substrate can be made to put
	// something there, and the check that reads it is the one about secret
	// bindings -- this port's headline feature. Empty means nothing is armed.
	emitted string
	// stalled suppresses the convergence a read otherwise performs, so a test
	// can drive the case a real cluster produces most often when something is
	// wrong: tasks that never start. Without it a wait could only ever be
	// tested succeeding, and the timeout path — the one that has to relay the
	// substrate's own diagnosis — would be unreachable.
	stalled bool
}

var _ ECSAPI = (*MemoryECS)(nil)

// NewMemoryECS returns an empty container service.
func NewMemoryECS() *MemoryECS {
	return &MemoryECS{
		services:    map[string]*memoryService{},
		revisions:   map[string]int{},
		definitions: map[string]TaskDefinitionRequest{},
	}
}

// MemoryCluster is the cluster name this substrate answers for.
//
// Like [MemoryAccount] and [MemoryRegion] it is a word rather than an ARN
// shape, deliberately: a fixture that imitates the real shape is a fixture
// somebody eventually fills in with a real value.
const MemoryCluster = "test-cluster"

// serviceKey scopes a service to its cluster, because a service name is unique
// within a cluster and not within an account.
func serviceKey(cluster, name string) string { return cluster + "\x00" + name }

// serviceARN and taskDefinitionARN are how this substrate answers "what is this
// thing's ARN". Both are read back by the provider and never composed by it.
func serviceARN(cluster, name string) string {
	return "arn:aws:ecs:" + MemoryRegion + ":" + MemoryAccount + ":service/" + cluster + "/" + name
}

func taskDefinitionARN(family string, revision int) string {
	return fmt.Sprintf("arn:aws:ecs:%s:%s:task-definition/%s:%d",
		MemoryRegion, MemoryAccount, family, revision)
}

// PutUnowned puts a service into the substrate without apphub's ownership
// tags, so that an Ensure has a collision to refuse.
func (m *MemoryECS) PutUnowned(cluster, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services[serviceKey(cluster, name)] = &memoryService{
		rec: ServiceRecord{
			Name: name, ARN: serviceARN(cluster, name), Status: ecsStatusActive,
			DesiredCount: 1, RunningCount: 1,
		},
		tags: map[string]string{"created-by": "somebody-else"},
	}
}

// RegisterTaskDefinition implements [ECSAPI].
func (m *MemoryECS) RegisterTaskDefinition(_ context.Context, in TaskDefinitionRequest) (string, error) {
	if err := m.take(); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(in.Family) == "" {
		return "", fmt.Errorf("%w: a task definition needs a family", ErrNoSuchResource)
	}
	m.revisions[in.Family]++
	arn := taskDefinitionARN(in.Family, m.revisions[in.Family])
	m.definitions[arn] = in
	return arn, nil
}

// Definition returns a registered revision, for tests.
func (m *MemoryECS) Definition(arn string) (TaskDefinitionRequest, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.definitions[arn]
	return in, ok
}

// Definitions returns every registered revision, newest last, for tests that
// need to assert what a sequence of Ensures rendered.
func (m *MemoryECS) Definitions() []TaskDefinitionRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.definitionsLocked()
}

// definitionsLocked is the body of [MemoryECS.Definitions]. The caller holds
// the lock; Dump needs it while already holding it.
func (m *MemoryECS) definitionsLocked() []TaskDefinitionRequest {
	arns := make([]string, 0, len(m.definitions))
	for arn := range m.definitions {
		arns = append(arns, arn)
	}
	sort.Strings(arns)
	out := make([]TaskDefinitionRequest, 0, len(arns))
	for _, arn := range arns {
		out = append(out, m.definitions[arn])
	}
	return out
}

// DescribeTaskDefinition implements [ECSAPI].
func (m *MemoryECS) DescribeTaskDefinition(_ context.Context, arn string) (*TaskDefinitionRequest, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	def, ok := m.definitions[arn]
	if !ok {
		return nil, fmt.Errorf("%w: task definition %q", ErrNoSuchResource, arn)
	}
	out := def
	out.Container.Env = append([]KeyValue(nil), def.Container.Env...)
	out.Container.Secrets = append([]SecretReference(nil), def.Container.Secrets...)
	out.Container.Ports = append([]int(nil), def.Container.Ports...)
	out.Container.DockerLabels = copyTags(def.Container.DockerLabels)
	out.Tags = copyTags(def.Tags)
	return &out, nil
}

// DescribeService implements [ECSAPI].
//
// Each read moves one pending task to running, so a service converges over
// successive reads rather than being instantly ready or never ready.
//
// That is deliberately a simulation of a scheduler rather than a shortcut:
// returning the desired count immediately would make [compute.PhasePending]
// unreachable and every Wait a no-op, so a provider that never polled would
// pass. Converging over reads is what makes a wait, a timeout and a progress
// callback all testable without a clock.
func (m *MemoryECS) DescribeService(_ context.Context, cluster, name string) (*ServiceRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, ok := m.services[serviceKey(cluster, name)]
	if !ok {
		return nil, fmt.Errorf("%w: service %q in cluster %q", ErrNoSuchResource, name, cluster)
	}
	// A FAILED rollout does not progress and does not un-fail itself. Letting
	// convergence overwrite it would make the substrate model a behaviour ECS
	// does not have, and would quietly hide the provider's failed-rollout path
	// from every test that reads back after a failure.
	failed := strings.EqualFold(svc.rec.RolloutState, rolloutFailed)
	if !m.stalled && !svc.stalled && !failed && strings.EqualFold(svc.rec.Status, ecsStatusActive) {
		// The primary deployment converges, which is what readiness reads. The
		// service-level count follows it rather than leading, so a test cannot
		// accidentally satisfy readiness from the previous revision's tasks.
		if svc.rec.PrimaryRunningCount < svc.rec.PrimaryDesiredCount {
			svc.rec.PrimaryRunningCount++
			if svc.rec.PendingCount > 0 {
				svc.rec.PendingCount--
			}
		}
		if svc.rec.PrimaryRunningCount >= svc.rec.PrimaryDesiredCount {
			svc.rec.RolloutState = rolloutCompleted
		}
		if svc.rec.RunningCount < svc.rec.DesiredCount {
			svc.rec.RunningCount++
		}
	}
	return m.withEmission(copyServiceRecord(&svc.rec, svc.tags)), nil
}

// CreateService implements [ECSAPI].
func (m *MemoryECS) CreateService(_ context.Context, in ServiceRequest) (*ServiceRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := serviceKey(in.Cluster, in.Name)
	if existing, ok := m.services[key]; ok && !strings.EqualFold(existing.rec.Status, ecsStatusInactive) {
		return nil, fmt.Errorf("%w: service %q in cluster %q", ErrAlreadyExists, in.Name, in.Cluster)
	}
	svc := &memoryService{
		rec: ServiceRecord{
			Name:              in.Name,
			ARN:               serviceARN(in.Cluster, in.Name),
			Status:            ecsStatusActive,
			TaskDefinitionARN: in.TaskDefinitionARN,
			DesiredCount:      in.DesiredCount,
			// A freshly created service has nothing running yet, which is what
			// makes the port's [compute.PhasePending] reachable in a test.
			RunningCount: 0,
			PendingCount: in.DesiredCount,
			ExecEnabled:  in.ExecEnabled,
			// The primary deployment, modelled because readiness is computed
			// from it. A create is a deployment of one revision with nothing
			// running.
			PrimaryTaskDefinitionARN: in.TaskDefinitionARN,
			PrimaryDesiredCount:      in.DesiredCount,
			PrimaryRunningCount:      0,
			RolloutState:             rolloutInProgress,
		},
		tags: copyTags(in.Tags),
	}
	m.services[key] = svc
	return m.withEmission(copyServiceRecord(&svc.rec, svc.tags)), nil
}

// UpdateService implements [ECSAPI].
func (m *MemoryECS) UpdateService(_ context.Context, in ServiceRequest) (*ServiceRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, ok := m.services[serviceKey(in.Cluster, in.Name)]
	if !ok {
		return nil, fmt.Errorf("%w: service %q in cluster %q", ErrNoSuchResource, in.Name, in.Cluster)
	}
	// A changed revision starts a NEW primary deployment, whose running count
	// begins at zero while the previous revision's tasks keep running. That is
	// the behaviour the port's readiness depends on and the reason the
	// service-level RunningCount cannot answer the question: modelling the
	// update as "same counts, new ARN" would hide the very defect this exists
	// to catch.
	if svc.rec.PrimaryTaskDefinitionARN != in.TaskDefinitionARN {
		svc.rec.PrimaryTaskDefinitionARN = in.TaskDefinitionARN
		svc.rec.PrimaryRunningCount = 0
		svc.rec.RolloutState = rolloutInProgress
	}
	svc.rec.PrimaryDesiredCount = in.DesiredCount
	svc.rec.TaskDefinitionARN = in.TaskDefinitionARN
	svc.rec.DesiredCount = in.DesiredCount
	svc.rec.ExecEnabled = in.ExecEnabled
	svc.rec.Status = ecsStatusActive
	// Tags are NOT applied here. ECS applies tags on create only, and a
	// substrate that quietly converged them on update would hide the fact that
	// the port has to converge them itself — which is exactly the kind of
	// difference an in-memory substrate must not paper over.
	return m.withEmission(copyServiceRecord(&svc.rec, svc.tags)), nil
}

// SetDesiredCount implements [ECSAPI].
func (m *MemoryECS) SetDesiredCount(_ context.Context, cluster, name string, count int) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, ok := m.services[serviceKey(cluster, name)]
	if !ok {
		return fmt.Errorf("%w: service %q in cluster %q", ErrNoSuchResource, name, cluster)
	}
	svc.rec.DesiredCount = count
	svc.rec.PrimaryDesiredCount = count
	if svc.rec.RunningCount > count {
		svc.rec.RunningCount = count
	}
	if svc.rec.PrimaryRunningCount > count {
		svc.rec.PrimaryRunningCount = count
	}
	return nil
}

// DeleteService implements [ECSAPI].
//
// The service becomes INACTIVE rather than disappearing, which is what ECS does
// and what the port has to cope with: a name stays taken.
func (m *MemoryECS) DeleteService(_ context.Context, cluster, name string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, ok := m.services[serviceKey(cluster, name)]
	if !ok {
		return fmt.Errorf("%w: service %q in cluster %q", ErrNoSuchResource, name, cluster)
	}
	if strings.EqualFold(svc.rec.Status, ecsStatusInactive) {
		// ECS's ServiceNotActiveException, classified the way [sdkECS.err]
		// classifies it. Deleting a deleted service is refused, not repeated.
		return fmt.Errorf("%w: service %q in cluster %q is INACTIVE", ErrAlreadyExists, name, cluster)
	}
	svc.rec.Status = ecsStatusInactive
	svc.rec.DesiredCount = 0
	svc.rec.RunningCount = 0
	svc.rec.PendingCount = 0
	return nil
}

// ListServiceTags implements [ECSAPI].
func (m *MemoryECS) ListServiceTags(_ context.Context, arn string) (map[string]string, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	svc := m.byARN(arn)
	if svc == nil {
		return nil, fmt.Errorf("%w: service %q", ErrNoSuchResource, arn)
	}
	return copyTags(svc.tags), nil
}

// TagService implements [ECSAPI].
func (m *MemoryECS) TagService(_ context.Context, arn string, tags map[string]string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	svc := m.byARN(arn)
	if svc == nil {
		return fmt.Errorf("%w: service %q", ErrNoSuchResource, arn)
	}
	if svc.tags == nil {
		svc.tags = map[string]string{}
	}
	for k, v := range tags {
		svc.tags[k] = v
	}
	return nil
}

// UntagService implements [ECSAPI].
func (m *MemoryECS) UntagService(_ context.Context, arn string, keys []string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	svc := m.byARN(arn)
	if svc == nil {
		return fmt.Errorf("%w: service %q", ErrNoSuchResource, arn)
	}
	for _, k := range keys {
		delete(svc.tags, k)
	}
	return nil
}

// byARN finds a service by ARN. The caller holds the lock.
func (m *MemoryECS) byARN(arn string) *memoryService {
	for _, svc := range m.services {
		if svc.rec.ARN == arn {
			return svc
		}
	}
	return nil
}

// Advance makes a service's running count reach its desired count, so a test
// can drive a wait to completion without a real scheduler.
//
// It is on the substrate rather than on the provider because "tasks started" is
// a substrate event, and a provider that could make its own workload ready
// would be able to satisfy a wait it should have failed.
func (m *MemoryECS) Advance(cluster, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if svc, ok := m.services[serviceKey(cluster, name)]; ok {
		svc.rec.RunningCount = svc.rec.DesiredCount
		svc.rec.PrimaryRunningCount = svc.rec.PrimaryDesiredCount
		svc.rec.PendingCount = 0
		svc.rec.RolloutState = rolloutCompleted
	}
}

// emitInto arms the marker every read surfaces in the service's events.
//
// An empty marker clears it, which the suite relies on: a persistent emission
// poisons every later check that reads a message.
func (m *MemoryECS) emitInto(marker string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.emitted = marker
}

// StallService stops ONE service converging, permanently.
//
// It is what [Harness.Stall] calls, and it is per-service for the reason given
// on memoryService.stalled: the hook it answers has no undo, so a stall taken
// for one ref must not reach any other.
//
// A service that does not exist is a no-op rather than an error. The hook is
// handed a Ref the suite just created, so an absent service means the suite and
// the substrate disagree about a name -- and that is a failure the Wait itself
// reports with the name in it, which is a better diagnostic than one from here.
func (m *MemoryECS) StallService(cluster, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if svc, ok := m.services[serviceKey(cluster, name)]; ok {
		svc.stalled = true
	}
}

// FailRollout makes the substrate report the primary deployment as failed, so a
// test can drive the state a wait must NOT sit through.
func (m *MemoryECS) FailRollout(cluster, name, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if svc, ok := m.services[serviceKey(cluster, name)]; ok {
		svc.rec.RolloutState = rolloutFailed
		svc.rec.RolloutReason = reason
	}
}

// Stall stops tasks from starting, and returns a function that lets them start
// again.
func (m *MemoryECS) Stall() func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stalled = true
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.stalled = false
	}
}

// SetEvents attaches substrate event text to a service, so a test can check
// that a failing wait relays the only diagnosis ECS offers.
func (m *MemoryECS) SetEvents(cluster, name string, events ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if svc, ok := m.services[serviceKey(cluster, name)]; ok {
		svc.rec.Events = append([]string(nil), events...)
	}
}

func copyServiceRecord(rec *ServiceRecord, tags map[string]string) *ServiceRecord {
	out := *rec
	out.Events = append([]string(nil), rec.Events...)
	out.Tags = copyTags(tags)
	return &out
}

// withEmission puts the armed marker at the FRONT of a record's events.
//
// The front, because [latestEvent] relays events[0] into the message and
// appending would arm a channel the scan cannot see. Applied to the copy a read
// returns rather than to the stored record, so arming and clearing the marker
// does not mutate what the substrate holds.
func (m *MemoryECS) withEmission(rec *ServiceRecord) *ServiceRecord {
	if m.emitted == "" {
		return rec
	}
	rec.Events = append([]string{m.emitted}, rec.Events...)
	return rec
}

// Dump renders everything this substrate holds, for the conformance harness.
//
// The task definitions are included, and the secrets array with them. That is
// deliberate and it is what makes the suite's
// secret-material-does-not-appear-in-rendered-artefacts invariant able to see
// this port at all: the array is where a resolved secret lands, so a dump that
// showed only the environment would scan a surface the material never reaches
// and report a pass. It holds parameter ARNs and never values, which is the
// property the invariant should confirm rather than assume.
func (m *MemoryECS) Dump() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	keys := make([]string, 0, len(m.services))
	for k := range m.services {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		svc := m.services[k]
		out = append(out, fmt.Sprintf("ecs service %s status=%s desired=%d running=%d "+
			"primary=%d/%d rollout=%s exec=%t taskdef=%s tags[%s]",
			svc.rec.Name, svc.rec.Status, svc.rec.DesiredCount, svc.rec.RunningCount,
			svc.rec.PrimaryRunningCount, svc.rec.PrimaryDesiredCount, svc.rec.RolloutState,
			svc.rec.ExecEnabled, svc.rec.TaskDefinitionARN, sortedPairs(svc.tags)))
	}
	// The task definition each service currently POINTS AT, keyed by the
	// revision ARN.
	//
	// Two decisions here, both load-bearing for what the conformance suite can
	// see, and both found by reading its observations rather than its failures.
	//
	// The ARN is in the line because [conformance.renderedFor] keeps only
	// artefacts containing "<name>:" or "<name>.", and a line naming the
	// task-definition FAMILY is followed by a space. So the line carrying the
	// environment and the secrets array — the only line where the removal half
	// of the convergence invariant could be observed — was invisible to the
	// suite, which duly reported that it "never contained" the marker. A dump
	// nothing can match is a dump that reports nothing.
	//
	// And only the revision in force is rendered, not every revision ever
	// registered. ECS revisions are immutable and retained, so a superseded one
	// genuinely still contains the environment variable a caller removed —
	// rendering it as current state would make "an element removed from a spec
	// is gone" unsatisfiable for any substrate with immutable revisions, which
	// would be the check being wrong rather than the provider. What converged is
	// which revision the service points at.
	for _, k := range keys {
		svc := m.services[k]
		def, ok := m.definitions[svc.rec.TaskDefinitionARN]
		if !ok {
			continue
		}
		env := make([]string, 0, len(def.Container.Env))
		for _, kv := range def.Container.Env {
			env = append(env, kv.Name+"="+kv.Value)
		}
		secrets := make([]string, 0, len(def.Container.Secrets))
		for _, sec := range def.Container.Secrets {
			secrets = append(secrets, sec.Name+"<-"+sec.ValueFrom)
		}
		labels := make([]string, 0, len(def.Container.DockerLabels))
		for _, lk := range sortedKeys(def.Container.DockerLabels) {
			labels = append(labels, lk+"="+def.Container.DockerLabels[lk])
		}
		out = append(out, fmt.Sprintf("ecs taskdef %s cpu=%d mem=%d exec-role=%s task-role=%s "+
			"image=%s env[%s] secrets[%s] labels[%s] tags[%s]",
			svc.rec.TaskDefinitionARN, def.CPUUnits, def.MemoryMiB, def.ExecutionRoleARN,
			def.TaskRoleARN, def.Container.Image, strings.Join(env, " "),
			strings.Join(secrets, " "), strings.Join(labels, " "), sortedPairs(def.Tags)))
	}
	return out
}

// DumpTaskDefinitions returns stable diagnostic lines for selected task definitions.
func (m *MemoryECS) DumpTaskDefinitions(arns []string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(arns))
	for _, arn := range arns {
		def, ok := m.definitions[arn]
		if !ok {
			continue
		}
		out = append(out, taskDefinitionDumpLine(arn, def))
	}
	return out
}

func taskDefinitionDumpLine(arn string, def TaskDefinitionRequest) string {
	env := make([]string, 0, len(def.Container.Env))
	for _, kv := range def.Container.Env {
		env = append(env, kv.Name+"="+kv.Value)
	}
	secrets := make([]string, 0, len(def.Container.Secrets))
	for _, sec := range def.Container.Secrets {
		secrets = append(secrets, sec.Name+"<-"+sec.ValueFrom)
	}
	labels := make([]string, 0, len(def.Container.DockerLabels))
	for _, lk := range sortedKeys(def.Container.DockerLabels) {
		labels = append(labels, lk+"="+def.Container.DockerLabels[lk])
	}
	return fmt.Sprintf("ecs taskdef %s cpu=%d mem=%d exec-role=%s task-role=%s "+
		"image=%s env[%s] secrets[%s] labels[%s] tags[%s]",
		arn, def.CPUUnits, def.MemoryMiB, def.ExecutionRoleARN,
		def.TaskRoleARN, def.Container.Image, strings.Join(env, " "),
		strings.Join(secrets, " "), strings.Join(labels, " "), sortedPairs(def.Tags))
}
