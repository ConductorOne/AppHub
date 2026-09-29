// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"context"

	"github.com/conductorone/apphub/credentials"
)

// The in-memory RDS and DynamoDB, and the inline-policy half of [MemoryIAM].
//
// Same contract as the rest of the memory substrate: a model of the services
// rather than a mock. Both of these are *asynchronous* services, which the ECR
// and IAM models are not, and that is the one thing worth reading carefully.
//
// # Why these substrates converge on a clock nobody sets
//
// A real DynamoDB table is CREATING and then ACTIVE; a real Aurora cluster is
// creating and then available, over minutes. [compute.KeyValueStatus] and
// [compute.RelationalStatus] both carry a phase precisely because of that, and
// the conformance suite's asynchronous checks — Ensure returns promptly, Wait
// blocks, Wait honours its deadline — only mean something against a substrate
// that is not instantly ready.
//
// So these models take a configurable number of observations to become ready,
// defaulting to one: the resource is created "creating" and the *next* describe
// reports it available. That is enough for a provider that returned
// [compute.PhaseReady] from a create to be caught, and it needs no wall clock,
// which matters because a hermetic suite must not sleep. [MemoryRDS.Stall] and
// [MemoryDynamoDB.Stall] make a resource stop converging altogether, which is
// what the Wait-deadline invariants need.

// memoryReadyAfter is how many observations a newly created resource takes to
// report itself available.
//
// Two, and the number is chosen rather than arbitrary: one Ensure performs
// exactly one describe of the resource it just created (the read-back it returns
// from), so a resource ready after *one* observation would be ready by the time
// Ensure returned. That is not what a real Aurora cluster or a real DynamoDB
// table does, and — worse — it leaves the Stall hook nothing to stall, so the
// suite's two Wait-deadline invariants would pass vacuously against a resource
// that had already converged.
//
// [MemoryRDS.Stall] and [MemoryDynamoDB.Stall] do not depend on this number:
// they put a resource back into its creating state, so the hook works whatever a
// provider's describe count turns out to be. The two reasons are independent on
// purpose, because a constant tuned to one call path is a constant that goes
// stale when the call path changes.
const memoryReadyAfter = 2

// --- inline policies on MemoryIAM -------------------------------------------

// GetRolePolicy implements [RolePolicyAPI].
func (m *MemoryIAM) GetRolePolicy(_ context.Context, role, policy string) (string, error) {
	if err := m.take(); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[role]; !ok {
		return "", fmt.Errorf("%w: role %q", ErrNoSuchResource, role)
	}
	doc, ok := m.policies[role][policy]
	if !ok {
		return "", fmt.Errorf("%w: role %q has no inline policy %q", ErrNoSuchResource, role, policy)
	}
	return doc, nil
}

// PutRolePolicy implements [RolePolicyAPI].
func (m *MemoryIAM) PutRolePolicy(_ context.Context, role, policy, document string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[role]; !ok {
		return fmt.Errorf("%w: role %q", ErrNoSuchResource, role)
	}
	if m.policies[role] == nil {
		m.policies[role] = map[string]string{}
	}
	// Replaces. IAM's PutRolePolicy does too, and it is the behaviour
	// [compute.Granter] depends on: an access level narrowed from read-write to
	// read has to narrow, and a substrate that merged documents would leave the
	// wider statement in force.
	m.policies[role][policy] = document
	return nil
}

// DeleteRolePolicy implements [RolePolicyAPI].
func (m *MemoryIAM) DeleteRolePolicy(_ context.Context, role, policy string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policies[role][policy]; !ok {
		return fmt.Errorf("%w: role %q has no inline policy %q", ErrNoSuchResource, role, policy)
	}
	delete(m.policies[role], policy)
	return nil
}

// Policies returns the inline policy documents on a role, for a test that wants
// to assert on what a grant wrote rather than on what it permits.
//
// The behavioural check is the one that matters and the conformance suite owns
// it; this exists so that a *least privilege* assertion — that a read grant
// names read actions and nothing else — has something to read.
func (m *MemoryIAM) Policies(role string) map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return copyTags(m.policies[role])
}

// --- RDS --------------------------------------------------------------------

// MemoryRDS is an in-memory managed-SQL service.
type MemoryRDS struct {
	failNext
	mu           sync.Mutex
	subnetGroups map[string]*SubnetGroupRecord
	clusters     map[string]*memoryCluster
	instances    map[string]*InstanceRecord
	// stalled is the set of cluster identifiers that will never converge.
	stalled map[string]bool
}

type memoryCluster struct {
	rec ClusterRecord
	// password is the master password the cluster was created with, held as a
	// [credentials.Secret].
	//
	// A real RDS cluster holds one too and never hands it back, which is what
	// lets [compute.RelationalStatus] promise a read-back carries no material.
	// This substrate has to be able to *authenticate* one, because that is the
	// only way the "a re-Ensure does not rotate the admin password" invariant
	// can be checked behaviourally — but it is never rendered, never returned in
	// a [ClusterRecord], and redacts if it is formatted.
	password credentials.Secret
	// observations counts describes since creation, so the cluster becomes
	// available without a clock.
	observations int
}

var _ RDSAPI = (*MemoryRDS)(nil)

// NewMemoryRDS returns an empty managed-SQL service.
func NewMemoryRDS() *MemoryRDS {
	return &MemoryRDS{
		subnetGroups: map[string]*SubnetGroupRecord{},
		clusters:     map[string]*memoryCluster{},
		instances:    map[string]*InstanceRecord{},
		stalled:      map[string]bool{},
	}
}

// The RDS status strings this substrate reports, which are RDS's own.
const (
	rdsStatusCreating  = "creating"
	rdsStatusAvailable = "available"
)

func clusterARN(id string) string {
	return "arn:aws:rds:" + MemoryRegion + ":" + MemoryAccount + ":cluster:" + id
}

func instanceARN(id string) string {
	return "arn:aws:rds:" + MemoryRegion + ":" + MemoryAccount + ":db:" + id
}

func subnetGroupARN(name string) string {
	return "arn:aws:rds:" + MemoryRegion + ":" + MemoryAccount + ":subgrp:" + name
}

// clusterEndpoint is the writer hostname this substrate reports.
//
// Under the reserved .invalid TLD rather than the real rds.amazonaws.com shape,
// for the same reason [MemoryRegistryHost] is: nothing in this package parses an
// endpoint, so the fixture does not have to imitate the shape, and imitating it
// would put a deployment-shaped hostname in a public repository.
func clusterEndpoint(id string) string { return id + ".cluster.rds.invalid" }

// Stall makes a cluster stop converging, so a Wait against it has something to
// time out on.
//
// It puts the cluster back into its creating state as well as marking it stuck,
// so that the hook works on a cluster that has already reached available. Without
// that, whether the hook did anything would depend on how many times the
// provider happened to describe the cluster on the way out of Ensure — and a
// Wait invariant whose effectiveness depends on a provider's internal call count
// is an invariant that stops holding without anyone editing it.
func (m *MemoryRDS) Stall(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stalled[id] = true
	if c, ok := m.clusters[id]; ok {
		c.rec.Status = rdsStatusCreating
		c.rec.Endpoint = ""
		c.observations = 0
	}
	for _, inst := range m.instances {
		if inst.ClusterIdentifier == id {
			inst.Status = rdsStatusCreating
		}
	}
}

// PutUnownedCluster puts a cluster into the substrate without apphub's
// ownership tag.
func (m *MemoryRDS) PutUnownedCluster(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clusters[id] = &memoryCluster{rec: ClusterRecord{
		Identifier: id, ARN: clusterARN(id), Status: rdsStatusAvailable,
		Endpoint: clusterEndpoint(id), Port: postgresPort,
		Tags: map[string]string{"created-by": "somebody-else"},
	}}
}

// DescribeSubnetGroup implements [RDSAPI].
func (m *MemoryRDS) DescribeSubnetGroup(_ context.Context, name string) (*SubnetGroupRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.subnetGroups[name]
	if !ok {
		return nil, fmt.Errorf("%w: DB subnet group %q", ErrNoSuchResource, name)
	}
	return copySubnetGroup(g), nil
}

// CreateSubnetGroup implements [RDSAPI].
func (m *MemoryRDS) CreateSubnetGroup(_ context.Context, in CreateSubnetGroupRequest) (*SubnetGroupRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.subnetGroups[in.Name]; ok {
		return nil, fmt.Errorf("%w: DB subnet group %q", ErrAlreadyExists, in.Name)
	}
	g := &SubnetGroupRecord{
		Name: in.Name, ARN: subnetGroupARN(in.Name),
		SubnetIDs: append([]string(nil), in.SubnetIDs...), Tags: copyTags(in.Tags),
	}
	if g.Tags == nil {
		g.Tags = map[string]string{}
	}
	m.subnetGroups[in.Name] = g
	return copySubnetGroup(g), nil
}

// DeleteSubnetGroup implements [RDSAPI].
func (m *MemoryRDS) DeleteSubnetGroup(_ context.Context, name string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.subnetGroups[name]; !ok {
		return fmt.Errorf("%w: DB subnet group %q", ErrNoSuchResource, name)
	}
	delete(m.subnetGroups, name)
	return nil
}

// DescribeCluster implements [RDSAPI].
//
// Each describe of a creating cluster counts as an observation, and after
// [memoryReadyAfter] of them the cluster reports itself available — unless it
// has been stalled. That is how a hermetic suite gets an asynchronous substrate
// without a clock.
func (m *MemoryRDS) DescribeCluster(_ context.Context, id string) (*ClusterRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clusters[id]
	if !ok {
		return nil, fmt.Errorf("%w: DB cluster %q", ErrNoSuchResource, id)
	}
	if c.rec.Status == rdsStatusCreating && !m.stalled[id] {
		c.observations++
		if c.observations >= memoryReadyAfter {
			c.rec.Status = rdsStatusAvailable
			c.rec.Endpoint = clusterEndpoint(id)
		}
	}
	rec := c.rec
	rec.Tags = copyTags(c.rec.Tags)
	rec.SecurityGroupIDs = append([]string(nil), c.rec.SecurityGroupIDs...)
	return &rec, nil
}

// CreateCluster implements [RDSAPI].
func (m *MemoryRDS) CreateCluster(_ context.Context, in CreateClusterRequest) (*ClusterRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clusters[in.Identifier]; ok {
		return nil, fmt.Errorf("%w: DB cluster %q", ErrAlreadyExists, in.Identifier)
	}
	if in.MasterPassword.IsZero() {
		// RDS refuses this too, and the refusal is worth modelling: a cluster
		// created with no password is a cluster nobody can log into, and the
		// caller's stored copy would be of nothing.
		return nil, fmt.Errorf("%w: DB cluster %q was created with no master password",
			ErrNoSuchResource, in.Identifier)
	}
	c := &memoryCluster{
		rec: ClusterRecord{
			Identifier: in.Identifier, ARN: clusterARN(in.Identifier),
			Engine: in.Engine, EngineVersion: in.EngineVersion,
			DatabaseName: in.DatabaseName, MasterUsername: in.MasterUsername,
			Port: postgresPort, Status: rdsStatusCreating,
			MinCapacity: in.MinCapacity, MaxCapacity: in.MaxCapacity,
			StorageEncrypted: in.StorageEncrypted,
			SecurityGroupIDs: append([]string(nil), in.SecurityGroupIDs...),
			SubnetGroup:      in.SubnetGroup,
			Tags:             copyTags(in.Tags),
		},
		password: in.MasterPassword,
	}
	if c.rec.Tags == nil {
		c.rec.Tags = map[string]string{}
	}
	m.clusters[in.Identifier] = c
	rec := c.rec
	rec.Tags = copyTags(c.rec.Tags)
	return &rec, nil
}

// ModifyClusterCapacity implements [RDSAPI].
func (m *MemoryRDS) ModifyClusterCapacity(_ context.Context, id string, minCapacity, maxCapacity float64) error {
	return m.withCluster(id, func(c *memoryCluster) error {
		c.rec.MinCapacity, c.rec.MaxCapacity = minCapacity, maxCapacity
		return nil
	})
}

// ModifyClusterSecurityGroups implements [RDSAPI].
func (m *MemoryRDS) ModifyClusterSecurityGroups(_ context.Context, id string, groups []string) error {
	return m.withCluster(id, func(c *memoryCluster) error {
		c.rec.SecurityGroupIDs = append([]string(nil), groups...)
		return nil
	})
}

// DeleteCluster implements [RDSAPI].
func (m *MemoryRDS) DeleteCluster(_ context.Context, id string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clusters[id]; !ok {
		return fmt.Errorf("%w: DB cluster %q", ErrNoSuchResource, id)
	}
	delete(m.clusters, id)
	delete(m.stalled, id)
	return nil
}

// DescribeInstance implements [RDSAPI].
func (m *MemoryRDS) DescribeInstance(_ context.Context, id string) (*InstanceRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.instances[id]
	if !ok {
		return nil, fmt.Errorf("%w: DB instance %q", ErrNoSuchResource, id)
	}
	if inst.Status == rdsStatusCreating && !m.stalled[inst.ClusterIdentifier] {
		inst.Status = rdsStatusAvailable
	}
	out := *inst
	out.Tags = copyTags(inst.Tags)
	return &out, nil
}

// CreateInstance implements [RDSAPI].
func (m *MemoryRDS) CreateInstance(_ context.Context, in CreateInstanceRequest) (*InstanceRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[in.Identifier]; ok {
		return nil, fmt.Errorf("%w: DB instance %q", ErrAlreadyExists, in.Identifier)
	}
	if _, ok := m.clusters[in.ClusterIdentifier]; !ok {
		// RDS refuses an instance in a cluster that does not exist, and
		// modelling it is what makes the provider's ordering testable: the
		// cluster has to come first.
		return nil, fmt.Errorf("%w: DB cluster %q", ErrNoSuchResource, in.ClusterIdentifier)
	}
	inst := &InstanceRecord{
		Identifier: in.Identifier, ARN: instanceARN(in.Identifier),
		ClusterIdentifier: in.ClusterIdentifier, Class: in.Class,
		Status: rdsStatusCreating, Tags: copyTags(in.Tags),
	}
	if inst.Tags == nil {
		inst.Tags = map[string]string{}
	}
	m.instances[in.Identifier] = inst
	out := *inst
	out.Tags = copyTags(inst.Tags)
	return &out, nil
}

// DeleteInstance implements [RDSAPI].
func (m *MemoryRDS) DeleteInstance(_ context.Context, id string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.instances[id]; !ok {
		return fmt.Errorf("%w: DB instance %q", ErrNoSuchResource, id)
	}
	delete(m.instances, id)
	return nil
}

// ListTags implements [RDSAPI].
func (m *MemoryRDS) ListTags(_ context.Context, arn string) (map[string]string, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tags, err := m.tagsOf(arn)
	if err != nil {
		return nil, err
	}
	return copyTags(tags), nil
}

// TagResource implements [RDSAPI].
func (m *MemoryRDS) TagResource(_ context.Context, arn string, tags map[string]string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	target, err := m.tagsOf(arn)
	if err != nil {
		return err
	}
	for k, v := range tags {
		target[k] = v
	}
	return nil
}

// UntagResource implements [RDSAPI].
func (m *MemoryRDS) UntagResource(_ context.Context, arn string, keys []string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	target, err := m.tagsOf(arn)
	if err != nil {
		return err
	}
	for _, k := range keys {
		delete(target, k)
	}
	return nil
}

// tagsOf finds the tag map an ARN addresses. Called with the lock held.
func (m *MemoryRDS) tagsOf(arn string) (map[string]string, error) {
	for _, c := range m.clusters {
		if c.rec.ARN == arn {
			return c.rec.Tags, nil
		}
	}
	for _, inst := range m.instances {
		if inst.ARN == arn {
			return inst.Tags, nil
		}
	}
	for _, g := range m.subnetGroups {
		if g.ARN == arn {
			return g.Tags, nil
		}
	}
	return nil, fmt.Errorf("%w: RDS resource %q", ErrNoSuchResource, arn)
}

func (m *MemoryRDS) withCluster(id string, fn func(*memoryCluster) error) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clusters[id]
	if !ok {
		return fmt.Errorf("%w: DB cluster %q", ErrNoSuchResource, id)
	}
	return fn(c)
}

// Authenticate reports whether username and password would log in to a cluster.
//
// It is the substrate operation the "a re-Ensure does not rotate the admin
// password" invariant needs, and there is no portable way to ask for it through
// [compute], which is why the conformance suite takes it as a hook. It compares
// through [credentials.Reveal] on both sides and returns a boolean: nothing here
// hands material back.
func (m *MemoryRDS) Authenticate(id, username string, password credentials.Secret) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clusters[id]
	if !ok {
		return false
	}
	return c.rec.MasterUsername == username &&
		credentials.Reveal(c.password) == credentials.Reveal(password) &&
		!password.IsZero()
}

// Dump renders every RDS resource, for the conformance suite's
// rendered-artefact invariants.
//
// The master password is not in it, and that is the invariant rather than an
// omission: "secret material appears in nothing the provider renders" is checked
// by searching exactly this output for the suite's sentinel.
func (m *MemoryRDS) Dump() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, id := range sortedMapKeys(m.clusters) {
		c := m.clusters[id]
		fields := []string{
			"engine=" + c.rec.Engine + "-" + c.rec.EngineVersion,
			"database=" + c.rec.DatabaseName,
			"user=" + c.rec.MasterUsername,
			"capacity=" + formatCapacity(c.rec.MinCapacity, c.rec.MaxCapacity),
			"encrypted=" + strconv.FormatBool(c.rec.StorageEncrypted),
			"subnet-group=" + c.rec.SubnetGroup,
			"security-groups=" + strings.Join(c.rec.SecurityGroupIDs, ","),
		}
		if pairs := sortedPairs(c.rec.Tags); pairs != "" {
			fields = append(fields, pairs)
		}
		out = append(out, fmt.Sprintf("Cluster %s: %s", c.rec.Identifier, strings.Join(fields, " ")))
	}
	for _, id := range sortedMapKeys(m.instances) {
		inst := m.instances[id]
		out = append(out, fmt.Sprintf("Instance %s: cluster=%s class=%s",
			inst.Identifier, inst.ClusterIdentifier, inst.Class))
	}
	for _, name := range sortedMapKeys(m.subnetGroups) {
		g := m.subnetGroups[name]
		out = append(out, fmt.Sprintf("SubnetGroup %s: subnets=%s",
			g.Name, strings.Join(g.SubnetIDs, ",")))
	}
	return out
}

// formatCapacity renders a capacity range the way the conformance suite's
// convergence marker expects to find it: the abstract units the caller asked
// for, not the ACUs this substrate stores.
//
// It is a translation back, and it is deliberately here rather than in the
// provider: the invariant is that a substrate observation stops showing a value
// the caller removed, so the observation has to be of what the substrate holds.
func formatCapacity(minACU, maxACU float64) string {
	return trimFloat(minACU/DefaultACUsPerUnit) + "-" + trimFloat(maxACU/DefaultACUsPerUnit)
}

func trimFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

func copySubnetGroup(in *SubnetGroupRecord) *SubnetGroupRecord {
	out := *in
	out.Tags = copyTags(in.Tags)
	out.SubnetIDs = append([]string(nil), in.SubnetIDs...)
	return &out
}

// --- DynamoDB ---------------------------------------------------------------

// MemoryDynamoDB is an in-memory key-value service.
type MemoryDynamoDB struct {
	failNext
	mu     sync.Mutex
	tables map[string]*memoryTable
}

type memoryTable struct {
	rec TableRecord
	// observations counts describes since creation, so the table becomes active
	// without a clock. A real table is CREATING first and the source system
	// polls DescribeTable sixty times waiting for ACTIVE (database.go:88-105).
	observations int
	stalled      bool
}

var _ DynamoDBAPI = (*MemoryDynamoDB)(nil)

// NewMemoryDynamoDB returns an empty key-value service.
func NewMemoryDynamoDB() *MemoryDynamoDB {
	return &MemoryDynamoDB{tables: map[string]*memoryTable{}}
}

// The DynamoDB status strings this substrate reports, which are DynamoDB's own.
const (
	tableStatusCreating = "CREATING"
	tableStatusActive   = "ACTIVE"
)

func tableARN(name string) string {
	return "arn:aws:dynamodb:" + MemoryRegion + ":" + MemoryAccount + ":table/" + name
}

// Stall makes a table stop converging. See [MemoryRDS.Stall] for why it resets
// the status rather than only setting a flag.
func (m *MemoryDynamoDB) Stall(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tables[name]; ok {
		t.stalled = true
		t.rec.Status = tableStatusCreating
		t.observations = 0
	}
}

// PutUnowned puts a table into the substrate without apphub's ownership tag.
func (m *MemoryDynamoDB) PutUnowned(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tables[name] = &memoryTable{rec: TableRecord{
		Name: name, ARN: tableARN(name), PartitionKey: "pk",
		Status: tableStatusActive,
		Tags:   map[string]string{"created-by": "somebody-else"},
	}}
}

// DescribeTable implements [DynamoDBAPI].
func (m *MemoryDynamoDB) DescribeTable(_ context.Context, name string) (*TableRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tables[name]
	if !ok {
		return nil, fmt.Errorf("%w: table %q", ErrNoSuchResource, name)
	}
	if t.rec.Status == tableStatusCreating && !t.stalled {
		t.observations++
		if t.observations >= memoryReadyAfter {
			t.rec.Status = tableStatusActive
		}
	}
	return copyTable(&t.rec), nil
}

// CreateTable implements [DynamoDBAPI].
func (m *MemoryDynamoDB) CreateTable(_ context.Context, in CreateTableRequest) (*TableRecord, error) {
	if err := m.take(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tables[in.Name]; ok {
		return nil, fmt.Errorf("%w: table %q", ErrAlreadyExists, in.Name)
	}
	t := &memoryTable{rec: TableRecord{
		Name: in.Name, ARN: tableARN(in.Name),
		PartitionKey: in.PartitionKey, SortKey: in.SortKey,
		Status: tableStatusCreating, Tags: copyTags(in.Tags),
	}}
	if t.rec.Tags == nil {
		t.rec.Tags = map[string]string{}
	}
	m.tables[in.Name] = t
	return copyTable(&t.rec), nil
}

// DeleteTable implements [DynamoDBAPI].
func (m *MemoryDynamoDB) DeleteTable(_ context.Context, name string) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tables[name]; !ok {
		return fmt.Errorf("%w: table %q", ErrNoSuchResource, name)
	}
	delete(m.tables, name)
	return nil
}

// ListTags implements [DynamoDBAPI].
func (m *MemoryDynamoDB) ListTags(_ context.Context, arn string) (map[string]string, error) {
	var out map[string]string
	err := m.withTableARN(arn, func(t *memoryTable) error {
		out = copyTags(t.rec.Tags)
		return nil
	})
	return out, err
}

// TagResource implements [DynamoDBAPI].
func (m *MemoryDynamoDB) TagResource(_ context.Context, arn string, tags map[string]string) error {
	return m.withTableARN(arn, func(t *memoryTable) error {
		for k, v := range tags {
			t.rec.Tags[k] = v
		}
		return nil
	})
}

// UntagResource implements [DynamoDBAPI].
func (m *MemoryDynamoDB) UntagResource(_ context.Context, arn string, keys []string) error {
	return m.withTableARN(arn, func(t *memoryTable) error {
		for _, k := range keys {
			delete(t.rec.Tags, k)
		}
		return nil
	})
}

func (m *MemoryDynamoDB) withTableARN(arn string, fn func(*memoryTable) error) error {
	if err := m.take(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tables {
		if t.rec.ARN == arn {
			return fn(t)
		}
	}
	return fmt.Errorf("%w: table %q", ErrNoSuchResource, arn)
}

// TableARN returns a table's ARN, for the conformance hooks that have to name a
// resource in a policy the way a data-plane request would.
func (m *MemoryDynamoDB) TableARN(name string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tables[name]
	if !ok {
		return "", false
	}
	return t.rec.ARN, true
}

// Dump renders every table.
func (m *MemoryDynamoDB) Dump() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, name := range sortedMapKeys(m.tables) {
		t := m.tables[name]
		fields := []string{"partition-key=" + t.rec.PartitionKey}
		if t.rec.SortKey != "" {
			fields = append(fields, "sort-key="+t.rec.SortKey)
		}
		for _, k := range sortedKeys(t.rec.Tags) {
			label, ok := strings.CutPrefix(k, tagLabelPrefix)
			if !ok {
				continue
			}
			fields = append(fields, label+"="+t.rec.Tags[k])
		}
		out = append(out, fmt.Sprintf("Table %s: %s", t.rec.Name, strings.Join(fields, " ")))
	}
	return out
}

func copyTable(in *TableRecord) *TableRecord {
	out := *in
	out.Tags = copyTags(in.Tags)
	return &out
}

// sortedMapKeys returns a map's keys in order, so that every Dump and every
// substrate walk is deterministic.
func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
