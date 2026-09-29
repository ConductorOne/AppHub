// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/modules/deploy"
)

const (
	demoProvider = "aws"
	demoRegistry = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
)

// seedApplication writes one application and everything a successful history
// of deployments would have left behind, in a single transaction.
func (s *seeder) seedApplication(ctx context.Context, index int, app demoApp) (bool, error) {
	id := stableID("app:" + app.repo)
	appID := cp.RecordID{Kind: cp.ApplicationKind, ID: id}
	if _, err := s.repo.Read(ctx, appID); err == nil {
		return false, nil
	} else if !errors.Is(err, cp.ErrNotFound) {
		return false, err
	}

	rng := rngFor("app:" + app.repo)
	input := s.input(rng, app)
	mapped, err := cp.MapApplication(id, input, s.target)
	if err != nil {
		return false, fmt.Errorf("map specification: %w", err)
	}
	owners := s.owners(index)
	record := cp.ApplicationRecord{ID: id, Owners: owners, TargetID: s.target.ID, Input: input, Application: mapped}
	record.CreatedAt = s.now.Add(-days(rng, 14, 150))
	if host := cp.EffectiveHostname(id, input); host != "" {
		record.ReservedHostnames = []string{host}
	}

	history := s.history(rng, app, &record, owners)
	mutations := make([]cp.Mutation, 0, len(history)+8)
	for _, d := range history {
		m, err := newRecord(cp.RecordID{Kind: cp.DeploymentKind, ParentID: id, ID: d.ID}, d)
		if err != nil {
			return false, err
		}
		mutations = append(mutations, m)
	}
	appMutation, err := newRecord(appID, record)
	if err != nil {
		return false, err
	}
	ownerIndex, err := cp.OwnerIndexMutations(id, nil, owners, nil)
	if err != nil {
		return false, fmt.Errorf("owner index: %w", err)
	}
	mutations = append(append([]cp.Mutation{appMutation}, mutations...), ownerIndex...)
	for _, host := range record.ReservedHostnames {
		m, err := newRecord(cp.RecordID{Kind: cp.HostnameKind, ParentID: s.target.ID, ID: host}, cp.HostnameReservation{TargetID: s.target.ID, Hostname: host, ApplicationID: id})
		if err != nil {
			return false, err
		}
		mutations = append(mutations, m)
	}
	if usage, ok := s.usage(rng, app, record, history); ok {
		m, err := newRecord(cp.RecordID{Kind: cp.ApplicationUsageKind, ID: id}, usage)
		if err != nil {
			return false, err
		}
		mutations = append(mutations, m)
	}
	ctx = cp.WithAuditContext(ctx, owners[0].ID, "application.create", "application:"+id)
	if err := s.repo.Commit(ctx, mutations); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}

func (s *seeder) input(rng *rand.Rand, app demoApp) cp.ApplicationInput {
	sizes := s.target.ResourceSizes
	size := sizes[rng.IntN(min(2, len(sizes)))]
	replicas := 1
	if app.public {
		size = sizes[min(len(sizes)-1, 1+rng.IntN(len(sizes)))]
		replicas = min(s.target.MaxReplicas, 2+rng.IntN(2))
	} else if app.schedule == "" && rng.IntN(3) == 0 {
		replicas = min(s.target.MaxReplicas, 2)
	}
	in := cp.ApplicationInput{
		Name:      app.name,
		TargetID:  s.target.ID,
		Source:    cp.SourceInput{URL: repoURL(app), Ref: "main", Dockerfile: "Dockerfile"},
		Execution: deploy.ExecutionService,
		Port:      []int{8080, 3000, 8000}[rng.IntN(3)],
		Resources: size,
		Replicas:  replicas,
		Exposure:  cp.ExposureInput{Mode: "private"},
		Category:  app.category,
	}
	if app.schedule != "" {
		in.Execution = deploy.ExecutionScheduled
		in.Schedule = &cp.ScheduleInput{Expression: app.schedule, Timezone: "America/Los_Angeles"}
	} else {
		in.Exposure.Hostname = app.repo
	}
	if app.public {
		in.Exposure = cp.ExposureInput{Mode: "public", Hostname: app.repo, MCPAuthEnabled: app.mcp}
	}
	switch app.db {
	case postgres:
		capacity := cp.CapacityInput{MinUnits: 0.5, MaxUnits: 4}
		if app.public {
			capacity = cp.CapacityInput{MinUnits: 1, MaxUnits: 16}
		}
		in.Database = &cp.DatabaseInput{Kind: deploy.DatabaseRelational, Engine: compute.EnginePostgres, EngineVersion: "18",
			DatabaseName: strings.ReplaceAll(app.repo, "-", "_"), AdminUsername: cp.DefaultAdminUsername,
			Capacity: capacity, Extensions: slices.Clone(app.extensions)}
	case dynamo:
		in.Database = &cp.DatabaseInput{Kind: deploy.DatabaseKeyValue, PartitionKey: cp.DefaultPartitionKey, SortKey: cp.DefaultSortKey}
	case noDatabase:
	}
	if app.bucket {
		in.Bucket = &cp.BucketInput{Kind: deploy.BucketStandard, Access: compute.AccessReadWrite}
	}
	return in
}

// owners gives the signed-in user a quarter of the catalog outright and a
// share of the rest, so both "my applications" and the directory are full.
func (s *seeder) owners(index int) []cp.ApplicationOwner {
	primary := s.users[(index*5)%len(s.users)]
	if index%4 == 0 {
		primary = s.owner
	}
	owners := []cp.ApplicationOwner{{Kind: cp.OwnerUser, ID: primary}}
	add := func(o cp.ApplicationOwner) {
		if !slices.Contains(owners, o) {
			owners = append(owners, o)
		}
	}
	if index%3 == 1 {
		add(cp.ApplicationOwner{Kind: cp.OwnerUser, ID: s.users[(index*7+3)%len(s.users)]})
	}
	if index%5 == 2 {
		add(cp.ApplicationOwner{Kind: cp.OwnerUser, ID: s.owner})
	}
	return owners
}

// history builds the application's deployments oldest first and records
// their outcome on the application, as the worker would have.
func (s *seeder) history(rng *rand.Rand, app demoApp, rec *cp.ApplicationRecord, owners []cp.ApplicationOwner) []cp.DeploymentRecord {
	rec.Revision = 1
	rec.UpdatedAt = rec.CreatedAt
	rec.Secrets = s.secrets(rng, app, rec.CreatedAt, owners)
	rec.Application.EnvSecrets = secretNames(rec.Secrets)
	if app.scenario == draft {
		return nil
	}
	count := 2 + rng.IntN(7)
	if app.scenario == neverRan {
		count = 2
	}
	latestAge := time.Duration(1+rng.IntN(96)) * time.Hour
	if app.scenario == deploying {
		latestAge = 90 * time.Second
	}
	span := s.now.Add(-latestAge).Sub(rec.CreatedAt.Add(time.Hour))
	deployments := make([]cp.DeploymentRecord, 0, count)
	for k := range count {
		created := rec.CreatedAt.Add(time.Hour + span*time.Duration(k)/time.Duration(max(1, count-1)))
		if k == count-1 {
			created = s.now.Add(-latestAge)
		}
		state := s.stateFor(rng, app, k, count)
		requester := owners[k%len(owners)]
		if requester.Kind != cp.OwnerUser {
			requester = owners[0]
		}
		d := s.deployment(rng, app, rec, k, created, state, requester.ID)
		deployments = append(deployments, d)
		s.apply(rec, d)
	}
	return deployments
}

func (s *seeder) stateFor(rng *rand.Rand, app demoApp, k, count int) cp.DeploymentState {
	latest := k == count-1
	switch {
	case app.scenario == neverRan:
		return cp.Failed
	case latest && app.scenario == failedLatest:
		return cp.Failed
	case latest && app.scenario == deploying:
		return cp.Running
	case latest && app.scenario == interrupted:
		return cp.Interrupted
	case latest || k == 0:
		return cp.Succeeded
	case rng.IntN(8) == 0:
		return cp.Failed
	}
	return cp.Succeeded
}

func (s *seeder) deployment(rng *rand.Rand, app demoApp, rec *cp.ApplicationRecord, k int, created time.Time, state cp.DeploymentState, requester string) cp.DeploymentRecord {
	started := created.Add(time.Duration(3+rng.IntN(20)) * time.Second)
	duration := time.Duration(100+rng.IntN(260)) * time.Second
	if app.db == postgres && k == 0 {
		duration += 7 * time.Minute
	}
	commit := hexString(rng, 40)
	d := cp.DeploymentRecord{
		ID:                  stableID(fmt.Sprintf("deployment:%s:%d", app.repo, k)),
		ApplicationID:       rec.ID,
		RequesterUserID:     requester,
		Requester:           cp.Principal{UserID: requester, ProviderID: "google", Issuer: "https://accounts.google.com", Subject: "demo-" + requester[:8], Scopes: []string{cp.ApplicationsWrite, cp.DeploymentsWrite}},
		ApplicationRevision: int64(k + 1),
		TargetID:            rec.TargetID,
		Application:         rec.Application,
		RequestedSourceRef:  "main",
		ResolvedCommit:      commit,
		State:               state,
		AttemptID:           stableID(fmt.Sprintf("attempt:%s:%d", app.repo, k)),
		CreatedAt:           created,
		StartedAt:           started,
	}
	full := s.artifacts(rec, commit)
	switch state {
	case cp.Succeeded:
		d.FinishedAt = started.Add(duration)
		d.Progress, d.Step, d.Artifacts = "100%", "complete", full
		d.Addresses = slices.Clone(full.Addresses)
		d.Message = "Deployment ready."
		if app.schedule != "" {
			d.Message = "Schedule installed."
		}
	case cp.Failed:
		d.FinishedAt = started.Add(duration / 2)
		d.Artifacts = deploy.Artifacts{Repository: full.Repository, Identity: full.Identity, KeyValue: full.KeyValue, Relational: full.Relational}
		d.Progress, d.Step = "40%", "image-build"
		if rng.IntN(2) == 0 {
			d.Artifacts.Image = full.Image
			d.Progress, d.Step = "85%", "service-ready"
		}
		d.ErrorCode, d.Message = "deployment_failed", "Deployment failed. Partial resources may remain."
	case cp.Running:
		d.Artifacts = deploy.Artifacts{Repository: full.Repository, Identity: full.Identity, Relational: full.Relational}
		d.Progress, d.Step, d.StepStartedAt = "35%", "image-build", started.Add(20*time.Second)
		d.Message = "Deployment in progress."
	case cp.Interrupted:
		d.FinishedAt = started.Add(duration)
		d.Artifacts = deploy.Artifacts{Repository: full.Repository, Identity: full.Identity, Image: full.Image, KeyValue: full.KeyValue}
		d.Progress, d.Step = "70%", "service-ready"
		d.ErrorCode, d.Message = "deployment_interrupted", "Deployment outcome is uncertain. Operator resolution is required."
	case cp.Queued:
	}
	d.HeartbeatAt = d.FinishedAt
	if d.FinishedAt.IsZero() {
		d.HeartbeatAt = s.now
	}
	return d
}

// apply records a deployment's outcome on its application, as the worker's
// operation store does when an attempt finishes.
func (s *seeder) apply(rec *cp.ApplicationRecord, d cp.DeploymentRecord) {
	rec.Revision = d.ApplicationRevision
	rec.LatestDeploymentID = d.ID
	rec.UpdatedAt = d.CreatedAt
	rec.Application.Artifacts = d.Artifacts
	rec.Application.DeployStep = d.Step
	rec.ActiveDeploymentID = ""
	switch d.State {
	case cp.Succeeded:
		rec.Application.Status = deploy.StatusRunning
		rec.Application.LastDeployedAt = d.FinishedAt
		rec.LastSuccessfulDeploymentID = d.ID
		rec.LastSuccessfulArtifacts = d.Artifacts
		rec.LastDeployedAt = d.FinishedAt
		rec.Addresses = slices.Clone(d.Addresses)
	case cp.Running, cp.Queued:
		rec.Application.Status = deploy.StatusDeploying
		rec.ActiveDeploymentID = d.ID
	case cp.Interrupted:
		rec.Application.Status = deploy.StatusFailed
		rec.ActiveDeploymentID = d.ID
	case cp.Failed:
		rec.Application.Status = deploy.StatusFailed
	}
}

// artifacts names the resources a successful deploy of rec would own, in the
// AWS provider's "<resource>/<name>" reference shape.
func (s *seeder) artifacts(rec *cp.ApplicationRecord, commit string) deploy.Artifacts {
	prefix := s.target.DeployConfig.ResourcePrefix
	name := prefix + "-" + strings.ReplaceAll(rec.ID, "-", "")[:12]
	ref := func(kind compute.Kind, resource, id string) compute.Ref {
		return compute.Ref{Provider: demoProvider, Kind: kind, ID: resource + "/" + id}
	}
	a := deploy.Artifacts{
		Repository: ref(compute.KindImageRepository, "repository", prefix+"/"+rec.ID),
		Image:      compute.ImageRef(demoRegistry + "/" + prefix + "/" + rec.ID + "@sha256:" + hexString(rngFor(commit), 64)),
		Identity:   ref(compute.KindWorkloadIdentity, "role", name),
		Workload:   ref(compute.KindService, "service", name),
	}
	if rec.Input.Execution == deploy.ExecutionScheduled {
		a.Workload = ref(compute.KindScheduledJob, "schedule", name)
	}
	switch rec.Application.Database.Kind {
	case deploy.DatabaseRelational:
		a.Relational = ref(compute.KindRelational, "cluster", name)
	case deploy.DatabaseKeyValue:
		a.KeyValue = ref(compute.KindKeyValueTable, "table", name)
	case deploy.DatabaseNone:
	}
	if rec.Application.Bucket.Kind != deploy.BucketNone {
		a.Bucket = ref(compute.KindBucket, "bucket", name)
	}
	for _, secret := range rec.Secrets {
		if a.Secrets == nil {
			a.Secrets = map[string]compute.Ref{}
		}
		a.Secrets[secret.Name] = ref(compute.KindSecret, "parameter", "/"+prefix+"/apps/"+rec.ID+"/"+secret.Name)
	}
	if routes := rec.Application.Routes; len(routes) > 0 {
		domain := s.target.DeployConfig.RouteDomain
		if routes[0].Internal {
			domain = s.target.DeployConfig.InternalRouteDomain
		}
		a.Addresses = []string{"https://" + routes[0].Hostname + "." + domain}
	}
	return a
}

func (s *seeder) secrets(rng *rand.Rand, app demoApp, created time.Time, owners []cp.ApplicationOwner) []cp.SecretEntry {
	entries := make([]cp.SecretEntry, 0, len(app.secrets))
	for _, name := range app.secrets {
		updated := created.Add(time.Duration(rng.IntN(72)) * time.Hour)
		entries = append(entries, cp.SecretEntry{Name: name, UpdatedAt: updated, UpdatedBy: owners[0].ID})
	}
	return entries
}

func secretNames(entries []cp.SecretEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
}
