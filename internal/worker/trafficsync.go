// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"log/slog"
	"path"
	"time"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
)

const (
	// trafficSyncInterval is how stale the portal's traffic may be.
	trafficSyncInterval = 5 * time.Minute
	// trafficWindow is how many trailing hours each sync recomputes: the
	// current hour and the one before, so a request logged just after an
	// hour boundary still lands in the hour it was made in.
	trafficWindow = 2 * time.Hour
	// trafficBackfill is the first sync's window after the worker starts, so
	// a restart or a newly enabled installation shows the last day at once.
	trafficBackfill = 24 * time.Hour
	trafficTimeout  = 3 * time.Minute
)

// ServiceHour is one ingress service's requests of one status class (2 for
// 2xx, and so on) in one UTC hour.
type ServiceHour struct {
	Service  string
	Hour     time.Time
	Class    int
	Requests int64
	First    time.Time
	Last     time.Time
}

// TrafficSource counts ingress requests per service over whole UTC hours. The
// composition root adapts internal/logs.TrafficReader to it, which keeps this
// package clear of the AWS SDK.
type TrafficSource interface {
	Hourly(ctx context.Context, start, end time.Time) ([]ServiceHour, error)
}

// TrafficSyncer periodically counts each application's ingress requests from
// the access log and stores them as hourly buckets (see
// internal/controlplane/usage.go).
//
// It runs alongside Dispatcher for the same reason DirectorySyncer does: it
// touches no deployment or provider state. Every sync recomputes whole hours
// and replaces them, so running it twice, or on two workers at once, stores
// the same numbers rather than twice the numbers.
type TrafficSyncer struct {
	repo    cp.Repository
	traffic TrafficSource
	now     func() time.Time
	synced  bool
}

// NewTrafficSyncer constructs a TrafficSyncer over an access-log source.
func NewTrafficSyncer(repo cp.Repository, traffic TrafficSource) (*TrafficSyncer, error) {
	if repo == nil || traffic == nil {
		return nil, errors.New("traffic syncer requires a repository and an access-log reader")
	}
	return &TrafficSyncer{repo: repo, traffic: traffic, now: time.Now}, nil
}

// Run polls until ctx is done. A failed sync is logged and retried on the next
// tick; the portal shows what was last stored.
func (t *TrafficSyncer) Run(ctx context.Context) error {
	ticker := time.NewTicker(trafficSyncInterval)
	defer ticker.Stop()
	for {
		t.tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (t *TrafficSyncer) tick(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, trafficTimeout)
	defer cancel()
	now := t.now().UTC()
	end := now.Truncate(time.Hour).Add(time.Hour)
	window := trafficWindow
	if !t.synced {
		window = trafficBackfill
	}
	start := end.Add(-window)
	rows, err := t.traffic.Hourly(ctx, start, end)
	if err != nil {
		slog.Warn("traffic sync failed", "err", err)
		return
	}
	services, err := t.services(ctx)
	if err != nil {
		slog.Warn("traffic sync could not list applications", "err", err)
		return
	}
	observed := map[string]map[time.Time]*cp.UsageObservation{}
	for _, r := range rows {
		appID, ok := services[r.Service]
		if !ok {
			continue
		}
		hours := observed[appID]
		if hours == nil {
			hours = map[time.Time]*cp.UsageObservation{}
			observed[appID] = hours
		}
		addServiceHour(hours, r)
	}
	written := 0
	for appID, hours := range observed {
		if t.store(ctx, appID, start, end, hours, now) {
			written++
		}
	}
	t.synced = true
	slog.Info("traffic synced", "applications", written, "rows", len(rows))
}

func addServiceHour(hours map[time.Time]*cp.UsageObservation, r ServiceHour) {
	o := hours[r.Hour]
	if o == nil {
		o = &cp.UsageObservation{Bucket: cp.UsageBucket{Hour: r.Hour}}
		hours[r.Hour] = o
	}
	o.Bucket.Requests += r.Requests
	switch r.Class {
	case 2:
		o.Bucket.Status2xx += r.Requests
	case 3:
		o.Bucket.Status3xx += r.Requests
	case 4:
		o.Bucket.Status4xx += r.Requests
	case 5:
		o.Bucket.Status5xx += r.Requests
	}
	if !r.First.IsZero() && (o.First.IsZero() || r.First.Before(o.First)) {
		o.First = r.First
	}
	if r.Last.After(o.Last) {
		o.Last = r.Last
	}
}

// services maps each deployed application's ingress service name to its ID.
// The name is the last path element of the workload reference the provider
// issued, which is the ECS service name the provider also writes into the
// service's ingress labels (compute/aws routes.go); an application whose
// workload is not a service has no ingress traffic to count.
func (t *TrafficSyncer) services(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	cursor := ""
	for {
		page, err := t.repo.Query(ctx, cp.Query{Kind: cp.ApplicationKind, Limit: 100, Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, r := range page.Records {
			app, err := cp.Decode[cp.ApplicationRecord](r)
			if err != nil {
				continue
			}
			for _, ref := range []compute.Ref{app.Application.Artifacts.Workload, app.LastSuccessfulArtifacts.Workload} {
				if ref.Kind == compute.KindService && ref.ID != "" {
					out[path.Base(ref.ID)] = app.ID
				}
			}
		}
		if page.Cursor == "" {
			return out, nil
		}
		cursor = page.Cursor
	}
}

// store merges one application's recomputed hours. A conflict means another
// worker wrote the same hours a moment ago; the next tick recomputes anyway.
func (t *TrafficSyncer) store(ctx context.Context, appID string, start, end time.Time, hours map[time.Time]*cp.UsageObservation, now time.Time) bool {
	id := cp.RecordID{Kind: cp.ApplicationUsageKind, ID: appID}
	rec := cp.ApplicationUsageRecord{ID: appID}
	var version int64
	current, err := t.repo.Read(ctx, id)
	switch {
	case err == nil:
		if rec, err = cp.Decode[cp.ApplicationUsageRecord](current); err != nil || rec.ID != appID {
			return false
		}
		version = current.Version
	case !errors.Is(err, cp.ErrNotFound):
		return false
	}
	observed := make([]cp.UsageObservation, 0, len(hours))
	for _, o := range hours {
		observed = append(observed, *o)
	}
	rec = cp.MergeUsage(rec, start, end, observed, now)
	record, err := cp.Encode(id, version+1, rec)
	if err != nil {
		return false
	}
	return t.repo.Commit(ctx, []cp.Mutation{{Record: record, ExpectedVersion: version}}) == nil
}
