// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"errors"
	"sort"
	"time"
)

// Traffic is counted from ingress access logs by the worker (see
// internal/worker/trafficsync.go) and stored as one record per application
// holding hourly buckets. One record rather than one row per hour because the
// repository has no range query, 30 days of hours is at most 720 small
// entries, and a whole-record write lets the worker replace recomputed hours
// under optimistic concurrency instead of incrementing counters it could
// double-apply on a retry.

// UsageRetention is how long hourly buckets are kept.
const UsageRetention = 30 * 24 * time.Hour

// ApplicationUsageKind stores one application's traffic buckets.
const ApplicationUsageKind RecordKind = "applicationUsage"

// UsageBucket is one UTC hour of requests to an application's routes.
type UsageBucket struct {
	Hour      time.Time `json:"hour"`
	Requests  int64     `json:"requests"`
	Status2xx int64     `json:"status2xx"`
	Status3xx int64     `json:"status3xx"`
	Status4xx int64     `json:"status4xx"`
	Status5xx int64     `json:"status5xx"`
}

// ApplicationUsageRecord is an application's recorded traffic. ID is the
// application ID.
type ApplicationUsageRecord struct {
	ID             string        `json:"id"`
	Buckets        []UsageBucket `json:"buckets"`
	FirstRequestAt time.Time     `json:"firstRequestAt"`
	LastRequestAt  time.Time     `json:"lastRequestAt"`
	CollectedAt    time.Time     `json:"collectedAt"`
}

// UsageObservation is one recomputed hour for one application: the complete
// count for that hour as of the query, never a delta.
type UsageObservation struct {
	Bucket UsageBucket
	First  time.Time
	Last   time.Time
}

// MergeUsage replaces every hour in [windowStart, windowEnd) with what was
// observed (an hour absent from observed had no requests), keeps hours
// outside the window, drops hours older than the retention period, and
// advances the first and last request times. Replacing rather than adding is
// what makes a repeated sync of an overlapping window harmless.
func MergeUsage(rec ApplicationUsageRecord, windowStart, windowEnd time.Time, observed []UsageObservation, now time.Time) ApplicationUsageRecord {
	cutoff := now.Add(-UsageRetention).Truncate(time.Hour)
	byHour := map[time.Time]UsageBucket{}
	for _, b := range rec.Buckets {
		inWindow := !b.Hour.Before(windowStart) && b.Hour.Before(windowEnd)
		if !inWindow && !b.Hour.Before(cutoff) {
			byHour[b.Hour] = b
		}
	}
	for _, o := range observed {
		hour := o.Bucket.Hour.UTC().Truncate(time.Hour)
		if o.Bucket.Requests <= 0 || hour.Before(cutoff) {
			continue
		}
		b := o.Bucket
		b.Hour = hour
		byHour[hour] = b
		if !o.First.IsZero() && (rec.FirstRequestAt.IsZero() || o.First.Before(rec.FirstRequestAt)) {
			rec.FirstRequestAt = o.First.UTC()
		}
		if o.Last.After(rec.LastRequestAt) {
			rec.LastRequestAt = o.Last.UTC()
		}
	}
	rec.Buckets = make([]UsageBucket, 0, len(byHour))
	for _, b := range byHour {
		rec.Buckets = append(rec.Buckets, b)
	}
	sort.Slice(rec.Buckets, func(i, j int) bool { return rec.Buckets[i].Hour.Before(rec.Buckets[j].Hour) })
	rec.CollectedAt = now.UTC()
	return rec
}

// UsageView is an application's traffic over one window.
type UsageView struct {
	Range          string        `json:"range"`
	Since          time.Time     `json:"since"`
	Buckets        []UsageBucket `json:"buckets"`
	TotalRequests  int64         `json:"totalRequests"`
	FirstRequestAt *time.Time    `json:"firstRequestAt,omitempty"`
	LastRequestAt  *time.Time    `json:"lastRequestAt,omitempty"`
	CollectedAt    *time.Time    `json:"collectedAt,omitempty"`
	Collecting     bool          `json:"collecting"`
	Tracked        bool          `json:"tracked"`
}

var usageRanges = map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

// WithTrafficCollection reports that the worker collects traffic. It changes
// only what GetUsage says about an empty record: without collection, no
// traffic is "unknown", not "none".
func WithTrafficCollection(enabled bool) ServiceOption {
	return func(s *Service) { s.trafficCollection = enabled }
}

// GetUsage returns an application's hourly traffic for a range of 24h, 7d or
// 30d (default 7d).
func (s *Service) GetUsage(ctx context.Context, p Principal, appID, window string) (UsageView, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return UsageView{}, err
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return UsageView{}, err
	}
	if window == "" {
		window = "7d"
	}
	span, ok := usageRanges[window]
	if !ok {
		return UsageView{}, Problem(400, "invalid_range", "Use a range of 24h, 7d or 30d.")
	}
	app, _, err := s.application(ctx, p, appID)
	if err != nil {
		return UsageView{}, err
	}
	now := time.Now().UTC()
	since := now.Add(-span).Truncate(time.Hour).Add(time.Hour)
	view := UsageView{Range: window, Since: since, Buckets: []UsageBucket{}, Collecting: s.trafficCollection, Tracked: len(app.Application.Routes) > 0}
	rec, err := s.usage(ctx, appID)
	if err != nil {
		return UsageView{}, err
	}
	for _, b := range rec.Buckets {
		if !b.Hour.Before(since) {
			view.Buckets = append(view.Buckets, b)
			view.TotalRequests += b.Requests
		}
	}
	view.FirstRequestAt = optionalTime(rec.FirstRequestAt)
	view.LastRequestAt = optionalTime(rec.LastRequestAt)
	view.CollectedAt = optionalTime(rec.CollectedAt)
	return view, nil
}

func (s *Service) usage(ctx context.Context, appID string) (ApplicationUsageRecord, error) {
	r, err := s.repo.Read(ctx, RecordID{Kind: ApplicationUsageKind, ID: appID})
	if errors.Is(err, ErrNotFound) {
		return ApplicationUsageRecord{ID: appID}, nil
	}
	if err != nil {
		return ApplicationUsageRecord{}, unavailable()
	}
	rec, err := Decode[ApplicationUsageRecord](r)
	if err != nil || rec.ID != appID {
		return ApplicationUsageRecord{}, unavailable()
	}
	return rec, nil
}

func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
