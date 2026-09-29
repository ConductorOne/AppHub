// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane_test

import (
	"testing"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func hourAt(h int) time.Time { return time.Date(2026, 9, 27, h, 0, 0, 0, time.UTC) }

func observation(h int, requests int64) cp.UsageObservation {
	return cp.UsageObservation{Bucket: cp.UsageBucket{Hour: hourAt(h), Requests: requests, Status2xx: requests}, First: hourAt(h).Add(time.Minute), Last: hourAt(h).Add(50 * time.Minute)}
}

func TestMergeUsageReplacesRecomputedHoursInsteadOfAddingThem(t *testing.T) {
	now := hourAt(15).Add(10 * time.Minute)
	rec := cp.MergeUsage(cp.ApplicationUsageRecord{ID: "a"}, hourAt(13), hourAt(16), []cp.UsageObservation{observation(13, 5), observation(14, 7)}, now)
	again := cp.MergeUsage(rec, hourAt(13), hourAt(16), []cp.UsageObservation{observation(13, 5), observation(14, 9)}, now)
	if len(again.Buckets) != 2 || again.Buckets[0].Requests != 5 || again.Buckets[1].Requests != 9 {
		t.Fatalf("buckets = %+v; want the recomputed counts, not their sum", again.Buckets)
	}
	if !again.FirstRequestAt.Equal(hourAt(13).Add(time.Minute)) || !again.LastRequestAt.Equal(hourAt(14).Add(50*time.Minute)) {
		t.Errorf("first %v last %v", again.FirstRequestAt, again.LastRequestAt)
	}
	outside := cp.MergeUsage(again, hourAt(14), hourAt(16), nil, now)
	if len(outside.Buckets) != 1 || !outside.Buckets[0].Hour.Equal(hourAt(13)) {
		t.Fatalf("buckets = %+v; want the hour outside the window kept and the empty one inside it dropped", outside.Buckets)
	}
	if !outside.FirstRequestAt.Equal(again.FirstRequestAt) {
		t.Error("an empty window moved the first request time")
	}
}

func TestMergeUsageDropsHoursPastRetention(t *testing.T) {
	now := hourAt(15)
	old := cp.UsageBucket{Hour: now.Add(-cp.UsageRetention - time.Hour), Requests: 3}
	rec := cp.MergeUsage(cp.ApplicationUsageRecord{ID: "a", Buckets: []cp.UsageBucket{old}}, hourAt(14), hourAt(16), []cp.UsageObservation{observation(14, 1)}, now)
	if len(rec.Buckets) != 1 || !rec.Buckets[0].Hour.Equal(hourAt(14)) {
		t.Fatalf("buckets = %+v; want only the recent hour", rec.Buckets)
	}
}

func TestGetUsageFiltersTheRangeAndReportsWhatIsTracked(t *testing.T) {
	f := newServiceFixture(t)
	service, err := cp.NewService(f.repo, f.eligibility, map[string]cp.TargetPolicy{f.target.ID: f.target}, cp.WithTrafficCollection(true))
	if err != nil {
		t.Fatal(err)
	}
	f.service = service
	app := f.create(t, "usage")
	now := time.Now().UTC().Truncate(time.Hour)
	storeValue(t, f.repo, cp.RecordID{Kind: cp.ApplicationUsageKind, ID: app.ID}, cp.ApplicationUsageRecord{ID: app.ID, Buckets: []cp.UsageBucket{
		{Hour: now.Add(-3 * 24 * time.Hour), Requests: 10},
		{Hour: now.Add(-2 * time.Hour), Requests: 4},
	}, FirstRequestAt: now.Add(-3 * 24 * time.Hour), LastRequestAt: now.Add(-time.Hour)})

	day, err := f.service.GetUsage(t.Context(), f.owner, app.ID, "24h")
	if err != nil || day.TotalRequests != 4 || len(day.Buckets) != 1 || !day.Collecting || day.Tracked {
		t.Fatalf("24h = %+v, %v; want one bucket, collecting, and untracked for a private app", day, err)
	}
	week, err := f.service.GetUsage(t.Context(), f.owner, app.ID, "")
	if err != nil || week.Range != "7d" || week.TotalRequests != 14 || week.FirstRequestAt == nil {
		t.Fatalf("default range = %+v, %v; want 7d with both buckets", week, err)
	}
	_, err = f.service.GetUsage(t.Context(), f.owner, app.ID, "1y")
	requireProblem(t, err, 400, "invalid_range")
	_, err = f.service.GetUsage(t.Context(), f.other, app.ID, "7d")
	requireProblem(t, err, 404, "")

	fresh := f.create(t, "no-traffic")
	empty, err := f.service.GetUsage(t.Context(), f.owner, fresh.ID, "7d")
	if err != nil || empty.Buckets == nil || empty.TotalRequests != 0 || empty.FirstRequestAt != nil {
		t.Fatalf("no traffic = %+v, %v; want an empty, never-seen view", empty, err)
	}
}
