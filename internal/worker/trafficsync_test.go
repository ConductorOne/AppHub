// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/testutil"
)

type fakeTraffic struct {
	rows    []ServiceHour
	err     error
	windows [][2]time.Time
}

func (f *fakeTraffic) Hourly(_ context.Context, start, end time.Time) ([]ServiceHour, error) {
	f.windows = append(f.windows, [2]time.Time{start, end})
	return f.rows, f.err
}

func trafficApp(t *testing.T, repo cp.Repository, id, service string) {
	t.Helper()
	app := cp.ApplicationRecord{ID: id, Owners: []cp.ApplicationOwner{{Kind: cp.OwnerUser, ID: "owner"}}, TargetID: "test", Revision: 1}
	app.Application.Artifacts.Workload = compute.Ref{Provider: "aws", Kind: compute.KindService, ID: "service/" + service}
	putWorkerRecord(t, repo, cp.RecordID{Kind: cp.ApplicationKind, ID: id}, app)
}

func TestTrafficSyncStoresHourlyCountsPerApplicationWithoutDoubleCounting(t *testing.T) {
	repo := testutil.NewRepository()
	trafficApp(t, repo, "app-one", "apphub-one")
	trafficApp(t, repo, "app-two", "apphub-two")
	hour := time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)
	traffic := &fakeTraffic{rows: []ServiceHour{
		{Service: "apphub-one", Hour: hour, Class: 2, Requests: 40, First: hour.Add(time.Minute), Last: hour.Add(30 * time.Minute)},
		{Service: "apphub-one", Hour: hour, Class: 5, Requests: 2, First: hour.Add(5 * time.Minute), Last: hour.Add(40 * time.Minute)},
		{Service: "someone-elses", Hour: hour, Class: 2, Requests: 99},
	}}
	s, err := NewTrafficSyncer(repo, traffic)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return hour.Add(45 * time.Minute) }

	s.tick(context.Background())
	s.tick(context.Background())

	rec := readWorkerRecord[cp.ApplicationUsageRecord](t, repo, cp.RecordID{Kind: cp.ApplicationUsageKind, ID: "app-one"})
	if len(rec.Buckets) != 1 {
		t.Fatalf("buckets = %+v", rec.Buckets)
	}
	b := rec.Buckets[0]
	if b.Requests != 42 || b.Status2xx != 40 || b.Status5xx != 2 {
		t.Fatalf("bucket = %+v; want 42 requests (40 2xx, 2 5xx) after two identical syncs", b)
	}
	if !rec.LastRequestAt.Equal(hour.Add(40*time.Minute)) || !rec.FirstRequestAt.Equal(hour.Add(time.Minute)) {
		t.Errorf("first %v last %v", rec.FirstRequestAt, rec.LastRequestAt)
	}
	if _, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.ApplicationUsageKind, ID: "app-two"}); !errors.Is(err, cp.ErrNotFound) {
		t.Error("an application with no traffic got a usage record")
	}
	if got := traffic.windows[0][1].Sub(traffic.windows[0][0]); got != trafficBackfill {
		t.Errorf("first sync covered %v; want the %v backfill", got, trafficBackfill)
	}
	if got := traffic.windows[1][1].Sub(traffic.windows[1][0]); got != trafficWindow {
		t.Errorf("later sync covered %v; want %v", got, trafficWindow)
	}
}

func TestAFailedTrafficQueryKeepsWhatWasStored(t *testing.T) {
	repo := testutil.NewRepository()
	trafficApp(t, repo, "app-one", "apphub-one")
	hour := time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)
	traffic := &fakeTraffic{rows: []ServiceHour{{Service: "apphub-one", Hour: hour, Class: 2, Requests: 5}}}
	s, _ := NewTrafficSyncer(repo, traffic)
	s.now = func() time.Time { return hour.Add(time.Minute) }
	s.tick(context.Background())
	traffic.err = errors.New("unavailable")
	s.tick(context.Background())
	rec := readWorkerRecord[cp.ApplicationUsageRecord](t, repo, cp.RecordID{Kind: cp.ApplicationUsageKind, ID: "app-one"})
	if len(rec.Buckets) != 1 || rec.Buckets[0].Requests != 5 {
		t.Fatalf("a failed sync changed stored usage: %+v", rec.Buckets)
	}
	if s.synced != true {
		t.Error("the successful first sync was not remembered")
	}
}
