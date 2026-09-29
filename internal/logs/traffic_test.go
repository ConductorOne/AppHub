// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type fakeInsights struct {
	started  *cloudwatchlogs.StartQueryInput
	statuses []cwtypes.QueryStatus
	rows     [][]cwtypes.ResultField
	startErr error
	stopped  bool
}

func (f *fakeInsights) StartQuery(_ context.Context, in *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	f.started = in
	if f.startErr != nil {
		return nil, f.startErr
	}
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("q1")}, nil
}

func (f *fakeInsights) GetQueryResults(_ context.Context, _ *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	status := f.statuses[0]
	if len(f.statuses) > 1 {
		f.statuses = f.statuses[1:]
	}
	return &cloudwatchlogs.GetQueryResultsOutput{Status: status, Results: f.rows}, nil
}

func (f *fakeInsights) StopQuery(_ context.Context, _ *cloudwatchlogs.StopQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	f.stopped = true
	return &cloudwatchlogs.StopQueryOutput{}, nil
}

func row(kv ...string) []cwtypes.ResultField {
	var out []cwtypes.ResultField
	for i := 0; i < len(kv); i += 2 {
		out = append(out, cwtypes.ResultField{Field: aws.String(kv[i]), Value: aws.String(kv[i+1])})
	}
	return out
}

func reader(t *testing.T, f *fakeInsights) *TrafficReader {
	t.Helper()
	r, err := NewTrafficReaderWithAPI(f, "/apphub/test/traefik")
	if err != nil {
		t.Fatal(err)
	}
	r.poll = time.Millisecond
	return r
}

func TestHourlyParsesServiceHoursAndSkipsMalformedRows(t *testing.T) {
	f := &fakeInsights{
		statuses: []cwtypes.QueryStatus{cwtypes.QueryStatusRunning, cwtypes.QueryStatusComplete},
		rows: [][]cwtypes.ResultField{
			row("hour", "2026-09-27 14:00:00.000", "ServiceName", "apphub-app-1@ecs", "class", "2", "requests", "40", "first", "2026-09-27 14:01:02.000", "last", "2026-09-27 14:59:00.000"),
			row("hour", "2026-09-27 14:00:00.000", "ServiceName", "apphub-app-1@ecs", "class", "5", "requests", "2", "first", "2026-09-27 14:10:00.000", "last", "2026-09-27 14:20:00.000"),
			row("hour", "not a time", "ServiceName", "x@ecs", "class", "2", "requests", "1"),
			row("hour", "2026-09-27 14:00:00.000", "ServiceName", "", "class", "2", "requests", "1"),
		},
	}
	start := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	got, err := reader(t, f).Hourly(context.Background(), start, start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Service != "apphub-app-1" || got[0].Class != 2 || got[0].Requests != 40 || got[1].Class != 5 {
		t.Fatalf("got %+v", got)
	}
	if !got[0].Last.Equal(time.Date(2026, 9, 27, 14, 59, 0, 0, time.UTC)) {
		t.Errorf("last = %v", got[0].Last)
	}
	if aws.ToInt64(f.started.StartTime) != start.Unix() || aws.ToInt64(f.started.EndTime) != start.Add(2*time.Hour).Unix()-1 {
		t.Errorf("query window %d..%d; want the half-open hours", aws.ToInt64(f.started.StartTime), aws.ToInt64(f.started.EndTime))
	}
}

func TestHourlyFailuresAreGeneric(t *testing.T) {
	start := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	f := &fakeInsights{startErr: errors.New("AccessDeniedException: arn:aws:iam::x:role/worker")}
	if _, err := reader(t, f).Hourly(context.Background(), start, start.Add(time.Hour)); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "arn:") {
		t.Fatalf("got %v; want a generic unavailable error", err)
	}
	f = &fakeInsights{statuses: []cwtypes.QueryStatus{cwtypes.QueryStatusFailed}}
	if _, err := reader(t, f).Hourly(context.Background(), start, start.Add(time.Hour)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v; want unavailable for a failed query", err)
	}
	if _, err := reader(t, &fakeInsights{}).Hourly(context.Background(), start.Add(time.Minute), start.Add(time.Hour)); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("got %v; want a refusal for a partial hour", err)
	}
}

func TestHourlyStopsAQueryThatOutlivesItsContext(t *testing.T) {
	start := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	f := &fakeInsights{statuses: []cwtypes.QueryStatus{cwtypes.QueryStatusRunning}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := reader(t, f).Hourly(ctx, start, start.Add(time.Hour)); !errors.Is(err, ErrUnavailable) || !f.stopped {
		t.Fatalf("got %v stopped=%t; want the query stopped", err, f.stopped)
	}
}
