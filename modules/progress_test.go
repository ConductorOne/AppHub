// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package modules_test

import (
	"context"
	"sync"
	"testing"

	"github.com/conductorone/apphub/modules"
)

func TestReportProgressReachesTheReporter(t *testing.T) {
	t.Parallel()

	type report struct {
		progress int
		message  string
	}
	var got []report

	ctx := modules.WithProgress(context.Background(), func(_ context.Context, progress int, message string) {
		got = append(got, report{progress, message})
	})

	modules.ReportProgress(ctx, 0, "starting")
	modules.ReportProgress(ctx, 100, "done")

	want := []report{{0, "starting"}, {100, "done"}}
	if len(got) != len(want) {
		t.Fatalf("got %d reports, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("report %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// Reporting is best-effort: a module calls ReportProgress unconditionally, and a
// caller that did not ask for progress is not an error every module has to
// handle separately.
func TestReportProgressWithoutReporterIsANoOp(t *testing.T) {
	t.Parallel()

	modules.ReportProgress(context.Background(), 50, "nobody is listening")
}

// A nil ProgressFunc in the context is the same as none. Without the nil check
// this is a panic inside whichever module happened to report first.
func TestReportProgressWithNilReporterIsANoOp(t *testing.T) {
	t.Parallel()

	ctx := modules.WithProgress(context.Background(), nil)
	modules.ReportProgress(ctx, 50, "still nobody")
}

// The innermost reporter wins, so a caller can wrap a context it was handed and
// intercept the reports of the work it starts.
func TestWithProgressNestsInnermostFirst(t *testing.T) {
	t.Parallel()

	var outer, inner int

	ctx := modules.WithProgress(context.Background(), func(context.Context, int, string) { outer++ })
	ctx = modules.WithProgress(ctx, func(context.Context, int, string) { inner++ })

	modules.ReportProgress(ctx, 1, "m")

	if outer != 0 {
		t.Errorf("outer reporter called %d times, want 0", outer)
	}
	if inner != 1 {
		t.Errorf("inner reporter called %d times, want 1", inner)
	}
}

// The context carrying the reporter is the one the reporter is handed, so a
// reporter can read whatever else the module put in it.
func TestReporterReceivesTheReportingContext(t *testing.T) {
	t.Parallel()

	type markerKey struct{}
	var seen any

	ctx := modules.WithProgress(context.Background(), func(ctx context.Context, _ int, _ string) {
		seen = ctx.Value(markerKey{})
	})
	ctx = context.WithValue(ctx, markerKey{}, "marker")

	modules.ReportProgress(ctx, 1, "m")

	if seen != "marker" {
		t.Errorf("reporter saw marker value %v, want %q", seen, "marker")
	}
}

// A module that fans work out reports from several goroutines, so the documented
// requirement that a ProgressFunc be concurrency-safe has to be exercised under
// -race rather than asserted in a comment.
func TestReportProgressIsSafeFromManyGoroutines(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	count := 0

	ctx := modules.WithProgress(context.Background(), func(context.Context, int, string) {
		mu.Lock()
		defer mu.Unlock()
		count++
	})

	const goroutines = 16
	const perGoroutine = 32

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				modules.ReportProgress(ctx, i, "step")
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if want := goroutines * perGoroutine; count != want {
		t.Errorf("reporter called %d times, want %d", count, want)
	}
}
