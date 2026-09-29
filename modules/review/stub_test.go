// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review_test

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"

	"github.com/conductorone/apphub/modules/review"
)

// A note on two field names in this file. The lifecycle log is `seq` and the
// opened pull request is `opened`, rather than the more natural alternatives,
// because the disclosure scan reads a dotted three-label token in a Go file as
// a hostname -- and both of those alternatives are delegated top-level
// domains, so a field of either name reached through two selectors reads as an
// internal host. `.gitleaks.toml` records that this collateral is accepted
// rather than tuned away, twice and with reasons, so the name gives way to the
// rule rather than the other way round. Renaming these back turns `make
// secrets` red, and writing the offending expression out even in a comment
// does the same -- which is how this paragraph got its second draft.

// Everything a test needs to drive the module is here, and none of it touches
// a network, a clock it does not control, a file, or a port. That is the whole
// point of the three interfaces the package declares.

// stubTree is an in-memory snapshot.
type stubTree struct {
	files map[string][]byte
	modes map[string]string
}

func newTree(files map[string]string) *stubTree {
	t := &stubTree{files: map[string][]byte{}, modes: map[string]string{}}
	for path, content := range files {
		t.files[path] = []byte(content)
	}
	return t
}

func (t *stubTree) List() []string {
	out := make([]string, 0, len(t.files))
	for p := range t.files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (t *stubTree) Read(p string) ([]byte, bool) {
	b, ok := t.files[p]
	return b, ok
}

func (t *stubTree) Mode(p string) (string, bool) {
	m, ok := t.modes[p]
	return m, ok
}

// stubFetcher returns a fixed snapshot or a fixed error, and records what it
// was asked for.
type stubFetcher struct {
	tree     review.Tree
	commit   string
	noSnap   bool
	err      error
	calls    int
	lastAt   review.Coordinates
	lastCapB int64
}

func (f *stubFetcher) Fetch(_ context.Context, at review.Coordinates, maxBytes int64) (*review.Snapshot, error) {
	f.calls++
	f.lastAt = at
	f.lastCapB = maxBytes
	if f.err != nil {
		return nil, f.err
	}
	if f.noSnap {
		return nil, nil
	}
	return &review.Snapshot{Tree: f.tree, Commit: f.commit}, nil
}

// stubScanner returns a fixed result or a fixed error, or both.
type stubScanner struct {
	result  *review.ScanResult
	err     error
	calls   int
	lastReq review.ScanRequest
}

func (s *stubScanner) Scan(_ context.Context, req review.ScanRequest) (*review.ScanResult, error) {
	s.calls++
	s.lastReq = req
	return s.result, s.err
}

// stubStore records every lifecycle call in order, so a test can state a
// property about the sequence rather than about one write.
type stubStore struct {
	seq []string

	markRunningErr error
	completeErr    error
	partialErr     error
	failErr        error

	completion  *review.Completion
	partialCost *review.Cost
	failMessage string
	failCalls   int
}

// Every method refuses a context that is already done, because that is what a
// real client does: an SDK short-circuits on ctx.Err() before it issues the
// request. A stub that ignored the context would accept a write on a cancelled
// one, and the whole reason terminal writes run on a context of their own is
// that the run's may be cancelled by the time they are needed.
func (s *stubStore) MarkRunning(ctx context.Context, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "MarkRunning")
	return s.markRunningErr
}

func (s *stubStore) Complete(ctx context.Context, _ string, c review.Completion) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "Complete")
	s.completion = &c
	return s.completeErr
}

func (s *stubStore) RecordPartialCost(ctx context.Context, _ string, cost review.Cost) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "RecordPartialCost")
	s.partialCost = &cost
	return s.partialErr
}

func (s *stubStore) Fail(ctx context.Context, _ string, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "Fail")
	s.failCalls++
	s.failMessage = message
	return s.failErr
}

// discardLogger writes nowhere. A test that wants the output builds its own.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testLimits() review.Limits {
	return review.Limits{
		MaxSourceBytes:       review.SuggestedMaxSourceBytes,
		TerminalWriteTimeout: 5 * time.Second,
	}
}

// harness is a wired module plus the stubs behind it.
type harness struct {
	module  *review.Module
	fetcher *stubFetcher
	scanner *stubScanner
	store   *stubStore
}

func newHarness(t *testing.T, mutate ...func(*harness)) *harness {
	t.Helper()
	h := &harness{
		fetcher: &stubFetcher{tree: newTree(map[string]string{"main.go": "package main\n"}), commit: "c0ffee1"},
		scanner: &stubScanner{result: &review.ScanResult{}},
		store:   &stubStore{},
	}
	for _, fn := range mutate {
		fn(h)
	}
	m, err := review.New(h.scanner, h.fetcher, h.store, discardLogger(), testLimits())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.module = m
	return h
}

// validParams is a complete, acceptable parameter map. Tests copy it and
// change one key, so what a case is about is the difference.
func validParams() map[string]any {
	return map[string]any{
		"scanId":         "scan-1",
		"owner":          "acme",
		"repo":           "widget",
		"ref":            "main",
		"mode":           string(review.ModeInstallation),
		"installationId": 42,
		"scanType":       string(review.DepthQuick),
	}
}

func with(params map[string]any, key string, value any) map[string]any {
	out := make(map[string]any, len(params)+1)
	for k, v := range params {
		out[k] = v
	}
	if value == nil {
		delete(out, key)
	} else {
		out[key] = value
	}
	return out
}
