// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/conductorone/apphub/modules/fix"
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

// stubFetcher returns a fixed snapshot or a fixed error.
type stubFetcher struct {
	tree   review.Tree
	commit string
	noSnap bool
	err    error
	calls  int
	lastAt review.Coordinates
}

func (f *stubFetcher) Fetch(_ context.Context, at review.Coordinates, _ int64) (*review.Snapshot, error) {
	f.calls++
	f.lastAt = at
	if f.err != nil {
		return nil, f.err
	}
	if f.noSnap {
		return nil, nil
	}
	return &review.Snapshot{Tree: f.tree, Commit: f.commit}, nil
}

// stubFixer returns fixed answers and records what it was asked.
type stubFixer struct {
	verdict     *fix.VerdictResult
	verdictErr  error
	patch       *fix.Patch
	patchErr    error
	validateN   int
	proposeN    int
	lastRequest fix.Request
}

func (f *stubFixer) Validate(_ context.Context, req fix.Request) (*fix.VerdictResult, error) {
	f.validateN++
	f.lastRequest = req
	return f.verdict, f.verdictErr
}

func (f *stubFixer) Propose(_ context.Context, req fix.Request) (*fix.Patch, error) {
	f.proposeN++
	f.lastRequest = req
	return f.patch, f.patchErr
}

// stubScans reads the parent scan.
type stubScans struct {
	scan *fix.Scan
	err  error
}

func (s *stubScans) Scan(context.Context, string) (*fix.Scan, error) { return s.scan, s.err }

// stubGit records the whole write sequence, which is what most of the push
// tests are about: the order matters, and so does the fact that nothing is
// written before the limits have been checked.
type stubGit struct {
	seq []string

	defaultBranch string
	branchHeads   map[string]string
	tags          map[string]bool

	defaultBranchErr error
	branchHeadErr    error
	createRefErr     error
	createRefFails   int // fail the first N CreateBranch calls with ErrRefExists
	openPRErr        error
	addLabelsErr     error

	blobs     [][]byte
	entries   []fix.TreeEntry
	message   string
	baseTree  string
	branches  []string
	opened    fix.PullRequest
	labels    []string
	labelCall int
}

func newGit() *stubGit {
	return &stubGit{
		defaultBranch: "main",
		branchHeads:   map[string]string{"main": "basesha"},
		tags:          map[string]bool{},
	}
}

func (g *stubGit) DefaultBranch(context.Context, fix.Coordinates) (string, error) {
	g.seq = append(g.seq, "DefaultBranch")
	return g.defaultBranch, g.defaultBranchErr
}

func (g *stubGit) BranchHead(_ context.Context, _ fix.Coordinates, branch string) (string, error) {
	g.seq = append(g.seq, "BranchHead:"+branch)
	if g.branchHeadErr != nil {
		return "", g.branchHeadErr
	}
	return g.branchHeads[branch], nil
}

func (g *stubGit) TagExists(_ context.Context, _ fix.Coordinates, tag string) (bool, error) {
	g.seq = append(g.seq, "TagExists:"+tag)
	return g.tags[tag], nil
}

func (g *stubGit) CommitTree(_ context.Context, _ fix.Coordinates, commitSHA string) (string, error) {
	g.seq = append(g.seq, "CommitTree:"+commitSHA)
	return "basetree", nil
}

func (g *stubGit) CreateBlob(_ context.Context, _ fix.Coordinates, content []byte) (string, error) {
	g.seq = append(g.seq, "CreateBlob")
	g.blobs = append(g.blobs, content)
	return fmt.Sprintf("blob%d", len(g.blobs)), nil
}

func (g *stubGit) CreateTree(_ context.Context, _ fix.Coordinates, baseTreeSHA string, entries []fix.TreeEntry) (string, error) {
	g.seq = append(g.seq, "CreateTree")
	g.baseTree = baseTreeSHA
	g.entries = entries
	return "newtree", nil
}

func (g *stubGit) CreateCommit(_ context.Context, _ fix.Coordinates, message, _, _ string) (string, error) {
	g.seq = append(g.seq, "CreateCommit")
	g.message = message
	return "newcommit", nil
}

func (g *stubGit) CreateBranch(_ context.Context, _ fix.Coordinates, branch, _ string) error {
	g.seq = append(g.seq, "CreateBranch:"+branch)
	g.branches = append(g.branches, branch)
	if g.createRefErr != nil {
		return g.createRefErr
	}
	if len(g.branches) <= g.createRefFails {
		return fmt.Errorf("taken: %w", fix.ErrRefExists)
	}
	return nil
}

func (g *stubGit) OpenPullRequest(_ context.Context, _ fix.Coordinates, pr fix.PullRequest) (*fix.PullRequestResult, error) {
	g.seq = append(g.seq, "OpenPullRequest")
	g.opened = pr
	if g.openPRErr != nil {
		return nil, g.openPRErr
	}
	return &fix.PullRequestResult{Number: 7, URL: "pull/7"}, nil
}

func (g *stubGit) AddLabels(_ context.Context, _ fix.Coordinates, _ int, labels []string) error {
	g.seq = append(g.seq, "AddLabels")
	g.labelCall++
	g.labels = labels
	return g.addLabelsErr
}

// stubStore records the lifecycle. As in modules/review it refuses a context
// that is already done, so a terminal write on a derived context fails here
// exactly as it would against a real client.
type stubStore struct {
	seq []string

	markRunningErr error
	completeErr    error
	failErr        error

	outcome     *fix.Outcome
	verdict     *fix.VerdictResult
	patchFiles  []fix.FileChange
	patchLines  int
	cost        *review.Cost
	costCalls   int
	failMessage string
	failCalls   int
}

func (s *stubStore) MarkRunning(ctx context.Context, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "MarkRunning")
	return s.markRunningErr
}

func (s *stubStore) MarkStatus(ctx context.Context, _ string, status fix.Status) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "MarkStatus:"+string(status))
	return nil
}

func (s *stubStore) RecordVerdict(ctx context.Context, _ string, v fix.VerdictResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "RecordVerdict")
	s.verdict = &v
	return nil
}

func (s *stubStore) RecordPatch(ctx context.Context, _ string, files []fix.FileChange, _ string, lines int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "RecordPatch")
	s.patchFiles = files
	s.patchLines = lines
	return nil
}

func (s *stubStore) RecordCost(ctx context.Context, _ string, cost review.Cost) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "RecordCost")
	s.costCalls++
	s.cost = &cost
	return nil
}

func (s *stubStore) FinalizeRejected(ctx context.Context, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "FinalizeRejected")
	return nil
}

func (s *stubStore) Complete(ctx context.Context, _ string, o fix.Outcome) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq = append(s.seq, "Complete")
	s.outcome = &o
	return s.completeErr
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

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type harness struct {
	module  *fix.Module
	fixer   *stubFixer
	fetcher *stubFetcher
	git     *stubGit
	scans   *stubScans
	store   *stubStore
}

func newHarness(t *testing.T, mutate ...func(*harness)) *harness {
	t.Helper()
	tree := newTree(map[string]string{"a.go": "package a\n", "b.sh": "#!/bin/sh\n"})
	tree.modes["b.sh"] = fix.ModeExecutable
	h := &harness{
		fixer: &stubFixer{
			// Both steps report a cost by default, so the default sequence a
			// test asserts on includes the ledger write. A default that spent
			// nothing would make every ordering assertion quieter than the
			// thing it is about.
			verdict: &fix.VerdictResult{
				Verdict: fix.VerdictReal, Reasoning: "it reproduces",
				Cost: review.Cost{Model: "m", Usage: review.Usage{Calls: 1, InputTokens: 5}, EstimatedCostMicros: 2},
			},
			patch: &fix.Patch{
				Summary: "guard the input",
				Files:   []fix.FileChange{{Path: "a.go", Contents: "package a // fixed\n"}},
				Cost:    review.Cost{Model: "m", Usage: review.Usage{Calls: 1, InputTokens: 5}, EstimatedCostMicros: 2},
			},
		},
		fetcher: &stubFetcher{tree: tree, commit: "basesha"},
		git:     newGit(),
		scans: &stubScans{scan: &fix.Scan{
			Complete: true,
			Owner:    "acme",
			Repo:     "widget",
			Ref:      "main",
			Findings: []review.Finding{{Severity: review.SeverityHigh, Title: "a finding", CheckID: "check-1", Path: "a.go", Line: 1}},
		}},
		store: &stubStore{},
	}
	for _, fn := range mutate {
		fn(h)
	}
	m, err := fix.New(fix.Config{
		Fixer: h.fixer, Source: h.fetcher, Git: h.git, Scans: h.scans, Store: h.store,
		Logger: discardLogger(), Identity: fix.Identity{Name: "apphub"},
		Limits: testLimits(), MaxSourceBytes: review.SuggestedMaxSourceBytes,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.module = m
	return h
}

func validParams() map[string]any {
	return map[string]any{
		"fixId":          "fix-1",
		"scanId":         "scan-1",
		"findingIndex":   0,
		"mode":           string(review.ModeInstallation),
		"installationId": 42,
		"owner":          "acme",
		"repo":           "widget",
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

func notFound() error { return fmt.Errorf("gone: %w", fix.ErrRecordNotFound) }

var _ = errors.Is
