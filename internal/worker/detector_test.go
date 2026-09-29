// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/detect"
	"github.com/conductorone/apphub/internal/source"
	"github.com/conductorone/apphub/internal/testutil"
	"github.com/conductorone/apphub/modules/deploy"
)

type fakeDiscoverer struct {
	tree      detect.Tree
	err       error
	closed    bool
	sawSource deploy.Source
}

func (f *fakeDiscoverer) Discover(_ context.Context, src deploy.Source) (string, detect.Tree, error) {
	f.sawSource = src
	if f.err != nil {
		return "", detect.Tree{}, f.err
	}
	return "0000000000000000000000000000000000000f", f.tree, nil
}
func (f *fakeDiscoverer) Close() error { f.closed = true; return nil }

func queueDetection(t *testing.T, repo *testutil.Repository, rec cp.DetectionRecord) {
	t.Helper()
	record, err := cp.Encode(cp.RecordID{Kind: cp.DetectionKind, ID: rec.ID}, 0, rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: record}}); err != nil {
		t.Fatal(err)
	}
}

func readDetection(t *testing.T, repo *testutil.Repository, id string) cp.DetectionRecord {
	t.Helper()
	record, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.DetectionKind, ID: id})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := cp.Decode[cp.DetectionRecord](record)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestDetectorScansQueuedDetectionAndRecordsResult(t *testing.T) {
	repo := testutil.NewRepository()
	queueDetection(t, repo, cp.DetectionRecord{ID: "det-1", RequesterUserID: "user-1", TargetID: "target-1", URL: "https://github.com/example/approved.git", Ref: "main", State: cp.DetectionQueued, CreatedAt: time.Now().UTC()})

	discoverer := &fakeDiscoverer{tree: detect.Tree{Files: map[string][]byte{"Dockerfile": []byte("FROM node:20\nEXPOSE 4000\n")}}}
	d, err := NewDetectorWithFactory(repo, func() (Discoverer, error) { return discoverer, nil })
	if err != nil {
		t.Fatal(err)
	}
	d.tick(context.Background())

	rec := readDetection(t, repo, "det-1")
	if rec.State != cp.DetectionSucceeded {
		t.Fatalf("state = %q, want succeeded (message=%q)", rec.State, rec.Message)
	}
	if rec.Result.DockerfilePath != "Dockerfile" || rec.Result.SuggestedPort != 4000 {
		t.Fatalf("result = %+v", rec.Result)
	}
	if rec.FinishedAt.IsZero() {
		t.Fatal("FinishedAt not set")
	}
	if !discoverer.closed {
		t.Fatal("Checkout was not closed")
	}
	if discoverer.sawSource.URL != "https://github.com/example/approved.git" || discoverer.sawSource.Ref != "main" {
		t.Fatalf("Discover called with wrong source: %+v", discoverer.sawSource)
	}

	// A finished detection must leave the queue directory.
	page, err := repo.Query(context.Background(), cp.Query{Kind: cp.DetectionKind, State: string(cp.DetectionQueued)})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("finished detection still queued: %+v", page.Records)
	}
}

func TestDetectorRecordsSafeFailureClassificationNotRawError(t *testing.T) {
	repo := testutil.NewRepository()
	queueDetection(t, repo, cp.DetectionRecord{ID: "det-2", RequesterUserID: "user-1", TargetID: "target-1", URL: "https://github.com/example/approved.git", State: cp.DetectionQueued, CreatedAt: time.Now().UTC()})

	discoverer := &fakeDiscoverer{err: errors.Join(errors.New("credential-canary-should-never-be-stored"), source.ErrRefused)}
	d, err := NewDetectorWithFactory(repo, func() (Discoverer, error) { return discoverer, nil })
	if err != nil {
		t.Fatal(err)
	}
	d.tick(context.Background())

	rec := readDetection(t, repo, "det-2")
	if rec.State != cp.DetectionFailed {
		t.Fatalf("state = %q, want failed", rec.State)
	}
	if rec.Message == "" || rec.Message == discoverer.err.Error() {
		t.Fatalf("message not a safe classification: %q", rec.Message)
	}
	if strings.Contains(rec.Message, "credential-canary") {
		t.Fatalf("raw error leaked into stored message: %q", rec.Message)
	}
}

func TestDetectorLoserOfACASRaceDoesNotOverwriteTheWinner(t *testing.T) {
	repo := testutil.NewRepository()
	staleRec := cp.DetectionRecord{ID: "det-3", RequesterUserID: "user-1", TargetID: "target-1", URL: "https://github.com/example/approved.git", State: cp.DetectionQueued, CreatedAt: time.Now().UTC()}
	queueDetection(t, repo, staleRec)
	staleRow, err := repo.Read(context.Background(), cp.RecordID{Kind: cp.DetectionKind, ID: "det-3"})
	if err != nil {
		t.Fatal(err)
	}

	// A sibling Detector replica finishes the same detection first.
	winner := staleRec
	winner.State, winner.FinishedAt = cp.DetectionSucceeded, time.Now().UTC()
	winner.Result.DockerfilePath = "winner.Dockerfile"
	won, err := cp.Encode(staleRow.RecordID, staleRow.Version, winner)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Commit(context.Background(), []cp.Mutation{{Record: won, ExpectedVersion: staleRow.Version}}); err != nil {
		t.Fatal(err)
	}

	// This Detector still holds the pre-steal row it polled and tries to
	// finish it too, with a different result -- process must lose the CAS and
	// must not overwrite the winner's record.
	discoverer := &fakeDiscoverer{tree: detect.Tree{Files: map[string][]byte{"Dockerfile": []byte("FROM node:20\n")}}}
	d, err := NewDetectorWithFactory(repo, func() (Discoverer, error) { return discoverer, nil })
	if err != nil {
		t.Fatal(err)
	}
	d.process(context.Background(), staleRow, staleRec)

	final := readDetection(t, repo, "det-3")
	if final.Result.DockerfilePath != "winner.Dockerfile" {
		t.Fatalf("loser overwrote the winner's result: %+v", final)
	}
}
