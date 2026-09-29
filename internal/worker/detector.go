// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"errors"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/detect"
	"github.com/conductorone/apphub/internal/serverconfig"
	"github.com/conductorone/apphub/internal/source"
	"github.com/conductorone/apphub/modules/deploy"
)

// detectorScanTimeout bounds one repository scan. It is far shorter than
// Dispatcher's deployment timeout: a scan reads a handful of small files
// after a shallow, depth-1 clone, not a full build.
const detectorScanTimeout = 45 * time.Second

// detectorPollInterval is how often Run checks for newly queued detections.
// There is no back-pressure signal to wait on (see the Repository interface),
// so, like Dispatcher's own deployment scan, this polls.
const detectorPollInterval = 2 * time.Second

// detectorBatch bounds how many queued detections one poll claims, so a burst
// of requests cannot make a single tick run unbounded work.
const detectorBatch = 10

// Discoverer is the source-acquisition port Detector needs: fetch one
// approved repository revision's file tree for advisory introspection,
// without exposing a build directory. *source.Checkout satisfies it through
// Discover; Close releases whatever Discover did not already clean up itself.
type Discoverer interface {
	Discover(ctx context.Context, src deploy.Source) (commit string, tree detect.Tree, err error)
	Close() error
}

// Detector performs the advisory repository scans RequestDetection queues:
// Dockerfile discovery, compose preview, and a database guess.
//
// It runs independently of Dispatcher, deliberately. A detection touches no
// application, deployment or provider state, so it needs none of Dispatcher's
// application-lock fencing, heartbeat, or interrupted-recovery machinery --
// see [github.com/conductorone/apphub/internal/controlplane.DetectionState]'s doc
// comment for why a worker that dies mid-scan can simply leave the record
// Queued for the next poll to retry, safely.
//
// Every scan uses the same source acquisition a real deploy uses, including
// GitHub App credentials for a private repository. That is why detection
// cannot run in the authenticated API process: it never holds them
// (serverconfig.Load skips loading source credentials in "serve" mode). A
// repository's Dockerfile is discovered by the same isolated worker that will
// eventually build it.
type Detector struct {
	repo     cp.Repository
	checkout func() (Discoverer, error)
}

// NewDetector builds a Detector that shallow-clones with a fresh
// source.Checkout per scan, exactly as the deployment Dispatcher constructs
// one per deploy.
func NewDetector(cfg serverconfig.Config, repo cp.Repository, keyReader GitHubAppKeyReader) (*Detector, error) {
	return NewDetectorWithFactory(repo, func() (Discoverer, error) {
		return newSourceCheckout(cfg, repo, keyReader)
	})
}

// NewDetectorWithFactory replaces only source acquisition, for hermetic tests
// that must not shell out to Git or reach a network.
func NewDetectorWithFactory(repo cp.Repository, factory func() (Discoverer, error)) (*Detector, error) {
	if repo == nil {
		return nil, errors.New("detector requires a repository")
	}
	if factory == nil {
		return nil, errors.New("detector requires a source factory")
	}
	return &Detector{repo: repo, checkout: factory}, nil
}

// Run polls the queued-detection directory until ctx is done. It never
// returns a non-nil error for a single failed scan or a single failed poll:
// those are recorded on the detection record or left for the next poll, and a
// transient Repository outage must not take the whole worker process down
// with it, unlike a Dispatcher readiness failure at startup.
func (d *Detector) Run(ctx context.Context) error {
	ticker := time.NewTicker(detectorPollInterval)
	defer ticker.Stop()
	for {
		d.tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (d *Detector) tick(ctx context.Context) {
	bounded, cancel := context.WithTimeout(ctx, persistenceTimeout)
	page, err := d.repo.Query(bounded, cp.Query{Kind: cp.DetectionKind, State: string(cp.DetectionQueued), Limit: detectorBatch})
	cancel()
	if err != nil {
		return
	}
	for _, row := range page.Records {
		if ctx.Err() != nil {
			return
		}
		rec, err := cp.Decode[cp.DetectionRecord](row)
		if err != nil {
			continue // A malformed row cannot be finished; leave it for an operator.
		}
		d.process(ctx, row, rec)
	}
}

func (d *Detector) process(ctx context.Context, row cp.Record, rec cp.DetectionRecord) {
	scanCtx, cancel := context.WithTimeout(ctx, detectorScanTimeout)
	result, scanErr := d.scan(scanCtx, rec)
	cancel()

	finished := rec
	finished.FinishedAt = time.Now().UTC()
	if scanErr != nil {
		finished.State, finished.Message = cp.DetectionFailed, classify(scanErr)
	} else {
		finished.State, finished.Result = cp.DetectionSucceeded, result
	}

	persist, cancel := context.WithTimeout(ctx, persistenceTimeout)
	defer cancel()
	m, err := cp.Encode(row.RecordID, row.Version+1, finished)
	if err != nil {
		return
	}
	// A version mismatch means another Detector replica already finished this
	// scan (or an operator otherwise touched it): dropping this result is the
	// correct outcome, not a failure to retry.
	_ = d.repo.Commit(persist, []cp.Mutation{{Record: m, ExpectedVersion: row.Version}})
}

func (d *Detector) scan(ctx context.Context, rec cp.DetectionRecord) (detect.Result, error) {
	checkout, err := d.checkout()
	if err != nil {
		return detect.Result{}, err
	}
	defer func() { _ = checkout.Close() }()
	_, tree, err := checkout.Discover(ctx, deploy.Source{URL: rec.URL, Ref: rec.Ref})
	if err != nil {
		return detect.Result{}, err
	}
	return detect.FromTree(tree), nil
}

// classify turns an acquisition failure into safe, service-authored text,
// never the underlying Git error -- the same "a failure records a
// classification, never the raw message" rule a failed deployment follows.
func classify(err error) string {
	switch {
	case errors.Is(err, source.ErrRefused):
		return "The repository, ref, or path was refused."
	case errors.Is(err, source.ErrLimit):
		return "Repository content exceeded the scan size limit."
	case errors.Is(err, source.ErrCanceled):
		return "The repository scan timed out."
	case errors.Is(err, source.ErrConfiguration):
		return "The repository is not configured for scanning."
	default:
		return "The repository scan failed."
	}
}
