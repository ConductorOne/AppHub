// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/conductorone/apphub/compute"
)

// TeardownStep is one ordered, idempotent step of deleting an application.
//
// The values are a wire contract: the control plane stores them as a
// teardown's planned and current steps and the portal renders them.
type TeardownStep string

// Teardown steps, in the order they run. The workload goes first so nothing is
// serving or writing while its data is deleted; the identity goes after every
// resource that holds a grant to it; the control-plane records go last, and are
// the caller's to delete because this package has no persistence.
const (
	StepDeleteWorkload        TeardownStep = "delete-workload"
	StepDeleteDatabase        TeardownStep = "delete-database"
	StepDeleteKeyValue        TeardownStep = "delete-key-value"
	StepDeleteBucket          TeardownStep = "delete-bucket"
	StepDeleteSecrets         TeardownStep = "delete-secrets"
	StepDeleteIdentity        TeardownStep = "delete-identity"
	StepDeleteImageRepository TeardownStep = "delete-image-repository"
	StepDeleteRecords         TeardownStep = "delete-records"
)

// TeardownPlan returns the steps a teardown of these artifacts runs, ending
// with [StepDeleteRecords]. A step whose resource was never recorded, or was
// already deleted by an earlier attempt, is left out, so a retried teardown
// shows only the work that remains.
//
// Secrets are always planned when the provider can store them: they are deleted by
// the application's scope rather than by the references recorded here, which
// is what makes a secret set by a deployment that failed before it checkpointed
// still findable.
func TeardownPlan(capabilities compute.CapabilitySet, a Artifacts) []TeardownStep {
	var plan []TeardownStep
	add := func(present bool, step TeardownStep) {
		if present {
			plan = append(plan, step)
		}
	}
	add(!a.Workload.IsZero(), StepDeleteWorkload)
	add(!a.Relational.IsZero(), StepDeleteDatabase)
	add(!a.KeyValue.IsZero(), StepDeleteKeyValue)
	add(!a.Bucket.IsZero(), StepDeleteBucket)
	add(capabilities.Has(compute.CapSecretStore), StepDeleteSecrets)
	add(!a.Identity.IsZero(), StepDeleteIdentity)
	add(!a.Repository.IsZero(), StepDeleteImageRepository)
	return append(plan, StepDeleteRecords)
}

// TeardownObserver persists a teardown's progress. Either method returning an
// error stops the teardown: an attempt that cannot record what it did must not
// go on doing more.
type TeardownObserver interface {
	// StartStep records that step is about to run.
	StartStep(ctx context.Context, step TeardownStep) error
	// CompleteStep records that step finished and which artifacts remain, so a
	// later attempt plans only what is left.
	CompleteStep(ctx context.Context, step TeardownStep, remaining Artifacts) error
}

// TeardownOptions bounds retrying. The zero value uses production defaults.
type TeardownOptions struct {
	// InitialBackoff is the first wait after a transient failure. It doubles
	// up to MaxBackoff. Default one second.
	InitialBackoff time.Duration
	// MaxBackoff caps the wait between attempts. Default thirty seconds.
	MaxBackoff time.Duration
	// PollInterval is how often a deleted workload is checked for being gone.
	// Default two seconds.
	PollInterval time.Duration
}

func (o TeardownOptions) withDefaults() TeardownOptions {
	if o.InitialBackoff <= 0 {
		o.InitialBackoff = time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 30 * time.Second
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 2 * time.Second
	}
	return o
}

// TeardownError names the step a teardown stopped at and a safe failure class.
// The wrapped error is for logs and errors.Is, never for a client.
type TeardownError struct {
	Step  TeardownStep
	Class string
	Err   error
}

func (e *TeardownError) Error() string {
	return fmt.Sprintf("teardown step %s failed (%s): %v", e.Step, e.Class, e.Err)
}

func (e *TeardownError) Unwrap() error { return e.Err }

// Teardown deletes every provider resource recorded in artifacts, for the
// application whose secret scope is appID. It does not run
// [StepDeleteRecords].
//
// # Why it can be run again at any point
//
// Every port delete it calls is idempotent, and an absent resource is success.
// So a teardown that failed, timed out, or lost its worker is resumed by running
// it again, and nothing needs to know how far the last attempt got. The
// observer's CompleteStep is an optimisation for the reader, not a correctness
// requirement.
//
// # Why it retries, and what it does not retry
//
// Cloud deletes are asynchronous. A database cluster cannot be deleted until
// its instance is gone, and a security group cannot be deleted until the
// interfaces in it are released, minutes later. Those arrive as
// [compute.ErrTransient], and so does throttling. Each step retries them with
// capped exponential backoff until ctx ends, which is how a slow step differs
// from a failed one. Anything else fails at once: a denial or a resource this
// platform does not own will not change by waiting, and the owner is better
// served by an immediate, specific failure than by a wait that ends in the
// same one.
func Teardown(ctx context.Context, provider compute.Provider, appID string, artifacts Artifacts, obs TeardownObserver, opts TeardownOptions) error {
	if appID == "" || provider == nil || obs == nil {
		return &TeardownError{Class: "invalid-application", Err: ErrInvalidApplication}
	}
	opts = opts.withDefaults()
	remaining := cloneTeardownArtifacts(artifacts)
	for _, step := range TeardownPlan(provider.Capabilities(), remaining) {
		if step == StepDeleteRecords {
			break
		}
		if err := obs.StartStep(ctx, step); err != nil {
			return &TeardownError{Step: step, Class: "checkpoint", Err: err}
		}
		err := retryTransient(ctx, opts, func(ctx context.Context) error {
			return runTeardownStep(ctx, provider, appID, step, remaining, opts)
		})
		if err != nil {
			return &TeardownError{Step: step, Class: classify(err), Err: err}
		}
		clearTeardownStep(&remaining, step)
		if err := obs.CompleteStep(ctx, step, cloneTeardownArtifacts(remaining)); err != nil {
			return &TeardownError{Step: step, Class: "checkpoint", Err: err}
		}
	}
	return nil
}

func runTeardownStep(ctx context.Context, provider compute.Provider, appID string, step TeardownStep, a Artifacts, opts TeardownOptions) error {
	switch step {
	case StepDeleteWorkload:
		return deleteWorkload(ctx, provider, a.Workload, opts)
	case StepDeleteDatabase:
		relational, err := provider.Relational()
		if err != nil {
			return err
		}
		return relational.DeleteRelational(ctx, a.Relational)
	case StepDeleteKeyValue:
		kv, err := provider.KeyValues()
		if err != nil {
			return err
		}
		return kv.DeleteKeyValueTable(ctx, a.KeyValue)
	case StepDeleteBucket:
		store, err := provider.ObjectStores()
		if err != nil {
			return err
		}
		if err := store.EmptyBucket(ctx, a.Bucket); err != nil {
			return err
		}
		return store.DeleteBucket(ctx, a.Bucket)
	case StepDeleteSecrets:
		secrets, err := provider.Secrets()
		if err != nil {
			return err
		}
		return secrets.DeleteScope(ctx, appID)
	case StepDeleteIdentity:
		return provider.Identities().DeleteWorkloadIdentity(ctx, a.Identity)
	case StepDeleteImageRepository:
		registry, err := provider.Registry()
		if err != nil {
			return err
		}
		return registry.DeleteRepository(ctx, a.Repository)
	case StepDeleteRecords:
		return fmt.Errorf("%w: records are deleted by the caller", ErrInvalidApplication)
	default:
		return fmt.Errorf("%w: unknown teardown step %q", ErrInvalidApplication, step)
	}
}

// deleteWorkload deletes a service or scheduled job and waits until the
// provider reports it gone, so the data steps after it run against nothing
// still serving. A deploy's retirement does the same wait; see
// [Module.retirePreviousWorkload].
func deleteWorkload(ctx context.Context, provider compute.Provider, ref compute.Ref, opts TeardownOptions) error {
	runtime, err := provider.Containers()
	if err != nil {
		return err
	}
	var gone func(context.Context) (bool, error)
	switch ref.Kind {
	case compute.KindService:
		if err := runtime.DeleteService(ctx, ref); err != nil {
			return err
		}
		gone = func(ctx context.Context) (bool, error) {
			status, err := runtime.DescribeService(ctx, ref)
			if errors.Is(err, compute.ErrNotFound) {
				return true, nil
			}
			if err != nil {
				return false, err
			}
			return status == nil || status.Phase == compute.PhaseGone, nil
		}
	case compute.KindScheduledJob:
		if err := runtime.DeleteScheduledJob(ctx, ref); err != nil {
			return err
		}
		gone = func(ctx context.Context) (bool, error) {
			_, err := runtime.DescribeScheduledJob(ctx, ref)
			if errors.Is(err, compute.ErrNotFound) {
				return true, nil
			}
			return false, err
		}
	default:
		return fmt.Errorf("%w: cannot delete workload kind %q", ErrInvalidApplication, ref.Kind)
	}
	ticker := time.NewTicker(opts.PollInterval)
	defer ticker.Stop()
	for {
		done, err := gone(ctx)
		if err != nil || done {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(compute.ErrTimeout, ctx.Err())
		case <-ticker.C:
		}
	}
}

// retryTransient runs fn until it succeeds, fails with something other than
// [compute.ErrTransient], or ctx ends. An absent resource is success.
func retryTransient(ctx context.Context, opts TeardownOptions, fn func(context.Context) error) error {
	backoff := opts.InitialBackoff
	for {
		err := fn(ctx)
		if err == nil || errors.Is(err, compute.ErrNotFound) {
			return nil
		}
		if !errors.Is(err, compute.ErrTransient) {
			return err
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(compute.ErrTimeout, ctx.Err(), err)
		case <-timer.C:
		}
		backoff = min(2*backoff, opts.MaxBackoff)
	}
}

func clearTeardownStep(a *Artifacts, step TeardownStep) {
	switch step {
	case StepDeleteWorkload:
		a.Workload = compute.Ref{}
		a.Addresses = nil
	case StepDeleteDatabase:
		a.Relational = compute.Ref{}
	case StepDeleteKeyValue:
		a.KeyValue = compute.Ref{}
	case StepDeleteBucket:
		a.Bucket = compute.Ref{}
	case StepDeleteSecrets:
		a.Secrets = nil
	case StepDeleteIdentity:
		a.Identity = compute.Ref{}
	case StepDeleteImageRepository:
		a.Repository = compute.Ref{}
		a.Image = ""
	case StepDeleteRecords:
	}
}

func cloneTeardownArtifacts(a Artifacts) Artifacts {
	secrets := make(map[string]compute.Ref, len(a.Secrets))
	for k, v := range a.Secrets {
		secrets[k] = v
	}
	a.Secrets = secrets
	a.Addresses = append([]string(nil), a.Addresses...)
	return a
}
