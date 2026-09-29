// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/credentials/workload"
)

// TestARetryableSubstrateFailureIsErrTransient is the gate the conformance
// suite cannot run against this provider.
//
// The suite has exactly one check for [compute.ErrTransient] and it drives a
// secret Put, "because a secret Put is the cheapest write on any provider" —
// which is true of a provider that has a secret store. This one does not, so
// the check skips, and the mapping six AWS providers are each writing
// independently goes unexercised. So it is checked here instead, and checked
// across every method of every port rather than at one call site: a mapping is
// per-service, and an implementation that reached ErrTransient from ECR and
// ErrFailed from IAM would pass any single-call check.
//
// This gap is reported as friction against the conformance suite rather than
// worked around silently; see the ticket report.
func TestARetryableSubstrateFailureIsErrTransient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Each case is a setup that runs before the throttle is armed and a call
	// that runs after it. Separating them matters: with the fixture creation
	// inside the call, the throttle lands on the setup and the test proves
	// nothing about the method it names.
	type probe struct {
		setup func(*aws.Provider) any
		call  func(*aws.Provider, any) error
	}
	repoRef := func(p *aws.Provider) any { return mustEnsureRepo(t, p, "app").Ref }
	identityRef := func(p *aws.Provider) any { return mustEnsureIdentity(t, p, "app").Ref }

	probes := map[string]probe{
		"Registry.EnsureRepository": {
			setup: func(*aws.Provider) any { return nil },
			call: func(p *aws.Provider, _ any) error {
				reg, err := p.Registry()
				if err != nil {
					return err
				}
				_, err = reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"})
				return err
			},
		},
		"Registry.DescribeRepository": {
			setup: repoRef,
			call: func(p *aws.Provider, fixture any) error {
				reg, err := p.Registry()
				if err != nil {
					return err
				}
				_, err = reg.DescribeRepository(ctx, fixture.(compute.Ref))
				return err
			},
		},
		"Registry.DeleteRepository": {
			setup: repoRef,
			call: func(p *aws.Provider, fixture any) error {
				reg, err := p.Registry()
				if err != nil {
					return err
				}
				return reg.DeleteRepository(ctx, fixture.(compute.Ref))
			},
		},
		"Identities.EnsureWorkloadIdentity": {
			setup: func(*aws.Provider) any { return nil },
			call: func(p *aws.Provider, _ any) error {
				_, err := p.Identities().EnsureWorkloadIdentity(ctx,
					compute.WorkloadIdentitySpec{Name: "app"})
				return err
			},
		},
		"Identities.DescribeWorkloadIdentity": {
			setup: identityRef,
			call: func(p *aws.Provider, fixture any) error {
				_, err := p.Identities().DescribeWorkloadIdentity(ctx, fixture.(compute.Ref))
				return err
			},
		},
		"Identities.DeleteWorkloadIdentity": {
			setup: identityRef,
			call: func(p *aws.Provider, fixture any) error {
				return p.Identities().DeleteWorkloadIdentity(ctx, fixture.(compute.Ref))
			},
		},
		"Builder.Build": {
			setup: func(p *aws.Provider) any { return mustEnsureRepo(t, p, "app").Prefix },
			call: func(p *aws.Provider, fixture any) error {
				b, err := p.Builder()
				if err != nil {
					return err
				}
				_, err = b.Build(ctx, compute.BuildRequest{
					Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
					Destinations: []compute.ImageRef{compute.ImageRef(fixture.(string) + ":latest")},
				})
				return err
			},
		},
	}

	// Builder.Build arms every service at once and the first ECR lookup consumes
	// the injected failure, so it never reaches the token service. Review caught
	// that: the test said it covered every service and its build probe covered
	// one. The token service therefore gets a probe that arms it alone, after
	// the ECR work is done.
	t.Run("Builder.Build/token service alone", func(t *testing.T) {
		t.Parallel()
		p, sub := newProvider(t, nil)
		prefix := mustEnsureRepo(t, p, "app").Prefix
		b, err := p.Builder()
		if err != nil {
			t.Fatalf("Builder(): %v", err)
		}
		req := compute.BuildRequest{
			Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
			Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
		}
		if _, err := b.Build(ctx, req); err != nil {
			t.Fatalf("the unarmed build failed: %v", err)
		}
		sts, ok := sub.STS.(*aws.MemorySTS)
		if !ok {
			t.Fatalf("the substrate's token service is a %T", sub.STS)
		}
		defer sts.FailNext(aws.ErrThrottled)()

		_, err = b.Build(ctx, req)
		switch {
		case err == nil:
			t.Fatal("the throttled mint succeeded, so this case checks nothing")
		case errors.Is(err, compute.ErrTransient):
		case errors.Is(err, compute.ErrFailed):
			t.Errorf("a throttled credential mint surfaced as compute.ErrFailed: %v", err)
		default:
			t.Errorf("a throttled credential mint surfaced as %v", err)
		}
	})

	// And the builder itself, which is the fourth substrate and has its own
	// mapping.
	t.Run("Builder.Build/the build runner alone", func(t *testing.T) {
		t.Parallel()
		p, sub := newProvider(t, nil)
		prefix := mustEnsureRepo(t, p, "app").Prefix
		b, err := p.Builder()
		if err != nil {
			t.Fatalf("Builder(): %v", err)
		}
		runner, ok := sub.Builder.(*aws.RecordingBuilder)
		if !ok {
			t.Fatalf("the substrate's builder is a %T", sub.Builder)
		}
		defer runner.FailNext(aws.ErrThrottled)()
		_, err = b.Build(ctx, compute.BuildRequest{
			Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
			Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
		})
		if err == nil || !errors.Is(err, compute.ErrTransient) {
			t.Errorf("a throttled build surfaced as %v, want compute.ErrTransient", err)
		}
	})

	for name, pr := range probes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, _ := newProvider(t, nil)
			fixture := pr.setup(p)

			stop, err := p.Harness().InduceTransient(ctx, aws.ErrThrottled)
			if err != nil {
				t.Fatalf("arming the throttle: %v", err)
			}
			defer stop()

			err = pr.call(p, fixture)
			switch {
			case err == nil:
				t.Fatal("the throttled call succeeded, so this case checks nothing")
			case errors.Is(err, compute.ErrTransient):
			case errors.Is(err, compute.ErrFailed):
				t.Errorf("a throttled call surfaced as compute.ErrFailed, which is documented as "+
					"not retryable without changing the spec; a caller that believes that "+
					"abandons a deploy that would have worked: %v", err)
			default:
				t.Errorf("a throttled call surfaced as %v, which matches no sentinel that would "+
					"make sense for it", err)
			}
		})
	}
}

func mustEnsureRepo(t *testing.T, p *aws.Provider, name string) *compute.Repository {
	t.Helper()
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	repo, err := reg.EnsureRepository(context.Background(), compute.RepositorySpec{
		Name:      name,
		Retention: compute.RetentionPolicy{KeepLast: 20},
	})
	if err != nil {
		t.Fatalf("EnsureRepository(%q): %v", name, err)
	}
	return repo
}

func mustEnsureIdentity(t *testing.T, p *aws.Provider, name string) *compute.WorkloadIdentity {
	t.Helper()
	id, err := p.Identities().EnsureWorkloadIdentity(context.Background(),
		compute.WorkloadIdentitySpec{Name: name})
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentity(%q): %v", name, err)
	}
	return id
}

// TestTheLifecyclePolicyIsReappliedOnEveryEnsure.
//
// The source system applies it only on the branch that creates the repository
// (build.go:320-341), so an existing repository never picks up a changed rule —
// and its own cache-repository variant does it on every call (build.go:479-490),
// which is the two halves of one file disagreeing. This checks the better half
// and then checks the case neither half covers: a spec that stops asking for
// retention leaves a repository with no policy rather than with the last rule
// anybody asked for.
func TestTheLifecyclePolicyIsReappliedOnEveryEnsure(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, nil)
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	ctx := context.Background()
	ensure := func(retention compute.RetentionPolicy) *compute.Repository {
		t.Helper()
		repo, err := reg.EnsureRepository(ctx, compute.RepositorySpec{
			Name: "app", Retention: retention,
		})
		if err != nil {
			t.Fatalf("EnsureRepository: %v", err)
		}
		return repo
	}
	read := func(ref compute.Ref) compute.RetentionPolicy {
		t.Helper()
		repo, err := reg.DescribeRepository(ctx, ref)
		if err != nil {
			t.Fatalf("DescribeRepository: %v", err)
		}
		return repo.Spec.Retention
	}

	repo := ensure(compute.RetentionPolicy{KeepLast: 20})
	if got := read(repo.Ref); got.KeepLast != 20 {
		t.Fatalf("after the creating Ensure the effective retention is %+v, want KeepLast 20", got)
	}

	// The case the source system misses: the repository already exists.
	ensure(compute.RetentionPolicy{KeepLast: 5})
	if got := read(repo.Ref); got.KeepLast != 5 {
		t.Errorf("re-Ensuring an existing repository with KeepLast 5 left the effective retention "+
			"at %+v; a changed rule never reaches a repository that already exists", got)
	}

	// Switching between the two shapes, which is the ordinary case: an
	// application repository is pruned by count and a cache repository expired
	// by age. Asking for both at once is refused rather than rendered, because
	// ECR permits one rule that applies to every image — see
	// TestRetentionShapesECRCannotCombineAreRefused.
	ensure(compute.RetentionPolicy{MaxAge: 14 * 24 * time.Hour})
	if got := read(repo.Ref); got.MaxAge != 14*24*time.Hour || got.KeepLast != 0 {
		t.Errorf("the effective retention is %+v, want MaxAge 336h and no count rule", got)
	}

	// And removal, which no branch of the source system performs.
	ensure(compute.RetentionPolicy{})
	if got := read(repo.Ref); got.KeepLast != 0 || got.MaxAge != 0 {
		t.Errorf("a spec that asks for no retention left %+v in force; Ensure converges rather "+
			"than accumulating", got)
	}
}

// TestAnAgeThatECRCannotExpressIsRefused.
//
// Rounding is the tempting answer and both directions are wrong: down can reach
// zero days, which expires every image in the repository, and up quietly
// retains longer than the caller asked for. The caller set a staleness bound
// for a reason, so the provider says it cannot do it.
func TestAnAgeThatECRCannotExpressIsRefused(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, nil)
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	for _, age := range []time.Duration{time.Hour, 23 * time.Hour, 36 * time.Hour, -time.Hour} {
		_, err := reg.EnsureRepository(context.Background(), compute.RepositorySpec{
			Name: "app", Retention: compute.RetentionPolicy{MaxAge: age},
		})
		if err == nil || !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("MaxAge %s was accepted or refused wrongly: %v", age, err)
		}
	}
	for _, age := range []time.Duration{24 * time.Hour, 7 * 24 * time.Hour} {
		if _, err := reg.EnsureRepository(context.Background(), compute.RepositorySpec{
			Name: "app", Retention: compute.RetentionPolicy{MaxAge: age},
		}); err != nil {
			t.Errorf("MaxAge %s was refused: %v", age, err)
		}
	}
}

// TestAnUnownedRepositoryIsRefusedBeforeAnythingIsWritten.
//
// The conformance suite checks that the refusal happens. This checks the part
// it cannot see: that nothing was written on the way to it. A provider that
// tagged the repository and then noticed it did not own it would pass the
// suite and still have mutated somebody else's infrastructure.
func TestAnUnownedRepositoryIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	ctx := context.Background()
	repo, err := reg.EnsureRepository(ctx, compute.RepositorySpec{Name: "app"})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	if err := reg.DeleteRepository(ctx, repo.Ref); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}
	mem, ok := sub.ECR.(*aws.MemoryECR)
	if !ok {
		t.Fatalf("the substrate's registry is a %T", sub.ECR)
	}
	// Somebody else's repository, under the name apphub wants.
	if err := p.Harness().CreateUnowned(ctx, repo.Ref); err != nil {
		t.Fatalf("CreateUnowned: %v", err)
	}
	before := strings.Join(mem.Dump(), "\n")

	_, err = reg.EnsureRepository(ctx, compute.RepositorySpec{
		Name:       "app",
		Retention:  compute.RetentionPolicy{KeepLast: 20},
		ScanOnPush: true,
		Labels:     map[string]string{"owner": "apphub"},
	})
	if err == nil {
		t.Fatal("Ensure adopted a repository this platform does not own")
	}
	if !errors.Is(err, compute.ErrNotOwned) {
		t.Errorf("Ensure refused an unowned repository with %v, want compute.ErrNotOwned", err)
	}
	if after := strings.Join(mem.Dump(), "\n"); after != before {
		t.Errorf("the refused Ensure changed the repository:\n before: %s\n  after: %s", before, after)
	}
	// And the refusal does not describe what it found, because the caller has
	// no business learning about somebody else's tags.
	if strings.Contains(err.Error(), "somebody-else") {
		t.Errorf("the refusal describes the resource it found: %v", err)
	}
}

// TestNoReferenceThisProviderIssuesCarriesAnAccountIdentifier.
//
// A [compute.Ref] is what the deploy layer persists, and the obvious ID for an
// AWS resource is its ARN — which is what the source system stores
// (bucket.go:194-215). An ARN embeds the account, so every stored reference
// would then carry one, and a reference issued against one account would be
// silently meaningful against another. Neither is a hypothetical: this
// repository is going public and its references are going into a database.
func TestNoReferenceThisProviderIssuesCarriesAnAccountIdentifier(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, nil)
	refs := []compute.Ref{
		mustEnsureRepo(t, p, "app").Ref,
		mustEnsureIdentity(t, p, "app").Ref,
	}
	for _, ref := range refs {
		if strings.Contains(ref.ID, "arn:") {
			t.Errorf("%s carries an ARN, so every persisted reference carries an account "+
				"identifier", ref)
		}
		if strings.Contains(ref.ID, aws.MemoryAccount) {
			t.Errorf("%s carries the account identifier", ref)
		}
		round, err := compute.ParseRef(ref.String())
		if err != nil || round != ref {
			t.Errorf("%s did not survive a String/ParseRef round trip: %#v, %v", ref, round, err)
		}
	}
}

// TestTheAttestationSubjectIsTheRoleARNTheSubstrateReported.
//
// The verifier resolves a presigned sts:GetCallerIdentity to an IAM role ARN
// and compares it against the stored expectation (auth/sts_verify.go:21-52), so
// the subject has to be exactly that ARN. It is read back from IAM rather than
// composed, which is what lets this package hold no account identifier at all.
func TestTheAttestationSubjectIsTheRoleARNTheSubstrateReported(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, nil)
	id := mustEnsureIdentity(t, p, "app")
	if id.Attestation.Method != workload.MethodAWSSTSCallerIdentity {
		t.Errorf("the attestation method is %q, want %q; a verifier handed an empty method must "+
			"refuse", id.Attestation.Method, workload.MethodAWSSTSCallerIdentity)
	}
	if !strings.HasPrefix(id.Attestation.Subject, "arn:aws:iam::") ||
		!strings.HasSuffix(id.Attestation.Subject, ":role/apphub-app") {
		t.Errorf("the attestation subject is %q, which is not the role ARN the substrate reported",
			id.Attestation.Subject)
	}
}

// TestTheTrustPolicyFollowsRunsOn.
//
// [compute.WorkloadIdentitySpec.RunsOn] exists because an AWS role trusted by
// ecs-tasks.amazonaws.com cannot be assumed by Lambda; this is the substrate
// the field was written for, so it is the substrate where getting it wrong is a
// runtime failure nobody can trace back. Convergence is checked too: a spec
// whose RunsOn changed rewrites the trust policy rather than keeping the first
// answer.
func TestTheTrustPolicyFollowsRunsOn(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	mem, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatalf("the substrate's identity service is a %T", sub.IAM)
	}
	ctx := context.Background()

	principal := func(name string) string {
		t.Helper()
		role, err := mem.GetRole(ctx, name)
		if err != nil {
			t.Fatalf("GetRole(%q): %v", name, err)
		}
		var doc struct {
			Statement []struct {
				Principal map[string]string `json:"Principal"`
			} `json:"Statement"`
		}
		if err := json.Unmarshal([]byte(role.AssumeRolePolicy), &doc); err != nil {
			t.Fatalf("the trust policy is not JSON: %v", err)
		}
		if len(doc.Statement) != 1 {
			t.Fatalf("the trust policy has %d statements, want 1", len(doc.Statement))
		}
		return doc.Statement[0].Principal["Service"]
	}

	for _, tc := range []struct {
		runsOn compute.RuntimeKind
		want   string
	}{
		{compute.RuntimeContainer, "ecs-tasks.amazonaws.com"},
		{compute.RuntimeFunction, "lambda.amazonaws.com"},
		{"", "ecs-tasks.amazonaws.com"},
	} {
		if _, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
			Name: "app", RunsOn: tc.runsOn,
		}); err != nil {
			t.Fatalf("EnsureWorkloadIdentity(RunsOn=%q): %v", tc.runsOn, err)
		}
		if got := principal("apphub-app"); got != tc.want {
			t.Errorf("RunsOn %q produced a role trusted by %q, want %q; a role trusted by the "+
				"wrong service cannot be assumed at all", tc.runsOn, got, tc.want)
		}
	}

	// An unrecognised runtime is refused rather than defaulted, because a
	// default would hand a function identity an ECS trust policy and the
	// failure would arrive at invocation time.
	_, err := p.Identities().EnsureWorkloadIdentity(ctx, compute.WorkloadIdentitySpec{
		Name: "app", RunsOn: "wasm",
	})
	if err == nil || !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("an unrecognised RunsOn was accepted or refused wrongly: %v", err)
	}
}

// TestARoleThisProviderCreatesCarriesNoPermissions.
//
// The source system creates the task role bare and then attaches ssmmessages
// and Bedrock statements from the deploy path (build.go:670-750). Those belong
// to the ports that own the capabilities, and a role that arrived with them
// would be a workload identity carrying permissions nobody asked for. This
// checks the role is created with a trust policy, tags, and nothing else.
func TestARoleThisProviderCreatesCarriesNoPermissions(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	mustEnsureIdentity(t, p, "app")
	mem, ok := sub.IAM.(*aws.MemoryIAM)
	if !ok {
		t.Fatalf("the substrate's identity service is a %T", sub.IAM)
	}
	role, err := mem.GetRole(context.Background(), "apphub-app")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	var doc struct {
		Statement []struct {
			Action []string `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(role.AssumeRolePolicy), &doc); err != nil {
		t.Fatalf("the trust policy is not JSON: %v", err)
	}
	for _, st := range doc.Statement {
		for _, action := range st.Action {
			if action != "sts:AssumeRole" {
				t.Errorf("the trust policy allows %q; a workload identity this package creates "+
					"is trusted to be assumed and permitted nothing", action)
			}
		}
	}
}

// TestAnOperatorsOwnTagSurvivesConvergence.
//
// Convergence has to remove a label the caller stopped asking for, and the
// naive implementation of that removes every tag not in the current spec —
// which deletes the account's cost-centre tag on the first redeploy. The
// namespacing exists so the set this provider may remove is exactly the set it
// put there, and this is the test that says so.
func TestAnOperatorsOwnTagSurvivesConvergence(t *testing.T) {
	t.Parallel()
	p, sub := newProvider(t, nil)
	reg, err := p.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	ctx := context.Background()
	repo, err := reg.EnsureRepository(ctx, compute.RepositorySpec{
		Name:   "app",
		Labels: map[string]string{"owner": "team-a", "extra": "present"},
	})
	if err != nil {
		t.Fatalf("EnsureRepository: %v", err)
	}
	mem, ok := sub.ECR.(*aws.MemoryECR)
	if !ok {
		t.Fatalf("the substrate's registry is a %T", sub.ECR)
	}
	// An account policy adds a tag apphub knows nothing about.
	if err := mem.TagResource(ctx, "arn:aws:ecr:"+aws.MemoryRegion+":"+aws.MemoryAccount+
		":repository/apphub/app", map[string]string{"cost-centre": "platform"}); err != nil {
		t.Fatalf("tagging as the operator: %v", err)
	}

	if _, err := reg.EnsureRepository(ctx, compute.RepositorySpec{
		Name:   "app",
		Labels: map[string]string{"owner": "team-a"},
	}); err != nil {
		t.Fatalf("re-EnsureRepository: %v", err)
	}
	got, err := reg.DescribeRepository(ctx, repo.Ref)
	if err != nil {
		t.Fatalf("DescribeRepository: %v", err)
	}
	if _, still := got.Spec.Labels["extra"]; still {
		t.Error("a label removed from the spec is still in force; Ensure accumulates rather than " +
			"converging")
	}
	if got.Spec.Labels["owner"] != "team-a" {
		t.Errorf("the surviving label is %v", got.Spec.Labels)
	}
	dump := strings.Join(mem.Dump(), "\n")
	if !strings.Contains(dump, "cost-centre=platform") {
		t.Error("the operator's own tag was removed by a convergence this provider performed on " +
			"its own labels")
	}
}

// TestTheRepositoryPrefixComesFromTheRegistry.
//
// [compute.Repository.Prefix] is what a caller appends a tag to, and composing
// it here would mean this package holding an account identifier and a hostname
// shape. It comes back from the registry instead, which is also what makes the
// builder's destination check a comparison rather than a parse.
func TestTheRepositoryPrefixComesFromTheRegistry(t *testing.T) {
	t.Parallel()
	p, _ := newProvider(t, nil)
	repo := mustEnsureRepo(t, p, "app")
	want := aws.MemoryRegistryHost + "/apphub/app"
	if repo.Prefix != want {
		t.Errorf("Prefix is %q, want %q", repo.Prefix, want)
	}
}

// TestTagImmutabilityConvergesOnAnExistingRepository.
//
// Immutability is operator configuration rather than a spec field, which is
// exactly why it is easy to leave un-converged: nothing in the interface, and
// nothing in the conformance suite, ever asks about it. An operator turning it
// on is turning on a control — a deployed tag cannot be moved under a running
// workload — and a control that silently applies only to repositories created
// after the change is a control nobody can rely on.
func TestTagImmutabilityConvergesOnAnExistingRepository(t *testing.T) {
	t.Parallel()
	mutable, sub := newProvider(t, func(cfg *aws.Config) {
		cfg.Registry.ImmutableTags = false
	})
	ctx := context.Background()
	mustEnsureRepo(t, mutable, "app")

	mem, ok := sub.ECR.(*aws.MemoryECR)
	if !ok {
		t.Fatalf("the substrate's registry is a %T", sub.ECR)
	}
	if got := strings.Join(mem.Dump(), "\n"); !strings.Contains(got, "immutable-tags=false") {
		t.Fatalf("the repository was not created mutable: %s", got)
	}

	// The operator flips the setting. The same substrate, a new provider.
	cfg := fullConfig()
	cfg.Registry.ImmutableTags = true
	strict, err := aws.New(sub, cfg)
	if err != nil {
		t.Fatalf("constructing the stricter provider: %v", err)
	}
	reg, err := strict.Registry()
	if err != nil {
		t.Fatalf("Registry(): %v", err)
	}
	if _, err := reg.EnsureRepository(ctx, compute.RepositorySpec{
		Name: "app", Retention: compute.RetentionPolicy{KeepLast: 20},
	}); err != nil {
		t.Fatalf("re-EnsureRepository: %v", err)
	}
	if got := strings.Join(mem.Dump(), "\n"); !strings.Contains(got, "immutable-tags=true") {
		t.Errorf("the repository is still mutable after an Ensure by a provider configured for "+
			"immutable tags: %s", got)
	}
}
