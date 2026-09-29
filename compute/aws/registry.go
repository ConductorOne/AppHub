// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// imageRegistry implements [compute.ImageRegistry] on ECR.
//
// # Why this port carries no Granter, with evidence from the source system
//
// [compute.ImageRegistry] used to embed [compute.Granter] and no longer does,
// and ECR is the clearest case for why. ECR authorises an IAM principal holding
// an authorization token; there is no policy to write that says "this workload
// identity may pull". Worse, on ECS the principal that pulls is not the workload
// at all — the task *execution* role fetches the image before the task role
// exists.
//
// The source system confirms it from the other side. Its per-application task
// role is created with no policies at all (build.go:619-666) and then
// accumulates DynamoDB, S3, Bedrock and ssmmessages statements over the deploy
// path — never ECR — because the pull runs under an operator-configured
// execution role that apphub does not manage (container.go:742). A Grant
// naming the application's identity would have authorised a principal that
// never makes the request.
//
// So this provider does not advertise [compute.CapImagePullGrants], and
// discharges the obligation [compute.ImageRegistry] states instead: the
// workloads it runs can pull the images their specs name. On ECS that is the
// execution role's business, which is USOSS-11's; this package issues no
// workload that pulls anything yet, so it has nothing to discharge and nothing
// to overclaim.
type imageRegistry struct{ p *Provider }

var _ compute.ImageRegistry = (*imageRegistry)(nil)

// ownedRepository is proof that a repository exists and that this platform owns
// it.
//
// # Why this is a type and not a check
//
// The ownership check used to be a step inside EnsureRepository. Review found
// that Build and DeleteRepository walked straight past it: a build minted a
// scoped push credential against a repository somebody else owned, and a delete
// destroyed one. The check was right about its own entry point and said nothing
// about the other three, and the fourth method added later would have forgotten
// it again.
//
// So ownership is now a property of *access*. The only way to obtain the
// coordinates a mutating call needs — the name, the ARN — is to go through
// [imageRegistry.owned] or [imageRegistry.ownedByName], which read the tags
// first and return [compute.ErrNotOwned] instead of a value. A method that
// forgets has nothing to pass.
//
// The second half of the finding is the sharper one: a [compute.Ref] this
// provider issued is not a capability. The resource behind it can be deleted and
// somebody else's can take the same physical name, so ownership is established
// at use rather than inherited from issuance. Every method resolves afresh.
type ownedRepository struct {
	rec  RepositoryRecord
	tags map[string]string
}

// owned resolves a caller's [compute.Ref] to a repository this platform may act
// on.
func (r *imageRegistry) owned(ctx context.Context, ref compute.Ref) (*ownedRepository, error) {
	name, err := r.p.resolve(ref, compute.KindImageRepository)
	if err != nil {
		return nil, err
	}
	got, found, err := r.ownedByName(ctx, name)
	switch {
	case err != nil:
		return nil, err
	case !found:
		return nil, fmt.Errorf("%w: repository %q", compute.ErrNotFound, name)
	}
	return got, nil
}

// ownedByName resolves a physical name. It reports absence rather than treating
// it as an error, because EnsureRepository's create branch needs to know.
func (r *imageRegistry) ownedByName(ctx context.Context, name string) (*ownedRepository, bool, error) {
	rec, err := r.p.sub.ECR.DescribeRepository(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, r.p.substrateError(err)
	}
	tags, err := r.p.sub.ECR.ListTags(ctx, rec.ARN)
	if err != nil {
		return nil, false, r.p.substrateError(err)
	}
	if err := checkOwned(tags, "repository", componentRepository, rec.Name); err != nil {
		return nil, false, err
	}
	return &ownedRepository{rec: *rec, tags: tags}, true, nil
}

// EnsureRepository creates or converges a repository.
//
// Four differences from the source system, all deliberate and all in the
// fail-closed direction:
//
//  1. **The ownership marker is read.** EnsureECRRepository (build.go:282-347)
//     writes a source-system-specific ManagedBy value on create and never checks it, so a
//     repository somebody else created under the name apphub wants is adopted
//     and then mutated. Repository names derive from mutable application names,
//     so this is a collision that happens. Here it is [compute.ErrNotOwned].
//
//  2. **The lifecycle policy is applied on every call.** The source applies it
//     only on the create branch, and logs a warning if it fails. So an existing
//     repository never picks up a changed rule, and a repository whose
//     PutLifecyclePolicy failed grows without bound with nothing but a log line
//     to say so. Its own cache-repository variant already does it on every call
//     (build.go:479-490), so the two halves of the same file disagree; this one
//     follows the better half and treats the failure as an error.
//
//  3. **Retention and scanning come from the spec.** The source hardcodes "keep
//     last 20" and scan-on-push true for images, and age-based expiry with
//     scanning off for the cache. Those are good defaults and they are the
//     caller's to choose.
//
//  4. **Removing retention removes the policy.** A spec with no rules converges
//     to a repository with no lifecycle policy, rather than to one still
//     carrying the last rule anybody asked for.
func (r *imageRegistry) EnsureRepository(ctx context.Context, spec compute.RepositorySpec) (*compute.Repository, error) {
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	policy, err := lifecyclePolicy(spec.Retention)
	if err != nil {
		return nil, err
	}
	name, err := r.p.repositoryName(spec.Name)
	if err != nil {
		return nil, err
	}
	desired := ownershipTags(name, componentRepository, spec.Labels)

	immutable := r.p.cfg.Registry.ImmutableTags
	owned, found, err := r.ownedByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if !found {
		// Created by this platform, so owned by construction.
		rec, err := r.p.sub.ECR.CreateRepository(ctx, name, spec.ScanOnPush, immutable, desired)
		if err != nil {
			return nil, r.p.substrateError(err)
		}
		owned = &ownedRepository{rec: *rec, tags: copyTags(desired)}
	} else {
		// Every write below re-establishes ownership immediately before itself.
		//
		// `owned` is the read that decided create-versus-adopt. Past this point
		// it may only cause a write to be SKIPPED, never to happen: each
		// condition here is re-evaluated against the fresh proof inside
		// [imageRegistry.writeOwned], which is the only thing that authorises
		// the call.
		if owned.rec.ScanOnPush != spec.ScanOnPush {
			err := r.writeOwned(ctx, name, func(fresh *ownedRepository) error {
				if fresh.rec.ScanOnPush == spec.ScanOnPush {
					return nil
				}
				return r.p.substrateError(r.p.sub.ECR.PutImageScanningConfiguration(
					ctx, fresh.rec.Name, spec.ScanOnPush))
			})
			if err != nil {
				return nil, err
			}
		}
		// Tag immutability is operator configuration rather than a spec field,
		// and it still has to converge. An operator who turns it on to stop a
		// deployed tag being moved under a running workload would otherwise
		// find every repository created before the change still mutable, with
		// nothing to say so.
		if owned.rec.ImmutableTags != immutable {
			err := r.writeOwned(ctx, name, func(fresh *ownedRepository) error {
				if fresh.rec.ImmutableTags == immutable {
					return nil
				}
				return r.p.substrateError(r.p.sub.ECR.PutImageTagMutability(
					ctx, fresh.rec.Name, immutable))
			})
			if err != nil {
				return nil, err
			}
		}
		if put, remove := tagDelta(owned.tags, desired); len(put) > 0 || len(remove) > 0 {
			if err := r.convergeTags(ctx, name, desired); err != nil {
				return nil, err
			}
		}
	}

	// The create branch is not exempt. A repository this call created a moment
	// ago is owned by construction, but "a moment ago" is the same claim every
	// other write here used to make, and the whole finding is that elapsed
	// proof is not proof.
	err = r.writeOwned(ctx, name, func(fresh *ownedRepository) error {
		return r.applyLifecycle(ctx, fresh, policy)
	})
	if err != nil {
		return nil, err
	}
	return r.repository(&owned.rec, spec), nil
}

// writeOwned performs one converging write against an ownership proof
// established immediately before it, and nothing older.
//
// # Why every write, and not just the last one
//
// Round four moved the ownership check down to the last write in
// EnsureRepository — the lifecycle policy — on the grounds that a decision made
// several round trips earlier is not a licence to write now. Round five found
// what that left behind: the other three writes, scanning configuration, tag
// mutability and tag convergence, still ran on the proof from the
// create-or-adopt read. A repository whose ownership marker was removed after
// that read had its scanning configuration changed, and only then received
// [compute.ErrNotOwned] from the lifecycle step. The mutation stood.
//
// It also needed no interleaving to reach: the revocation completed before the
// scan write, so this is outside the race below rather than an instance of it.
//
// That is "ownership is checked once" again, one level in. The check had been
// *moved* rather than made unavoidable, and moving a check leaves it wherever
// the next write is not.
//
// The construction is the one the exported methods already use, applied inside:
// a write cannot obtain the coordinates it needs without going through a read
// that returns [compute.ErrNotOwned] instead of a value. [imageRegistry.owned]
// does that for a caller's [compute.Ref]; this does it for Ensure's own writes.
//
// # What a stale read may still do, and what it may not
//
// EnsureRepository decides whether each write is needed from the earlier read,
// and then re-decides from the fresh one here. Stale state may therefore cause
// this provider to do LESS — a convergence skipped now and performed on the next
// call, which an eventually-convergent contract permits — and never to write.
// Authorising a write on stale state is the defect above; declining one on it is
// not.
//
// # What this does not close
//
// The window is one round trip rather than several, and it is not zero: ECR has
// no conditional write, so nothing here makes the check and the write atomic. A
// person revoking ownership inside that window still has one write land. That is
// a genuine race, it is stated rather than implied, and it is not what this
// defends against.
func (r *imageRegistry) writeOwned(ctx context.Context, name string, write func(*ownedRepository) error) error {
	fresh, found, err := r.ownedByName(ctx, name)
	switch {
	case err != nil:
		return err
	case !found:
		return fmt.Errorf("%w: repository %q was removed while this call was in progress",
			compute.ErrNotFound, name)
	}
	return write(fresh)
}

// convergeTags reconciles the tag sub-namespace this provider owns.
//
// It is two API calls and therefore two ownership proofs, one each. Sharing a
// proof between them would be the round-five finding at its smallest scale: the
// second write would run on a decision taken a call ago, and "a call ago" is
// where this has been wrong twice. Removal goes first so that a rename converges
// through a repository briefly carrying neither name rather than both.
//
// Note what it does *not* do, because the rule is easy to over-apply: it
// converges `apphub:` tags exactly and leaves every other tag alone. AWS's
// tagging APIs differ here and the difference has already cost another port a
// defect — ECR's TagResource/UntagResource are additive and subtractive, while
// S3's PutBucketTagging replaces the whole set, so a reconcile-to-exactly-the-
// spec written against the second silently deletes an operator's cost and
// compliance tags on every deploy. See [tagDelta]; the rule is *converge the
// sub-namespace you own, never touch what you do not*.
func (r *imageRegistry) convergeTags(ctx context.Context, name string, desired map[string]string) error {
	err := r.writeOwned(ctx, name, func(fresh *ownedRepository) error {
		_, remove := tagDelta(fresh.tags, desired)
		if len(remove) == 0 {
			return nil
		}
		return r.p.substrateError(r.p.sub.ECR.UntagResource(ctx, fresh.rec.ARN, remove))
	})
	if err != nil {
		return err
	}
	return r.writeOwned(ctx, name, func(fresh *ownedRepository) error {
		put, _ := tagDelta(fresh.tags, desired)
		if len(put) == 0 {
			return nil
		}
		return r.p.substrateError(r.p.sub.ECR.TagResource(ctx, fresh.rec.ARN, put))
	})
}

// applyLifecycle converges the repository's lifecycle policy.
//
// # Why this is six lines again, after three attempts at something cleverer
//
// The lifecycle policy of a repository *this provider owns* belongs to this
// provider. There is no read, no ownership classification, no claim recorded
// anywhere, and no refusal: a spec with retention writes the policy, a spec
// without one removes it.
//
// That is where this started, and it went through three more elaborate versions
// first — a read-merge-write splitting the document by a rule marker, then a
// claim tag gating a refusal. Between them they produced five findings: an
// operator rule deleted because its description started with the marker, merged
// documents that violated ECR's unique-priority invariant, a refusal that
// contradicted its own remedy text, a check-then-write race, and a stale claim
// that could authorise overwriting somebody else's policy. Every version was
// wrong in a new way.
//
// # What justified the complexity, and why it does not apply here
//
// The concern was real and general: a substrate call that *replaces* a whole
// collection destroys what it did not write. Another port hit exactly that on
// S3's PutBucketTagging, where the rule is right — AWS and operators apply tags
// to buckets account-wide, for cost allocation and compliance, so a bucket you
// own carries tags you did not write and must not delete.
//
// **ECR lifecycle policies have no such mechanism.** Nothing in AWS applies a
// lifecycle policy to a repository on your behalf; there is no account-level
// policy that lands on repositories, and no service that adds rules. The only
// way a policy this provider did not write appears on a repository this provider
// *created and tagged* is a person editing it by hand.
//
// So the analogy that motivated the machinery does not hold, and the machinery
// was solving a problem this substrate does not have — while introducing five
// that it does.
//
// # What this does mean, stated so nobody has to infer it
//
// An operator who hand-edits the lifecycle policy of a repository apphub owns
// has that edit replaced on the next deploy. That is the same exposure every
// other declarative field already has: scan-on-push, tag mutability, and the
// caller's labels are all converged the same way, and [compute.RepositorySpec]
// is a description of desired state. The protection for a repository an operator
// owns is the ownership check, which runs before this and refuses.
//
// Its ownership proof is [imageRegistry.writeOwned]'s, established one round trip
// before the write and not inherited from anything older. Round four put that
// check inline here; round five found that placing it next to *this* write said
// nothing about the three before it, so it is now the property of a helper every
// write in this file goes through rather than a step in one of them.
func (r *imageRegistry) applyLifecycle(ctx context.Context, owned *ownedRepository, policy string) error {
	if policy == "" {
		err := r.p.sub.ECR.DeleteLifecyclePolicy(ctx, owned.rec.Name)
		if err == nil || errors.Is(err, ErrNoSuchResource) {
			return nil
		}
		return r.p.substrateError(err)
	}
	return r.p.substrateError(r.p.sub.ECR.PutLifecyclePolicy(ctx, owned.rec.Name, policy))
}

// DescribeRepository reads a repository back through the interface.
func (r *imageRegistry) DescribeRepository(ctx context.Context, ref compute.Ref) (*compute.Repository, error) {
	owned, err := r.owned(ctx, ref)
	if err != nil {
		return nil, err
	}
	// The effective retention is read out of the lifecycle policy that is
	// actually in force, not out of anything this provider remembered. A
	// read-back that echoed the last spec would report convergence a failed
	// PutLifecyclePolicy had never achieved.
	retention, err := r.readRetention(ctx, owned)
	if err != nil {
		return nil, err
	}
	return r.repository(&owned.rec, compute.RepositorySpec{
		Name:       owned.rec.Name,
		Retention:  retention,
		ScanOnPush: owned.rec.ScanOnPush,
		Labels:     labelsFromTags(owned.tags),
	}), nil
}

func (r *imageRegistry) readRetention(ctx context.Context, owned *ownedRepository) (compute.RetentionPolicy, error) {
	doc, err := r.p.sub.ECR.GetLifecyclePolicy(ctx, owned.rec.Name)
	switch {
	case errors.Is(err, ErrNoSuchResource):
		return compute.RetentionPolicy{}, nil
	case err != nil:
		return compute.RetentionPolicy{}, r.p.substrateError(err)
	}
	policy, err := parseLifecyclePolicy(doc)
	if err != nil {
		return compute.RetentionPolicy{}, fmt.Errorf("%w: reading back the lifecycle policy on "+
			"repository %q: %w", compute.ErrFailed, owned.rec.Name, err)
	}
	return policy, nil
}

// DeleteRepository removes a repository and its images.
//
// Deleting an absent repository returns nil, as the port requires. Deleting one
// this platform does not own is [compute.ErrNotOwned] — a Ref that was valid
// when it was issued is not a licence to destroy whatever holds that name now.
func (r *imageRegistry) DeleteRepository(ctx context.Context, ref compute.Ref) error {
	name, err := r.p.resolve(ref, compute.KindImageRepository)
	if err != nil {
		return err
	}
	owned, found, err := r.ownedByName(ctx, name)
	switch {
	case err != nil:
		return err
	case !found:
		return nil
	}
	err = r.p.sub.ECR.DeleteRepository(ctx, owned.rec.Name)
	if errors.Is(err, ErrNoSuchResource) {
		return nil
	}
	return r.p.substrateError(err)
}

func (r *imageRegistry) repository(rec *RepositoryRecord, spec compute.RepositorySpec) *compute.Repository {
	spec.Labels = copyTags(spec.Labels)
	return &compute.Repository{
		Ref:    r.p.ref(compute.KindImageRepository, rec.Name),
		Prefix: rec.URI,
		Spec:   spec,
	}
}

// --- lifecycle policy ---------------------------------------------------------

// ECR expresses age in whole days and nothing finer.
const hoursPerDay = 24

// lifecyclePolicy renders a [compute.RetentionPolicy] as an ECR lifecycle
// policy document, or "" when the policy asks for nothing.
//
// Both shapes exist because the source system needs both and for different
// reasons: application images are pruned by count (build.go:320-336) and
// build-cache layers by age (build.go:417-434), because every cached layer is
// its own image and a count-based rule evicts live cache entries after two
// builds.
func lifecyclePolicy(p compute.RetentionPolicy) (string, error) {
	// ECR permits exactly one rule with tagStatus "any" and requires it to have
	// the highest priority. Both shapes this provider renders are tagStatus
	// "any" — they are about every image in the repository — so a spec asking
	// for both produces a document the service rejects outright.
	//
	// Refused here rather than emitted, for the same reason a MaxAge that is not
	// a whole number of days is refused: a spec a caller was entitled to write
	// must not turn into a call that can never succeed, discovered at deploy
	// time as a validation error about policy syntax.
	//
	// It is an interface concession and is reported as one. It costs nothing the
	// source system does: it prunes application images by count and cache layers
	// by age, on two different repositories, never both on one. See
	// docs/DECISIONS.md.
	if p.KeepLast > 0 && p.MaxAge > 0 {
		return "", fmt.Errorf("%w: RetentionPolicy asks for both KeepLast and MaxAge, and ECR "+
			"permits only one lifecycle rule that applies to every image in a repository. Use one "+
			"repository pruned by count and another expired by age, which is how the two shapes "+
			"are actually used", compute.ErrInvalidSpec)
	}
	if p.KeepLast < 0 {
		return "", fmt.Errorf("%w: RetentionPolicy.KeepLast is negative (%d)",
			compute.ErrInvalidSpec, p.KeepLast)
	}
	if p.MaxAge < 0 {
		return "", fmt.Errorf("%w: RetentionPolicy.MaxAge is negative (%s)",
			compute.ErrInvalidSpec, p.MaxAge)
	}
	type selection struct {
		TagStatus   string `json:"tagStatus"`
		CountType   string `json:"countType"`
		CountUnit   string `json:"countUnit,omitempty"`
		CountNumber int    `json:"countNumber"`
	}
	type rule struct {
		RulePriority int               `json:"rulePriority"`
		Description  string            `json:"description"`
		Selection    selection         `json:"selection"`
		Action       map[string]string `json:"action"`
	}
	var rules []rule
	expire := map[string]string{"type": "expire"}

	if p.KeepLast > 0 {
		rules = append(rules, rule{
			RulePriority: len(rules) + 1,
			Description:  fmt.Sprintf("keep the last %d images", p.KeepLast),
			Selection: selection{
				TagStatus: "any", CountType: "imageCountMoreThan", CountNumber: p.KeepLast,
			},
			Action: expire,
		})
	}
	if p.MaxAge > 0 {
		// Rounding is refused rather than performed. Rounding down can reach
		// zero days, which expires everything immediately; rounding up quietly
		// retains longer than the caller asked for, which is a staleness bound
		// the caller set for a reason. Neither is a decision a provider should
		// make silently, and ECR simply cannot express the request.
		if p.MaxAge%(hoursPerDay*time.Hour) != 0 {
			return "", fmt.Errorf("%w: RetentionPolicy.MaxAge is %s, and ECR expresses age only "+
				"in whole days; rounding down can reach zero days and expire every image, and "+
				"rounding up would retain longer than asked", compute.ErrInvalidSpec, p.MaxAge)
		}
		days := int(p.MaxAge / (hoursPerDay * time.Hour))
		rules = append(rules, rule{
			RulePriority: len(rules) + 1,
			Description:  fmt.Sprintf("expire images older than %d days", days),
			Selection: selection{
				TagStatus: "any", CountType: "sinceImagePushed",
				CountUnit: "days", CountNumber: days,
			},
			Action: expire,
		})
	}
	if len(rules) == 0 {
		return "", nil
	}
	doc, err := json.Marshal(map[string]any{"rules": rules})
	if err != nil {
		// Unreachable for these types; returned rather than ignored because the
		// source system discards this error (build.go:337, :475) and would ship
		// an empty policy document if it ever fired.
		return "", fmt.Errorf("%w: rendering the lifecycle policy: %w", compute.ErrFailed, err)
	}
	return string(doc), nil
}

// parseLifecyclePolicy recovers a [compute.RetentionPolicy] from a document.
//
// It reads the two rule shapes this provider writes and ignores everything else.
// It does **not** decide ownership: an earlier version classified rules by a
// description prefix so that they could be merged, and that classification was
// wrong in a way that deleted an operator's rules. Ownership of the policy is a
// tag on the repository now — see [imageRegistry.applyLifecycle] — and nothing
// reads it out of the document.
func parseLifecyclePolicy(doc string) (compute.RetentionPolicy, error) {
	if strings.TrimSpace(doc) == "" {
		return compute.RetentionPolicy{}, nil
	}
	var parsed struct {
		Rules []struct {
			Selection struct {
				CountType   string `json:"countType"`
				CountUnit   string `json:"countUnit"`
				CountNumber int    `json:"countNumber"`
			} `json:"selection"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return compute.RetentionPolicy{}, err
	}
	var out compute.RetentionPolicy
	for _, rule := range parsed.Rules {
		switch {
		case rule.Selection.CountType == "imageCountMoreThan":
			out.KeepLast = rule.Selection.CountNumber
		case rule.Selection.CountType == "sinceImagePushed" && rule.Selection.CountUnit == "days":
			out.MaxAge = time.Duration(rule.Selection.CountNumber) * hoursPerDay * time.Hour
		}
	}
	return out, nil
}
