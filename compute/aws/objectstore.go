// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// objectStore implements [compute.ObjectStore] over S3.
type objectStore struct{ p *Provider }

var _ compute.ObjectStore = (*objectStore)(nil)

// encryptionAlgorithm is what every bucket this provider creates gets.
//
// AES256 is S3-managed server-side encryption. A KMS key is not a field on
// [compute.BucketSpec] and deliberately so: the interface's documentation says a
// provider must ensure buckets are encrypted and that making it optional would
// invite a spec that turns it off. An operator who needs a customer-managed key
// sets a default at the account level, which this does not override -- S3 applies
// the account default when a bucket has none, and this sets one, so the two would
// conflict. That is a real limitation and it is stated rather than hidden.
const encryptionAlgorithm = "AES256"

// s3EncryptionAlgorithms is what S3's ServerSideEncryptionConfiguration accepts
// as an SSEAlgorithm, and it exists because [encryptionAlgorithm] being a
// constant is not the same as it being *right*.
//
// Review found that setting the constant to a value S3 has never heard of left
// the whole repository green: nothing read it back, and the memory substrate
// stores whatever it is handed. A constant nothing checks is a value nobody
// checks -- the compiler pins the spelling, not the meaning.
//
// So the set is written down and [objectStore.harden] refuses anything outside
// it. The check cannot fire on today's tree by construction, which is the point:
// it fires on the edit that would otherwise ship a bucket with no default
// encryption and no error. The alternative -- discovering it from S3's
// InvalidArgument on the real path, and never on the memory one -- is how this
// got past review in the first place.
var s3EncryptionAlgorithms = map[string]bool{
	// S3-managed keys, which is what this provider uses.
	"AES256": true,
	// The two customer-key forms, legal on the API and not used here: neither is
	// reachable without a key ARN, and [compute.BucketSpec] has no field for one.
	// They are in the set because it describes what S3 accepts, not what this
	// provider chooses.
	"aws:kms":      true,
	"aws:kms:dsse": true,
}

// EnsureBucket implements [compute.ObjectStore].
//
// # Order of operations, and the one window it leaves
//
// Create, then harden, then tag. A newly created bucket is unhardened for the
// duration of two API calls, which is not nothing -- and the alternative is
// worse in a way worth writing down, because it looks better.
//
// S3 has no create-with-public-access-block and no create-with-encryption. The
// flags are separate calls by construction -- unlike CreateTableBucket and
// CreateVectorBucket, which take their tags in the request and therefore have no
// window at all. So the choice here is not "atomic versus windowed"; it is which
// order the window sits in. Hardening first is impossible, since there is nothing
// to harden until the bucket exists.
//
// That leaves harden-then-tag against tag-then-harden, and the difference is
// **which window makes a false claim visible to somebody else**:
//
//   - tag first, and between the tag and the hardening the bucket *claims* to be
//     managed by this platform while it is not hardened. Anything reading the
//     ownership tags -- an audit, an operator, a differently-configured instance of
//     this provider -- is told a false thing about a real bucket.
//   - harden first, and between the create and the tag the bucket is unhardened
//     *and unclaimed*. Nothing asserts anything false about it; it is simply not
//     ours yet, and [objectStore.unwind] removes it.
//
// An earlier version of this comment gave a different reason -- that tagging first
// would let the ownership check adopt the bucket on the next Ensure and skip the
// hardening. **That was false, and contradicted by the paragraph immediately after
// it**: harden runs on the adopt path too. The conclusion was right and the
// argument was not, which is the more dangerous of the two failures, because the
// argument is what the next reader reuses.
//
// And the window is closed on every subsequent call rather than only at create:
// harden runs on the adopt path, so a bucket whose block was turned off
// out-of-band is re-hardened by the next Ensure instead of being reported as
// converged.
func (s *objectStore) EnsureBucket(ctx context.Context, spec compute.BucketSpec) (*compute.Bucket, error) {
	class, err := s.resolveClass(spec)
	if err != nil {
		return nil, err
	}
	if spec.PublicAccess {
		return nil, fmt.Errorf("%w: compute/aws: this provider does not create publicly readable "+
			"buckets. PublicAccess true would mean clearing the four public-access-block controls "+
			"the contract requires false to actually apply, and an anonymously readable bucket is "+
			"a data-exposure decision that should not arrive as a field on a deploy spec. Serve "+
			"public objects through a CDN in front of a private bucket", compute.ErrUnsupported)
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	name, err := s.p.bucketName(spec.Name)
	if err != nil {
		return nil, err
	}
	// The provider's region, not a per-spec one: [compute.BucketSpec] has no
	// Placement field, and that is right rather than an omission. A bucket name
	// is globally unique and a bucket is reachable from every region, so
	// "which placement" is not a question the caller has to answer -- unlike a
	// secret, which a Kubernetes workload can only resolve inside its own
	// namespace. A provider that invented a placement here would be answering a
	// question the interface deliberately does not ask.
	region := s.p.cfg.Region

	// created records whether THIS call brought the bucket into existence, which
	// decides whether a later failure may roll it back. Rolling back an adopted
	// bucket would delete somebody's data; rolling back one we just created
	// deletes an empty bucket nobody has seen.
	created := false
	switch err := s.p.substrateError(s.p.sub.S3.HeadBucket(ctx, name)); {
	case err == nil:
		// It exists. Ownership before anything else: a bucket this platform did
		// not create is not ours to reconfigure. The tags distinguish the two
		// only inside the AWS account/trust boundary that controls who may write
		// the reserved tag namespace; see the package-level ownership boundary.
		tags, terr := s.p.sub.S3.GetBucketTagging(ctx, name)
		if terr != nil {
			return nil, s.p.substrateError(terr)
		}
		if oerr := checkOwned(tags, "bucket", componentBucket, name); oerr != nil {
			return nil, oerr
		}
	case errors.Is(err, compute.ErrNotFound):
		if cerr := s.p.substrateError(s.p.sub.S3.CreateBucket(ctx, name, region)); cerr != nil {
			if errors.Is(cerr, compute.ErrNotOwned) {
				// The collision, reported by the one call S3 answers precisely:
				// BucketAlreadyExists is another account's name, and this
				// account's own bucket is BucketAlreadyOwnedByYou. Reaching here
				// after a not-found HEAD is the ordinary shape rather than a
				// race -- S3 answers a HEAD on an inaccessible bucket with 403 or
				// 404 as it likes, so "absent" was never a claim that the name
				// was free. See [S3API.HeadBucket] and [ErrNameTaken].
				//
				// The sentinel is already right; what the substrate cannot say is
				// which knob resolves it, and a caller reading "the name belongs
				// to another account" has no way to know that this provider
				// composed the name from a configurable prefix.
				return nil, fmt.Errorf("%w. A bucket name is shared with every other AWS "+
					"account, so this one has to change: set Config.ObjectStore.NamePrefix, or "+
					"rename the logical bucket %q. No permission this account can be granted "+
					"makes a name somebody else holds available", cerr, spec.Name)
			}
			return nil, cerr
		}
		created = true
	case errors.Is(err, compute.ErrNotPermitted):
		// A denial on the HEAD, which is genuinely two conditions S3 will not
		// separate: the name belongs to another account, or these credentials may
		// not head this bucket. Its own documentation says an inaccessible bucket
		// answers 400, 403 or 404 and declines to say when -- an answer that
		// distinguished them would make a HEAD an enumeration tool for a global
		// namespace.
		//
		// So the sentinel stays [compute.ErrNotPermitted], which is what the
		// substrate said, and the message carries the second reading. Guessing
		// [compute.ErrNotOwned] here would be a provider claiming to know
		// something S3 refused to tell it, and it would be wrong every time a
		// role is simply missing s3:ListBucket -- the far more common of the two.
		//
		// The collision is not left unreported: the 404 half of the same case
		// reaches CreateBucket, which answers BucketAlreadyExists for another
		// account's name, and that arrives as [ErrNameTaken] and comes back as
		// ErrNotOwned. See [S3API.HeadBucket] and [ErrNameTaken].
		return nil, fmt.Errorf("compute/aws: bucket %q could not be read. S3 answers a HEAD "+
			"identically for a bucket these credentials may not read and for a name held by "+
			"another AWS account, and a bucket name is global, so both are worth checking: grant "+
			"s3:ListBucket on the platform's role, or change Config.ObjectStore.NamePrefix or the "+
			"logical name %q. If it is only this one name, it is the collision; if it is every "+
			"bucket, it is the role: %w", name, spec.Name, err)
	default:
		return nil, err
	}

	if err := s.harden(ctx, name); err != nil {
		return nil, s.unwind(ctx, name, created, err)
	}
	if err := s.reconcileTags(ctx, name, spec); err != nil {
		return nil, s.unwind(ctx, name, created, err)
	}
	return s.bucket(name, class, spec), nil
}

// unwind removes a bucket this call created but could not finish configuring.
//
// # The state it exists to prevent
//
// S3's CreateBucket takes no tags -- unlike CreateTableBucket and
// CreateVectorBucket, which is why only this flavour needs an unwind at all. So
// between the create and the ownership tagging there is a window in which the
// bucket exists carrying no marker. A failure in that window used to leave it
// there, and **an untagged bucket is refused by every subsequent reconcile as
// ErrNotOwned, because it is indistinguishable from a bucket this platform did
// not create.** The resource was stranded permanently, with no recovery path
// through this interface, by the ownership check working exactly as designed.
//
// Adopting an untagged bucket instead would close the window and open a much
// worse one -- see
// docs/decisions/usoss-13-the-aws-provider-does-not-offer-zonal-object-storage.md
// for why "it is under our name prefix" is an argument rather than a check.
//
// # Only what this call created
//
// created is threaded through from the branch that made it rather than inferred,
// because the two cases are indistinguishable afterwards and the consequences are
// not symmetric: unwinding an adopted bucket deletes data this platform did not
// put there. On the adopt path the original error is returned untouched.
//
// # When the unwind itself fails
//
// Both errors are reported and the bucket is named, because that is the one case
// this cannot fix and a human can. Reporting only the unwind failure would hide
// the cause; reporting only the cause would hide that something needs deleting.
//
// # The classification is the cause's, and exactly one sentinel comes back
//
// An earlier version wrapped the cause in [compute.ErrTransient] on the success
// path, on the reasoning that the bucket was gone so the Ensure could be retried
// from scratch. **That reasoning is about the bucket and the sentinel is about
// the error**, and the two answer different questions: [compute.ErrTransient] is
// documented as the only sentinel that says "try again", and every other one is
// terminal for the call that produced it. Relabelling made the returned error
// satisfy two of them at once.
//
// The live case was a denial. An IAM role without s3:PutPublicAccessBlock made
// every Ensure create a bucket, get refused, delete it, and answer "try again" --
// a loop with no exit, because the one thing that would end it is
// [compute.ErrNotPermitted] sending the operator to the role. It also produced
// ErrTransient together with [compute.ErrFailed] for an unclassified failure,
// where a caller reading either sentinel first reaches an opposite conclusion.
//
// So the removal is reported in the message and never in the taxonomy:
//
//   - Removed: the cause is returned wrapped, so whatever it already said about
//     retrying is what the caller reads. A throttle stays transient; a denial
//     stays a denial.
//   - Not removed: [compute.ErrFailed], and the cause's text without its
//     sentinel. This is the one branch that deliberately reclassifies, because
//     the state changed under it -- the untagged bucket now refuses every later
//     Ensure, so "try again" is false however transient the cause was, and only a
//     human deleting or tagging it can make progress.
func (s *objectStore) unwind(ctx context.Context, name string, created bool, cause error) error {
	if !created {
		return cause
	}
	if derr := s.p.sub.S3.DeleteBucket(ctx, name); derr != nil {
		return fmt.Errorf("%w: compute/aws: bucket %q was created and could not be configured, and "+
			"removing it failed too, so it is left in place with no ownership tag -- which every "+
			"subsequent Ensure will refuse as ErrNotOwned because it cannot tell it from a bucket "+
			"this platform did not create. Delete %q by hand, or tag it with %s=%s and %s=%s to "+
			"adopt it. Configuration failure: %v. Removal failure: %v",
			compute.ErrFailed, name, name, tagManagedBy, managedByValue, tagComponent,
			componentBucket, cause, derr)
	}
	return fmt.Errorf("compute/aws: bucket %q could not be configured after it was created, so it "+
		"was removed rather than left untagged; an untagged bucket would be refused by every later "+
		"reconcile as not-owned, which is why this unwinds rather than leaving a partially "+
		"configured resource. Whether retrying can help is decided by the failure below and not by "+
		"the removal: %w", name, cause)
}

// resolveClass decides the storage class, refusing what this provider cannot do
// safely rather than quietly downgrading.
func (s *objectStore) resolveClass(spec compute.BucketSpec) (compute.ObjectClass, error) {
	class := spec.Class
	if class == "" {
		class = compute.ObjectClassStandard
	}
	switch class {
	case compute.ObjectClassStandard:
		if spec.Zone != "" {
			// Ignoring it would be the source system's behaviour and it is the
			// wrong one: a caller who named a zone believes the data is pinned
			// there, and a provider that drops the field on the floor lets them
			// keep believing it.
			return "", fmt.Errorf("%w: compute/aws: Zone %q was supplied with class %q. A zone is "+
				"meaningful only for ObjectClassZonal, and this provider refuses rather than "+
				"ignoring it: a caller who named a zone is relying on placement that would not "+
				"happen", compute.ErrInvalidSpec, spec.Zone, class)
		}
		return class, nil
	case compute.ObjectClassZonal:
		return "", fmt.Errorf("%w: compute/aws: this provider does not offer zonal object storage. "+
			"S3 Express One Zone directory buckets have no bucket-level tagging, so there is "+
			"nowhere to put the ownership marker every provider must check before adopting a "+
			"resource -- and without it an Ensure cannot tell a bucket this platform created from "+
			"one that merely has the same name. The capability is not advertised, so a caller can "+
			"see this before it calls", compute.ErrUnsupported)
	default:
		return "", fmt.Errorf("%w: compute/aws: unknown object class %q", compute.ErrInvalidSpec, class)
	}
}

// harden applies the two controls the contract requires, on every Ensure.
//
// Unconditionally rather than after reading the current state. Two reasons: the
// read costs as much as the write, and a converge that only writes when it
// believes the state is wrong is a converge that trusts its own read -- which is
// exactly what a caller who turned the block off out-of-band would be relying on.
func (s *objectStore) harden(ctx context.Context, name string) error {
	if err := s.p.sub.S3.PutPublicAccessBlock(ctx, name); err != nil {
		return s.p.substrateError(err)
	}
	if !s3EncryptionAlgorithms[encryptionAlgorithm] {
		// Refuse rather than send it: an algorithm S3 does not accept comes back
		// as an InvalidArgument naming the XML rather than the constant, and the
		// memory substrate does not come back at all. Failing here names the
		// thing that is wrong, and failing at all is what stops a bucket being
		// created with no default encryption and a green suite. See
		// [s3EncryptionAlgorithms].
		return fmt.Errorf("%w: compute/aws: encryptionAlgorithm is %q, which is not an SSE "+
			"algorithm S3 accepts. A bucket must not be created with a default-encryption "+
			"setting the substrate will reject, so this refuses before the bucket is touched",
			compute.ErrFailed, encryptionAlgorithm)
	}
	if err := s.p.sub.S3.PutBucketEncryption(ctx, name, encryptionAlgorithm); err != nil {
		return s.p.substrateError(err)
	}
	return nil
}

// reconcileTags converges the ownership tags without deleting anybody else's.
//
// It reads before it writes, which the other resources in this package do not
// have to do: PutBucketTagging replaces the whole set, so the current tags are an
// input to the call rather than something to compare against. See
// [mergedBucketTags].
func (s *objectStore) reconcileTags(ctx context.Context, name string, spec compute.BucketSpec) error {
	current, err := s.p.sub.S3.GetBucketTagging(ctx, name)
	if err != nil {
		return s.p.substrateError(err)
	}
	desired := ownershipTags(spec.Name, componentBucket, spec.Labels)
	merged := mergedBucketTags(current, desired)
	if err := s.p.sub.S3.PutBucketTagging(ctx, name, merged); err != nil {
		return s.p.substrateError(err)
	}
	return nil
}

// bucket renders the read-back.
func (s *objectStore) bucket(name string, class compute.ObjectClass, spec compute.BucketSpec) *compute.Bucket {
	effective := spec
	effective.Class = class
	return &compute.Bucket{
		Ref:   s.p.flavouredRef(flavourBucket, name),
		Name:  name,
		Class: class,
		// The scheme AWS clients expect. Region is not in it because an s3://
		// URI has no place for one; a client resolves the region from the
		// bucket, which is what GetBucketLocation is for.
		URI:  "s3://" + name,
		Spec: effective,
	}
}

// DescribeBucket implements [compute.ObjectStore].
func (s *objectStore) DescribeBucket(ctx context.Context, ref compute.Ref) (*compute.Bucket, error) {
	name, err := s.p.resolveFlavoured(ref, flavourBucket)
	if err != nil {
		return nil, err
	}
	if err := s.p.substrateError(s.p.sub.S3.HeadBucket(ctx, name)); err != nil {
		return nil, err
	}
	tags, err := s.p.sub.S3.GetBucketTagging(ctx, name)
	if err != nil {
		return nil, s.p.substrateError(err)
	}
	if err := checkOwned(tags, "bucket", componentBucket, name); err != nil {
		return nil, err
	}
	// The bucket's actual region, checked rather than assumed.
	//
	// A bucket name is globally unique, so an owned bucket in a region this
	// provider is not configured for is a real condition rather than an
	// impossible one: an operator changed Config.Region, or a bucket was
	// created by a differently-configured instance of this provider. Reporting
	// it beats returning a read-back that silently describes a bucket somewhere
	// else -- every subsequent data-plane call would be cross-region, and the
	// caller would learn that from latency rather than from an error.
	region, err := s.p.sub.S3.GetBucketLocation(ctx, name)
	if err != nil {
		return nil, s.p.substrateError(err)
	}
	if region != s.p.cfg.Region {
		// Not ErrNotOwned, which the message itself contradicts: the bucket
		// carries this platform's ownership tag, and ErrNotOwned means "the
		// resource exists and is not managed by this platform". A caller
		// branching on the sentinel would conclude the opposite of what it reads.
		// What is wrong is the configuration this provider was built with, which
		// is what ErrInvalidSpec is for -- and Config.Region is the field to
		// change.
		return nil, fmt.Errorf("%w: compute/aws: bucket %q is in %s and this provider is "+
			"configured for %s. The bucket carries this platform's ownership tag, so it was "+
			"created by an instance configured differently; check Config.Region against the "+
			"deployment that provisioned it", compute.ErrInvalidSpec, name, region, s.p.cfg.Region)
	}
	// The spec is reconstructed from the substrate rather than remembered, so a
	// read-back reports what is true rather than what was asked for.
	spec := compute.BucketSpec{
		Name:   tags[tagName],
		Class:  compute.ObjectClassStandard,
		Labels: labelsFromTags(tags),
	}
	return s.bucket(name, compute.ObjectClassStandard, spec), nil
}

// DeleteBucket implements [compute.ObjectStore].
//
// A non-empty bucket is refused rather than emptied. The interface leaves the
// policy to the provider and requires it to be documented, and this is the
// documentation: apphub will not delete objects a caller did not ask it to
// delete. The source system runs a separate scheduled cleanup for that
// (jobs/bucket_cleanup_scheduler.go) precisely because it is a different
// decision, made by a different operator, with a different blast radius. A
// caller that has made that decision calls [objectStore.EmptyBucket] first.
func (s *objectStore) DeleteBucket(ctx context.Context, ref compute.Ref) error {
	name, err := s.p.resolveFlavoured(ref, flavourBucket)
	if err != nil {
		return err
	}
	tags, err := s.p.sub.S3.GetBucketTagging(ctx, name)
	switch {
	case err == nil:
	case errors.Is(s.p.substrateError(err), compute.ErrNotFound):
		// Already gone. Teardown has to be re-runnable.
		return nil
	default:
		return s.p.substrateError(err)
	}
	if err := checkOwned(tags, "bucket", componentBucket, name); err != nil {
		return err
	}
	empty, err := s.p.sub.S3.IsEmpty(ctx, name)
	if err != nil {
		return s.p.substrateError(err)
	}
	if !empty {
		return fmt.Errorf("%w: compute/aws: bucket %q still holds objects. This provider does not "+
			"empty a bucket to delete it: the objects are the caller's data and removing them is a "+
			"decision apphub is not entitled to make as a side effect of a teardown. Empty it "+
			"deliberately, or use a lifecycle rule", compute.ErrFailed, name)
	}
	if err := s.p.sub.S3.DeleteBucket(ctx, name); err != nil {
		if errors.Is(s.p.substrateError(err), compute.ErrNotFound) {
			return nil
		}
		return s.p.substrateError(err)
	}
	return nil
}

// EmptyBucket implements [compute.ObjectStore].
//
// Every version and every delete marker, not just the objects a listing shows.
// A versioned bucket whose objects an application "deleted" holds nothing a
// plain listing can see and still refuses DeleteBucket, so an EmptyBucket that
// listed objects would report success on exactly the bucket it was called to
// clear -- and [objectStore.DeleteBucket]'s IsEmpty precondition would agree
// with it, leaving S3's own refusal as the first thing to notice.
//
// Ownership is checked once, before anything is deleted, the same way
// DeleteBucket checks it: this is the most destructive call on the port, and an
// unowned bucket is somebody else's data.
//
// Each round lists the first page of what is left and deletes that page in one
// batch, until a listing comes back empty. The two S3 limits are both
// [s3MaxKeys], so a page is always one request, and listing from the start each
// time needs no continuation marker into a listing that is being deleted under
// it. A round that deletes a page and then lists it again has made no progress,
// and that is refused rather than looped on: S3 has accepted a delete it did not
// perform, and retrying the same request cannot change that.
//
// Cancellation is checked before each round, so a caller that gives up stops the
// deletion at a batch boundary. What was deleted before that stays deleted; a
// later call finishes the job, which is what makes the operation idempotent.
func (s *objectStore) EmptyBucket(ctx context.Context, ref compute.Ref) error {
	name, err := s.p.resolveFlavoured(ref, flavourBucket)
	if err != nil {
		return err
	}
	tags, err := s.p.sub.S3.GetBucketTagging(ctx, name)
	switch {
	case err == nil:
	case errors.Is(s.p.substrateError(err), compute.ErrNotFound):
		// Nothing to empty. Teardown has to be re-runnable.
		return nil
	default:
		return s.p.substrateError(err)
	}
	if err := checkOwned(tags, "bucket", componentBucket, name); err != nil {
		return err
	}
	err = s.emptyOwned(ctx, name)
	if errors.Is(err, compute.ErrNotFound) {
		// Deleted under this call. Gone is empty.
		return nil
	}
	return err
}

// emptyOwned runs [objectStore.EmptyBucket]'s rounds against a bucket whose
// ownership has already been checked.
func (s *objectStore) emptyOwned(ctx context.Context, name string) error {
	var previous []ObjectVersion
	for {
		if err := ctx.Err(); err != nil {
			return s.p.substrateError(err)
		}
		page, err := s.p.sub.S3.ListObjectVersions(ctx, name)
		if err != nil {
			return s.p.substrateError(err)
		}
		if len(page) == 0 {
			return nil
		}
		if len(previous) > 0 && page[0] == previous[0] {
			return fmt.Errorf("%w: compute/aws: bucket %q still lists key %q version %q after a "+
				"batch delete of it succeeded. S3 accepted the delete and did not perform it, "+
				"which retrying the same request cannot change; check the bucket for Object Lock "+
				"or MFA Delete, either of which keeps a version this provider cannot remove",
				compute.ErrFailed, name, page[0].Key, page[0].VersionID)
		}
		if err := s.p.sub.S3.DeleteObjectVersions(ctx, name, page); err != nil {
			return s.p.substrateError(err)
		}
		previous = page
	}
}

// grantPolicyName is the inline-policy name for one bucket's access.
//
// One policy per (flavour, bucket) rather than one policy per role holding every
// bucket. The source system's equivalent writes a single document naming every
// resource the application can reach, so a revoke has to rewrite it -- and a
// rewrite that races with a concurrent grant drops the other grant silently.
// Per-resource names make grant and revoke independent operations on disjoint
// objects.
//
// The flavour is in the name, not just the bucket, because the three services
// have separate namespaces: a general-purpose bucket and a table bucket can hold
// the same name at once, and a policy name that ignored the flavour would make a
// grant on one silently overwrite the grant on the other.
func grantPolicyName(flavour, bucket string) (string, error) {
	name := "apphub-" + flavour + "-" + bucket
	if len(name) > maxIAMPolicyName {
		return "", fmt.Errorf("%w: compute/aws: the inline policy name for %s %q would be %d "+
			"characters, over IAM's limit of %d", compute.ErrInvalidSpec, flavour, bucket,
			len(name), maxIAMPolicyName)
	}
	if !iamRoleName.MatchString(name) {
		return "", fmt.Errorf("%w: compute/aws: %q is not a legal IAM policy name",
			compute.ErrInvalidSpec, name)
	}
	return name, nil
}

// maxIAMPolicyName is IAM's limit on an inline policy name.
const maxIAMPolicyName = 128

// Grant implements [compute.Granter], and the same method serves the two ext
// ports because [ext.TableBucketProvisioner.Grant] has the identical signature.
//
// The grant is an inline policy on the *identity's* role, not a resource policy
// on the bucket. Both would work and only one of them is the provider's to own: a
// resource policy is a single document per resource, so two providers granting to
// one bucket would contend for it -- and a resource policy can also name a
// principal outside this account, which is the cross-domain case this package
// refuses to be able to express at all.
func (s *objectStore) Grant(ctx context.Context, resource, identity compute.Ref, level compute.AccessLevel) error {
	target, role, err := s.grantTargets(ctx, resource, identity)
	if err != nil {
		return err
	}
	policy, err := grantPolicyName(target.flavour, target.name)
	if err != nil {
		return err
	}
	doc, err := s.grantDocument(target, level)
	if err != nil {
		return err
	}
	if err := s.p.sub.IAM.PutRolePolicy(ctx, role, policy, doc); err != nil {
		return s.p.substrateError(err)
	}
	return nil
}

// Revoke implements [compute.Granter].
func (s *objectStore) Revoke(ctx context.Context, resource, identity compute.Ref) error {
	target, role, err := s.grantTargets(ctx, resource, identity)
	if err != nil {
		return err
	}
	policy, err := grantPolicyName(target.flavour, target.name)
	if err != nil {
		return err
	}
	if err := s.p.sub.IAM.DeleteRolePolicy(ctx, role, policy); err != nil {
		if errors.Is(s.p.substrateError(err), compute.ErrNotFound) {
			// Revoking an absent grant returns nil, per [compute.Granter].
			return nil
		}
		return s.p.substrateError(err)
	}
	return nil
}

// DescribeGrant implements [compute.Granter], and serves the two ext bucket
// ports for the same reason [objectStore.Grant] does.
//
// The level is recovered from the standing document rather than remembered, which
// is the property that makes this worth having: a provider that returned the last
// level it was asked for would satisfy every round-trip check while a grant that
// never reached IAM looked present. See [levelFromStoredPolicy].
//
// [compute.ErrNotFound] covers both "no grant" and "no such bucket", as
// [compute.GrantInfo] documents — and here they arrive by different routes:
// grantTargets refuses an absent bucket, and IAM's ErrNoSuchResource reports an
// absent policy.
func (s *objectStore) DescribeGrant(ctx context.Context, resource, identity compute.Ref) (*compute.GrantInfo, error) {
	target, role, err := s.grantTargets(ctx, resource, identity)
	if err != nil {
		return nil, err
	}
	policy, err := grantPolicyName(target.flavour, target.name)
	if err != nil {
		return nil, err
	}
	doc, err := s.p.sub.IAM.GetRolePolicy(ctx, role, policy)
	if err != nil {
		mapped := s.p.substrateError(err)
		if errors.Is(mapped, compute.ErrNotFound) {
			// No inline policy under this name means no grant on this pair. The
			// role exists — grantTargets established that — so this is the
			// ordinary "nothing granted" answer rather than a missing resource.
			return nil, fmt.Errorf("%w: compute/aws: role %q holds no grant on %s %q",
				compute.ErrNotFound, role, target.flavour, target.name)
		}
		return nil, mapped
	}
	level, err := levelFromStoredPolicy(doc, func(l compute.AccessLevel) (string, error) {
		return s.grantDocument(target, l)
	})
	if err != nil {
		return nil, err
	}
	return &compute.GrantInfo{Resource: resource, Identity: identity, Level: level}, nil
}

// grantTarget is a resolved, ownership-checked grant subject.
type grantTarget struct {
	flavour string
	name    string
	// arn is what the policy names. For a general-purpose bucket it is composed
	// (S3 reports none); for the other two it is read back from the service,
	// because those ARNs carry the account identifier.
	arn string
}

// grantDocument renders the policy for one target and level.
func (s *objectStore) grantDocument(t grantTarget, level compute.AccessLevel) (string, error) {
	switch t.flavour {
	case flavourBucket:
		return bucketAccessPolicy(partitionFor(s.p.cfg.Region), t.name, level)
	case flavourTableBucket:
		actions, err := tableActions(level)
		if err != nil {
			return "", err
		}
		return extAccessPolicy(t.arn, actions)
	case flavourVectorBucket:
		actions, err := vectorActions(level)
		if err != nil {
			return "", err
		}
		return extAccessPolicy(t.arn, actions)
	default:
		return "", fmt.Errorf("%w: compute/aws: unknown bucket flavour %q", compute.ErrInvalidSpec, t.flavour)
	}
}

// grantTargets resolves both refs and checks that this platform owns both ends.
//
// Both, not one. A grant is an edge between two resources and either end being
// somebody else's makes it somebody else's edge: writing a policy onto a role
// this platform did not create modifies a stranger's permissions, and granting
// access to a bucket it did not create hands out access to a stranger's data. The
// source system checks neither.
//
// The bucket end is checked against the service the flavour names, which is the
// whole reason the flavour is in the Ref: checking a table bucket's ownership by
// reading the general-purpose bucket of the same name would be checking a
// different resource.
func (s *objectStore) grantTargets(ctx context.Context, resource, identity compute.Ref) (grantTarget, string, error) {
	var zero grantTarget
	flavour, err := bucketFlavour(resource)
	if err != nil {
		return zero, "", err
	}
	name, err := s.p.resolveFlavoured(resource, flavour)
	if err != nil {
		return zero, "", err
	}
	role, err := s.p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return zero, "", err
	}

	target := grantTarget{flavour: flavour, name: name}
	switch flavour {
	case flavourBucket:
		tags, terr := s.p.sub.S3.GetBucketTagging(ctx, name)
		if terr != nil {
			return zero, "", s.p.substrateError(terr)
		}
		if oerr := checkOwned(tags, "bucket", componentBucket, name); oerr != nil {
			return zero, "", oerr
		}
		target.arn = bucketARN(partitionFor(s.p.cfg.Region), name)
	case flavourTableBucket:
		if s.p.sub.S3Tables == nil {
			return zero, "", s.p.unsupported(compute.CapObjectStore, "Substrate.S3Tables is nil")
		}
		rec, gerr := s.p.sub.S3Tables.GetTableBucket(ctx, name)
		if gerr != nil {
			return zero, "", s.p.substrateError(gerr)
		}
		if oerr := checkOwned(rec.Tags, "table bucket", componentTableBucket, name); oerr != nil {
			return zero, "", oerr
		}
		target.arn = rec.ARN
	case flavourVectorBucket:
		if s.p.sub.S3Vectors == nil {
			return zero, "", s.p.unsupported(compute.CapObjectStore, "Substrate.S3Vectors is nil")
		}
		rec, gerr := s.p.sub.S3Vectors.GetVectorBucket(ctx, name)
		if gerr != nil {
			return zero, "", s.p.substrateError(gerr)
		}
		if oerr := checkOwned(rec.Tags, "vector bucket", componentVectorBucket, name); oerr != nil {
			return zero, "", oerr
		}
		target.arn = rec.ARN
	}

	rec, err := s.p.sub.IAM.GetRole(ctx, role)
	if err != nil {
		return zero, "", s.p.substrateError(err)
	}
	if err := checkOwned(rec.Tags, "role", componentIdentity, role); err != nil {
		return zero, "", err
	}
	return target, role, nil
}

// listGrants names every bucket grant on a role, across all three flavours.
//
// Used by the harness, which is the only thing that needs to enumerate them. It
// lives here because the naming convention lives here, and a second place that
// knows the prefix is a second place that can disagree about it.
func listGrants(ctx context.Context, iam IAMAPI, role string) ([]string, error) {
	names, err := iam.ListRolePolicyNames(ctx, role)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		for _, f := range []string{flavourBucket, flavourTableBucket, flavourVectorBucket} {
			if strings.HasPrefix(n, "apphub-"+f+"-") {
				out = append(out, n)
				break
			}
		}
	}
	return out, nil
}
