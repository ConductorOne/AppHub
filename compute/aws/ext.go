// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/ext"
)

// This file implements the two optional S3 ports, reached only through
// compute/ext's lookups. Nothing in this package calls them, and nothing in the
// core object-store path can: they are here because the substrate has them and
// the portable interface deliberately does not.
//
// [ext.ExternalAccessGranter] is NOT implemented, and that is a ruling rather
// than an omission. See
// docs/decisions/usoss-37-the-cross-domain-grant-seam-stays-with-no-production-implementation.md
// and docs/decisions/usoss-13-cross-domain-object-access-is-not-ported.md.
// [policyDocument]'s grammar cannot express a cross-account statement, so the
// refusal is structural and not a matter of nobody having written the method.

var (
	_ ext.TableBucketProvisioner  = (*objectStore)(nil)
	_ ext.VectorBucketProvisioner = (*objectStore)(nil)
)

// componentTableBucket and componentVectorBucket are the ownership components.
//
// Distinct from [componentBucket] rather than shared, because the three are
// different services with different namespaces: a table bucket and a general
// bucket can hold the same name at once, and a check that could not tell them
// apart would let an Ensure of one adopt the other's tags.
const (
	componentTableBucket  = "table-bucket"
	componentVectorBucket = "vector-bucket"
)

// refuseUnapplicableSpec rejects the parts of a [compute.BucketSpec] that neither
// S3 Tables nor S3 Vectors can express.
//
// Refusing rather than ignoring, and the reason is the read-back invariant rather
// than tidiness. Both Ensures return a *Bucket carrying the effective spec, and
// the contract is that the effective spec is what the substrate has. An Ensure
// that accepted Class=zonal, applied nothing, and echoed Spec.Class=zonal back
// would not merely have a gap -- it would report the gap as configured state, and
// a caller reading it back has no way to discover otherwise. **Accept-and-ignore
// is the worst of the three options, and echoing it back as effective is what
// turns a gap into a lie.**
//
// So: name the limit, refuse at the spec, and let the caller decide. Neither
// service has a storage class, an availability zone, or a public-access control,
// so all three are refused rather than silently dropped.
func refuseUnapplicableSpec(kind string, spec compute.BucketSpec) error {
	if spec.Class != "" && spec.Class != compute.ObjectClassStandard {
		return fmt.Errorf("%w: compute/aws: a %s has no storage class, and %q cannot be applied to "+
			"one. The class is refused rather than ignored: an Ensure that dropped it would return "+
			"an effective spec claiming a class the substrate does not have",
			compute.ErrInvalidSpec, kind, spec.Class)
	}
	if spec.Zone != "" {
		return fmt.Errorf("%w: compute/aws: a %s is regional and has no availability zone, so Zone "+
			"%q cannot be applied. A caller who named a zone is relying on placement that would "+
			"not happen", compute.ErrInvalidSpec, kind, spec.Zone)
	}
	if spec.PublicAccess {
		return fmt.Errorf("%w: compute/aws: a %s has no public-access control to clear, so "+
			"PublicAccess true cannot be honoured and must not be reported as effective. Neither "+
			"service serves anonymous requests at all, which is why this is a refusal rather than "+
			"a silent false", compute.ErrUnsupported, kind)
	}
	return nil
}

// EnsureTableBucket implements [ext.TableBucketProvisioner].
//
// Tags at create time, because that is all the service offers in the shape this
// needs: there is no separate table-bucket tagging call here, so an untagged
// table bucket is a failed create rather than a converge that has not run. The
// consequence is worth stating -- a create that succeeds and whose tags do not
// arrive is not a state this can produce, which is a stronger guarantee than the
// general-purpose path has.
func (s *objectStore) EnsureTableBucket(ctx context.Context, spec compute.BucketSpec) (*compute.Bucket, error) {
	if s.p.sub.S3Tables == nil {
		return nil, s.p.unsupported(compute.CapObjectStore,
			"set Config.ObjectStore.TableBuckets and supply Substrate.S3Tables")
	}
	if err := refuseUnapplicableSpec("table bucket", spec); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	name, err := s.p.bucketName(spec.Name)
	if err != nil {
		return nil, err
	}
	rec, err := s.p.sub.S3Tables.GetTableBucket(ctx, name)
	switch {
	case err == nil:
		if oerr := checkOwned(rec.Tags, "table bucket", componentTableBucket, name); oerr != nil {
			return nil, oerr
		}
	case errors.Is(s.p.substrateError(err), compute.ErrNotFound):
		rec, err = s.p.sub.S3Tables.CreateTableBucket(ctx, name,
			ownershipTags(spec.Name, componentTableBucket, spec.Labels))
		if err != nil {
			return nil, s.p.substrateError(err)
		}
	default:
		return nil, s.p.substrateError(err)
	}
	return &compute.Bucket{
		Ref:   s.p.flavouredRef(flavourTableBucket, name),
		Name:  name,
		Class: compute.ObjectClassStandard,
		// The ARN the service reported, not one composed here. A table bucket
		// ARN carries the account identifier, and this package holds none.
		URI: rec.ARN,
		// The EFFECTIVE spec, which is what the substrate has rather than what
		// the caller asked for: Class normalised, Labels read back off the record.
		// See [effectiveExtSpec] for why the labels cannot come from the request.
		Spec: effectiveExtSpec(spec, rec.Tags),
	}, nil
}

// DeleteTableBucket implements [ext.TableBucketProvisioner].
func (s *objectStore) DeleteTableBucket(ctx context.Context, ref compute.Ref) error {
	if s.p.sub.S3Tables == nil {
		return s.p.unsupported(compute.CapObjectStore,
			"set Config.ObjectStore.TableBuckets and supply Substrate.S3Tables")
	}
	name, err := s.p.resolveFlavoured(ref, flavourTableBucket)
	if err != nil {
		return err
	}
	rec, err := s.p.sub.S3Tables.GetTableBucket(ctx, name)
	switch {
	case err == nil:
	case errors.Is(s.p.substrateError(err), compute.ErrNotFound):
		return nil
	default:
		return s.p.substrateError(err)
	}
	if err := checkOwned(rec.Tags, "table bucket", componentTableBucket, name); err != nil {
		return err
	}
	if err := s.p.sub.S3Tables.DeleteTableBucket(ctx, rec.ARN); err != nil {
		if errors.Is(s.p.substrateError(err), compute.ErrNotFound) {
			return nil
		}
		return s.p.substrateError(err)
	}
	return nil
}

// EnsureVectorBucket implements [ext.VectorBucketProvisioner].
func (s *objectStore) EnsureVectorBucket(ctx context.Context, spec compute.BucketSpec) (*compute.Bucket, error) {
	if s.p.sub.S3Vectors == nil {
		return nil, s.p.unsupported(compute.CapObjectStore,
			"set Config.ObjectStore.VectorBuckets and supply Substrate.S3Vectors")
	}
	if err := refuseUnapplicableSpec("vector bucket", spec); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	name, err := s.p.bucketName(spec.Name)
	if err != nil {
		return nil, err
	}
	rec, err := s.p.sub.S3Vectors.GetVectorBucket(ctx, name)
	switch {
	case err == nil:
		if oerr := checkOwned(rec.Tags, "vector bucket", componentVectorBucket, name); oerr != nil {
			return nil, oerr
		}
	case errors.Is(s.p.substrateError(err), compute.ErrNotFound):
		rec, err = s.p.sub.S3Vectors.CreateVectorBucket(ctx, name,
			ownershipTags(spec.Name, componentVectorBucket, spec.Labels))
		if err != nil {
			return nil, s.p.substrateError(err)
		}
	default:
		return nil, s.p.substrateError(err)
	}
	return &compute.Bucket{
		Ref:   s.p.flavouredRef(flavourVectorBucket, name),
		Name:  name,
		Class: compute.ObjectClassStandard,
		// s3vectors addresses a bucket by name, which is the asymmetry with table
		// buckets. A name is what the service uses, so a name is what this
		// returns rather than an ARN composed here from an account identifier
		// this package deliberately does not hold.
		URI:  "s3vectors://" + name,
		Spec: effectiveExtSpec(spec, rec.Tags),
	}, nil
}

// DeleteVectorBucket implements [ext.VectorBucketProvisioner].
func (s *objectStore) DeleteVectorBucket(ctx context.Context, ref compute.Ref) error {
	if s.p.sub.S3Vectors == nil {
		return s.p.unsupported(compute.CapObjectStore,
			"set Config.ObjectStore.VectorBuckets and supply Substrate.S3Vectors")
	}
	name, err := s.p.resolveFlavoured(ref, flavourVectorBucket)
	if err != nil {
		return err
	}
	rec, err := s.p.sub.S3Vectors.GetVectorBucket(ctx, name)
	switch {
	case err == nil:
	case errors.Is(s.p.substrateError(err), compute.ErrNotFound):
		return nil
	default:
		return s.p.substrateError(err)
	}
	if err := checkOwned(rec.Tags, "vector bucket", componentVectorBucket, name); err != nil {
		return err
	}
	if err := s.p.sub.S3Vectors.DeleteVectorBucket(ctx, name); err != nil {
		if errors.Is(s.p.substrateError(err), compute.ErrNotFound) {
			return nil
		}
		return s.p.substrateError(err)
	}
	return nil
}

// Grant and Revoke on the ext ports are the general-purpose ones: a table bucket
// and a vector bucket are both authorised by an IAM policy on the caller's role,
// which is what [objectStore.Grant] already writes. They are inherited rather
// than reimplemented so there is one place that decides what an access level
// means.

// effectiveExtSpec is the spec as the substrate holds it: Class normalised, and
// Labels read off the record rather than copied from the request.
//
// # Why Labels cannot come from the request
//
// An earlier version copied everything but Class and said above the call site
// that "the fields that could have differed were refused above, so nothing here
// can be an echo". Labels could differ and were not refused, and neither ext
// Ensure reconciles tags on the adopt path -- unlike [objectStore.EnsureBucket],
// which calls reconcileTags. So a caller who changed a label and re-Ensured was
// told the new label was effective while the bucket still carried the old one.
//
// That is the exact shape [refuseUnapplicableSpec] was written to prevent, one
// field over: **accept-and-ignore is the worst of the three options, and echoing
// it back as effective is what turns a gap into a lie.** The comment claiming it
// could not happen here is the part that made it hard to see.
//
// Reading the record closes it without adding a capability. Neither S3 Tables nor
// S3 Vectors exposes a tagging call on [S3TablesAPI] or [S3VectorsAPI], so this
// provider genuinely cannot converge a label after create -- but reporting what
// the substrate holds means a caller can *discover* that, which is the whole
// difference between a gap and a lie. Converging them is a capability these
// interfaces would have to grow first; USOSS-13 records it as not done rather
// than as done.
//
// Both branches read the same way, create included: every create here passes the
// ownership tags into the create call and gets a record back carrying them, so
// the tags are the substrate's answer on both paths rather than the request's on
// one and the substrate's on the other.
func effectiveExtSpec(spec compute.BucketSpec, tags map[string]string) compute.BucketSpec {
	out := spec
	out.Class = compute.ObjectClassStandard
	out.Labels = labelsFromTags(tags)
	return out
}
