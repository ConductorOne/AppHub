// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"

	"github.com/conductorone/apphub/compute"
)

// The substrate-level errors a [ParameterStore] implementation reports, so that
// the provider can map them onto the [compute] taxonomy in one place.
//
// They are this package's own sentinels rather than compute's on purpose. A
// substrate implementation should say what SSM said; deciding what that means to
// a caller above the compute interface is the provider's job, and keeping the
// two apart is what let the mapping be tested by handing the store a synthetic
// failure instead of a live service.
var (
	// ErrParameterNotFound reports that no parameter exists under the name.
	ErrParameterNotFound = errors.New("aws: parameter does not exist")

	// ErrParameterExists reports that a create-only PutParameter collided with
	// an existing parameter. It is how the ownership check learns that it lost a
	// race, rather than overwriting whatever it found.
	ErrParameterExists = errors.New("aws: parameter already exists")

	// ErrParameterTooLarge reports that the value exceeds what the parameter's
	// tier allows.
	ErrParameterTooLarge = errors.New("aws: parameter value exceeds the tier's maximum size")
)

// ParameterTier is the SSM parameter tier a secret is stored in.
//
// Intelligent-Tiering is deliberately absent. Its whole behaviour is to promote
// a parameter to the advanced tier when the value exceeds the standard limit,
// which means the maximum size a caller can rely on is not knowable from the
// configuration — and a provider whose "value too large" boundary moves on its
// own cannot have the documented, tested behaviour this port is required to
// have. An operator who wants the advanced limit asks for it.
type ParameterTier string

// The tiers this provider offers, with the value limits AWS documents for each.
const (
	// TierStandard is the free tier: up to [MaxStandardValueBytes] and no
	// per-parameter charge.
	TierStandard ParameterTier = "Standard"

	// TierAdvanced raises the value limit to [MaxAdvancedValueBytes] and is
	// billed per parameter per month, which is why it is opt-in.
	TierAdvanced ParameterTier = "Advanced"
)

// The documented value-size limits, in bytes, of each tier.
const (
	// MaxStandardValueBytes is the standard tier's maximum value size.
	MaxStandardValueBytes = 4096
	// MaxAdvancedValueBytes is the advanced tier's maximum value size.
	MaxAdvancedValueBytes = 8192
)

// MaxValueBytes returns the tier's documented maximum value size, or zero for a
// tier this provider does not offer.
func (t ParameterTier) MaxValueBytes() int {
	switch t {
	case TierStandard:
		return MaxStandardValueBytes
	case TierAdvanced:
		return MaxAdvancedValueBytes
	default:
		return 0
	}
}

// PutParameterInput is one write to Parameter Store.
type PutParameterInput struct {
	// Name is the fully qualified parameter name, leading slash included.
	Name string

	// Value is the material. It is a [compute.SecretValue] rather than a string
	// so that the substrate boundary itself cannot leak it through a formatting
	// verb: a PutParameterInput printed with %v or %+v redacts.
	Value compute.SecretValue

	// KeyID is the KMS key that encrypts the value. Empty means the account's
	// default SSM key.
	KeyID string

	// Tier is the parameter tier.
	Tier ParameterTier

	// Tags are applied at creation. They are only honoured when Overwrite is
	// false: SSM rejects a PutParameter that carries both Tags and
	// Overwrite=true, which is why the source system tagged in a second call
	// and, because it discarded that call's error (container.go:320), could
	// leave a parameter untagged and therefore unowned.
	Tags map[string]string

	// Overwrite permits replacing an existing parameter. When false, a
	// collision is [ErrParameterExists].
	Overwrite bool
}

// ParameterMetadata is what a listing returns.
//
// It has no value field, and that absence is the point. "No secret value may be
// returned by a listing operation" is a requirement this port has to meet, and
// a type that cannot carry a value meets it by construction — there is no
// correct-looking code path that returns one. The SSM-backed implementation
// therefore uses DescribeParameters, which returns metadata only, rather than
// GetParametersByPath, which returns values.
type ParameterMetadata struct {
	// Name is the fully qualified parameter name.
	Name string
	// ARN is the parameter's ARN, as the service reports it.
	//
	// It is read back rather than composed, which is the same decision the
	// registry port made for a repository: a [compute.Ref] deliberately carries
	// a name and not an ARN, so that no persisted application record holds an
	// account identifier, and the way back to an ARN is therefore to ask the
	// substrate rather than to reconstruct one from a template. The source
	// system reconstructed ARNs by string template in a dozen places
	// (bucket.go:194-215, container.go:1530-1537), which is the coupling a Ref
	// exists to prevent.
	ARN string
	// Tier is the tier the parameter is in.
	Tier ParameterTier
	// Version is the parameter's current version number.
	Version int64
	// KeyID is the KMS key encrypting it, when the service reports one.
	KeyID string
}

// ParameterStore is the subset of SSM Parameter Store this provider uses.
//
// SEVEN operations, and the count is stated because it is checkable: Put, Get,
// Describe, DescribeByPath, Tags, SetTags, Delete. It said six, which was wrong
// and is the kind of wrong that reads as a stronger claim than the interface
// makes.
//
// Enumerating them is the point: a reader can see that the port never LISTS
// values, reads a value only through [ParameterStore.Get], and has no way to ask
// for "every parameter in the account". Note what that does and does not say --
// Get returns material, by design and by necessity, and this port is therefore
// not value-free. What it is, is value-free on every path except one, with that
// one named and single-callered.
type ParameterStore interface {
	// Put writes a parameter and returns the version it created. A create-only
	// Put that collides returns an error satisfying errors.Is against
	// [ErrParameterExists]; a value over the tier's limit returns one satisfying
	// [ErrParameterTooLarge].
	//
	// The version is returned because [compute.SecretStore.Put] has to report
	// it: without it, [compute.SecretBinding.Version] is a field the write path
	// cannot fill. SSM supplies it on the response
	// (PutParameterOutput.Version), so this costs nothing.
	Put(ctx context.Context, in PutParameterInput) (int64, error)

	// Get reads a parameter's value, decrypting it. It is the one operation
	// that returns material, and [compute.SecretStore.Get] is the one caller.
	// An absent parameter is [ErrParameterNotFound].
	Get(ctx context.Context, name string) (compute.SecretValue, error)

	// Describe returns metadata for one parameter, or [ErrParameterNotFound].
	Describe(ctx context.Context, name string) (ParameterMetadata, error)

	// DescribeByPath returns metadata for every parameter at or below path,
	// recursively. Metadata only: see [ParameterMetadata].
	DescribeByPath(ctx context.Context, path string) ([]ParameterMetadata, error)

	// Tags returns a parameter's tags, or [ErrParameterNotFound].
	Tags(ctx context.Context, name string) (map[string]string, error)

	// SetTags applies add and removes remove, in that order. Removing a tag
	// that is not present is not an error: converging on a tag set has to be
	// re-runnable.
	SetTags(ctx context.Context, name string, add map[string]string, remove []string) error

	// Delete removes a parameter. Deleting an absent parameter returns
	// [ErrParameterNotFound]; turning that into the nil the compute interface
	// requires is the provider's job, not the substrate's, so that a substrate
	// cannot hide a delete that failed for some other reason.
	Delete(ctx context.Context, name string) error
}
