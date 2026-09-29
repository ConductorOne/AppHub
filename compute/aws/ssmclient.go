// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"

	smithy "github.com/aws/smithy-go"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/conductorone/apphub/compute"
)

// SSMAPI is the set of SSM operations [SSMParameterStore] calls.
//
// A narrow interface over the generated client rather than the client itself,
// so that the translation layer below can be tested by handing it the SDK's own
// error types — which is where the interesting behaviour is. It is satisfied by
// *ssm.Client.
type SSMAPI interface {
	PutParameter(ctx context.Context, in *ssm.PutParameterInput, opts ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	DescribeParameters(ctx context.Context, in *ssm.DescribeParametersInput, opts ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error)
	ListTagsForResource(ctx context.Context, in *ssm.ListTagsForResourceInput, opts ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error)
	AddTagsToResource(ctx context.Context, in *ssm.AddTagsToResourceInput, opts ...func(*ssm.Options)) (*ssm.AddTagsToResourceOutput, error)
	RemoveTagsFromResource(ctx context.Context, in *ssm.RemoveTagsFromResourceInput, opts ...func(*ssm.Options)) (*ssm.RemoveTagsFromResourceOutput, error)
	DeleteParameter(ctx context.Context, in *ssm.DeleteParameterInput, opts ...func(*ssm.Options)) (*ssm.DeleteParameterOutput, error)
}

// SSMParameterStore is the [ParameterStore] backed by SSM Parameter Store.
//
// It is a translation layer and nothing else: every decision about what a
// failure means to a caller is made in secret.go, against the sentinels this
// file maps AWS's error shapes onto. That split is deliberate — the source
// system branched on AWS error shapes at the call sites (a smithy error code
// compared against "InvalidPermission.Duplicate" in build.go:872-878, a string
// match on "RepositoryNotFoundException" in build.go:434-441), which puts a
// provider dependency inside every conditional in the deploy path.
type SSMParameterStore struct {
	api SSMAPI

	// describePageSize bounds one DescribeParameters call. Exposed for tests,
	// which need more than one page without creating fifty parameters.
	describePageSize int32
}

// NewSSMParameterStore returns a [ParameterStore] over an SSM client.
//
// Supplying the client keeps this adapter independent of credential discovery.
// Hosted callers use NewFromConfig, which loads ambient operator credentials and
// attaches this store only when Config.Secrets is enabled.
func NewSSMParameterStore(api SSMAPI) *SSMParameterStore {
	return &SSMParameterStore{api: api, describePageSize: 50}
}

var _ ParameterStore = (*SSMParameterStore)(nil)

// Put implements [ParameterStore].
//
// Tags are sent only on the create-only path. SSM rejects a PutParameter that
// carries both Tags and Overwrite=true, which is the constraint that made the
// source system tag in a second call; see [secretStore] for why that mattered.
func (s *SSMParameterStore) Put(ctx context.Context, in PutParameterInput) (int64, error) {
	tier, err := ssmTier(in.Tier)
	if err != nil {
		return 0, err
	}
	req := &ssm.PutParameterInput{
		Name: awssdk.String(in.Name),
		// Reveal at the boundary, into the request the SDK is about to
		// serialise, and nowhere else. This is the only place in the package
		// where material is written out.
		Value: awssdk.String(compute.RevealSecret(in.Value)),
		// Never configurable: see [secretStore].
		Type:      ssmtypes.ParameterTypeSecureString,
		Tier:      tier,
		Overwrite: awssdk.Bool(in.Overwrite),
	}
	if in.KeyID != "" {
		req.KeyId = awssdk.String(in.KeyID)
	}
	if !in.Overwrite {
		req.Tags = ssmTags(in.Tags)
	}
	out, err := s.api.PutParameter(ctx, req)
	if err != nil {
		return 0, ssmError(err, in.Name)
	}
	if out == nil {
		return 0, fmt.Errorf("ssm: PutParameter for %s returned no result", in.Name)
	}
	return out.Version, nil
}

// Get implements [ParameterStore].
func (s *SSMParameterStore) Get(ctx context.Context, name string) (compute.SecretValue, error) {
	out, err := s.api.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           awssdk.String(name),
		WithDecryption: awssdk.Bool(true),
	})
	if err != nil {
		return compute.SecretValue{}, ssmError(err, name)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		// A 200 with no value is not something the service does, but the field
		// is a pointer and an empty secret is worse than an error: it would be
		// injected into a workload as an empty credential.
		return compute.SecretValue{}, fmt.Errorf("%w: parameter %s came back with no value",
			ErrParameterNotFound, name)
	}
	return compute.NewSecretValue(*out.Parameter.Value), nil
}

// Describe implements [ParameterStore].
//
// It filters DescribeParameters on an exact name rather than calling
// GetParameter, because GetParameter returns the value and this operation has
// no use for it. Asking for less is the whole point.
func (s *SSMParameterStore) Describe(ctx context.Context, name string) (ParameterMetadata, error) {
	out, err := s.api.DescribeParameters(ctx, &ssm.DescribeParametersInput{
		MaxResults: awssdk.Int32(s.describePageSize),
		ParameterFilters: []ssmtypes.ParameterStringFilter{{
			Key:    awssdk.String("Name"),
			Option: awssdk.String("Equals"),
			Values: []string{name},
		}},
	})
	if err != nil {
		return ParameterMetadata{}, ssmError(err, name)
	}
	for _, meta := range out.Parameters {
		if awssdk.ToString(meta.Name) == name {
			return parameterMetadata(meta), nil
		}
	}
	return ParameterMetadata{}, fmt.Errorf("%w: %s", ErrParameterNotFound, name)
}

// DescribeByPath implements [ParameterStore].
//
// DescribeParameters with a recursive Path filter, not GetParametersByPath. The
// two enumerate the same set; only one of them returns the values as well, and
// a teardown has no use for material. See [ParameterMetadata].
//
// The Recursive path option is a hierarchy match rather than a string-prefix
// match, so a scope path of ".../app-1" does not enumerate ".../app-1x". That
// distinction is what keeps DeleteScope from deleting another application's
// secrets, and because it is a property of the service rather than of this code,
// MemoryParameters.DescribeByPath implements the hierarchy semantics explicitly
// instead of a prefix compare -- a fake that were more permissive than the
// service would let this port pass its own tests and delete the wrong thing.
func (s *SSMParameterStore) DescribeByPath(ctx context.Context, path string) ([]ParameterMetadata, error) {
	var (
		out   []ParameterMetadata
		token *string
	)
	for {
		page, err := s.api.DescribeParameters(ctx, &ssm.DescribeParametersInput{
			MaxResults: awssdk.Int32(s.describePageSize),
			NextToken:  token,
			ParameterFilters: []ssmtypes.ParameterStringFilter{{
				Key:    awssdk.String("Path"),
				Option: awssdk.String("Recursive"),
				Values: []string{path},
			}},
		})
		if err != nil {
			return nil, ssmError(err, path)
		}
		for _, meta := range page.Parameters {
			out = append(out, parameterMetadata(meta))
		}
		// A paginated listing that stops early is how a teardown leaves
		// credentials behind and reports success, so the loop ends only when
		// the service says there is no more.
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

// Tags implements [ParameterStore].
func (s *SSMParameterStore) Tags(ctx context.Context, name string) (map[string]string, error) {
	out, err := s.api.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{
		ResourceType: ssmtypes.ResourceTypeForTaggingParameter,
		ResourceId:   awssdk.String(name),
	})
	if err != nil {
		return nil, ssmError(err, name)
	}
	tags := make(map[string]string, len(out.TagList))
	for _, t := range out.TagList {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return tags, nil
}

// SetTags implements [ParameterStore]. Adds first, then removes, so that a
// failure between the two leaves the ownership tag in place rather than
// stripping it.
func (s *SSMParameterStore) SetTags(ctx context.Context, name string, add map[string]string, remove []string) error {
	if len(add) > 0 {
		if _, err := s.api.AddTagsToResource(ctx, &ssm.AddTagsToResourceInput{
			ResourceType: ssmtypes.ResourceTypeForTaggingParameter,
			ResourceId:   awssdk.String(name),
			Tags:         ssmTags(add),
		}); err != nil {
			return ssmError(err, name)
		}
	}
	if len(remove) > 0 {
		if _, err := s.api.RemoveTagsFromResource(ctx, &ssm.RemoveTagsFromResourceInput{
			ResourceType: ssmtypes.ResourceTypeForTaggingParameter,
			ResourceId:   awssdk.String(name),
			TagKeys:      remove,
		}); err != nil {
			return ssmError(err, name)
		}
	}
	return nil
}

// Delete implements [ParameterStore].
func (s *SSMParameterStore) Delete(ctx context.Context, name string) error {
	if _, err := s.api.DeleteParameter(ctx, &ssm.DeleteParameterInput{Name: awssdk.String(name)}); err != nil {
		return ssmError(err, name)
	}
	return nil
}

// ssmTier maps a tier onto the SDK enum, refusing one this provider does not
// offer rather than sending an empty value — an empty Tier makes Parameter
// Store apply the account's default tier configuration, which may be
// Intelligent-Tiering, and then the value-size limit this port documents is not
// the one in force.
func ssmTier(t ParameterTier) (ssmtypes.ParameterTier, error) {
	switch t {
	case TierStandard:
		return ssmtypes.ParameterTierStandard, nil
	case TierAdvanced:
		return ssmtypes.ParameterTierAdvanced, nil
	default:
		return "", fmt.Errorf("%w: %q is not a parameter tier this provider offers",
			compute.ErrInvalidSpec, t)
	}
}

func ssmTags(in map[string]string) []ssmtypes.Tag {
	out := make([]ssmtypes.Tag, 0, len(in))
	for _, k := range sortedKeys(in) {
		out = append(out, ssmtypes.Tag{Key: awssdk.String(k), Value: awssdk.String(in[k])})
	}
	return out
}

func parameterMetadata(meta ssmtypes.ParameterMetadata) ParameterMetadata {
	return ParameterMetadata{
		Name:    awssdk.ToString(meta.Name),
		ARN:     awssdk.ToString(meta.ARN),
		Tier:    ParameterTier(meta.Tier),
		Version: meta.Version,
		KeyID:   awssdk.ToString(meta.KeyId),
	}
}

// ssmError maps an SDK error onto this package's substrate sentinels.
//
// Everything it does not recognise is returned wrapped, not swallowed. A
// classification that guessed would be worse than none: the caller's own
// mapping in secret.go falls through to an unclassified error, which a caller
// above the compute interface treats as an unknown failure rather than as a
// deletion or a conflict.
func ssmError(err error, name string) error {
	if err == nil {
		return nil
	}
	var (
		notFound  *ssmtypes.ParameterNotFound
		badID     *ssmtypes.InvalidResourceId
		exists    *ssmtypes.ParameterAlreadyExists
		limit     *ssmtypes.ParameterLimitExceeded
		versions  *ssmtypes.ParameterMaxVersionLimitExceeded
		denied    *smithy.GenericAPIError
		tooMany   *ssmtypes.TooManyUpdates
		throttled *ssmtypes.ThrottlingException
		internal  *ssmtypes.InternalServerError
	)
	switch {
	case errors.As(err, &notFound):
		return fmt.Errorf("%w: %s: %w", ErrParameterNotFound, name, err)
	case errors.As(err, &badID):
		// ListTagsForResource and the tagging calls report an absent parameter
		// as an invalid resource ID rather than as ParameterNotFound. Mapping
		// it to anything else would make an ownership check on a parameter that
		// has just been deleted look like a hard failure.
		return fmt.Errorf("%w: %s: %w", ErrParameterNotFound, name, err)
	case errors.As(err, &exists):
		return fmt.Errorf("%w: %s: %w", ErrParameterExists, name, err)
	case errors.As(err, &limit), errors.As(err, &versions):
		// Both are account-level ceilings rather than anything about this
		// value, and neither is retryable, so they stay unclassified with the
		// service's own message attached.
		return fmt.Errorf("ssm: %s: %w", name, err)
	case errors.As(err, &denied) && denied.ErrorCode() == "AccessDeniedException":
		// A denial is the platform's own IAM role lacking ssm:PutParameter or
		// ssm:GetParameter, and SSM reports it as a generic API error with a
		// code rather than as a modelled type -- so errors.As on a typed
		// exception cannot see it, which is why this arm did not exist.
		//
		// It matters which sentinel it becomes: ErrFailed sends an operator to
		// the parameter, and the parameter is fine. Only the role can be fixed.
		return fmt.Errorf("%w: %s: %w", ErrDenied, name, err)
	case errors.As(err, &tooMany), errors.As(err, &throttled), errors.As(err, &internal):
		return fmt.Errorf("%w: %s: %w", ErrThrottled, name, err)
	default:
		return fmt.Errorf("ssm: %s: %w", name, err)
	}
}
