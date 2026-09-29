// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// SecretConfig configures the SSM Parameter Store port.
type SecretConfig struct {
	// PathPrefix is the parameter-hierarchy root this platform owns, leading
	// slash included and no trailing slash: "/apphub/prod", say.
	//
	// Required, with no default. The source system read it from SSM_PREFIX and
	// disagreed with itself about an empty value — a hard failure on the
	// database path (container.go:284-287) and a silent skip on the
	// secret-injection path (container.go:652-653). A silent skip means an
	// application deploys without the secrets it asked for, so the empty case
	// is now one refusal at construction.
	PathPrefix string `yaml:"pathPrefix" json:"pathPrefix"`

	// KMSKeyARN is the KMS key that encrypts every parameter this port writes,
	// as a full key or alias ARN.
	//
	// An ARN rather than a bare key ID or alias, and that is a deliberate
	// narrowing. Composing an ARN from a bare ID needs a partition and an
	// account number, and this package never composes an ARN -- every one it
	// emits is read back from the substrate, because an ARN this package
	// assembled is a claim about the account it is running in that nothing
	// verified. A key ARN is also what an operator copies out of the KMS
	// console, so requiring it costs nothing and removes the only place an
	// account identifier would have had to be configured.
	//
	// Empty means the account's AWS-managed SSM key. That is a real difference
	// and it is worth stating: with the AWS-managed key, any principal granted
	// ssm:GetParameter on the path can decrypt, whereas a customer-managed key
	// adds a second, independent authorisation on kms:Decrypt. The
	// least-privilege policy in policy.go includes the kms:Decrypt grant only
	// when a key is configured, because granting it against the AWS-managed key
	// is neither necessary nor scopeable.
	KMSKeyARN string `yaml:"kmsKeyArn" json:"kmsKeyArn"`

	// Tier is the parameter tier. Empty means [TierStandard].
	//
	// This decides the maximum value size, which is a documented, tested
	// behaviour of this port rather than whatever the SDK happens to report.
	// See [ParameterTier] for why Intelligent-Tiering is not offered.
	Tier ParameterTier `yaml:"tier" json:"tier"`
}

// pathSegment is the scope directory every application's secrets live under.
//
// It is a layout rather than an identifier, and it matches the source system's
// "{prefix}/apps/{appId}/{name}" hierarchy (container.go:1140) so that an
// operator's existing IAM policies and their existing parameter tree describe
// the same thing. Keeping it also keeps this platform's application secrets
// distinguishable, by path, from the other trees a deployment puts under the
// same prefix.
const appsSegment = "apps"

// SSM parameter-name limits, from the Parameter Store reference. The provider
// checks both so that an over-long name is [compute.ErrInvalidSpec] rather than
// a ValidationException from a service the caller never named.
const (
	// maxParameterName is the maximum length of a fully qualified parameter
	// name, hierarchy included.
	maxParameterName = 1011

	// maxParameterARNPrefix bounds "arn:{partition}:ssm:{region}:{account}:parameter",
	// which SSM counts against maxParameterName.
	//
	// Derived rather than guessed, and deliberately an over-estimate so the
	// refusal is earlier than the service's: "arn::ssm:::parameter" is 20
	// characters of fixed text, the longest published partition name is
	// "aws-iso-f" at 9, an account number is 12, and no published region name
	// exceeds 24. 20+9+12+24 = 65.
	maxParameterARNPrefix = 65

	// maxPathElement bounds one element of a parameter path. SSM allows a
	// hierarchy level of any length within the total budget above; this keeps a
	// single element short enough that the readable part of a name survives, and
	// it is the limit [sanitizeWith] is given.
	maxPathElement = 64
	// maxParameterDepth is the maximum number of hierarchy levels.
	maxParameterDepth = 15
)

// reservedNamePrefixes are the first-level path names SSM refuses.
var reservedNamePrefixes = []string{"aws", "ssm"}

// pathPrefixPattern is a legal parameter-hierarchy root.
var pathPrefixPattern = regexp.MustCompile(`^(/[a-zA-Z0-9_.-]+)+$`)

// secretStore implements [compute.SecretStore] on SSM Parameter Store.
//
// # Why every parameter is a SecureString
//
// There is no configuration for it. A String parameter is stored in plaintext
// and is readable by anything with ssm:GetParameter, and this port's entire
// subject is credential material. Offering the choice would make the unsafe
// option one field away, and the source system's own parameter writes are
// already SecureString (source system @ backend/internal/modules/deploy/container.go),
//
// # Ownership
//
// Parameter names derive from a caller-chosen scope and name, and those derive
// from mutable application names, so two different platforms can want the same
// path. Every parameter this port creates carries [tagManagedBy], and a Put
// that finds an existing parameter without it returns [compute.ErrNotOwned]
// rather than overwriting somebody else's material.
//
// Getting that right needs the create and the tagging to be one operation,
// because a parameter that exists without the ownership tag is indistinguishable
// from somebody else's. SSM rejects a PutParameter carrying both Tags and
// Overwrite=true, so the source system tagged in a second call — and discarded
// its error (container.go:320-327). This port creates with Overwrite=false and
// Tags in the same call, so a created parameter is always tagged, and only
// takes the two-call path once it has established that the parameter is already
// its own.
type secretStore struct {
	p      *Provider
	cfg    SecretConfig
	prefix string
	tier   ParameterTier
}

var _ compute.SecretStore = (*secretStore)(nil)

func newSecretStore(p *Provider, cfg SecretConfig) (*secretStore, error) {
	prefix := cfg.PathPrefix
	if prefix == "" {
		return nil, fmt.Errorf("%w: SecretStore.PathPrefix is required; a provider with no "+
			"parameter prefix has nowhere to put a secret, and treating that as 'inject nothing' "+
			"deploys an application without the credentials it asked for", compute.ErrInvalidSpec)
	}
	if !pathPrefixPattern.MatchString(prefix) {
		return nil, fmt.Errorf("%w: SecretStore.PathPrefix %q must be an absolute parameter path "+
			"with no trailing slash, each level made of letters, digits, underscore, dot or dash",
			compute.ErrInvalidSpec, prefix)
	}
	if key := cfg.KMSKeyARN; key != "" && !strings.HasPrefix(key, "arn:") {
		return nil, fmt.Errorf("%w: SecretConfig.KMSKeyARN %q is not an ARN; this package composes "+
			"no AWS identifier, so it cannot turn a bare key id or an alias into one — and a "+
			"policy Resource element that is not an ARN is a grant IAM will not honour. Paste the "+
			"key or alias ARN the KMS console shows",
			compute.ErrInvalidSpec, key)
	}
	first := strings.SplitN(strings.TrimPrefix(prefix, "/"), "/", 2)[0]
	for _, reserved := range reservedNamePrefixes {
		if strings.EqualFold(first, reserved) {
			return nil, fmt.Errorf("%w: SecretStore.PathPrefix %q starts with %q, which SSM "+
				"reserves for its own parameters", compute.ErrInvalidSpec, prefix, first)
		}
	}
	tier := cfg.Tier
	if tier == "" {
		tier = TierStandard
	}
	if tier.MaxValueBytes() == 0 {
		return nil, fmt.Errorf("%w: SecretStore.Tier %q is not a tier this provider offers; it "+
			"offers %q and %q, and deliberately not Intelligent-Tiering, whose maximum value size "+
			"is not knowable from the configuration",
			compute.ErrInvalidSpec, tier, TierStandard, TierAdvanced)
	}
	return &secretStore{p: p, cfg: cfg, prefix: prefix, tier: tier}, nil
}

// scopePath returns the parameter path every secret in scope lives under.
//
// Each level goes through [sanitizeWith], which is this package's one naming
// function and is injective: two logical names that collapsed onto one path
// element would be one parameter with two owners, and for a scope element that
// means one application's secrets landing where another application's
// least-privilege grant already reaches. The property is asserted in
// names_internal_test.go rather than restated here.
func (s *secretStore) scopePath(scope string) (string, error) {
	seg, err := sanitizeWith("", scope, maxPathElement, digestMarker)
	if err != nil {
		return "", err
	}
	return s.prefix + "/" + appsSegment + "/" + seg, nil
}

// path returns the fully qualified parameter name for one secret.
func (s *secretStore) path(scope, name string) (string, error) {
	dir, err := s.scopePath(scope)
	if err != nil {
		return "", err
	}
	seg, err := sanitizeWith("", name, maxPathElement, digestMarker)
	if err != nil {
		return "", err
	}
	return dir + "/" + seg, nil
}

// validatePath rejects a derived name SSM could not hold, so that the caller
// learns at the spec rather than from a ValidationException.
func (s *secretStore) validatePath(name string) error {
	// SSM's 1011-character budget for a caller-specified name counts the ARN
	// prefix that precedes it, and that prefix varies with the partition, the
	// region and the account. Checking the name alone would accept a name the
	// service then rejects on a long region -- the defect would live below the
	// check's resolution.
	//
	// So the prefix is BOUNDED rather than composed. This package never composes
	// an ARN (see SecretConfig.KMSKeyARN and Provider.SecretParameterARNs for
	// why), and it does not need to in order to be safe here: an upper bound
	// refuses slightly earlier than the service would, which fails closed, while
	// a composed ARN would be a claim about the account that nothing verified.
	if total := maxParameterARNPrefix + len(name); total > maxParameterName {
		return fmt.Errorf("%w: the derived parameter name is %d characters once the ARN prefix "+
			"this account and region contribute is counted, and SSM allows %d; shorten the scope, "+
			"the secret name, or SecretStore.PathPrefix",
			compute.ErrInvalidSpec, total, maxParameterName)
	}
	if depth := strings.Count(name, "/"); depth > maxParameterDepth {
		return fmt.Errorf("%w: the derived parameter name has %d hierarchy levels and SSM allows "+
			"%d; shorten SecretStore.PathPrefix", compute.ErrInvalidSpec, depth, maxParameterDepth)
	}
	return nil
}

// Put implements [compute.SecretStore].
//
// The documented behaviour for the three cases the interface leaves open:
//
//   - The parameter already exists and this platform owns it: the value is
//     replaced, the tag set converges on the spec's labels, and the same
//     [compute.Ref] comes back. That is what "idempotent" has to mean for a
//     port whose caller is an ensure-then-use deploy loop.
//   - The parameter already exists and this platform does not own it:
//     [compute.ErrNotOwned]. Adopting it would mutate somebody else's material.
//   - The value is larger than the configured tier allows:
//     [compute.ErrInvalidSpec], decided here, before the value is sent
//     anywhere.
func (s *secretStore) Put(ctx context.Context, spec compute.SecretSpec) (compute.StoredSecret, error) {
	// Both refusals name the half of the identity that IS present. An error
	// reading only "a secret needs a name" cannot be placed by whoever reads it
	// out of a log, and it is not evidence for the conformance suite either:
	// security/secret-material-does-not-appear-in-errors searches these refusals
	// for the value that came with the spec, and a refusal composed from none of
	// the spec is clean whatever this store does with the material.
	if strings.TrimSpace(spec.Name) == "" {
		return compute.StoredSecret{}, fmt.Errorf("%w: a secret in scope %q needs a name",
			compute.ErrInvalidSpec, spec.Scope)
	}
	if strings.TrimSpace(spec.Scope) == "" {
		return compute.StoredSecret{}, fmt.Errorf("%w: secret %q needs a scope; teardown deletes by scope, "+
			"and a secret in none is one nothing will ever remove", compute.ErrInvalidSpec, spec.Name)
	}
	placement, err := s.p.cfg.placement(spec.Placement)
	if err != nil {
		return compute.StoredSecret{}, err
	}
	// AND THE PLACEMENT IS HONOURED, NOT JUST VALIDATED.
	//
	// The comment that stood here said "an SSM parameter is account-global, so
	// this provider does not place a secret anywhere". That AWS fact is wrong in
	// the direction that mattered: a parameter is REGIONAL -- its ARN carries the
	// region -- and [PlacementConfig.Region] exists precisely so placements can
	// differ in region ("a placement that could not differ in region would not be
	// one"). This store talks to one SSM client in one region, so a Put for a
	// placement in another region wrote the parameter HERE and handed the
	// workload an ARN in the wrong region.
	//
	// Refused rather than silently mis-placed. Multi-region parameter storage is
	// a feature this store does not have, and the honest form of not having it is
	// a refusal at the spec rather than a success in the wrong place.
	if placement.Region != s.p.cfg.Region {
		return compute.StoredSecret{}, fmt.Errorf("%w: placement %q is in region %s and this secret store "+
			"writes to %s; an SSM parameter is regional, so storing it here would hand the "+
			"workload an ARN in another region. Configure a provider per region",
			compute.ErrInvalidSpec, placement.Name, placement.Region, s.p.cfg.Region)
	}
	if spec.Value.IsZero() {
		// An empty SecureString is not something SSM stores, and a caller that
		// reached here with one has a bug it would otherwise discover as a
		// workload starting with an empty credential.
		return compute.StoredSecret{}, fmt.Errorf("%w: the secret has no value", compute.ErrInvalidSpec)
	}
	// Reveal is called for the length and nothing else, and the result is not
	// bound to a variable. The check happens before any call, so a value too
	// large for the tier never leaves the process.
	if size := len(compute.RevealSecret(spec.Value)); size > s.tier.MaxValueBytes() {
		// The limit and the tier are named; the actual size is not. A size is
		// not material, but it narrows a brute force, and the caller holds the
		// value and can measure it.
		return compute.StoredSecret{}, fmt.Errorf("%w: the value exceeds the %d-byte maximum of the %s "+
			"parameter tier; store a reference to the material instead, or configure the %s tier",
			compute.ErrInvalidSpec, s.tier.MaxValueBytes(), s.tier, TierAdvanced)
	}
	if err := validateLabels(spec.Labels); err != nil {
		return compute.StoredSecret{}, err
	}
	name, err := s.path(spec.Scope, spec.Name)
	if err != nil {
		return compute.StoredSecret{}, err
	}
	if err := s.validatePath(name); err != nil {
		return compute.StoredSecret{}, err
	}
	desired := s.tagSet(name, placement.Name, spec.Labels)
	if len(desired) > maxTagsPerResource {
		return compute.StoredSecret{}, fmt.Errorf("%w: %d tags would be applied and AWS allows %d on a "+
			"parameter; %d of them are the ownership and operator tags this provider manages",
			compute.ErrInvalidSpec, len(desired), maxTagsPerResource, len(desired)-len(spec.Labels))
	}

	// Create-and-tag in one call. On success the parameter exists and is owned,
	// with no window in which it exists untagged.
	version, err := s.p.sub.Parameters.Put(ctx, PutParameterInput{
		Name:      name,
		Value:     spec.Value,
		KeyID:     s.cfg.KMSKeyARN,
		Tier:      s.tier,
		Tags:      desired,
		Overwrite: false,
	})
	switch {
	case err == nil:
		return s.stored(name, version), nil
	case !errors.Is(err, ErrParameterExists):
		return compute.StoredSecret{}, s.wrap(err, name)
	}

	// It exists. Whose is it?
	tags, err := s.p.sub.Parameters.Tags(ctx, name)
	if err != nil {
		return compute.StoredSecret{}, s.wrap(err, name)
	}
	if err := checkOwned(tags, "parameter", componentSecret, name); err != nil {
		// Not adopted, and the message says why rather than just refusing: secret
		// names derive from mutable application names, so a collision here is
		// somebody else's credential about to be overwritten.
		return compute.StoredSecret{}, err
	}
	// A tier downgrade is refused here rather than at the API. SSM cannot move a
	// parameter from the advanced tier back to the standard one -- the parameter
	// has to be deleted and recreated -- so an operator who narrows the
	// configuration would otherwise get a ValidationException on every redeploy
	// of every existing secret, naming a constraint the caller never set.
	if meta, mErr := s.p.sub.Parameters.Describe(ctx, name); mErr == nil {
		if meta.Tier == TierAdvanced && s.tier != TierAdvanced {
			return compute.StoredSecret{}, fmt.Errorf("%w: parameter %s is in the %s tier and this provider "+
				"is configured for %s; SSM cannot downgrade a parameter's tier, so the parameter "+
				"has to be deleted and recreated deliberately",
				compute.ErrInvalidSpec, name, meta.Tier, s.tier)
		}
	} else if !errors.Is(mErr, ErrParameterNotFound) {
		return compute.StoredSecret{}, s.wrap(mErr, name)
	}
	version, err = s.p.sub.Parameters.Put(ctx, PutParameterInput{
		Name:      name,
		Value:     spec.Value,
		KeyID:     s.cfg.KMSKeyARN,
		Tier:      s.tier,
		Overwrite: true,
	})
	if err != nil {
		return compute.StoredSecret{}, s.wrap(err, name)
	}
	if err := s.convergeTags(ctx, name, tags, desired); err != nil {
		return compute.StoredSecret{}, s.wrap(err, name)
	}
	return s.stored(name, version), nil
}

// stored reports what a Put wrote.
//
// The version is SSM's own parameter version, rendered as a decimal string. It
// is opaque to the caller by contract, and it is the value that goes back
// through [compute.SecretBinding.Version] to pin a workload to a revision --
// which SSM honours natively, since GetParameter and an ECS valueFrom both
// accept a "name:version" selector.
func (s *secretStore) stored(name string, version int64) compute.StoredSecret {
	return compute.StoredSecret{
		Ref:     s.p.ref(compute.KindSecret, name),
		Version: strconv.FormatInt(version, 10),
	}
}

// tagSet is the complete tag set a parameter should carry.
//
// There is no scope tag. An earlier version carried one as a digest, on the
// reasoning that a caller-chosen scope is not guaranteed legal in a tag value --
// which is true and was solving a problem nothing had: the readable scope is
// already a path element of the parameter's own name, nothing in this package or
// its tests ever read the tag, and an unread tag is a second place for the truth
// to live. Ownership is decided by [checkOwned] against the parameter's name,
// which the lookup already keys on.
func (s *secretStore) tagSet(name, placement string, labels map[string]string) map[string]string {
	tags := ownershipTags(name, componentSecret, labels)
	// The resolved placement NAME, never the caller's empty "use the default":
	// a consumer comparing two placements has to see the same spelling from both
	// sides, and Config.placement is what fills the empty case in.
	tags[tagPlacement] = placement
	return tags
}

// convergeTags makes the parameter's tags equal to desired.
//
// The removal half is the part that matters and the part an implementation is
// most likely to skip. [compute.SecretSpec.Labels] is a declarative set, so a
// label present in one deploy's spec and absent from the next has to be gone
// from the substrate; an implementation that only ever adds leaves it behind,
// and the operator tooling that reads those tags is then describing a deploy
// that no longer exists.
func (s *secretStore) convergeTags(ctx context.Context, name string, current, desired map[string]string) error {
	add, remove := tagDelta(current, desired)
	if len(add) == 0 && len(remove) == 0 {
		return nil
	}
	return s.p.sub.Parameters.SetTags(ctx, name, add, remove)
}

// Get implements [compute.SecretStore].
//
// This is the one operation in the port that returns material, and the
// interface names its single legitimate caller: the master database password,
// which apphub has to present to Postgres in order to create roles
// (postgres_roles.go:154-165). Injection into a workload never comes through
// here — that is [compute.SecretBinding] and the runtime resolves it at launch.
//
// A read of a reference that does not exist is [compute.ErrNotFound], and a
// reference this provider did not issue is [compute.ErrForeignRef]. The two are
// kept apart because a caller told "not found" concludes the secret was deleted
// and recreates it, which against another provider's reference means writing
// material somewhere it does not belong.
func (s *secretStore) Get(ctx context.Context, ref compute.Ref) (compute.SecretValue, error) {
	name, err := s.resolve(ref)
	if err != nil {
		return compute.SecretValue{}, err
	}
	value, err := s.p.sub.Parameters.Get(ctx, name)
	if err != nil {
		return compute.SecretValue{}, s.wrap(err, name)
	}
	return value, nil
}

// Describe implements [compute.SecretStore].
//
// It asks the substrate for the parameter's metadata rather than its value:
// SSM's DescribeParameters answers whether a parameter exists without returning
// what is in it, which is the whole point of the operation. Nothing here touches
// [ParameterStore.Get].
//
// It reports [compute.SecretPlacementGlobal] and no placement, which is what is
// true here: an SSM parameter is account-global, and [compute.SecretSpec] says
// in as many words that an AWS provider ignores the placement field. Every
// workload this provider runs can bind any secret it stores.
//
// The first version resolved the provider's DEFAULT placement and reported that.
// Review showed why it was worse than saying nothing: Put accepts any configured
// placement, so a secret stored at "secondary" was described as "default", and a
// caller comparing the two would refuse a valid deployment as cross-placement.
// Reporting a placement this store does not have was a plausible-looking answer
// to a question it cannot be asked — so the question changed shape instead.
func (s *secretStore) Describe(ctx context.Context, ref compute.Ref) (*compute.SecretInfo, error) {
	name, err := s.resolve(ref)
	if err != nil {
		return nil, err
	}
	if _, err := s.p.sub.Parameters.Describe(ctx, name); err != nil {
		return nil, s.wrap(err, name)
	}
	return &compute.SecretInfo{Ref: ref, PlacementScope: compute.SecretPlacementGlobal}, nil
}

// Delete implements [compute.SecretStore]. Deleting an absent secret returns
// nil: teardown runs again after a failure and finds some of its work done.
func (s *secretStore) Delete(ctx context.Context, ref compute.Ref) error {
	name, err := s.resolve(ref)
	if err != nil {
		return err
	}
	if err := s.p.sub.Parameters.Delete(ctx, name); err != nil {
		if errors.Is(err, ErrParameterNotFound) {
			return nil
		}
		return s.wrap(err, name)
	}
	return nil
}

// DeleteScope implements [compute.SecretStore].
//
// It enumerates with a metadata-only description of the scope's path rather
// than with GetParametersByPath, which returns values: a teardown has no use
// for the material, and a listing that cannot carry a value cannot leak one.
// See [ParameterMetadata].
//
// A parameter under the scope's path that this platform does not own is not
// deleted, and its presence is reported as [compute.ErrNotOwned] once the
// owned ones are gone. Deleting it would destroy somebody else's material, and
// silently skipping it would make a teardown that left credentials behind look
// like a clean one.
func (s *secretStore) DeleteScope(ctx context.Context, scope string) error {
	if strings.TrimSpace(scope) == "" {
		return fmt.Errorf("%w: DeleteScope needs a scope", compute.ErrInvalidSpec)
	}
	path, err := s.scopePath(scope)
	if err != nil {
		return err
	}
	found, err := s.p.sub.Parameters.DescribeByPath(ctx, path)
	if err != nil {
		return s.wrap(err, path)
	}
	var foreign []string
	for _, meta := range found {
		tags, err := s.p.sub.Parameters.Tags(ctx, meta.Name)
		if err != nil {
			if errors.Is(err, ErrParameterNotFound) {
				// Somebody else's teardown got there first, which is the
				// outcome this one wanted.
				continue
			}
			return s.wrap(err, meta.Name)
		}
		if checkOwned(tags, "parameter", componentSecret, meta.Name) != nil {
			foreign = append(foreign, meta.Name)
			continue
		}
		if err := s.p.sub.Parameters.Delete(ctx, meta.Name); err != nil && !errors.Is(err, ErrParameterNotFound) {
			return s.wrap(err, meta.Name)
		}
	}
	if len(foreign) > 0 {
		sort.Strings(foreign)
		return fmt.Errorf("%w: %d parameter(s) under %s do not carry this provider's ownership tags "+
			"for a %s and were left in place: %s; this provider did not create them and deleting "+
			"them would destroy material it does not own",
			compute.ErrNotOwned, len(foreign), path, componentSecret, strings.Join(foreign, ", "))
	}
	return nil
}

// revision checks that a parameter has the version a binding pinned.
//
// SSM honours a "name:version" selector natively, so this provider honours a pin
// rather than refusing it -- but it validates the revision rather than trusting
// it. A reference to a version that does not exist is a workload that cannot
// start, and finding that out while a runtime is still building a specification
// is worth one API call.
func (s *secretStore) revision(ctx context.Context, name, version string) (int64, error) {
	n, err := strconv.ParseInt(version, 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%w: %q is not an SSM parameter version; a version comes from "+
			"compute.StoredSecret.Version and is not composed by a caller",
			compute.ErrInvalidSpec, version)
	}
	meta, err := s.p.sub.Parameters.Describe(ctx, name)
	if err != nil {
		return 0, s.wrap(err, name)
	}
	if n > meta.Version {
		return 0, fmt.Errorf("%w: parameter %s has %d revision(s) and revision %d was asked for",
			compute.ErrNotFound, name, meta.Version, n)
	}
	return n, nil
}

// resolve turns a secret reference into a parameter name, refusing a reference
// that addresses something outside this store's own prefix.
//
// The last check is the one that is not obvious. A [compute.Ref] is opaque and
// provider-issued, so a well-behaved caller can only have got one from this
// store — but a reference is also the thing a caller persists, so a stale one
// from a differently-configured provider, or one assembled by hand, can arrive.
// Refusing anything outside the configured prefix means a Delete can only ever
// address a parameter this store could have created.
func (s *secretStore) resolve(ref compute.Ref) (string, error) {
	name, err := s.p.resolve(ref, compute.KindSecret)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(name, s.prefix+"/"+appsSegment+"/") {
		return "", fmt.Errorf("%w: reference %s addresses a parameter outside this store's prefix; "+
			"a reference issued by a provider configured with a different prefix is not this "+
			"store's to read or delete", compute.ErrInvalidSpec, ref)
	}
	return name, nil
}

// wrap maps a substrate error onto the [compute] taxonomy.
//
// The parameter name is included; NOTHING ELSE THIS FUNCTION EMITS COMES FROM
// THE CALL. The previous wording -- "the value never is" -- was true and far too
// narrow: it promised only that the value is absent, while the arms below were
// retaining the substrate's entire error, which is text this package did not
// write. A claim that names the one thing you did keep out is read as a claim
// about everything.
//
// The name is topology rather than material, and it is derived here rather than
// received: without it an operator reading a failed deploy cannot tell which of
// an application's secrets failed.
//
// A retryable substrate failure becomes [compute.ErrTransient] and never
// [compute.ErrFailed]: a caller told the spec has to change abandons a deploy
// that would have worked on a retry.
func (s *secretStore) wrap(err error, name string) error {
	if err == nil {
		return nil
	}
	// EVERY ARM CLASSIFIES AND THEN EMITS TEXT THIS REPOSITORY OWNS. The incoming
	// error is never retained -- not by %w, not by %v, not in any arm.
	//
	// [Substrate.Parameters] is an interface, so the error arriving here is
	// written by whoever supplied the adapter, and [SSMParameterStore] -- ours --
	// carries the AWS SDK's message. Both are text this package did not write, on
	// the one port whose substrate handles credential material. Review planted a
	// marker in a foreign error and read it back out of SecretStore.Put:
	//
	//	secret store: parameter /p/apps/a/T: REVIEW-CREDENTIAL-MATERIAL-7b5c2a
	//
	// Four of the five arms retained the chain, and the reproduction only went
	// through one of them. Sanitising the reproduced arm would have left three
	// live and a green test would have read as closure -- so the property is
	// stated over the function rather than fixed per branch, and
	// TestNoForeignErrorTextReachesACaller drives every arm from outside.
	//
	// # Why this is not solved by sealing the interface
	//
	// Making ParameterStore unimplementable outside this package would remove the
	// third-party adapter and leave the leak: ssmError retains the SDK's message
	// in every one of its arms, so our own implementation is a foreign-text
	// source. A seal would also have to be a seal on every substrate port to mean
	// anything, and it would still not close this. Not retaining is the property;
	// the seam's openness is not the defect.
	//
	// # What is deliberately lost
	//
	// The substrate's own message. That is a real cost to an operator debugging a
	// tagging failure, and it is the trade the security bar requires: an error
	// whose provenance is a caller-supplied adapter cannot be shown to be free of
	// material. What survives is the classification, which is what a caller
	// branches on, and the parameter name, which this package derived itself.
	switch {
	case errors.Is(err, ErrParameterNotFound):
		return fmt.Errorf("%w: parameter %s", compute.ErrNotFound, name)
	case errors.Is(err, ErrParameterTooLarge):
		// Reached only if the substrate's limit is stricter than the tier's
		// documented one, which would mean this provider's own check is out of
		// date. It is still a caller-fixable spec problem.
		return fmt.Errorf("%w: the value is too large for parameter %s", compute.ErrInvalidSpec, name)
	case errors.Is(err, ErrParameterExists):
		// Reached only where the create-only Put's collision was not consumed by
		// the ownership branch above. A create that raced another create is not
		// a collision with somebody else's infrastructure, so it is transient
		// rather than [compute.ErrNotOwned].
		return fmt.Errorf("%w: parameter %s already exists", compute.ErrTransient, name)
	case errors.Is(err, ErrThrottled):
		return fmt.Errorf("%w: the substrate throttled the request for parameter %s",
			compute.ErrTransient, name)
	case errors.Is(err, ErrDenied):
		// The platform's own IAM role lacks an ssm permission. ErrFailed would
		// send an operator to the parameter, which is fine; only the role can be
		// fixed. See [Provider.substrateError] for the same reasoning on the
		// other ports, and ssmError for why this arm needs a code check rather
		// than a typed exception.
		return fmt.Errorf("%w: parameter %s: the platform's credentials lack an ssm permission",
			compute.ErrNotPermitted, name)
	case errors.Is(err, context.Canceled):
		// RECOGNISED FROM the incoming error and ANSWERED WITH a canonical
		// sentinel. The previous version returned err itself, which was the
		// seventh foreign-text arm and the one I added while fixing the other
		// six: "returned as itself, because it is this package's own context"
		// assumed the cancellation came from us. It arrives from the adapter,
		// which can wrap the sentinel in anything --
		//
		//	fmt.Errorf("MARKER: %w", context.Canceled)
		//
		// -- and returning the thing you recognised is exactly what the other
		// arms stopped doing. The classification was right and the return was
		// the defect.
		//
		// Still not ErrTransient: "try again" inverts the instruction the caller
		// just gave. context.Canceled survives errors.Is, which is what a caller
		// branches on.
		return fmt.Errorf("%w: the call for parameter %s was cancelled", context.Canceled, name)
	case errors.Is(err, context.DeadlineExceeded):
		// Separate from cancellation because they are different facts to act on:
		// a deadline is the caller's own budget, and compute.ErrTimeout is the
		// taxonomy's word for it.
		return fmt.Errorf("%w: %w: the call for parameter %s exceeded its deadline",
			compute.ErrTimeout, context.DeadlineExceeded, name)
	default:
		// Unclassified, and now carrying a sentinel. It previously returned
		// "secret store: parameter %s: %w" with NO compute sentinel at all, so a
		// caller branching on the taxonomy fell through every arm and got
		// nothing to act on.
		return fmt.Errorf("%w: parameter %s: the substrate refused the operation",
			compute.ErrFailed, name)
	}
}
