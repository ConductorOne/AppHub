// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// keyValueProvisioner implements [compute.KeyValueProvisioner] with DynamoDB.
//
// It is the source system's database.go:50-149 — a PAY_PER_REQUEST table, and an
// inline IAM policy granting the application's task role access to it.
//
// # Why this port exists here at all
//
// compute/k8s declines [compute.CapKeyValueTable] unconditionally, and that is a
// perfectly good precedent for declining a port cleanly. This provider does not
// follow it, for three reasons that are about this substrate rather than about
// completeness. DynamoDB is the substrate [compute.KeyValueProvisioner] was
// *derived from*, so declining here would leave a capability the interface
// declares with no implementation anywhere outside compute/fake. It is the
// substrate [compute.Granter]'s presence on this port was argued from — "the
// source system grants the application's task role eight DynamoDB actions on the
// table and its indexes, with no notion of a database-internal principal" — so
// the grant half is portable exactly here and nowhere else. And the source
// system's own deploy path offers it as one of two database types
// (container.go:243-259), so an application configured for it has no other
// answer.
//
// The cost of saying yes is one boundary rule. See
// docs/decisions/usoss-14-the-dynamodb-fence-is-widened-for-provisioning-in-both-halves-one-package-and-one-file.md.
//
// # What is different from the source
//
// **The keys are the caller's.** The source hardcodes a "PK"/"SK" pair
// (database.go:67-74) and always creates both. [compute.KeyValueSpec] makes the
// partition key required and the sort key optional, so this provider creates a
// table with one key when that is what was asked for.
//
// **The grant is least privilege at two levels.** The source grants eight
// actions unconditionally, which means a read-only consumer gets PutItem and
// DeleteItem. [compute.AccessRead] here grants four read actions and
// [compute.AccessReadWrite] grants those plus four writes, and narrowing
// replaces the policy rather than adding to it.
//
// **The ownership marker is read before the table is written.** The source
// adopts whatever table it finds under the name it wanted.
type keyValueProvisioner struct{ p *Provider }

var _ compute.KeyValueProvisioner = (*keyValueProvisioner)(nil)

// EnsureKeyValueTable creates or converges a key-value table.
func (k *keyValueProvisioner) EnsureKeyValueTable(ctx context.Context, spec compute.KeyValueSpec) (*compute.KeyValueStatus, error) {
	if err := validateName(spec.Name); err != nil {
		return nil, err
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	if spec.PartitionKey == "" {
		return nil, fmt.Errorf("%w: a key-value table needs a partition key", compute.ErrInvalidSpec)
	}
	if spec.SortKey != "" && spec.SortKey == spec.PartitionKey {
		return nil, fmt.Errorf("%w: %q is named as both the partition key and the sort key",
			compute.ErrInvalidSpec, spec.SortKey)
	}
	// A DynamoDB table is regional and this provider does not place it anywhere,
	// which is the case [compute.Placement] predicts. The placement is still
	// resolved: an unconfigured one is a caller mistake worth reporting whether
	// or not this substrate would have used it, and the effective spec has to
	// echo the resolved name rather than the caller's empty "use the default".
	pc, err := k.p.cfg.placement(spec.Placement)
	if err != nil {
		return nil, err
	}
	name, err := k.p.tableName(spec.Name)
	if err != nil {
		return nil, err
	}

	desired := databaseTags(name, componentKeyValue, pc.Name, spec.Name, spec.Labels)
	table, err := k.p.sub.DynamoDB.DescribeTable(ctx, name)
	switch {
	case err == nil:
		if err := checkOwned(table.Tags, "DynamoDB table", componentKeyValue, name); err != nil {
			return nil, err
		}
		// A key schema cannot be changed after creation, and DynamoDB would
		// refuse. Saying so is better than a reconcile that appears to succeed
		// while the table keeps its old keys: the application's queries are
		// written against the schema it asked for.
		if table.PartitionKey != spec.PartitionKey || table.SortKey != spec.SortKey {
			return nil, fmt.Errorf("%w: table %q exists with partition key %q and sort key %q, and "+
				"the spec asks for %q and %q; a key schema cannot be changed after creation, so "+
				"this is a new table rather than a reconcile", compute.ErrInvalidSpec, name,
				table.PartitionKey, table.SortKey, spec.PartitionKey, spec.SortKey)
		}
		put, remove := tagDelta(table.Tags, desired)
		if len(remove) > 0 {
			if err := k.p.sub.DynamoDB.UntagResource(ctx, table.ARN, remove); err != nil {
				return nil, k.p.substrateError(err)
			}
		}
		if len(put) > 0 {
			if err := k.p.sub.DynamoDB.TagResource(ctx, table.ARN, put); err != nil {
				return nil, k.p.substrateError(err)
			}
		}
	case errors.Is(err, ErrNoSuchResource):
		if _, err := k.p.sub.DynamoDB.CreateTable(ctx, CreateTableRequest{
			Name:         name,
			PartitionKey: spec.PartitionKey,
			SortKey:      spec.SortKey,
			Tags:         desired,
		}); err != nil {
			return nil, k.p.substrateError(err)
		}
	default:
		return nil, k.p.substrateError(err)
	}
	return k.DescribeKeyValueTable(ctx, k.p.ref(compute.KindKeyValueTable, name))
}

// DescribeKeyValueTable reads a table back through the interface.
func (k *keyValueProvisioner) DescribeKeyValueTable(ctx context.Context, ref compute.Ref) (*compute.KeyValueStatus, error) {
	name, err := k.p.resolve(ref, compute.KindKeyValueTable)
	if err != nil {
		return nil, err
	}
	table, err := k.p.sub.DynamoDB.DescribeTable(ctx, name)
	if errors.Is(err, ErrNoSuchResource) {
		return &compute.KeyValueStatus{Status: k.p.status(ref, compute.PhaseGone, "")}, nil
	}
	if err != nil {
		return nil, k.p.substrateError(err)
	}
	spec := compute.KeyValueSpec{
		Name:         logicalFromTags(table.Tags, table.Name),
		PartitionKey: table.PartitionKey,
		SortKey:      table.SortKey,
		Placement:    k.p.placementFromTags(table.Tags),
		Labels:       labelsFromTags(table.Tags),
	}
	phase, err := keyValuePhase(table.Status)
	if err != nil {
		return nil, err
	}
	return &compute.KeyValueStatus{
		Status: k.p.status(ref, phase, ""),
		Spec:   spec,
		Name:   table.Name,
	}, nil
}

// keyValueTablePhases is every TableStatus DynamoDB documents, mapped onto the
// interface's phases.
//
// Exhaustive, with a fatal default, for the reason set out on
// [relationalClusterPhases]: a tolerant default converts a new terminal status
// into a wait that never ends. The set is small enough that this is cheap.
var keyValueTablePhases = map[string]compute.Phase{
	"ACTIVE":                              compute.PhaseReady,
	"CREATING":                            compute.PhasePending,
	"UPDATING":                            compute.PhasePending,
	"ARCHIVING":                           compute.PhasePending,
	"DELETING":                            compute.PhaseDeleting,
	"ARCHIVED":                            compute.PhaseFailed,
	"INACCESSIBLE_ENCRYPTION_CREDENTIALS": compute.PhaseFailed,
	"REPLICATION_NOT_AUTHORIZED":          compute.PhaseFailed,
}

// keyValuePhase maps a DynamoDB table status onto the interface's phases, or
// refuses.
func keyValuePhase(status string) (compute.Phase, error) {
	if phase, ok := keyValueTablePhases[strings.ToUpper(strings.TrimSpace(status))]; ok {
		return phase, nil
	}
	return "", fmt.Errorf("%w: DynamoDB reported table status %q, which this provider does not "+
		"recognise. It is refused rather than assumed transitional, because a status this provider "+
		"has never seen may be terminal and a wait on it would never return. If AWS has added a "+
		"status, add it to keyValueTablePhases with the phase it means", compute.ErrFailed, status)
}

// keyValueNotFoundGrace bounds how many consecutive not-found reads
// WaitForKeyValueTable tolerates before it believes them.
//
// # Why a wait needs this at all
//
// A production deploy failed with "the resource was deleted while waiting for
// it" immediately after CreateTable had succeeded: CloudTrail showed
// DescribeTable and ListTagsOfResource answering ResourceNotFoundException for
// a table that unquestionably existed, moments after CreateTable reported it
// created. DynamoDB's control plane is not immediately read-consistent with
// itself, and [keyValueProvisioner.DescribeKeyValueTable] maps that
// not-found straight to [compute.PhaseGone] -- correctly, for every caller
// that is not mid-wait right after a create. This wait is exactly that
// caller, so it treats a short run of not-found as the table still becoming
// visible rather than as evidence it was deleted out from under it.
//
// # A count, not a duration
//
// The propagation delay is undocumented and short, so this bounds it in polls
// rather than wall-clock time: that needs no clock beyond the one this wait
// already has (the interval [Config.pollInterval] chooses), and it is exactly
// as effective at [DefaultPollInterval] or at a test's millisecond one. A
// table still not found after this many consecutive reads is reported gone,
// the same as it always was -- so a table that is genuinely deleted mid-wait
// still surfaces [compute.ErrNotFound], only after the propagation window a
// real creation would have cleared.
const keyValueNotFoundGrace = 3

// WaitForKeyValueTable blocks until the table is usable.
func (k *keyValueProvisioner) WaitForKeyValueTable(ctx context.Context, ref compute.Ref, opts compute.WaitOptions) (*compute.KeyValueStatus, error) {
	var last *compute.KeyValueStatus
	var notFoundStreak int
	st, err := waitFor(ctx, k.p.cfg.pollInterval(), opts, func() (compute.Status, bool, error) {
		s, err := k.DescribeKeyValueTable(ctx, ref)
		if err != nil {
			return compute.Status{}, false, err
		}
		if s.Phase != compute.PhaseGone {
			notFoundStreak = 0
			last = s
			return s.Status, s.Phase == compute.PhaseReady, nil
		}
		notFoundStreak++
		if notFoundStreak > keyValueNotFoundGrace {
			// The grace period is spent. Reported as gone, same as ever: this
			// is no longer distinguishable from a table that really is gone.
			last = s
			return s.Status, false, nil
		}
		// Tolerated. Reported as pending rather than gone, so the loop in
		// [waitFor] keeps polling instead of returning compute.ErrNotFound for
		// a table that answered CreateTable a moment ago.
		pending := *s
		pending.Status = k.p.status(ref, compute.PhasePending,
			"table not yet visible to DescribeTable; expected briefly after creation")
		last = &pending
		return pending.Status, false, nil
	})
	if last == nil {
		return nil, err
	}
	last.Status = st
	return last, err
}

// DeleteKeyValueTable removes a table and its data.
func (k *keyValueProvisioner) DeleteKeyValueTable(ctx context.Context, ref compute.Ref) error {
	name, err := k.p.resolve(ref, compute.KindKeyValueTable)
	if err != nil {
		return err
	}
	return k.p.deleteIfPresent(ctx, func() error {
		return k.p.sub.DynamoDB.DeleteTable(ctx, name)
	})
}

// --- grants ------------------------------------------------------------------

// The DynamoDB actions each access level admits.
//
// Two lists rather than one, and the split is the least-privilege decision the
// source system does not make: it attaches all eight actions whenever an
// application has a table (database.go:117-126), so a component that only reads
// gets PutItem, UpdateItem, DeleteItem and BatchWriteItem as well.
//
// The read set includes the two batch and two query actions because a reader
// that cannot Query or Scan cannot find anything, which is what
// [compute.AccessRead] means by "reading data and the metadata needed to find
// it". DescribeTable is deliberately absent: it is control-plane metadata, the
// caller already has everything the interface reports about the table, and a
// grant is about data.
var (
	keyValueReadActions = []string{
		"dynamodb:BatchGetItem",
		"dynamodb:GetItem",
		"dynamodb:Query",
		"dynamodb:Scan",
	}
	keyValueWriteActions = []string{
		"dynamodb:BatchWriteItem",
		"dynamodb:DeleteItem",
		"dynamodb:PutItem",
		"dynamodb:UpdateItem",
	}
)

// keyValueActions is the DynamoDB action set for one access level.
//
// Split from the renderer below so that a level can be validated without an ARN
// to render against, which is what [keyValueProvisioner.Grant] needs in order to
// refuse a bad level before it calls DescribeTable. Same shape as
// [objectActions] and [bucketAccessPolicy] in policy.go.
//
// There is no AccessAdmin. DynamoDB's structural actions are table creation and
// deletion, which this port owns through EnsureKeyValueTable and
// DeleteKeyValueTable; handing them to a workload would let it drop the table it
// was granted access to.
func keyValueActions(level compute.AccessLevel) ([]string, error) {
	switch level {
	case compute.AccessRead:
		return keyValueReadActions, nil
	case compute.AccessReadWrite:
		return append(append([]string{}, keyValueReadActions...), keyValueWriteActions...), nil
	default:
		// An access level the interface does not define must not become some
		// provider default: a typo in a caller would silently pick one.
		return nil, fmt.Errorf("%w: access level %q is not one this interface defines (%q, %q)",
			compute.ErrInvalidSpec, level, compute.AccessRead, compute.AccessReadWrite)
	}
}

// keyValueAccessPolicy renders the inline policy for one (table ARN, level)
// pair.
//
// Extracted from [keyValueProvisioner.Grant] so that the read-back has the same
// authority the write does. [levelFromStoredPolicy] recovers a level by asking
// which one would render the standing document, and that answer is only
// trustworthy while there is exactly one renderer — a second copy here, kept in
// step by hand, would report a stale level as confidently as a current one.
func keyValueAccessPolicy(arn string, level compute.AccessLevel) (string, error) {
	actions, err := keyValueActions(level)
	if err != nil {
		return "", err
	}
	doc, err := json.Marshal(policyDocument{
		Version: "2012-10-17",
		Statement: []statement{{
			Sid:    "AppHubKeyValueAccess",
			Effect: "Allow",
			Action: actions,
			// The table and its indexes, which is what the source system names
			// (database.go:127-130) and is not wider than it looks: an index is
			// a view of the table's own items, so a reader that may Query the
			// table may already read everything the index would show.
			Resource: []string{arn, arn + "/index/*"},
		}},
	})
	if err != nil {
		return "", fmt.Errorf("%w: rendering the access policy: %w", compute.ErrFailed, err)
	}
	return string(doc), nil
}

// Grant gives identity the stated level of access to a table.
func (k *keyValueProvisioner) Grant(ctx context.Context, resource, identity compute.Ref, level compute.AccessLevel) error {
	table, role, err := k.p.resolveGrant(resource, identity)
	if err != nil {
		return err
	}
	// The level is validated before the substrate is touched, so a caller's typo
	// costs no API call and cannot half-apply. This ordering is the existing
	// behaviour, kept: the level check used to sit here inline.
	if _, err := keyValueActions(level); err != nil {
		return err
	}

	rec, err := k.p.sub.DynamoDB.DescribeTable(ctx, table)
	if err != nil {
		return k.p.substrateError(err)
	}
	// The ARN is read back from DynamoDB, never composed. Composing it would
	// mean this package holding an account identifier, and a policy naming a
	// wrongly composed ARN grants access to nothing while reporting success.
	doc, err := keyValueAccessPolicy(rec.ARN, level)
	if err != nil {
		return err
	}
	policy, err := k.p.cfg.KeyValue.grantPolicyName(table)
	if err != nil {
		return err
	}
	// Put, not merge. [compute.Granter] is last-write-wins on level, so
	// narrowing from read-write to read has to narrow — and the shape an
	// implementation gets wrong is adding a second statement, which leaves the
	// wider one in force.
	//
	// What makes that safe is that the name is per-table: replacement is scoped
	// to the pair the interface is keyed on. Under a provider-wide name the same
	// Put narrowed the level *and* dropped every other table the role could
	// reach, which is the same call reading as last-write-wins on the role.
	return k.p.substrateError(k.p.sub.IAM.PutRolePolicy(ctx, role, policy, doc))
}

// Revoke removes any access identity has to a table.
//
// To *a* table: the resource argument is load-bearing, and it was once resolved
// only to be discarded. Deleting a provider-wide policy name removed the role's
// access to every other table as well, and returned nil.
func (k *keyValueProvisioner) Revoke(ctx context.Context, resource, identity compute.Ref) error {
	table, role, err := k.p.resolveGrant(resource, identity)
	if err != nil {
		return err
	}
	policy, err := k.p.cfg.KeyValue.grantPolicyName(table)
	if err != nil {
		return err
	}
	err = k.p.sub.IAM.DeleteRolePolicy(ctx, role, policy)
	if errors.Is(err, ErrNoSuchResource) {
		// Revoking an absent grant is nil. Teardown revokes what it believes it
		// granted, and a failed deploy leaves that set incomplete.
		return nil
	}
	return k.p.substrateError(err)
}

// DescribeGrant reports the access an identity has to a table.
//
// The ARN is read back from DynamoDB here for the same reason Grant reads it
// rather than composing one: the policy that stands names the real ARN, so a
// comparison against a composed one would report "no recognisable grant" for
// every grant this provider ever wrote.
//
// # The table is read before the policy, and the order is load-bearing
//
// Both substrates are consulted, and this asks DynamoDB first — which is the
// order [keyValueProvisioner.Grant] uses, for the same reason: the table is the
// precondition. A grant naming a table that is gone authorises nothing, so the
// table's absence is the fact to report, and interpreting a policy document
// before knowing whether its subject exists gets that backwards.
//
// It also keeps this method's error mapping attributable to this port. The
// conformance suite's transient gate arms the substrate belonging to the kind
// under test (USOSS-42), which for a key-value table is DynamoDB and not IAM. A
// version of this that read IAM first returned [compute.ErrNotFound] — correctly,
// for an absent policy — before the armed substrate was ever reached, so a
// throttled DynamoDB surfaced as "no grant". That is the fail-open direction: a
// caller told a pair has no grant grants again, and a reconciler told it during a
// throttling episode concludes a whole deployment has lost its access.
func (k *keyValueProvisioner) DescribeGrant(ctx context.Context, resource, identity compute.Ref) (*compute.GrantInfo, error) {
	table, role, err := k.p.resolveGrant(resource, identity)
	if err != nil {
		return nil, err
	}
	rec, err := k.p.sub.DynamoDB.DescribeTable(ctx, table)
	if errors.Is(err, ErrNoSuchResource) {
		return nil, fmt.Errorf("%w: table %q", compute.ErrNotFound, table)
	}
	if err != nil {
		return nil, k.p.substrateError(err)
	}
	policy, err := k.p.cfg.KeyValue.grantPolicyName(table)
	if err != nil {
		return nil, err
	}
	doc, err := k.p.sub.IAM.GetRolePolicy(ctx, role, policy)
	if errors.Is(err, ErrNoSuchResource) {
		return nil, fmt.Errorf("%w: role %q holds no grant on table %q",
			compute.ErrNotFound, role, table)
	}
	if err != nil {
		return nil, k.p.substrateError(err)
	}
	level, err := levelFromStoredPolicy(doc, func(l compute.AccessLevel) (string, error) {
		return keyValueAccessPolicy(rec.ARN, l)
	})
	if err != nil {
		return nil, err
	}
	return &compute.GrantInfo{Resource: resource, Identity: identity, Level: level}, nil
}

// resolveGrant checks both references and the grant capability.
//
// The capability check comes first, because [compute.CapWorkloadGrants] is what
// a caller checks in advance: an operator who reads a refusal naming the port's
// own capability reconfigures the wrong thing.
func (p *Provider) resolveGrant(resource, identity compute.Ref) (table, role string, err error) {
	if !p.caps.Has(compute.CapWorkloadGrants) {
		return "", "", p.unsupported(compute.CapWorkloadGrants,
			"this provider is not configured to authorise workload identities against the "+
				"resources it provisions")
	}
	table, err = p.resolve(resource, compute.KindKeyValueTable)
	if err != nil {
		return "", "", err
	}
	role, err = p.resolve(identity, compute.KindWorkloadIdentity)
	if err != nil {
		return "", "", err
	}
	return table, role, nil
}
