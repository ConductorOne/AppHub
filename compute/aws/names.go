// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// The tag vocabulary this provider owns.
//
// tagManagedBy is the ownership marker [compute.ErrNotOwned] requires every
// provider to have. The source system writes a source-specific ManagedBy value
// (build.go:312) and then never reads it: EnsureECRRepository adopts whatever it
// finds under the name it wanted. Writing a marker nobody checks is the same as
// having none, and this provider reads it before it writes anything.
//
// Boundary of the proof: the marker proves "an AWS principal allowed to write
// these reserved tags in this account claimed the resource", not "this process
// wrote it". A bucket with tagManagedBy=managedByValue and the matching
// tagComponent is accepted as this platform's only inside that AWS
// account/trust boundary; a tenant or workload that can forge those tags can
// present its own bucket as ours. Cross-tenant deployments therefore need
// separate AWS accounts or an equivalent boundary that prevents tenants from
// writing the reserved tag namespace. See
// docs/decisions/usoss-62-ownership-by-tag-is-aws-account-scoped.md.
const (
	tagManagedBy = "apphub:managed-by"
	tagName      = "apphub:name"
	tagComponent = "apphub:component"

	// tagPlacement records the [compute.Placement] a resource was created for.
	//
	// It exists because a validated-then-discarded input looks exactly like an
	// honoured one: the secret store refused an unconfigured placement and then
	// kept nothing, which reads from outside as placement-awareness. USOSS-11
	// found it by composing a container port against the store -- a consumer
	// needing to detect a cross-placement binding has nothing to read.
	//
	// The database ports (USOSS-14) need the same record for the same reason
	// read from the other end: a read-back has to be able to tell the truth
	// about a resource this substrate does not place. A DynamoDB table is
	// regional and an IAM role is account-global, so neither substrate stores a
	// placement, and a Describe that reported [Config.DefaultPlacement] would
	// say "default" about a resource the caller explicitly put in "secondary".
	// The effective spec would then differ from the spec, which is the one thing
	// a read-back is for.
	//
	// It is not a caller label: [labelsFromTags] only recovers keys under
	// [tagLabelPrefix], so this tag is invisible to the caller as metadata while
	// still being the provider's own record.
	//
	// The workload-identity port (USOSS-10) reports the default placement
	// instead, and has the same gap; it is called out in the USOSS-14 report
	// rather than changed here, because tuning another port's behaviour from
	// that PR is not its business.
	tagPlacement = "apphub:placement"

	// managedByValue is what tagManagedBy holds. It names the project, which is
	// public, and never a deployment.
	managedByValue = "apphub"

	// tagLabelPrefix namespaces a caller's [compute.RepositorySpec.Labels] and
	// friends so they cannot collide with this provider's own tags or with an
	// operator's.
	//
	// Prefixing is what makes the removal half of convergence safe. Ensure has
	// to delete tags the caller stopped asking for, and a provider that deleted
	// every tag not in the current spec would delete the operator's cost-centre
	// tag on the first redeploy. With a prefix, the set this provider may
	// remove is exactly the set it put there.
	tagLabelPrefix = "apphub:label/"

	// The bookkeeping tags: provider state the substrate has no other field
	// for, so that a read-back can reconstruct an effective spec from the
	// resource itself rather than from anything remembered in process. Lambda
	// and ELBv2 both make a caller's own metadata unrecoverable otherwise —
	// there is no annotation, and no equivalent of the Kubernetes provider's
	// encoded-spec annotation, because an AWS tag value stops at 256 characters.
	//
	// They are deliberately not [tagLabelPrefix] keys. [labelsFromTags] hands
	// that namespace back to the caller as its own labels, and provider
	// bookkeeping appearing there would look to a caller like metadata it had
	// set.
	//
	// None of them holds an AWS identifier. tagIdentity and tagTarget hold the
	// substrate *name* of a resource this provider issued, never an ARN, for
	// the same reason [Provider.ref] is not an ARN: an ARN embeds the account.
	tagIdentity = "apphub:identity"
	tagTarget   = "apphub:target"

	// tagPeer records which [compute.PeerKind] a security group rule was written
	// for.
	//
	// It exists because **a finished EC2 rule does not preserve the peer kind**,
	// and a read-back that infers one is asking the data a question it can no
	// longer answer. A [compute.PeerPlatformIngress] rule and a
	// [compute.PeerWorkload] rule are both "a rule naming another security
	// group"; the only thing that distinguished them was a comparison against
	// the operator's *current* configuration, so a placement removed or a proxy
	// group changed made an owned rule unclassifiable — and an unclassifiable
	// rule was silently dropped from the effective spec. Reporting an endpoint as
	// having no ingress when it has two is a lie a caller reconciles against.
	//
	// So the peer kind is recorded at the write, where it is known for certain,
	// rather than reconstructed at the read from state that never held it. Same
	// construction as the ownership marker: the claim lives outside the thing
	// being claimed, in a field no caller can write.
	tagPeer = "apphub:peer"
)

// componentRepository and friends name what a resource is, for an operator
// reading a tag in the console.
const (
	componentRepository = "image-repository"
	componentBucket     = "object-bucket"
	componentIdentity   = "workload-identity"
	componentSecret     = "application-secret"

	// The function port's four. There are four for one port because a load
	// balancer, a target group and a security group are three objects in three
	// namespaces that one [compute.EndpointSpec] creates under one logical
	// name. Giving them a single component would make them interchangeable by
	// name in exactly the way the two-tag ownership check exists to prevent.
	componentFunction        = "function"
	componentEndpoint        = "function-endpoint"
	componentEndpointTargets = "function-endpoint-targets"
	componentEndpointIngress = "function-endpoint-ingress"
)

// ecrRepositoryName is ECR's grammar: 2-256 characters of lowercase
// alphanumerics, separated by ".", "_", "-", or "/".
var ecrRepositoryName = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)

// iamRoleName is IAM's grammar for a role name.
var iamRoleName = regexp.MustCompile(`^[\w+=,.@-]+$`)

// elbName is ELBv2's grammar for a load balancer name, and for a target group
// name, which is the same one: alphanumerics and hyphens, beginning and ending
// with an alphanumeric.
//
// Note what is absent. No full stop, and no underscore either. A full stop is
// legal in both grammars [sanitize] was written for, which is why [digestMarker]
// is one and why this port cannot use it. See [markerDoubleDash].
var elbName = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// lambdaFunctionName is Lambda's grammar for a function name. It admits an
// underscore and still no full stop.
var lambdaFunctionName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// endpointSecurityGroupName is EC2's grammar for a security group name: the most
// permissive of the four here, and still not universal.
var endpointSecurityGroupName = regexp.MustCompile(`^[a-zA-Z0-9 ._:/()#,@\[\]+=&;{}!$*-]+$`)

// namePrefixGrammar is what an operator-supplied physical-name prefix must
// match for the grammars this port writes into.
//
// It is load-bearing rather than tidiness. [markerDoubleDash] is injective only
// because a physical name that carries no digest provably contains no run of two
// hyphens, and the prefix is the one part of a physical name that does not pass
// through [notAllowed]. A prefix admitting "--" would put the marker's own
// separator into the undigested form and collapse the two sets back together —
// the same shape of defect as the bare-digest branch that [sanitize]'s comment
// records, so it is closed the same way: by construction, at configuration time.
var namePrefixGrammar = regexp.MustCompile(`^(?:[a-z0-9]+-?)*$`)

// s3BucketName is the general-purpose bucket grammar: lowercase alphanumerics,
// hyphens and dots, starting and ending alphanumeric, 3-63 characters. Dots are
// legal and this provider never emits one -- see [bucketDigestMarker].
var s3BucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// reservedBucketPrefix and reservedBucketSuffix are the affixes AWS reserves.
var (
	reservedBucketPrefix = regexp.MustCompile(`^(xn--|sthree-|amzn-s3-demo-)`)
	reservedBucketSuffix = regexp.MustCompile(`(-s3alias|--ol-s3|--x-s3|--table-s3)$`)
)

// The prefixes two of the substrates reserve.
const (
	reservedELBPrefix = "internal-"
	reservedSGPrefix  = "sg-"
)

// The length ceilings the substrates impose.
const (
	maxECRRepositoryName = 256
	maxIAMRoleName       = 64

	// maxELBName is the ceiling on a load balancer name and on a target group
	// name, and it is the tightest budget in the package by a wide margin. It
	// is why the source system truncates at all (lambda.go:421-431), with
	// nothing appended, so two applications agreeing on their first 32
	// characters share one load balancer.
	maxELBName = 32

	// maxLambdaFunctionName is the ceiling on a function name.
	maxLambdaFunctionName = 64

	// maxSecurityGroupName is the ceiling on a security group name.
	//
	// Nothing sizes a name against it, because one name serves the load balancer,
	// the target group and the security group and [maxELBName] is far tighter.
	// It is kept because that is a claim about two constants —
	// maxELBName <= maxSecurityGroupName — and a future edit to either could
	// falsify it silently. TestTheEndpointNameIsLegalOnBothSubstrates asserts it.
	maxSecurityGroupName = 255

	// maxStatementID is the ceiling on a Lambda resource-policy statement
	// identifier.
	maxStatementID = 100

	// maxS3BucketName is 63, and it is a DNS label limit rather than an S3 one:
	// a bucket is addressed as a hostname label in virtual-hosted style.
	maxS3BucketName = 63
)

// notAllowed matches every character that has to be replaced before a logical
// name can become a physical one on either substrate.
var notAllowed = regexp.MustCompile(`[^a-z0-9]+`)

// digestMarker separates a sanitized name from the digest that disambiguates
// it.
//
// A full stop, and the choice is the whole of what makes the mapping safe.
// [notAllowed] replaces every character outside [a-z0-9] — the full stop
// included — so the *lossless* form of a name provably contains none. A full
// stop after the configured prefix therefore means "a digest follows" and can
// mean nothing else, which is what keeps the two forms disjoint sets of strings
// rather than two shapes that might happen to coincide.
//
// It is legal in the ECR and IAM grammars: ECR admits ".", "_" and "-" between
// alphanumeric runs, and an IAM role name admits [\w+=,.@-].
//
// It is NOT legal everywhere. An RDS cluster identifier admits letters, digits
// and single hyphens and nothing else, so the relational port cannot use this
// marker and passes its own to [sanitizeWith]. See [rdsDigestMarker] for how
// disjointness is recovered in an alphabet with no spare character. The ELBv2
// and Lambda grammars this port writes into cannot use it either, which is what
// [markerDoubleDash] exists for.
const digestMarker = "."

// markerDoubleDash is the digest marker for the grammars a full stop is illegal
// in.
//
// # Why a second marker has to exist
//
// [digestMarker] was chosen for the two substrates USOSS-10 needed, and the
// construction built on it is right. The *character* does not generalise. A full
// stop is illegal in an ELBv2 load balancer name, in an ELBv2 target group name
// (both [elbName]) and in a Lambda function name ([lambdaFunctionName]), so
// calling [sanitize] for any of those returns a name the AWS API rejects — and
// only for a name that gets digested, which is to say only for a name carrying
// punctuation, mixed case, or length. Every plain lowercase name works and the
// break arrives from a live AWS API on the first name that does not. That is the
// same failure distribution as the collision the marker was introduced to close.
//
// An underscore is the obvious wrong answer: legal in a Lambda function name,
// **illegal in an ELBv2 name**, which admits only alphanumerics and hyphens.
//
// # Why two hyphens is safe when one is not
//
// A single hyphen cannot be a marker, because [notAllowed] *produces* hyphens.
// "foo-a1b2" is reachable both as a name spelled that way and as a digested
// rendering of something beginning "foo", which is the collision USOSS-13 found
// and it must not be reopened.
//
// A run of two cannot appear in the undigested form. [sanitize] emits a name
// verbatim only when `clean == name` byte for byte, and clean is the input with
// every *run* of non-alphanumerics replaced by a single hyphen and the ends
// trimmed — so a name that survives that comparison contains no two adjacent
// hyphens, by construction rather than by inspection. The prefix is the only
// other component, and [namePrefixGrammar] forbids "--" there. So an undigested
// physical name contains no "--" and a digested one contains exactly one:
// disjoint sets of strings, the same argument [sanitize] documents, over a
// character these grammars admit.
//
// The single occurrence also makes the split unique, so a digested name
// determines its own head and digest and two digested names can only collide by
// colliding on a 64-bit digest of the whole logical name.
//
// The convention is USOSS-13's, reached independently there for S3 bucket names
// — a third grammar where a full stop is legal but unwanted, because a dot in a
// bucket name breaks virtual-hosted-style TLS.
const markerDoubleDash = "--"

// bucketDigestMarker is the same separator for S3 bucket names, and it has to be
// a different string.
//
// A double hyphen, and it carries [digestMarker]'s disjointness argument
// unchanged: [notAllowed] collapses every run of non-alphanumerics to a *single*
// hyphen, so a lossless name provably contains no double hyphen. The marker
// therefore means "a digest follows" in a bucket name and can mean nothing else,
// which is the property the injectivity depends on.
//
// # Why the marker cannot be shared across grammars
//
// The separator is per-grammar because the grammars do not agree, and the trap is
// that legality is not the test:
//
//   - "." is legal in an S3 bucket name and harmful in one. A bucket whose name
//     contains a dot cannot be addressed virtual-hosted-style over HTTPS without
//     failing certificate validation, because the wildcard certificate covers one
//     label and a dot adds another. AWS's own guidance is not to use them.
//   - "--" is legal in S3 and IAM and *illegal* in an ECR repository name, whose
//     grammar admits ".", "_" and "-" only between alphanumeric runs.
//
// So no single marker is both safe and legal everywhere, which is why
// [sanitizeWith] takes it rather than reading a package constant. One
// implementation of the injective mapping, three callers that name their own
// separator: two implementations of one property is how the property drifts.
const bucketDigestMarker = "--"

// digestLength is how much of the digest a name carries.
//
// Sixteen hex digits, which is 64 bits. The number that matters is not the
// birthday bound but the second-preimage one: the attack this is defending
// against is choosing an application name that collides with a *specific*
// existing one, so that an Ensure adopts its repository or its role. That is
// 2^64 work here. Eight hex digits, which an earlier revision used, is 2^32 —
// findable.
const digestLength = 16

// sanitize turns a logical name into a legal physical one, deterministically
// and injectively.
//
// # The two properties, and why the second one needed a rewrite
//
// **Determinism** is a contract rather than a convenience: teardown has to be
// able to reconstruct a reference from a logical name whose provisioned
// identifier may never have been persisted, and the conformance suite checks
// that a second provider instance reaches the same resource from the same
// logical name.
//
// **Injectivity** — two distinct logical names never produce one physical name
// — is the property that keeps two applications from sharing one resource. It
// is worth stating what happens without it, because it is not a naming
// annoyance: EnsureWorkloadIdentity would resolve two applications to one IAM
// role, so application B's workload would assume the identity provisioned for
// application A. The ownership check cannot catch that. Both resources are
// genuinely apphub-owned and carry the same component tag; neither tag
// distinguishes two legitimate callers.
//
// This function did not have it, twice, and both were found by review rather
// than by a test:
//
//   - The **truncating** path appended "-" plus an eight-hex digest, so a short
//     name spelled "foo-a1b2c3d4" collided with a long name beginning "foo"
//     whose digest started "a1b2c3d4". About 2^32 work against a chosen prefix.
//   - The **untruncated** path — the common one — collapsed each run of
//     non-alphanumerics to a single hyphen and stopped there, so six spellings
//     of one name — differing only in the punctuation between the two words, or
//     in case — all produced the same physical name. No work factor at all.
//
// # The construction
//
// One rule, and it is a rule about sets rather than a check about strings.
//
// A name is used verbatim only when sanitization changed nothing at all —
// clean == name, byte for byte — and it fits. Such a name is drawn from
// [a-z0-9-] with no leading, trailing or repeated hyphen, so it contains no
// full stop.
//
// Every other name — lossy, too long, or both — is rendered as
// head + [digestMarker] + a digest of the *whole* logical name. So:
//
//   - two verbatim names differ because the names differ;
//   - two digested names differ because their digests differ;
//   - a verbatim name and a digested one differ because exactly one of them
//     contains a full stop after the prefix.
//
// The third clause is the one both earlier revisions were missing, and it is a
// property of the alphabet rather than of a digest length, which is why it does
// not need arguing about work factors.
//
// A prefix that leaves no room for a head, a marker and a digest is refused
// rather than papered over. An earlier revision returned the bare digest in
// that case, which is an ordinary verbatim-shaped name and reintroduced exactly
// the collision the marker exists to prevent — a new instance of the defect,
// inside the branch added to close the previous one.
func sanitize(prefix, name string, limit int) (string, error) {
	return sanitizeWith(prefix, name, limit, digestMarker)
}

// sanitizeWith is [sanitize] with the marker as a parameter.
//
// It exists because the marker has to be legal in the substrate's own grammar
// and no single character is legal in all of them: a full stop suits ECR, IAM,
// DynamoDB, a security group and a DB subnet group, and an RDS cluster
// identifier admits neither it nor a repeated hyphen; ELBv2 and Lambda names
// admit neither a full stop nor (for ELBv2) an underscore, which is what
// [markerDoubleDash] is for. Rather than a second implementation of the
// construction — which is how a restatement drifts from what it restates — the
// construction is here once and the marker is chosen by the caller. [sanitize]
// is this function with the full stop, and TestSanitizeIsSanitizeWithTheFullStop
// pins that they cannot diverge.
//
// The injectivity property belongs to the marker rather than to this function:
// it holds for any marker that cannot occur in `prefix + clean`. The marker's
// obligation, and the reason it is not a free choice: the verbatim form of a
// name must provably not end in the marker followed by a digest. A marker
// outside [a-z0-9-] gets that for free, because the lossless form of a name
// contains no such character. A marker inside that alphabet — which is all an
// RDS identifier leaves — does not, so the verbatim clause below excludes a name
// that already looks digested and sends it down the digest path instead. The
// two sets stay disjoint either way, and by a decidable property of the string
// rather than by a digest length, and there is a test quantifying over pairs of
// distinct names from an adversarial corpus rather than naming cases.
func sanitizeWith(prefix, name string, limit int, marker string) (string, error) {
	clean := notAllowed.ReplaceAllString(strings.ToLower(name), "-")
	clean = strings.Trim(clean, "-")

	// The verbatim set. Byte-identical, so a difference in case or punctuation
	// cannot land here: two spellings differing only in case are two names
	// and get two results. And never a string that already carries a digest
	// tail, or the two sets would overlap for a marker drawn from the name
	// alphabet.
	if clean != "" && clean == name && len(prefix)+len(clean) <= limit &&
		!hasDigestTail(clean, marker) {
		return prefix + clean, nil
	}

	sum := sha256.Sum256([]byte(name))
	suffix := marker + hex.EncodeToString(sum[:])[:digestLength]
	keep := limit - len(prefix) - len(suffix)
	if keep < 1 {
		return "", fmt.Errorf("%w: a name prefix of %d characters leaves no room for a name in "+
			"the %d characters this substrate allows; shorten the configured prefix",
			compute.ErrInvalidSpec, len(prefix), limit)
	}
	if clean == "" {
		// A logical name with no alphanumerics at all. The head is a
		// placeholder and the digest carries the identity.
		clean = "x"
	}
	if len(clean) > keep {
		clean = clean[:keep]
	}
	// clean has no leading hyphen and no repeated hyphens, so the trim can only
	// remove a trailing one and always leaves at least one character.
	head := strings.Trim(clean, "-")
	if head == "" {
		head = "x"
	}
	return prefix + head + suffix, nil
}

// hasDigestTail reports whether s already ends in the marker followed by a
// digest, and is what keeps the verbatim and digested sets disjoint when the
// marker is drawn from the same alphabet the name is.
//
// It is the decidable half of the construction: every digested name has such a
// tail by construction, and a verbatim candidate that has one is refused
// verbatim status. Neither clause depends on how long the digest is.
func hasDigestTail(s, marker string) bool {
	tail, ok := strings.CutPrefix(s[max(0, len(s)-digestLength-len(marker)):], marker)
	if !ok || len(tail) != digestLength {
		return false
	}
	for i := range len(tail) {
		c := tail[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// repositoryName renders a logical name as an ECR repository name.
func (p *Provider) repositoryName(logical string) (string, error) {
	prefix := ""
	if p.cfg.Registry != nil {
		prefix = p.cfg.Registry.NamePrefix
	}
	name, err := sanitizeWith(strings.ToLower(prefix), logical, maxECRRepositoryName, digestMarker)
	if err != nil {
		return "", fmt.Errorf("%w (check Config.Registry.NamePrefix)", err)
	}
	if !ecrRepositoryName.MatchString(name) {
		// Reachable only through a configured prefix, since sanitize's output
		// is otherwise always legal. Saying which half is wrong is the point.
		return "", fmt.Errorf("%w: %q is not a legal ECR repository name; check "+
			"Config.Registry.NamePrefix", compute.ErrInvalidSpec, name)
	}
	return name, nil
}

// roleName renders a logical name as an IAM role name.
func (p *Provider) roleName(logical string) (string, error) {
	name, err := sanitizeWith(p.cfg.Identity.NamePrefix, logical, maxIAMRoleName, digestMarker)
	if err != nil {
		return "", fmt.Errorf("%w (check Config.Identity.NamePrefix)", err)
	}
	if !iamRoleName.MatchString(name) {
		return "", fmt.Errorf("%w: %q is not a legal IAM role name; check "+
			"Config.Identity.NamePrefix", compute.ErrInvalidSpec, name)
	}
	return name, nil
}

// The physical-name renderers for the function port's three substrates.
//
// Each pairs a grammar with a marker legal in it, and then checks the *finished*
// name against the grammar rather than trusting that the pieces composed. That
// placement is the point: the marker mistake this port found would have been
// caught by a check on the artefact and is invisible to a check on any step that
// built it.

// functionName renders a logical name as a Lambda function name.
func (p *Provider) functionName(logical string) (string, error) {
	prefix := ""
	if p.cfg.Function != nil {
		prefix = p.cfg.Function.NamePrefix
	}
	name, err := sanitizeWith(prefix, logical, maxLambdaFunctionName, markerDoubleDash)
	if err != nil {
		return "", fmt.Errorf("%w (check Config.Function.NamePrefix)", err)
	}
	if !lambdaFunctionName.MatchString(name) {
		return "", fmt.Errorf("%w: %q is not a legal Lambda function name; check "+
			"Config.Function.NamePrefix", compute.ErrInvalidSpec, name)
	}
	return name, nil
}

// endpointName renders a logical name as the physical name of all three objects
// an endpoint is made of: the load balancer, its target group, and its security
// group.
//
// # One name, and the third reason is the load-bearing one
//
// It is *safe*: a load balancer, a target group and a security group are three
// different namespaces, so one name cannot collide with itself. It is *cheaper*
// than appending a discriminator, which would spend budget out of the tightest
// ceiling in the package ([maxELBName], 32) and would give three objects three
// injectivity arguments where one will do. What keeps them from being mistaken
// for each other is [checkOwned] over distinct components, which is the
// mechanism that exists for exactly that.
//
// But the reason it *has* to be one name is teardown. A [compute.Ref] carries
// the physical ELBv2 name, and [sanitizeWith] is not invertible — a digested
// name cannot be turned back into the logical name it came from. So a security
// group named by a second mapping at a second ceiling would be **unlocatable
// from a reference alone**, and it would need to be located exactly when the
// load balancer that recorded the placement is already gone. An earlier revision
// had two mappings and returned success from that teardown while the security
// group survived. One name makes the group's name computable from the reference,
// which is what lets [functionRuntime.DeleteEndpoint] finish.
func (p *Provider) endpointName(logical string) (string, error) {
	prefix := ""
	if p.cfg.Endpoint != nil {
		prefix = p.cfg.Endpoint.NamePrefix
	}
	name, err := sanitizeWith(prefix, logical, maxELBName, markerDoubleDash)
	if err != nil {
		return "", fmt.Errorf("%w (check Config.Endpoint.NamePrefix)", err)
	}
	switch {
	case !elbName.MatchString(name):
		return "", fmt.Errorf("%w: %q is not a legal ELBv2 name; check "+
			"Config.Endpoint.NamePrefix", compute.ErrInvalidSpec, name)
	case !endpointSecurityGroupName.MatchString(name):
		// Unreachable while [elbName] is a subset of the security group
		// alphabet, and checked anyway: this one name has to be legal on both
		// substrates, and "a subset" is a claim about two regexps that a future
		// edit to either could falsify silently.
		return "", fmt.Errorf("%w: %q is a legal ELBv2 name and not a legal security group name",
			compute.ErrInvalidSpec, name)
	case strings.HasPrefix(name, reservedELBPrefix):
		// Refusing is the only option. Renaming would break the determinism
		// contract teardown depends on.
		return "", fmt.Errorf("%w: %q begins with %q, which ELBv2 reserves; check "+
			"Config.Endpoint.NamePrefix", compute.ErrInvalidSpec, name, reservedELBPrefix)
	case strings.HasPrefix(name, reservedSGPrefix):
		return "", fmt.Errorf("%w: %q begins with %q, which EC2 reserves for a security group "+
			"identifier; check Config.Endpoint.NamePrefix",
			compute.ErrInvalidSpec, name, reservedSGPrefix)
	}
	return name, nil
}

// invokeStatementID names the resource-policy statement that lets one endpoint
// invoke one function.
//
// Derived from the endpoint's physical name, which is already injective and
// already inside 32 characters, so this is injective and inside 100 without
// needing a mapping of its own. Statement identifiers admit [a-zA-Z0-9_-], so
// the physical name's alphabet is legal here unchanged.
//
// It is per-endpoint, and that is the substantive difference from the source
// system, which uses the constant "AllowALBInvoke" (lambda.go:670). With a
// constant, a second endpoint's AddPermission is a conflict rather than a second
// statement — and the source tolerates that conflict with a logged warning
// (lambda.go:464-467), so the second endpoint is created, reports success, and
// cannot invoke anything.
func invokeStatementID(endpointName string) string {
	id := "apphub-invoke-" + endpointName
	if len(id) > maxStatementID {
		// Unreachable while maxELBName is 32; here so that raising that ceiling
		// cannot silently produce an illegal identifier.
		id = id[:maxStatementID]
	}
	return id
}

// validateName rejects a logical name that cannot become a physical one at all,
// so the caller learns at the spec rather than from an AWS API.
func validateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: the resource name is empty", compute.ErrInvalidSpec)
	}
	return nil
}

// validateLabels rejects caller metadata this provider cannot carry as an AWS
// tag.
//
// AWS tag keys and values are bounded and exclude a few characters. Refusing is
// better than truncating: a label silently cut in half is metadata that says
// something the caller did not.
const (
	maxTagKey   = 128
	maxTagValue = 256

	// maxTagsPerResource is AWS's per-resource tag ceiling, and it is the same 50
	// on every service this package touches. Enforced where tags are composed
	// rather than left to the substrate, so an over-tagged spec is ErrInvalidSpec
	// from apphub instead of a service error the caller has to interpret.
	maxTagsPerResource = 50
)

var badTagRune = regexp.MustCompile(`[^\p{L}\p{N}\p{Z}_.:/=+@-]`)

func validateLabels(labels map[string]string) error {
	for k, v := range labels {
		switch {
		case k == "":
			return fmt.Errorf("%w: a label key is empty", compute.ErrInvalidSpec)
		case len(tagLabelPrefix)+len(k) > maxTagKey:
			return fmt.Errorf("%w: label key %q is longer than an AWS tag key can be once "+
				"namespaced (%d characters including the %q prefix)",
				compute.ErrInvalidSpec, k, maxTagKey, tagLabelPrefix)
		case len(v) > maxTagValue:
			return fmt.Errorf("%w: the value of label %q is longer than an AWS tag value can "+
				"be (%d characters)", compute.ErrInvalidSpec, k, maxTagValue)
		case badTagRune.MatchString(k) || badTagRune.MatchString(v):
			return fmt.Errorf("%w: label %q contains a character an AWS tag cannot hold; "+
				"tags admit letters, digits, whitespace and _.:/=+@-", compute.ErrInvalidSpec, k)
		case strings.HasPrefix(strings.ToLower(k), "aws:"):
			return fmt.Errorf("%w: label key %q is in the reserved aws: namespace",
				compute.ErrInvalidSpec, k)
		}
	}
	return nil
}

// ownershipTags are the tags every resource this provider creates carries,
// including the caller's labels under [tagLabelPrefix].
func ownershipTags(name, component string, labels map[string]string) map[string]string {
	out := map[string]string{
		tagManagedBy: managedByValue,
		tagName:      name,
	}
	if component != "" {
		out[tagComponent] = component
	}
	for k, v := range labels {
		out[tagLabelPrefix+k] = v
	}
	return out
}

// bucketName renders a logical name as an S3 bucket name.
//
// A bucket name is a DNS label, which is why the limit is 63 rather than
// anything S3-specific: virtual-hosted-style addressing puts it in a hostname.
// See [bucketDigestMarker] for why the separator differs from the one the
// registry and identity names use.
func (p *Provider) bucketName(logical string) (string, error) {
	name, err := sanitizeWith(strings.ToLower(p.cfg.ObjectStore.NamePrefix), logical,
		maxS3BucketName, bucketDigestMarker)
	if err != nil {
		return "", fmt.Errorf("%w (check Config.ObjectStore.NamePrefix)", err)
	}
	if !s3BucketName.MatchString(name) {
		return "", fmt.Errorf("%w: %q is not a legal S3 bucket name; check "+
			"Config.ObjectStore.NamePrefix", compute.ErrInvalidSpec, name)
	}
	if reservedBucketPrefix.MatchString(name) || reservedBucketSuffix.MatchString(name) {
		// AWS reserves a handful of affixes -- "xn--" for punycode, "sthree-",
		// and the "--x-s3"/"--ol-s3"/"-s3alias" suffixes for directory buckets,
		// object-lambda and access-point aliases. A name that lands on one is
		// rejected by S3 with a message about the affix rather than about the
		// prefix that produced it, so it is refused here where the caller can
		// see which half to change.
		return "", fmt.Errorf("%w: %q uses a bucket-name affix AWS reserves; check "+
			"Config.ObjectStore.NamePrefix", compute.ErrInvalidSpec, name)
	}
	return name, nil
}

// mergedBucketTags is what to send to PutBucketTagging.
//
// S3 replaces a bucket's **entire** tag set, so sending only the tags this
// provider owns deletes everything else -- an operator's cost-allocation tags,
// their compliance tags -- and reports success. That is the worst shape of
// destructive bug: silent, total, and indistinguishable from working.
//
// So the desired set is merged over whatever is already there, and the only keys
// this provider removes are ones inside its own namespace that it no longer
// wants. A key outside the namespace is never touched, whatever it is.
func mergedBucketTags(current, desired map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range current {
		if k == tagManagedBy || k == tagName || k == tagComponent ||
			strings.HasPrefix(k, tagLabelPrefix) {
			// Inside this provider's namespace: the desired set decides.
			continue
		}
		out[k] = v
	}
	for k, v := range desired {
		out[k] = v
	}
	return out
}

// checkOwned decides whether this platform may write a resource it found under
// a name it wanted.
//
// Two tags have to agree, not one. The ownership tag says apphub created it;
// the component tag says what apphub created it *as*. Checking only the first
// makes every resource this platform owns interchangeable by name, and the
// resources are not interchangeable: an IAM role that a workload assumes and an
// IAM role that another account assumes are the same kind of object in the same
// account-global namespace, and adopting one as the other silently repurposes a
// trust relationship. This is USOSS-13's finding, generalised from the source
// system's own purpose tag (bucket.go:545-551), and it matters here because the
// sibling AWS ports create roles too.
//
// The message names the resource and nothing else. What the resource does carry
// is somebody else's business, and the caller only needs to know the name it
// asked for is taken.
func checkOwned(tags map[string]string, kind, component, name string) error {
	if tags[tagManagedBy] != managedByValue {
		return fmt.Errorf("%w: %s %q exists and does not carry %s=%s",
			compute.ErrNotOwned, kind, name, tagManagedBy, managedByValue)
	}
	if got := tags[tagComponent]; got != component {
		return fmt.Errorf("%w: %s %q is managed by apphub as a %q, and this call would claim it "+
			"as a %q", compute.ErrNotOwned, kind, name, got, component)
	}
	return nil
}

// labelsFromTags is the inverse: the caller's labels, recovered from the tags
// this provider wrote. Everything else on the resource — its ownership marker,
// and any tag an operator or an account policy added — is invisible to the
// caller, which is why the removal half of convergence can be safe.
func labelsFromTags(tags map[string]string) map[string]string {
	var out map[string]string
	for k, v := range tags {
		if label, ok := strings.CutPrefix(k, tagLabelPrefix); ok {
			if out == nil {
				out = map[string]string{}
			}
			out[label] = v
		}
	}
	return out
}

// tagDelta reports which tags have to be written and which removed to converge
// current onto desired.
//
// Only keys this provider owns are eligible for removal: the ownership marker,
// its own metadata, and the namespaced labels. A tag an operator added survives
// every Ensure, which is the difference between converging a spec and taking
// over a resource.
func tagDelta(current, desired map[string]string) (put map[string]string, remove []string) {
	put = map[string]string{}
	for k, v := range desired {
		if current[k] != v {
			put[k] = v
		}
	}
	for k := range current {
		if _, wanted := desired[k]; wanted {
			continue
		}
		if k == tagManagedBy || k == tagName || k == tagComponent ||
			k == tagPlacement || k == tagIdentity || k == tagTarget ||
			k == tagPeer || strings.HasPrefix(k, tagLabelPrefix) {
			remove = append(remove, k)
		}
	}
	sort.Strings(remove)
	if len(put) == 0 {
		put = nil
	}
	return put, remove
}

// copyTags returns a map sharing no storage with the one it was given.
//
// A read-back that hands out the provider's own map lets a caller rewrite what
// the provider believes it deployed by editing a label it was shown. The
// conformance suite checks for it on every port, and it is the kind of defect
// that survives a careful review because nothing about the code looks wrong.
func copyTags(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// sortedPairs renders a map as "k=v k=v", key-sorted, for a rendered artefact.
func sortedPairs(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, " ")
}

// validateNamePrefix checks an operator-supplied physical-name prefix for the
// grammars this port writes into.
//
// Called from [New] rather than from a name renderer, because a prefix that
// cannot produce a legal name is a misconfiguration and the operator who wrote
// it is the person who can act on it — not the deploy that happened to be the
// first to need a digested name. See [namePrefixGrammar] for why "--"
// specifically is refused.
func validateNamePrefix(field, prefix string) error {
	if !namePrefixGrammar.MatchString(prefix) {
		return fmt.Errorf("aws: %s %q must be lowercase alphanumerics separated by single "+
			"hyphens: two adjacent hyphens are the digest marker this port relies on being "+
			"absent from a name that carries no digest", field, prefix)
	}
	return nil
}
