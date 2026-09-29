// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// This file holds every IAM action this provider will ever grant, and nothing
// else. It is deliberately the only place an action string appears: a grant that
// is wider than it needs to be is the failure mode with the longest half-life,
// because nothing reports it and the resource keeps working.

// Two policy grammars live in this package, and the distinction is load-bearing.
//
// The object-store functions below render into policyDocument and statement,
// declared in pushcreds.go and shared deliberately: two spellings of one grammar
// is how a document IAM accepts from one call site gets rejected from another.
// [PolicyDocument] and [PolicyStatement] are the secret store's (USOSS-26), and
// carry a Sid, a Principal and a Condition that the object-store grammar has not.
//
// # What the object-store grammar cannot express, and why that matters here
//
// It has no Principal field and no Condition field. That is not an omission to be
// filled in later. An identity-based policy attached to a role has no principal,
// and the only thing in this domain that needs one is a cross-account trust
// statement -- the ConductorOne datasource binding, excluded from v1 (see
// docs/decisions/usoss-13-cross-domain-object-access-is-not-ported.md).
//
// Leaving a cross-account statement *unrepresentable* rather than merely unwritten
// is the point. The source system hardcodes three real cross-account role ARNs as
// constants; a grammar that cannot hold a foreign principal cannot acquire them
// because somebody added a field.
//
// # The second grammar does not reopen that, and the reason is a field it lacks
//
// [PolicyStatement] does have a Principal, so the sentence above stopped being
// true of "this file" the moment the two grammars met -- which is why it is now
// scoped to the grammar and not to the file. The property survives for a
// different reason: [PolicyPrincipal] holds only Service. There is no AWS,
// Federated or CanonicalUser field anywhere a policy is RENDERED in this package;
// those spellings appear only in identity.go, which recognises them in order to
// refuse a trust policy, and in test fixtures. So no renderer here can name a
// foreign account, in either grammar.
//
// Two claims rather than one, because they have different lifetimes: the
// object-store grammar cannot hold a principal at all, and the secret grammar can
// hold only a service. Adding an AWS field to [PolicyPrincipal] would break the
// second without touching the first.

// The IAM policy-language constants this package emits.
const (
	policyVersion = "2012-10-17"
	effectAllow   = "Allow"
)

// PolicyDocument is an IAM policy document.
//
// It is a typed document rather than a string template because a policy is the
// one artefact in this package where a formatting mistake is a privilege
// escalation. A template makes `"Resource": "%s"` and `"Resource": "%s*"` look
// equally plausible; a struct whose Resource is built from validated parameter
// names does not.
type PolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

// IsEmpty reports whether the document grants nothing.
//
// Callers must check it. An IAM policy with no statements is not a valid policy
// document, so a caller that attached one blindly would get an API error — and
// the alternative reading, that "nothing to grant" should widen to something,
// is the failure this whole file exists to prevent.
func (d PolicyDocument) IsEmpty() bool { return len(d.Statement) == 0 }

// PolicyStatement is one statement in a [PolicyDocument].
type PolicyStatement struct {
	Sid       string                       `json:"Sid,omitempty"`
	Effect    string                       `json:"Effect"`
	Principal *PolicyPrincipal             `json:"Principal,omitempty"`
	Action    []string                     `json:"Action"`
	Resource  []string                     `json:"Resource,omitempty"`
	Condition map[string]map[string]string `json:"Condition,omitempty"`
}

// PolicyPrincipal is the Principal element of a trust policy.
type PolicyPrincipal struct {
	Service []string `json:"Service,omitempty"`
}

// The actions [Provider.SecretReadPolicy] grants, and the ones it deliberately
// does not.
//
// Granted: the two named reads. Both take parameter names and are constrained
// entirely by the Resource element, so including both does not widen anything —
// a container runtime resolving ECS `valueFrom` calls GetParameters, and a
// function reading its own configuration at startup calls GetParameter.
//
// Not granted, and this is the part that matters:
//
//   - ssm:GetParametersByPath and ssm:DescribeParameters are enumeration. A
//     principal that can enumerate a path can discover and read every secret
//     under it, so granting either against a hierarchy turns a grant scoped to
//     one application into a grant over all of them. The source system's
//     execution-role policy grants reads against
//     "…:parameter{prefix}/apps/*" (terraform/modules/ecs/iam.tf:39-46) — every
//     application's secrets, to every application's tasks.
//   - ssm:PutParameter, ssm:DeleteParameter and ssm:AddTagsToResource are
//     writes. A workload has no business writing to the store that feeds it.
//   - ssm:* is not a thing this file can say. There is no wildcard input and no
//     wildcard constant.
var secretReadActions = []string{"ssm:GetParameter", "ssm:GetParameters"}

// SecretParameterRef is one resolved secret binding: the environment variable a
// workload expects, and the ARN of the parameter behind it, pinned to a revision
// when the binding asked for one.
//
// It exists because a [compute.Ref] deliberately does not carry an ARN — a Ref
// is what a caller persists, and an ARN carries the account, so putting one in a
// Ref would spread the account identifier through every stored application
// record. A runtime that has to reference a parameter (an ECS `valueFrom`, an
// IAM Resource element) needs the ARN, and this is the supported way to get from
// one to the other.
type SecretParameterRef struct {
	// EnvName is the environment variable the workload sees.
	EnvName string

	// ARN is what a runtime references: the parameter's ARN as the substrate
	// reported it, with ":<version>" appended when the binding pinned one.
	//
	// The selector is part of the reference and not part of the grant. SSM's
	// version selector lives in the name a caller passes to GetParameter and in
	// an ECS valueFrom; an IAM Resource element has no version component at all,
	// so [Provider.SecretReadPolicy] uses the unversioned ARN. Establishing that
	// mattered: had it been the other way round, a pinned binding would have
	// been authorised by nothing and the failure would have surfaced as a task
	// that would not start.
	ARN string

	// Version is the revision the binding pinned, empty when it pinned none. It
	// is reported separately as well as being in the ARN, so a caller that wants
	// the base ARN -- for a grant, say -- does not have to parse it back out.
	Version string
}

// baseARN is the reference with any version selector removed: the ARN a grant
// names.
//
// Trimming by the recorded version rather than by "everything after the last
// colon" is deliberate. An ARN is full of colons, and a suffix rule that did not
// know whether a version was actually appended would corrupt every unpinned ARN
// it was handed.
func (r SecretParameterRef) baseARN() string {
	if r.Version == "" {
		return r.ARN
	}
	return strings.TrimSuffix(r.ARN, ":"+r.Version)
}

// SecretParameterARNs resolves each binding to the parameter behind it.
//
// The ARN is read back from the substrate rather than composed from a template.
// That is the same decision the registry port made for a repository, and it is
// what the source system got wrong: it stored bare ARNs and then reconstructed
// them by string template in a dozen places (bucket.go:194-215,
// container.go:1530-1537), which is exactly the coupling [compute.Ref] exists to
// prevent.
//
// It has a second effect worth having. A parameter that does not exist is
// [compute.ErrNotFound] here, at the point where a runtime is building a task
// definition — rather than an opaque container-launch failure minutes later, when
// the agent cannot resolve a reference nobody checked.
//
// Refusals rather than omissions, in every case: a foreign reference is
// [compute.ErrForeignRef], one outside this store's prefix or of the wrong kind
// is [compute.ErrInvalidSpec], and a binding with no environment variable name
// is [compute.ErrInvalidSpec]. Silently dropping one would produce a task
// definition that looks correct and a workload that starts without a credential
// it was written to require.
func (p *Provider) SecretParameterARNs(ctx context.Context, bindings []compute.SecretBinding) ([]SecretParameterRef, error) {
	if p.secret == nil {
		return nil, compute.Unsupported(p.name, compute.CapSecretStore)
	}
	out := make([]SecretParameterRef, 0, len(bindings))
	for _, b := range bindings {
		if b.EnvName == "" {
			return nil, fmt.Errorf("%w: a secret binding with no environment variable name binds "+
				"the secret to nothing", compute.ErrInvalidSpec)
		}
		name, err := p.secret.resolve(b.Secret)
		if err != nil {
			return nil, err
		}
		meta, err := p.sub.Parameters.Describe(ctx, name)
		if err != nil {
			return nil, p.secret.wrap(err, name)
		}
		if meta.ARN == "" {
			return nil, fmt.Errorf("%w: the substrate reported no ARN for parameter %s, and a "+
				"runtime cannot reference it without one", compute.ErrFailed, name)
		}
		arn, version := meta.ARN, b.Version
		if b.Version != "" {
			n, err := p.secret.revision(ctx, name, b.Version)
			if err != nil {
				return nil, err
			}
			// The PARSED revision, not the string that was handed over.
			// [secretStore.revision] normalises through strconv.ParseInt, which
			// accepts "007" and "+7" -- both validate here and neither is a
			// selector SSM resolves. A normalisation that is computed and then
			// discarded is only a check, and the value it checked still reaches
			// the substrate.
			//
			// Both fields, from the same value: [SecretParameterRef.baseARN]
			// recovers the unversioned ARN by trimming Version off ARN, so the
			// two disagreeing would silently stop the grant deduplicating a
			// pinned and an unpinned binding to one parameter.
			version = strconv.FormatInt(n, 10)
			arn += ":" + version
		}
		out = append(out, SecretParameterRef{EnvName: b.EnvName, ARN: arn, Version: version})
	}
	return out, nil
}

// SecretReadPolicy returns the IAM policy that lets one principal resolve
// exactly the secrets in refs, and nothing else.
//
// # Why it takes resolved references rather than bindings or a scope
//
// The narrowest grant that works is the set of parameter ARNs the workload
// actually references, and taking them already-resolved means this function
// cannot invent one: every ARN it can emit came back from the substrate through
// [Provider.SecretParameterARNs]. There is no wildcard input and no template.
//
// A scope-shaped variant — "everything under this application's path" — is
// deliberately not offered. It would be the obvious convenience, it would be
// wider than necessary in every case, and an API that offers a wider grant next
// to a narrower one gets the wider one used. Widening this needs an argument in
// a pull request, not a parameter.
//
// # Who attaches it
//
// Not this port. On AWS the principal that resolves an ECS `valueFrom` is the
// task *execution* role, and the principal that reads a parameter from
// application code is the task or function role; which of those applies is a
// property of the runtime, so the container and function runtimes attach this
// document and the secret store only says what it should contain. That split is
// why this returns a document instead of performing a grant, and it is also why
// [compute.SecretStore] is not a [compute.Granter]: the identity that reads a
// bound secret on AWS is not necessarily the workload's own.
func (p *Provider) SecretReadPolicy(refs []SecretParameterRef) (PolicyDocument, error) {
	doc := PolicyDocument{Version: policyVersion}
	if p.secret == nil {
		return doc, compute.Unsupported(p.name, compute.CapSecretStore)
	}
	if len(refs) == 0 {
		// No references means no grant. Not a grant over the prefix, and not an
		// empty Resource element, which IAM reads as "this statement applies to
		// nothing" in an identity policy but which is one edit away from being
		// read as everything.
		return doc, nil
	}
	seen := map[string]bool{}
	var resources []string
	for _, r := range refs {
		switch {
		case r.EnvName == "":
			return PolicyDocument{}, fmt.Errorf("%w: a secret reference with no environment "+
				"variable name binds the secret to nothing", compute.ErrInvalidSpec)
		case r.ARN == "":
			return PolicyDocument{}, fmt.Errorf("%w: the secret reference for %q has no ARN; "+
				"resolve bindings through Provider.SecretParameterARNs rather than composing one",
				compute.ErrInvalidSpec, r.EnvName)
		case !strings.HasPrefix(r.ARN, "arn:"):
			return PolicyDocument{}, fmt.Errorf("%w: the secret reference for %q does not name an "+
				"ARN", compute.ErrInvalidSpec, r.EnvName)
		case strings.ContainsAny(r.ARN, "*?"):
			// A pattern cannot get here from this provider: every element of a
			// parameter path comes from segment(), whose character class has no
			// wildcard, and the configured prefix is matched against
			// pathPrefixPattern, which has none either. The check is here because
			// the ARN now arrives from the substrate rather than from this
			// package, so "it cannot happen" stopped being a property of code a
			// reader can see.
			return PolicyDocument{}, fmt.Errorf("%w: refusing to emit a policy whose Resource "+
				"element contains a wildcard", compute.ErrInvalidSpec)
		}
		// The grant names the parameter, not the revision. An IAM Resource
		// element for an SSM parameter has no version component, so a policy
		// naming "…:parameter/x:3" authorises nothing at all -- it fails closed,
		// which is the safe direction, but it fails closed on every deploy that
		// pins anything. Two parameters pinned to different revisions therefore
		// collapse to one resource, which is correct: the grant is "may read this
		// parameter", and which revision the workload asked for is a property of
		// the reference.
		resource := r.baseARN()
		if seen[resource] {
			continue
		}
		seen[resource] = true
		resources = append(resources, resource)
	}
	sort.Strings(resources)
	doc.Statement = append(doc.Statement, PolicyStatement{
		Sid:      "ReadBoundAppHubSecrets",
		Effect:   effectAllow,
		Action:   secretReadActions,
		Resource: resources,
	})
	if key := p.secret.cfg.KMSKeyARN; key != "" {
		// Only for a customer-managed key. Against the AWS-managed SSM key the
		// grant is neither needed (the service authorises via the SSM
		// permission) nor scopeable to one key, so emitting it would be a
		// broader grant that buys nothing.
		doc.Statement = append(doc.Statement, PolicyStatement{
			Sid:      "DecryptAppHubSecrets",
			Effect:   effectAllow,
			Action:   []string{"kms:Decrypt"},
			Resource: []string{key},
			Condition: map[string]map[string]string{
				// Narrows the grant to decryption performed on SSM's behalf, so
				// the key cannot be used to decrypt arbitrary ciphertext the
				// workload obtained elsewhere.
				"StringEquals": {"kms:ViaService": "ssm." + p.cfg.Region + ".amazonaws.com"},
			},
		})
	}
	return doc, nil
}

// SecretPlacement reports the placement a secret was stored for.
//
// It exists because [compute.SecretBinding] carries a [compute.Ref] and nothing
// else, so a runtime asked to bind a secret has no portable way to ask where that
// secret belongs -- and the conformance suite's
// security/secrets-do-not-cross-placements invariant requires exactly that
// question to be answerable. USOSS-11 found it by composing a container port
// against this store: the check had never run, because it needs both the
// container-service and secret-store capabilities and no provider had both.
//
// # Why this is a method here and not a field on the Ref
//
// A Ref is opaque and its ID is the parameter path, which the IAM grants are
// written against. Encoding the placement into the path would change every
// grant, every existing parameter's name, and the meaning of a stored reference.
// The placement is metadata about the resource, so it lives in a tag, and this
// reads it back from the substrate rather than recomposing it -- the same rule as
// [Provider.SecretParameterARNs].
//
// A parameter without the tag predates it. That is reported as an error rather
// than as an empty placement, because "no placement recorded" and "the default
// placement" are different facts and a consumer comparing them would silently
// treat the first as the second.
func (p *Provider) SecretPlacement(ctx context.Context, ref compute.Ref) (string, error) {
	if p.secret == nil {
		return "", compute.Unsupported(p.name, compute.CapSecretStore)
	}
	name, err := p.secret.resolve(ref)
	if err != nil {
		return "", err
	}
	tags, err := p.sub.Parameters.Tags(ctx, name)
	if err != nil {
		return "", p.secret.wrap(err, name)
	}
	if err := checkOwned(tags, "parameter", componentSecret, name); err != nil {
		return "", err
	}
	placement := tags[tagPlacement]
	if placement == "" {
		return "", fmt.Errorf("%w: parameter %s carries no %s tag, so the placement it was stored "+
			"for is unknown; it was created before the store recorded one and cannot be compared "+
			"against a workload's placement", compute.ErrFailed, name, tagPlacement)
	}
	return placement, nil
}

// Object-store actions, by access level.
//
// # Read is genuinely read-only
//
// s3:GetObject and s3:ListBucket, plus GetBucketLocation because a client that
// cannot resolve a bucket's region cannot address it. No Put, no Delete, no
// tagging, and no s3:GetBucketPolicy -- a reader that can read the policy can
// enumerate who else has access, which is not part of reading the data.
//
// # ReadWrite adds exactly the object verbs
//
// Put, Delete and the multipart-abort that a large upload needs in order to be
// cleaned up after a failure. It does not add any Bucket-level mutation: a
// workload with ReadWrite cannot change the bucket's encryption, its
// public-access block, or its tags. Those are the platform's, and a workload that
// could turn off the public-access block could undo the one control that makes
// PublicAccess=false mean anything.
//
// # There is no admin level for a plain bucket
//
// [compute.AccessAdmin] is refused. The source system's equivalent grants a
// wildcard s3:* to the application role (bucket.go:441-470), which includes
// PutBucketPolicy and PutPublicAccessBlock -- so an "admin" grant lets the
// workload make its own bucket public. That is a privilege escalation dressed as
// a convenience, and the interface's own documentation says a provider may refuse
// a level it cannot express safely.
func objectActions(level compute.AccessLevel) ([]string, []string, error) {
	read := []string{"s3:GetObject", "s3:GetObjectVersion"}
	bucket := []string{"s3:ListBucket", "s3:GetBucketLocation"}
	switch level {
	case compute.AccessRead:
		return bucket, read, nil
	case compute.AccessReadWrite:
		return bucket, append(read,
			"s3:PutObject",
			"s3:DeleteObject",
			"s3:AbortMultipartUpload",
		), nil
	case compute.AccessAdmin:
		return nil, nil, fmt.Errorf("%w: compute/aws: this provider does not offer AccessAdmin on a "+
			"bucket. An admin grant on S3 means the bucket-configuration actions -- PutBucketPolicy, "+
			"PutPublicAccessBlock, PutBucketEncryption -- and a workload holding those can make its "+
			"own bucket public and undo the hardening this provider applies on every Ensure. The "+
			"source system granted s3:* here; that is a privilege escalation and it is not ported. "+
			"Use AccessReadWrite for data access, and change the bucket's configuration through the "+
			"spec, which is the only path that stays audited", compute.ErrUnsupported)
	default:
		return nil, nil, fmt.Errorf("%w: compute/aws: unknown access level %q", compute.ErrInvalidSpec, level)
	}
}

// bucketAccessPolicy renders the inline policy for one (bucket, level) pair.
//
// Two statements rather than one, because S3 splits its actions across two
// resource shapes: the bucket ARN for the bucket-level verbs and the "/*" form
// for the object-level ones. A single statement listing both action sets against
// both ARNs would grant every action on both resources -- wider than asked for,
// and wider in a way that reads as correct.
func bucketAccessPolicy(partition, bucket string, level compute.AccessLevel) (string, error) {
	bucketVerbs, objectVerbs, err := objectActions(level)
	if err != nil {
		return "", err
	}
	doc := policyDocument{
		Version: policyVersion,
		Statement: []statement{
			{
				Sid:      "BucketLevel",
				Effect:   "Allow",
				Action:   bucketVerbs,
				Resource: []string{bucketARN(partition, bucket)},
			},
			{
				Sid:      "ObjectLevel",
				Effect:   "Allow",
				Action:   objectVerbs,
				Resource: []string{objectsARN(partition, bucket)},
			},
		},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		// Every field is a string or a slice of strings; an error here is a
		// programming mistake rather than a runtime condition.
		return "", fmt.Errorf("%w: compute/aws: rendering the bucket policy: %w", compute.ErrFailed, err)
	}
	return string(out), nil
}

// Table-bucket actions, by access level.
//
// # Admin is offered here and refused on a plain bucket
//
// The asymmetry is deliberate and it is about what "admin" denotes in each
// service. On S3 the bucket-configuration actions are the public-access block and
// the bucket policy, so an admin grant lets a workload expose its own data --
// see [objectActions]. On S3 Tables the equivalent is *schema*: creating and
// dropping namespaces and tables, which is a real thing an analytics workload
// legitimately owns and which exposes nothing to anybody outside the account.
//
// The policy-shaped actions are excluded from every level regardless.
// s3tables:PutTableBucketPolicy and s3tables:PutTablePolicy are resource-policy
// writes, so a workload holding one could grant a third party access -- the same
// escalation objectActions refuses, in the one service where the rest of admin is
// safe to hand over.
func tableActions(level compute.AccessLevel) ([]string, error) {
	read := []string{
		"s3tables:GetTableBucket",
		"s3tables:ListNamespaces",
		"s3tables:ListTables",
		"s3tables:GetNamespace",
		"s3tables:GetTable",
		"s3tables:GetTableData",
		"s3tables:GetTableMetadataLocation",
	}
	switch level {
	case compute.AccessRead:
		return read, nil
	case compute.AccessReadWrite:
		return append(read,
			"s3tables:PutTableData",
			"s3tables:UpdateTableMetadataLocation",
		), nil
	case compute.AccessAdmin:
		return append(read,
			"s3tables:PutTableData",
			"s3tables:UpdateTableMetadataLocation",
			"s3tables:CreateNamespace",
			"s3tables:DeleteNamespace",
			"s3tables:CreateTable",
			"s3tables:DeleteTable",
			"s3tables:RenameTable",
		), nil
	default:
		return nil, fmt.Errorf("%w: compute/aws: unknown access level %q", compute.ErrInvalidSpec, level)
	}
}

// Vector-bucket actions, by access level. Same admin reasoning as [tableActions]:
// an index is schema, and s3vectors:PutVectorBucketPolicy is excluded from every
// level.
func vectorActions(level compute.AccessLevel) ([]string, error) {
	read := []string{
		"s3vectors:GetVectorBucket",
		"s3vectors:ListIndexes",
		"s3vectors:GetIndex",
		"s3vectors:GetVectors",
		"s3vectors:QueryVectors",
		"s3vectors:ListVectors",
	}
	switch level {
	case compute.AccessRead:
		return read, nil
	case compute.AccessReadWrite:
		return append(read, "s3vectors:PutVectors", "s3vectors:DeleteVectors"), nil
	case compute.AccessAdmin:
		return append(read,
			"s3vectors:PutVectors",
			"s3vectors:DeleteVectors",
			"s3vectors:CreateIndex",
			"s3vectors:DeleteIndex",
		), nil
	default:
		return nil, fmt.Errorf("%w: compute/aws: unknown access level %q", compute.ErrInvalidSpec, level)
	}
}

// extAccessPolicy renders the inline policy for a table or vector bucket.
//
// One statement, unlike [bucketAccessPolicy]: neither service splits its actions
// across two resource shapes the way S3 does, so the bucket ARN and its "/*"
// child form both belong in the same statement's resource list.
func extAccessPolicy(arn string, actions []string) (string, error) {
	doc := policyDocument{
		Version: policyVersion,
		Statement: []statement{{
			Sid:      "BucketAndChildren",
			Effect:   "Allow",
			Action:   actions,
			Resource: []string{arn, arn + "/*"},
		}},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("%w: compute/aws: rendering the policy: %w", compute.ErrFailed, err)
	}
	return string(out), nil
}

// --- reading a grant back ----------------------------------------------------

// grantLevels is the order [levelFromStoredPolicy] tries the defined levels in.
//
// Ascending, so that if two levels ever rendered the same document the narrower
// one is reported. That cannot happen with the action tables above and the order
// is not load-bearing today; it is written this way because the mistake it would
// otherwise permit — reporting an access wider than the one that stands — is the
// one direction a security read-back must not be wrong in.
func grantLevels() []compute.AccessLevel {
	return []compute.AccessLevel{compute.AccessRead, compute.AccessReadWrite, compute.AccessAdmin}
}

// levelFromStoredPolicy recovers which [compute.AccessLevel] a stored inline
// policy expresses, given the function that renders one.
//
// # Why it re-renders rather than parses
//
// The alternative is to read the action list and classify it, which means a
// second table mapping actions back onto levels — and a second table is a second
// thing to keep in step with the first. This file states, in as many words, that
// it is "the only place an action string appears"; a hand-written inverse would
// break that, and would break it silently, because forward and backward tables
// that disagreed would report the wrong access rather than fail.
//
// Re-rendering keeps one authority. A document expresses a level exactly when
// that level would produce it, so an action added to [objectActions] or
// [tableActions] is an action this recognises with no second edit.
//
// # Why meaning rather than bytes
//
// The bytes are not this package's by the time they come back. IAM returns an
// inline policy URL-encoded, and a substrate may re-serialise a document it
// stored — reordering keys, changing whitespace, collapsing a one-element list to
// a scalar — all of which leave the policy identical and a byte comparison false.
// [samePolicyDocument] already exists for that reason on the trust-policy path
// and is reused here rather than reimplemented: the comparison a grant read-back
// needs is the comparison a trust-policy convergence check needed.
func levelFromStoredPolicy(stored string, render func(compute.AccessLevel) (string, error)) (compute.AccessLevel, error) {
	have, err := decodePolicyDocument(stored)
	if err != nil {
		return "", err
	}
	for _, level := range grantLevels() {
		want, rerr := render(level)
		if rerr != nil {
			// A level this resource refuses cannot be the level standing on it. A
			// plain bucket refuses AccessAdmin (see [objectActions]), and treating
			// that refusal as a failure here would make every bucket grant
			// unreadable.
			continue
		}
		same, cerr := samePolicyDocument(have, want)
		if cerr != nil {
			return "", fmt.Errorf("%w: compute/aws: comparing the standing policy against the one "+
				"%q renders: %w", compute.ErrFailed, level, cerr)
		}
		if same {
			return level, nil
		}
	}
	return "", fmt.Errorf("%w: compute/aws: a policy stands under a name this provider uses and is "+
		"not one it would render for any access level it defines (%q, %q, %q), so it has been "+
		"written or edited outside this platform. No level is reported: the choice would be between "+
		"under-reporting an access that exists and reporting one that does not, and a caller acting "+
		"on either is worse off than one told the read failed",
		compute.ErrFailed, compute.AccessRead, compute.AccessReadWrite, compute.AccessAdmin)
}

// decodePolicyDocument returns a policy document as JSON text, URL-encoded or
// not.
//
// IAM's GetRolePolicy returns the document URL-encoded, and its adapter returns
// what IAM gave it unaltered and deliberately — see [sdkIAM.GetRolePolicy], which
// says the decoding is the caller's. The in-memory substrate returns exactly what
// was stored. Rather than make a caller know which substrate it is talking to,
// the shape decides: a JSON object starts with '{' and its percent-encoding
// starts with "%7B", so one attempt and one fallback covers both with nothing to
// configure.
func decodePolicyDocument(raw string) (string, error) {
	var probe any
	if err := json.Unmarshal([]byte(raw), &probe); err == nil {
		return raw, nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("%w: compute/aws: a stored policy document is neither JSON nor "+
			"URL-encoded JSON: %w", compute.ErrFailed, err)
	}
	if err := json.Unmarshal([]byte(decoded), &probe); err != nil {
		return "", fmt.Errorf("%w: compute/aws: a stored policy document does not parse as JSON: %w",
			compute.ErrFailed, err)
	}
	return decoded, nil
}
