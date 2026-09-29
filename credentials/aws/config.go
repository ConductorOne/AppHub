// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ProviderID is the registry key for this provider.
//
// It names what the provider is rather than what it vends for. The internal
// implementation registered as "claude", which is a model family and not a
// credential source: the same code vends a Bedrock bearer token and an IAM user,
// and a second AWS-native provider would have had nowhere to go.
const ProviderID = "aws-bedrock"

// Errors this package returns for a configuration it will not act on.
//
// Each is a sentinel rather than a bare error string because an operator wiring
// a deployment needs to distinguish "you did not configure this" from "you
// configured it wrongly" without reading prose.
var (
	// ErrNotConfigured means neither credential type was configured, so the
	// provider would be able to vend nothing at all.
	ErrNotConfigured = errors.New("aws: neither dynamic nor static credentials are configured")

	// ErrMissingClient means a credential type is configured and the AWS client
	// it needs was not supplied. Registering such a provider would defer the
	// failure to the first vend.
	ErrMissingClient = errors.New("aws: a configured credential type has no AWS client")

	// ErrTypeNotConfigured means a vend asked for a credential type this
	// deployment did not configure.
	ErrTypeNotConfigured = errors.New("aws: that credential type is not configured on this provider")

	// ErrRequesterRequired means a vend did not say who is asking.
	//
	// It exists because of a mutation that survived: deleting the explicit check in
	// createDynamic still refused the request, because prefixedName rejects the
	// empty session name -- but it came back as ErrNameNotUsable, so a caller
	// testing for that sentinel would read "nobody said who is asking" as "the name
	// you chose is unusable". The suite asserted that an error came back and not
	// which one, so one bit of coverage was missing. A refusal preserved with its
	// reason changed is not an equivalent refusal.
	ErrRequesterRequired = errors.New("aws: the vend did not say who is asking")

	// The three ways a web identity token can fail at STS. All three are wrapped
	// with credentials.ErrTransient; see the comment on Provider.assume for why a
	// rejected token is retryable FOR THIS PROVIDER and would not be for a caller
	// that reuses one.
	//
	// They are separate sentinels because they are separate diagnoses. An operator
	// reading "the token aged out before STS read it" looks at latency; one reading
	// "STS could not validate it" looks at the trust policy and the signing key;
	// one reading "the identity provider rejected the claim" looks at the provider.
	// Collapsing them would make the branch a caller lands in unobservable.
	//
	// Which branch a caller lands in is decided by the predicates, which are
	// disjoint over the errors STS returns -- not by the order the cases are written
	// in, as an earlier version of this comment claimed. See
	// TestTheTypedErrorPredicatesAreDisjoint.
	ErrWebIdentityTokenExpired  = errors.New("aws: the web identity token expired before STS read it")
	ErrWebIdentityTokenInvalid  = errors.New("aws: STS could not validate the web identity token")
	ErrWebIdentityClaimRejected = errors.New("aws: the identity provider rejected the claim")

	// ErrLimit means the request cannot be honored as asked, and the limit is
	// named in the message. It is never rounded into range: see the note on
	// docs/decisions/ about refusing at the spec rather than approximating.
	ErrLimit = errors.New("aws: the request exceeds a limit AWS imposes")
)

// Config is what an adopter must supply. Every field is required and none has a
// default.
//
// The two credential types are separately optional and separately configured. A
// nil DynamicConfig means this deployment does not vend dynamic credentials at
// all, which is reported through [Provider.Capabilities] and refused at vend
// time with ErrTypeNotConfigured. That is deliberately not the same thing as a
// zero-valued struct: "not offered" and "offered with everything unset" are
// different states, and only one of them is a misconfiguration.
type Config struct {
	// Region is the AWS region whose STS and IAM endpoints are used. Required.
	//
	// The internal implementation defaulted this to a region name compiled into
	// the source (claude.go:66-69, claude.go:297-300). A default region is a
	// silent choice about where a credential is minted and, for the dynamic path,
	// which STS endpoint signs the token -- so it is refused rather than guessed.
	Region string

	// Dynamic configures Bedrock bearer tokens. Nil means they are not offered.
	Dynamic *DynamicConfig

	// Static configures IAM-user credentials. Nil means they are not offered.
	Static *StaticConfig
}

// DynamicConfig is the configuration for a Bedrock bearer token.
type DynamicConfig struct {
	// RoleARN is the IAM role the token is minted from. Required.
	//
	// It is operator configuration and not request metadata, which is a
	// deliberate narrowing. The internal implementation read role_arn out of the
	// per-request metadata bag (claude.go:96), so the caller chose which role the
	// platform assumed; any role whose trust policy admits the platform was
	// reachable from a vend request. Here the operator names the role once.
	//
	// The source also treated it as optional and presigned with the platform's
	// own ambient credentials when it was absent (claude.go:96-152 skips the
	// whole assume-role block). The resulting token authenticates as the platform
	// itself. That is the single most consequential fail-open in the file and the
	// reason this field has no zero value that means "skip".
	RoleARN string

	// SessionNamePrefix prefixes the STS RoleSessionName, which is the most
	// visible attribution in a CloudTrail row. Required.
	//
	// The internal implementation prefixed sessions with two letters standing for
	// the internal project name (claude.go:102). An operator naming their own
	// deployment is the same facility without the disclosure.
	SessionNamePrefix string
}

// StaticConfig is the configuration for an IAM-user credential.
type StaticConfig struct {
	// UserPath is the IAM path new users are created under, e.g. "/example/".
	// Required, and must be a valid IAM path.
	//
	// The internal implementation compiled in a path naming the internal project
	// (claude.go:26). The path is how an operator finds and scopes these users in
	// their own account, so it is theirs to choose.
	UserPath string

	// UserNamePrefix prefixes created IAM user names. Required.
	UserNamePrefix string

	// PolicyARN is the managed policy attached to a created user. Required.
	//
	// The internal implementation compiled in an AWS managed policy granting
	// broad Bedrock access (claude.go:28, claude.go:243-249). Which grant a
	// vended credential carries is the operator's least-privilege decision, and a
	// compiled-in answer means every adopter inherits ours.
	PolicyARN string

	// PermissionsBoundaryARN bounds everything the created user can ever be
	// granted. Required.
	//
	// The internal implementation read this from optional request metadata
	// (claude.go:236-238), so a vend that omitted it created an unbounded user.
	// It is required here: the boundary is the only thing that limits the damage
	// if PolicyARN is wider than its author believed, and a security control that
	// is skipped by leaving a field blank is not a control.
	PermissionsBoundaryARN string
}

// Grammar and limits AWS itself imposes. Each is a fact about the service, so
// each is a constant rather than a knob.
const (
	// maxRoleSessionName is the STS RoleSessionName ceiling.
	maxRoleSessionName = 64
	// maxIAMUserName is the IAM user-name ceiling.
	maxIAMUserName = 64
	// maxIAMPath is the IAM path ceiling.
	maxIAMPath = 512
	// minPrefixHeadroom is how many characters a prefix must leave for the name
	// it prefixes. Without it a Config could validate and then refuse every
	// possible request, which is worse than refusing at construction.
	minPrefixHeadroom = 8
)

var (
	// iamNameRunes is IAM's grammar for a user name and STS's for a role session
	// name: they are the same set.
	iamNameRunes = regexp.MustCompile(`^[\w+=,.@-]+$`)

	// iamPath is IAM's path grammar: "/" alone, or printable ASCII between two
	// slashes. AWS states it as (/)|(/[\u0021-\u007E]+/), and the inner class
	// includes "/" so that nested paths are legal.
	iamPath = regexp.MustCompile(`^/(?:[!-~]+/)?$`)

	// policyARN is the shape AttachUserPolicy and PermissionsBoundary accept: an
	// IAM policy in the AWS partition (a managed policy) or in an account
	// (a customer-managed one).
	//
	// It matches the shape and never a value. Writing a known account into this
	// pattern would publish that account in the pattern, which is the disclosure
	// the pattern exists to bound.
	policyARN = regexp.MustCompile(`^arn:aws[a-z0-9-]*:iam::(?:aws|[0-9]{12}):policy/[!-~]+$`)

	// roleARN is the shape AssumeRole and AssumeRoleWithWebIdentity accept.
	roleARN = regexp.MustCompile(`^arn:aws[a-z0-9-]*:iam::[0-9]{12}:role/[!-~]+$`)

	// regionName is deliberately not AWS's region grammar, which grows.
	//
	// What it has to exclude is anything that could turn a region into a
	// different host: the region is interpolated into an endpoint by the SDK, so
	// a dot or a slash in it is an endpoint substitution. Letters, digits and
	// hyphens cannot be.
	regionName = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// Validate reports whether the configuration can be acted on.
//
// It is exported because a composition root should be able to reject a
// deployment's configuration before it builds anything, and because a
// configuration error is the one error in this package a human is expected to
// read and fix.
func (c Config) Validate() error {
	if err := requireMatch("Region", c.Region, regionName, 0); err != nil {
		return err
	}
	if c.Dynamic == nil && c.Static == nil {
		return ErrNotConfigured
	}
	if c.Dynamic != nil {
		if err := c.Dynamic.validate(); err != nil {
			return err
		}
	}
	if c.Static != nil {
		if err := c.Static.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (d DynamicConfig) validate() error {
	if err := requireMatch("Dynamic.RoleARN", d.RoleARN, roleARN, 0); err != nil {
		return err
	}
	return requireMatch("Dynamic.SessionNamePrefix", d.SessionNamePrefix, iamNameRunes,
		maxRoleSessionName-minPrefixHeadroom)
}

func (s StaticConfig) validate() error {
	if err := requireMatch("Static.UserPath", s.UserPath, iamPath, maxIAMPath); err != nil {
		return err
	}
	if err := requireMatch("Static.UserNamePrefix", s.UserNamePrefix, iamNameRunes,
		maxIAMUserName-minPrefixHeadroom); err != nil {
		return err
	}
	if err := requireMatch("Static.PolicyARN", s.PolicyARN, policyARN, 0); err != nil {
		return err
	}
	return requireMatch("Static.PermissionsBoundaryARN", s.PermissionsBoundaryARN, policyARN, 0)
}

// requireMatch is the whole of configuration validation, and it takes the field
// name as a constant from the caller.
//
// The rejected value is never in the message. A configuration value is not
// credential material by intent, but it is a value this process did not author,
// and this package holds the same invariant as its siblings: no error it returns
// contains text that did not come from a constant here, a count, or a Go type
// name. Naming the field and the limit is what an operator needs; echoing what
// they typed is how a mistyped secret ends up in a log.
func requireMatch(field, value string, pattern *regexp.Regexp, maxLen int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("aws: %s is required and has no default", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("aws: %s has leading or trailing whitespace", field)
	}
	if maxLen > 0 && len(value) > maxLen {
		return fmt.Errorf("aws: %s is %d bytes (max %d): %w", field, len(value), maxLen, ErrLimit)
	}
	if !pattern.MatchString(value) {
		return fmt.Errorf("aws: %s is not in the form AWS accepts", field)
	}
	return nil
}
