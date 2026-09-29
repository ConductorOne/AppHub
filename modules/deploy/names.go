// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// resourcePrefixGrammar is what a prefix may contain. Deliberately narrower
// than any one substrate's rules: a prefix appears in every physical name a
// provider derives, and the intersection of what ECR, IAM, S3, RDS and a
// Kubernetes object name will each accept is roughly this.
var resourcePrefixGrammar = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// applicationIDGrammar is what an application identifier may contain, and it is
// enforced rather than sanitised. See [resourceName].
var applicationIDGrammar = regexp.MustCompile(`^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*$`)

// maxResourceName is the longest logical name this module will hand a provider.
//
// It is the smallest limit the providers in this repository advertise
// (compute/fake allows 63), and it is checked here so that "the name is too
// long" is a refusal an operator gets once, at the top, naming the application
// — rather than a provider refusal partway through a deploy that has already
// created three resources.
const maxResourceName = 63

// validateResourcePrefix reports whether a prefix is usable.
func validateResourcePrefix(prefix string) error {
	if !resourcePrefixGrammar.MatchString(prefix) {
		return fmt.Errorf("ResourcePrefix %q must be lowercase alphanumeric words separated by "+
			"single hyphens; every physical name a provider derives contains it", prefix)
	}
	if len(prefix) > maxResourceName/2 {
		return fmt.Errorf("ResourcePrefix %q is %d characters, which leaves too little of the "+
			"%d-character name budget for the application", prefix, len(prefix), maxResourceName)
	}
	return nil
}

// resourceName is the logical name every resource for an application is created
// under: the configured prefix, then the application's identifier.
//
// # Why the identifier and not the name
//
// The code this was ported from derived every resource name from the
// application's *display name*, folded through a sanitiser that mapped every
// character outside [A-Za-z0-9_-] to a hyphen (lambda.go:844-858). Two
// consequences, both delivered behaviour rather than theory:
//
//   - the fold is many-to-one, so applications called "my app" and "my-app"
//     were handed the same ECS service, the same IAM role, the same security
//     group and the same bucket. Reported as a source defect; not reproduced
//     here.
//   - the display name is mutable, so renaming an application moved every
//     resource name and orphaned everything the previous deploy had created.
//
// Deriving from the identifier fixes both at once: it is stable across a
// rename, and the mapping is the identity function, so it is injective without
// a digest to reconcile. The display name still travels — as a label, which is
// where a human-readable string belongs and where no resource identity depends
// on it.
//
// # Why the identifier is checked rather than sanitised
//
// A sanitiser is what made the fold many-to-one. Refusing an identifier this
// module cannot use without folding keeps the mapping injective by
// construction, and an operator learns about it when the application is created
// rather than when two applications quietly share a bucket.
func resourceName(prefix string, app *Application) (string, error) {
	if !applicationIDGrammar.MatchString(app.ID) {
		return "", fmt.Errorf("%w: application identifier %q must be alphanumeric words "+
			"separated by single '.', '_' or '-' characters; it is used verbatim in every "+
			"resource name, and folding it to fit would make two applications share one set "+
			"of resources", ErrInvalidApplication, app.ID)
	}
	name := prefix + "-" + app.ID
	if len(name) > maxResourceName {
		return "", fmt.Errorf("%w: the resource name %q for application %q is %d characters and "+
			"no provider here accepts more than %d", ErrInvalidApplication, name, app.ID,
			len(name), maxResourceName)
	}
	return name, nil
}

// ValidateSourceURL canonicalises an application's source location and refuses
// anything that is not an HTTPS URL on an allowed host.
//
// It is a port of the source's ValidateRepoURL (build.go:104-150) with one
// change: the host allowlist arrives as a parameter instead of being compiled
// in, because which code hosts a deployment trusts is that deployment's policy.
// An empty allowlist refuses everything, which is the fail-closed reading of
// "unset" and the reason [Config.Validate] requires the field.
//
// What it is defending against, in the source's own words: SSRF, command
// injection through a git transport, and handing credentials to a server
// somebody else controls. Each check below closes one of those, and the tests
// name which.
func ValidateSourceURL(raw string, allowedHosts []string) (string, error) {
	// Before parsing: a control character in the input is a request to confuse
	// something downstream that splits on lines, and no legitimate URL has one.
	if strings.ContainsAny(raw, "\r\n\x00") {
		return "", fmt.Errorf("%w: it contains a control character", ErrSourceRefused)
	}
	lower := strings.ToLower(raw)
	for _, encoded := range []string{"%0a", "%0d", "%00"} {
		if strings.Contains(lower, encoded) {
			return "", fmt.Errorf("%w: it contains a percent-encoded control character",
				ErrSourceRefused)
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		// The parse error can echo the input, and the input is attacker-shaped.
		// Say what was wrong, not what was sent.
		return "", fmt.Errorf("%w: it is not a well-formed URL", ErrSourceRefused)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("%w: only https is accepted, and this one is %q",
			ErrSourceRefused, u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("%w: it has no host", ErrSourceRefused)
	}
	if ip := net.ParseIP(host); ip != nil {
		return "", fmt.Errorf("%w: it names an address rather than a host, which is how an "+
			"allowlist of host names gets bypassed", ErrSourceRefused)
	}
	if u.User != nil {
		// Never render u.User: it is where a token would be.
		return "", fmt.Errorf("%w: it carries embedded credentials", ErrSourceRefused)
	}
	if port := u.Port(); port != "" && port != "443" {
		return "", fmt.Errorf("%w: it names port %s, and only the default HTTPS port is accepted",
			ErrSourceRefused, port)
	}
	var allowed bool
	for _, h := range allowedHosts {
		if host == strings.ToLower(strings.TrimSpace(h)) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("%w: host %q is not in the configured allowlist", ErrSourceRefused, host)
	}

	// Canonicalise. url.Parse lowercases the scheme but not the host, and a
	// trailing slash reaches a version-control client as part of the path.
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}
