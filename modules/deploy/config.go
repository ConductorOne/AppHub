// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"fmt"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// DefaultWaitTimeout bounds how long a deploy waits for a workload to become
// ready before giving up.
//
// This is a duration, not an identifier: it names nothing about any deployment
// and a wrong value costs a retry rather than a disclosure, so unlike every
// other field of [Config] it has a default. The code this was ported from
// polled sixty times at two seconds (container.go:1092-1093 and :1130).
const DefaultWaitTimeout = 2 * time.Minute

// Config is the deployment-wide configuration this module cannot derive.
//
// Every identifier here was a compiled-in constant in the code this was ported
// from, and all of them named ConductorOne's own infrastructure. The rule
// adopted for this repository is that such a value becomes configuration with
// no default and is refused when absent, so that an adopter's deployment cannot
// silently inherit ours and ours cannot be read out of a public repository.
//
// "Refused when absent" is [Config.Validate] for the fields every deploy needs,
// and a refusal at the point of use for [Config.RouteDomain], which only an
// application that publishes a route needs. Both are refusals; neither is a
// default.
type Config struct {
	// WorkloadIdentityMode selects platform attestation or only the provider's
	// native workload identity. Empty retains platform behavior.
	WorkloadIdentityMode string

	// ResourcePrefix is prepended to every name this module asks a provider to
	// create, so one substrate can host several deployments without their
	// resources colliding.
	//
	// A source audit found ten hard-coded app-prefix sites in its deploy package
	// alone -- bucket.go:42 and :575, container.go:247, :265, :266, :267,
	// :272, :429, :509 and :1393. It is required, and it is
	// validated rather than merely non-empty: a prefix with a character a
	// substrate's naming rules reject turns into a provider refusal on every
	// deploy, which is a bad way to learn about a typo.
	ResourcePrefix string

	// RouteDomain is the DNS suffix published routes live under: an application
	// whose route hostname is "reports" is reachable at
	// "reports." + RouteDomain.
	//
	// The source composed this from a compiled-in internal domain plus an
	// environment segment read from the process environment. Four sites, by
	// `grep -n secsvcs container.go`: :1303, :1313, :1355 and :1360. (The brief
	// this port was written from named :1327, which is not one of them.) Both
	// are gone; an operator
	// supplies the whole suffix, environment segment included, and an
	// application asking for a route when this is empty is refused rather than
	// published somewhere guessed. There is deliberately no default: a default
	// here is a hostname somebody else owns.
	RouteDomain string

	// RouteCertificate names the TLS certificate published routes are served
	// with, as the compute provider knows it.
	//
	// Required for any route that does not set AllowPlaintext, and there is no
	// default: a default certificate reference is one that either does not
	// exist, in which case every deploy fails at the last step, or belongs to
	// somebody else's domain. A route with neither a certificate nor an
	// explicit AllowPlaintext is refused, which is the fail-closed reading —
	// the source published every route on its plaintext entrypoint with no field
	// to say otherwise (container.go:1304, :1323, :1356 and :1370, all "web").
	RouteCertificate string

	// InternalRouteDomain and InternalRouteCertificate are RouteDomain and
	// RouteCertificate for internal routes ([Route.Internal]), which the
	// platform's internal ingress serves inside the network only. Both have
	// no default for the same reasons; an internal route with no domain is
	// refused rather than published under the public one.
	InternalRouteDomain      string
	InternalRouteCertificate string

	// AllowedSourceHosts are the hosts an application's source may be fetched
	// from. Required and non-empty: an empty allowlist is the fail-closed state
	// and this module refuses to run with one rather than treating "unset" as
	// "anywhere".
	//
	// The source allowed exactly one host, compiled in (build.go:96-98). That
	// is a deployment's policy, not this module's.
	AllowedSourceHosts []string

	// SecretStoreName is the name the credential layer uses for this compute
	// provider's secret store, as it appears in
	// [github.com/conductorone/apphub/credentials.SecretRef.Store].
	//
	// It exists because the two sides name stores in different vocabularies —
	// "aws-ssm" on one, the provider name on the other — and the deploy layer
	// is the only party that sees both. It is optional, and unset is
	// fail-closed rather than permissive: a credential reference that names a
	// store is then refused, because nothing establishes that the store it
	// names is the one this provider backs. A reference naming no store is the
	// deployment's default store and is accepted either way.
	SecretStoreName string

	// Placement selects where resources are created, for a provider configured
	// with more than one. The zero value means the provider's default
	// placement, which is what the interface documents; a provider with no
	// default refuses, and that refusal is the operator's answer.
	Placement compute.Placement
	// PostgresRootCertPath is the operator-mounted RDS CA bundle used to verify
	// Aurora's hostname when installing requested PostgreSQL extensions. It is
	// required only for applications requesting extensions.
	PostgresRootCertPath string

	// WaitTimeout bounds waiting for a workload to become ready. Zero means
	// [DefaultWaitTimeout].
	WaitTimeout time.Duration
}

// Validate reports whether the configuration is usable, naming everything that
// is not.
//
// It reports every problem rather than the first, because an operator
// configuring this for the first time would otherwise learn about the fields
// one restart at a time.
func (c Config) Validate() error {
	var problems []string
	switch c.WorkloadIdentityMode {
	case "", "platform", "native":
	default:
		problems = append(problems, "WorkloadIdentityMode must be platform or native")
	}
	if strings.TrimSpace(c.ResourcePrefix) == "" {
		problems = append(problems, "ResourcePrefix is required: it is the namespace this "+
			"deployment's resources are created under and there is no default")
	} else if err := validateResourcePrefix(c.ResourcePrefix); err != nil {
		problems = append(problems, err.Error())
	}
	if len(c.AllowedSourceHosts) == 0 {
		problems = append(problems, "AllowedSourceHosts is required: an empty allowlist is the "+
			"fail-closed state, so this module refuses to start rather than fetch from anywhere")
	}
	for i, host := range c.AllowedSourceHosts {
		if h := strings.TrimSpace(host); h == "" || h != strings.ToLower(h) {
			problems = append(problems, fmt.Sprintf("AllowedSourceHosts[%d] %q is not a lowercase "+
				"host name; hosts are compared after lowercasing and a mixed-case entry would "+
				"never match", i, host))
		}
	}
	if c.WaitTimeout < 0 {
		problems = append(problems, "WaitTimeout is negative")
	}
	if len(problems) > 0 {
		return fmt.Errorf("deploy configuration is incomplete: %s", strings.Join(problems, "; "))
	}
	return nil
}

// waitTimeout is the effective timeout.
func (c Config) waitTimeout() time.Duration {
	if c.WaitTimeout == 0 {
		return DefaultWaitTimeout
	}
	return c.WaitTimeout
}

// routeDomain returns the configured DNS suffix, or an error naming what an
// operator has to set.
//
// Separate from [Config.Validate] because a deployment whose applications
// publish no routes needs no domain, and requiring one would make an operator
// invent a value — which is how a placeholder domain ends up in a route.
func (c Config) routeDomain() (string, error) {
	return checkDomain("RouteDomain", c.RouteDomain)
}

// internalRouteDomain is routeDomain for internal routes.
func (c Config) internalRouteDomain() (string, error) {
	return checkDomain("InternalRouteDomain", c.InternalRouteDomain)
}

func checkDomain(field, value string) (string, error) {
	domain := strings.TrimSpace(strings.ToLower(value))
	if domain == "" {
		return "", fmt.Errorf("%w: this application publishes a route, but no %s is "+
			"configured; set the DNS suffix routes are published under rather than letting one "+
			"be guessed", ErrNotConfigured, field)
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", fmt.Errorf("%w: %s %q has a leading or trailing dot", ErrInvalidApplication, field, domain)
	}
	return domain, nil
}
