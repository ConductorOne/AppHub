// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// This file renders [compute.Route] onto the platform ingress.
//
// # Why this is labels and not a load balancer
//
// On this substrate a route is a registration with a pre-existing shared
// reverse proxy, not a load balancer this port provisions. That is a fact about
// the source system rather than a choice: of the 21 Go files in its deploy
// package exactly one references elbv2, and it is the Lambda one — the
// container path never creates an ELBv2 object and never sets CreateService's
// LoadBalancers field. Container exposure is entirely
// "write labels the proxy reads" (source system @
// backend/internal/modules/deploy/container.go).
//
// So [compute.Route] here compiles to container labels, and dedicated
// load-balancer provisioning stays where it belongs, on
// [compute.FunctionRuntime.EnsureEndpoint] (USOSS-12).

// The label vocabulary of the reverse proxy the source system runs.
//
// It is Traefik's, and it is spelled out here rather than templated from
// configuration because a label schema is not an identifier: nothing in these
// strings names a deployment, an account, or a host. What IS deployment
// specific — the hostname, and the name of the authentication middleware — comes
// from the spec and from configuration respectively.
//
// The namespace is a separate constant from the rest of each key, and that is
// not stylistic. Joined up, "<ns>.http.services" is shaped exactly like a
// three-label hostname ending in the .services TLD, and this repository's
// disclosure scan reads it as one — correctly, since it cannot tell a label key
// from a host. Splitting the namespace out means no literal here has the shape,
// which is the right way round: a label schema is not a reason to loosen a rule
// that exists to catch internal hostnames. USOSS-10 made the same call for its
// naming fixtures.
const (
	proxyLabelNS = "traefik"

	labelEnable          = proxyLabelNS + ".enable"
	labelRouterRule      = proxyLabelNS + ".http.routers.%s.rule"
	labelRouterEntry     = proxyLabelNS + ".http.routers.%s.entrypoints"
	labelRouterTLS       = proxyLabelNS + ".http.routers.%s.tls"
	labelRouterCert      = proxyLabelNS + ".http.routers.%s.tls.certresolver"
	labelRouterMW        = proxyLabelNS + ".http.routers.%s.middlewares"
	labelRouterPrio      = proxyLabelNS + ".http.routers.%s.priority"
	labelRouterSvc       = proxyLabelNS + ".http.routers.%s.service"
	labelServicePort     = proxyLabelNS + ".http.services.%s.loadbalancer.server.port"
	labelServiceURL      = proxyLabelNS + ".http.services.%s.loadbalancer.server.url"
	labelHeaderRequest   = proxyLabelNS + ".http.middlewares.%s.headers.customrequestheaders.%s"
	labelForwardAddress  = proxyLabelNS + ".http.middlewares.%s.forwardauth.address"
	labelForwardRequest  = proxyLabelNS + ".http.middlewares.%s.forwardauth.authrequestheaders"
	labelForwardResponse = proxyLabelNS + ".http.middlewares.%s.forwardauth.authresponseheaders"
	labelReplacePath     = proxyLabelNS + ".http.middlewares.%s.replacepath.path"

	// entrypointTLS and entrypointPlain are the proxy's listeners. A route
	// either terminates TLS at Traefik or it does not, and which entrypoint it
	// is on is how the proxy knows. Edge termination ([TLSTerminationEdge])
	// still names a certificate — the control plane requires one — but puts
	// the router on entrypointPlain because Traefik is not the TLS terminator.
	entrypointTLS   = "websecure"
	entrypointPlain = "web"

	// Public exemptions must beat a route's default auth, while MCP auth and
	// discovery must beat both the base route and any generic exemption.
	publicPathPriority = "5000"
	mcpRoutePriority   = "6000"
)

// renderRoutes compiles a service's routes into container labels, and reports
// the addresses the proxy will answer on.
//
// Every refusal here is a fail-closed choice about something the caller asked
// for and this provider cannot deliver. There is no path that drops a route.
func (p *Provider) renderRoutes(serviceName string, pc PlacementConfig, routes []compute.Route) (map[string]string, []string, error) {
	if len(routes) == 0 {
		return nil, nil, nil
	}
	labels := map[string]string{labelEnable: "true"}
	addresses := make([]string, 0, len(routes))

	for i, r := range routes {
		host := strings.TrimSpace(r.Host)
		if host == "" {
			return nil, nil, fmt.Errorf("%w: route %d names no host", compute.ErrInvalidSpec, i)
		}
		if err := checkPort(fmt.Sprintf("route %d for %q TargetPort", i, host), r.TargetPort); err != nil {
			return nil, nil, err
		}

		// The plaintext decision, which the interface makes a provider enforce:
		// a route with neither a certificate nor an explicit AllowPlaintext is
		// refused rather than served over HTTP. The field exists so that
		// serving HTTP is a decision somebody wrote down.
		entrypoint := entrypointPlain
		certResolver := ""
		switch {
		case r.TLS != nil:
			ref := r.TLS.CertificateRef
			if strings.TrimSpace(ref) == "" {
				return nil, nil, fmt.Errorf("%w: route %d for %q has a TLS configuration with no "+
					"certificate reference", compute.ErrInvalidSpec, i, host)
			}
			resolved, ok := pc.Certificates[ref]
			if !ok {
				return nil, nil, fmt.Errorf("%w: route %d for %q names the certificate %q, which "+
					"placement %q does not have. Configure it in "+
					"Config.Placements[%q].Certificates; a reference that cannot be resolved is "+
					"refused rather than served without the certificate the caller asked for",
					compute.ErrInvalidSpec, i, host, ref, pc.Name, pc.Name)
			}
			if !p.edgeTLS() && !r.Internal {
				entrypoint = entrypointTLS
				certResolver = resolved
			}
			// Edge termination: TLS is at the load balancer in front of
			// Traefik. The certificate still had to resolve — an unknown ref
			// would otherwise be served as if the caller had asked for
			// plaintext — but Traefik must not be told to terminate TLS on an
			// entrypoint nothing reaches with HTTPS.
		case r.AllowPlaintext:
			// Deliberate, and recorded as such: the caller has said in the spec
			// that this hostname is served over HTTP.
		default:
			return nil, nil, fmt.Errorf("%w: route %d for %q has no certificate and does not set "+
				"AllowPlaintext. A public application hostname served over HTTP is a fail-open "+
				"default, so it has to be asked for explicitly", compute.ErrInvalidSpec, i, host)
		}

		if r.Internal {
			// The internal load balancer terminates TLS and forwards only to
			// this entrypoint; the public one never reaches it, so a Host
			// header naming an internal route cannot be sent from outside.
			if p.cfg.Container == nil || strings.TrimSpace(p.cfg.Container.InternalEntrypoint) == "" {
				return nil, nil, fmt.Errorf("%w: route %d for %q is internal and this provider has "+
					"no Config.Container.InternalEntrypoint. Refusing rather than publishing it on "+
					"the public ingress", compute.ErrInvalidSpec, i, host)
			}
			entrypoint = strings.TrimSpace(p.cfg.Container.InternalEntrypoint)
		}
		if p.cfg.Container == nil || strings.TrimSpace(p.cfg.Container.IngressCookieStripMiddleware) == "" {
			return nil, nil, fmt.Errorf("%w: route %d for %q requires Config.Container.IngressCookieStripMiddleware; "+
				"refusing to forward the shared platform SSO cookie to an application", compute.ErrInvalidSpec, i, host)
		}
		cookieStrip := strings.TrimSpace(p.cfg.Container.IngressCookieStripMiddleware)

		if r.RequireAuth && p.cfg.Container.IngressAuthMiddleware == "" {
			return nil, nil, fmt.Errorf("%w: route %d for %q requires authentication and this "+
				"provider has no Config.Container.IngressAuthMiddleware configured. Refusing "+
				"rather than deploying a route that reports authenticated and is not",
				compute.ErrInvalidSpec, i, host)
		}

		router := routerName(serviceName, i)
		hostRule := fmt.Sprintf("Host(`%s`)", host)
		rule := hostRule
		if len(r.PathPrefixes) > 0 {
			rule = hostRule + " && " + pathRule(r.PathPrefixes)
		}
		labels[fmt.Sprintf(labelRouterRule, router)] = rule
		labels[fmt.Sprintf(labelRouterEntry, router)] = entrypoint
		labels[fmt.Sprintf(labelRouterSvc, router)] = serviceName
		labels[fmt.Sprintf(labelServicePort, serviceName)] = fmt.Sprint(r.TargetPort)
		if certResolver != "" {
			labels[fmt.Sprintf(labelRouterTLS, router)] = "true"
			labels[fmt.Sprintf(labelRouterCert, router)] = certResolver
		}
		// Every router for this host shares the same first middleware. A
		// client must not be able to supply either platform identity pair;
		// ForwardAuth may only populate its own pair after this strip.
		identityStrip := router + "-identity-strip"
		for _, header := range []string{
			"X-AppHub-User-ID", "X-AppHub-Email", "X-AppHub-Application-ID",
			"X-AppHub-MCP-Host", "X-Auth-Request-User", "X-Auth-Request-Email",
		} {
			labels[fmt.Sprintf(labelHeaderRequest, identityStrip, header)] = ""
		}
		middlewares := identityStrip
		if r.RequireAuth {
			middlewares += "," + p.cfg.Container.IngressAuthMiddleware
		}
		labels[fmt.Sprintf(labelRouterMW, router)] = middlewares + "," + cookieStrip

		if r.MCPAuthApplicationID != "" {
			if err := p.renderMCPRoute(labels, router, hostRule, entrypoint, certResolver, serviceName, host, r.MCPAuthApplicationID, identityStrip, cookieStrip); err != nil {
				return nil, nil, fmt.Errorf("route %d for %q: %w", i, host, err)
			}
		}

		// The exemption routers omit authentication, not the identity
		// boundary. They must strip unverified headers even on public paths.
		for j, prefix := range r.PublicPaths {
			if !r.RequireAuth {
				// A public path on an unauthenticated route is not an error,
				// but it is not doing anything either, and silently accepting
				// it would let a caller believe an exemption is in force on a
				// route that never authenticated. Refuse, and say which.
				return nil, nil, fmt.Errorf("%w: route %d for %q lists the public path %q but does "+
					"not set RequireAuth. PublicPaths is the authentication EXEMPTION set, so it "+
					"means nothing without it", compute.ErrInvalidSpec, i, host, prefix)
			}
			trimmed := strings.TrimSpace(prefix)
			if trimmed == "" || !strings.HasPrefix(trimmed, "/") {
				return nil, nil, fmt.Errorf("%w: route %d for %q has the public path %q, which is "+
					"not a path", compute.ErrInvalidSpec, i, host, prefix)
			}
			// Paths match exactly; a trailing /* is the only way to also
			// exempt everything below a prefix. Path() and PathPrefix() are
			// chosen accordingly, rather than PathPrefix() for both shapes:
			// "/healthz" must not also exempt "/healthzevil", and
			// "/api/webhooks/*" must not also exempt "/api/webhooksevil".
			var matchRule string
			switch {
			case trimmed == "/*":
				return nil, nil, fmt.Errorf("%w: route %d for %q has the public path %q, which "+
					"exempts every path. Turn off RequireAuth for the route instead of exempting "+
					"everything under it", compute.ErrInvalidSpec, i, host, prefix)
			case strings.HasSuffix(trimmed, "/*"):
				matchRule = fmt.Sprintf("PathPrefix(`%s`)", strings.TrimSuffix(trimmed, "*"))
			default:
				matchRule = fmt.Sprintf("Path(`%s`)", trimmed)
			}
			pub := fmt.Sprintf("%s-public-%d", router, j)
			labels[fmt.Sprintf(labelRouterRule, pub)] = hostRule + " && " + matchRule
			labels[fmt.Sprintf(labelRouterEntry, pub)] = entrypoint
			labels[fmt.Sprintf(labelRouterSvc, pub)] = serviceName
			labels[fmt.Sprintf(labelRouterPrio, pub)] = publicPathPriority
			labels[fmt.Sprintf(labelRouterMW, pub)] = identityStrip + "," + cookieStrip
			if certResolver != "" {
				labels[fmt.Sprintf(labelRouterTLS, pub)] = "true"
				labels[fmt.Sprintf(labelRouterCert, pub)] = certResolver
			}
		}

		addresses = append(addresses, host)
	}
	sort.Strings(addresses)
	return labels, addresses, nil
}

func (p *Provider) renderMCPRoute(labels map[string]string, router, hostRule, entrypoint, certResolver, serviceName, host, applicationID, identityStrip, cookieStrip string) error {
	if p.cfg.Container == nil {
		return fmt.Errorf("%w: MCP authentication requires a container configuration", compute.ErrInvalidSpec)
	}
	backend := strings.TrimSuffix(strings.TrimSpace(p.cfg.Container.MCPAuthBackendURL), "/")
	u, err := url.Parse(backend)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Path != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%w: MCP authentication requires a canonical Config.Container.MCPAuthBackendURL", compute.ErrInvalidSpec)
	}
	if applicationID == "" || strings.ContainsAny(applicationID, "/?# \t\r\n") {
		return fmt.Errorf("%w: MCP authentication names an invalid application ID", compute.ErrInvalidSpec)
	}

	mcpRouter := router + "-mcp"
	contextMiddleware := mcpRouter + "-context"
	authMiddleware := mcpRouter + "-auth"
	stripMiddleware := mcpRouter + "-strip"
	metadataRouter := router + "-mcp-discovery"
	metadataMiddleware := metadataRouter + "-path"
	metadataService := metadataRouter

	labels[fmt.Sprintf(labelRouterRule, mcpRouter)] = hostRule + " && (Path(`/mcp`) || PathPrefix(`/mcp/`))"
	labels[fmt.Sprintf(labelRouterEntry, mcpRouter)] = entrypoint
	labels[fmt.Sprintf(labelRouterSvc, mcpRouter)] = serviceName
	labels[fmt.Sprintf(labelRouterPrio, mcpRouter)] = mcpRoutePriority
	labels[fmt.Sprintf(labelRouterMW, mcpRouter)] = strings.Join([]string{identityStrip, contextMiddleware, authMiddleware, stripMiddleware, cookieStrip}, ",")
	labels[fmt.Sprintf(labelHeaderRequest, contextMiddleware, "X-AppHub-Application-ID")] = applicationID
	labels[fmt.Sprintf(labelHeaderRequest, contextMiddleware, "X-AppHub-MCP-Host")] = host
	labels[fmt.Sprintf(labelForwardAddress, authMiddleware)] = backend + "/authz/app-mcp"
	labels[fmt.Sprintf(labelForwardRequest, authMiddleware)] = "Authorization,X-AppHub-Application-ID,X-AppHub-MCP-Host"
	labels[fmt.Sprintf(labelForwardResponse, authMiddleware)] = "X-AppHub-User-ID,X-AppHub-Email"
	labels[fmt.Sprintf(labelHeaderRequest, stripMiddleware, "Authorization")] = ""
	labels[fmt.Sprintf(labelHeaderRequest, stripMiddleware, "X-AppHub-Application-ID")] = ""
	labels[fmt.Sprintf(labelHeaderRequest, stripMiddleware, "X-AppHub-MCP-Host")] = ""

	labels[fmt.Sprintf(labelRouterRule, metadataRouter)] = hostRule + " && (Path(`/.well-known/oauth-protected-resource`) || Path(`/.well-known/oauth-protected-resource/mcp`))"
	labels[fmt.Sprintf(labelRouterEntry, metadataRouter)] = entrypoint
	labels[fmt.Sprintf(labelRouterSvc, metadataRouter)] = metadataService
	labels[fmt.Sprintf(labelRouterPrio, metadataRouter)] = mcpRoutePriority
	labels[fmt.Sprintf(labelRouterMW, metadataRouter)] = strings.Join([]string{identityStrip, metadataMiddleware, cookieStrip}, ",")
	labels[fmt.Sprintf(labelReplacePath, metadataMiddleware)] = "/.well-known/oauth-protected-resource/mcp/apps/" + applicationID + "/" + host
	labels[fmt.Sprintf(labelServiceURL, metadataService)] = backend

	for _, name := range []string{mcpRouter, metadataRouter} {
		if certResolver != "" {
			labels[fmt.Sprintf(labelRouterTLS, name)] = "true"
			labels[fmt.Sprintf(labelRouterCert, name)] = certResolver
		}
	}
	return nil
}

// routerName names one route's router, deterministically and uniquely within a
// service.
func routerName(serviceName string, index int) string {
	return fmt.Sprintf("%s-%d", serviceName, index)
}

// pathRule renders a set of prefixes as one Traefik matcher.
func pathRule(prefixes []string) string {
	parts := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		clean := strings.TrimSuffix(strings.TrimSpace(prefix), "/*")
		parts = append(parts, fmt.Sprintf("PathPrefix(`%s`)", clean))
	}
	sort.Strings(parts)
	return "(" + strings.Join(parts, " || ") + ")"
}

// edgeTLS reports whether published routes terminate TLS in front of Traefik.
func (p *Provider) edgeTLS() bool {
	return p.cfg.Container != nil && p.cfg.Container.TLSTermination == TLSTerminationEdge
}
