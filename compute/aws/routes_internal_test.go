// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"testing"

	"github.com/conductorone/apphub/compute"
)

func TestRenderRoutesPutsTLSOnWebsecureByDefault(t *testing.T) {
	t.Parallel()
	p := &Provider{cfg: Config{Container: &ContainerConfig{IngressCookieStripMiddleware: "strip-cookie@file"}}}
	pc := PlacementConfig{Name: "default", Certificates: map[string]string{"platform": "platform"}}
	labels, _, err := p.renderRoutes("billing", pc, []compute.Route{{
		Host:       "reports.apps.example.test",
		TargetPort: 8080,
		TLS:        &compute.TLSConfig{CertificateRef: "platform"},
	}})
	if err != nil {
		t.Fatalf("renderRoutes: %v", err)
	}
	if got := labels["traefik.http.routers.billing-0.entrypoints"]; got != entrypointTLS {
		t.Errorf("entrypoints = %q, want %q", got, entrypointTLS)
	}
	if got := labels["traefik.http.routers.billing-0.tls"]; got != "true" {
		t.Errorf("tls = %q, want true", got)
	}
	if got := labels["traefik.http.routers.billing-0.tls.certresolver"]; got != "platform" {
		t.Errorf("certresolver = %q, want platform", got)
	}
}

func TestRenderRoutesPutsTLSOnWebWhenTerminationIsEdge(t *testing.T) {
	t.Parallel()
	p := &Provider{cfg: Config{Container: &ContainerConfig{TLSTermination: TLSTerminationEdge, IngressCookieStripMiddleware: "strip-cookie@file"}}}
	pc := PlacementConfig{Name: "default", Certificates: map[string]string{"platform": "platform"}}
	labels, addrs, err := p.renderRoutes("billing", pc, []compute.Route{{
		Host:       "reports.apps.example.test",
		TargetPort: 8080,
		TLS:        &compute.TLSConfig{CertificateRef: "platform"},
	}})
	if err != nil {
		t.Fatalf("renderRoutes: %v", err)
	}
	if got := labels["traefik.http.routers.billing-0.entrypoints"]; got != entrypointPlain {
		t.Errorf("entrypoints = %q, want %q (Traefik sees HTTP from the ALB)", got, entrypointPlain)
	}
	if _, ok := labels["traefik.http.routers.billing-0.tls"]; ok {
		t.Error("edge termination must not set tls=true; Traefik is not the TLS terminator")
	}
	if _, ok := labels["traefik.http.routers.billing-0.tls.certresolver"]; ok {
		t.Error("edge termination must not set tls.certresolver")
	}
	if len(addrs) != 1 || addrs[0] != "reports.apps.example.test" {
		t.Errorf("addresses = %v, want the published host", addrs)
	}
}

func TestRenderRoutesStillRefusesAnUnresolvableCertificateWhenTerminationIsEdge(t *testing.T) {
	t.Parallel()
	p := &Provider{cfg: Config{Container: &ContainerConfig{TLSTermination: TLSTerminationEdge}}}
	pc := PlacementConfig{Name: "default", Certificates: map[string]string{"platform": "platform"}}
	_, _, err := p.renderRoutes("billing", pc, []compute.Route{{
		Host:       "reports.apps.example.test",
		TargetPort: 8080,
		TLS:        &compute.TLSConfig{CertificateRef: "no-such-certificate"},
	}})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("unresolvable certificate under edge termination returned %v, want ErrInvalidSpec", err)
	}
}

func TestAnInternalRouteIsServedOnlyOnTheInternalEntrypoint(t *testing.T) {
	t.Parallel()
	p := &Provider{cfg: Config{Container: &ContainerConfig{InternalEntrypoint: "internal", IngressAuthMiddleware: "auth@file", IngressCookieStripMiddleware: "strip-cookie@file"}}}
	pc := PlacementConfig{Name: "default", Certificates: map[string]string{"internal": "internal"}}
	labels, addrs, err := p.renderRoutes("billing", pc, []compute.Route{{
		Host:        "reports.internal.apps.example.test",
		TargetPort:  8080,
		TLS:         &compute.TLSConfig{CertificateRef: "internal"},
		Internal:    true,
		RequireAuth: true,
		PublicPaths: []string{"/healthz"},
	}})
	if err != nil {
		t.Fatalf("renderRoutes: %v", err)
	}
	for _, router := range []string{"billing-0", "billing-0-public-0"} {
		if got := labels["traefik.http.routers."+router+".entrypoints"]; got != "internal" {
			t.Errorf("%s entrypoints = %q; want only the internal entrypoint", router, got)
		}
		if _, ok := labels["traefik.http.routers."+router+".tls.certresolver"]; ok {
			t.Errorf("%s has a cert resolver; the internal load balancer terminates TLS", router)
		}
	}
	if got := labels["traefik.http.routers.billing-0.middlewares"]; got != "billing-0-identity-strip,auth@file,strip-cookie@file" {
		t.Errorf("middlewares = %q; an internal route strips untrusted identity before platform sign-in", got)
	}
	if len(addrs) != 1 || addrs[0] != "reports.internal.apps.example.test" {
		t.Errorf("addresses = %v", addrs)
	}
}

func TestAnInternalRouteIsRefusedWithoutAnInternalEntrypoint(t *testing.T) {
	t.Parallel()
	p := &Provider{cfg: Config{Container: &ContainerConfig{}}}
	pc := PlacementConfig{Name: "default", Certificates: map[string]string{"internal": "internal"}}
	_, _, err := p.renderRoutes("billing", pc, []compute.Route{{
		Host: "reports.internal.apps.example.test", TargetPort: 8080,
		TLS: &compute.TLSConfig{CertificateRef: "internal"}, Internal: true,
	}})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("got %v; want the route refused rather than published publicly", err)
	}
}

func TestApplicationRoutesStripClientIdentityBeforeVerifiedIdentityIsAdded(t *testing.T) {
	t.Parallel()
	const appID = "018f3f85-9b61-7b70-bc24-38426ea34e21"
	for _, tc := range []struct {
		name, authMiddleware string
		requireAuth, mcp     bool
	}{
		{name: "plain"},
		{name: "base auth and public path", authMiddleware: "oauth-auth@ecs", requireAuth: true},
		{name: "MCP without base auth", mcp: true},
		{name: "MCP and base auth with public MCP exemption", authMiddleware: "oauth-auth@ecs", requireAuth: true, mcp: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Provider{cfg: Config{Container: &ContainerConfig{
				IngressAuthMiddleware:        tc.authMiddleware,
				IngressCookieStripMiddleware: "strip-cookie@file",
				MCPAuthBackendURL:            "http://127.0.0.1:8080",
			}}}
			route := compute.Route{Host: "billing.invalid", TargetPort: 8080, AllowPlaintext: true, RequireAuth: tc.requireAuth}
			if tc.requireAuth {
				route.PublicPaths = []string{"/healthz", "/mcp"}
			}
			if tc.mcp {
				route.MCPAuthApplicationID = appID
			}
			labels, _, err := p.renderRoutes("billing", PlacementConfig{}, []compute.Route{route})
			if err != nil {
				t.Fatalf("renderRoutes: %v", err)
			}
			strip := "billing-0-identity-strip"
			for _, header := range []string{
				"X-AppHub-User-ID", "X-AppHub-Email", "X-AppHub-Application-ID",
				"X-AppHub-MCP-Host", "X-Auth-Request-User", "X-Auth-Request-Email",
			} {
				key := "traefik.http.middlewares." + strip + ".headers.customrequestheaders." + header
				if value, ok := labels[key]; !ok || value != "" {
					t.Errorf("%s = %q (present=%t), want an explicit removal", key, value, ok)
				}
			}
			baseChain := strip
			if tc.requireAuth {
				baseChain += "," + tc.authMiddleware
			}
			baseChain += ",strip-cookie@file"
			if got := labels["traefik.http.routers.billing-0.middlewares"]; got != baseChain {
				t.Errorf("base middleware order = %q, want %q", got, baseChain)
			}
			if tc.requireAuth {
				for _, pub := range []string{"billing-0-public-0", "billing-0-public-1"} {
					if got := labels["traefik.http.routers."+pub+".middlewares"]; got != strip+",strip-cookie@file" {
						t.Errorf("%s middleware order = %q; public exemptions still strip identity but do not authenticate", pub, got)
					}
					if got := labels["traefik.http.routers."+pub+".priority"]; got != publicPathPriority {
						t.Errorf("%s priority = %q, want %q", pub, got, publicPathPriority)
					}
				}
			}
			if !tc.mcp {
				if _, ok := labels["traefik.http.routers.billing-0-mcp.rule"]; ok {
					t.Error("unexpected protected MCP router without MCP auth enabled")
				}
				return
			}
			mcpChain := strip + ",billing-0-mcp-context,billing-0-mcp-auth,billing-0-mcp-strip,strip-cookie@file"
			if got := labels["traefik.http.routers.billing-0-mcp.middlewares"]; got != mcpChain {
				t.Errorf("MCP middleware order = %q, want %q", got, mcpChain)
			}
			if got := labels["traefik.http.routers.billing-0-mcp.rule"]; got != "Host(`billing.invalid`) && (Path(`/mcp`) || PathPrefix(`/mcp/`))" {
				t.Errorf("MCP rule = %q; /MCP must bypass this case-sensitive protected router and use the stripped base route", got)
			}
			if got := labels["traefik.http.routers.billing-0-mcp.priority"]; got != mcpRoutePriority {
				t.Errorf("MCP priority = %q, want %q (above public /mcp)", got, mcpRoutePriority)
			}
			if got := labels["traefik.http.routers.billing-0-mcp-discovery.middlewares"]; got != strip+",billing-0-mcp-discovery-path,strip-cookie@file" {
				t.Errorf("discovery middleware order = %q; backend metadata cannot receive client identity", got)
			}
			for header, want := range map[string]string{
				"X-AppHub-Application-ID": appID,
				"X-AppHub-MCP-Host":       "billing.invalid",
			} {
				if got := labels["traefik.http.middlewares.billing-0-mcp-context.headers.customrequestheaders."+header]; got != want {
					t.Errorf("MCP context %s = %q, want %q", header, got, want)
				}
			}
			if got := labels["traefik.http.middlewares.billing-0-mcp-auth.forwardauth.authrequestheaders"]; got != "Authorization,X-AppHub-Application-ID,X-AppHub-MCP-Host" {
				t.Errorf("MCP auth request headers = %q; auth requires bearer token and trusted context", got)
			}
			if got := labels["traefik.http.middlewares.billing-0-mcp-auth.forwardauth.authresponseheaders"]; got != "X-AppHub-User-ID,X-AppHub-Email" {
				t.Errorf("MCP auth response headers = %q; only verified AppHub identity can be restored", got)
			}
			for _, header := range []string{"X-AppHub-User-ID", "X-AppHub-Email", "X-Auth-Request-User", "X-Auth-Request-Email"} {
				if _, ok := labels["traefik.http.middlewares.billing-0-mcp-strip.headers.customrequestheaders."+header]; ok {
					t.Errorf("post-auth MCP middleware removes %s after verification", header)
				}
			}
		})
	}
}

func TestApplicationRouteRefusesMissingSSOCookieBoundary(t *testing.T) {
	t.Parallel()
	for _, internal := range []bool{false, true} {
		p := &Provider{cfg: Config{Container: &ContainerConfig{
			InternalEntrypoint: "internal", IngressAuthMiddleware: "oauth-auth@ecs",
			MCPAuthBackendURL: "http://127.0.0.1:8080",
		}}}
		_, _, err := p.renderRoutes("billing", PlacementConfig{}, []compute.Route{{
			Host: "billing.invalid", TargetPort: 8080, AllowPlaintext: true, Internal: internal,
		}})
		if !errors.Is(err, compute.ErrInvalidSpec) {
			t.Errorf("internal=%t: without cookie-strip middleware got %v, want ErrInvalidSpec", internal, err)
		}
		if p.Capabilities().Has(compute.CapIngressAuth) || p.Capabilities().Has(compute.CapMCPAuth) {
			t.Error("auth capabilities advertised despite routes failing closed without cookie isolation")
		}
	}
}

// TestPublicPathsMatchExactlyUnlessWildcarded pins the fix for a proxy-path
// bug: an exempted path must not also exempt an unrelated sibling that merely
// shares its prefix. "/healthz" must not exempt "/healthzevil", and only a
// path ending in the literal "/*" exempts everything below it.
func TestPublicPathsMatchExactlyUnlessWildcarded(t *testing.T) {
	t.Parallel()
	p := &Provider{cfg: Config{Container: &ContainerConfig{
		IngressAuthMiddleware: "oauth-auth@ecs", IngressCookieStripMiddleware: "strip-cookie@file",
	}}}
	labels, _, err := p.renderRoutes("billing", PlacementConfig{}, []compute.Route{{
		Host: "billing.invalid", TargetPort: 8080, AllowPlaintext: true, RequireAuth: true,
		PublicPaths: []string{"/healthz", "/api/webhooks/*"},
	}})
	if err != nil {
		t.Fatalf("renderRoutes: %v", err)
	}
	if got := labels["traefik.http.routers.billing-0-public-0.rule"]; got != "Host(`billing.invalid`) && Path(`/healthz`)" {
		t.Errorf("exact public path rule = %q; an exact path must use Path(), not PathPrefix(), so it "+
			"does not also exempt /healthzevil", got)
	}
	if got := labels["traefik.http.routers.billing-0-public-1.rule"]; got != "Host(`billing.invalid`) && PathPrefix(`/api/webhooks/`)" {
		t.Errorf("wildcard public path rule = %q; a trailing /* must become PathPrefix() on the slash "+
			"boundary, so it does not also exempt /api/webhooksevil", got)
	}
}

// TestBarePublicPathWildcardIsRefused pins that "/*" -- which would exempt
// every path from authentication -- is refused at the provider layer too,
// not only by the control plane that normally rejects it first.
func TestBarePublicPathWildcardIsRefused(t *testing.T) {
	t.Parallel()
	p := &Provider{cfg: Config{Container: &ContainerConfig{
		IngressAuthMiddleware: "oauth-auth@ecs", IngressCookieStripMiddleware: "strip-cookie@file",
	}}}
	_, _, err := p.renderRoutes("billing", PlacementConfig{}, []compute.Route{{
		Host: "billing.invalid", TargetPort: 8080, AllowPlaintext: true, RequireAuth: true,
		PublicPaths: []string{"/*"},
	}})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Errorf("bare /* public path returned %v, want ErrInvalidSpec", err)
	}
}
