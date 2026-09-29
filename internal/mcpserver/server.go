// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package mcpserver exposes the application service through the official MCP
// transports. It never runs deployments or constructs cloud providers.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/oauth"
	sdk "github.com/conductorone/apphub/sdk/go"
)

const maxRequestBodyBytes = 128 << 10
const deploymentOptionsURI = "apphub://deployment-options"

type principalKey struct{}

// New returns the exact /mcp handler. Every HTTP request is independently
// authenticated for the MCP resource, including initialization and discovery.
func New(service *cp.Service, authority *oauth.Server, publicOrigin string) (http.Handler, error) {
	if service == nil || authority == nil {
		return nil, errors.New("MCP requires an application service and OAuth authority")
	}
	if !validOrigin(publicOrigin) {
		return nil, errors.New("MCP requires a canonical public origin")
	}
	return newHTTPHandler(service, authority.AuthenticateBearer, publicOrigin), nil
}

func validOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	// The composition root additionally requires explicit allowLoopbackHTTP.
	return u.Scheme == "http" && ip != nil && ip.IsLoopback()
}

func newHTTPHandler(service *cp.Service, authenticate func(context.Context, string, string) (cp.Principal, error), origin string) http.Handler {
	server := newServer(serviceBackend{service})
	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 true,
		MaxRequestBodyBytes:          maxRequestBodyBytes,
		PropagateRequestCancellation: true,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if origins, present := r.Header["Origin"]; present && (len(origins) != 1 || origins[0] != origin) {
			writeProblem(w, cp.Problem(403, "invalid_origin", "The request origin is not permitted."))
			return
		}
		if len(r.Header.Values("Authorization")) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+origin+`/.well-known/oauth-protected-resource/mcp"`)
			writeProblem(w, cp.Problem(401, "invalid_token", "A valid MCP access token is required."))
			return
		}
		principal, err := authenticate(r.Context(), r.Header.Get("Authorization"), origin+"/mcp")
		if err != nil {
			problem := safeProblem(err)
			if problem.Status == 401 {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="`+origin+`/.well-known/oauth-protected-resource/mcp"`)
			}
			writeProblem(w, problem)
			return
		}
		if !principal.Bearer || principal.UserID == "" {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="`+origin+`/.well-known/oauth-protected-resource/mcp"`)
			writeProblem(w, cp.Problem(401, "invalid_token", "A valid MCP access token is required."))
			return
		}
		if r.ContentLength > maxRequestBodyBytes {
			writeProblem(w, cp.Problem(413, "request_too_large", "The request exceeds the size limit."))
			return
		}
		transport.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, principal)))
	})
}

func scopedPrincipal(ctx context.Context, scope string) (cp.Principal, error) {
	principal, ok := ctx.Value(principalKey{}).(cp.Principal)
	if !ok || !principal.Bearer || principal.UserID == "" {
		return cp.Principal{}, cp.Problem(401, "invalid_token", "A valid MCP access token is required.")
	}
	if !slices.Contains(principal.Scopes, scope) {
		return cp.Principal{}, cp.Problem(403, "insufficient_scope", "The access token does not permit this action.")
	}
	return principal, nil
}

func safeProblem(err error) *cp.Error {
	var problem *cp.Error
	if errors.As(err, &problem) {
		return problem
	}
	return cp.Problem(503, "unavailable", "A required dependency is unavailable. Try again later.")
}

func writeProblem(w http.ResponseWriter, problem *cp.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(problem.Status)
	_ = json.NewEncoder(w).Encode(cp.ErrorResponse{Error: problem})
}

// RunStdio serves the same tools using only the CLI's authenticated API client.
// MCP protocol output owns stdout; this adapter writes no prompts or progress.
func RunStdio(ctx context.Context, client *sdk.Client) error {
	if client == nil {
		return errors.New("MCP stdio requires an authenticated AppHub client")
	}
	return newServer(clientBackend{client}).Run(ctx, &mcp.StdioTransport{})
}
