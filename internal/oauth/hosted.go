// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

const (
	hostedApplicationHeader = "X-AppHub-Application-ID"
	hostedHostHeader        = "X-AppHub-MCP-Host"
	hostedUserHeader        = "X-AppHub-User-ID"
	hostedEmailHeader       = "X-AppHub-Email"
)

var errHostedResource = errors.New("hosted MCP resource not found")

type resourcePolicy struct {
	Resource        string
	Issuer          string
	Scopes          []string
	ApplicationID   string
	ApplicationHost string
}

type resourcePolicyKey struct{}

func (s *Server) managementPolicy(resource string) (resourcePolicy, bool) {
	if resource != s.origin+"/api" && resource != s.origin+"/mcp" {
		return resourcePolicy{}, false
	}
	return resourcePolicy{Resource: resource, Issuer: s.origin, Scopes: managementScopes}, true
}

func requestResourcePolicy(r *http.Request) (resourcePolicy, bool) {
	policy, ok := r.Context().Value(resourcePolicyKey{}).(resourcePolicy)
	return policy, ok
}

func (s *Server) policyForRequest(r *http.Request, resource string) (resourcePolicy, bool) {
	if policy, ok := requestResourcePolicy(r); ok {
		return policy, resource == policy.Resource
	}
	return s.managementPolicy(resource)
}

func (s *Server) issuerForRequest(r *http.Request) string {
	if policy, ok := requestResourcePolicy(r); ok {
		return policy.Issuer
	}
	return s.origin
}

func (s *Server) hostedPolicy(ctx context.Context, applicationID, host string) (resourcePolicy, error) {
	if applicationID == "" || strings.ContainsAny(applicationID, "/?# \t\r\n") || host == "" || host != strings.ToLower(host) {
		return resourcePolicy{}, errHostedResource
	}
	u, err := url.Parse("https://" + host)
	if err != nil || u.Host != host || u.Hostname() != host || u.Port() != "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return resourcePolicy{}, errHostedResource
	}
	record, err := s.repo.Read(ctx, cp.RecordID{Kind: cp.ApplicationKind, ID: applicationID})
	if err != nil {
		if errors.Is(err, cp.ErrNotFound) {
			return resourcePolicy{}, errHostedResource
		}
		return resourcePolicy{}, unavailable()
	}
	application, err := cp.Decode[cp.ApplicationRecord](record)
	if err != nil {
		return resourcePolicy{}, unavailable()
	}
	address := "https://" + host
	if application.ID != applicationID || application.Input.Exposure.Mode != "public" || !application.Input.Exposure.MCPAuthEnabled || !slices.Contains(application.Addresses, address) {
		return resourcePolicy{}, errHostedResource
	}
	issuer := s.origin + "/mcp/apps/" + applicationID + "/" + host
	return resourcePolicy{
		Resource:        address + "/mcp",
		Issuer:          issuer,
		Scopes:          []string{cp.AppAccess},
		ApplicationID:   applicationID,
		ApplicationHost: host,
	}, nil
}

func (s *Server) withHostedPolicy(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policy, err := s.hostedPolicy(r.Context(), r.PathValue("applicationId"), r.PathValue("host"))
		if err != nil {
			if errors.Is(err, errHostedResource) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/oauth/token"):
					oauthError(w, http.StatusBadRequest, "invalid_grant")
				case strings.HasSuffix(r.URL.Path, "/oauth/revoke"):
					w.WriteHeader(http.StatusOK)
				case strings.HasSuffix(r.URL.Path, "/oauth/authorize"):
					oauthError(w, http.StatusBadRequest, "invalid_target")
				default:
					http.NotFound(w, r)
				}
				return
			}
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		ctx := context.WithValue(r.Context(), resourcePolicyKey{}, policy)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) validateStoredHostedPolicy(ctx context.Context, applicationID, host, resource, issuer string) (resourcePolicy, error) {
	if applicationID == "" || host == "" {
		return resourcePolicy{}, errHostedResource
	}
	policy, err := s.hostedPolicy(ctx, applicationID, host)
	if err != nil {
		return resourcePolicy{}, err
	}
	if policy.Resource != resource || policy.Issuer != issuer {
		return resourcePolicy{}, errHostedResource
	}
	return policy, nil
}

// AuthenticateApplicationBearer verifies a bearer token presented to the hosted
// MCP endpoint of applicationID at host, and returns the principal it was issued
// to. It refuses every token while hosted MCP authentication is disabled for
// that application.
func (s *Server) AuthenticateApplicationBearer(ctx context.Context, authorization, applicationID, host string) (cp.Principal, error) {
	policy, err := s.hostedPolicy(ctx, applicationID, host)
	if err != nil {
		if isUnavailable(err) {
			return cp.Principal{}, unavailable()
		}
		return cp.Principal{}, invalidToken()
	}
	return s.authenticateBearer(ctx, authorization, policy)
}

func oneHeader(r *http.Request, name string) (string, bool) {
	values := r.Header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = strings.TrimSpace(values[0])
	}
	return returnValue, len(values) == 1 && returnValue != ""
}

func (s *Server) forwardHostedMCP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	authorization, authOK := oneHeader(r, "Authorization")
	applicationID, applicationOK := oneHeader(r, hostedApplicationHeader)
	host, hostOK := oneHeader(r, hostedHostHeader)
	if !authOK || !applicationOK || !hostOK {
		s.hostedChallenge(w, host)
		return
	}
	principal, err := s.AuthenticateApplicationBearer(r.Context(), authorization, applicationID, host)
	if err != nil {
		if isUnavailable(err) {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		s.hostedChallenge(w, host)
		return
	}
	userRecord, err := s.repo.Read(r.Context(), cp.RecordID{Kind: cp.UserKind, ID: principal.UserID})
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	user, err := cp.Decode[cp.User](userRecord)
	if err != nil || user.ID != principal.UserID {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	w.Header().Set(hostedUserHeader, principal.UserID)
	w.Header().Set(hostedEmailHeader, user.Email)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) hostedChallenge(w http.ResponseWriter, host string) {
	metadata := ""
	if _, err := url.ParseRequestURI("https://" + host + "/.well-known/oauth-protected-resource/mcp"); err == nil && host != "" && !strings.ContainsAny(host, "\"\\\r\n") {
		metadata = fmt.Sprintf(` resource_metadata="https://%s/.well-known/oauth-protected-resource/mcp"`, host)
	}
	w.Header().Set("WWW-Authenticate", "Bearer"+metadata+`, error="invalid_token"`)
	oauthError(w, http.StatusUnauthorized, "invalid_token")
}
