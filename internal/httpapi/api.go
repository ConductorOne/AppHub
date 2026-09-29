// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/conductorone/apphub/internal/auth"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/oauth"
)

// Authenticate selects a credential transport by header presence, never by its
// value or validity. In particular an empty/invalid bearer cannot use a cookie.
// Callers serving MCP must additionally require Authorization header presence.
func Authenticate(r *http.Request, browser *auth.Manager, authority *oauth.Server, resource string, mutation bool) (cp.Principal, error) {
	p, _, err := authenticate(r, browser, authority, resource, mutation)
	return p, err
}

func authorization(r *http.Request) (string, bool, bool) {
	var values []string
	present := false
	for key, value := range r.Header {
		if strings.EqualFold(key, "Authorization") {
			present = true
			values = append(values, value...)
		}
	}
	if !present {
		return "", false, false
	}
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", true, false
	}
	return values[0], true, true
}

func authenticate(r *http.Request, browser *auth.Manager, authority *oauth.Server, resource string, mutation bool) (cp.Principal, cp.Session, error) {
	value, present, valid := authorization(r)
	if present {
		if !valid {
			return cp.Principal{}, cp.Session{}, cp.Problem(401, "invalid_token", "A valid access token is required.")
		}
		if authority == nil {
			return cp.Principal{}, cp.Session{}, cp.Problem(503, "unavailable", "Authentication is unavailable. Try again later.")
		}
		p, err := authority.AuthenticateBearer(r.Context(), value, resource)
		if err != nil {
			return cp.Principal{}, cp.Session{}, err
		}
		if len(p.Scopes) == 0 {
			return cp.Principal{}, cp.Session{}, cp.Problem(403, "insufficient_scope", "A granted scope is required.")
		}
		return p, cp.Session{}, nil
	}
	if browser == nil {
		return cp.Principal{}, cp.Session{}, cp.Problem(503, "unavailable", "Authentication is unavailable. Try again later.")
	}
	p, session, err := browser.Browser(r)
	if err != nil {
		return cp.Principal{}, cp.Session{}, err
	}
	if mutation {
		if err := browser.RequireCSRF(r, session); err != nil {
			return cp.Principal{}, cp.Session{}, err
		}
	}
	return p, session, nil
}

type api struct {
	service   *cp.Service
	browser   *auth.Manager
	authority *oauth.Server
	resource  string
	metadata  string
	// origin is this deployment's bare public origin, used only to build the
	// browser redirect the GitHub App Manifest callback issues once it
	// completes (githubAppManifestCallback) -- every other handler works in
	// terms of the request path alone.
	origin string
}

type endpoint func(http.ResponseWriter, *http.Request, cp.Principal, cp.Session) (int, any, error)

// Register installs application, deployment and authenticated account routes.
// Register browser login/logout and OAuth protocol routes separately through
// Manager.Register and Server.Register. No handler owns deployment execution.
func Register(mux *http.ServeMux, service *cp.Service, browser *auth.Manager, authority *oauth.Server, publicOrigin string) {
	a := &api{service: service, browser: browser, authority: authority, resource: publicOrigin + "/api", metadata: publicOrigin + "/.well-known/oauth-protected-resource/api", origin: publicOrigin}
	a.handle(mux, "GET /api/v1/targets", false, a.targets)
	a.handle(mux, "GET /api/v1/categories", false, a.categories)
	a.handle(mux, "POST /api/v1/targets/{id}/detect", true, a.detectRepository)
	a.handle(mux, "GET /api/v1/detections/{id}", false, a.detection)
	a.handle(mux, "GET /api/v1/admin/github-app", false, a.githubAppStatus)
	a.handle(mux, "PUT /api/v1/admin/github-app", true, a.setGithubAppConfig)
	a.handle(mux, "DELETE /api/v1/admin/github-app/installations/{id}", true, a.forgetGithubAppInstallation)
	a.handle(mux, "POST /api/v1/admin/github-app/manifest", true, a.startGithubAppManifest)
	// The Manifest flow's callback is a top-level browser GET redirect from
	// github.com, not a fetch/XHR: it can carry no custom header and must
	// answer with a redirect, not JSON, so it is registered directly rather
	// than through a.handle -- the same reason Manager.Register and
	// Server.Register install their own OAuth redirect routes separately
	// from this JSON API (see this function's own doc comment).
	mux.HandleFunc("GET /api/v1/admin/github-app/manifest/callback", a.githubAppManifestCallback)
	a.handle(mux, "GET /api/v1/admin/log-groups", false, a.logGroups)
	a.handle(mux, "GET /api/v1/admin/logs/{name}", false, a.queryLogs)
	a.handle(mux, "GET /api/v1/admin/members", false, a.members)
	a.handle(mux, "GET /api/v1/admin/directory/entitlements", false, a.directoryEntitlements)
	a.handle(mux, "GET /api/v1/admin/role-mappings", false, a.roleMappings)
	a.handle(mux, "GET /api/v1/admin/audit-logs", false, a.auditLogs)
	a.handle(mux, "PUT /api/v1/admin/role-mappings/{entitlementId}", true, a.setRoleMapping)
	a.handle(mux, "DELETE /api/v1/admin/role-mappings/{entitlementId}", true, a.deleteRoleMapping)
	a.handle(mux, "GET /api/v1/admin/feature-flags", false, a.featureFlags)
	a.handle(mux, "PUT /api/v1/admin/feature-flags/{key}", true, a.setFeatureFlag)
	a.handle(mux, "GET /api/v1/directory/applications", false, a.directory)
	a.handle(mux, "GET /api/v1/directory/applications/{id}", false, a.directoryEntry)
	a.handle(mux, "GET /api/v1/applications", false, a.applications)
	a.handle(mux, "POST /api/v1/applications", true, a.createApplication)
	a.handle(mux, "GET /api/v1/applications/{id}", false, a.application)
	a.handle(mux, "PUT /api/v1/applications/{id}", true, a.updateApplication)
	a.handle(mux, "POST /api/v1/applications/{id}/deployments", true, a.submitDeployment)
	a.handle(mux, "POST /api/v1/applications/{id}/deletion", true, a.deleteApplication)
	a.handle(mux, "GET /api/v1/applications/{id}/owners", false, a.owners)
	a.handle(mux, "POST /api/v1/applications/{id}/owners", true, a.addOwner)
	a.handle(mux, "DELETE /api/v1/applications/{id}/owners/{ownerKey}", true, a.removeOwner)
	a.handle(mux, "GET /api/v1/directory/principals", false, a.searchPrincipals)
	a.handle(mux, "GET /api/v1/applications/{id}/deployments", false, a.deployments)
	a.handle(mux, "GET /api/v1/applications/{id}/usage", false, a.usage)
	a.handle(mux, "GET /api/v1/applications/{id}/secrets", false, a.secrets)
	a.handle(mux, "POST /api/v1/applications/{id}/secrets/deployments", true, a.deploySecretChanges)
	a.handle(mux, "GET /api/v1/deployments/{id}", false, a.deployment)
	a.handle(mux, "POST /api/v1/deployments/{id}/resolve-interrupted", true, a.resolveInterrupted)
	a.handle(mux, "GET /api/v1/users/me", false, a.me)
	a.handle(mux, "GET /api/v1/sessions", false, a.sessions)
	a.handle(mux, "DELETE /api/v1/sessions/{id}", true, a.revokeSession)
	a.handle(mux, "GET /api/v1/oauth/consents/{transactionId}", false, a.consent)
}

func (a *api) handle(mux *http.ServeMux, pattern string, mutation bool, fn endpoint) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		requestID := cp.NewID()
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		p, session, err := authenticate(r, a.browser, a.authority, a.resource, mutation)
		if err != nil {
			a.writeError(w, requestID, err)
			return
		}
		if mutation {
			r = r.WithContext(cp.WithAuditContext(r.Context(), p.UserID, r.Method+" "+r.Pattern, ""))
		}
		status, body, err := fn(w, r, p, session)
		if err != nil {
			a.writeError(w, requestID, err)
			return
		}
		writeAPIJSON(w, status, body)
	})
}

func writeAPIJSON(w http.ResponseWriter, status int, body any) {
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (a *api) writeError(w http.ResponseWriter, requestID string, err error) {
	var problem *cp.Error
	switch {
	case errors.Is(err, cp.ErrInvalidCursor):
		problem = cp.Problem(400, "invalid_cursor", "The pagination cursor is invalid.")
	case errors.Is(err, cp.ErrNotFound):
		problem = cp.Problem(404, "not_found", "The requested resource was not found.")
	case errors.Is(err, cp.ErrConflict):
		problem = cp.Problem(409, "conflict", "The resource changed. Reload before trying again.")
	case errors.As(err, &problem) && problem.Status >= 400 && problem.Status <= 599:
	default:
		problem = cp.Problem(503, "unavailable", "A required dependency is unavailable. Try again later.")
	}
	if problem.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+a.metadata+`"`)
	}
	writeAPIJSON(w, problem.Status, cp.ErrorResponse{Error: problem, RequestID: requestID})
}

// Decode one object only. Using concrete DTOs closes the credential/artifact
// injection boundary, including unknown fields inside nested specifications.
func decodeBody[T any](w http.ResponseWriter, r *http.Request) (T, error) {
	var zero T
	if r.ContentLength > maxRequestBodyBytes {
		return zero, cp.Problem(413, "body_too_large", "The request body exceeds 128 KiB.")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var value *T
	err := decoder.Decode(&value)
	if err == nil {
		var extra json.RawMessage
		err = decoder.Decode(&extra)
		if err == io.EOF && value != nil {
			return *value, nil
		}
	}
	var oversized *http.MaxBytesError
	if errors.As(err, &oversized) {
		return zero, cp.Problem(413, "body_too_large", "The request body exceeds 128 KiB.")
	}
	return zero, cp.Problem(400, "malformed_request", "The body must be one JSON object with only supported fields.")
}

func listOptions(r *http.Request, allowAll bool) (cp.ListOptions, error) {
	options := cp.ListOptions{Limit: 50}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return options, cp.Problem(400, "invalid_query", "The query parameters are malformed.")
	}
	invalid := cp.Problem(400, "invalid_query", "Use a limit from 1 to 100, one cursor, and all=true or all=false only for application inventory.")
	for _, key := range []string{"limit", "cursor", "all"} {
		if len(query[key]) > 1 {
			return options, invalid
		}
	}
	if value, ok := query["limit"]; ok {
		limit, err := strconv.Atoi(value[0])
		if err != nil || limit < 1 || limit > 100 {
			return options, invalid
		}
		options.Limit = limit
	}
	options.Cursor = query.Get("cursor")
	if values, ok := query["all"]; ok {
		if !allowAll || (values[0] != "true" && values[0] != "false") {
			return options, invalid
		}
		options.All = values[0] == "true"
	}
	return options, nil
}

func idempotencyKey(r *http.Request) (string, error) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", cp.Problem(400, "idempotency_key_required", "Exactly one nonempty Idempotency-Key header is required.")
	}
	return values[0], nil
}

func revisionHeader(r *http.Request) (int64, error) {
	values := r.Header.Values("If-Match")
	invalid := cp.Problem(400, "invalid_revision", "If-Match must contain one quoted positive application revision.")
	if len(values) != 1 {
		return 0, invalid
	}
	value := strings.TrimSpace(values[0])
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, invalid
	}
	number := value[1 : len(value)-1]
	if number[0] == '0' {
		return 0, invalid
	}
	for _, c := range number {
		if c < '0' || c > '9' {
			return 0, invalid
		}
	}
	revision, err := strconv.ParseInt(number, 10, 64)
	if err != nil || revision < 1 {
		return 0, invalid
	}
	return revision, nil
}

func applicationETag(w http.ResponseWriter, view cp.ApplicationView) {
	w.Header().Set("ETag", `"`+strconv.FormatInt(view.Revision, 10)+`"`)
}

func (a *api) targets(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	views, err := a.service.ListTargets(r.Context(), p)
	if views == nil {
		views = []cp.TargetView{}
	}
	return 200, views, err
}
func (a *api) categories(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	views, err := a.service.ListCategories(r.Context(), p)
	return 200, views, err
}
func (a *api) detectRepository(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	input, err := decodeBody[cp.DetectionInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.RequestDetection(r.Context(), p, r.PathValue("id"), input)
	if err == nil {
		w.Header().Set("Location", "/api/v1/detections/"+url.PathEscape(view.DetectionID))
	}
	return 202, view, err
}
func (a *api) detection(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	view, err := a.service.GetDetection(r.Context(), p, r.PathValue("id"))
	return 200, view, err
}
func (a *api) githubAppStatus(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	view, err := a.service.GetGitHubAppStatus(r.Context(), p)
	return 200, view, err
}
func (a *api) setGithubAppConfig(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	input, err := decodeBody[cp.GitHubAppConfigInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.SetGitHubAppConfig(r.Context(), p, input)
	return 200, view, err
}
func (a *api) forgetGithubAppInstallation(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	err := a.service.ForgetGitHubAppInstallation(r.Context(), p, r.PathValue("id"))
	return 204, nil, err
}
func (a *api) startGithubAppManifest(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	input, err := decodeBody[cp.GitHubAppManifestInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.StartGitHubAppManifest(r.Context(), p, input)
	return 200, view, err
}

// githubAppManifestCallback consumes GitHub's redirect back from the App
// Manifest flow. It authenticates the administrator's ordinary browser
// session cookie (mutation is false: this is a plain top-level GET a browser
// navigated to, not a form submission this origin could apply CSRF-header
// checks to) and always answers with a redirect into the Workspace, success
// or failure, never a JSON body a browser navigation would just display raw.
func (a *api) githubAppManifestCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _, err := authenticate(r, a.browser, a.authority, a.resource, false)
	if err != nil {
		a.redirectManifestResult(w, r, "unauthenticated")
		return
	}
	r = r.WithContext(cp.WithAuditContext(r.Context(), p.UserID, "GET /api/v1/admin/github-app/manifest/callback", ""))
	q := r.URL.Query()
	if _, err := a.service.CompleteGitHubAppManifest(r.Context(), p, q.Get("code"), q.Get("state")); err != nil {
		a.redirectManifestResult(w, r, manifestErrorReason(err))
		return
	}
	http.Redirect(w, r, a.origin+"/workspace?tab=github-app&manifest=success", http.StatusFound)
}
func (a *api) redirectManifestResult(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, a.origin+"/workspace?tab=github-app&manifest=error&reason="+url.QueryEscape(reason), http.StatusFound)
}

// manifestErrorReason reduces a service error to its safe, fixed Problem
// code (e.g. "invalid_state", "forbidden") for the query string a browser
// navigation surfaces the failure through -- never the free-form message,
// which is written for a JSON API response, not a URL.
func manifestErrorReason(err error) string {
	var problem *cp.Error
	if errors.As(err, &problem) && problem.Code != "" {
		return problem.Code
	}
	return "unavailable"
}
func (a *api) logGroups(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	names, err := a.service.ListLogGroups(r.Context(), p)
	if names == nil {
		names = []string{}
	}
	return 200, names, err
}
func (a *api) auditLogs(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, nil, cp.Problem(400, "invalid_query", "Use a limit from 1 to 100 and one cursor.")
	}
	for key, values := range query {
		if (key != "limit" && key != "cursor") || len(values) != 1 {
			return 0, nil, cp.Problem(400, "invalid_query", "Use a limit from 1 to 100 and one cursor.")
		}
	}
	limit := 50
	if value := query.Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 100 {
			return 0, nil, cp.Problem(400, "invalid_query", "Use a limit from 1 to 100 and one cursor.")
		}
	}
	page, err := a.service.ListAuditLogs(r.Context(), p, limit, query.Get("cursor"))
	return 200, page, err
}

func (a *api) members(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	views, err := a.service.ListMembers(r.Context(), p)
	if views == nil {
		views = []cp.MemberView{}
	}
	return 200, views, err
}
func (a *api) directoryEntitlements(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	views, err := a.service.ListDirectoryEntitlements(r.Context(), p)
	if views == nil {
		views = []cp.DirectoryEntitlementView{}
	}
	return 200, views, err
}
func (a *api) roleMappings(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	views, err := a.service.ListRoleMappings(r.Context(), p)
	if views == nil {
		views = []cp.RoleMappingView{}
	}
	return 200, views, err
}
func (a *api) setRoleMapping(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	input, err := decodeBody[cp.RoleMappingInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.SetRoleMapping(r.Context(), p, r.PathValue("entitlementId"), input)
	return 200, view, err
}
func (a *api) deleteRoleMapping(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	err := a.service.DeleteRoleMapping(r.Context(), p, r.PathValue("entitlementId"))
	return 204, nil, err
}
func (a *api) featureFlags(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	views, err := a.service.ListFeatureFlags(r.Context(), p)
	if views == nil {
		views = []cp.FeatureFlagView{}
	}
	return 200, views, err
}
func (a *api) setFeatureFlag(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	input, err := decodeBody[cp.FeatureFlagInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.SetFeatureFlag(r.Context(), p, r.PathValue("key"), input)
	return 200, view, err
}
func (a *api) queryLogs(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	q, err := logQuery(r)
	if err != nil {
		return 0, nil, err
	}
	res, err := a.service.QueryLogs(r.Context(), p, r.PathValue("name"), q)
	return 200, res, err
}

// logQuery parses the bounded query parameters an admin log read accepts.
// start/end default to the last hour when both are omitted; supplying only
// one is refused rather than guessing the other half of the window.
func logQuery(r *http.Request) (cp.LogQuery, error) {
	invalid := cp.Problem(400, "invalid_query", "Use RFC 3339 start/end (both or neither), an optional filter of at most 2048 characters, an optional nextToken, and a limit from 1 to 10000.")
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return cp.LogQuery{}, invalid
	}
	for _, key := range []string{"start", "end", "filter", "nextToken", "limit"} {
		if len(query[key]) > 1 {
			return cp.LogQuery{}, invalid
		}
	}
	startRaw, endRaw := query.Get("start"), query.Get("end")
	var q cp.LogQuery
	switch {
	case startRaw == "" && endRaw == "":
		q.End = time.Now().UTC()
		q.Start = q.End.Add(-time.Hour)
	case startRaw != "" && endRaw != "":
		q.Start, err = time.Parse(time.RFC3339, startRaw)
		if err != nil {
			return cp.LogQuery{}, invalid
		}
		q.End, err = time.Parse(time.RFC3339, endRaw)
		if err != nil {
			return cp.LogQuery{}, invalid
		}
	default:
		return cp.LogQuery{}, invalid
	}
	filter := query.Get("filter")
	if len(filter) > 2048 {
		return cp.LogQuery{}, invalid
	}
	q.FilterPattern = filter
	token := query.Get("nextToken")
	if len(token) > 8192 {
		return cp.LogQuery{}, invalid
	}
	q.NextToken = token
	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 10000 {
			return cp.LogQuery{}, invalid
		}
		q.Limit = int32(limit) //nolint:gosec // bounded to [1, 10000] by the check above
	}
	return q, nil
}
func (a *api) applications(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	options, err := listOptions(r, true)
	if err != nil {
		return 0, nil, err
	}
	page, err := a.service.ListApplications(r.Context(), p, options)
	return 200, page, err
}
func (a *api) application(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	view, err := a.service.GetApplication(r.Context(), p, r.PathValue("id"))
	if err == nil {
		applicationETag(w, view)
	}
	return 200, view, err
}
func (a *api) createApplication(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	key, err := idempotencyKey(r)
	if err != nil {
		return 0, nil, err
	}
	input, err := decodeBody[cp.ApplicationInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.CreateApplication(r.Context(), p, input, key)
	if err == nil {
		applicationETag(w, view)
		w.Header().Set("Location", "/api/v1/applications/"+url.PathEscape(view.ID))
	}
	return 201, view, err
}
func (a *api) updateApplication(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	revision, err := revisionHeader(r)
	if err != nil {
		return 0, nil, err
	}
	input, err := decodeBody[cp.ApplicationInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.UpdateApplication(r.Context(), p, r.PathValue("id"), input, revision)
	if err == nil {
		applicationETag(w, view)
	}
	return 200, view, err
}
func (a *api) submitDeployment(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	key, err := idempotencyKey(r)
	if err != nil {
		return 0, nil, err
	}
	input, err := decodeBody[cp.SubmitDeploymentInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.SubmitDeployment(r.Context(), p, r.PathValue("id"), input, key)
	if err == nil {
		w.Header().Set("Location", view.StatusURL)
		w.Header().Set("Retry-After", "2")
	}
	return 202, view, err
}
func (a *api) deleteApplication(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	key, err := idempotencyKey(r)
	if err != nil {
		return 0, nil, err
	}
	input, err := decodeBody[cp.DeleteApplicationInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.DeleteApplication(r.Context(), p, r.PathValue("id"), input, key)
	if err != nil || view == nil {
		return 204, nil, err
	}
	w.Header().Set("Location", view.StatusURL)
	w.Header().Set("Retry-After", "2")
	return 202, view, nil
}
func (a *api) owners(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	list, err := a.service.ListOwners(r.Context(), p, r.PathValue("id"))
	return 200, list, err
}
func (a *api) addOwner(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	input, err := decodeBody[cp.OwnerInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	list, err := a.service.AddOwner(r.Context(), p, r.PathValue("id"), input)
	return 200, list, err
}
func (a *api) removeOwner(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	list, err := a.service.RemoveOwner(r.Context(), p, r.PathValue("id"), r.PathValue("ownerKey"))
	return 200, list, err
}
func (a *api) searchPrincipals(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	result, err := a.service.SearchPrincipals(r.Context(), p, r.URL.Query().Get("q"))
	return 200, result, err
}
func (a *api) directory(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	options, err := listOptions(r, false)
	if err != nil {
		return 0, nil, err
	}
	page, err := a.service.ListDirectory(r.Context(), p, options)
	return 200, page, err
}
func (a *api) directoryEntry(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	summary, err := a.service.GetDirectoryEntry(r.Context(), p, r.PathValue("id"))
	return 200, summary, err
}
func (a *api) usage(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	view, err := a.service.GetUsage(r.Context(), p, r.PathValue("id"), r.URL.Query().Get("range"))
	return 200, view, err
}
func (a *api) secrets(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	list, err := a.service.ListSecrets(r.Context(), p, r.PathValue("id"))
	return 200, list, err
}
func (a *api) deploySecretChanges(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	key, err := idempotencyKey(r)
	if err != nil {
		return 0, nil, err
	}
	input, err := decodeBody[cp.SecretChangesInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.DeploySecretChanges(r.Context(), p, r.PathValue("id"), input, key)
	if err == nil {
		w.Header().Set("Location", view.StatusURL)
		w.Header().Set("Retry-After", "2")
	}
	return 202, view, err
}
func (a *api) deployments(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	options, err := listOptions(r, false)
	if err != nil {
		return 0, nil, err
	}
	page, err := a.service.ListDeployments(r.Context(), p, r.PathValue("id"), options)
	return 200, page, err
}
func (a *api) deployment(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	view, err := a.service.GetDeployment(r.Context(), p, r.PathValue("id"))
	return 200, view, err
}
func (a *api) resolveInterrupted(w http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	input, err := decodeBody[cp.ResolveInterruptedInput](w, r)
	if err != nil {
		return 0, nil, err
	}
	view, err := a.service.ResolveInterrupted(r.Context(), p, r.PathValue("id"), input)
	return 200, view, err
}
func (a *api) me(_ http.ResponseWriter, r *http.Request, p cp.Principal, session cp.Session) (int, any, error) {
	view, err := a.browser.Me(r.Context(), p, session.CSRF)
	return 200, view, err
}
func (a *api) sessions(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	options, err := listOptions(r, false)
	if err != nil {
		return 0, nil, err
	}
	page, err := a.browser.ListSessions(r.Context(), p, options)
	return 200, page, err
}
func (a *api) revokeSession(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	err := a.browser.RevokeSession(r.Context(), p, r.PathValue("id"))
	return 204, nil, err
}
func (a *api) consent(_ http.ResponseWriter, r *http.Request, p cp.Principal, _ cp.Session) (int, any, error) {
	if p.Bearer {
		return 0, nil, cp.Problem(403, "browser_session_required", "Consent requires its original browser session.")
	}
	if a.authority == nil {
		return 0, nil, cp.Problem(503, "unavailable", "Authorization is unavailable. Try again later.")
	}
	view, err := a.authority.Consent(r.Context(), p, r.PathValue("transactionId"))
	return 200, view, err
}
