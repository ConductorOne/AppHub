// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package oauth implements AppHub's public-client authorization server. It never
// accepts an upstream token as an AppHub credential.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/conductorone/apphub/internal/auth"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/serverconfig"
)

const codeLifetime = 5 * time.Minute
const accessLifetime = 15 * time.Minute
const familyLifetime = 30 * 24 * time.Hour

var managementScopes = []string{cp.ApplicationsRead, cp.ApplicationsWrite, cp.DeploymentsRead, cp.DeploymentsWrite}
var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// Server issues resource-bound opaque credentials through browser consent and
// durable single-use code/refresh transactions. Construct it with New.
type Server struct {
	origin         string
	repo           cp.Repository
	browser        *auth.Manager
	clients        map[string][]string
	metadataClient *http.Client
	cacheMu        sync.Mutex
	cache          map[string]metadataCacheEntry
	fetchSlots     chan struct{}
}
type consentTransaction struct {
	SessionID       string       `json:"sessionId"`
	Principal       cp.Principal `json:"principal"`
	ClientID        string       `json:"clientId"`
	RedirectURI     string       `json:"redirectUri"`
	State           string       `json:"state"`
	Resource        string       `json:"resource"`
	Issuer          string       `json:"issuer"`
	Scopes          []string     `json:"scopes"`
	ApplicationID   string       `json:"applicationId,omitempty"`
	ApplicationHost string       `json:"applicationHost,omitempty"`
	Challenge       string       `json:"challenge"`
	ExpiresAt       time.Time    `json:"expiresAt"`
	Consumed        bool         `json:"consumed"`
}
type authorizationCode struct {
	Principal       cp.Principal `json:"principal"`
	ClientID        string       `json:"clientId"`
	RedirectURI     string       `json:"redirectUri"`
	Resource        string       `json:"resource"`
	Issuer          string       `json:"issuer"`
	Scopes          []string     `json:"scopes"`
	ApplicationID   string       `json:"applicationId,omitempty"`
	ApplicationHost string       `json:"applicationHost,omitempty"`
	Challenge       string       `json:"challenge"`
	ExpiresAt       time.Time    `json:"expiresAt"`
	Consumed        bool         `json:"consumed"`
}

// New validates the fixed issuer and public-client registrations and installs
// SSRF-safe metadata discovery; browser authentication and persistence are required.
func New(cfg serverconfig.Config, repo cp.Repository, browser *auth.Manager) (*Server, error) {
	if repo == nil || browser == nil {
		return nil, errors.New("OAuth requires persistence and browser authentication")
	}
	u, err := url.Parse(cfg.PublicOrigin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && (!cfg.Auth.AllowLoopbackHTTP || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1"))) {
		return nil, errors.New("invalid OAuth public origin")
	}
	s := &Server{origin: cfg.PublicOrigin, repo: repo, browser: browser, clients: make(map[string][]string), metadataClient: newMetadataHTTPClient(), cache: make(map[string]metadataCacheEntry), fetchSlots: make(chan struct{}, 8)}
	for _, c := range cfg.Auth.Clients {
		if c.ID == "" || c.ID == "apphub-cli" || len(c.RedirectURIs) == 0 {
			return nil, errors.New("invalid configured OAuth client")
		}
		if _, ok := s.clients[c.ID]; ok {
			return nil, errors.New("duplicate OAuth client")
		}
		for _, redirect := range c.RedirectURIs {
			if !httpsRedirect(redirect) {
				return nil, errors.New("configured OAuth client redirect must be HTTPS")
			}
		}
		s.clients[c.ID] = slices.Clone(c.RedirectURIs)
	}
	return s, nil
}

// Register installs exact discovery, consent, token, revocation, and hosted MCP
// authorization routes.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.metadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/api", s.resourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.resourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/mcp/apps/{applicationId}/{host}", s.withHostedPolicy(s.metadata))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp/apps/{applicationId}/{host}", s.withHostedPolicy(s.resourceMetadata))
	mux.HandleFunc("GET /oauth/authorize", denyFraming(s.authorize))
	mux.HandleFunc("POST /oauth/authorize", denyFraming(s.approve))
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/revoke", s.revoke)
	mux.HandleFunc("GET /mcp/apps/{applicationId}/{host}/oauth/authorize", denyFraming(s.withHostedPolicy(s.authorize)))
	mux.HandleFunc("POST /mcp/apps/{applicationId}/{host}/oauth/token", s.withHostedPolicy(s.token))
	mux.HandleFunc("POST /mcp/apps/{applicationId}/{host}/oauth/revoke", s.withHostedPolicy(s.revoke))
	mux.HandleFunc("/authz/app-mcp", s.forwardHostedMCP)
}

// denyFraming covers both successful consent redirects and failures before a
// transaction exists (including rejected hosted authorization targets).
func denyFraming(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		next(w, r)
	}
}

func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	issuer := s.origin
	allowed := managementScopes
	if policy, ok := requestResourcePolicy(r); ok {
		issuer = policy.Issuer
		allowed = policy.Scopes
	}
	sendJSON(w, 200, map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/oauth/authorize", "token_endpoint": issuer + "/oauth/token", "revocation_endpoint": issuer + "/oauth/revoke", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"}, "revocation_endpoint_auth_methods_supported": []string{"none"}, "scopes_supported": allowed, "authorization_response_iss_parameter_supported": true, "client_id_metadata_document_supported": true})
}
func (s *Server) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	if policy, ok := requestResourcePolicy(r); ok {
		sendJSON(w, 200, map[string]any{"resource": policy.Resource, "authorization_servers": []string{policy.Issuer}, "scopes_supported": policy.Scopes, "bearer_methods_supported": []string{"header"}})
		return
	}
	resource := s.origin + "/api"
	if r.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
		resource = s.origin + "/mcp"
	}
	sendJSON(w, 200, map[string]any{"resource": resource, "authorization_servers": []string{s.origin}, "scopes_supported": managementScopes, "bearer_methods_supported": []string{"header"}})
}
func parseScopes(v string, allowed []string) ([]string, bool) {
	if v == "" || strings.ContainsAny(v, "\t\r\n") {
		return nil, false
	}
	out := strings.Split(v, " ")
	seen := map[string]bool{}
	for _, scope := range out {
		if !slices.Contains(allowed, scope) || seen[scope] {
			return nil, false
		}
		seen[scope] = true
	}
	slices.Sort(out)
	return out, true
}
func secret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func validSecret(v string) bool {
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == v
}
func hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func mutation(kind cp.RecordKind, id string, version int64, value any) cp.Mutation {
	r, err := cp.Encode(cp.RecordID{Kind: kind, ID: id}, version+1, value)
	if err != nil {
		panic("OAuth record cannot be encoded")
	}
	return cp.Mutation{Record: r, ExpectedVersion: version}
}
func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func oauthError(w http.ResponseWriter, status int, code string) {
	sendJSON(w, status, map[string]string{"error": code})
}
func unavailable() error {
	return cp.Problem(503, "unavailable", "Authentication is temporarily unavailable.")
}
func invalidToken() error {
	return cp.Problem(401, "invalid_token", "A valid access token is required.")
}
func notFound() error { return cp.Problem(404, "not_found", "Consent transaction not found.") }
func isUnavailable(err error) bool {
	var p *cp.Error
	return errors.Is(err, cp.ErrUnavailable) || (errors.As(err, &p) && p.Status >= 500)
}
func readFailure(err error) error {
	if errors.Is(err, cp.ErrNotFound) {
		return invalidToken()
	}
	return unavailable()
}

type consentDecision struct {
	TransactionID string
	Action        string
}

func readDecision(w http.ResponseWriter, r *http.Request, v *consentDecision) error {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	d := json.NewDecoder(r.Body)
	invalid := errors.New("invalid consent JSON")
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return invalid
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return invalid
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return invalid
		}
		seen[key] = true
		switch key {
		case "transactionId":
			err = d.Decode(&v.TransactionID)
		case "action":
			err = d.Decode(&v.Action)
		default:
			return invalid
		}
		if err != nil {
			return invalid
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != 2 {
		return invalid
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return invalid
	}
	return nil
}
func singleValues(values url.Values) bool {
	for _, v := range values {
		if len(v) != 1 {
			return false
		}
	}
	return true
}
func form(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	if r.Header.Get("Authorization") != "" || len(r.URL.RawQuery) > 0 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		oauthError(w, 400, "invalid_request")
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if r.ParseForm() != nil || !singleValues(r.PostForm) {
		oauthError(w, 400, "invalid_request")
		return nil, false
	}
	return r.PostForm, true
}
func familyPrincipal(f cp.OAuthFamily) cp.Principal {
	return cp.Principal{UserID: f.UserID, ProviderID: f.ProviderID, Issuer: f.Issuer, Subject: f.Subject, Bearer: true, Scopes: slices.Clone(f.Scopes), SessionID: f.ID}
}

// AuthenticateBearer strongly checks a management token, its durable family
// and the current external identity. Cookies are deliberately not an input.
func (s *Server) AuthenticateBearer(ctx context.Context, authorization, resource string) (cp.Principal, error) {
	policy, ok := s.managementPolicy(resource)
	if !ok {
		return cp.Principal{}, invalidToken()
	}
	return s.authenticateBearer(ctx, authorization, policy)
}

func (s *Server) authenticateBearer(ctx context.Context, authorization string, policy resourcePolicy) (cp.Principal, error) {
	parts := strings.Split(authorization, " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !validSecret(parts[1]) {
		return cp.Principal{}, invalidToken()
	}
	rec, err := s.repo.Read(ctx, cp.RecordID{Kind: cp.AccessKind, ID: hash(parts[1])})
	if err != nil {
		return cp.Principal{}, readFailure(err)
	}
	token, err := cp.Decode[cp.OAuthToken](rec)
	if err != nil {
		return cp.Principal{}, unavailable()
	}
	now := time.Now()
	if token.Consumed || !now.Before(token.ExpiresAt) {
		return cp.Principal{}, invalidToken()
	}
	rec, err = s.repo.Read(ctx, cp.RecordID{Kind: cp.FamilyKind, ID: token.FamilyID})
	if err != nil {
		return cp.Principal{}, readFailure(err)
	}
	family, err := cp.Decode[cp.OAuthFamily](rec)
	if err != nil {
		return cp.Principal{}, unavailable()
	}
	if family.ID != token.FamilyID || family.Revoked || !now.Before(family.ExpiresAt) ||
		family.Resource != policy.Resource || family.ApplicationID != policy.ApplicationID ||
		family.ApplicationHost != policy.ApplicationHost || len(family.Scopes) == 0 {
		return cp.Principal{}, invalidToken()
	}
	if _, ok := parseScopes(strings.Join(family.Scopes, " "), policy.Scopes); !ok {
		return cp.Principal{}, invalidToken()
	}
	p, err := s.browser.CheckPrincipal(ctx, familyPrincipal(family))
	if err != nil {
		if isUnavailable(err) {
			return cp.Principal{}, unavailable()
		}
		return cp.Principal{}, invalidToken()
	}
	return p, nil
}
