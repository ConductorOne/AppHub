// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package auth verifies upstream identities and manages identity-bound browser
// sessions with local admission rechecks and CSRF protection.
package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/conductorone/apphub/credentials"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/serverconfig"
)

// Manager coordinates verified login transactions and durable browser sessions.
// Construct it with New so endpoint trust and cookie security are validated.
type Manager struct {
	*Eligibility
	origin    string
	secure    bool
	aead      cipher.AEAD
	providers map[string]*OIDCClient
}
type loginTransaction struct {
	ProviderID  string    `json:"providerId"`
	Issuer      string    `json:"issuer"`
	ClientID    string    `json:"clientId"`
	Callback    string    `json:"callback"`
	BindingHash string    `json:"bindingHash"`
	ReturnTo    string    `json:"returnTo"`
	Payload     []byte    `json:"payload"`
	ExpiresAt   time.Time `json:"expiresAt"`
}
type loginSecrets struct {
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

var providerIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// New validates provider trust, discovers every configured issuer, and requires
// persistence and a transaction-encryption key; failures never enable anonymous
// access. groups is optional -- see NewEligibility.
func New(ctx context.Context, cfg serverconfig.Config, repo cp.Repository, groups GroupLookup) (*Manager, error) {
	if repo == nil || len(cfg.Auth.Providers) == 0 || !safeEndpoint(cfg.PublicOrigin, cfg.Auth.AllowLoopbackHTTP) {
		return nil, unavailable()
	}
	origin, err := url.Parse(cfg.PublicOrigin)
	if err != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.ForceQuery {
		return nil, unavailable()
	}
	key := []byte(credentials.Reveal(cfg.Auth.TransactionKey))
	if len(key) != 32 {
		return nil, unavailable()
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, unavailable()
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, unavailable()
	}
	m := &Manager{Eligibility: NewEligibility(cfg.Auth, repo, groups), origin: cfg.PublicOrigin, secure: origin.Scheme == "https", aead: aead, providers: map[string]*OIDCClient{}}
	configurations := map[string]bool{}
	for _, p := range cfg.Auth.Providers {
		issuer := providerIssuer(p)
		key := issuer + "\x00" + p.ClientID
		if !providerIDPattern.MatchString(p.ID) || m.providers[p.ID] != nil || configurations[key] || (p.Kind != "google" && p.Kind != "oidc") || !safeEndpoint(issuer, cfg.Auth.AllowLoopbackHTTP) || len(p.AllowedDomains)+len(p.AllowedEmails) == 0 {
			return nil, unavailable()
		}
		if p.Kind == "google" && p.Issuer != "" && canonicalIssuer(p.Issuer) != GoogleIssuerURL {
			return nil, unavailable()
		}
		configurations[key] = true
		client, err := NewOIDCClient(ctx, Config{IssuerURL: issuer, ClientID: p.ClientID, ClientSecret: credentials.Reveal(p.ClientSecret), RedirectURL: m.origin + "/auth/" + p.ID + "/callback"})
		if err != nil {
			return nil, err
		}
		for _, endpoint := range []string{client.oauth2Config.Endpoint.AuthURL, client.oauth2Config.Endpoint.TokenURL, client.provider.UserInfoEndpoint(), client.jwksURL} {
			if endpoint != "" && !safeEndpoint(endpoint, cfg.Auth.AllowLoopbackHTTP) {
				return nil, unavailable()
			}
		}
		m.providers[p.ID] = client
	}
	return m, nil
}
func safeEndpoint(raw string, loopback bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return loopback && u.Scheme == "http" && ip != nil && ip.IsLoopback()
}

// Register installs provider discovery, login callbacks and browser-only logout.
func (m *Manager) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/auth/providers", m.listProviders)
	mux.HandleFunc("GET /auth/{providerId}/login", m.login)
	mux.HandleFunc("GET /auth/{providerId}/callback", m.callback)
	mux.HandleFunc("POST /auth/logout", m.logout)
}
func (m *Manager) listProviders(w http.ResponseWriter, _ *http.Request) {
	type providerView struct {
		ID       string `json:"id"`
		Label    string `json:"label"`
		Kind     string `json:"kind"`
		LoginURL string `json:"loginUrl"`
	}
	views := make([]providerView, 0, len(m.cfg.Providers))
	for _, p := range m.cfg.Providers {
		views = append(views, providerView{p.ID, p.Label, p.Kind, "/auth/" + p.ID + "/login"})
	}
	sendJSON(w, 200, struct {
		Providers []providerView `json:"providers"`
	}{views})
}
func (m *Manager) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id := r.PathValue("providerId")
	client := m.providers[id]
	if client == nil {
		m.loginError(w, r, cp.Problem(404, "not_found", "Identity provider not found."))
		return
	}
	state, nonce, verifier, binding := randomSecret(), randomSecret(), randomSecret(), randomSecret()
	stateHash := hash(state)
	payload, _ := json.Marshal(loginSecrets{nonce, verifier})
	iv := make([]byte, m.aead.NonceSize())
	_, _ = rand.Read(iv)
	encrypted := m.aead.Seal(iv, iv, payload, []byte(stateHash))
	tx := loginTransaction{ProviderID: id, Issuer: client.oauth2Config.Endpoint.AuthURL, ClientID: client.oauth2Config.ClientID, Callback: client.oauth2Config.RedirectURL, BindingHash: hash(binding), ReturnTo: safeReturn(r.URL.Query().Get("return_to")), Payload: encrypted, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	for _, p := range m.cfg.Providers {
		if p.ID == id {
			tx.Issuer = providerIssuer(p)
			break
		}
	}
	rec, err := cp.Encode(cp.RecordID{Kind: cp.LoginKind, ID: stateHash}, 0, tx)
	if err != nil || m.repo.Commit(r.Context(), []cp.Mutation{{Record: rec, ExpectedVersion: 0}}) != nil {
		m.loginError(w, r, unavailable())
		return
	}
	m.setCookie(w, m.loginCookieName(stateHash), binding, tx.ExpiresAt)
	http.Redirect(w, r, client.GetAuthURL(state, nonce, verifier), http.StatusFound)
}
func (m *Manager) callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q, err := url.ParseQuery(r.URL.RawQuery)
	state := q.Get("state")
	// A callback only clears its own cookie; unrelated concurrent attempts survive.
	if state != "" {
		m.clearCookie(w, m.loginCookieName(hash(state)))
	}
	if err != nil || len(q["state"]) != 1 || !validSecret(state) || len(q["code"]) > 1 || len(q["error"]) > 1 {
		m.loginError(w, r, invalidLogin())
		return
	}
	id := r.PathValue("providerId")
	client := m.providers[id]
	if client == nil {
		m.loginError(w, r, invalidLogin())
		return
	}
	rec, err := m.repo.Read(r.Context(), cp.RecordID{Kind: cp.LoginKind, ID: hash(state)})
	if err != nil {
		if errors.Is(err, cp.ErrNotFound) {
			m.loginError(w, r, invalidLogin())
		} else {
			m.loginError(w, r, unavailable())
		}
		return
	}
	tx, err := cp.Decode[loginTransaction](rec)
	cookie, cookieErr := r.Cookie(m.loginCookieName(hash(state)))
	issuer := ""
	for _, p := range m.cfg.Providers {
		if p.ID == id {
			issuer = providerIssuer(p)
			break
		}
	}
	if err != nil || cookieErr != nil || !validSecret(cookie.Value) || tx.ProviderID != id || tx.Issuer != issuer || tx.ClientID != client.oauth2Config.ClientID || tx.Callback != client.oauth2Config.RedirectURL || !time.Now().Before(tx.ExpiresAt) || subtle.ConstantTimeCompare([]byte(hash(cookie.Value)), []byte(tx.BindingHash)) != 1 {
		m.loginError(w, r, invalidLogin())
		return
	}
	if err := m.repo.Commit(r.Context(), []cp.Mutation{{Record: rec, ExpectedVersion: rec.Version, Delete: true}}); err != nil {
		if errors.Is(err, cp.ErrConflict) {
			m.loginError(w, r, invalidLogin())
		} else {
			m.loginError(w, r, unavailable())
		}
		return
	}
	if q.Get("error") != "" || q.Get("code") == "" {
		m.loginError(w, r, invalidLogin())
		return
	}
	if len(tx.Payload) < m.aead.NonceSize() {
		m.loginError(w, r, invalidLogin())
		return
	}
	data, err := m.aead.Open(nil, tx.Payload[:m.aead.NonceSize()], tx.Payload[m.aead.NonceSize():], []byte(hash(state)))
	if err != nil {
		m.loginError(w, r, invalidLogin())
		return
	}
	var secrets loginSecrets
	if json.Unmarshal(data, &secrets) != nil {
		m.loginError(w, r, invalidLogin())
		return
	}
	info, err := client.Exchange(r.Context(), q.Get("code"), secrets.Verifier, secrets.Nonce)
	if err != nil {
		m.loginError(w, r, err)
		return
	}
	if info.Issuer != tx.Issuer {
		m.loginError(w, r, invalidLogin())
		return
	}
	var provider serverconfig.ProviderConfig
	for _, p := range m.cfg.Providers {
		if p.ID == id {
			provider = p
			break
		}
	}
	if !provider.Admits(info.Email, info.EmailVerified) {
		m.loginError(w, r, cp.Problem(403, "admission_denied", "This identity is not admitted to AppHub."))
		return
	}
	token, session, err := m.establish(r.Context(), id, info)
	if err != nil {
		m.loginError(w, r, err)
		return
	}
	m.logAdminHintIfNeeded(id, info)
	m.setCookie(w, m.sessionCookieName(), token, session.ExpiresAt)
	http.Redirect(w, r, safeReturn(tx.ReturnTo), http.StatusSeeOther)
}

// logAdminHintIfNeeded prints the exact auth.admins entry an operator would add
// to grant this identity admin authority. It is the only discovery path for that
// value -- there is no admin-management UI -- so it fires on every non-admin
// login rather than only during initial bootstrap. Never gates or grants access.
func (m *Manager) logAdminHintIfNeeded(providerID string, info *UserInfo) {
	for _, admin := range m.cfg.Admins {
		if admin.ProviderID == providerID && admin.Subject == info.ID {
			return
		}
	}
	slog.Info("apphub: signed in without admin authority; add this identity to auth.admins and restart the API to grant it",
		"providerId", providerID, "subject", info.ID, "email", info.Email)
}
func safeReturn(raw string) string {
	if raw == "" || len(raw) > 4096 {
		return "/applications"
	}
	checked := raw
	for range 8 {
		if !strings.HasPrefix(checked, "/") || strings.HasPrefix(checked, "//") || strings.ContainsAny(checked, "\\") {
			return "/applications"
		}
		for _, ch := range checked {
			if ch < 32 || ch == 127 {
				return "/applications"
			}
		}
		u, err := url.Parse(checked)
		if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" {
			return "/applications"
		}
		decoded, err := url.PathUnescape(checked)
		if err != nil {
			return "/applications"
		}
		if decoded == checked {
			return raw
		}
		checked = decoded
	}
	return "/applications"
}
func randomSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func validSecret(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func hash(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func (m *Manager) sessionCookieName() string {
	if m.secure {
		return "__Host-apphub_session"
	}
	return "apphub_session"
}
func (m *Manager) loginCookieName(h string) string {
	prefix := "apphub_login_"
	if m.secure {
		prefix = "__Host-" + prefix
	}
	return prefix + h[:32]
}
func (m *Manager) setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	// #nosec G124 -- New permits Secure=false only with explicit AllowLoopbackHTTP
	// and a literal loopback HTTP origin; HTTPS always uses Secure host-only cookies.
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: m.secure, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: int(time.Until(expires).Seconds())})
}
func (m *Manager) clearCookie(w http.ResponseWriter, name string) {
	// #nosec G124 -- Match the cookie being expired: New restricts Secure=false
	// to explicitly enabled literal-loopback HTTP development origins.
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/", Secure: m.secure, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}
func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, err error) {
	var p *cp.Error
	if !errors.As(err, &p) {
		p = unavailable()
	}
	sendJSON(w, p.Status, cp.ErrorResponse{Error: p, RequestID: uuid()})
}
func (m *Manager) loginError(w http.ResponseWriter, r *http.Request, err error) {
	if !strings.Contains(r.Header.Get("Accept"), "text/html") {
		writeError(w, err)
		return
	}
	var problem *cp.Error
	if !errors.As(err, &problem) {
		problem = unavailable()
	}
	code := "invalid_callback"
	if problem.Status == 503 || problem.Status == 404 {
		code = "provider_unavailable"
	} else if problem.Code == "admission_denied" {
		code = problem.Code
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/login?error="+code, http.StatusSeeOther)
}
