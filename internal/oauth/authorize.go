// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !singleValues(q) || len(r.URL.RawQuery) > 16<<10 {
		oauthError(w, 400, "invalid_request")
		return
	}
	clientID, redirect := q.Get("client_id"), q.Get("redirect_uri")
	if err = s.validateClient(r.Context(), clientID, redirect); err != nil {
		oauthError(w, 400, "invalid_client")
		return
	}
	state := q.Get("state")
	if state == "" || len(state) > 2048 || strings.IndexFunc(state, func(c rune) bool { return c < 32 || c == 127 }) >= 0 {
		oauthError(w, 400, "invalid_request")
		return
	}
	issuer := s.issuerForRequest(r)
	reject := func(code string) {
		// #nosec G710 -- validateClient above requires an exact registered/CIMD
		// HTTPS redirect, or apphub-cli's literal 127.0.0.1 ephemeral callback.
		http.Redirect(w, r, callbackURL(redirect, state, issuer, "error", code), http.StatusFound)
	}
	for key := range q {
		if key != "client_id" && key != "redirect_uri" && key != "state" && key != "response_type" && key != "resource" && key != "scope" && key != "code_challenge" && key != "code_challenge_method" {
			reject("invalid_request")
			return
		}
	}
	if q.Get("response_type") != "code" {
		reject("unsupported_response_type")
		return
	}
	policy, ok := s.policyForRequest(r, q.Get("resource"))
	if !ok {
		reject("invalid_target")
		return
	}
	requested, ok := parseScopes(q.Get("scope"), policy.Scopes)
	if !ok {
		reject("invalid_scope")
		return
	}
	if q.Get("code_challenge_method") != "S256" || !validSecret(q.Get("code_challenge")) {
		reject("invalid_request")
		return
	}
	p, session, err := s.browser.Browser(r)
	if err != nil {
		var problem *cp.Error
		if errors.As(err, &problem) && problem.Status == 401 && r.Header.Get("Authorization") == "" {
			http.Redirect(w, r, "/login?"+url.Values{"return_to": {r.URL.RequestURI()}}.Encode(), http.StatusFound)
			return
		}
		if isUnavailable(err) {
			oauthError(w, 503, "temporarily_unavailable")
		} else {
			oauthError(w, 401, "login_required")
		}
		return
	}
	now := time.Now().UTC()
	id := secret()
	tx := consentTransaction{SessionID: p.SessionID, Principal: p, ClientID: clientID, RedirectURI: redirect, State: state, Resource: policy.Resource, Issuer: policy.Issuer, Scopes: requested, ApplicationID: policy.ApplicationID, ApplicationHost: policy.ApplicationHost, Challenge: q.Get("code_challenge"), ExpiresAt: now.Add(codeLifetime)}
	// Bind transaction creation to the live session as well as the later consume.
	sr, err := s.repo.Read(r.Context(), cp.RecordID{Kind: cp.SessionKind, ID: p.SessionID})
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	live, err := cp.Decode[cp.Session](sr)
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	if live.Revoked || live.ID != session.ID || !now.Before(live.ExpiresAt) {
		oauthError(w, 401, "login_required")
		return
	}
	err = s.repo.Commit(r.Context(), []cp.Mutation{mutation(cp.ConsentKind, hash(id), 0, tx), mutation(cp.SessionKind, p.SessionID, sr.Version, live)})
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	http.Redirect(w, r, "/authorize?"+url.Values{"transactionId": {id}}.Encode(), http.StatusFound)
}
func callbackURL(redirect, state, issuer, key, value string) string {
	u, _ := url.Parse(redirect)
	q := u.Query()
	q.Set("state", state)
	q.Set("iss", issuer)
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// Consent returns only server-validated request details and only to the browser
// session which initiated that authorization, never to a delegated bearer.
func (s *Server) Consent(ctx context.Context, p cp.Principal, id string) (cp.ConsentView, error) {
	if p.Bearer || p.SessionID == "" || !validSecret(id) {
		return cp.ConsentView{}, notFound()
	}
	checked, err := s.browser.CheckPrincipal(ctx, p)
	if err != nil {
		return cp.ConsentView{}, err
	}
	rec, err := s.repo.Read(ctx, cp.RecordID{Kind: cp.ConsentKind, ID: hash(id)})
	if err != nil {
		if errors.Is(err, cp.ErrNotFound) {
			return cp.ConsentView{}, notFound()
		}
		return cp.ConsentView{}, unavailable()
	}
	tx, err := cp.Decode[consentTransaction](rec)
	if err != nil {
		return cp.ConsentView{}, unavailable()
	}
	if tx.Consumed || !time.Now().Before(tx.ExpiresAt) || tx.SessionID != checked.SessionID || tx.Principal.UserID != checked.UserID {
		return cp.ConsentView{}, notFound()
	}
	sr, err := s.repo.Read(ctx, cp.RecordID{Kind: cp.SessionKind, ID: p.SessionID})
	if err != nil {
		return cp.ConsentView{}, readFailure(err)
	}
	session, err := cp.Decode[cp.Session](sr)
	if err != nil {
		return cp.ConsentView{}, unavailable()
	}
	if session.Revoked || !time.Now().Before(session.ExpiresAt) {
		return cp.ConsentView{}, invalidToken()
	}
	ir, err := s.repo.Read(ctx, cp.RecordID{Kind: cp.IdentityKind, ID: p.Subject, ParentID: p.Issuer})
	if err != nil {
		return cp.ConsentView{}, readFailure(err)
	}
	identity, err := cp.Decode[cp.ExternalIdentity](ir)
	if err != nil {
		return cp.ConsentView{}, unavailable()
	}
	return cp.ConsentView{TransactionID: id, ClientID: tx.ClientID, RedirectURI: tx.RedirectURI, Resource: tx.Resource, Scopes: tx.Scopes, ExpiresAt: tx.ExpiresAt, Identity: cp.IdentityView{ProviderID: identity.ProviderID, Issuer: identity.Issuer, Subject: identity.Subject, Email: identity.Email}}, nil
}
func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	p, session, err := s.browser.Browser(r)
	if err != nil {
		if isUnavailable(err) {
			oauthError(w, 503, "temporarily_unavailable")
		} else {
			oauthError(w, 401, "login_required")
		}
		return
	}
	if err = s.browser.RequireCSRF(r, session); err != nil {
		oauthError(w, 403, "access_denied")
		return
	}
	var in consentDecision
	if readDecision(w, r, &in) != nil || !validSecret(in.TransactionID) || (in.Action != "approve" && in.Action != "deny") {
		oauthError(w, 400, "invalid_request")
		return
	}
	rec, err := s.repo.Read(r.Context(), cp.RecordID{Kind: cp.ConsentKind, ID: hash(in.TransactionID)})
	if err != nil {
		if errors.Is(err, cp.ErrNotFound) {
			oauthError(w, 400, "invalid_request")
		} else {
			oauthError(w, 503, "temporarily_unavailable")
		}
		return
	}
	tx, err := cp.Decode[consentTransaction](rec)
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	now := time.Now().UTC()
	if tx.Consumed || !now.Before(tx.ExpiresAt) || tx.SessionID != p.SessionID || tx.Principal.UserID != p.UserID {
		oauthError(w, 400, "invalid_request")
		return
	}
	sr, err := s.repo.Read(r.Context(), cp.RecordID{Kind: cp.SessionKind, ID: p.SessionID})
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	live, err := cp.Decode[cp.Session](sr)
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	if live.Revoked || live.ID != session.ID || !now.Before(live.ExpiresAt) {
		oauthError(w, 401, "login_required")
		return
	}
	issuer := tx.Issuer
	if issuer == "" {
		issuer = s.origin
	}
	if in.Action == "approve" && tx.ApplicationID != "" {
		if _, policyErr := s.validateStoredHostedPolicy(r.Context(), tx.ApplicationID, tx.ApplicationHost, tx.Resource, issuer); policyErr != nil {
			if isUnavailable(policyErr) {
				oauthError(w, 503, "temporarily_unavailable")
			} else {
				oauthError(w, 400, "invalid_request")
			}
			return
		}
	}
	tx.Consumed = true
	writes := []cp.Mutation{mutation(cp.ConsentKind, hash(in.TransactionID), rec.Version, tx), mutation(cp.SessionKind, p.SessionID, sr.Version, live)}
	redirect := callbackURL(tx.RedirectURI, tx.State, issuer, "error", "access_denied")
	if in.Action == "approve" {
		raw := secret()
		code := authorizationCode{Principal: p, ClientID: tx.ClientID, RedirectURI: tx.RedirectURI, Resource: tx.Resource, Issuer: issuer, Scopes: tx.Scopes, ApplicationID: tx.ApplicationID, ApplicationHost: tx.ApplicationHost, Challenge: tx.Challenge, ExpiresAt: now.Add(codeLifetime)}
		writes = append(writes, mutation(cp.CodeKind, hash(raw), 0, code))
		redirect = callbackURL(tx.RedirectURI, tx.State, issuer, "code", raw)
	}
	if err = s.repo.Commit(r.Context(), writes); err != nil {
		if errors.Is(err, cp.ErrConflict) {
			oauthError(w, 400, "invalid_request")
		} else {
			oauthError(w, 503, "temporarily_unavailable")
		}
		return
	}
	// Fetch clients explicitly navigate this URL; issuing a 302 here would make
	// fetch follow an unrelated origin and obscure the correlated response.
	sendJSON(w, 200, map[string]string{"redirectUrl": redirect})
}
