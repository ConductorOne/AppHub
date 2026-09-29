// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	values, ok := form(w, r)
	if !ok {
		return
	}
	switch values.Get("grant_type") {
	case "authorization_code":
		if !onlyFields(values, "grant_type", "client_id", "redirect_uri", "code", "code_verifier", "resource") {
			oauthError(w, 400, "invalid_request")
			return
		}
		s.exchange(w, r, values)
	case "refresh_token":
		if !onlyFields(values, "grant_type", "client_id", "refresh_token", "resource") {
			oauthError(w, 400, "invalid_request")
			return
		}
		s.refresh(w, r, values)
	default:
		oauthError(w, 400, "unsupported_grant_type")
	}
}
func onlyFields(v url.Values, allowed ...string) bool {
	for k := range v {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func tokenError(w http.ResponseWriter, err error) {
	if isUnavailable(err) {
		oauthError(w, 503, "temporarily_unavailable")
	} else {
		oauthError(w, 400, "invalid_grant")
	}
}
func (s *Server) exchange(w http.ResponseWriter, r *http.Request, v url.Values) {
	policy, validPolicy := s.policyForRequest(r, v.Get("resource"))
	if !validSecret(v.Get("code")) || !verifierPattern.MatchString(v.Get("code_verifier")) || !validPolicy {
		oauthError(w, 400, "invalid_grant")
		return
	}
	rec, err := s.repo.Read(r.Context(), cp.RecordID{Kind: cp.CodeKind, ID: hash(v.Get("code"))})
	if err != nil {
		tokenError(w, readFailure(err))
		return
	}
	code, err := cp.Decode[authorizationCode](rec)
	if err != nil {
		tokenError(w, unavailable())
		return
	}
	challengeBytes := sha256.Sum256([]byte(v.Get("code_verifier")))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	now := time.Now().UTC()
	if code.Consumed || !now.Before(code.ExpiresAt) || code.ClientID != v.Get("client_id") ||
		code.RedirectURI != v.Get("redirect_uri") || code.Resource != policy.Resource ||
		code.Issuer != policy.Issuer || code.ApplicationID != policy.ApplicationID ||
		code.ApplicationHost != policy.ApplicationHost ||
		subtle.ConstantTimeCompare([]byte(challenge), []byte(code.Challenge)) != 1 {
		oauthError(w, 400, "invalid_grant")
		return
	}
	p, err := s.browser.CheckPrincipal(r.Context(), code.Principal)
	if err != nil {
		tokenError(w, err)
		return
	}
	family := cp.OAuthFamily{ID: uuid(), UserID: p.UserID, ProviderID: p.ProviderID, Issuer: p.Issuer, Subject: p.Subject, ClientID: code.ClientID, Resource: code.Resource, Scopes: code.Scopes, ApplicationID: code.ApplicationID, ApplicationHost: code.ApplicationHost, CreatedAt: now, ExpiresAt: now.Add(familyLifetime)}
	response, tokens := newTokens(family, now)
	code.Consumed = true
	writes := []cp.Mutation{mutation(cp.CodeKind, rec.ID, rec.Version, code), mutation(cp.FamilyKind, family.ID, 0, family)}
	writes = append(writes, tokens...)
	if err = s.repo.Commit(r.Context(), writes); err != nil {
		if errors.Is(err, cp.ErrConflict) {
			oauthError(w, 400, "invalid_grant")
		} else {
			tokenError(w, unavailable())
		}
		return
	}
	sendJSON(w, 200, response)
}
func newTokens(f cp.OAuthFamily, now time.Time) (tokenResponse, []cp.Mutation) {
	access, refresh := secret(), secret()
	expires := now.Add(accessLifetime)
	if f.ExpiresAt.Before(expires) {
		expires = f.ExpiresAt
	}
	response := tokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(expires.Sub(now) / time.Second), RefreshToken: refresh, Scope: strings.Join(f.Scopes, " ")}
	writes := []cp.Mutation{mutation(cp.AccessKind, hash(access), 0, cp.OAuthToken{FamilyID: f.ID, ExpiresAt: expires}), mutation(cp.RefreshKind, hash(refresh), 0, cp.OAuthToken{FamilyID: f.ID, ExpiresAt: f.ExpiresAt})}
	return response, writes
}
func (s *Server) refresh(w http.ResponseWriter, r *http.Request, v url.Values) {
	policy, validPolicy := s.policyForRequest(r, v.Get("resource"))
	if !validSecret(v.Get("refresh_token")) || v.Get("client_id") == "" || !validPolicy {
		oauthError(w, 400, "invalid_grant")
		return
	}
	rec, err := s.repo.Read(r.Context(), cp.RecordID{Kind: cp.RefreshKind, ID: hash(v.Get("refresh_token"))})
	if err != nil {
		tokenError(w, readFailure(err))
		return
	}
	token, err := cp.Decode[cp.OAuthToken](rec)
	if err != nil {
		tokenError(w, unavailable())
		return
	}
	fr, err := s.repo.Read(r.Context(), cp.RecordID{Kind: cp.FamilyKind, ID: token.FamilyID})
	if err != nil {
		tokenError(w, readFailure(err))
		return
	}
	family, err := cp.Decode[cp.OAuthFamily](fr)
	if err != nil {
		tokenError(w, unavailable())
		return
	}
	now := time.Now().UTC()
	if family.ID != token.FamilyID || family.ClientID != v.Get("client_id") ||
		family.Resource != policy.Resource || family.ApplicationID != policy.ApplicationID ||
		family.ApplicationHost != policy.ApplicationHost || family.Revoked ||
		!now.Before(family.ExpiresAt) || !now.Before(token.ExpiresAt) {
		oauthError(w, 400, "invalid_grant")
		return
	}
	if token.Consumed {
		tokenError(w, s.rejectReplay(r.Context(), family.ID))
		return
	}
	if _, err = s.browser.CheckPrincipal(r.Context(), familyPrincipal(family)); err != nil {
		tokenError(w, err)
		return
	}
	response, writes := newTokens(family, now)
	// Refresh tombstones survive for the absolute family lifetime. Touching the
	// family in the same CAS transaction serializes refresh with every revocation.
	token.Consumed = true
	token.ExpiresAt = family.ExpiresAt
	writes = append(writes, mutation(cp.RefreshKind, rec.ID, rec.Version, token), mutation(cp.FamilyKind, fr.ID, fr.Version, family))
	if err = s.repo.Commit(r.Context(), writes); err != nil {
		if !errors.Is(err, cp.ErrConflict) {
			tokenError(w, unavailable())
			return
		}
		// Another refresh may have consumed this token while this request checked
		// eligibility. Treat that as replay, including parallel use of the secret.
		latest, readErr := s.repo.Read(r.Context(), rec.RecordID)
		if readErr != nil {
			tokenError(w, readFailure(readErr))
			return
		}
		used, decodeErr := cp.Decode[cp.OAuthToken](latest)
		if decodeErr != nil {
			tokenError(w, unavailable())
			return
		}
		if used.Consumed {
			tokenError(w, s.rejectReplay(r.Context(), family.ID))
			return
		}
		oauthError(w, 400, "invalid_grant")
		return
	}
	sendJSON(w, 200, response)
}
func (s *Server) rejectReplay(ctx context.Context, id string) error {
	if err := s.revokeFamily(ctx, id); err != nil {
		return err
	}
	return invalidToken()
}
func (s *Server) revokeFamily(ctx context.Context, id string) error {
	for range 8 {
		rec, err := s.repo.Read(ctx, cp.RecordID{Kind: cp.FamilyKind, ID: id})
		if err != nil {
			if errors.Is(err, cp.ErrNotFound) {
				return nil
			}
			return unavailable()
		}
		family, err := cp.Decode[cp.OAuthFamily](rec)
		if err != nil {
			return unavailable()
		}
		if family.Revoked {
			return nil
		}
		family.Revoked = true
		err = s.repo.Commit(ctx, []cp.Mutation{mutation(cp.FamilyKind, id, rec.Version, family)})
		if err == nil {
			return nil
		}
		if !errors.Is(err, cp.ErrConflict) {
			return unavailable()
		}
	}
	return unavailable()
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	v, ok := form(w, r)
	if !ok {
		return
	}
	if !onlyFields(v, "token", "token_type_hint", "client_id") || v.Get("client_id") == "" || v.Get("token") == "" {
		oauthError(w, 400, "invalid_request")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !validSecret(v.Get("token")) {
		w.WriteHeader(http.StatusOK)
		return
	}
	for _, kind := range []cp.RecordKind{cp.RefreshKind, cp.AccessKind} {
		rec, err := s.repo.Read(r.Context(), cp.RecordID{Kind: kind, ID: hash(v.Get("token"))})
		if errors.Is(err, cp.ErrNotFound) {
			continue
		}
		if err != nil {
			tokenError(w, unavailable())
			return
		}
		token, err := cp.Decode[cp.OAuthToken](rec)
		if err != nil {
			tokenError(w, unavailable())
			return
		}
		fr, err := s.repo.Read(r.Context(), cp.RecordID{Kind: cp.FamilyKind, ID: token.FamilyID})
		if errors.Is(err, cp.ErrNotFound) {
			w.WriteHeader(http.StatusOK)
			return
		}
		if err != nil {
			tokenError(w, unavailable())
			return
		}
		family, err := cp.Decode[cp.OAuthFamily](fr)
		if err != nil {
			tokenError(w, unavailable())
			return
		}
		if family.ClientID == v.Get("client_id") {
			if err = s.revokeFamily(r.Context(), family.ID); err != nil {
				tokenError(w, err)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
}
