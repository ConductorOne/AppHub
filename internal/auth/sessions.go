// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

func (m *Manager) establish(ctx context.Context, providerID string, info *UserInfo) (string, cp.Session, error) {
	identityID := cp.RecordID{Kind: cp.IdentityKind, ID: info.ID, ParentID: info.Issuer}
	for range 4 {
		now := time.Now().UTC()
		ir, err := m.repo.Read(ctx, identityID)
		fresh := errors.Is(err, cp.ErrNotFound)
		if err != nil && !fresh {
			return "", cp.Session{}, unavailable()
		}
		var user cp.User
		var ur cp.Record
		if fresh {
			user = cp.User{ID: uuid(), CreatedAt: now}
		} else {
			identity, decodeErr := cp.Decode[cp.ExternalIdentity](ir)
			if decodeErr != nil || identity.Issuer != info.Issuer || identity.Subject != info.ID {
				return "", cp.Session{}, unavailable()
			}
			ur, err = m.repo.Read(ctx, cp.RecordID{Kind: cp.UserKind, ID: identity.UserID})
			if err != nil {
				return "", cp.Session{}, readAuthError(err)
			}
			user, err = cp.Decode[cp.User](ur)
			if err != nil || user.ID != identity.UserID {
				return "", cp.Session{}, unavailable()
			}
			if user.Disabled {
				return "", cp.Session{}, unauthorized()
			}
		}
		user.Email = strings.ToLower(strings.TrimSpace(info.Email))
		user.Name = info.Name
		user.Avatar = info.AvatarURL
		user.UpdatedAt = now
		identity := cp.ExternalIdentity{UserID: user.ID, ProviderID: providerID, Issuer: info.Issuer, Subject: info.ID, Email: user.Email, EmailVerified: info.EmailVerified, Name: info.Name, Avatar: info.AvatarURL, UpdatedAt: now}
		token := randomSecret()
		session := cp.Session{ID: uuid(), UserID: user.ID, ProviderID: providerID, Issuer: info.Issuer, Subject: info.ID, CSRF: randomSecret(), CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
		identityRecord, e1 := cp.Encode(identityID, ir.Version, identity)
		userRecord, e2 := cp.Encode(cp.RecordID{Kind: cp.UserKind, ID: user.ID}, ur.Version, user)
		sessionRecord, e3 := cp.Encode(cp.RecordID{Kind: cp.SessionKind, ID: hash(token)}, 0, session)
		if e1 != nil || e2 != nil || e3 != nil {
			return "", cp.Session{}, unavailable()
		}
		err = m.repo.Commit(ctx, []cp.Mutation{{Record: identityRecord, ExpectedVersion: ir.Version}, {Record: userRecord, ExpectedVersion: ur.Version}, {Record: sessionRecord, ExpectedVersion: 0}})
		if err == nil {
			return token, session, nil
		}
		if !errors.Is(err, cp.ErrConflict) {
			return "", cp.Session{}, unavailable()
		}
	}
	return "", cp.Session{}, unavailable()
}

// Browser authenticates an unexpired, unrevoked cookie session and rechecks
// admission. Any Authorization header forbids cookie fallback.
func (m *Manager) Browser(r *http.Request) (cp.Principal, cp.Session, error) {
	if _, present := r.Header["Authorization"]; present {
		return cp.Principal{}, cp.Session{}, unauthorized()
	}
	// Header map access also covers manually constructed noncanonical requests.
	for k := range r.Header {
		if strings.EqualFold(k, "Authorization") {
			return cp.Principal{}, cp.Session{}, unauthorized()
		}
	}
	cookie, err := r.Cookie(m.sessionCookieName())
	if err != nil || !validSecret(cookie.Value) {
		return cp.Principal{}, cp.Session{}, unauthorized()
	}
	rec, err := m.repo.Read(r.Context(), cp.RecordID{Kind: cp.SessionKind, ID: hash(cookie.Value)})
	if err != nil {
		return cp.Principal{}, cp.Session{}, readAuthError(err)
	}
	session, err := cp.Decode[cp.Session](rec)
	if err != nil {
		return cp.Principal{}, cp.Session{}, unavailable()
	}
	if session.Revoked || !time.Now().Before(session.ExpiresAt) {
		return cp.Principal{}, cp.Session{}, unauthorized()
	}
	p, err := m.CheckPrincipal(r.Context(), cp.Principal{UserID: session.UserID, ProviderID: session.ProviderID, Issuer: session.Issuer, Subject: session.Subject, SessionID: rec.ID})
	if err != nil {
		return cp.Principal{}, cp.Session{}, err
	}
	return p, session, nil
}

// RequireCSRF requires exactly one trusted Origin and a session-bound CSRF token.
func (m *Manager) RequireCSRF(r *http.Request, session cp.Session) error {
	origins := r.Header.Values("Origin")
	tokens := r.Header.Values("X-CSRF-Token")
	if len(origins) != 1 || origins[0] != m.origin || len(tokens) != 1 || session.CSRF == "" || subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(session.CSRF)) != 1 {
		return cp.Problem(403, "csrf_failed", "The browser request could not be verified.")
	}
	return nil
}
func (m *Manager) logout(w http.ResponseWriter, r *http.Request) {
	p, s, err := m.Browser(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err = m.RequireCSRF(r, s); err != nil {
		writeError(w, err)
		return
	}
	if err = m.revokeRecord(r.Context(), p, cp.RecordID{Kind: cp.SessionKind, ID: p.SessionID}); err != nil {
		writeError(w, err)
		return
	}
	m.clearCookie(w, m.sessionCookieName())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// Me returns the caller's current profile and effective actions after admission
// revalidation; bearer callers never receive the browser CSRF token.
func (m *Manager) Me(ctx context.Context, p cp.Principal, csrf string) (cp.UserView, error) {
	p, err := m.CheckPrincipal(ctx, p)
	if err != nil {
		return cp.UserView{}, err
	}
	rec, err := m.repo.Read(ctx, cp.RecordID{Kind: cp.UserKind, ID: p.UserID})
	if err != nil {
		return cp.UserView{}, readAuthError(err)
	}
	user, err := cp.Decode[cp.User](rec)
	if err != nil {
		return cp.UserView{}, unavailable()
	}
	ir, err := m.repo.Read(ctx, cp.RecordID{Kind: cp.IdentityKind, ID: p.Subject, ParentID: p.Issuer})
	if err != nil {
		return cp.UserView{}, readAuthError(err)
	}
	identity, err := cp.Decode[cp.ExternalIdentity](ir)
	if err != nil {
		return cp.UserView{}, unavailable()
	}
	actions := []string{cp.ApplicationsRead, cp.DeploymentsRead}
	if p.Role != cp.RoleMember {
		actions = append(actions, cp.ApplicationsWrite, cp.DeploymentsWrite)
	}
	if p.Bearer {
		actions = append([]string{}, p.Scopes...)
		csrf = ""
	}
	role := p.Role
	if role == "" {
		// Reached only by a Principal that skipped CheckPrincipal (not this
		// method's own caller, which always revalidates first): the
		// pre-role-mapping default, matching resolveAccess's own fallback.
		role = cp.RoleMember
	}
	features := p.Features
	if features == nil {
		features = []string{}
	}
	return cp.UserView{ID: user.ID, Email: user.Email, Name: user.Name, Avatar: user.Avatar, Role: role, VulnAdmin: p.VulnAdmin, EnabledFeatures: features, PermittedActions: actions, CSRFToken: csrf, Identity: cp.IdentityView{ProviderID: p.ProviderID, Issuer: p.Issuer, Subject: p.Subject, Email: identity.Email}}, nil
}

type sessionCursor struct {
	Kind   cp.RecordKind `json:"kind"`
	Cursor string        `json:"cursor"`
}

// ListSessions returns only the caller's browser and OAuth sessions, using
// bounded pagination and authoritative rereads before exposing session details.
func (m *Manager) ListSessions(ctx context.Context, p cp.Principal, options cp.ListOptions) (cp.Page[cp.SessionView], error) {
	p, err := m.CheckPrincipal(ctx, p)
	if err != nil {
		return cp.Page[cp.SessionView]{}, err
	}
	limit := options.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 || len(options.Cursor) > 8192 {
		return cp.Page[cp.SessionView]{}, cp.Problem(400, "invalid_pagination", "Invalid session pagination.")
	}
	cursor := sessionCursor{Kind: cp.SessionKind}
	if options.Cursor != "" {
		data, e := base64.RawURLEncoding.DecodeString(options.Cursor)
		if e != nil || json.Unmarshal(data, &cursor) != nil || (cursor.Kind != cp.SessionKind && cursor.Kind != cp.FamilyKind) {
			return cp.Page[cp.SessionView]{}, cp.Problem(400, "invalid_cursor", "Invalid session cursor.")
		}
	}
	result := cp.Page[cp.SessionView]{Items: []cp.SessionView{}}
	for len(result.Items) < limit {
		page, e := m.repo.Query(ctx, cp.Query{Kind: cursor.Kind, OwnerUserID: p.UserID, Limit: limit - len(result.Items), Cursor: cursor.Cursor})
		if e != nil {
			if errors.Is(e, cp.ErrInvalidCursor) {
				return cp.Page[cp.SessionView]{}, cp.Problem(400, "invalid_cursor", "Invalid session cursor.")
			}
			return cp.Page[cp.SessionView]{}, unavailable()
		}
		for _, index := range page.Records {
			rec, e := m.repo.Read(ctx, index.RecordID)
			if errors.Is(e, cp.ErrNotFound) {
				continue
			}
			if e != nil {
				return cp.Page[cp.SessionView]{}, unavailable()
			}
			view, owner, e := sessionView(rec, p)
			if e != nil {
				return cp.Page[cp.SessionView]{}, unavailable()
			}
			if owner == p.UserID {
				result.Items = append(result.Items, view)
			}
		}
		cursor.Cursor = page.Cursor
		if page.Cursor == "" {
			if cursor.Kind == cp.FamilyKind {
				return result, nil
			}
			cursor.Kind = cp.FamilyKind
		}
		// Empty filtered index pages still carry continuation; do not claim empty inventory.
	}
	data, _ := json.Marshal(cursor)
	result.Cursor = base64.RawURLEncoding.EncodeToString(data)
	return result, nil
}
func sessionView(rec cp.Record, p cp.Principal) (cp.SessionView, string, error) {
	if rec.Kind == cp.SessionKind {
		s, err := cp.Decode[cp.Session](rec)
		return cp.SessionView{ID: s.ID, Kind: "browser", Identity: cp.IdentityView{ProviderID: s.ProviderID, Issuer: s.Issuer, Subject: s.Subject}, Current: !p.Bearer && p.SessionID == rec.ID, Revoked: s.Revoked, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt}, s.UserID, err
	}
	s, err := cp.Decode[cp.OAuthFamily](rec)
	return cp.SessionView{ID: s.ID, Kind: "oauth", ClientID: s.ClientID, Resource: s.Resource, Scopes: s.Scopes, Identity: cp.IdentityView{ProviderID: s.ProviderID, Issuer: s.Issuer, Subject: s.Subject}, Current: p.Bearer && p.SessionID == rec.ID, Revoked: s.Revoked, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt}, s.UserID, err
}

// RevokeSession durably revokes an owned session by its nonsecret display ID.
// Only browser principals may manage sessions; delegated clients use OAuth revocation.
func (m *Manager) RevokeSession(ctx context.Context, p cp.Principal, displayID string) error {
	p, err := m.CheckPrincipal(ctx, p)
	if err != nil {
		return err
	}
	// Settings-wide revocation is browser authority, not one of the delegated
	// application/deployment scopes. Delegated clients revoke at /oauth/revoke.
	if p.Bearer {
		return cp.Problem(403, "browser_session_required", "Use a browser session to manage sessions.")
	}
	if displayID == "" || len(displayID) > 128 {
		return cp.Problem(404, "not_found", "Session not found.")
	}
	for _, kind := range []cp.RecordKind{cp.SessionKind, cp.FamilyKind} {
		cursor := ""
		for {
			page, err := m.repo.Query(ctx, cp.Query{Kind: kind, OwnerUserID: p.UserID, Limit: 100, Cursor: cursor})
			if err != nil {
				return unavailable()
			}
			for _, index := range page.Records {
				view, owner, err := sessionView(index, p)
				if err != nil {
					return unavailable()
				}
				if view.ID == displayID && owner == p.UserID {
					return m.revokeRecord(ctx, p, index.RecordID)
				}
			}
			if page.Cursor == "" {
				break
			}
			cursor = page.Cursor
		}
	}
	return cp.Problem(404, "not_found", "Session not found.")
}
func (m *Manager) revokeRecord(ctx context.Context, p cp.Principal, id cp.RecordID) error {
	for range 4 {
		rec, err := m.repo.Read(ctx, id)
		if err != nil {
			if errors.Is(err, cp.ErrNotFound) {
				return cp.Problem(404, "not_found", "Session not found.")
			}
			return unavailable()
		}
		view, owner, err := sessionView(rec, p)
		if err != nil {
			return unavailable()
		}
		if owner != p.UserID {
			return cp.Problem(404, "not_found", "Session not found.")
		}
		if view.Revoked {
			return nil
		}
		var updated cp.Record
		if id.Kind == cp.SessionKind {
			s, e := cp.Decode[cp.Session](rec)
			if e != nil {
				return unavailable()
			}
			s.Revoked = true
			updated, err = cp.Encode(id, rec.Version, s)
		} else {
			s, e := cp.Decode[cp.OAuthFamily](rec)
			if e != nil {
				return unavailable()
			}
			s.Revoked = true
			updated, err = cp.Encode(id, rec.Version, s)
		}
		if err != nil {
			return unavailable()
		}
		err = m.repo.Commit(ctx, []cp.Mutation{{Record: updated, ExpectedVersion: rec.Version}})
		if err == nil {
			return nil
		}
		if !errors.Is(err, cp.ErrConflict) {
			return unavailable()
		}
	}
	return unavailable()
}
