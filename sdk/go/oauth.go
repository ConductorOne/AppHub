// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

const requestedScopes = "applications:read applications:write deployments:read deployments:write"

func (c *Client) readMetadata(ctx context.Context, endpoint string, value any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("OAuth discovery unavailable")
	}
	defer func() { _ = response.Body.Close() }() // Read/status errors determine the discovery outcome.
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("OAuth discovery failed (HTTP %d)", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 || json.Unmarshal(body, value) != nil {
		return errors.New("invalid OAuth discovery response")
	}
	return nil
}

func (c *Client) discover(ctx context.Context) error {
	var resource ProtectedResourceMetadata
	if err := c.readMetadata(ctx, "/.well-known/oauth-protected-resource/api", &resource); err != nil {
		return err
	}
	if resource.Resource != c.origin+"/api" || len(resource.AuthorizationServers) != 1 || resource.AuthorizationServers[0] != c.origin {
		return errors.New("OAuth protected-resource discovery does not match the selected AppHub server")
	}
	var meta AuthorizationServerMetadata
	if err := c.readMetadata(ctx, "/.well-known/oauth-authorization-server", &meta); err != nil {
		return err
	}
	// This client speaks the fixed AppHub contract, not arbitrary endpoints
	// advertised by an untrusted metadata document. Validate before code/token use.
	if meta.Issuer != c.origin || meta.AuthorizationEndpoint != c.origin+"/oauth/authorize" || meta.TokenEndpoint != c.origin+"/oauth/token" || meta.RevocationEndpoint != c.origin+"/oauth/revoke" || !bool(meta.AuthorizationResponseIssParameterSupported) || !slices.Contains(meta.CodeChallengeMethodsSupported, "S256") || !slices.Contains(meta.ResponseTypesSupported, "code") || !slices.Contains(meta.GrantTypesSupported, "authorization_code") || !slices.Contains(meta.GrantTypesSupported, "refresh_token") || !slices.Contains(meta.TokenEndpointAuthMethodsSupported, "none") {
		return errors.New("OAuth discovery issuer, endpoints, or security capabilities do not match the AppHub contract")
	}
	return nil
}

func randomSecret() string {
	var b [32]byte
	// crypto/rand.Read fills the complete buffer or terminates on an irrecoverable
	// randomness failure with supported Go toolchains.
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// NewIdempotencyKey creates an opaque key to retain for one logical mutation.
func NewIdempotencyKey() string { return randomSecret() }

type callbackResult struct {
	code string
	err  error
}

func callbackHandler(state, issuer, redirectHost string, result chan<- callbackResult) http.Handler {
	var delivered atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		q, err := url.ParseQuery(r.URL.RawQuery)
		// Uncorrelated callbacks, including OAuth errors, do not end the login.
		// Validate RFC 9207 issuer before processing either error or authorization code.
		if err != nil || r.Host != redirectHost || len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 || len(q["iss"]) != 1 || q.Get("iss") != issuer || (q.Has("resource") && (len(q["resource"]) != 1 || q.Get("resource") != issuer+"/api")) {
			http.Error(w, "Uncorrelated login response; return to the original login tab.", http.StatusBadRequest)
			return
		}
		answer := callbackResult{}
		if len(q["error"]) == 1 && q.Get("error") != "" && !q.Has("code") {
			answer.err = errors.New("AppHub authorization was denied or failed; start login again")
		} else if len(q["code"]) == 1 && q.Get("code") != "" && !q.Has("error") {
			answer.code = q.Get("code")
		} else {
			http.Error(w, "Invalid login response.", http.StatusBadRequest)
			return
		}
		if !delivered.CompareAndSwap(false, true) {
			http.Error(w, "Login response already received.", http.StatusConflict)
			return
		}
		result <- answer
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "Login response received. Return to the terminal to confirm completion. You can close this tab.")
	})
	return mux
}

// Login performs authorization-code/S256 PKCE against the selected AppHub
// issuer. noBrowser prints the same browser URL; it is not a device-code flow.
// output is for prompts (CLI callers pass stderr).
func Login(ctx context.Context, server string, noBrowser bool, output io.Writer) (*Client, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if output == nil {
		output = io.Discard
	}
	c, err := NewClient(server)
	if err != nil {
		return nil, err
	}
	if err := c.discover(ctx); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind login callback: %w", err)
	}
	defer func() { _ = listener.Close() }() // Also covers cleanup before Serve owns the listener.
	redirect := "http://" + listener.Addr().String() + "/callback"
	state, verifier := randomSecret(), randomSecret()
	hash := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])},
		"code_challenge_method": {"S256"}, "resource": {c.origin + "/api"}, "scope": {requestedScopes},
	}
	authorizationURL := c.origin + "/oauth/authorize?" + query.Encode()
	results := make(chan callbackResult, 1)
	callback := &http.Server{Handler: callbackHandler(state, c.origin, listener.Addr().String(), results), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- callback.Serve(listener) }()
	defer func() { _ = callback.Close() }() // Callback cleanup cannot undo an exchanged and persisted token.
	// The socket is bound and the handler installed before launching the browser.
	if _, err := fmt.Fprintf(output, "Complete AppHub login in your browser:\n%s\n", authorizationURL); err != nil {
		return nil, err
	}
	if !noBrowser {
		if err := openBrowser(authorizationURL); err != nil {
			_, _ = fmt.Fprintln(output, "Could not open a browser; open the URL above manually.")
		}
	}
	var result callbackResult
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("login observation canceled or timed out: %w", ctx.Err())
	case err := <-serveErrors:
		return nil, fmt.Errorf("login callback server stopped: %w", err)
	case result = <-results:
	}
	if result.err != nil {
		return nil, result.err
	}
	s, err := openCredentials(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close()
	tok, err := c.postToken(ctx, url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {result.code}, "redirect_uri": {redirect}, "code_verifier": {verifier}, "resource": {c.origin + "/api"}})
	if err != nil {
		return nil, err
	}
	key := credentialKey(c.origin)
	s.data.Entries[key] = credential{Server: c.origin, Resource: c.origin + "/api", ClientID: clientID, AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, ExpiresAt: time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)}
	s.data.Current = key
	if err := s.save(); err != nil {
		return nil, fmt.Errorf("persist login: %w", err)
	}
	return c, nil
}

func refreshForm(token, resource string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {token}, "resource": {resource}}
}

func (c *Client) postToken(ctx context.Context, form url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("OAuth token exchange outcome uncertain; login again")
	}
	defer func() { _ = response.Body.Close() }() // Preserve a valid rotated token; close errors must not discard it.
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OAuth token exchange failed (HTTP %d); login again", response.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(b) > 64<<10 {
		return nil, errors.New("OAuth token response unavailable; login again")
	}
	var tok TokenResponse
	if json.Unmarshal(b, &tok) != nil || tok.AccessToken == "" || tok.RefreshToken == "" || !strings.EqualFold(string(tok.TokenType), "Bearer") || tok.ExpiresIn <= 0 || tok.ExpiresIn > 86400 || strings.ContainsAny(tok.AccessToken+tok.RefreshToken, "\r\n\x00") {
		return nil, errors.New("invalid OAuth token response; login again")
	}
	if tok.Scope != "" {
		for _, scope := range strings.Fields(tok.Scope) {
			if !slices.Contains(strings.Fields(requestedScopes), scope) {
				return nil, errors.New("unexpected OAuth scope; login again")
			}
		}
	}
	return &tok, nil
}

func (c *Client) revoke(ctx context.Context, token string) error {
	if token == "" {
		return ErrReauthenticationRequired
	}
	form := url.Values{"client_id": {clientID}, "token": {token}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/oauth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("OAuth revocation unavailable; credentials retained, retry logout")
	}
	defer func() { _ = response.Body.Close() }() // Revocation is determined by the response status.
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("OAuth revocation failed (HTTP %d); credentials retained, retry logout", response.StatusCode)
	}
	return nil
}

func openBrowser(rawURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL) // #nosec G204 -- Login constructs this HTTPS/literal-loopback URL from canonicalServer and url.Values; no shell or caller-selected executable.
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL) // #nosec G204 -- Login constructs this HTTPS/literal-loopback URL from canonicalServer and url.Values; fixed DLL handler, no shell.
	default:
		cmd = exec.Command("xdg-open", rawURL) // #nosec G204 -- Login constructs this HTTPS/literal-loopback URL from canonicalServer and url.Values; no shell or caller-selected executable.
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
