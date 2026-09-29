// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/credhttp"
)

// DefaultAPIBaseURL is the GitHub REST API root for github.com. A GitHub
// Enterprise Server deployment overrides it with its own /api/v3 root.
const DefaultAPIBaseURL = "https://api.github.com"

// MaxAppJWTLifetime is the upper bound GitHub allows on app JWTs, less a minute
// of clock-skew allowance. The claim set back-dates iat by the same minute, so
// the signed window is exactly the ten minutes GitHub permits.
const MaxAppJWTLifetime = 9 * time.Minute

// maxDrainBytes bounds how much of a discarded error body is read to let the
// connection be reused.
const maxDrainBytes = 4 << 10

// maxTokenBodyBytes bounds how much of a token response is decoded.
const maxTokenBodyBytes = 1 << 20

// ErrFullInstallationGrant means a token request asked for no restriction at all
// without saying so.
//
// It is the fundamental form of a defect review found one layer up: the provider
// treated a present-but-blank scoping value as an absent one, and GitHub reads an
// absent scoping field as "grant everything the installation can reach". So a
// blank value in operator configuration escalated a two-repository token to every
// repository, silently.
//
// Fixing the parsing was necessary and is not sufficient, because the shape of
// the bug is that the widest possible grant was the default that any parsing
// mistake fell into. This error moves the refusal underneath every caller: an
// unrestricted request has to be asked for by name
// (InstallationTokenRequest.FullInstallationGrant), so no future parsing bug in
// any caller can produce one by omission.
var ErrFullInstallationGrant = errors.New("githubapp: an unrestricted installation token must set FullInstallationGrant")

// ErrBaseURL means the configured API base URL is not a URL this client will
// send an app JWT to. See the package comment for why that is refused rather
// than normalized.
var ErrBaseURL = errors.New("githubapp: invalid API base URL")

// App is a configured GitHub App, ready to mint installation tokens.
//
// It holds an RSA private key, so it is credential-bearing: do not log it, do
// not serialize it, and do not put it in an error.
type App struct {
	appID      int64
	privateKey *rsa.PrivateKey
	baseURL    string
	http       *credhttp.Client
}

// AppConfig is the input to NewApp.
type AppConfig struct {
	// AppID is the numeric GitHub App ID. Required.
	AppID int64

	// PrivateKeyPEM is the app's RSA private key, PEM-encoded. Required, and
	// material: it arrives in a credentials.Secret so that the only place it
	// exists as a string is the one call that parses it.
	PrivateKeyPEM credentials.Secret

	// BaseURL overrides the API root for GitHub Enterprise Server. Empty means
	// DefaultAPIBaseURL. Must be an absolute https URL; see ErrBaseURL.
	BaseURL string

	// Transport is the HTTP transport used for every call. Optional: nil uses a
	// shared default.
	//
	// It is a http.RoundTripper and not an *http.Client deliberately. Redirect
	// refusal is a field on http.Client, so an earlier version of this field let a
	// caller supplying a client for tracing or a test silently re-enable redirects
	// -- and every request here carries an app JWT, which is higher privilege than
	// any installation token it can be exchanged for. A RoundTripper cannot
	// express a redirect policy, so this field cannot be used to remove one. See
	// internal/credhttp.
	Transport http.RoundTripper
}

// NewApp validates the configuration and parses the private key.
//
// It performs no network I/O: an App that cannot be built without reaching
// GitHub is an App that cannot be built in a hermetic test either.
func NewApp(cfg AppConfig) (*App, error) {
	if cfg.AppID <= 0 {
		return nil, errors.New("githubapp: app ID is required and must be positive")
	}
	base, err := NormalizeBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	key, err := parsePrivateKeyPEM(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &App{appID: cfg.AppID, privateKey: key, baseURL: base, http: credhttp.New(cfg.Transport)}, nil
}

// NormalizeBaseURL returns the API root to use, or ErrBaseURL.
//
// The constraints are deliberately narrow: this URL decides where an app JWT is
// sent, so anything ambiguous is refused rather than guessed at. A path is
// allowed because GitHub Enterprise Server serves its API under /api/v3.
// Callers that store a destination without constructing an App must use this
// same validation before persisting it.
func NormalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultAPIBaseURL, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: not a URL", ErrBaseURL)
	}
	switch {
	case u.Opaque != "":
		return "", fmt.Errorf("%w: must not be an opaque URL", ErrBaseURL)
	case u.Scheme != "https":
		return "", fmt.Errorf("%w: scheme must be https", ErrBaseURL)
	case u.Host == "":
		return "", fmt.Errorf("%w: no host", ErrBaseURL)
	case u.User != nil:
		return "", fmt.Errorf("%w: must not carry userinfo", ErrBaseURL)
	case u.RawQuery != "" || u.ForceQuery:
		return "", fmt.Errorf("%w: must not carry a query string", ErrBaseURL)
	case u.Fragment != "":
		return "", fmt.Errorf("%w: must not carry a fragment", ErrBaseURL)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// parsePrivateKeyPEM decodes a PEM-encoded RSA private key, accepting both
// PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") blocks because GitHub
// has emitted both.
//
// No error from this function mentions the key: a parse failure on key material
// is exactly the place where a helpful error message becomes a leak.
func parsePrivateKeyPEM(material credentials.Secret) (*rsa.PrivateKey, error) {
	pemData := credentials.Reveal(material)
	if strings.TrimSpace(pemData) == "" {
		return nil, errors.New("githubapp: private key is required")
	}
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("githubapp: private key is not valid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("githubapp: private key is neither a PKCS#1 nor a PKCS#8 RSA key")
	}
	rsaKey, ok := anyKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("githubapp: private key is a %T, not RSA", anyKey)
	}
	return rsaKey, nil
}

// jwtHeaderRS256 is the fixed header for app JWTs.
var jwtHeaderRS256 = []byte(`{"alg":"RS256","typ":"JWT"}`)

// appJWTClaims is the claim set GitHub expects. RFC 7519 defines iss as a
// StringOrURI, so the app ID is rendered as a decimal string; GitHub still
// accepts a JSON number, but emitting a string keeps this conformant.
type appJWTClaims struct {
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
}

// mintAppJWT signs an RS256 JWT for app-level calls, valid for
// MaxAppJWTLifetime with iat back-dated sixty seconds to tolerate clock drift
// between this process and GitHub.
//
// There is no lifetime parameter because there is nothing here that would ever
// want a different one, and a parameter with one possible value is a branch
// nothing exercises.
//
// The result is credential material: it authenticates as the app itself, which
// is strictly more privilege than any installation token it can be exchanged
// for.
func (a *App) mintAppJWT() (credentials.Secret, error) {
	now := time.Now()
	claims := appJWTClaims{
		Iat: now.Add(-60 * time.Second).Unix(),
		Exp: now.Add(MaxAppJWTLifetime).Unix(),
		Iss: strconv.FormatInt(a.appID, 10),
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return credentials.Secret{}, errors.New("githubapp: encoding the app JWT claims failed")
	}

	signingInput := base64.RawURLEncoding.EncodeToString(jwtHeaderRS256) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return credentials.Secret{}, errors.New("githubapp: signing the app JWT failed")
	}
	return credentials.NewSecret(signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)), nil
}

// InstallationTokenRequest is the scoping for an installation token.
//
// Every empty field widens the grant, because that is how GitHub's API reads an
// omitted field: no repositories named means every repository the installation
// can reach, and no permissions named means every permission the app holds. That
// makes the widest possible token the value that any parsing mistake falls into,
// which is exactly the defect review found in the layer above this one.
//
// So the widest token is not reachable by omission here. A request that restricts
// nothing is refused with ErrFullInstallationGrant unless it says
// FullInstallationGrant. Naming it is one line in a caller and it is visible in a
// diff; arriving at it by accident now takes a deliberate statement rather than a
// blank string.
type InstallationTokenRequest struct {
	// RepositoryIDs restricts the token to these repository IDs.
	RepositoryIDs []int64
	// Repositories restricts the token to these repository names (no owner).
	Repositories []string
	// Permissions restricts the token to a subset of the installation's
	// permissions, e.g. {"contents": "read"}.
	Permissions map[string]string

	// FullInstallationGrant asks for a token carrying everything the installation
	// can reach: every repository, every permission the app holds.
	//
	// It is a legitimate request -- "vend me a token for this installation" is the
	// ordinary case -- and it must be a request rather than a default. Setting it
	// alongside a restriction is refused too: a caller that has said both things
	// does not know which it meant, and guessing in the widening direction is the
	// mistake this field exists to make unreachable.
	FullInstallationGrant bool
}

// restricts reports whether the request narrows the grant at all.
func (r InstallationTokenRequest) restricts() bool {
	return len(r.RepositoryIDs) > 0 || len(r.Repositories) > 0 || len(r.Permissions) > 0
}

// validate refuses a request whose grant is wider than it says.
func (r InstallationTokenRequest) validate() error {
	switch {
	case r.restricts() && r.FullInstallationGrant:
		return fmt.Errorf("%w: a request cannot both restrict the token and ask for the full grant", ErrFullInstallationGrant)
	case !r.restricts() && !r.FullInstallationGrant:
		return ErrFullInstallationGrant
	default:
		return nil
	}
}

// InstallationToken is GitHub's answer from the access_tokens endpoint.
type InstallationToken struct {
	// Token is the installation access token. Material.
	Token credentials.Secret `json:"token"`
	// ExpiresAt is when GitHub will stop accepting it. GitHub enforces an upper
	// bound of one hour, and it is authoritative: the token really does stop
	// working then, without anything here having to tear it down.
	ExpiresAt time.Time `json:"expires_at"`
	// Permissions is what the token actually carries.
	Permissions map[string]string `json:"permissions"`
	// Repositories is the repository set, when the token is repository-scoped.
	Repositories []TokenRepository `json:"repositories,omitempty"`
	// RepositorySelection is "all" or "selected".
	RepositorySelection string `json:"repository_selection,omitempty"`
}

// TokenRepository is the slim repository object returned alongside a token.
type TokenRepository struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

// MintInstallationToken creates a scoped installation access token. GitHub caps
// the lifetime at one hour and this client does not ask for anything else: the
// TTL is GitHub's to decide, and InstallationToken.ExpiresAt reports what it
// chose.
func (a *App) MintInstallationToken(ctx context.Context, installationID int64, opts InstallationTokenRequest) (*InstallationToken, error) {
	if installationID <= 0 {
		return nil, errors.New("githubapp: installation ID is required and must be positive")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}

	body := map[string]any{}
	if len(opts.RepositoryIDs) > 0 {
		body["repository_ids"] = opts.RepositoryIDs
	}
	if len(opts.Repositories) > 0 {
		body["repositories"] = opts.Repositories
	}
	if len(opts.Permissions) > 0 {
		body["permissions"] = opts.Permissions
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			return nil, errors.New("githubapp: encoding the token request failed")
		}
		bodyReader = bytes.NewReader(bodyJSON)
	}

	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", a.baseURL, installationID)
	resp, err := a.doAppRequest(ctx, http.MethodPost, endpoint, credhttp.OpGitHubAppMintInstallationToken(), bodyReader)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return nil, statusError(credhttp.OpGitHubAppMintInstallationToken(), resp)
	}

	var out InstallationToken
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenBodyBytes)).Decode(&out); err != nil {
		return nil, errors.New("githubapp: token response was not the expected JSON")
	}
	if out.Token.IsZero() {
		return nil, errors.New("githubapp: token response carried no token")
	}
	if out.ExpiresAt.IsZero() {
		return nil, errors.New("githubapp: token response carried no expiry")
	}
	return &out, nil
}

// doAppRequest issues a request authenticated with a freshly minted app JWT.
//
// A fresh JWT per request rather than a cached one: the JWT is the app's highest
// privilege, it is valid for minutes, and caching it buys one RSA signature.
//
// op is the only detail that reaches a transport-failure error. It is a
// credhttp.Op and not a string, so the label cannot be built from anything that
// arrived from outside; see internal/credhttp.
func (a *App) doAppRequest(ctx context.Context, method, endpoint string, op credhttp.Op, body io.Reader) (*http.Response, error) {
	jwt, err := a.mintAppJWT()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("%s: building the request failed", op)
	}
	req.Header.Set("Authorization", "Bearer "+credentials.Reveal(jwt))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// credhttp.Client.Do refuses redirects and classifies its own errors. That is
	// what keeps the app JWT out of a transport's diagnostic text, which review
	// demonstrated was otherwise returned verbatim. See internal/credhttp.
	resp, err := a.http.Do(req, op)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// doTokenRequest is doAppRequest authenticated with an installation access
// token instead of an app JWT. The token is material and reaches only the
// Authorization header.
func (a *App) doTokenRequest(ctx context.Context, method, endpoint string, token credentials.Secret, op credhttp.Op) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: building the request failed", op)
	}
	req.Header.Set("Authorization", "Bearer "+credentials.Reveal(token))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := a.http.Do(req, op)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// statusError turns a non-2xx response into an error.
//
// It carries the status code and the operation, and nothing from the response
// body. The source interpolated the body; a body this process did not write is a
// body that can quote back the app JWT or the token it just minted, and an error
// is the one string that reliably reaches a log. The cost is real -- GitHub's
// "message" field is genuinely useful -- and it is paid on purpose. See the same
// decision, and the test that forced it, in credentials/datadog.
//
// Retryable statuses are marked with credentials.ErrTransient so the reconciler
// can tell "come back later" from "this will never work".
func statusError(op credhttp.Op, resp *http.Response) error {
	// The body is drained rather than read so the connection can be reused; its
	// content is deliberately discarded.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))

	if isTransientStatus(resp.StatusCode) {
		return fmt.Errorf("%s failed (%d): %w", op, resp.StatusCode, credentials.ErrTransient)
	}
	return fmt.Errorf("%s failed (%d)", op, resp.StatusCode)
}

// isTransientStatus reports whether a status is worth retrying: rate limits, and
// anything the server admits is its own fault.
func isTransientStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// Installation is one row of GET /app/installations: an account that has
// installed this app.
type Installation struct {
	ID                  int64               `json:"id"`
	Account             InstallationAccount `json:"account"`
	RepositorySelection string              `json:"repository_selection"`
	Permissions         map[string]string   `json:"permissions"`
	Events              []string            `json:"events"`
	SuspendedAt         *time.Time          `json:"suspended_at,omitempty"`
	HTMLURL             string              `json:"html_url"`
}

// InstallationAccount is the organization or user that installed the app.
type InstallationAccount struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"` // "Organization" | "User"
}

// ErrInstallationsTruncated is returned by ListInstallations when more
// installations exist than the safety cap allows enumerating. The partial
// slice is also returned but must not be treated as authoritative: in
// particular, a caller that prunes local records missing from this result
// must refuse to prune when this error is returned, or it deletes a record
// for an installation that still exists past the cap.
var ErrInstallationsTruncated = errors.New("githubapp: installation list exceeded safety cap")

// listInstallationsMaxPages is a sanity cap, not a real-world limit: at 100
// installs per page this permits up to 1,000,000 installations. It exists so
// a misbehaving API or a logic bug cannot loop forever, not to bound a real
// deployment -- which is why it is intentionally far above any real scale.
const listInstallationsMaxPages = 10000

// maxInstallationsBodyBytes bounds one page of the installations response.
const maxInstallationsBodyBytes = 4 << 20

// ListInstallations fetches every installation visible to this app,
// paginating to completion. See [ErrInstallationsTruncated] for what a caller
// must not do with a truncated result.
func (a *App) ListInstallations(ctx context.Context) ([]Installation, error) {
	const perPage = 100
	var all []Installation
	for page := 1; page <= listInstallationsMaxPages; page++ {
		endpoint := fmt.Sprintf("%s/app/installations?per_page=%d&page=%d", a.baseURL, perPage, page)
		resp, err := a.doAppRequest(ctx, http.MethodGet, endpoint, credhttp.OpGitHubAppListInstallations(), nil)
		if err != nil {
			return all, err
		}
		if resp.StatusCode >= 400 {
			err := statusError(credhttp.OpGitHubAppListInstallations(), resp)
			return all, err
		}
		var batch []Installation
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxInstallationsBodyBytes)).Decode(&batch)
		_ = resp.Body.Close()
		if decodeErr != nil {
			return all, errors.New("githubapp: installations response was not the expected JSON")
		}
		all = append(all, batch...)
		if len(batch) < perPage {
			return all, nil
		}
	}
	// Hit the safety cap with a full final page -- there are likely more.
	return all, ErrInstallationsTruncated
}

// maxInstallationRepositories bounds how many repository URLs one
// installation contributes to the deploy form. Past that, the form still
// accepts a pasted URL; the list is a convenience, not the allowlist.
const maxInstallationRepositories = 500

// ListInstallationRepositories returns canonical https://github.com/owner/repo
// URLs for repositories this installation can access, up to
// maxInstallationRepositories. It mints a full installation token to do
// that and discards it with the call.
func (a *App) ListInstallationRepositories(ctx context.Context, installationID int64) ([]string, error) {
	if installationID <= 0 {
		return nil, errors.New("githubapp: installation ID is required and must be positive")
	}
	tok, err := a.MintInstallationToken(ctx, installationID, InstallationTokenRequest{FullInstallationGrant: true})
	if err != nil {
		return nil, err
	}
	const perPage = 100
	seen := map[string]bool{}
	var urls []string
	for page := 1; len(urls) < maxInstallationRepositories; page++ {
		endpoint := fmt.Sprintf("%s/installation/repositories?per_page=%d&page=%d", a.baseURL, perPage, page)
		resp, err := a.doTokenRequest(ctx, http.MethodGet, endpoint, tok.Token, credhttp.OpGitHubAppListInstallationRepositories())
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 400 {
			return nil, statusError(credhttp.OpGitHubAppListInstallationRepositories(), resp)
		}
		var body struct {
			Repositories []struct {
				FullName string `json:"full_name"`
			} `json:"repositories"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxInstallationsBodyBytes)).Decode(&body)
		_ = resp.Body.Close()
		if decodeErr != nil {
			return nil, errors.New("githubapp: installation repositories response was not the expected JSON")
		}
		if len(body.Repositories) == 0 {
			break
		}
		for _, repo := range body.Repositories {
			raw, ok := installationRepositoryURL(repo.FullName)
			if !ok || seen[raw] {
				continue
			}
			seen[raw] = true
			urls = append(urls, raw)
			if len(urls) >= maxInstallationRepositories {
				break
			}
		}
		if len(body.Repositories) < perPage {
			break
		}
	}
	return urls, nil
}

// installationRepositoryURL accepts GitHub's owner/name full_name and nothing
// else. A value with a slash in the wrong place, a space, or a control
// character is dropped rather than turned into a URL the form would offer.
func installationRepositoryURL(fullName string) (string, bool) {
	owner, name, ok := strings.Cut(fullName, "/")
	if !ok || strings.Contains(name, "/") || owner == "" || name == "" {
		return "", false
	}
	if strings.ContainsAny(owner, " \t\r\n?#\\") || strings.ContainsAny(name, " \t\r\n?#\\") {
		return "", false
	}
	return "https://github.com/" + owner + "/" + name, true
}

// GetInstallationByOwner returns the installation matching the given account
// login (case-insensitive), or nil if the app is not installed there. It
// tries the organization endpoint first, then the user endpoint, since
// GitHub exposes no single lookup that covers both account kinds.
func (a *App) GetInstallationByOwner(ctx context.Context, login string) (*Installation, error) {
	target := strings.TrimSpace(login)
	if target == "" {
		return nil, errors.New("githubapp: owner is required")
	}
	inst, err := a.getInstallation(ctx, "orgs", target)
	if err != nil || inst != nil {
		return inst, err
	}
	return a.getInstallation(ctx, "users", target)
}

func (a *App) getInstallation(ctx context.Context, kind, login string) (*Installation, error) {
	endpoint := fmt.Sprintf("%s/%s/%s/installation", a.baseURL, kind, url.PathEscape(login))
	resp, err := a.doAppRequest(ctx, http.MethodGet, endpoint, credhttp.OpGitHubAppGetInstallation(), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		var inst Installation
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenBodyBytes)).Decode(&inst); err != nil {
			return nil, errors.New("githubapp: installation response was not the expected JSON")
		}
		return &inst, nil
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, statusError(credhttp.OpGitHubAppGetInstallation(), resp)
	}
}
