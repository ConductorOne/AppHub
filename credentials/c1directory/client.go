// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1directory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/credhttp"
)

// Wire limits. This package's own bounds on what it will read, not
// restatements of the upstream's.
const (
	// maxResponseBodyBytes caps a decoded response. Union Station reads
	// the whole body; this is AppHub's extra bound so a runaway page cannot
	// fill memory.
	maxResponseBodyBytes = 32 << 20
	// maxDrainBytes caps how much of a failed response is read and discarded.
	maxDrainBytes = 1 << 16
	// pageSize is the page size requested on every search call.
	// ConductorOne accepts at most 100; Union Station's searchGroups and
	// listUserGrants both send 100.
	pageSize = 100
	// maxSearchPages bounds pagination so a misbehaving nextPageToken cannot
	// loop forever. 100 pages * 100/page = 10,000 entitlements, matching
	// Union Station's maxAllGroupsPages.
	maxSearchPages = 100
)

// tokenPath is the OAuth token endpoint, relative to Config.BaseURL. The same
// path credentials/c1 uses -- both packages talk to the same ConductorOne
// tenant API, just with different credentials and different routes beyond
// this one.
//
//nolint:gosec // G101: the name of an endpoint, not a credential.
const tokenPath = "/auth/v1/token"

// searchEntitlementsPath is the entitlement-catalog search endpoint, verified
// against the source system's own client (backend/internal/conductorone/client.go).
const searchEntitlementsPath = "/api/v1/search/entitlements"

// searchUsersPath resolves an email to a ConductorOne user ID. Verified
// against the source system's own client, Client.GetUserByEmail
// (backend/internal/conductorone/client.go:608-657).
const searchUsersPath = "/api/v1/search/users"

// searchGrantsPath lists the entitlements one ConductorOne user holds a
// grant on. Verified against the source system's own client, Client.listUserGrants
// (backend/internal/conductorone/client.go:685-751).
const searchGrantsPath = "/api/v1/search/grants"

// userSearchPageSize mirrors the source system's own GetUserByEmail, which asks
// for 10 candidates and then requires an exact, case-insensitive email match
// among them rather than trusting the search to return only one.
const userSearchPageSize = 10

// maxUserGrantPages bounds pagination of one user's grants. 1000 pages *
// 100/page = 100,000 grants, matching the source system's own
// maxUserGrantPages -- an order of magnitude above maxSearchPages because a
// single user's grants are pathological at a scale where the org-wide
// catalog is merely large.
const (
	maxUserGrantPages = 1000
	// maxGrantFilterIDs is SearchGrants' entitlement_refs max_items: 32.
	// Chunking keeps a 34-group catalog in two requests rather than one
	// rejected body.
	maxGrantFilterIDs = 32
)

// tokenRefreshSkew is how far before a token's stated expiry it is refreshed.
// Capped at half the token's own lifetime so a short-lived token cannot yield
// an already-expired one. Mirrors credentials/c1's own constant.
const tokenRefreshSkew = 5 * time.Minute

// Entitlement is one ConductorOne app entitlement, the shape a group and a
// finer-grained entitlement share on the wire. See doc.go for what
// distinguishes a "group" from an "entitlement" in this package: which search
// filter returned it, not a field on the object itself.
type Entitlement struct {
	ID          string
	DisplayName string
	Description string
	// AppID is the application or resource this entitlement grants access
	// to. Empty for a directory-wide group.
	AppID string
}

// Client is what this package's caller needs from ConductorOne's directory.
type Client interface {
	// ListGroups returns the subset of the entitlement catalog ConductorOne's
	// own automation can grant programmatically (isAutomated: true on the
	// search request).
	ListGroups(ctx context.Context) ([]Entitlement, error)

	// ListEntitlements returns the full entitlement catalog, including
	// directory-synced entries ListGroups would not.
	ListEntitlements(ctx context.Context) ([]Entitlement, error)

	// ListUserGroupIDs returns the IDs of every entitlement email currently
	// holds a grant on -- membership, not the catalog ListGroups and
	// ListEntitlements read. Unlike those two, there is no isAutomated
	// filter here: the grants-search endpoint reports what a specific user
	// holds, not what ConductorOne's own automation could grant.
	//
	// Returns an empty slice and a nil error, never ErrUnauthenticated or a
	// wrapped upstream failure, when email does not resolve to a
	// ConductorOne user at all: a locally admitted identity with no
	// ConductorOne account simply maps to no role, the same way
	// the source system's own GetUserGroups treats "user not found" as zero
	// groups rather than a caller-visible error.
	ListUserGroupIDs(ctx context.Context, email string) ([]string, error)

	// ListUserHeldEntitlementIDs is ListUserGroupIDs restricted to the
	// given catalog entries. The grants search is filtered with
	// entitlementRefs (appId + id), the SearchGrants request field, so a
	// user who holds tens of thousands of grants is not crawled page by
	// page. Empty refs, or refs missing appId, return an empty slice
	// without a grants call.
	ListUserHeldEntitlementIDs(ctx context.Context, email string, refs []EntitlementRef) ([]string, error)
}

// EntitlementRef identifies one catalog entitlement for a filtered grants
// search. Both fields are required: SearchGrants' entitlement_refs items
// validate app_id and id as 27-character identifiers.
type EntitlementRef struct {
	ID    string
	AppID string
}

// SecretResolver reads a secret from the deployment's secret store.
//
// Declared again here rather than shared with credentials/c1.SecretResolver:
// the two packages hold different credentials for different trust
// relationships (doc.go), and a shared type would be the one piece of code
// this design explicitly said not to share.
type SecretResolver interface {
	Resolve(ctx context.Context, ref credentials.SecretRef) (credentials.Secret, error)
}

// Deps are the collaborators this package needs from its host.
type Deps struct {
	// Secrets resolves cfg.ClientSecret at use. Required.
	Secrets SecretResolver
	// Transport is the HTTP transport used for every call. Optional: nil
	// means the shared default in internal/credhttp.
	Transport http.RoundTripper
}

// ErrSecretResolverRequired means Deps.Secrets was nil.
var ErrSecretResolverRequired = errors.New("c1directory: Deps.Secrets is required")

func (d Deps) validate() error {
	if d.Secrets == nil {
		return ErrSecretResolverRequired
	}
	return nil
}

// ErrUnauthenticated means AppHub's own directory credentials were rejected.
// An operator problem, not a caller's.
var ErrUnauthenticated = errors.New("c1directory: apphub is not authenticated to conductorone")

// ErrClientSecretUnresolved means the deployment's secret store did not
// return the directory client secret.
var ErrClientSecretUnresolved = errors.New("c1directory: the client secret could not be resolved")

// httpClient implements C1 directory reads and optional deployment provisioning.
type httpClient struct {
	cfg   Config
	deps  Deps
	http  *credhttp.Client
	token tokenCache
}

// NewClient returns a Client that talks to the ConductorOne tenant in cfg. It
// performs no network I/O.
func NewClient(cfg Config, deps Deps) (Client, error) {
	return newHTTPClient(cfg, deps)
}

func newHTTPClient(cfg Config, deps Deps) (*httpClient, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := deps.validate(); err != nil {
		return nil, err
	}
	return &httpClient{cfg: cfg, deps: deps, http: credhttp.New(deps.Transport)}, nil
}

func (c *httpClient) ListGroups(ctx context.Context) ([]Entitlement, error) {
	return c.searchEntitlements(ctx, true)
}

func (c *httpClient) ListEntitlements(ctx context.Context) ([]Entitlement, error) {
	return c.searchEntitlements(ctx, false)
}

func (c *httpClient) ListUserGroupIDs(ctx context.Context, email string) ([]string, error) {
	return c.listHeldEntitlementIDs(ctx, email, nil)
}

func (c *httpClient) ListUserHeldEntitlementIDs(ctx context.Context, email string, refs []EntitlementRef) ([]string, error) {
	refs = uniqueRefs(refs)
	if len(refs) == 0 {
		return []string{}, nil
	}
	return c.listHeldEntitlementIDs(ctx, email, refs)
}

func (c *httpClient) listHeldEntitlementIDs(ctx context.Context, email string, refs []EntitlementRef) ([]string, error) {
	userID, err := c.searchUserID(ctx, email)
	if err != nil {
		return nil, err
	}
	if userID == "" {
		return []string{}, nil
	}
	if len(refs) == 0 {
		return c.listUserGrantIDs(ctx, userID, nil)
	}
	var out []string
	seen := make(map[string]bool, len(refs))
	for start := 0; start < len(refs); start += maxGrantFilterIDs {
		end := min(start+maxGrantFilterIDs, len(refs))
		chunk, err := c.listUserGrantIDs(ctx, userID, refs[start:end])
		if err != nil {
			return nil, err
		}
		for _, id := range chunk {
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

func uniqueRefs(refs []EntitlementRef) []EntitlementRef {
	if len(refs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(refs))
	out := make([]EntitlementRef, 0, len(refs))
	for _, r := range refs {
		if r.ID == "" || r.AppID == "" {
			continue
		}
		key := r.AppID + "\x00" + r.ID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

// userSearchResponse is the POST /api/v1/search/users response, verified
// against the source system's own client: users nest under a "user" object per
// row, not directly under "list".
type userSearchResponse struct {
	List []struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	} `json:"list"`
}

// searchUserID resolves email to its ConductorOne user ID, requiring an
// exact case-insensitive match among the candidates the search returns
// (mirrors the source system's GetUserByEmail, which does not trust the search
// itself to return only one result). Returns "" when no candidate matches,
// which ListUserGroupIDs treats as "not a ConductorOne user", not an error.
func (c *httpClient) searchUserID(ctx context.Context, email string) (string, error) {
	body, err := json.Marshal(struct {
		Query    string `json:"query"`
		PageSize int    `json:"pageSize"`
	}{Query: email, PageSize: userSearchPageSize})
	if err != nil {
		return "", errors.New("c1directory: encoding the user search request failed")
	}

	op := credhttp.OpC1DirectorySearchUsers()
	resp, err := c.do(ctx, http.MethodPost, searchUsersPath, op, body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", statusError(op, resp)
	}

	var decoded userSearchResponse
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&decoded)
	_ = resp.Body.Close()
	if decodeErr != nil {
		return "", errors.New("c1directory: the user search response was not the expected JSON")
	}
	for _, item := range decoded.List {
		if strings.EqualFold(item.User.Email, email) {
			return item.User.ID, nil
		}
	}
	return "", nil
}

// grantsSearchResponse is the POST /api/v1/search/grants response, verified
// against the source system's own client: a grant's entitlement is denormalized
// under "entitlement.appEntitlement", the same appEntitlement shape
// searchResponse reads from the catalog endpoint.
type grantsSearchResponse struct {
	List []struct {
		Entitlement struct {
			AppEntitlement struct {
				ID string `json:"id"`
			} `json:"appEntitlement"`
		} `json:"entitlement"`
	} `json:"list"`
	NextPageToken string `json:"nextPageToken"`
}

// grantsSearchRequest is the POST /api/v1/search/grants body.
// EntitlementRefs is AppEntitlementSearchServiceSearchGrantsRequest's
// entitlement_refs (max 32), each requiring appId and id.
type grantsSearchRequest struct {
	UserID          string               `json:"userId"`
	EntitlementRefs []entitlementRefJSON `json:"entitlementRefs,omitempty"`
	PageSize        int                  `json:"pageSize"`
	PageToken       string               `json:"pageToken,omitempty"`
}

type entitlementRefJSON struct {
	AppID string `json:"appId"`
	ID    string `json:"id"`
}

// listUserGrantIDs paginates through grants the given ConductorOne user ID
// holds and returns the deduplicated entitlement IDs. When filter is
// nonempty, the search is restricted to those IDs. A cancelled context
// returns an error rather than a truncated list: Eligibility caches a
// successful result for GroupMembershipCacheTTL, so a partial crawl would
// stick as "not a member" of groups the timeout never reached.
func (c *httpClient) listUserGrantIDs(ctx context.Context, userID string, filter []EntitlementRef) ([]string, error) {
	allow := make(map[string]bool, len(filter))
	for _, r := range filter {
		allow[r.ID] = true
	}
	var out []string
	seen := make(map[string]bool)
	pageToken := ""

	for page := 0; page < maxUserGrantPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := grantsSearchRequest{UserID: userID, PageSize: pageSize, PageToken: pageToken}
		if len(filter) > 0 {
			refs := make([]entitlementRefJSON, len(filter))
			for i, r := range filter {
				refs[i] = entitlementRefJSON{AppID: r.AppID, ID: r.ID}
			}
			req.EntitlementRefs = refs
		}
		body, err := json.Marshal(req)
		if err != nil {
			return nil, errors.New("c1directory: encoding the grants search request failed")
		}

		op := credhttp.OpC1DirectorySearchGrants()
		resp, err := c.do(ctx, http.MethodPost, searchGrantsPath, op, body)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 400 {
			return nil, statusError(op, resp)
		}

		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("c1directory: reading the grants search response failed: %w", classifyRead(readErr))
		}
		if len(raw) > maxResponseBodyBytes {
			return nil, errors.New("c1directory: the grants search response was not the expected JSON")
		}
		var decoded grantsSearchResponse
		if json.Unmarshal(raw, &decoded) != nil {
			return nil, errors.New("c1directory: the grants search response was not the expected JSON")
		}

		for _, item := range decoded.List {
			id := item.Entitlement.AppEntitlement.ID
			if id == "" || seen[id] || (len(allow) > 0 && !allow[id]) {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}

		if decoded.NextPageToken == "" || len(decoded.List) == 0 {
			return out, nil
		}
		pageToken = decoded.NextPageToken
	}
	return out, nil
}

// searchRequest is the POST /api/v1/search/entitlements request body.
type searchRequest struct {
	PageSize    int    `json:"pageSize"`
	PageToken   string `json:"pageToken,omitempty"`
	IsAutomated bool   `json:"isAutomated,omitempty"`
}

// searchResponse is the POST /api/v1/search/entitlements response, the same
// nested appEntitlement shape Union Station's searchGroups unmarshals.
type searchResponse struct {
	List []struct {
		AppEntitlement struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			Description string `json:"description"`
			AppID       string `json:"appId"`
		} `json:"appEntitlement"`
	} `json:"list"`
	NextPageToken string `json:"nextPageToken"`
}

// classifyDecode classifies an Unmarshal failure without echoing the body.
func classifyDecode(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return errEmptyJSON
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return errTruncatedJSON
	}
	if classified := classifyRead(err); !errors.Is(classified, errReadFailed) {
		return classified
	}
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("%w at offset %d", errMalformedJSON, se.Offset)
	}
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		if ute.Field != "" {
			return fmt.Errorf("%w (%s)", errMalformedJSON, ute.Field)
		}
		if ute.Value != "" {
			return fmt.Errorf("%w (%s)", errMalformedJSON, ute.Value)
		}
	}
	return errMalformedJSON
}

func bodyKind(raw []byte) string {
	s := bytes.TrimSpace(raw)
	if len(s) == 0 {
		return "empty"
	}
	switch s[0] {
	case '{':
		return "json-object"
	case '[':
		return "json-array"
	case '<':
		return "html"
	case '"':
		return "json-string"
	default:
		if s[0] < 0x20 || s[0] > 0x7e {
			return "binary"
		}
		return "text"
	}
}

var (
	errEmptyJSON     = errors.New("empty body")
	errTruncatedJSON = errors.New("truncated body")
	errMalformedJSON = errors.New("malformed body")
	errReadTimeout   = errors.New("deadline exceeded")
	errReadCanceled  = errors.New("canceled")
	errReadFailed    = errors.New("read failed")
)

func classifyRead(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return errReadTimeout
	case errors.Is(err, context.Canceled):
		return errReadCanceled
	default:
		var ne interface{ Timeout() bool }
		if errors.As(err, &ne) && ne.Timeout() {
			return errReadTimeout
		}
		return errReadFailed
	}
}

func (c *httpClient) searchEntitlements(ctx context.Context, automatedOnly bool) ([]Entitlement, error) {
	var out []Entitlement
	seen := make(map[string]bool)
	pageToken := ""

	for page := 0; page < maxSearchPages; page++ {
		body, err := json.Marshal(searchRequest{PageSize: pageSize, PageToken: pageToken, IsAutomated: automatedOnly})
		if err != nil {
			return nil, errors.New("c1directory: encoding the search request failed")
		}

		op := credhttp.OpC1DirectorySearchEntitlements()
		resp, err := c.do(ctx, http.MethodPost, searchEntitlementsPath, op, body)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode >= 400 {
			return nil, statusError(op, resp)
		}

		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("c1directory: reading the search response failed: %w", classifyRead(readErr))
		}
		if len(raw) > maxResponseBodyBytes {
			return nil, fmt.Errorf("c1directory: the search response was not the expected JSON: %w (%s, %d bytes)", errTruncatedJSON, bodyKind(raw[:maxResponseBodyBytes]), maxResponseBodyBytes)
		}
		var decoded searchResponse
		if decodeErr := json.Unmarshal(raw, &decoded); decodeErr != nil {
			return nil, fmt.Errorf("c1directory: the search response was not the expected JSON: %w (%s, %d bytes)", classifyDecode(decodeErr), bodyKind(raw), len(raw))
		}

		for _, item := range decoded.List {
			ent := item.AppEntitlement
			if ent.ID == "" || seen[ent.ID] {
				continue
			}
			seen[ent.ID] = true
			out = append(out, Entitlement{
				ID:          ent.ID,
				DisplayName: ent.DisplayName,
				Description: ent.Description,
				AppID:       ent.AppID,
			})
		}

		if decoded.NextPageToken == "" || len(decoded.List) == 0 {
			return out, nil
		}
		if decoded.NextPageToken == pageToken {
			// The cursor did not advance; further requests would repeat this page.
			return out, nil
		}
		pageToken = decoded.NextPageToken
	}
	// Union Station's searchGroups returns what it has at this cap rather
	// than failing the whole fetch. DirectorySyncer would otherwise skip
	// the upsert and leave the Role assignment tab empty on a tenant whose
	// unfiltered catalog is larger than 10,000 entitlements.
	return out, nil
}

// do issues one authenticated request. Union Station's doOnce uses the
// caller's context and a 30s http.Client timeout that covers the body read;
// it does not cancel the request context when the headers come back.
// Config.Timeout is that same bound, kept alive until the body is closed so
// ReadAll is not aborted by a defer cancel() on return.
func (c *httpClient) do(ctx context.Context, method, path string, op credhttp.Op, body []byte) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout())

	token, err := c.token.get(ctx, c.cfg, c.deps, c.http)
	if err != nil {
		cancel()
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL()+path, bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%s: building the request failed", op)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+credentials.Reveal(token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req, op)
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelBody ties the request timeout to the response body lifetime.
type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// tokenCache holds one access token and serialises fetches of it.
type tokenCache struct {
	mu      sync.Mutex
	token   credentials.Secret
	expires time.Time
}

// now is the clock, so a test can pin one without sleeping.
var now = time.Now

func (t *tokenCache) get(ctx context.Context, cfg Config, deps Deps, hc *credhttp.Client) (credentials.Secret, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.token.IsZero() && now().Before(t.expires) {
		return t.token, nil
	}

	token, lifetime, err := fetchToken(ctx, cfg, deps, hc)
	if err != nil {
		return credentials.Secret{}, err
	}

	skew := tokenRefreshSkew
	if half := lifetime / 2; half < skew {
		skew = half
	}
	t.token = token
	t.expires = now().Add(lifetime - skew)
	return token, nil
}

// tokenResponse is the OAuth token endpoint's response.
type tokenResponse struct {
	AccessToken credentials.Secret `json:"access_token"`
	ExpiresIn   int64              `json:"expires_in"`
}

// fetchToken exchanges the directory client's credentials for an access
// token, via the OAuth 2.0 client-credentials grant verified against
// the source system's own ConductorOne client.
func fetchToken(ctx context.Context, cfg Config, deps Deps, hc *credhttp.Client) (credentials.Secret, time.Duration, error) {
	secret, err := deps.Secrets.Resolve(ctx, cfg.ClientSecret)
	if err != nil || secret.IsZero() {
		return credentials.Secret{}, 0, ErrClientSecretUnresolved
	}

	// Union Station getAccessToken: client_credentials with client_id and
	// client_secret. A ConductorOne personal-client credential is posted as
	// that secret string, not as a JWT assertion.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", credentials.Reveal(secret))

	op := credhttp.OpC1DirectoryFetchToken()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BaseURL()+tokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return credentials.Secret{}, 0, fmt.Errorf("%s: building the request failed", op)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req, op)
	if err != nil {
		return credentials.Secret{}, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return credentials.Secret{}, 0, statusError(op, resp)
	}

	var decoded tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&decoded); err != nil {
		return credentials.Secret{}, 0, errors.New("c1directory: the token response was not the expected JSON")
	}
	if decoded.AccessToken.IsZero() {
		return credentials.Secret{}, 0, errors.New("c1directory: the token response carried no access token")
	}
	if decoded.ExpiresIn <= 0 {
		return credentials.Secret{}, 0, errors.New("c1directory: the token response stated no positive lifetime")
	}
	return decoded.AccessToken, time.Duration(decoded.ExpiresIn) * time.Second, nil
}

// statusError turns a non-2xx response into an error built only from
// constants in this repository, the status code, and the request's own
// method and path. Mirrors credentials/c1's own statusError -- the body is
// drained and discarded because an upstream error body is text this process
// did not write, and the query string is left out too: a page token is not a
// secret, but this keeps the bound tight rather than trusting every future
// caller not to put one there.
func statusError(op credhttp.Op, resp *http.Response) error {
	drain(resp)
	method, path := requestMethodPath(resp)
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%s: %s %s failed (%d): %w",
			op, method, path, resp.StatusCode, ErrUnauthenticated)
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("%s: %s %s failed (%d): %w",
			op, method, path, resp.StatusCode, credentials.ErrTransient)
	default:
		return fmt.Errorf("%s: %s %s failed (%d)", op, method, path, resp.StatusCode)
	}
}

// requestMethodPath reports the method and path of the request that produced
// resp. Both are empty when the response carries no request, which should
// not happen from credhttp.Client.Do but must not panic if it ever does.
func requestMethodPath(resp *http.Response) (string, string) {
	if resp.Request == nil || resp.Request.URL == nil {
		return "", ""
	}
	return resp.Request.Method, resp.Request.URL.Path
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
	_ = resp.Body.Close()
}
