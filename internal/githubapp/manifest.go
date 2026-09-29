// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package githubapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/credhttp"
)

// maxManifestConversionBodyBytes bounds the manifest-conversion response,
// which is small (an App's identity and credentials, nothing bulk).
const maxManifestConversionBodyBytes = 64 << 10

// ManifestConversion is the safe projection of GitHub's manifest-conversion
// response: exactly what AppHub stores for an admin-managed GitHub App (see
// docs/design/github-app.md: serve checks webhook deliveries with the HMAC
// secret injected from Parameter Store, not with the secret GitHub generates
// during this exchange, and AppHub never performs the user-facing OAuth flow
// a GitHub App also supports).
// GitHub's response additionally carries client_id, client_secret and
// webhook_secret; this type never decodes them, so they cannot leak through
// it even by accident. The webhook_secret in particular is not the one serve
// checks.
type ManifestConversion struct {
	// AppID is the new App's numeric ID.
	AppID int64
	// Slug is the App's URL-safe name.
	Slug string
	// PrivateKeyPEM is the App's freshly generated private key. Material.
	PrivateKeyPEM credentials.Secret
	// HTMLURL is the App's public settings page.
	HTMLURL string
}

// ConvertManifest exchanges a GitHub App Manifest flow's one-time code for
// the App it just created, calling POST {baseURL}/app-manifests/{code}/conversions.
//
// This is the one GitHub App REST call that requires no authentication of
// its own -- the code itself, minted by GitHub only after an administrator
// approved creating the App in GitHub's own UI, is the credential -- so
// unlike every other function in this package it needs no already-configured
// App to call through. baseURL follows the same rules as
// AppConfig.BaseURL: empty means DefaultAPIBaseURL.
func ConvertManifest(ctx context.Context, code, baseURL string, transport http.RoundTripper) (ManifestConversion, error) {
	if strings.TrimSpace(code) == "" {
		return ManifestConversion{}, errors.New("githubapp: manifest code is required")
	}
	base, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return ManifestConversion{}, err
	}
	endpoint := fmt.Sprintf("%s/app-manifests/%s/conversions", base, url.PathEscape(code))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return ManifestConversion{}, errors.New("githubapp: building the manifest conversion request failed")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	op := credhttp.OpGitHubAppManifestConversion()
	resp, err := credhttp.New(transport).Do(req, op)
	if err != nil {
		return ManifestConversion{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return ManifestConversion{}, statusError(op, resp)
	}

	var out struct {
		ID      int64  `json:"id"`
		Slug    string `json:"slug"`
		PEM     string `json:"pem"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxManifestConversionBodyBytes)).Decode(&out); err != nil {
		return ManifestConversion{}, errors.New("githubapp: manifest conversion response was not the expected JSON")
	}
	if out.ID <= 0 || strings.TrimSpace(out.PEM) == "" {
		return ManifestConversion{}, errors.New("githubapp: manifest conversion response carried no app ID or private key")
	}
	return ManifestConversion{AppID: out.ID, Slug: out.Slug, PrivateKeyPEM: credentials.NewSecret(out.PEM), HTMLURL: out.HTMLURL}, nil
}
