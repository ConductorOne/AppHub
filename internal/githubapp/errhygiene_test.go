// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package githubapp_test

// The standing error-content invariant, stated over this package by this package.
// internal/errhygiene holds the mechanism and the reasoning; this file holds the
// part only this package can write.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/errhygiene"
	"github.com/conductorone/apphub/internal/githubapp"
)

func TestErrorHygiene(t *testing.T) {
	errhygiene.Assert(t, errhygiene.Subject{
		ImportPath: "github.com/conductorone/apphub/internal/githubapp",
		Drivers:    hygieneDrivers,
		EmptyPopulations: []errhygiene.Population{
			// This package exports callables with arguments and no type with a
			// rendering method. Both absences are asserted rather than left to
			// a check that quietly does nothing.
			errhygiene.PopulationRenderers,
			errhygiene.PopulationTextProducers,
		},
	})
}

func hygieneKey() credentials.Secret { return credentials.NewSecret(errhygiene.RSAKeyPEM()) }

var hygieneDrivers = map[string]errhygiene.Driver{
	"githubapp.NormalizeBaseURL": {Run: func(_ *testing.T, s string) []any {
		var out []any
		for _, raw := range []string{s, "https://" + strings.ToLower(s) + ".example.com", "https://u:p@" + strings.ToLower(s) + ".example.com"} {
			_, err := githubapp.NormalizeBaseURL(raw)
			out = append(out, err)
		}
		return out
	}},
	"githubapp.NewApp": {Run: func(_ *testing.T, s string) []any {
		var out []any
		for _, base := range []string{
			s,
			"https://" + strings.ToLower(s) + ".example.com",
			"http://" + strings.ToLower(s) + ".example.com",
			"//" + strings.ToLower(s),
			"mailto:" + strings.ToLower(s) + "@example.com",
			"https://u:p@" + strings.ToLower(s) + ".example.com",
			"https://" + strings.ToLower(s) + ".example.com?q=1",
			"https://" + strings.ToLower(s) + ".example.com#f",
		} {
			_, err := githubapp.NewApp(githubapp.AppConfig{
				AppID:         1,
				PrivateKeyPEM: hygieneKey(),
				BaseURL:       base,
				Transport:     errhygiene.ErroringTransport(s),
			})
			out = append(out, err)
		}
		// A private key that is the sentinel rather than a key.
		_, err := githubapp.NewApp(githubapp.AppConfig{
			AppID:         1,
			PrivateKeyPEM: credentials.NewSecret(s),
			Transport:     errhygiene.ErroringTransport(s),
		})
		out = append(out, err)
		return out
	}},
	"githubapp.(*App).MintInstallationToken": {Run: func(t *testing.T, s string) []any {
		var out []any
		for _, rt := range []http.RoundTripper{
			errhygiene.ErroringTransport(s),
			errhygiene.RespondingTransport(s, 0),
			errhygiene.RespondingTransport(s, http.StatusOK),
			errhygiene.RespondingTransport(s, http.StatusFound),
		} {
			app, err := githubapp.NewApp(githubapp.AppConfig{
				AppID:         1,
				PrivateKeyPEM: hygieneKey(),
				BaseURL:       "https://" + strings.ToLower(s) + ".example.com",
				Transport:     rt,
			})
			if err != nil {
				t.Fatalf("NewApp: %v", err)
			}
			for _, req := range []githubapp.InstallationTokenRequest{
				{Repositories: []string{s}},
				{Permissions: map[string]string{s: s}},
				{RepositoryIDs: []int64{1}},
				{FullInstallationGrant: true},
				{},
				{Repositories: []string{s}, FullInstallationGrant: true},
			} {
				tok, mintErr := app.MintInstallationToken(context.Background(), 1, req)
				out = append(out, mintErr)
				if tok != nil {
					out = append(out, tok.Token)
				}
			}
		}
		return out
	}},
	"githubapp.(*App).ListInstallationRepositories": {Run: func(t *testing.T, s string) []any {
		var out []any
		app, err := githubapp.NewApp(githubapp.AppConfig{
			AppID:         1,
			PrivateKeyPEM: hygieneKey(),
			BaseURL:       "https://example.com",
			Transport:     errhygiene.ErroringTransport(s),
		})
		if err != nil {
			t.Fatalf("NewApp: %v", err)
		}
		for _, id := range []int64{0, 1} {
			urls, listErr := app.ListInstallationRepositories(context.Background(), id)
			out = append(out, listErr)
			out = append(out, urls)
		}
		return out
	}},
	"githubapp.(*App).ListInstallations": {Run: func(t *testing.T, s string) []any {
		var out []any
		for _, rt := range []http.RoundTripper{
			errhygiene.ErroringTransport(s),
			errhygiene.RespondingTransport(s, 0),
			errhygiene.RespondingTransport(s, http.StatusOK),
			errhygiene.RespondingTransport(s, http.StatusFound),
		} {
			app, err := githubapp.NewApp(githubapp.AppConfig{
				AppID:         1,
				PrivateKeyPEM: hygieneKey(),
				BaseURL:       "https://example.com",
				Transport:     rt,
			})
			if err != nil {
				t.Fatalf("NewApp: %v", err)
			}
			insts, listErr := app.ListInstallations(context.Background())
			out = append(out, listErr)
			for _, inst := range insts {
				out = append(out, inst)
			}
		}
		return out
	}},
	// A bool. There is no error, string, or other rendering a body, header, or
	// secret can appear in; the signature tests cover the match itself.
	"githubapp.ValidWebhookSignature": {Why: "returns only a bool, so there is no rendering that can carry caller text"},
	"githubapp.ConvertManifest": {Run: func(_ *testing.T, s string) []any {
		var out []any
		for _, rt := range []http.RoundTripper{
			errhygiene.ErroringTransport(s),
			errhygiene.RespondingTransport(s, 0),
			errhygiene.RespondingTransport(s, http.StatusOK),
			errhygiene.RespondingTransport(s, http.StatusFound),
		} {
			for _, base := range []string{"", "https://" + strings.ToLower(s) + ".example.com"} {
				conv, err := githubapp.ConvertManifest(context.Background(), s, base, rt)
				out = append(out, err, conv.PrivateKeyPEM)
			}
		}
		return out
	}},
	"githubapp.(*App).GetInstallationByOwner": {Run: func(t *testing.T, s string) []any {
		var out []any
		for _, rt := range []http.RoundTripper{
			errhygiene.ErroringTransport(s),
			errhygiene.RespondingTransport(s, 0),
			errhygiene.RespondingTransport(s, http.StatusOK),
			errhygiene.RespondingTransport(s, http.StatusNotFound),
			errhygiene.RespondingTransport(s, http.StatusFound),
		} {
			app, err := githubapp.NewApp(githubapp.AppConfig{
				AppID:         1,
				PrivateKeyPEM: hygieneKey(),
				BaseURL:       "https://example.com",
				Transport:     rt,
			})
			if err != nil {
				t.Fatalf("NewApp: %v", err)
			}
			for _, login := range []string{s, "", strings.ToLower(s)} {
				inst, getErr := app.GetInstallationByOwner(context.Background(), login)
				out = append(out, getErr, inst)
			}
		}
		return out
	}},
}
