// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package github_test

// The standing error-content invariant, stated over this package by this package.
// internal/errhygiene holds the mechanism and the reasoning; this file holds the
// part only this package can write.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/github"
	"github.com/conductorone/apphub/internal/errhygiene"
)

func TestErrorHygiene(t *testing.T) {
	errhygiene.Assert(t, errhygiene.Subject{
		ImportPath: "github.com/conductorone/apphub/credentials/github",
		Drivers:    drivers,
		EmptyPopulations: []errhygiene.Population{
			// This package declares no type with a rendering method, and the
			// absence is asserted rather than left to a check that quietly does
			// nothing.
			errhygiene.PopulationRenderers,
		},
	})
}

// hygieneMetadata builds GitHub metadata with the sentinel in one value at a time, keeping
// the app credentials usable so the sentinel reaches the request-building and
// transport paths rather than stopping at the first validation.
func hygieneMetadata(sentinel, key string) credentials.Metadata {
	m := credentials.Metadata{
		github.MetadataAppID:          "12345",
		github.MetadataInstallationID: "67890",
		github.MetadataPrivateKey:     errhygiene.RSAKeyPEM(),
		github.MetadataRepositories:   "one,two",
	}
	if key != "" {
		m[key] = sentinel
	}
	return m
}

var drivers = map[string]errhygiene.Driver{
	"github.(*Provider).CreateCredential": {Run: func(_ *testing.T, s string) []any {
		var out []any
		keys := []string{
			"", github.MetadataAppID, github.MetadataInstallationID, github.MetadataPrivateKey,
			github.MetadataAPIBaseURL, github.MetadataRepositories, github.MetadataRepositoryIDs,
			github.MetadataPermissions, s,
		}
		for _, key := range keys {
			for _, rt := range []http.RoundTripper{
				errhygiene.ErroringTransport(s),
				errhygiene.RespondingTransport(s, 0),
				errhygiene.RespondingTransport(s, http.StatusOK),
				errhygiene.RespondingTransport(s, http.StatusFound),
			} {
				p := github.NewProvider(github.WithTransport(rt))
				res, err := p.CreateCredential(context.Background(), credentials.CreateRequest{
					Name:           s,
					CredentialType: credentials.CredentialTypeDynamic,
					Metadata:       hygieneMetadata(s, key),
					RequesterID:    s,
					IdempotencyKey: s,
				})
				out = append(out, err)
				if res != nil {
					out = append(out, res.APIKey)
				}
			}
			p := github.NewProvider(github.WithTransport(errhygiene.ErroringTransport(s)))
			_, err := p.CreateCredential(context.Background(), credentials.CreateRequest{
				CredentialType: credentials.CredentialType(s),
				Metadata:       hygieneMetadata(s, key),
				RequestedScope: []string{s},
			})
			out = append(out, err)
		}
		// A base URL that is a well-formed https URL carrying the sentinel gets past
		// validation, so the sentinel reaches request construction.
		p := github.NewProvider(github.WithTransport(errhygiene.ErroringTransport(s)))
		m := hygieneMetadata(s, "")
		m[github.MetadataAPIBaseURL] = "https://" + strings.ToLower(s) + ".example.com"
		_, err := p.CreateCredential(context.Background(), credentials.CreateRequest{
			CredentialType: credentials.CredentialTypeDynamic,
			Metadata:       m,
		})
		out = append(out, err, github.NewProvider())
		return out
	}},
	"github.(*Provider).RevokeCredential": {Run: func(_ *testing.T, s string) []any {
		p := github.NewProvider(github.WithTransport(errhygiene.ErroringTransport(s)))
		return []any{p.RevokeCredential(context.Background(), s, hygieneMetadata(s, ""))}
	}},
	"github.(*Provider).GetCredentialStatus": {Run: func(_ *testing.T, s string) []any {
		p := github.NewProvider(github.WithTransport(errhygiene.ErroringTransport(s)))
		st, err := p.GetCredentialStatus(context.Background(), s, hygieneMetadata(s, ""))
		return []any{err, string(st)}
	}},

	"github.NewProvider": {Why: "takes options that carry a http.RoundTripper and no text, and returns a " +
		"*Provider with no rendering method. The transport it installs is driven, and its errors carry " +
		"the sentinel, in all three github.(*Provider) drivers above."},
	"github.WithTransport": {Why: "takes a http.RoundTripper and returns an Option. It is the way every " +
		"driver above installs a sentinel-bearing transport, so it is exercised on every one of those " +
		"paths rather than on its own."},
}
