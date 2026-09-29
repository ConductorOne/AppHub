// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package datadog_test

// The standing error-content invariant, stated over this package by this package.
// internal/errhygiene holds the mechanism and the reasoning; this file holds the
// part only this package can write.

import (
	"context"
	"net/http"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/datadog"
	"github.com/conductorone/apphub/internal/errhygiene"
)

func TestErrorHygiene(t *testing.T) {
	errhygiene.Assert(t, errhygiene.Subject{
		ImportPath: "github.com/conductorone/apphub/credentials/datadog",
		Drivers:    drivers,
		EmptyPopulations: []errhygiene.Population{
			// This package declares no type with a rendering method. An empty set
			// passes every check made over it, so the absence is asserted here: a
			// type that grows an Error, String, Format or LogValue method fails,
			// at which point it needs a driver that proves what it renders.
			errhygiene.PopulationRenderers,
		},
	})
}

// hygieneMetadata builds Datadog metadata with the sentinel in one value at a time, and a
// valid value everywhere else, so each key is reached in turn.
func hygieneMetadata(sentinel, key string) credentials.Metadata {
	m := credentials.Metadata{
		datadog.MetadataAdminAPIKey: "api-key-value",
		datadog.MetadataAdminAppKey: "app-key-value",
		datadog.MetadataSite:        "api.datadoghq.com",
	}
	if key != "" {
		m[key] = sentinel
	}
	return m
}

var drivers = map[string]errhygiene.Driver{
	"datadog.(*Provider).CreateCredential": {Run: func(_ *testing.T, s string) []any {
		var out []any
		keys := []string{"", datadog.MetadataAdminAPIKey, datadog.MetadataAdminAppKey, datadog.MetadataSite, s}
		for _, key := range keys {
			for _, rt := range []http.RoundTripper{
				errhygiene.ErroringTransport(s),
				errhygiene.RespondingTransport(s, 0),
				errhygiene.RespondingTransport(s, http.StatusOK),
				errhygiene.RespondingTransport(s, http.StatusFound),
			} {
				p := datadog.NewProvider(datadog.WithTransport(rt))
				res, err := p.CreateCredential(context.Background(), credentials.CreateRequest{
					Name:           s,
					CredentialType: credentials.CredentialTypeStatic,
					Metadata:       hygieneMetadata(s, key),
					RequesterID:    s,
					RequesterType:  s,
					IdempotencyKey: s,
				})
				out = append(out, err)
				if res != nil {
					out = append(out, res.APIKey)
				}
			}
			// A requested scope and a foreign credential type are refused before any
			// transport is reached.
			p := datadog.NewProvider(datadog.WithTransport(errhygiene.ErroringTransport(s)))
			_, err := p.CreateCredential(context.Background(), credentials.CreateRequest{
				Name:           s,
				CredentialType: credentials.CredentialType(s),
				Metadata:       hygieneMetadata(s, key),
				RequestedScope: []string{s},
			})
			out = append(out, err)
		}
		// A provider holding no transport of this fixture's, for method coverage: a
		// Provider's fields are an HTTP client and nothing else, so its zero-argument
		// methods cannot render caller text, and the probe proves they return
		// constants.
		out = append(out, datadog.NewProvider())
		return out
	}},
	"datadog.(*Provider).RevokeCredential": {Run: func(_ *testing.T, s string) []any {
		var out []any
		for _, rt := range []http.RoundTripper{
			errhygiene.ErroringTransport(s),
			errhygiene.RespondingTransport(s, 0),
		} {
			p := datadog.NewProvider(datadog.WithTransport(rt))
			out = append(out,
				p.RevokeCredential(context.Background(), s, hygieneMetadata(s, "")),
				p.RevokeCredential(context.Background(), "", hygieneMetadata(s, datadog.MetadataSite)),
			)
		}
		return out
	}},
	"datadog.(*Provider).GetCredentialStatus": {Run: func(_ *testing.T, s string) []any {
		var out []any
		for _, rt := range []http.RoundTripper{
			errhygiene.ErroringTransport(s),
			errhygiene.RespondingTransport(s, 0),
		} {
			p := datadog.NewProvider(datadog.WithTransport(rt))
			st, err := p.GetCredentialStatus(context.Background(), s, hygieneMetadata(s, ""))
			out = append(out, err, string(st))
			st, err = p.GetCredentialStatus(context.Background(), "", hygieneMetadata(s, datadog.MetadataSite))
			out = append(out, err, string(st))
		}
		return out
	}},

	"datadog.NewProvider": {Why: "takes options that carry a http.RoundTripper and no text, and returns " +
		"a *Provider with no rendering method. The transport it installs is driven, and its errors carry " +
		"the sentinel, in all three datadog.(*Provider) drivers above."},
	"datadog.WithTransport": {Why: "takes a http.RoundTripper and returns an Option. It is the way every " +
		"driver above installs a sentinel-bearing transport, so it is exercised on every one of those " +
		"paths rather than on its own."},
}
