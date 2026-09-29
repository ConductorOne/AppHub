// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credhttp_test

// The standing error-content invariant, stated over this package by this package.
// internal/errhygiene holds the mechanism and the reasoning; this file holds the
// part only this package can write.

import (
	"context"
	"net/http"
	"testing"

	"github.com/conductorone/apphub/internal/credhttp"
	"github.com/conductorone/apphub/internal/errhygiene"
)

func TestErrorHygiene(t *testing.T) {
	errhygiene.Assert(t, errhygiene.Subject{
		ImportPath: "github.com/conductorone/apphub/internal/credhttp",
		Drivers:    hygieneDrivers,
	})
}

var hygieneDrivers = map[string]errhygiene.Driver{
	"credhttp.(*Client).Do": {Run: func(_ *testing.T, s string) []any {
		out := []any{
			credhttp.OpDatadogCreateAPIKey(),
			credhttp.OpDatadogDeleteAPIKey(),
			credhttp.OpDatadogStatusCheck(),
			credhttp.OpGitHubAppMintInstallationToken(),
			credhttp.OpC1FetchToken(),
			credhttp.OpC1MintCredential(),
			credhttp.OpC1GetCredential(),
			credhttp.OpC1RevokeCredential(),
			credhttp.OpC1DirectoryFetchToken(),
			credhttp.OpC1DirectorySearchEntitlements(),
			credhttp.OpC1DirectorySearchUsers(),
			credhttp.OpC1DirectorySearchGrants(),
			credhttp.Op{},
		}
		// A foreign URL, a foreign transport error, and a foreign redirect target
		// are the three ways text has reached a Do error.
		for _, target := range []string{
			"https://" + s + ".example.com/path/" + s + "?q=" + s,
			"http://" + s + ".example.com/plaintext",
		} {
			for _, rt := range []http.RoundTripper{
				errhygiene.ErroringTransport(s),
				errhygiene.RespondingTransport(s, http.StatusFound),
			} {
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
				if err != nil {
					// A URL this test built is not a finding; skip it rather than
					// reporting the parse error, which quotes the input by design.
					continue
				}
				req.Header.Set("X-Credential", "material-that-must-not-escape")
				resp, doErr := credhttp.New(rt).Do(req, credhttp.OpDatadogCreateAPIKey())
				if resp != nil {
					_ = resp.Body.Close()
				}
				out = append(out, doErr)
			}
		}
		// A Client built on no sentinel-bearing transport, for method coverage. The
		// sentinel-bearing ones are not returned: they hold this fixture's own
		// scaffolding, and a walk would find the sentinel in the test double rather
		// than in anything the package produced.
		out = append(out, credhttp.New(nil))
		return out
	}},

	"credhttp.New": {Why: "takes a http.RoundTripper and returns a *Client with no rendering method. It " +
		"is how the credhttp.(*Client).Do driver installs each sentinel-bearing transport."},
}
