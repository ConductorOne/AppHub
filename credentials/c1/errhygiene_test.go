// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1_test

// The standing error-content invariant, stated over credentials/c1.
//
// # Why this file used to be a second copy of the mechanism
//
// internal/errhygiene held this invariant for five packages, and adding a sixth was
// a two-line change to its package list. It was not that change, because driving an
// entry point means calling it, and calling into credentials/c1 means importing
// credentials/c1 -- which internal/errhygiene may not do. The "c1-optional"
// boundary rule deliberately covers first-party *test* imports
// (internal/boundary/boundary.go), precisely so that a test cannot be the wedge
// that widens it, and the one allowlist entry USOSS-8 added is the composition
// root. A second entry requires supervisor approval per
// docs/design/credential-vending.md §11.3, and a test fixture is not a good enough
// reason to spend it.
//
// So USOSS-8 restated the invariant here, by the same method, and said in its own
// report what the fix was. USOSS-52 is that fix: internal/errhygiene is now an
// importable helper that a package's own test drives on itself. The import runs the
// other way, which is the direction the boundary rule has nothing to say about --
// it denies *importing* credentials/c1, and this package importing a test helper is
// not that. The allowlist is unchanged, and `go run ./hack/boundarycheck` says so.
//
// What is left here is the part only this package can write: how each of its
// exported inputs is driven with a sentinel, and a named reason for every one that
// is deliberately not.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/c1"
	"github.com/conductorone/apphub/internal/errhygiene"
)

func TestErrorHygiene(t *testing.T) {
	errhygiene.Assert(t, errhygiene.Subject{
		ImportPath: "github.com/conductorone/apphub/credentials/c1",
		Drivers:    hygieneDrivers,
		EmptyPopulations: []errhygiene.Population{
			// credentials/c1 has no type with a rendering method, and that is a fact
			// worth pinning rather than a set worth iterating: an empty set passes
			// every check made over it, so the absence is asserted. A type here that
			// grows an Error, String, Format or LogValue method fails this, at which
			// point it needs a driver that proves what it renders -- the way
			// credentials.Foreign and credentials.Secret have.
			errhygiene.PopulationRenderers,
		},
	})
}

// -- the sentinel-bearing collaborators -------------------------------------

// sentinelTransport answers with a response whose status line, every header and
// whole body carry the sentinel, and whose transport error does too on demand.
type sentinelTransport struct {
	sentinel string
	status   int
	failDial bool
	tokenOK  bool
}

func (s sentinelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if s.failDial {
		return nil, fmt.Errorf("dial tcp %s:443: connect: %s", s.sentinel, s.sentinel)
	}
	if s.tokenOK && strings.HasSuffix(req.URL.Path, "/auth/v1/token") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 " + s.sentinel,
			Header:     http.Header{"X-Note": []string{s.sentinel}},
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"` + s.sentinel + `","expires_in":3600}`)),
			Request:    req,
		}, nil
	}
	status := s.status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, s.sentinel),
		Header: http.Header{
			"X-Upstream-Note": []string{s.sentinel},
			"Location":        []string{"https://" + s.sentinel + ".example.invalid/collect"},
		},
		Body: io.NopCloser(strings.NewReader(
			`{"credential":{"id":"` + s.sentinel + `","servicePrincipalId":"` + s.sentinel +
				`","clientId":"` + s.sentinel + `"},"clientSecret":"` + s.sentinel +
				`","message":"` + s.sentinel + `"}`)),
		Request: req,
	}, nil
}

// sentinelSecrets and sentinelSigner put the sentinel in a host collaborator's
// error and in the material it returns.
type sentinelSecrets struct {
	sentinel string
	fail     bool
}

func (s sentinelSecrets) Resolve(context.Context, credentials.SecretRef) (credentials.Secret, error) {
	if s.fail {
		return credentials.Secret{}, errors.New(s.sentinel)
	}
	return credentials.NewSecret(s.sentinel), nil
}

type sentinelSigner struct {
	sentinel string
	fail     bool
}

func (s sentinelSigner) SignAssertion(context.Context, string, time.Duration) (credentials.Secret, error) {
	if s.fail {
		return credentials.Secret{}, errors.New(s.sentinel)
	}
	return credentials.NewSecret(s.sentinel), nil
}

// bodyTransport answers the credential API with a fixed status and body per HTTP
// method, and always answers the token endpoint successfully.
type bodyTransport struct {
	sentinel string
	post     string
	postCode int
	del      string
	delCode  int
	get      string
	getCode  int
}

func (b bodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/auth/v1/token") {
		return httpReply(http.StatusOK, `{"access_token":"`+b.sentinel+`","expires_in":3600}`, b.sentinel, req), nil
	}
	code, body := http.StatusInternalServerError, `{"message":"`+b.sentinel+`"}`
	switch req.Method {
	case http.MethodPost:
		if b.postCode != 0 {
			code, body = b.postCode, b.post
		}
	case http.MethodDelete:
		if b.delCode != 0 {
			code, body = b.delCode, b.del
		}
	case http.MethodGet:
		if b.getCode != 0 {
			code, body = b.getCode, b.get
		}
	}
	return httpReply(code, body, b.sentinel, req), nil
}

// httpReply builds a response whose status line and headers also carry the
// sentinel, so a driver cannot accidentally look only at the body.
func httpReply(code int, body, sentinel string, req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, sentinel),
		Header: http.Header{
			"X-Upstream-Note": []string{sentinel},
			"Location":        []string{"https://" + sentinel + ".example.invalid/collect"},
		},
		Body:    io.NopCloser(strings.NewReader(body)),
		Request: req,
	}
}

// malformedBodies are 200 responses whose bodies are not the JSON this package
// expects, with the sentinel inside them.
//
// They exist because the mutation round found the gap: every other transport here
// returns either an error status or a body that decodes, so a decoder error that was
// forwarded instead of dropped -- encoding/json quotes a byte of its input, which is
// how a credential response leaks one character at a time -- passed the whole
// fixture. A population containing only shapes the implementation already handles is
// a control that cannot fire.
func malformedBodies(sentinel string) []string {
	return []string{
		sentinel,                            // not JSON at all
		`{"credential":`,                    // truncated
		`{"credential":"` + sentinel + `"}`, // right key, wrong type
		`[{"credential":{}}]`,               // an array where an object belongs
		`{"clientSecret":` + sentinel + `}`, // an unquoted value
	}
}

// malformedAPITransport answers the token endpoint successfully and the API with a
// body that will not decode.
type malformedAPITransport struct {
	sentinel string
	body     string
}

func (m malformedAPITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/auth/v1/token") {
		return httpReply(http.StatusOK, `{"access_token":"`+m.sentinel+`","expires_in":3600}`, m.sentinel, req), nil
	}
	return httpReply(http.StatusOK, m.body, m.sentinel, req), nil
}

// malformedTokenTransport answers the token endpoint with a body that will not
// decode, so the token decoder's own error is exercised too.
type malformedTokenTransport struct {
	sentinel string
	body     string
}

func (m malformedTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return httpReply(http.StatusOK, m.body, m.sentinel, req), nil
}

// mintedJSON is a mint response with the sentinel wherever the upstream chooses a
// value, and the given granted scope.
func mintedJSON(sentinel string, roles []string, withSecret bool) string {
	body := `{"credential":{"id":"` + testCredential + `","servicePrincipalId":"` + testPrincipal +
		`","clientId":"` + sentinel + `"`
	if roles != nil {
		body += `,"scopedRoleIds":["` + strings.Join(roles, `","`) + `"]`
	}
	body += `}`
	if withSecret {
		body += `,"clientSecret":"` + sentinel + `"`
	}
	return body + `}`
}

// -- configuration and wiring -----------------------------------------------

// hygieneConfig is a valid configuration with the sentinel in one field.
func hygieneConfig(sentinel, field string) c1.Config {
	cfg := c1.Config{
		TenantURL:    "https://tenant.example.invalid",
		ClientID:     "apphub-client",
		ClientSecret: credentials.SecretRef{Name: "/run/secrets/c1"},
	}
	switch field {
	case "tenant":
		cfg.TenantURL = sentinel + "://host.example.invalid"
	case "clientID":
		cfg.ClientID = sentinel
	case "secretRef":
		cfg.ClientSecret = credentials.SecretRef{Name: sentinel, Store: sentinel}
	case "audience":
		cfg.Audience = sentinel
	case "mode":
		cfg.AuthMode = c1.AuthMode(sentinel)
	}
	return cfg
}

// hygieneEnv is a valid environment with the sentinel in one variable.
func hygieneEnv(sentinel, victim string) func(string) string {
	base := map[string]string{
		c1.EnvTenantURL:       "https://tenant.example.invalid",
		c1.EnvClientID:        "apphub-client",
		c1.EnvClientSecretRef: "/run/secrets/c1",
	}
	if victim == c1.EnvTenantURL {
		base[victim] = sentinel + "://host.example.invalid"
	} else {
		base[victim] = sentinel
	}
	return func(k string) string { return base[k] }
}

// hygieneMetadata puts the sentinel in the service principal.
func hygieneMetadata(sentinel string) credentials.Metadata {
	return credentials.Metadata{c1.MetadataServicePrincipalID: sentinel}
}

// sentinelScope is n distinct scope values, each carrying the sentinel.
func sentinelScope(sentinel string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%02d", sentinel, i)
	}
	return out
}

// hygieneMetadataPopulation is every shape the service-principal metadata value can
// take with the sentinel in it.
//
// The bare sentinel is *inside* the handle grammar -- it is alphanumeric and starts
// with a letter -- so a driver that used only it never reached the refusal path, and
// the mutation round caught that: a refusal rendering the rejected value passed the
// whole fixture. The population therefore straddles the grammar rather than sitting
// on one side of it.
func hygieneMetadataPopulation(sentinel string) []credentials.Metadata {
	out := []credentials.Metadata{hygieneMetadata(sentinel)}
	for _, bad := range []string{
		sentinel + "/x",             // a separator
		"../" + sentinel,            // traversal
		"." + sentinel,              // a leading dot
		"-" + sentinel,              // a leading dash
		sentinel + " ",              // trailing whitespace, trimmed to a valid value
		sentinel + "\t" + sentinel,  // interior whitespace
		sentinel + "%2F" + sentinel, // an encoded separator
		strings.Repeat(sentinel, 8), // over the length limit
	} {
		out = append(out, credentials.Metadata{c1.MetadataServicePrincipalID: bad})
	}
	return out
}

// hygieneHTTPClient builds the real HTTP client over a sentinel-bearing transport,
// so the Client interface methods are driven through the implementation rather than
// exempted.
func hygieneHTTPClient(t *testing.T, sentinel string, rt http.RoundTripper) c1.Client {
	t.Helper()
	client, err := c1.NewClient(hygieneConfig(sentinel, ""), c1.Deps{
		Secrets:   sentinelSecrets{sentinel: sentinel},
		Transport: rt,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// -- the values a driver returns for method coverage ------------------------
//
// A driver returns the values it wants checked, and a value that holds the input by
// design is not one of them. A Config holds the tenant URL an operator configured, a
// Ref is built from the identifiers it names, and a Client holds the Config: walking
// any of those finds the sentinel because that is what they are for, and asserting
// otherwise would be asserting that a data type must not be a data type.
//
// They still have to be produced, because credentials/c1 has seven exported
// zero-argument methods whose results can carry text and internal/errhygiene
// requires each to be invoked -- directly and through a template, which is
// USOSS-43's path. So the drivers return SENTINEL-FREE instances: the methods get
// called and their results checked, on a value whose contents this fixture chose.
// What the errors render is the sentinel-bearing half, and that is what the drivers
// return from the calls themselves.

func cleanConfig() c1.Config {
	return c1.Config{
		TenantURL:    "https://tenant.example.invalid",
		ClientID:     "apphub-client",
		ClientSecret: credentials.SecretRef{Name: "/run/secrets/c1"},
		Audience:     "apphub",
	}
}

func cleanProvider(t *testing.T) *c1.Provider {
	t.Helper()
	client, err := c1.NewClient(cleanConfig(), c1.Deps{
		Secrets:   sentinelSecrets{sentinel: "constant-secret"},
		Transport: bodyTransport{sentinel: "constant-body"},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	p, err := c1.NewProvider(client)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// hygieneProvider builds a Provider over the real HTTP client and the given
// transport. c1.Client is sealed, so the transport is the substitution point --
// which also means every driver below exercises the real request construction,
// response decoding and error classification rather than a fake's.
func hygieneProvider(t *testing.T, sentinel string, rt http.RoundTripper) *c1.Provider {
	t.Helper()
	p, err := c1.NewProvider(hygieneHTTPClient(t, sentinel, rt))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// -- the drivers ------------------------------------------------------------

var hygieneDrivers = map[string]errhygiene.Driver{
	"c1.ConfigFromEnv": {Run: func(_ *testing.T, s string) []any {
		var out []any
		// Every variable in turn, with a valid value everywhere else, so a leak is
		// attributable to the variable rather than to the whole environment. All
		// three of the refusals this found were formatting an operator-supplied
		// value into a message.
		for _, victim := range []string{
			c1.EnvTenantURL, c1.EnvClientID, c1.EnvClientSecretRef, c1.EnvClientSecret,
			c1.EnvAuthMode, c1.EnvAudience, c1.EnvRequestTimeout,
		} {
			_, err := c1.ConfigFromEnv(hygieneEnv(s, victim))
			out = append(out, err)
		}
		// And the shapes that reach Validate's other refusals.
		for _, tenant := range []string{
			"https://user:" + s + "@host.example.invalid",
			"https://host.example.invalid?q=" + s,
			"https://host.example.invalid#" + s,
			"http://" + s + ".example.invalid",
			s,
		} {
			env := map[string]string{
				c1.EnvTenantURL:       tenant,
				c1.EnvClientID:        "apphub-client",
				c1.EnvClientSecretRef: "/run/secrets/c1",
			}
			_, err := c1.ConfigFromEnv(func(k string) string { return env[k] })
			out = append(out, err)
		}
		// A sentinel-free Config, so Config's five text-producing zero-argument
		// methods are invoked. See the note above.
		out = append(out, cleanConfig())
		return out
	}},

	"c1.FormatHandle": {Run: func(_ *testing.T, s string) []any {
		var out []any
		for _, ref := range []c1.Ref{
			{ServicePrincipalID: s, CredentialID: s},
			{ServicePrincipalID: s + "/x", CredentialID: testCredential},
			{ServicePrincipalID: testPrincipal, CredentialID: "../" + s},
			{ServicePrincipalID: "", CredentialID: s},
		} {
			// The handle is deliberately dropped: FormatHandle's whole job is to
			// build one out of the identifiers it was given, so the handle contains
			// them by construction. What must not contain them is the refusal.
			_, err := c1.FormatHandle(ref)
			out = append(out, err)
		}
		return out
	}},

	"c1.ParseHandle": {Run: func(_ *testing.T, s string) []any {
		var out []any
		for _, in := range []string{
			s, s + "/" + s, s + "/" + s + "/" + s, "../" + s, s + "/has space", "",
		} {
			// The Ref is dropped for the same reason the handle is above.
			_, err := c1.ParseHandle(in)
			out = append(out, err)
		}
		return out
	}},

	"c1.NewClient": {Run: func(_ *testing.T, s string) []any {
		var out []any
		for _, field := range []string{"tenant", "clientID", "secretRef", "audience", "mode"} {
			_, err := c1.NewClient(hygieneConfig(s, field), c1.Deps{
				Secrets:    sentinelSecrets{sentinel: s},
				Assertions: sentinelSigner{sentinel: s},
				Transport:  sentinelTransport{sentinel: s},
			})
			out = append(out, err)
		}
		// And the wiring refusals.
		_, err := c1.NewClient(hygieneConfig(s, ""), c1.Deps{})
		out = append(out, err)
		return out
	}},

	"c1.NewProvider": {Run: func(t *testing.T, s string) []any {
		_, err := c1.NewProvider(hygieneHTTPClient(t, s, sentinelTransport{sentinel: s}))
		_, nilErr := c1.NewProvider(nil)
		// A Provider over a sentinel-free client, so Provider's zero-argument
		// methods are invoked.
		return []any{err, nilErr, cleanProvider(t)}
	}},

	"c1.Register": {Run: func(_ *testing.T, s string) []any {
		var out []any
		for _, field := range []string{"", "tenant", "clientID", "secretRef", "mode"} {
			reg := credentials.NewProviderRegistry()
			err := c1.Register(reg, hygieneConfig(s, field), c1.Deps{
				Secrets:    sentinelSecrets{sentinel: s},
				Assertions: sentinelSigner{sentinel: s},
				Transport:  sentinelTransport{sentinel: s},
			})
			out = append(out, err)
			// A second registration, so the duplicate-provider path is reached.
			out = append(out, c1.Register(reg, hygieneConfig(s, field), c1.Deps{
				Secrets:   sentinelSecrets{sentinel: s},
				Transport: sentinelTransport{sentinel: s},
			}))
		}
		out = append(out, c1.Register(nil, hygieneConfig(s, ""), c1.Deps{}))
		return out
	}},

	"c1.(Client).Mint": {Run: func(t *testing.T, s string) []any {
		var out []any
		// The real implementation, against a transport whose response and whose
		// transport error both carry the sentinel, across the status codes that take
		// different paths out of statusError.
		for _, rt := range []http.RoundTripper{
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusBadRequest},
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusUnauthorized},
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusTooManyRequests},
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusFound},
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusOK},
			sentinelTransport{sentinel: s, failDial: true},
			sentinelTransport{sentinel: s, status: http.StatusOK}, // a token response that is not one
		} {
			// The MintResponse is dropped where one comes back: it carries the
			// credential the upstream chose, which is the whole point of asking.
			_, err := hygieneHTTPClient(t, s, rt).Mint(context.Background(), c1.MintRequest{
				ServicePrincipalID: testPrincipal,
				DisplayName:        s,
				ScopedRoleIDs:      []string{s, s},
				TTL:                time.Hour,
			})
			out = append(out, err)
		}
		// Responses that will not decode, on both the API and the token endpoint.
		for _, body := range malformedBodies(s) {
			for _, rt := range []http.RoundTripper{
				malformedAPITransport{sentinel: s, body: body},
				malformedTokenTransport{sentinel: s, body: body},
			} {
				_, err := hygieneHTTPClient(t, s, rt).Mint(context.Background(), c1.MintRequest{
					ServicePrincipalID: testPrincipal, DisplayName: "n", TTL: time.Hour,
				})
				out = append(out, err)
			}
		}
		// Local refusals, with the sentinel in each field in turn.
		for _, req := range []c1.MintRequest{
			{ServicePrincipalID: s, DisplayName: s, TTL: time.Hour},
			{ServicePrincipalID: s + "/x", DisplayName: s, TTL: time.Hour},
			{ServicePrincipalID: "../" + s, DisplayName: s, TTL: time.Hour},
			{ServicePrincipalID: "." + s, DisplayName: s, TTL: time.Hour},
			{ServicePrincipalID: strings.Repeat(s, 8), DisplayName: s, TTL: time.Hour},
			// Over the upstream's scope-list limit, so the refusal that reports a
			// count is reached with sentinel-bearing values behind it. The mutation
			// round found this one: nothing here exceeded the limit, so a refusal
			// that listed the roles instead of counting them passed.
			{ServicePrincipalID: testPrincipal, DisplayName: "n", TTL: time.Hour, ScopedRoleIDs: sentinelScope(s, 33)},
			{ServicePrincipalID: testPrincipal, DisplayName: "", TTL: time.Hour},
			{ServicePrincipalID: testPrincipal, DisplayName: strings.Repeat(s, 20), TTL: time.Hour},
			{ServicePrincipalID: testPrincipal, DisplayName: s, TTL: 0},
		} {
			_, err := hygieneHTTPClient(t, s, sentinelTransport{sentinel: s, tokenOK: true}).
				Mint(context.Background(), req)
			out = append(out, err)
		}
		return out
	}},

	"c1.(Client).Get": {Run: func(t *testing.T, s string) []any {
		var out []any
		for _, rt := range []http.RoundTripper{
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusNotFound},
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusForbidden},
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusBadGateway},
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusOK},
			sentinelTransport{sentinel: s, failDial: true},
		} {
			_, err := hygieneHTTPClient(t, s, rt).Get(context.Background(), c1.Ref{
				ServicePrincipalID: testPrincipal, CredentialID: testCredential,
			})
			out = append(out, err)
		}
		for _, body := range malformedBodies(s) {
			for _, rt := range []http.RoundTripper{
				malformedAPITransport{sentinel: s, body: body},
				malformedTokenTransport{sentinel: s, body: body},
			} {
				_, err := hygieneHTTPClient(t, s, rt).Get(context.Background(), c1.Ref{
					ServicePrincipalID: testPrincipal, CredentialID: testCredential,
				})
				out = append(out, err)
			}
		}
		_, err := hygieneHTTPClient(t, s, sentinelTransport{sentinel: s, tokenOK: true}).
			Get(context.Background(), c1.Ref{ServicePrincipalID: s, CredentialID: s})
		out = append(out, err)
		return out
	}},

	"c1.(Client).Revoke": {Run: func(t *testing.T, s string) []any {
		var out []any
		for _, rt := range []http.RoundTripper{
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusNotFound},
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusUnauthorized},
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusServiceUnavailable},
			sentinelTransport{sentinel: s, tokenOK: true, status: http.StatusNoContent},
			sentinelTransport{sentinel: s, failDial: true},
		} {
			out = append(out, hygieneHTTPClient(t, s, rt).Revoke(context.Background(), c1.Ref{
				ServicePrincipalID: testPrincipal, CredentialID: testCredential,
			}))
		}
		out = append(out, hygieneHTTPClient(t, s, sentinelTransport{sentinel: s, tokenOK: true}).
			Revoke(context.Background(), c1.Ref{ServicePrincipalID: s, CredentialID: "../" + s}))
		return out
	}},

	"c1.(SecretResolver).Resolve": {Run: func(t *testing.T, s string) []any {
		// The host's resolver is where a deployment's own error text arrives. It must
		// not be forwarded, and the material it returns must not be rendered either.
		var out []any
		for _, secrets := range []c1.SecretResolver{
			sentinelSecrets{sentinel: s, fail: true},
			sentinelSecrets{sentinel: s},
		} {
			client, err := c1.NewClient(hygieneConfig(s, ""), c1.Deps{
				Secrets:   secrets,
				Transport: sentinelTransport{sentinel: s, status: http.StatusUnauthorized},
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			_, mintErr := client.Mint(context.Background(), c1.MintRequest{
				ServicePrincipalID: testPrincipal, DisplayName: "n", TTL: time.Hour,
			})
			out = append(out, mintErr)
		}
		return out
	}},

	"c1.(AssertionSigner).SignAssertion": {Run: func(t *testing.T, s string) []any {
		var out []any
		cfg := hygieneConfig(s, "")
		cfg.AuthMode = c1.AuthModeFederatedJWT
		cfg.Audience = s
		for _, signer := range []c1.AssertionSigner{
			sentinelSigner{sentinel: s, fail: true},
			sentinelSigner{sentinel: s},
		} {
			client, err := c1.NewClient(cfg, c1.Deps{
				Assertions: signer,
				Transport:  sentinelTransport{sentinel: s, status: http.StatusUnauthorized},
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			_, mintErr := client.Mint(context.Background(), c1.MintRequest{
				ServicePrincipalID: testPrincipal, DisplayName: "n", TTL: time.Hour,
			})
			out = append(out, mintErr)
		}
		return out
	}},

	"c1.(*Provider).CreateCredential": {Run: func(t *testing.T, s string) []any {
		var out []any
		// The sentinel in every caller-controlled field of the request, one at a
		// time, plus a client whose every answer is the sentinel.
		requests := []credentials.CreateRequest{
			{Name: s, CredentialType: credentials.CredentialTypeDynamic, TTL: time.Hour, Metadata: hygieneMetadata(testPrincipal)},
			{Name: "n", CredentialType: credentials.CredentialType(s), TTL: time.Hour, Metadata: hygieneMetadata(testPrincipal)},
			{Name: "n", CredentialType: credentials.CredentialTypeDynamic, TTL: time.Hour, Metadata: hygieneMetadata(testPrincipal), RequestedScope: []string{s}},
			{Name: "n", CredentialType: credentials.CredentialTypeDynamic, TTL: time.Hour, Metadata: hygieneMetadata(testPrincipal), RequesterID: s, RequesterType: s},
		}
		requests = append(requests, credentials.CreateRequest{
			Name: "n", CredentialType: credentials.CredentialTypeDynamic, TTL: time.Hour,
			Metadata: hygieneMetadata(testPrincipal), RequestedScope: sentinelScope(s, 33),
		})
		for _, md := range hygieneMetadataPopulation(s) {
			requests = append(requests, credentials.CreateRequest{
				Name: "n", CredentialType: credentials.CredentialTypeDynamic, TTL: time.Hour, Metadata: md,
			})
		}
		for _, req := range requests {
			// The CreateResult is dropped where one comes back: it carries the
			// material and the handle the upstream chose, which is what a caller
			// asked for.
			_, err := hygieneProvider(t, s, bodyTransport{sentinel: s}).CreateCredential(context.Background(), req)
			out = append(out, err)
		}
		// The scope-widening and undelivered paths, where a handle survives in an
		// error and must not render.
		for _, rt := range []http.RoundTripper{
			// Widened, compensating revoke succeeds.
			bodyTransport{sentinel: s, postCode: 200, post: mintedJSON(s, []string{"roleA", s}, true), delCode: 200, del: `{}`},
			// Widened by several roles, so a count and a list render differently.
			bodyTransport{sentinel: s, postCode: 200, post: mintedJSON(s, []string{"roleA", s, s + "2", s + "3"}, true), delCode: 200, del: `{}`},
			// Widened, compensating revoke fails.
			bodyTransport{sentinel: s, postCode: 200, post: mintedJSON(s, []string{"roleA", s}, true), delCode: 500, del: `{"message":"` + s + `"}`},
			// Material undelivered.
			bodyTransport{sentinel: s, postCode: 200, post: mintedJSON(s, nil, false), delCode: 200, del: `{}`},
			// Narrowed, and delivered.
			bodyTransport{sentinel: s, postCode: 200, post: mintedJSON(s, []string{"roleA"}, true)},
			// A 200 whose body will not decode.
			malformedAPITransport{sentinel: s, body: s},
			malformedAPITransport{sentinel: s, body: `{"credential":`},
			malformedTokenTransport{sentinel: s, body: s},
		} {
			_, err := hygieneProvider(t, s, rt).CreateCredential(context.Background(), credentials.CreateRequest{
				Name: "n", CredentialType: credentials.CredentialTypeDynamic, TTL: time.Hour,
				Metadata: hygieneMetadata(testPrincipal), RequestedScope: []string{"roleA"},
			})
			out = append(out, err)
		}
		return out
	}},

	"c1.(*Provider).RevokeCredential": {Run: func(t *testing.T, s string) []any {
		var out []any
		for _, handle := range []string{s, s + "/" + s, testPrincipal + "/" + testCredential, "../" + s, ""} {
			for _, rt := range []http.RoundTripper{
				bodyTransport{sentinel: s},
				bodyTransport{sentinel: s, delCode: 200, del: `{}`},
				bodyTransport{sentinel: s, delCode: 404, del: `{"message":"` + s + `"}`},
				bodyTransport{sentinel: s, delCode: 401, del: `{"message":"` + s + `"}`},
				sentinelTransport{sentinel: s, failDial: true},
				malformedTokenTransport{sentinel: s, body: s},
			} {
				out = append(out, hygieneProvider(t, s, rt).
					RevokeCredential(context.Background(), handle, hygieneMetadata(s)))
			}
		}
		return out
	}},

	"c1.(*Provider).GetCredentialStatus": {Run: func(t *testing.T, s string) []any {
		var out []any
		for _, handle := range []string{s, s + "/" + s, testPrincipal + "/" + testCredential, "../" + s, ""} {
			for _, rt := range []http.RoundTripper{
				bodyTransport{sentinel: s},
				bodyTransport{sentinel: s, getCode: 200, get: mintedJSON(s, []string{s}, false)},
				bodyTransport{sentinel: s, getCode: 404, get: `{"message":"` + s + `"}`},
				bodyTransport{sentinel: s, getCode: 403, get: `{"message":"` + s + `"}`},
				sentinelTransport{sentinel: s, failDial: true},
				malformedAPITransport{sentinel: s, body: s},
				malformedTokenTransport{sentinel: s, body: s},
			} {
				status, err := hygieneProvider(t, s, rt).
					GetCredentialStatus(context.Background(), handle, hygieneMetadata(s))
				out = append(out, err, string(status))
			}
		}
		return out
	}},
}
