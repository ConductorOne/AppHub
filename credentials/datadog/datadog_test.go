// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package datadog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/datadog"
	"github.com/conductorone/apphub/credentials/lifecycle"
)

// Fixture values. Deliberately not shaped like real Datadog credentials: a test
// in a public repository should not carry anything a scanner has to decide about,
// and these exist only to be searched for in error strings.
const (
	fixtureAdminAPIKey = "fixture-admin-api-key-value"
	fixtureAdminAppKey = "fixture-admin-app-key-value"
	fixtureVendedKey   = "fixture-vended-key-material"
)

// roundTripFunc is the whole test transport. No httptest server and no listening
// socket: every test asserts on the request it captured and answers from a
// literal, so the suite needs no network at all and cannot collide with a
// sibling task over a port.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// recorder captures the requests a provider makes and replies with canned
// responses, one per call in order (the last is repeated).
type recorder struct {
	requests []*http.Request
	bodies   []string
	replies  []reply
	err      error
}

// The exported field names are a leftover, kept because renaming them back is
// churn and not because they are needed. An all-lowercase three-segment field
// chain (r.reply.body) used to be reported by the repository's
// hostname-disclosure scan, which could not tell a Go selector chain from a
// hostname; a leading capital ended the match. That rule was rebuilt to decide by
// position rather than by suffix, and the false positive is gone -- verified
// against the current ruleset, which now carries a self-test case for exactly
// this shape.
type reply struct {
	Status int
	Body   string
	Header http.Header
}

// transport is the whole test HTTP layer. WithTransport takes a RoundTripper and
// nothing else, which is the point: there is no longer an API through which a
// test -- or a caller supplying a client for tracing -- can replace the
// provider's redirect policy.
func (r *recorder) transport() http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := ""
		if req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			body = string(b)
		}
		r.requests = append(r.requests, req)
		r.bodies = append(r.bodies, body)
		if r.err != nil {
			return nil, r.err
		}
		rep := r.replies[min(len(r.requests)-1, len(r.replies)-1)]
		header := rep.Header
		if header == nil {
			header = http.Header{}
		}
		return &http.Response{
			StatusCode: rep.Status,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(rep.Body)),
			Request:    req,
		}, nil
	})
}

func (r *recorder) provider(replies ...reply) *datadog.Provider {
	r.replies = replies
	if len(r.replies) == 0 {
		r.replies = []reply{{Status: 200, Body: "{}"}}
	}
	return datadog.NewProvider(datadog.WithTransport(r.transport()))
}

func metadata() credentials.Metadata {
	return credentials.Metadata{
		datadog.MetadataAdminAPIKey: fixtureAdminAPIKey,
		datadog.MetadataAdminAppKey: fixtureAdminAppKey,
	}
}

func staticRequest() credentials.CreateRequest {
	return credentials.CreateRequest{
		Name:           "apphub-vended",
		CredentialType: credentials.CredentialTypeStatic,
		Metadata:       metadata(),
		IdempotencyKey: "record-1",
	}
}

func createdBody(id, key string) string {
	return fmt.Sprintf(`{"data":{"id":%q,"type":"api_keys","attributes":{"name":"apphub-vended","key":%q}}}`, id, key)
}

// TestCreateCredentialVendsAStaticKey pins the wire contract: the endpoint, the
// two authentication headers, the request body, and what comes back.
func TestCreateCredentialVendsAStaticKey(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: createdBody("key-id-1", fixtureVendedKey)})

	got, err := p.CreateCredential(context.Background(), staticRequest())
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	if len(rec.requests) != 1 {
		t.Fatalf("made %d requests, want 1", len(rec.requests))
	}
	req := rec.requests[0]
	if req.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if got, want := req.URL.String(), "https://api.datadoghq.com/api/v2/api_keys"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
	if got := req.Header.Get("DD-API-KEY"); got != fixtureAdminAPIKey {
		t.Errorf("DD-API-KEY = %q, want the admin API key", got)
	}
	if got := req.Header.Get("DD-APPLICATION-KEY"); got != fixtureAdminAppKey {
		t.Errorf("DD-APPLICATION-KEY = %q, want the admin app key", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}

	var sent map[string]any
	if err := json.Unmarshal([]byte(rec.bodies[0]), &sent); err != nil {
		t.Fatalf("request body was not JSON: %v", err)
	}
	data, _ := sent["data"].(map[string]any)
	attrs, _ := data["attributes"].(map[string]any)
	if data["type"] != "api_keys" || attrs["name"] != "apphub-vended" {
		t.Errorf("request body = %s", rec.bodies[0])
	}

	if got.PlatformKeyID != "key-id-1" {
		t.Errorf("PlatformKeyID = %q, want %q", got.PlatformKeyID, "key-id-1")
	}
	if credentials.Reveal(got.APIKey) != fixtureVendedKey {
		t.Error("APIKey did not carry the vended material")
	}
	if got.Credentials != nil {
		t.Error("Credentials should be nil for a single-value credential")
	}
}

// TestCreateCredentialReportsNoExpiry is the regression test for the source's
// fabricated expiry. lifecycle.Record.ExpiryAuthoritative is derived from whether
// this field was set, and a true there lets the reconciler finalize a record as
// expired -- so a Datadog key, which never expires, must report nothing.
func TestCreateCredentialReportsNoExpiry(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: createdBody("key-id-1", fixtureVendedKey)})

	req := staticRequest()
	req.TTL = 24 * time.Hour // a caller applying its own policy clamp
	got, err := p.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if got.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil: a Datadog API key does not expire, and a "+
			"value here would be recorded as a provider-stated expiry", got.ExpiresAt)
	}
	if got.GrantedScope != nil {
		t.Errorf("GrantedScope = %v, want nil: Datadog does not describe key scope", got.GrantedScope)
	}
}

// TestCreateCredentialRefusesEverythingButStatic covers the source's missing
// check: it reported SupportsDynamic() false and then vended whatever it was
// asked for.
func TestCreateCredentialRefusesEverythingButStatic(t *testing.T) {
	for _, typ := range []credentials.CredentialType{credentials.CredentialTypeDynamic, ""} {
		rec := &recorder{}
		p := rec.provider()
		req := staticRequest()
		req.CredentialType = typ
		if _, err := p.CreateCredential(context.Background(), req); err == nil {
			t.Errorf("CreateCredential(type=%q) succeeded, want refusal", typ)
		}
		if len(rec.requests) != 0 {
			t.Errorf("type=%q: provider called Datadog before refusing", typ)
		}
	}
}

// TestCreateCredentialRefusesARequestedScope: ignoring a narrowing request would
// vend something wider than was asked for, which CreateRequest.RequestedScope
// forbids.
func TestCreateCredentialRefusesARequestedScope(t *testing.T) {
	rec := &recorder{}
	p := rec.provider()
	req := staticRequest()
	req.RequestedScope = []string{"metrics:read"}

	_, err := p.CreateCredential(context.Background(), req)
	if !errors.Is(err, credentials.ErrScopeNotSupported) {
		t.Fatalf("CreateCredential(scoped) = %v, want ErrScopeNotSupported", err)
	}
	if len(rec.requests) != 0 {
		t.Error("provider vended before refusing the scope")
	}
}

// TestCreateCredentialValidatesTheName bounds what reaches the request body.
func TestCreateCredentialValidatesTheName(t *testing.T) {
	for _, name := range []string{"", "   ", strings.Repeat("x", 257)} {
		rec := &recorder{}
		p := rec.provider()
		req := staticRequest()
		req.Name = name
		if _, err := p.CreateCredential(context.Background(), req); err == nil {
			t.Errorf("CreateCredential(name=%d bytes) succeeded, want refusal", len(name))
		}
		if len(rec.requests) != 0 {
			t.Error("provider called Datadog with an invalid name")
		}
	}
}

// TestMetadataIsRequired: a missing admin credential is refused before any call.
func TestMetadataIsRequired(t *testing.T) {
	for _, missing := range []string{datadog.MetadataAdminAPIKey, datadog.MetadataAdminAppKey} {
		md := metadata()
		delete(md, missing)

		rec := &recorder{}
		p := rec.provider()
		req := staticRequest()
		req.Metadata = md
		if _, err := p.CreateCredential(context.Background(), req); err == nil {
			t.Errorf("CreateCredential without %q succeeded", missing)
		}
		if len(rec.requests) != 0 {
			t.Errorf("provider called Datadog without %q", missing)
		}
	}
}

// TestSiteAllowlist is the SSRF test. dd_site decides where an admin API key is
// sent, so an unrecognized host must be refused before the request is built.
func TestSiteAllowlist(t *testing.T) {
	t.Run("refuses an unknown host", func(t *testing.T) {
		for _, site := range []string{
			"attacker.example.com",
			"api.datadoghq.com.attacker.example.com",
			"api.datadoghq.com:8443",
			"api.datadoghq.com/../evil",
			"localhost",
			"169.254.169.254",
		} {
			md := metadata()
			md[datadog.MetadataSite] = site

			rec := &recorder{}
			p := rec.provider()
			req := staticRequest()
			req.Metadata = md

			_, err := p.CreateCredential(context.Background(), req)
			if !errors.Is(err, datadog.ErrSiteNotAllowed) {
				t.Errorf("dd_site=%q gave %v, want ErrSiteNotAllowed", site, err)
			}
			if len(rec.requests) != 0 {
				t.Errorf("dd_site=%q: the admin key was sent to an unallowlisted host", site)
			}
		}
	})

	t.Run("accepts an allowlisted host, case-insensitively", func(t *testing.T) {
		md := metadata()
		md[datadog.MetadataSite] = "API.DATADOGHQ.EU"

		rec := &recorder{}
		p := rec.provider(reply{Status: 201, Body: createdBody("key-id-1", fixtureVendedKey)})
		req := staticRequest()
		req.Metadata = md

		if _, err := p.CreateCredential(context.Background(), req); err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}
		if got, want := rec.requests[0].URL.Host, "api.datadoghq.eu"; got != want {
			t.Errorf("host = %q, want %q", got, want)
		}
	})
}

// TestCreateCredentialRefusesAResponseWithNoMaterial covers the outcome where a
// credential exists upstream and cannot be delivered.
//
// The earlier version of this test asserted that the error names the key. That
// assertion was the defect: it required the provider to format a
// response-controlled value into an error string, which review then exploited by
// returning an administrative key in data.id. The handle still has to survive --
// it is the only record of a key that needs deleting -- so it now travels in a
// type that will not render it.
func TestCreateCredentialRefusesAResponseWithNoMaterial(t *testing.T) {
	for _, tc := range []struct{ Name, Body string }{
		{"no key", `{"data":{"id":"orphan-1","attributes":{"name":"n"}}}`},
		{"empty key", `{"data":{"id":"orphan-1","attributes":{"key":"","name":"n"}}}`},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			rec := &recorder{}
			p := rec.provider(reply{Status: 201, Body: tc.Body})

			got, err := p.CreateCredential(context.Background(), staticRequest())
			if err == nil {
				t.Fatalf("CreateCredential returned %+v, want an error", got)
			}
			if !errors.Is(err, credentials.ErrCreateNotDelivered) {
				t.Errorf("err = %v, want ErrCreateNotDelivered", err)
			}

			var nd *credentials.CreateNotDeliveredError
			if !errors.As(err, &nd) {
				t.Fatalf("err = %v, want a *CreateNotDeliveredError carrying the handle", err)
			}
			// The accessors return a credentials.Foreign, so recovering the text is a
			// second deliberate act. A string there would be an exported
			// zero-argument method returning caller text, which text/template calls
			// by name -- see USOSS-43.
			if got := credentials.RevealForeign(nd.PlatformKeyID()); got != "orphan-1" {
				t.Errorf("RevealForeign(PlatformKeyID()) = %q, want %q", got, "orphan-1")
			}
			if got := credentials.RevealForeign(nd.ProviderID()); got != datadog.ProviderID {
				t.Errorf("RevealForeign(ProviderID()) = %q", got)
			}

			// The handle must not appear under any verb, in a wrapped error, or in a
			// structured log record.
			wrapped := fmt.Errorf("issuing for application %s: %w", "app-1", err)
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			logger.Error("vend failed", "err", err)
			renderings := []string{
				err.Error(),
				fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err),
				fmt.Sprintf("%s", err), fmt.Sprintf("%q", err),
				fmt.Sprintf("%v", []error{err}), fmt.Sprintf("%#v", struct{ E error }{err}),
				wrapped.Error(), buf.String(),
			}
			for i, rendering := range renderings {
				if strings.Contains(rendering, "orphan-1") {
					t.Errorf("rendering %d exposed the handle: %s", i, rendering)
				}
			}
		})
	}

	t.Run("no ID", func(t *testing.T) {
		rec := &recorder{}
		p := rec.provider(reply{Status: 201, Body: `{"data":{"attributes":{"key":"k"}}}`})
		if _, err := p.CreateCredential(context.Background(), staticRequest()); err == nil {
			t.Error("a response with no key ID was accepted")
		}
	})
}

// TestAReflectedIDNeverReachesAnError is review's reproduction, kept verbatim in
// intent: a 201 whose data.id is the administrative key and which carries no key
// material. The previous implementation returned
// `datadog: key "fixture-admin-api-key-value" was created ...`.
func TestAReflectedIDNeverReachesAnError(t *testing.T) {
	body := fmt.Sprintf(`{"data":{"id":%q,"attributes":{"name":"apphub-vended"}}}`, fixtureAdminAPIKey)

	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: body})

	_, err := p.CreateCredential(context.Background(), staticRequest())
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), fixtureAdminAPIKey) {
		t.Fatalf("the error reflected the response-controlled ID: %v", err)
	}

	// The handle is still reachable, which is the half that must not regress
	// either: a fix that simply dropped it would lose the only pointer to a key
	// that needs deleting.
	var nd *credentials.CreateNotDeliveredError
	if !errors.As(err, &nd) || credentials.RevealForeign(nd.PlatformKeyID()) != fixtureAdminAPIKey {
		t.Errorf("the handle did not survive structurally: %v", err)
	}
}

// TestRevokeTreatsAMissingKeyAsRevoked: the point of a revoke is that the material
// no longer works, and a 404 says so. Erroring would leave the reconciler retrying
// forever against a key nobody can find.
func TestRevokeTreatsAMissingKeyAsRevoked(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{Status: 404, Body: `{"errors":["not found"]}`})

	if err := p.RevokeCredential(context.Background(), "key-id-1", metadata()); err != nil {
		t.Fatalf("RevokeCredential on a missing key = %v, want nil", err)
	}
	req := rec.requests[0]
	if req.Method != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", req.Method)
	}
	if got, want := req.URL.String(), "https://api.datadoghq.com/api/v2/api_keys/key-id-1"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}

// TestRevokeEscapesTheKeyID: the handle comes back out of the platform's own
// record, which is not a thing to trust with path construction.
func TestRevokeEscapesTheKeyID(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{Status: 204})

	if err := p.RevokeCredential(context.Background(), "../../api/v2/users", metadata()); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	if got, want := rec.requests[0].URL.EscapedPath(), "/api/v2/api_keys/..%2F..%2Fapi%2Fv2%2Fusers"; got != want {
		t.Errorf("escaped path = %q, want %q", got, want)
	}
}

// TestRevokeRequiresAKeyID keeps a blank handle from becoming a request against
// the collection endpoint.
func TestRevokeRequiresAKeyID(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{Status: 204})
	if err := p.RevokeCredential(context.Background(), "  ", metadata()); err == nil {
		t.Error("RevokeCredential accepted a blank key ID")
	}
	if len(rec.requests) != 0 {
		t.Error("a blank key ID reached the API")
	}
}

// TestGetCredentialStatus maps upstream answers to the contract's statuses.
func TestGetCredentialStatus(t *testing.T) {
	for _, tc := range []struct {
		Name      string
		Status    int
		Want      credentials.CredentialStatus
		WantErr   bool
		Transient bool
	}{
		{"present", 200, credentials.CredentialStatusActive, false, false},
		{"gone", 404, credentials.CredentialStatusRevoked, false, false},
		{"forbidden", 403, credentials.CredentialStatusUnknown, true, false},
		{"rate limited", 429, credentials.CredentialStatusUnknown, true, true},
		{"upstream fault", 503, credentials.CredentialStatusUnknown, true, true},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			rec := &recorder{}
			p := rec.provider(reply{Status: tc.Status, Body: `{"errors":["something"]}`})

			got, err := p.GetCredentialStatus(context.Background(), "key-id-1", metadata())
			if got != tc.Want {
				t.Errorf("status = %q, want %q", got, tc.Want)
			}
			if (err != nil) != tc.WantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.WantErr)
			}
			if errors.Is(err, credentials.ErrTransient) != tc.Transient {
				t.Errorf("ErrTransient = %v, want %v (err = %v)", !tc.Transient, tc.Transient, err)
			}
			if rec.requests[0].Method != http.MethodGet {
				t.Errorf("method = %q, want GET", rec.requests[0].Method)
			}
		})
	}
}

// TestTransientClassification is what lets the reconciler tell "come back later"
// from "this will never work". Getting it backwards means either retrying a
// permanent failure forever or giving up on a rate limit.
func TestTransientClassification(t *testing.T) {
	for _, tc := range []struct {
		Status    int
		Transient bool
	}{
		{400, false}, {401, false}, {403, false}, {409, false},
		{429, true}, {500, true}, {502, true}, {503, true},
	} {
		rec := &recorder{}
		p := rec.provider(reply{Status: tc.Status, Body: `{"errors":["nope"]}`})
		_, err := p.CreateCredential(context.Background(), staticRequest())
		if err == nil {
			t.Fatalf("status %d: CreateCredential succeeded", tc.Status)
		}
		if errors.Is(err, credentials.ErrTransient) != tc.Transient {
			t.Errorf("status %d: ErrTransient = %v, want %v", tc.Status, !tc.Transient, tc.Transient)
		}
	}

	t.Run("transport failure", func(t *testing.T) {
		rec := &recorder{err: errors.New("connection reset")}
		p := rec.provider()
		if _, err := p.CreateCredential(context.Background(), staticRequest()); !errors.Is(err, credentials.ErrTransient) {
			t.Errorf("transport failure = %v, want ErrTransient", err)
		}
	})
}

// TestErrorsCarryNoCredentialMaterial walks every failing path with material in
// the metadata and in the response body, and asserts none of it reaches the error
// string. This is the property the whole Secret type exists to defend, and a
// provider that interpolates a response body defeats it on its own.
func TestErrorsCarryNoCredentialMaterial(t *testing.T) {
	// A response body that leaks in three ways at once: a key in the documented
	// place, a key in an error message, and the admin key echoed back.
	leaky := fmt.Sprintf(
		`{"errors":["rejected key %s and admin key %s"],"data":{"attributes":{"key":%q}}}`,
		fixtureVendedKey, fixtureAdminAPIKey, fixtureVendedKey)

	material := []string{fixtureAdminAPIKey, fixtureAdminAppKey, fixtureVendedKey}

	check := func(t *testing.T, label string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: expected an error", label)
		}
		for _, secret := range material {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: error leaks credential material: %q", label, err)
			}
		}
	}

	for _, status := range []int{400, 401, 403, 429, 500} {
		rec := &recorder{}
		p := rec.provider(reply{Status: status, Body: leaky})
		_, err := p.CreateCredential(context.Background(), staticRequest())
		check(t, fmt.Sprintf("create %d", status), err)

		err = p.RevokeCredential(context.Background(), "key-id-1", metadata())
		check(t, fmt.Sprintf("revoke %d", status), err)

		_, err = p.GetCredentialStatus(context.Background(), "key-id-1", metadata())
		check(t, fmt.Sprintf("status %d", status), err)
	}

	t.Run("a formatted request does not leak either", func(t *testing.T) {
		req := staticRequest()
		if rendered := fmt.Sprintf("%v %+v %#v", req, req, req); strings.Contains(rendered, fixtureAdminAPIKey) {
			t.Errorf("formatting a CreateRequest leaked the admin key: %s", rendered)
		}
	})
}

// TestErrorsCarryOnlyTheStatusCode is the other half of the leak test: rather
// than checking that specific material is absent, it checks that nothing from the
// response body is present at all. That is the property that makes the leak test
// above hold for bodies nobody thought to write a fixture for.
func TestErrorsCarryOnlyTheStatusCode(t *testing.T) {
	body := `{"errors":["distinctive-upstream-detail"],"extra":"another-distinctive-token"}`

	rec := &recorder{}
	p := rec.provider(reply{Status: 400, Body: body})
	_, err := p.CreateCredential(context.Background(), staticRequest())
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, fragment := range []string{"distinctive-upstream-detail", "another-distinctive-token"} {
		if strings.Contains(msg, fragment) {
			t.Errorf("error %q carries the upstream response body", msg)
		}
	}
	if !strings.Contains(msg, "400") {
		t.Errorf("error %q does not report the status code", msg)
	}
	if strings.ContainsAny(msg, "\n\r") {
		t.Errorf("error %q spans lines", msg)
	}
}

// TestDefaultClientRefusesRedirects: Go strips Authorization across hosts, but
// DD-API-KEY is not a header it knows about, so a followed redirect would deliver
// an admin key to whatever the response named.
func TestDefaultClientRefusesRedirects(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{
		Status: http.StatusFound,
		Header: http.Header{"Location": []string{"https://attacker.example.com/collect"}},
	})

	_, err := p.CreateCredential(context.Background(), staticRequest())
	if !errors.Is(err, credentials.ErrRedirectRefused) {
		t.Fatalf("CreateCredential against a redirect = %v, want ErrRedirectRefused", err)
	}
	for _, req := range rec.requests {
		if req.URL.Host == "attacker.example.com" {
			t.Fatal("the admin key was sent to the redirect target")
		}
	}
	if errors.Is(err, credentials.ErrTransient) {
		t.Error("a refused redirect is marked transient; the reconciler would retry a misconfiguration forever")
	}
}

// TestCapabilitiesAreDeclaredAndAdmitStatic is the reason this provider implements
// CapabilityReporter at all: an undeclared provider is inferred static-incapable,
// and this one vends nothing else.
func TestCapabilitiesAreDeclaredAndAdmitStatic(t *testing.T) {
	p := datadog.NewProvider()
	got := credentials.CapabilitiesOf(p)
	want := credentials.Capabilities{
		Dynamic: false, Static: true, Revoke: true, Status: true, Rotate: false, RecoverCreate: false,
	}
	if got != want {
		t.Fatalf("CapabilitiesOf() = %+v, want %+v", got, want)
	}
	if !got.Supports(credentials.CredentialTypeStatic) || got.Supports(credentials.CredentialTypeDynamic) {
		t.Error("capabilities disagree with SupportsDynamic")
	}
	if p.SupportsDynamic() {
		t.Error("SupportsDynamic() = true")
	}

	policy := lifecycle.ProviderPolicy{
		Enabled:                    true,
		AllowedTypes:               []credentials.CredentialType{credentials.CredentialTypeStatic},
		MaxTTL:                     map[credentials.CredentialType]time.Duration{credentials.CredentialTypeStatic: 24 * time.Hour},
		AllowUnrecoverableIssuance: true,
	}
	if err := lifecycle.CheckIssuable(p, policy, credentials.CredentialTypeStatic); err != nil {
		t.Errorf("CheckIssuable(static) = %v, want nil", err)
	}
	if err := lifecycle.CheckIssuable(p, policy, credentials.CredentialTypeDynamic); err == nil {
		t.Error("CheckIssuable(dynamic) succeeded against a static-only provider")
	}

	// The other half of the same fact, and the reason it is worth stating in a
	// test: Datadog has no idempotent create, so this provider cannot implement
	// CreateRecoverer, and an operator has to accept that explicitly.
	policy.AllowUnrecoverableIssuance = false
	if err := lifecycle.CheckIssuable(p, policy, credentials.CredentialTypeStatic); !errors.Is(err, lifecycle.ErrUnrecoverableIssuance) {
		t.Errorf("CheckIssuable without the opt-in = %v, want ErrUnrecoverableIssuance", err)
	}
	if _, ok := any(p).(credentials.CreateRecoverer); ok {
		t.Error("provider implements CreateRecoverer; Datadog has no idempotent create to build it on")
	}
}

// TestRegistersUnderItsOwnID checks the provider is usable through the registry,
// which is how every caller reaches it.
func TestRegistersUnderItsOwnID(t *testing.T) {
	reg := credentials.NewProviderRegistry()
	p := datadog.NewProvider()
	if err := reg.Register(p); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(datadog.NewProvider()); err == nil {
		t.Error("a second Datadog provider was registered under the same ID")
	}
	got, ok := reg.Get(datadog.ProviderID)
	if !ok {
		t.Fatalf("Get(%q) missed", datadog.ProviderID)
	}
	if got.Name() != "Datadog" {
		t.Errorf("Name() = %q", got.Name())
	}
}

// TestSecretsSurviveAFullVendUnformatted guards the one path that has to reveal
// material: the result is handed to the caller, and nothing on the way there may
// render it.
func TestSecretsSurviveAFullVendUnformatted(t *testing.T) {
	rec := &recorder{}
	p := rec.provider(reply{Status: 201, Body: createdBody("key-id-1", fixtureVendedKey)})

	got, err := p.CreateCredential(context.Background(), staticRequest())
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%v|%+v|%#v|%s|%q", got, got, got, got.APIKey, got.APIKey)
	if strings.Contains(buf.String(), fixtureVendedKey) {
		t.Errorf("formatting the result rendered the material: %s", buf.String())
	}
	if credentials.Reveal(got.APIKey) != fixtureVendedKey {
		t.Error("Reveal did not return the material")
	}
}

// TestRevokeAndStatusValidateBeforeCalling: both take a handle and metadata from a
// stored record, and both refuse a bad one without reaching Datadog.
func TestRevokeAndStatusValidateBeforeCalling(t *testing.T) {
	badSite := metadata()
	badSite[datadog.MetadataSite] = "attacker.example.com"

	for _, tc := range []struct {
		Name  string
		KeyID string
		Md    credentials.Metadata
	}{
		{"blank handle", "", metadata()},
		{"missing admin key", "key-id-1", credentials.Metadata{datadog.MetadataAdminAppKey: fixtureAdminAppKey}},
		{"unallowlisted site", "key-id-1", badSite},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			rec := &recorder{}
			p := rec.provider(reply{Status: 200, Body: "{}"})

			if err := p.RevokeCredential(context.Background(), tc.KeyID, tc.Md); err == nil {
				t.Error("RevokeCredential succeeded")
			}
			status, err := p.GetCredentialStatus(context.Background(), tc.KeyID, tc.Md)
			if err == nil {
				t.Error("GetCredentialStatus succeeded")
			}
			if status != credentials.CredentialStatusUnknown {
				t.Errorf("status = %q, want unknown on a refusal", status)
			}
			if len(rec.requests) != 0 {
				t.Errorf("%d request(s) reached Datadog", len(rec.requests))
			}
		})
	}
}

// dumpingTransport is the accidental-instrumentation failure review reproduced: a
// transport that has seen the authenticated request and includes it in its own
// diagnostic error. Nothing here is malicious; a tracing layer that annotates
// failures with request detail is an ordinary thing to write.
func dumpingTransport() http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var dump bytes.Buffer
		dump.WriteString("dial failed for " + req.Method + " " + req.URL.String() + " with headers: ")
		for name, values := range req.Header {
			dump.WriteString(name + "=" + strings.Join(values, ",") + " ")
		}
		return nil, errors.New(dump.String())
	})
}

// TestTransportErrorsCarryNoRequestDetail is review's second reproduction. The
// previous implementation wrapped the error from http.Client.Do with %w, so a
// transport that dumped its request returned the full DD-API-KEY through the
// provider's error.
func TestTransportErrorsCarryNoRequestDetail(t *testing.T) {
	p := datadog.NewProvider(datadog.WithTransport(dumpingTransport()))

	check := func(t *testing.T, label string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: expected an error", label)
		}
		for _, forbidden := range []string{
			fixtureAdminAPIKey, fixtureAdminAppKey,
			// Not just the material: no text from the transport at all. Asserting on
			// the header name as well as the value is what makes this a test of the
			// class rather than of one fixture.
			"DD-API-KEY", "Dd-Api-Key", "headers:", "dial failed",
		} {
			if strings.Contains(err.Error(), forbidden) {
				t.Errorf("%s: error carries %q: %v", label, forbidden, err)
			}
		}
		if !errors.Is(err, credentials.ErrTransient) {
			t.Errorf("%s: a transport failure must still classify as transient: %v", label, err)
		}
	}

	_, err := p.CreateCredential(context.Background(), staticRequest())
	check(t, "create", err)
	check(t, "revoke", p.RevokeCredential(context.Background(), "key-id-1", metadata()))
	_, err = p.GetCredentialStatus(context.Background(), "key-id-1", metadata())
	check(t, "status", err)
}

// TestASuppliedTransportCannotReEnableRedirects is review's first reproduction,
// against the narrowed API.
//
// The bypass was that WithHTTPClient replaced the whole *http.Client, and redirect
// refusal is a field on it -- so a caller supplying a client for tracing silently
// turned the refusal into Go's default of following. The API now accepts only a
// RoundTripper, which cannot express a redirect policy, so the test's job is to
// prove the refusal survives a replacement made through the only seam that
// remains.
func TestASuppliedTransportCannotReEnableRedirects(t *testing.T) {
	var seen []*http.Request
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = append(seen, req)
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://attacker.example.com/collect"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	p := datadog.NewProvider(datadog.WithTransport(rt))

	_, err := p.CreateCredential(context.Background(), staticRequest())
	if !errors.Is(err, credentials.ErrRedirectRefused) {
		t.Fatalf("CreateCredential = %v, want ErrRedirectRefused", err)
	}
	if errors.Is(err, credentials.ErrTransient) {
		t.Error("a refused redirect must not be transient; retrying a misconfiguration is not a retry policy")
	}
	if len(seen) != 1 {
		t.Fatalf("the transport saw %d requests; the redirect was followed", len(seen))
	}
	if seen[0].URL.Host != "api.datadoghq.com" {
		t.Errorf("first request went to %q", seen[0].URL.Host)
	}
	// The refusal message must not quote the Location header either: that value is
	// upstream-controlled, and it is the same class of mistake as formatting a
	// response body into an error.
	if strings.Contains(err.Error(), "attacker.example.com") {
		t.Errorf("the refusal reflected the redirect target: %v", err)
	}
}

// TestNoMetadataValueReachesAnError is the class-level invariant, and the reason
// it exists is that review's findings were not the failures of individual
// judgement calls but of a property nobody had stated: no error from this package
// contains text that arrived from outside it.
//
// Every metadata value here is a unique sentinel, so any error that echoes one
// fails regardless of which path produced it. credentials.Metadata already
// establishes that metadata values do not render; this holds the providers to the
// same rule.
func TestNoMetadataValueReachesAnError(t *testing.T) {
	const (
		sentinelAPIKey = "SENTINEL-metadata-admin-api-key"
		sentinelAppKey = "SENTINEL-metadata-admin-app-key"
		sentinelSite   = "SENTINEL-metadata-dd-site"
	)
	sentinels := []string{sentinelAPIKey, sentinelAppKey, sentinelSite}

	cases := map[string]credentials.Metadata{
		"unallowlisted site": {
			datadog.MetadataAdminAPIKey: sentinelAPIKey,
			datadog.MetadataAdminAppKey: sentinelAppKey,
			datadog.MetadataSite:        sentinelSite,
		},
		"valid site, upstream refuses": {
			datadog.MetadataAdminAPIKey: sentinelAPIKey,
			datadog.MetadataAdminAppKey: sentinelAppKey,
			datadog.MetadataSite:        "api.datadoghq.eu",
		},
		"blank app key": {
			datadog.MetadataAdminAPIKey: sentinelAPIKey,
			datadog.MetadataAdminAppKey: "",
		},
	}

	for name, md := range cases {
		t.Run(name, func(t *testing.T) {
			// Two response shapes: an upstream refusal, and a 2xx that reflects a
			// sentinel back through data.id.
			for _, rep := range []reply{
				{Status: 403, Body: `{"errors":["denied"]}`},
				{Status: 201, Body: fmt.Sprintf(`{"data":{"id":%q,"attributes":{}}}`, sentinelAPIKey)},
			} {
				rec := &recorder{}
				p := rec.provider(rep)

				req := staticRequest()
				req.Metadata = md
				req.RequestedScope = nil

				var errs []error
				_, err := p.CreateCredential(context.Background(), req)
				errs = append(errs, err)
				errs = append(errs, p.RevokeCredential(context.Background(), "key-id-1", md))
				_, err = p.GetCredentialStatus(context.Background(), "key-id-1", md)
				errs = append(errs, err)

				// A scoped request and a bad type exercise the pre-flight refusals.
				scoped := req
				scoped.RequestedScope = []string{"metrics:read"}
				_, err = p.CreateCredential(context.Background(), scoped)
				errs = append(errs, err)
				wrongType := req
				wrongType.CredentialType = credentials.CredentialTypeDynamic
				_, err = p.CreateCredential(context.Background(), wrongType)
				errs = append(errs, err)

				for _, err := range errs {
					if err == nil {
						continue
					}
					for _, sentinel := range sentinels {
						// Case-insensitive: extractAuth lowercases dd_site, and a
						// case-sensitive check let a normalized copy of a metadata value
						// through. A normalizing path is still an echoing path.
						if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(sentinel)) {
							t.Errorf("error echoed a metadata value: %v", err)
						}
					}
				}
			}
		})
	}
}
