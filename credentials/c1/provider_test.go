// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1_test

// Provider is exercised through the real HTTP client over a fake transport,
// rather than over a fake c1.Client.
//
// That is not a stylistic preference. c1.Client is sealed -- an implementation
// from outside the package would be an API accepting arbitrary text that
// Provider renders back out, which is the defect the USOSS-7 review found four
// times -- so the substitution point is Deps.Transport, the same one
// credentials/datadog and credentials/github offer. It also makes these tests
// stronger than they would have been: every one of them now exercises the real
// request construction, the real path escaping and the real response decoding on
// its way to the behaviour it is about.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/c1"
)

// The two identifiers these tests mint against. Both are inside the handle
// grammar and neither resembles anything real.
// Deliberately low-entropy and repetitive. An earlier pair of values read like
// generated identifiers and the repository's own secret gate flagged one of them
// as a credential-shaped assignment -- correctly, on the shape rather than on the
// value. Fixture identifiers should not look like material.
const (
	testPrincipal   = "sp1111111111111111111111111"
	testCredential  = "fixture-fixture-11111"
	otherPrincipal  = "sp2222222222222222222222222"
	otherCredential = "fixture-fixture-22222"
)

// reply is one canned HTTP answer.
type reply struct {
	status int
	body   string
}

// script answers the credential API by HTTP method. A method with no entry is a
// test asserting that method is never called, so it answers 500 loudly rather
// than succeeding quietly.
type script struct {
	post   *reply
	get    *reply
	delete *reply
}

func (s script) transport() *fakeTransport {
	return &fakeTransport{api: func(req *http.Request) (*http.Response, error) {
		var r *reply
		switch req.Method {
		case http.MethodPost:
			r = s.post
		case http.MethodGet:
			r = s.get
		case http.MethodDelete:
			r = s.delete
		}
		if r == nil {
			return jsonResponse(http.StatusInternalServerError,
				`{"message":"this test did not script a `+req.Method+`"}`, req), nil
		}
		return jsonResponse(r.status, r.body, req), nil
	}}
}

// credentialJSON builds a mint or get response body.
func credentialJSON(credID, clientID, secret, expiresAt string, roles []string) string {
	var b strings.Builder
	b.WriteString(`{"credential":{"id":"` + credID + `","servicePrincipalId":"` + testPrincipal + `"`)
	if clientID != "" {
		b.WriteString(`,"clientId":"` + clientID + `"`)
	}
	if expiresAt != "" {
		b.WriteString(`,"expiresAt":"` + expiresAt + `"`)
	}
	if roles != nil {
		b.WriteString(`,"scopedRoleIds":["` + strings.Join(roles, `","`) + `"]`)
	}
	b.WriteString(`}`)
	if secret != "" {
		b.WriteString(`,"clientSecret":"` + secret + `"`)
	}
	b.WriteString(`}`)
	return b.String()
}

// goodMint is a complete, well-formed mint response.
func goodMint(roles []string) *reply {
	return &reply{http.StatusOK, credentialJSON(testCredential, "client-id-value", "client-secret-value", "2030-01-01T00:00:00Z", roles)}
}

func providerOver(t *testing.T, ft *fakeTransport) *c1.Provider {
	t.Helper()
	client, err := c1.NewClient(secretModeConfig(), c1.Deps{
		Secrets:   &stubSecrets{secret: credentials.NewSecret("apphub-client-secret")},
		Transport: ft,
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

// requestsByMethod counts what the transport actually saw, so a test can assert
// that a refusal happened before anything went out and that a compensating
// revoke did or did not run.
func requestsByMethod(ft *fakeTransport, method string) []recordedRequest {
	var out []recordedRequest
	for _, r := range ft.apiRequests() {
		if r.Method == method {
			out = append(out, r)
		}
	}
	return out
}

func testMetadata() credentials.Metadata {
	return credentials.Metadata{c1.MetadataServicePrincipalID: testPrincipal}
}

func dynamicRequest() credentials.CreateRequest {
	return credentials.CreateRequest{
		Name:           "apphub-vended",
		CredentialType: credentials.CredentialTypeDynamic,
		TTL:            time.Hour,
		Metadata:       testMetadata(),
	}
}

func handleFor(t *testing.T, ref c1.Ref) string {
	t.Helper()
	h, err := c1.FormatHandle(ref)
	if err != nil {
		t.Fatalf("FormatHandle: %v", err)
	}
	return h
}

// -- the interface, and what the provider claims about itself ----------------

func TestProviderSatisfiesTheContractAndDeclaresWhatTheAPICanDo(t *testing.T) {
	p := providerOver(t, script{}.transport())

	if p.ID() != "c1" {
		t.Errorf("ID() = %q, want c1", p.ID())
	}
	if p.Name() != "ConductorOne" {
		t.Errorf("Name() = %q, want ConductorOne", p.Name())
	}
	if !p.SupportsDynamic() {
		t.Error("SupportsDynamic() = false; short-lived credentials are the integration")
	}

	want := credentials.Capabilities{
		Dynamic: true, Static: false, Revoke: true, Status: true, Rotate: false, RecoverCreate: false,
	}
	if got := p.Capabilities(); got != want {
		t.Errorf("Capabilities() = %+v, want %+v", got, want)
	}
	// CapabilitiesOf must agree. It clears RecoverCreate for a provider that does
	// not implement credentials.CreateRecoverer, so a disagreement here would mean
	// the declaration and the interfaces had drifted apart.
	if got := credentials.CapabilitiesOf(p); got != want {
		t.Errorf("CapabilitiesOf() = %+v, want %+v", got, want)
	}
}

func TestProviderDoesNotClaimToRecoverAnAmbiguousVend(t *testing.T) {
	// Assumption A4 stated as a compile-time fact rather than as a sentence in a
	// document. ConductorOne's create request has no idempotency key and returns
	// the secret exactly once, so there is nothing to resolve a lost vend by. A
	// future author who adds a ResolveCreate method that guesses -- by listing
	// credentials and matching on a display name, say -- makes this test fail,
	// which is the point: lifecycle.CheckIssuable admits managed issuance on the
	// strength of this interface.
	if _, ok := any(providerOver(t, script{}.transport())).(credentials.CreateRecoverer); ok {
		t.Fatal("Provider implements credentials.CreateRecoverer; ConductorOne has no idempotency key to resolve a vend by")
	}
}

// -- create -----------------------------------------------------------------

func TestCreateRefusesEveryCredentialTypeButDynamic(t *testing.T) {
	// The population is every type the enum has plus the shapes an unset or
	// mistyped field takes, rather than the one case ("static") the
	// implementation names.
	population := []credentials.CredentialType{
		credentials.CredentialTypeStatic, "", "Dynamic", "dynamic ", "STATIC", "something-new",
	}
	if len(population) == 0 {
		t.Fatal("empty population")
	}
	for _, ct := range population {
		ft := script{post: goodMint(nil)}.transport()
		req := dynamicRequest()
		req.CredentialType = ct
		_, err := providerOver(t, ft).CreateCredential(context.Background(), req)
		if !errors.Is(err, c1.ErrStaticNotSupported) {
			t.Errorf("CreateCredential(type=%q) err = %v, want ErrStaticNotSupported", ct, err)
		}
		if len(ft.seen) != 0 {
			t.Errorf("CreateCredential(type=%q) reached the network before refusing", ct)
		}
	}
	// The other direction: the one accepted type must not be refused, or this
	// test would pass against a provider that refuses everything.
	ft := script{post: goodMint(nil)}.transport()
	if _, err := providerOver(t, ft).CreateCredential(context.Background(), dynamicRequest()); err != nil {
		t.Fatalf("CreateCredential refused the dynamic type it is supposed to accept: %v", err)
	}
}

func TestCreateRequiresAUsableServicePrincipal(t *testing.T) {
	for i, md := range []credentials.Metadata{
		nil,
		{},
		{c1.MetadataServicePrincipalID: ""},
		{c1.MetadataServicePrincipalID: "   "},
		{"c1_service_principal": testPrincipal}, // a near-miss key
	} {
		ft := script{post: goodMint(nil)}.transport()
		req := dynamicRequest()
		req.Metadata = md
		_, err := providerOver(t, ft).CreateCredential(context.Background(), req)
		if !errors.Is(err, c1.ErrServicePrincipalRequired) {
			t.Errorf("metadata[%d]: err = %v, want ErrServicePrincipalRequired", i, err)
		}
		if len(ft.seen) != 0 {
			t.Errorf("metadata[%d]: reached the network before refusing", i)
		}
	}

	// Anything outside the handle grammar is refused for the same reason a handle
	// is: this value is interpolated into a URL path.
	for _, bad := range invalidSegments() {
		if strings.TrimSpace(bad) == "" {
			continue // covered above as "required"
		}
		ft := script{post: goodMint(nil)}.transport()
		req := dynamicRequest()
		req.Metadata = credentials.Metadata{c1.MetadataServicePrincipalID: bad}
		_, err := providerOver(t, ft).CreateCredential(context.Background(), req)
		if !errors.Is(err, c1.ErrMalformedServicePrincipalID) && !errors.Is(err, c1.ErrServicePrincipalRequired) {
			t.Errorf("service principal of length %d: err = %v, want a refusal", len(bad), err)
		}
		if len(ft.seen) != 0 {
			t.Errorf("service principal of length %d reached the network", len(bad))
		}
	}
}

func TestCreateSendsTheRequestItWasGivenAndRecordsWhatWasGranted(t *testing.T) {
	ft := script{post: goodMint([]string{"roleA"})}.transport()
	req := dynamicRequest()
	req.TTL = 37 * time.Minute
	req.RequestedScope = []string{"roleA", "roleB"}

	res, err := providerOver(t, ft).CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	posts := requestsByMethod(ft, http.MethodPost)
	if len(posts) != 1 {
		t.Fatalf("%d POSTs, want 1", len(posts))
	}
	if want := "/api/v1/service_principals/" + testPrincipal + "/credentials"; posts[0].Path != want {
		t.Errorf("POST path = %q, want %q", posts[0].Path, want)
	}
	// The TTL must reach the wire unaltered by the provider. Clamping to the
	// upstream ceiling is the client's job, where the ceiling is a fact about the
	// API rather than a second opinion about policy.
	if want := fmt.Sprintf(`"expires":"%ds"`, int64((37 * time.Minute).Seconds())); !strings.Contains(posts[0].Body, want) {
		t.Errorf("POST body %q does not carry %s", posts[0].Body, want)
	}
	if !strings.Contains(posts[0].Body, `"scopedRoles":["roleA","roleB"]`) {
		t.Errorf("POST body %q does not carry the requested scope", posts[0].Body)
	}
	if !strings.Contains(posts[0].Body, `"displayName":"apphub-vended"`) {
		t.Errorf("POST body %q does not carry the requested name", posts[0].Body)
	}

	// The result records what was granted, not what was asked for.
	if len(res.GrantedScope) != 1 || res.GrantedScope[0] != "roleA" {
		t.Errorf("GrantedScope = %v, want the upstream's narrower list", res.GrantedScope)
	}
	if res.ExpiresAt == nil || res.ExpiresAt.Year() != 2030 {
		t.Errorf("ExpiresAt = %v, want the upstream's value", res.ExpiresAt)
	}
	if !res.APIKey.IsZero() {
		t.Error("APIKey was set; a ConductorOne credential has two halves and belongs in Credentials")
	}
	for _, key := range []string{c1.CredentialKeyClientID, c1.CredentialKeyClientSecret} {
		if res.Credentials[key].IsZero() {
			t.Errorf("Credentials[%q] is empty", key)
		}
	}
	if got := credentials.Reveal(res.Credentials[c1.CredentialKeyClientSecret]); got != "client-secret-value" {
		t.Error("the client secret was not the one the upstream returned")
	}
}

func TestCreateProducesASelfContainedHandle(t *testing.T) {
	ft := script{post: goodMint(nil)}.transport()
	res, err := providerOver(t, ft).CreateCredential(context.Background(), dynamicRequest())
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	ref, err := c1.ParseHandle(res.PlatformKeyID)
	if err != nil {
		t.Fatalf("the handle CreateCredential produced does not parse: %v", err)
	}
	if ref.ServicePrincipalID != testPrincipal || ref.CredentialID != testCredential {
		t.Fatalf("the handle names the wrong credential")
	}

	// The whole point of the handle carrying both halves: a revoke needs no
	// metadata at all, so no caller can change what gets revoked by changing what
	// it passes.
	revokeFT := script{delete: &reply{http.StatusOK, `{}`}}.transport()
	if err := providerOver(t, revokeFT).RevokeCredential(context.Background(), res.PlatformKeyID, nil); err != nil {
		t.Fatalf("RevokeCredential with nil metadata: %v", err)
	}
	deletes := requestsByMethod(revokeFT, http.MethodDelete)
	if len(deletes) != 1 {
		t.Fatalf("%d DELETEs, want 1", len(deletes))
	}
	if want := "/api/v1/service_principals/" + testPrincipal + "/credentials/" + testCredential; deletes[0].Path != want {
		t.Errorf("DELETE path = %q, want %q", deletes[0].Path, want)
	}
}

// -- least privilege --------------------------------------------------------

func TestCreateRefusesAndRevokesAWidenedScope(t *testing.T) {
	ft := script{
		post:   goodMint([]string{"roleA", "roleUNASKED"}),
		delete: &reply{http.StatusOK, `{}`},
	}.transport()
	req := dynamicRequest()
	req.RequestedScope = []string{"roleA"}

	res, err := providerOver(t, ft).CreateCredential(context.Background(), req)
	if res != nil {
		t.Error("CreateCredential returned a credential wider than the request")
	}
	if !errors.Is(err, c1.ErrScopeWidened) {
		t.Fatalf("err = %v, want ErrScopeWidened", err)
	}
	deletes := requestsByMethod(ft, http.MethodDelete)
	if len(deletes) != 1 {
		t.Fatalf("the over-privileged credential was revoked %d times, want 1", len(deletes))
	}
	if !strings.HasSuffix(deletes[0].Path, "/"+testCredential) {
		t.Errorf("the compensating revoke targeted %q", deletes[0].Path)
	}
	// Nothing lives upstream, so there is no handle for the lifecycle layer to
	// compensate with and none should be offered.
	var undelivered *credentials.CreateNotDeliveredError
	if errors.As(err, &undelivered) {
		t.Error("a successfully compensated widening was reported as an undelivered credential")
	}
}

func TestAWidenedScopeThatCannotBeRevokedTravelsAsAnUndeliveredCredential(t *testing.T) {
	ft := script{
		post:   goodMint([]string{"roleA", "roleUNASKED"}),
		delete: &reply{http.StatusInternalServerError, `{"message":"upstream said no"}`},
	}.transport()
	req := dynamicRequest()
	req.RequestedScope = []string{"roleA"}

	_, err := providerOver(t, ft).CreateCredential(context.Background(), req)
	if !errors.Is(err, c1.ErrScopeWidened) {
		t.Errorf("the reason was lost: err = %v", err)
	}
	var undelivered *credentials.CreateNotDeliveredError
	if !errors.As(err, &undelivered) {
		t.Fatalf("a live over-privileged credential was reported without its handle: %v", err)
	}
	if undelivered.PlatformKeyID().IsZero() {
		t.Fatal("the undelivered error carries no handle, so nothing can revoke the credential")
	}
	// The handle comes back through RevealForeign rather than as a bare string: it
	// is a value the upstream response chose, so recovering it is a deliberate act
	// and the accessor refuses to render.
	ref, parseErr := c1.ParseHandle(credentials.RevealForeign(undelivered.PlatformKeyID()))
	if parseErr != nil || ref.CredentialID != testCredential {
		t.Fatalf("the recoverable handle does not name the live credential: %v", parseErr)
	}
	if strings.Contains(err.Error(), testCredential) {
		t.Error("the error rendered the handle")
	}
}

func TestAnUnscopedRequestNeverTripsTheWideningCheck(t *testing.T) {
	// An empty RequestedScope is "do not narrow", and ConductorOne answers with
	// the service principal's own roles. Comparing those against an empty request
	// would report every one as a widening, which would make the check fire on
	// every ordinary vend.
	//
	// This is the generalisation the check's first form got wrong, and it is the
	// half a test that only exercised a narrowed request could not see.
	for _, granted := range [][]string{nil, {}, {"roleA"}, {"roleA", "roleB", "roleC"}} {
		ft := script{post: goodMint(granted), delete: &reply{http.StatusOK, `{}`}}.transport()
		req := dynamicRequest()
		req.RequestedScope = nil
		if _, err := providerOver(t, ft).CreateCredential(context.Background(), req); err != nil {
			t.Errorf("unscoped request with %d granted roles was refused: %v", len(granted), err)
		}
		if n := len(requestsByMethod(ft, http.MethodDelete)); n != 0 {
			t.Errorf("unscoped request with %d granted roles triggered %d compensating revokes", len(granted), n)
		}
	}
}

func TestANarrowedScopeIsAccepted(t *testing.T) {
	// The other direction of the widening check: a grant that is a subset of the
	// request is correct behaviour and must not be refused, or the check would be
	// indistinguishable from one that refuses every scoped vend.
	for _, granted := range [][]string{nil, {"roleA"}, {"roleA", "roleB"}} {
		ft := script{post: goodMint(granted), delete: &reply{http.StatusOK, `{}`}}.transport()
		req := dynamicRequest()
		req.RequestedScope = []string{"roleA", "roleB", "roleC"}
		if _, err := providerOver(t, ft).CreateCredential(context.Background(), req); err != nil {
			t.Errorf("a narrowed grant of %d roles was refused: %v", len(granted), err)
		}
		if n := len(requestsByMethod(ft, http.MethodDelete)); n != 0 {
			t.Errorf("a narrowed grant of %d roles triggered %d compensating revokes", len(granted), n)
		}
	}
}

// -- undelivered material ---------------------------------------------------

func TestACredentialMissingEitherHalfIsUndeliveredAndIsNotRevokedHere(t *testing.T) {
	// A consumer needs both halves, so either one missing is an undelivered
	// credential. The population is both halves rather than the secret alone,
	// because a response with a secret and no client id is just as unusable and is
	// the case a test written around "the secret is missing" would not have.
	incomplete := map[string]string{
		"no secret":    credentialJSON(testCredential, "client-id-value", "", "", nil),
		"no client id": credentialJSON(testCredential, "", "client-secret-value", "", nil),
		"neither":      credentialJSON(testCredential, "", "", "", nil),
	}
	for name, body := range incomplete {
		ft := script{post: &reply{http.StatusOK, body}, delete: &reply{http.StatusOK, `{}`}}.transport()
		_, err := providerOver(t, ft).CreateCredential(context.Background(), dynamicRequest())
		var undelivered *credentials.CreateNotDeliveredError
		if !errors.As(err, &undelivered) {
			t.Errorf("%s: err = %v, want a CreateNotDeliveredError", name, err)
			continue
		}
		if undelivered.PlatformKeyID().IsZero() {
			t.Errorf("%s: the handle did not survive", name)
		}
		if got := credentials.RevealForeign(undelivered.PlatformKeyID()); got != handleFor(t, c1.Ref{
			ServicePrincipalID: testPrincipal, CredentialID: testCredential,
		}) {
			t.Errorf("%s: the surviving handle does not name the credential", name)
		}
		if got := credentials.RevealForeign(undelivered.ProviderID()); got != "c1" {
			t.Errorf("%s: ProviderID() = %q", name, got)
		}
		// Deliberately not compensated here: whether to revoke a credential whose
		// material was lost is the lifecycle layer's decision, and a provider that
		// revoked on its way out would be making it where nobody can see it.
		if n := len(requestsByMethod(ft, http.MethodDelete)); n != 0 {
			t.Errorf("%s: the provider compensated on its own (%d DELETEs)", name, n)
		}
	}
}

// -- revoke -----------------------------------------------------------------

func TestRevokeTargetsExactlyTheCredentialItsHandleNames(t *testing.T) {
	// A revoke that reached a different credential than the one asked for would be
	// invisible to a test that only checked the returned error, because the
	// upstream reports success either way. Distinct handles, asserted separately,
	// is what makes that observable.
	for _, want := range []c1.Ref{
		{ServicePrincipalID: testPrincipal, CredentialID: testCredential},
		{ServicePrincipalID: otherPrincipal, CredentialID: otherCredential},
		{ServicePrincipalID: testPrincipal, CredentialID: otherCredential},
	} {
		ft := script{delete: &reply{http.StatusOK, `{}`}}.transport()
		if err := providerOver(t, ft).RevokeCredential(context.Background(), handleFor(t, want), testMetadata()); err != nil {
			t.Fatalf("RevokeCredential: %v", err)
		}
		deletes := requestsByMethod(ft, http.MethodDelete)
		if len(deletes) != 1 {
			t.Fatalf("%d DELETEs, want 1", len(deletes))
		}
		wantPath := "/api/v1/service_principals/" + want.ServicePrincipalID + "/credentials/" + want.CredentialID
		if deletes[0].Path != wantPath {
			t.Errorf("DELETE path = %q, want %q", deletes[0].Path, wantPath)
		}
	}
}

func TestRevokeIgnoresMetadataEntirely(t *testing.T) {
	// If the service principal came from metadata, a caller supplying a different
	// one would revoke against the wrong principal -- and because revoking
	// something absent succeeds, it would report a successful revoke having
	// revoked nothing. The handle is the only input.
	handle := handleFor(t, c1.Ref{ServicePrincipalID: testPrincipal, CredentialID: testCredential})
	wantPath := "/api/v1/service_principals/" + testPrincipal + "/credentials/" + testCredential
	for _, md := range []credentials.Metadata{
		nil,
		{},
		{c1.MetadataServicePrincipalID: otherPrincipal},
		{c1.MetadataServicePrincipalID: "../../elsewhere"},
	} {
		ft := script{delete: &reply{http.StatusOK, `{}`}}.transport()
		if err := providerOver(t, ft).RevokeCredential(context.Background(), handle, md); err != nil {
			t.Fatalf("RevokeCredential: %v", err)
		}
		if got := requestsByMethod(ft, http.MethodDelete)[0].Path; got != wantPath {
			t.Errorf("metadata changed the revoke target to %q", got)
		}
	}
}

func TestRevokeNeverReportsThatItIsUnsupported(t *testing.T) {
	// ConductorOne can revoke by identifier, so this provider has no business
	// returning credentials.ErrRevokeNotSupported. The population is every way the
	// revoke path can fail, because the sentinel leaking in through one of them is
	// how a provider ends up quietly telling the lifecycle layer that a credential
	// can only be left to expire.
	handle := handleFor(t, c1.Ref{ServicePrincipalID: testPrincipal, CredentialID: testCredential})
	for _, status := range []int{200, 204, 400, 401, 403, 404, 409, 429, 500, 502, 503} {
		ft := script{delete: &reply{status, `{"message":"upstream detail"}`}}.transport()
		if err := providerOver(t, ft).RevokeCredential(context.Background(), handle, nil); errors.Is(err, credentials.ErrRevokeNotSupported) {
			t.Errorf("RevokeCredential reported ErrRevokeNotSupported for status %d", status)
		}
	}
	// A dial failure, and a token exchange that fails.
	for _, ft := range []*fakeTransport{
		{token: func(*http.Request) (*http.Response, error) { return nil, errors.New("dial failed") }},
		{token: func(req *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusUnauthorized, `{}`, req), nil
		}},
	} {
		if err := providerOver(t, ft).RevokeCredential(context.Background(), handle, nil); errors.Is(err, credentials.ErrRevokeNotSupported) {
			t.Error("RevokeCredential reported ErrRevokeNotSupported for a transport or auth failure")
		}
	}
	// And a malformed handle, which is refused locally.
	ft := script{delete: &reply{http.StatusOK, `{}`}}.transport()
	got := providerOver(t, ft).RevokeCredential(context.Background(), "not a handle", nil)
	if errors.Is(got, credentials.ErrRevokeNotSupported) {
		t.Error("a malformed handle was reported as an unsupported revoke")
	}
	if !errors.Is(got, c1.ErrMalformedHandle) {
		t.Errorf("err = %v, want ErrMalformedHandle", got)
	}
	if len(ft.seen) != 0 {
		t.Error("a malformed handle reached the network")
	}
}

func TestRevokeOfSomethingAlreadyGoneSucceeds(t *testing.T) {
	handle := handleFor(t, c1.Ref{ServicePrincipalID: testPrincipal, CredentialID: testCredential})
	ft := script{delete: &reply{http.StatusNotFound, `{"message":"gone"}`}}.transport()
	if err := providerOver(t, ft).RevokeCredential(context.Background(), handle, nil); err != nil {
		t.Errorf("err = %v; the reconciler would retry forever", err)
	}
}

// -- status -----------------------------------------------------------------

func TestStatusIsTheDocumentedFunctionOfWhatTheUpstreamSaid(t *testing.T) {
	handle := handleFor(t, c1.Ref{ServicePrincipalID: testPrincipal, CredentialID: testCredential})
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)

	population := []struct {
		name    string
		reply   *reply
		want    credentials.CredentialStatus
		wantErr bool
	}{
		{"expiry in the future", &reply{200, credentialJSON(testCredential, "c", "", future, nil)}, credentials.CredentialStatusActive, false},
		{"expiry in the past", &reply{200, credentialJSON(testCredential, "c", "", past, nil)}, credentials.CredentialStatusExpired, false},
		{"absent upstream", &reply{404, `{"message":"gone"}`}, credentials.CredentialStatusUnknown, false},
		{"present with no stated expiry", &reply{200, credentialJSON(testCredential, "c", "", "", nil)}, credentials.CredentialStatusUnknown, false},
		{"apphub is not authenticated", &reply{401, `{}`}, credentials.CredentialStatusUnknown, true},
		{"upstream is unwell", &reply{503, `{}`}, credentials.CredentialStatusUnknown, true},
		{"a response that is not a credential", &reply{200, `{"credential":{}}`}, credentials.CredentialStatusUnknown, true},
	}

	seen := map[credentials.CredentialStatus]int{}
	for _, o := range population {
		ft := script{get: o.reply}.transport()
		got, err := providerOver(t, ft).GetCredentialStatus(context.Background(), handle, nil)
		if got != o.want {
			t.Errorf("%s: status = %q, want %q", o.name, got, o.want)
		}
		if (err != nil) != o.wantErr {
			t.Errorf("%s: err = %v, wantErr = %t", o.name, err, o.wantErr)
		}
		seen[got]++
	}

	// Both directions. A mapping that answered "unknown" to everything would
	// satisfy every assertion above, so the statuses that must be reachable are
	// asserted reachable.
	for _, must := range []credentials.CredentialStatus{
		credentials.CredentialStatusActive,
		credentials.CredentialStatusExpired,
		credentials.CredentialStatusUnknown,
	} {
		if seen[must] == 0 {
			t.Errorf("no input in a population of %d produced %q; the mapping has collapsed", len(population), must)
		}
	}
	// And the one that is not reachable, which is a documented limit of the API
	// rather than an oversight: a revoked credential is deleted rather than
	// tombstoned, so absence cannot be told apart from expiry-and-cleanup.
	// Reporting revoked would be the platform concluding a credential is dead on
	// the strength of a 404. If ConductorOne ever grows a revoked-but-present
	// state, this is the test that says the mapping has to be revisited.
	if seen[credentials.CredentialStatusRevoked] != 0 {
		t.Error("a status read reported revoked; ConductorOne has no revoked-but-present state to observe")
	}
}

func TestStatusRefusesAMalformedHandleWithoutCallingUpstream(t *testing.T) {
	for _, bad := range []string{"", "no-separator", "a/b/c", "../x", "x/..", " /x"} {
		ft := script{get: &reply{200, credentialJSON(testCredential, "c", "", "", nil)}}.transport()
		got, err := providerOver(t, ft).GetCredentialStatus(context.Background(), bad, nil)
		if !errors.Is(err, c1.ErrMalformedHandle) {
			t.Errorf("handle of length %d: err = %v, want ErrMalformedHandle", len(bad), err)
		}
		if got != credentials.CredentialStatusUnknown {
			t.Errorf("handle of length %d: status = %q, want unknown", len(bad), got)
		}
		if len(ft.seen) != 0 {
			t.Errorf("handle of length %d reached the network", len(bad))
		}
	}
}

func TestNewProviderRefusesANilClient(t *testing.T) {
	if _, err := c1.NewProvider(nil); err == nil {
		t.Fatal("NewProvider accepted a nil client")
	}
}

// -- registration -----------------------------------------------------------

func TestRegisterIsTheSinglePinnedEntryPoint(t *testing.T) {
	var _ c1.RegisterFunc = c1.Register

	// An unconfigured deployment: nothing registered, and not an error the caller
	// has to special-case as "off".
	reg := credentials.NewProviderRegistry()
	if err := c1.Register(reg, c1.Config{}, c1.Deps{}); !errors.Is(err, c1.ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNotConfigured", err)
	}
	if n := len(reg.List()); n != 0 {
		t.Errorf("%d providers registered from an empty configuration", n)
	}

	// A half-configured one: an error, and still nothing registered. A deployment
	// that believes it has ConductorOne vending and does not is worse than one
	// that fails to start.
	for name, cfg := range map[string]c1.Config{
		"tenant only":       {TenantURL: testTenant},
		"no secret ref":     {TenantURL: testTenant, ClientID: testClientID},
		"plain http tenant": {TenantURL: "http://tenant.example.invalid", ClientID: testClientID, ClientSecret: credentials.SecretRef{Name: "x"}},
	} {
		reg := credentials.NewProviderRegistry()
		err := c1.Register(reg, cfg, c1.Deps{Secrets: &stubSecrets{}})
		if err == nil {
			t.Errorf("%s: Register accepted a half-configured deployment", name)
		}
		if errors.Is(err, c1.ErrNotConfigured) {
			t.Errorf("%s: a half-configured deployment was reported as unconfigured", name)
		}
		if n := len(reg.List()); n != 0 {
			t.Errorf("%s: %d providers registered despite the failure", name, n)
		}
	}

	// And the other direction: a complete configuration registers exactly one
	// provider, under the expected ID, without dialling anything.
	reg = credentials.NewProviderRegistry()
	ft := script{}.transport()
	if err := c1.Register(reg, secretModeConfig(), c1.Deps{Secrets: &stubSecrets{}, Transport: ft}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if n := len(reg.List()); n != 1 {
		t.Fatalf("%d providers registered, want 1", n)
	}
	if _, ok := reg.Get("c1"); !ok {
		t.Error(`no provider registered under "c1"`)
	}
	if len(ft.seen) != 0 {
		t.Errorf("Register issued %d HTTP requests; startup must not dial ConductorOne", len(ft.seen))
	}

	// A nil registry is a wiring bug, not something to register into.
	if err := c1.Register(nil, secretModeConfig(), c1.Deps{Secrets: &stubSecrets{}}); err == nil {
		t.Error("Register accepted a nil registry")
	}
}
