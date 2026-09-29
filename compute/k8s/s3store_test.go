// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/k8s"
)

// hexDigest is the payload digest SigV4 signs as a header. The test computes it
// with the standard library rather than through an exported hook, so the signer
// and the test do not share an implementation of the one input the signature is
// most sensitive to.
func hexDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// recordedRequest is one request the store client issued.
type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Auth   string
	Body   string
	Header http.Header
}

// storeStub answers the object store's requests in memory.
//
// It is a [http.RoundTripper] rather than an httptest.Server on purpose. A
// loopback server binds a port, and this environment is shared with other
// workers; a round tripper opens no socket at all, so the hermeticity claim is
// structural rather than "an ephemeral port is probably fine".
type storeStub struct {
	mu       sync.Mutex
	requests []recordedRequest
	// answer maps "METHOD path?query" onto a response. A request with no entry
	// gets 404, which is what makes a missing expectation a visible failure
	// rather than a silent pass.
	answer map[string]stubResponse
}

type stubResponse struct {
	status int
	body   string
}

func newStoreStub() *storeStub {
	return &storeStub{answer: map[string]stubResponse{}}
}

func (s *storeStub) on(method, pathAndQuery string, status int, body string) *storeStub {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answer[method+" "+pathAndQuery] = stubResponse{status: status, body: body}
	return s
}

func (s *storeStub) RoundTrip(req *http.Request) (*http.Response, error) {
	body := ""
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(raw)
	}
	key := req.Method + " " + req.URL.Path
	if req.URL.RawQuery != "" {
		key += "?" + req.URL.RawQuery
	}

	s.mu.Lock()
	s.requests = append(s.requests, recordedRequest{
		Method: req.Method,
		Path:   req.URL.Path,
		Query:  req.URL.RawQuery,
		Auth:   req.Header.Get("Authorization"),
		Body:   body,
		Header: req.Header.Clone(),
	})
	resp, ok := s.answer[key]
	s.mu.Unlock()

	if !ok {
		resp = stubResponse{status: http.StatusNotFound, body: "<Error><Code>NoSuchBucket</Code></Error>"}
	}
	return &http.Response{
		StatusCode: resp.status,
		Body:       io.NopCloser(strings.NewReader(resp.body)),
		Header:     http.Header{"Content-Type": []string{"application/xml"}},
		Request:    req,
	}, nil
}

func (s *storeStub) recorded() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRequest(nil), s.requests...)
}

// testSigner is a fixed-time SigV4 signer. The timestamp is injected so a
// signature is a function of its inputs and can be asserted on at all.
//
// The secret is a literal that is obviously not a credential and matches no
// real key format. The access key identifier follows AWS's documentation-example
// shape, which is deliberately not a live key prefix.
func testSigner() *k8s.SigV4Signer {
	return &k8s.SigV4Signer{
		AccessKeyID:     "EXAMPLEKEYIDNOTREAL",
		SecretAccessKey: compute.NewSecretValue("not-a-real-secret-access-key"),
		Region:          "us-east-1",
		Now:             func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) },
	}
}

func newS3Store(t *testing.T, stub *storeStub) *k8s.S3ObjectStore {
	t.Helper()
	store, err := k8s.NewS3ObjectStore("https://objects.invalid", testSigner(),
		k8s.S3Options{Transport: stub})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}
	return store
}

// TestNewS3ObjectStoreRefusesAnIncompleteConstruction pins the fail-closed
// constructor. The signer check is the one that matters: a client with no signer
// would issue anonymous requests, and an anonymous request to an object store
// that happens to allow it succeeds — so the failure would be silent.
func TestNewS3ObjectStoreRefusesAnIncompleteConstruction(t *testing.T) {
	t.Parallel()

	if _, err := k8s.NewS3ObjectStore("", testSigner(), k8s.S3Options{}); err == nil {
		t.Error("NewS3ObjectStore accepted an empty endpoint")
	}
	if _, err := k8s.NewS3ObjectStore("https://objects.invalid", nil, k8s.S3Options{}); err == nil {
		t.Error("NewS3ObjectStore accepted a nil signer; every request would have gone out " +
			"unsigned, which is an anonymous request made by accident")
	}
	if _, err := k8s.NewS3ObjectStore("objects.invalid", testSigner(), k8s.S3Options{}); err == nil {
		t.Error("NewS3ObjectStore accepted an endpoint with no scheme")
	}
}

// publicReadPolicy is the policy document this client writes, as a store would
// hand it back.
func publicReadPolicy(bucket string) string {
	return `{"Version":"2012-10-17","Statement":[{"Sid":"apphub-public-read",` +
		`"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],` +
		`"Resource":["arn:aws:s3:::` + bucket + `/*"]}]}`
}

// TestGetBucketReadsRatherThanInfers is the read-side regression for the same
// defect, and it is the half that did the reporting damage.
//
// The earlier version set PublicRead from !BlockPublicPolicy. **The absence of a
// block is not the presence of a grant**: a bucket with every block cleared and no
// policy is private, and reporting it public described a state that had never been
// created. A describe that infers is a claim; this asserts it is an observation.
//
// Three sub-resources are read because there is no single call that returns tags,
// blocks and policy, and each of the three is load-bearing.
func TestGetBucketReadsRatherThanInfers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tags := `<Tagging><TagSet>
		<Tag><Key>apphub.dev/managed-by</Key><Value>apphub</Value></Tag>
		<Tag><Key>apphub.dev/object-class</Key><Value>standard</Value></Tag>
		<Tag><Key>apphub.dev/label/app</Key><Value>web</Value></Tag>
	</TagSet></Tagging>`
	unblocked := `<PublicAccessBlockConfiguration>
		<BlockPublicAcls>false</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls>
		<BlockPublicPolicy>false</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets>
		</PublicAccessBlockConfiguration>`
	blockedPolicy := `<PublicAccessBlockConfiguration>
		<BlockPublicAcls>false</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls>
		<BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets>
		</PublicAccessBlockConfiguration>`
	restricted := `<PublicAccessBlockConfiguration>
		<BlockPublicAcls>false</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls>
		<BlockPublicPolicy>false</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets>
		</PublicAccessBlockConfiguration>`

	for name, tc := range map[string]struct {
		block        string
		policyStatus int
		policyBody   string
		want         bool
		why          string
	}{
		"unblocked with a public policy": {
			block: unblocked, policyStatus: http.StatusOK, policyBody: publicReadPolicy("reports"),
			want: true,
			why:  "a grant exists and nothing suppresses it, which is the only way a bucket is public",
		},
		"unblocked with NO policy": {
			block: unblocked, policyStatus: http.StatusNotFound, policyBody: "",
			want: false,
			why: "this is the exact case the old inference got wrong: every block cleared, no " +
				"grant, therefore private",
		},
		"public policy suppressed by BlockPublicPolicy": {
			block: blockedPolicy, policyStatus: http.StatusOK, policyBody: publicReadPolicy("reports"),
			want: false,
			why:  "the grant exists but the store is rejecting it",
		},
		"public policy suppressed by RestrictPublicBuckets": {
			block: restricted, policyStatus: http.StatusOK, policyBody: publicReadPolicy("reports"),
			want: false,
			why: "the old code read only BlockPublicPolicy and would have reported this public; " +
				"either flag suppresses a grant",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stub := newStoreStub().
				on("GET", "/reports?tagging=", http.StatusOK, tags).
				on("GET", "/reports?publicAccessBlock=", http.StatusOK, tc.block).
				on("GET", "/reports?policy=", tc.policyStatus, tc.policyBody)
			store := newS3Store(t, stub)

			state, found, err := store.GetBucket(ctx, "reports")
			if err != nil {
				t.Fatalf("GetBucket: %v", err)
			}
			if !found {
				t.Fatal("GetBucket reported an existing bucket as absent")
			}
			if state.PublicRead != tc.want {
				t.Errorf("PublicRead=%v, want %v — %s", state.PublicRead, tc.want, tc.why)
			}
			if len(stub.recorded()) != 3 {
				t.Errorf("GetBucket issued %d requests, want 3 (tags, blocks, policy); reading "+
					"fewer means something is being inferred", len(stub.recorded()))
			}
			// The rest of the state must survive regardless.
			if state.Claim != k8s.ClaimOurs {
				t.Errorf("GetBucket reported claim %v; the ownership marker was not read back, "+
					"so every Ensure would refuse the bucket it created", state.Claim)
			}
			if state.Class != compute.ObjectClassStandard {
				t.Errorf("the object class read back as %q", state.Class)
			}
			if state.Labels["app"] != "web" {
				t.Errorf("the caller's labels read back as %v", state.Labels)
			}
		})
	}
}

// TestGetBucketRefusesAPolicyItCannotEvaluate is the fail-closed-on-uncertainty
// half.
//
// A policy somebody else wrote may grant anonymous access in a shape this client
// does not model — a condition, a NotPrincipal, an unfamiliar action. Reporting
// such a bucket private is the dangerous direction and reporting it public would
// be a guess, so it is refused. A read-back is supposed to be an observation.
func TestGetBucketRefusesAPolicyItCannotEvaluate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tags := `<Tagging><TagSet><Tag><Key>apphub.dev/managed-by</Key>` +
		`<Value>apphub</Value></Tag></TagSet></Tagging>`
	unblocked := `<PublicAccessBlockConfiguration><BlockPublicPolicy>false</BlockPublicPolicy>` +
		`<RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>`

	for name, policy := range map[string]string{
		"an anonymous grant with a condition": `{"Statement":[{"Sid":"apphub-public-read",` +
			`"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],` +
			`"Resource":["arn:aws:s3:::reports/*"],"Condition":{"IpAddress":{}}}]}`,
		"an anonymous grant somebody else wrote": `{"Statement":[{"Sid":"someone-elses",` +
			`"Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:*"],` +
			`"Resource":["arn:aws:s3:::reports/*"]}]}`,
		"a NotPrincipal statement": `{"Statement":[{"Effect":"Allow",` +
			`"NotPrincipal":{"AWS":"someone"},"Action":["s3:GetObject"],` +
			`"Resource":["arn:aws:s3:::reports/*"]}]}`,
		"an explicit anonymous Deny": `{"Statement":[{"Effect":"Deny","Principal":"*",` +
			`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::reports/*"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newS3Store(t, newStoreStub().
				on("GET", "/reports?tagging=", http.StatusOK, tags).
				on("GET", "/reports?publicAccessBlock=", http.StatusOK, unblocked).
				on("GET", "/reports?policy=", http.StatusOK, policy))

			_, found, err := store.GetBucket(ctx, "reports")
			if err == nil {
				t.Fatal("GetBucket answered for a policy it does not fully evaluate; reporting " +
					"private would be the dangerous direction and public would be a guess")
			}
			if !errors.Is(err, k8s.ErrObjectStoreControlPlane) {
				t.Errorf("the refusal is %v, want it to wrap ErrObjectStoreControlPlane", err)
			}
			if found {
				t.Error("GetBucket reported found alongside an error")
			}
		})
	}

	// The control: the policy this client writes itself must NOT be refused, or
	// the refusal above would fire on every bucket and prove nothing.
	store := newS3Store(t, newStoreStub().
		on("GET", "/reports?tagging=", http.StatusOK, tags).
		on("GET", "/reports?publicAccessBlock=", http.StatusOK, unblocked).
		on("GET", "/reports?policy=", http.StatusOK, publicReadPolicy("reports")))
	state, found, err := store.GetBucket(ctx, "reports")
	if err != nil || !found || !state.PublicRead {
		t.Fatalf("this client's own policy was not recognised: public=%v found=%v err=%v",
			state.PublicRead, found, err)
	}
}

// TestGetBucketDistinguishesAbsentFromUnknown is the honest-refusal case.
//
// An absent bucket is "not found", which the provider reads as "the name is
// free". A bucket whose public-access configuration cannot be read is neither
// private nor public as far as this client knows, and answering either way would
// be an invention — so it is an error. Reporting it as private is the tempting
// one and the dangerous one.
func TestGetBucketDistinguishesAbsentFromUnknown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	absent := newS3Store(t, newStoreStub()) // every request 404s
	if _, found, err := absent.GetBucket(ctx, "nope"); err != nil || found {
		t.Errorf("GetBucket of an absent bucket returned (found=%v, err=%v), want (false, nil)",
			found, err)
	}

	// The bucket exists (its tags read) but the store has no public-access
	// sub-resource.
	partial := newS3Store(t, newStoreStub().
		on("GET", "/reports?tagging=", http.StatusOK,
			`<Tagging><TagSet><Tag><Key>apphub.dev/managed-by</Key><Value>apphub</Value></Tag></TagSet></Tagging>`))
	_, found, err := partial.GetBucket(ctx, "reports")
	if err == nil {
		t.Fatal("GetBucket reported a bucket whose public-access configuration it could not " +
			"read; whether it is publicly readable was unknown and the answer would have been " +
			"invented")
	}
	if found {
		t.Error("GetBucket reported found alongside an error")
	}
	if !errors.Is(err, k8s.ErrObjectStoreControlPlane) {
		t.Errorf("the refusal is %v, want it to wrap ErrObjectStoreControlPlane", err)
	}
}

// TestAnonymousReadIsUnsigned is the one call that must NOT carry credentials.
//
// It is how "public access is off unless it was asked for" is checked, and a
// signed request would answer that question about the platform's own credential
// rather than about an anonymous caller — a check that always passed.
func TestAnonymousReadIsUnsigned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	open := newS3Store(t, newStoreStub().on("GET", "/assets", http.StatusOK, ""))
	if err := open.AnonymousRead(ctx, "assets"); err != nil {
		t.Errorf("AnonymousRead of a public bucket: %v", err)
	}

	stub := newStoreStub().on("GET", "/reports", http.StatusForbidden, "")
	closed := newS3Store(t, stub)
	err := closed.AnonymousRead(ctx, "reports")
	if !errors.Is(err, k8s.ErrObjectStoreDenied) {
		t.Errorf("AnonymousRead of a private bucket returned %v, want ErrObjectStoreDenied", err)
	}
	for _, req := range stub.recorded() {
		if req.Auth != "" {
			t.Errorf("the anonymous read carried an Authorization header; the check would have "+
				"been answered about the platform's credential instead of about an anonymous "+
				"caller. header: %q", req.Auth)
		}
		if req.Header.Get("X-Amz-Content-Sha256") != "" {
			t.Error("the anonymous read carried SigV4 headers")
		}
	}
}

// TestStatusMappingReachesTheRightSentinel pins the mapping a wrong answer here
// would corrupt: a 503 that arrived as a terminal failure tells a caller its
// spec has to change when a retry would have worked. That is the same defect
// ErrTransient was added to the compute taxonomy to fix, arriving through a
// different substrate.
func TestStatusMappingReachesTheRightSentinel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for status, want := range map[int]error{
		http.StatusNotFound:            compute.ErrNotFound,
		http.StatusForbidden:           k8s.ErrObjectStoreDenied,
		http.StatusUnauthorized:        k8s.ErrObjectStoreDenied,
		http.StatusTooManyRequests:     k8s.ErrBackingTransient,
		http.StatusInternalServerError: k8s.ErrBackingTransient,
		http.StatusServiceUnavailable:  k8s.ErrBackingTransient,
	} {
		store := newS3Store(t, newStoreStub().on("DELETE", "/reports", status, ""))
		err := store.DeleteBucket(ctx, "reports")
		if status == http.StatusNotFound {
			// Deleting an absent bucket is not an error: every Delete on every
			// port is idempotent by contract.
			if err != nil {
				t.Errorf("DeleteBucket on a 404 returned %v, want nil", err)
			}
			continue
		}
		if !errors.Is(err, want) {
			t.Errorf("HTTP %d mapped to %v, want it to wrap %v", status, err, want)
		}
	}

	// A transport failure — no response at all — is transient too. A dialling
	// error is the most common failure a real client sees and the least likely
	// to be a caller's fault.
	store, err := k8s.NewS3ObjectStore("https://objects.invalid", testSigner(),
		k8s.S3Options{Transport: failingTransport{}})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}
	if err := store.DeleteBucket(ctx, "reports"); !errors.Is(err, k8s.ErrBackingTransient) {
		t.Errorf("a transport failure mapped to %v, want ErrBackingTransient", err)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial: no route to a host under a reserved TLD")
}

// TestTheGranterHalfRefusesRatherThanPickingAVendor pins the finding.
//
// compute.ObjectStore embeds Granter, and there is no vendor-neutral S3 request
// that authorises an OIDC subject against a bucket. Refusing is the correct
// answer; picking AWS's mechanism and calling it portable is the incorrect one,
// and would look identical from outside until somebody ran it against MinIO.
//
// Both halves are asserted. A grant that refused while a revoke silently
// succeeded would be worse than either: a caller would believe access had been
// removed that was never there to remove.
func TestTheGranterHalfRefusesRatherThanPickingAVendor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	stub := newStoreStub()
	store := newS3Store(t, stub)

	subject := "system:serviceaccount:apphub-apps:api"
	for name, err := range map[string]error{
		"SetPolicy":   store.SetPolicy(ctx, "reports", subject, compute.AccessRead),
		"ClearPolicy": store.ClearPolicy(ctx, "reports", subject),
		"Read":        store.Read(ctx, "reports", subject),
		"Write":       store.Write(ctx, "reports", subject),
	} {
		if !errors.Is(err, k8s.ErrObjectStoreControlPlane) {
			t.Errorf("%s returned %v, want it to wrap ErrObjectStoreControlPlane", name, err)
		}
	}
	if len(stub.recorded()) != 0 {
		t.Errorf("a refused operation still issued %d requests; a refusal that half-executes "+
			"is worse than either answer", len(stub.recorded()))
	}
}

// TestS3StoreSatisfiesTheSeam is the compile-time claim, made observable: the
// production store and the in-memory one are interchangeable behind ObjectStore,
// which is the whole reason the seam was added.
func TestS3StoreSatisfiesTheSeam(t *testing.T) {
	t.Parallel()
	var _ k8s.ObjectStore = newS3Store(t, newStoreStub())
	var _ k8s.ObjectStore = k8s.NewMemoryObjectStore()
}

// --- the signer ------------------------------------------------------------------

// TestSigV4SignsDeterministicallyAndSensitively is what carries the signing
// implementation, and it is deliberately explicit about what it does not carry.
//
// **What it proves.** The signature is a function of its inputs; it changes when
// any component SigV4 covers changes; the Authorization header has the documented
// shape and names the credential scope and the signed headers; and the secret
// never appears in any header.
//
// **What it does not prove: that a real store accepts the result.** There is no
// reference implementation here to compare against, and comparing this
// implementation to a second one written from the same reading of the
// specification would be circular. So the arithmetic is checked for the
// properties a signing bug would break, and "a real store accepts this" is an
// untested surface, recorded as one. It is the safest place on this branch to be
// wrong: a bad signature is a 403 on the first request.
func TestSigV4SignsDeterministicallyAndSensitively(t *testing.T) {
	t.Parallel()

	sign := func(mutate func(*k8s.SigV4Signer), method, target, body string) string {
		t.Helper()
		signer := testSigner()
		if mutate != nil {
			mutate(signer)
		}
		req, err := http.NewRequest(method, target, strings.NewReader(body))
		if err != nil {
			t.Fatalf("building a request: %v", err)
		}
		if err := signer.Sign(req, hexDigest([]byte(body))); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return req.Header.Get("Authorization")
	}

	base := sign(nil, http.MethodPut, "https://objects.invalid/reports?tagging=", "<Tagging/>")
	if base == "" {
		t.Fatal("Sign wrote no Authorization header")
	}
	if again := sign(nil, http.MethodPut, "https://objects.invalid/reports?tagging=", "<Tagging/>"); again != base {
		t.Error("the same inputs produced two different signatures; the signer is reading " +
			"something it was not given")
	}

	// Shape. Each of these is a component a server parses out of the header, and
	// a missing one is a 400 rather than a 403 — a different failure to diagnose.
	for _, want := range []string{
		"AWS4-HMAC-SHA256 ",
		"Credential=EXAMPLEKEYIDNOTREAL/20260822/us-east-1/s3/aws4_request",
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date",
		"Signature=",
	} {
		if !strings.Contains(base, want) {
			t.Errorf("the Authorization header does not contain %q:\n%s", want, base)
		}
	}

	// Sensitivity. Every one of these is covered by the algorithm, so a
	// signature that did not move is a signature computed over less than it
	// should be — the failure mode that produces a signer which works for one
	// request shape and 403s for another.
	for name, got := range map[string]string{
		"method": sign(nil, http.MethodGet, "https://objects.invalid/reports?tagging=", "<Tagging/>"),
		"path":   sign(nil, http.MethodPut, "https://objects.invalid/other?tagging=", "<Tagging/>"),
		"query":  sign(nil, http.MethodPut, "https://objects.invalid/reports?policy=", "<Tagging/>"),
		"body":   sign(nil, http.MethodPut, "https://objects.invalid/reports?tagging=", "<Tagging>x</Tagging>"),
		"host":   sign(nil, http.MethodPut, "https://other.invalid/reports?tagging=", "<Tagging/>"),
		"region": sign(func(s *k8s.SigV4Signer) { s.Region = "eu-west-1" }, http.MethodPut, "https://objects.invalid/reports?tagging=", "<Tagging/>"),
		"access key": sign(func(s *k8s.SigV4Signer) { s.AccessKeyID = "EXAMPLEKEYIDOTHER" },
			http.MethodPut, "https://objects.invalid/reports?tagging=", "<Tagging/>"),
		"secret": sign(func(s *k8s.SigV4Signer) {
			s.SecretAccessKey = compute.NewSecretValue("a-different-not-real-secret")
		}, http.MethodPut, "https://objects.invalid/reports?tagging=", "<Tagging/>"),
		"timestamp": sign(func(s *k8s.SigV4Signer) {
			s.Now = func() time.Time { return time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC) }
		}, http.MethodPut, "https://objects.invalid/reports?tagging=", "<Tagging/>"),
	} {
		if got == base {
			t.Errorf("changing the %s did not change the signature; the canonical request does "+
				"not cover it", name)
		}
	}
}

// TestSigV4NeverEmitsTheSecret is a security assertion rather than a correctness
// one, and it is checked on the request the signer produces rather than by
// reading the code, because that is the artifact that leaves the process.
func TestSigV4NeverEmitsTheSecret(t *testing.T) {
	t.Parallel()

	const secret = "an-unmistakable-not-real-secret-value"
	signer := testSigner()
	signer.SecretAccessKey = compute.NewSecretValue(secret)

	req, err := http.NewRequest(http.MethodPut, "https://objects.invalid/reports?tagging=",
		strings.NewReader("<Tagging/>"))
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	if err := signer.Sign(req, hexDigest(nil)); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	for name, values := range req.Header {
		for _, v := range values {
			if strings.Contains(v, secret) {
				t.Errorf("header %s carries the secret access key", name)
			}
		}
	}
	if strings.Contains(req.URL.String(), secret) {
		t.Error("the request URL carries the secret access key")
	}
	// And the SecretValue type must redact itself, because the next person to
	// add a log line will format the signer.
	//
	// Formatted through fmt rather than by calling String() directly, and that is
	// not merely a rename. USOSS-43 removed SecretValue.String() and kept
	// Format, so fmt is now the only route -- and it is the route the comment
	// above always described, because a log line formats a value, it does not
	// call String() by hand. The migration made the test truer to its own stated
	// intent. Verified by mutation rather than by compiling: making Format emit
	// the real value fails this assertion.
	if rendered := fmt.Sprintf("%v", signer.SecretAccessKey); strings.Contains(rendered, secret) {
		t.Errorf("compute.SecretValue rendered as %q", rendered)
	}
}

// TestSigV4RefusesAnIncompleteSigner pins the fail-closed constructor-equivalent.
// A signer missing a region produces a signature no server will reproduce, and
// finding that out as a 403 is much worse than finding it out here.
func TestSigV4RefusesAnIncompleteSigner(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*k8s.SigV4Signer){
		"no access key": func(s *k8s.SigV4Signer) { s.AccessKeyID = "" },
		"no secret":     func(s *k8s.SigV4Signer) { s.SecretAccessKey = compute.SecretValue{} },
		"no region":     func(s *k8s.SigV4Signer) { s.Region = "" },
	} {
		signer := testSigner()
		mutate(signer)
		req, err := http.NewRequest(http.MethodGet, "https://objects.invalid/", nil)
		if err != nil {
			t.Fatalf("building a request: %v", err)
		}
		if err := signer.Sign(req, hexDigest(nil)); err == nil {
			t.Errorf("Sign accepted a signer with %s", name)
		}
	}

	signer := testSigner()
	req, err := http.NewRequest(http.MethodGet, "https://objects.invalid/", nil)
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	if err := signer.Sign(req, ""); err == nil {
		t.Error("Sign accepted an empty payload digest; SigV4 signs it as a header, so an " +
			"empty one is a signature over a lie")
	}
}

// TestTheReportedAccessStateAgreesWithTheActualProbe is the invariant behind B1,
// stated as a property rather than as a case.
//
// A reviewer reproduced the defect with a bidirectional control in one run: the
// state reader positively said public while the provider's own unsigned read
// positively said denied. Two answers about the same bucket, from the same client,
// disagreeing. Every individual assertion about blocks and policies is a case;
// **"the describe and the probe agree" is the class**, and it is the thing a caller
// actually relies on.
//
// So this drives every combination of the two things that decide public access and
// requires the two answers to match in all of them. The old inference fails the
// unblocked-with-no-policy row, which is precisely the row the reviewer found.
func TestTheReportedAccessStateAgreesWithTheActualProbe(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tags := `<Tagging><TagSet><Tag><Key>apphub.dev/managed-by</Key>` +
		`<Value>apphub</Value></Tag></TagSet></Tagging>`
	blockDoc := func(blocked bool) string {
		v := "false"
		if blocked {
			v = "true"
		}
		return `<PublicAccessBlockConfiguration>` +
			`<BlockPublicAcls>` + v + `</BlockPublicAcls>` +
			`<IgnorePublicAcls>` + v + `</IgnorePublicAcls>` +
			`<BlockPublicPolicy>` + v + `</BlockPublicPolicy>` +
			`<RestrictPublicBuckets>` + v + `</RestrictPublicBuckets>` +
			`</PublicAccessBlockConfiguration>`
	}

	agreed := 0
	for _, blocked := range []bool{false, true} {
		for _, granted := range []bool{false, true} {
			// The store's ground truth: an anonymous read succeeds only when a
			// grant exists and nothing is suppressing it.
			readable := granted && !blocked
			anonStatus := http.StatusForbidden
			if readable {
				anonStatus = http.StatusOK
			}
			policyStatus, policyBody := http.StatusNotFound, ""
			if granted {
				policyStatus, policyBody = http.StatusOK, publicReadPolicy("reports")
			}

			stub := newStoreStub().
				on("GET", "/reports?tagging=", http.StatusOK, tags).
				on("GET", "/reports?publicAccessBlock=", http.StatusOK, blockDoc(blocked)).
				on("GET", "/reports?policy=", policyStatus, policyBody).
				on("GET", "/reports", anonStatus, "")
			store := newS3Store(t, stub)

			state, found, err := store.GetBucket(ctx, "reports")
			if err != nil || !found {
				t.Fatalf("blocked=%v granted=%v: GetBucket: found=%v err=%v",
					blocked, granted, found, err)
			}
			probeErr := store.AnonymousRead(ctx, "reports")
			probeSaysPublic := probeErr == nil

			if state.PublicRead != probeSaysPublic {
				t.Errorf("blocked=%v granted=%v: DescribeBucket reports PublicRead=%v but the "+
					"unsigned probe says public=%v (%v).\nThe state reader and the actual access "+
					"check disagree about the same bucket, which is a describe that invents "+
					"rather than observes.",
					blocked, granted, state.PublicRead, probeSaysPublic, probeErr)
				continue
			}
			agreed++
		}
	}
	// All four combinations, and both answers must actually occur — otherwise a
	// client that always said "private" would pass this.
	if agreed != 4 {
		t.Fatalf("only %d of 4 combinations agreed", agreed)
	}
}

// TestDescribeDoesNotHideAnUnreadableBucket is the B2 regression.
//
// Describe listed the buckets and then silently skipped any it could not read. A
// backing 500 therefore *removed a configured bucket from the security artifact*
// rather than failing, and Harness.Rendered trusts that result — so a scan over
// the rendered artifacts could pass because the object it needed to inspect had
// quietly disappeared from them.
//
// That is the vacuous-pass class arriving through an error path rather than a skip
// path, which is a route nobody had enumerated. An error while describing must
// fail the describe, not shrink its output.
func TestDescribeDoesNotHideAnUnreadableBucket(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	listing := `<ListAllMyBucketsResult><Buckets>` +
		`<Bucket><Name>reports</Name></Bucket></Buckets></ListAllMyBucketsResult>`

	// The bucket is listed, and reading it fails.
	store := newS3Store(t, newStoreStub().
		on("GET", "/", http.StatusOK, listing).
		on("GET", "/reports?tagging=", http.StatusInternalServerError, ""))

	lines, err := store.Describe(ctx, "s3")
	if err == nil {
		t.Fatalf("Describe returned %v lines and no error for a bucket it could not read; a "+
			"security scan over that output would pass by omission", len(lines))
	}
	if len(lines) != 0 {
		t.Errorf("Describe returned %d lines alongside an error", len(lines))
	}
	// It must be the transient class, so a caller can tell "the store is having a
	// bad minute" from "your configuration is wrong".
	if !errors.Is(err, k8s.ErrBackingTransient) {
		t.Errorf("Describe failed with %v; a 500 from the store is transient", err)
	}

	// The control: a bucket that vanished between the listing and the read is a
	// real race rather than an error, and it is RECORDED rather than dropped —
	// for the same reason. A caller comparing two describes must see that a
	// bucket went away, not simply a shorter list.
	raced := newS3Store(t, newStoreStub().
		on("GET", "/", http.StatusOK, listing).
		on("GET", "/reports?tagging=", http.StatusNotFound, ""))
	lines, err = raced.Describe(ctx, "s3")
	if err != nil {
		t.Fatalf("Describe of a vanished bucket: %v", err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "vanished") {
		t.Errorf("a bucket that vanished between listing and read rendered as %v; it must be "+
			"recorded, not dropped", lines)
	}
}

// statefulStore models the two things that decide whether an S3 bucket is
// publicly readable, and answers an unsigned GET from them.
//
// It exists because request-order assertions cannot see the defect a reviewer
// found. Order tests initialise no prior state, so they cannot observe an
// interleaving where a *previous* partial failure left a latent grant that the next
// transition exposes. Modelling the state and computing readability from it is the
// only way the question "is the bucket readable right now" has an answer.
//
// # It fails a write named by the caller, and does not know which writes exist
//
// The failure injection is a *key* — "PUT ?tagging" — rather than a set of
// booleans for the writes somebody thought of. The previous version had
// failPolicyWrite and failBlockWrite and no way to fail tagging, and a reviewer
// found the defect that omission hid: a tagging failure after the unblock left a
// formerly-private bucket public while returning an error. The enumeration built
// to escape hand-picked cases had a hand-picked axis.
//
// So this type takes an opaque key and the enumeration discovers the keys by
// watching a clean run. Adding a write to the reconcile grows the population with
// no edit here or there.
type statefulStore struct {
	mu sync.Mutex
	// blocked and policy are the store's ground truth.
	blocked bool
	policy  bool
	// failNth, when positive, makes the Nth mutating request return 500 --
	// counting occurrences, not distinct keys.
	//
	// The previous version matched a KEY, and the enumeration over it skipped
	// repeats: PutBucket writes publicAccessBlock twice on a public transition,
	// and only the first was ever failed, so the *unblock* -- the write that
	// actually exposes the bucket -- was never independently injected. A derived
	// population undone by a key collision. Counting occurrences is what makes
	// "inject a failure into each write" mean each write.
	failNth int
	// seen counts mutating requests, so failNth can name one.
	seen int
	// failWrite is kept for the few tests that want a named write rather than an
	// index; it is matched only when failNth is unset.
	failWrite string
	// firedAt and firedKey record WHICH request the injected failure landed on --
	// its ordinal and its key -- rather than merely that one did.
	//
	// The previous version was a bool, and a reviewer found what a bool cannot
	// see: if every ordinal were shifted by one, each cell would still observe
	// "an injection fired" and the gate would still pass, while the occurrence
	// the cell meant to fail was never failed. An observed-to-fire check that
	// counts is not the property; the property is identity. This is the
	// count-is-not-a-property rule landing inside the fix for the dedup, one
	// layer down.
	firedAt  int
	firedKey string
	// mutations records every mutating request in order, which is how the
	// enumeration derives its own failure population.
	mutations []string
}

// requestKey names a request the way the enumeration refers to it.
func requestKey(method, rawQuery string) string {
	q := rawQuery
	if i := strings.IndexByte(q, '='); i >= 0 {
		q = q[:i]
	}
	return method + " ?" + q
}

// isMutation reports whether a method changes anything. GET and HEAD do not, so a
// failure injected into one could not affect exposure and would only test the
// error plumbing.
func isMutation(method string) bool {
	return method == http.MethodPut || method == http.MethodDelete || method == http.MethodPost
}

func (s *statefulStore) readable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policy && !s.blocked
}

func (s *statefulStore) mutatingWrites() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.mutations...)
}

// injectionFired reports the ordinal and key of the request the injected failure
// landed on. A zero ordinal means it never fired.
func (s *statefulStore) injectionFired() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firedAt, s.firedKey
}

func (s *statefulStore) RoundTrip(req *http.Request) (*http.Response, error) {
	body := ""
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(raw)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	reply := func(status int, payload string) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(payload)),
			Header:     http.Header{},
			Request:    req,
		}, nil
	}
	q := req.URL.RawQuery
	key := requestKey(req.Method, q)

	if isMutation(req.Method) {
		s.mutations = append(s.mutations, key)
		s.seen++
		switch {
		case s.failNth > 0 && s.seen == s.failNth:
			s.firedAt, s.firedKey = s.seen, key
			return reply(http.StatusInternalServerError, "")
		case s.failNth == 0 && s.failWrite != "" && key == s.failWrite:
			s.firedAt, s.firedKey = s.seen, key
			return reply(http.StatusInternalServerError, "")
		}
	}

	switch {
	case req.Method == http.MethodHead:
		return reply(http.StatusOK, "")

	case strings.HasPrefix(q, "policy"):
		switch req.Method {
		case http.MethodGet:
			if !s.policy {
				return reply(http.StatusNotFound, "<Error><Code>NoSuchBucketPolicy</Code></Error>")
			}
			return reply(http.StatusOK, publicReadPolicy("reports"))
		case http.MethodPut:
			s.policy = strings.Contains(body, publicReadStatementIDForTest)
			return reply(http.StatusOK, "")
		case http.MethodDelete:
			s.policy = false
			return reply(http.StatusNoContent, "")
		}

	case strings.HasPrefix(q, "publicAccessBlock"):
		// A GET must SERVE the state, not set it. The first version of this stub
		// fell through to the write branch on a read, computed "blocked" from an
		// empty body, and so unblocked the bucket every time the client looked at
		// it — a fixture that mutated what it was asked to report. It produced
		// four confident failures that were nothing to do with the code.
		if req.Method == http.MethodGet {
			v := "false"
			if s.blocked {
				v = "true"
			}
			return reply(http.StatusOK, `<PublicAccessBlockConfiguration>`+
				`<BlockPublicAcls>`+v+`</BlockPublicAcls>`+
				`<IgnorePublicAcls>`+v+`</IgnorePublicAcls>`+
				`<BlockPublicPolicy>`+v+`</BlockPublicPolicy>`+
				`<RestrictPublicBuckets>`+v+`</RestrictPublicBuckets>`+
				`</PublicAccessBlockConfiguration>`)
		}
		s.blocked = strings.Contains(body, "<BlockPublicPolicy>true</BlockPublicPolicy>")
		return reply(http.StatusOK, "")

	case strings.HasPrefix(q, "tagging"):
		if req.Method == http.MethodGet {
			// The ownership marker, so confirmOwnership sees a bucket that is ours.
			return reply(http.StatusOK, `<Tagging><TagSet><Tag>`+
				`<Key>apphub.dev/managed-by</Key><Value>apphub</Value></Tag></TagSet></Tagging>`)
		}
		return reply(http.StatusOK, "")

	case q == "" && req.Method == http.MethodPut:
		return reply(http.StatusOK, "") // CreateBucket

	case q == "" && req.Method == http.MethodGet:
		// The unsigned anonymous read, answered from the modelled state.
		if s.policy && !s.blocked {
			return reply(http.StatusOK, "")
		}
		return reply(http.StatusForbidden, "")
	}
	return reply(http.StatusNotFound, "<Error><Code>NoSuchKey</Code></Error>")
}

// publicReadStatementIDForTest mirrors the Sid the client writes. It is only used
// to decide, inside the stub, whether a policy body is a grant.
const publicReadStatementIDForTest = "apphub-public-read"

// TestNoPartialPutBucketLeavesABucketReadable is the exposure invariant, checked
// over a failure population the test **derives** rather than chooses.
//
// # Why the population is derived, which is the whole point of this revision
//
// The previous version enumerated four prior states x two desired states x a
// failure injected into each of *two* writes — the two the author had thought of.
// The reconcile makes more than two, and a reviewer found the one that was left
// out: a tagging failure after the unblock returned an error with a
// formerly-private bucket public. The property was sound and its population was
// hand-picked, **inside the construction written to escape hand-picked cases.**
//
// So the writes are no longer named here. For each (prior state, desired state)
// the reconcile is run once with nothing failing, the stub records every mutating
// request it received, and that recorded set becomes the failure population for
// that cell. Add a write to PutBucket and this grows on its own; remove one and it
// shrinks. There is no list to forget to update.
//
// Two gates keep the derivation from passing vacuously:
//
//   - the discovered write set must be non-empty for at least one cell, and its
//     union across cells must contain every subresource the reconcile is known to
//     touch, so a stub that silently stopped recording cannot make this trivial;
//   - every injected failure must actually **fire**. A cell whose injection was
//     never reached proves nothing, and silently counting it as a pass is how an
//     enumeration reports coverage it does not have.
//
// The invariant itself: **a failure must not increase exposure**, and a success
// must land exactly where it was asked to. Stated as a delta rather than a state,
// because the stronger "must not be readable" form flagged three cases where a
// failed call on an already-public bucket changed nothing — and believing them
// would have pushed the fix toward blocking buckets it had no business touching.
func TestNoPartialPutBucketLeavesABucketReadable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	newStore := func(prior struct{ blocked, policy bool }, failNth int) (*statefulStore, k8s.ObjectStore) {
		st := &statefulStore{blocked: prior.blocked, policy: prior.policy, failNth: failNth}
		client, err := k8s.NewS3ObjectStore("https://objects.invalid", testSigner(),
			k8s.S3Options{Transport: st})
		if err != nil {
			t.Fatalf("NewS3ObjectStore: %v", err)
		}
		return st, client
	}
	put := func(client k8s.ObjectStore, public bool) error {
		return client.PutBucket(ctx, k8s.BucketState{
			Name: "reports", Class: compute.ObjectClassStandard, PublicRead: public, Claim: k8s.ClaimOurs,
		})
	}

	type priorState struct{ blocked, policy bool }
	priors := []priorState{{false, false}, {false, true}, {true, false}, {true, true}}

	discovered := map[string]bool{}
	cells, injected := 0, 0
	// occurrences is the DENOMINATOR: the total number of mutating-request
	// occurrences the clean discovery runs found, accumulated as they are found.
	//
	// Round seven's finding is why it exists. Ordinal-plus-key identity proves each
	// cell is evidence about the write it names, and it cannot see a cell that was
	// never run: skipping one occurrence left the enumeration reporting 25 of 25
	// fired where the clean traversal had found 26, and every gate still passed,
	// because "all the cells I ran fired" is true of any subset. A count of what
	// happened is not a denominator; the denominator has to come from the
	// discovery run and be compared against.
	occurrences := 0
	repeatedKeyInjected := false

	for _, prior := range priors {
		for _, wantPublic := range []bool{false, true} {
			// Discovery run: nothing fails, and the stub reports every mutating
			// request the reconcile made, in order.
			probe, client := newStore(prior, 0)
			if err := put(client, wantPublic); err != nil {
				t.Fatalf("prior%v want-public=%v: the discovery run failed: %v",
					prior, wantPublic, err)
			}
			writes := probe.mutatingWrites()
			if len(writes) == 0 {
				continue
			}

			// # One cell per OCCURRENCE, not per distinct key
			//
			// The previous version deduplicated by key, and a reviewer found what
			// that hid: on a public transition PutBucket writes publicAccessBlock
			// twice -- the guard and the unblock -- and only the first was ever
			// failed. The *unblock* is the write that actually exposes the bucket,
			// and it was never independently injected. Deriving the population and
			// then collapsing it by key is a population fix undone one line later.
			keyCount := map[string]int{}
			for _, w := range writes {
				keyCount[w]++
			}
			// Counted from the CLEAN run, before any cell runs, so it is a
			// denominator rather than a tally of what happened.
			occurrences += len(writes)
			for i, w := range writes {
				discovered[w] = true
				cells++

				readableBefore := prior.policy && !prior.blocked
				st, client := newStore(prior, i+1)
				putErr := put(client, wantPublic)
				readableAfter := st.readable()

				desc := fmt.Sprintf("prior(blocked=%v policy=%v) want-public=%v fail=#%d(%s)",
					prior.blocked, prior.policy, wantPublic, i+1, w)

				// Identity, not a count: this cell is only evidence about write
				// #i+1 if the failure landed on write #i+1. A bool here would
				// accept an injection that fired on a different occurrence, which
				// is exactly the shape of the dedup bug this enumeration exists
				// to close.
				firedAt, firedKey := st.injectionFired()
				switch {
				case firedAt == 0:
					t.Errorf("%s: the injected failure was never reached, so this cell is not "+
						"evidence about anything", desc)
					continue
				case firedAt != i+1 || firedKey != w:
					t.Errorf("%s: the injection landed on request #%d (%s) rather than the "+
						"#%d (%s) this cell is about, so the cell is evidence about a "+
						"different write than the one it names", desc, firedAt, firedKey, i+1, w)
					continue
				}
				injected++
				if keyCount[w] > 1 {
					// Only a CONFIRMED hit on a repeated key counts: the gate is
					// about a failure actually landing on the second occurrence,
					// not about the enumeration having listed one.
					repeatedKeyInjected = true
				}

				switch {
				case putErr == nil:
					t.Errorf("%s: PutBucket succeeded although write #%d failed", desc, i+1)
				case readableAfter && !readableBefore:
					t.Errorf("%s: PutBucket failed (%v) and the bucket is NOW publicly readable "+
						"when it was not before. A failed call must not increase exposure: the "+
						"caller has been told the operation did not happen.", desc, putErr)
				}
			}

			if got := probe.readable(); got != wantPublic {
				t.Errorf("prior%v: a successful PutBucket(public=%v) left readable=%v",
					prior, wantPublic, got)
			}
		}
	}

	// The gate on the dedup fix: at least one cell must have injected a failure
	// into a REPEATED key, or the enumeration has collapsed back to one cell per
	// distinct write and the unblock is unexercised again.
	if !repeatedKeyInjected {
		t.Error("no cell injected a failure into a repeated request key. PutBucket writes " +
			"publicAccessBlock twice on a public transition, and if only one of them is ever " +
			"failed then the unblock -- the write that exposes the bucket -- is untested.")
	}

	if cells == 0 || injected == 0 || occurrences == 0 {
		t.Fatalf("the enumeration discovered %d occurrences, ran %d cells and fired %d "+
			"injections; with any of them at zero it is asserting nothing",
			occurrences, cells, injected)
	}
	// The denominator, and the reason it is an equality rather than a floor: every
	// occurrence the clean run discovered must have been run AND must have fired.
	// A subset satisfies every other gate in this test.
	if cells != occurrences {
		t.Errorf("the clean traversal discovered %d mutating-request occurrences but the "+
			"enumeration ran %d cells. Some occurrence was skipped, so the exposure invariant "+
			"is unasserted for it -- and every other gate here would still pass, because they "+
			"are all statements about the cells that ran.", occurrences, cells)
	}
	if injected != occurrences {
		t.Errorf("%d occurrences were discovered but only %d injections fired. A cell whose "+
			"injection never reached its write is not evidence about that write, and counting "+
			"only the ones that did fire cannot see the difference.", occurrences, injected)
	}
	// The derivation must have found every write the reconcile is known to make.
	// This is the one place a list appears, and it is a floor rather than the
	// population: if the reconcile grows a write, the enumeration picks it up
	// automatically and this check does not need to change. If the reconcile
	// *loses* one of these, that is a change worth failing on.
	for _, must := range []string{"PUT ?", "PUT ?tagging", "PUT ?publicAccessBlock"} {
		if !discovered[must] {
			t.Errorf("the derivation never saw %q. Either the reconcile stopped making that "+
				"write, or the stub stopped recording it — and in the second case every cell "+
				"above is weaker than it looks.", must)
		}
	}
	// Tagging specifically: this is the write whose omission was the defect, so
	// its presence in the derived population is asserted by name rather than
	// trusted to the floor above.
	if !discovered["PUT ?tagging"] {
		t.Error("tagging is not in the derived failure population; that omission was B1")
	}
	t.Logf("derived %d distinct writes over %d discovered occurrences; %d cells ran, %d injections fired: %v",
		len(discovered), occurrences, cells, injected, sortedKeysOf(discovered))
}

// sortedKeysOf renders a set deterministically for a log line.
func sortedKeysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestTheReviewersExactInterleavingIsClosed pins the named reproduction, and it
// no longer fails the way it used to for a reason worth writing down.
//
// Their fixture starts at blocked=true, policy=true — the latent grant a failed
// private revoke leaves — and asks for public with the policy write failing. Under
// the old code that cleared the block first, reactivating the latent grant, and
// then returned an error with the bucket readable.
//
// Under the reconcile-from-observed-state logic the grant is **already correct**,
// so no policy write is attempted at all: the only thing that has to change is the
// block, and unblocking a bucket that already carries the intended grant is the
// whole of the requested transition. So their exact inputs now describe a
// *successful* call, and asserting a failure would be asserting the old shape.
//
// Both readings are checked, because "the write we were going to get wrong is no
// longer issued" is only half an answer:
//
//  1. their literal state, which must now succeed and end publicly readable;
//  2. the state where the policy write genuinely is attempted and fails, which is
//     what their scenario was reaching for — and there the bucket must stay
//     blocked and unreadable.
func TestTheReviewersExactInterleavingIsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	newClient := func(t *testing.T, st *statefulStore) k8s.ObjectStore {
		t.Helper()
		c, err := k8s.NewS3ObjectStore("https://objects.invalid", testSigner(),
			k8s.S3Options{Transport: st})
		if err != nil {
			t.Fatalf("NewS3ObjectStore: %v", err)
		}
		return c
	}
	put := func(client k8s.ObjectStore, public bool) error {
		return client.PutBucket(ctx, k8s.BucketState{
			Name: "reports", Class: compute.ObjectClassStandard,
			PublicRead: public, Claim: k8s.ClaimOurs,
		})
	}

	// 1. Their literal inputs. The latent grant is what was wanted, so the call
	//    succeeds by unblocking and never touches the policy.
	latent := &statefulStore{blocked: true, policy: true, failWrite: "PUT ?policy"}
	if err := put(newClient(t, latent), true); err != nil {
		t.Fatalf("the grant was already correct, so no policy write should have been attempted; "+
			"PutBucket returned %v", err)
	}
	if !latent.readable() {
		t.Errorf("after unblocking a bucket that already carried the grant: blocked=%v policy=%v, "+
			"want readable", latent.blocked, latent.policy)
	}

	// 2. What their scenario was reaching for: the policy write is genuinely
	//    needed, and it fails. The bucket must stay blocked and unreadable.
	needsGrant := &statefulStore{blocked: true, policy: false, failWrite: "PUT ?policy"}
	client := newClient(t, needsGrant)
	if err := put(client, true); err == nil {
		t.Fatal("PutBucket succeeded with the policy write failing")
	}
	if needsGrant.readable() {
		t.Fatalf("after the failed public transition: blocked=%v policy=%v, and the bucket is "+
			"readable. The block must stay on until the grant is in place.",
			needsGrant.blocked, needsGrant.policy)
	}
	if !needsGrant.blocked {
		t.Errorf("the block was cleared before the grant succeeded: blocked=%v", needsGrant.blocked)
	}

	// 3. The other half of their finding: a private transition whose revoke fails
	//    must leave the bucket blocked, so the latent grant it leaves behind cannot
	//    be exposed by the next public transition. That is the coupling between the
	//    two directions, and it is why fixing one required understanding the other.
	revokeFails := &statefulStore{blocked: false, policy: true, failWrite: "DELETE ?policy"}
	if err := put(newClient(t, revokeFails), false); err == nil {
		t.Fatal("PutBucket succeeded with the revoke failing")
	}
	if revokeFails.readable() {
		t.Errorf("after a failed private transition: blocked=%v policy=%v, and the bucket is "+
			"still readable", revokeFails.blocked, revokeFails.policy)
	}
}

// TestNoSuchTagSetIsNotNoSuchBucket is the B2 regression, and the impact is
// ownership rather than cosmetics.
//
// GetBucketTagging answers 404 for two unrelated things: `NoSuchBucket`, and
// `NoSuchTagSet`, which means *the bucket exists and has no tags*. A client that
// read the status alone reported an existing untagged bucket as absent. Then
// EnsureBucket read "absent" as "the name is free", wrote access configuration,
// and stamped the ownership tag onto a bucket somebody else created. That is
// adoption, which compute.ErrNotOwned exists to forbid.
func TestNoSuchTagSetIsNotNoSuchBucket(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const noSuchTagSet = `<Error><Code>NoSuchTagSet</Code>` +
		`<Message>The TagSet does not exist</Message></Error>`
	const noSuchBucket = `<Error><Code>NoSuchBucket</Code>` +
		`<Message>The specified bucket does not exist</Message></Error>`
	unblocked := `<PublicAccessBlockConfiguration><BlockPublicPolicy>false</BlockPublicPolicy>` +
		`<RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>`

	t.Run("an existing untagged bucket is present and unowned", func(t *testing.T) {
		t.Parallel()
		// HEAD says it is there; tagging 404s because there are no tags.
		store := newS3Store(t, newStoreStub().
			on("GET", "/reports?tagging=", http.StatusNotFound, noSuchTagSet).
			on("HEAD", "/reports", http.StatusOK, "").
			on("GET", "/reports?publicAccessBlock=", http.StatusOK, unblocked).
			on("GET", "/reports?policy=", http.StatusNotFound, ""))

		state, found, err := store.GetBucket(ctx, "reports")
		if err != nil {
			t.Fatalf("GetBucket: %v", err)
		}
		if !found {
			t.Fatal("an existing untagged bucket reported as absent. EnsureBucket reads that as " +
				"'the name is free' and goes on to configure and tag somebody else's bucket.")
		}
		if state.Claim != k8s.ClaimUnclaimed {
			t.Errorf("a bucket with no tags reported claim %v; an empty tag set is ClaimUnclaimed, "+
				"and reporting it as ours would adopt anything untagged while reporting it as "+
				"foreign would make a failed tag write permanent", state.Claim)
		}
	})

	t.Run("a bucket somebody else owns is present, not absent", func(t *testing.T) {
		t.Parallel()
		// HEAD 403: it exists and this credential may not see it.
		store := newS3Store(t, newStoreStub().
			on("GET", "/reports?tagging=", http.StatusNotFound, noSuchTagSet).
			on("HEAD", "/reports", http.StatusForbidden, "").
			on("GET", "/reports?publicAccessBlock=", http.StatusOK, unblocked).
			on("GET", "/reports?policy=", http.StatusNotFound, ""))

		_, found, err := store.GetBucket(ctx, "reports")
		if err != nil {
			t.Fatalf("GetBucket: %v", err)
		}
		if !found {
			t.Error("a bucket that answered HEAD with 403 reported as absent; 403 means it is " +
				"there and not ours, which is the answer that prevents adoption")
		}
	})

	t.Run("a genuinely absent bucket is absent", func(t *testing.T) {
		t.Parallel()
		// The control. Without it the fix could be "always report present", which
		// would break every first EnsureBucket.
		store := newS3Store(t, newStoreStub().
			on("GET", "/reports?tagging=", http.StatusNotFound, noSuchBucket).
			on("HEAD", "/reports", http.StatusNotFound, ""))

		_, found, err := store.GetBucket(ctx, "reports")
		if err != nil {
			t.Fatalf("GetBucket: %v", err)
		}
		if found {
			t.Error("an absent bucket reported as present; no name would ever be free")
		}
	})
}

// TestReconcilingPublicAccessPreservesOtherStatements is the should-fix.
//
// The client claimed, on publicReadStatementID, to recognise its own statement so
// it could "leave anybody else's policy alone" — and then PUT a complete
// one-statement document to grant and DELETEd the whole policy to revoke. An owned
// bucket can legitimately carry statements an operator or another service wrote,
// and both paths destroyed them. The comment and the code disagreed, which is the
// drift class this project keeps paying for.
func TestReconcilingPublicAccessPreservesOtherStatements(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A policy with somebody else's statement in it, and no grant of ours.
	foreign := `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"operator-audit-reader","Effect":"Allow","Principal":{"AWS":"audit-role"},` +
		`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::reports/*"]}]}`
	blocked := `<PublicAccessBlockConfiguration><BlockPublicPolicy>true</BlockPublicPolicy>` +
		`<RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`

	t.Run("granting keeps them", func(t *testing.T) {
		t.Parallel()
		stub := newStoreStub().
			on("PUT", "/reports", http.StatusOK, "").
			on("GET", "/reports?publicAccessBlock=", http.StatusOK, blocked).
			on("GET", "/reports?policy=", http.StatusOK, foreign).
			on("PUT", "/reports?policy=", http.StatusOK, "").
			on("PUT", "/reports?publicAccessBlock=", http.StatusOK, "").
			on("PUT", "/reports?tagging=", http.StatusOK, "")
		store := newS3Store(t, stub)

		if err := store.PutBucket(ctx, k8s.BucketState{
			Name: "reports", Class: compute.ObjectClassStandard, PublicRead: true, Claim: k8s.ClaimOurs,
		}); err != nil {
			t.Fatalf("PutBucket: %v", err)
		}
		written := ""
		for _, r := range stub.recorded() {
			if r.Method == http.MethodPut && strings.Contains(r.Query, "policy") {
				written = r.Body
			}
		}
		if written == "" {
			t.Fatal("no policy was written")
		}
		if !strings.Contains(written, "operator-audit-reader") {
			t.Errorf("the operator's statement was destroyed by a public reconcile:\n%s", written)
		}
		if !strings.Contains(written, "apphub-public-read") {
			t.Errorf("our own grant was not added:\n%s", written)
		}
	})

	t.Run("revoking keeps them and does not delete the document", func(t *testing.T) {
		t.Parallel()
		withOurs := `{"Version":"2012-10-17","Statement":[` +
			`{"Sid":"operator-audit-reader","Effect":"Allow","Principal":{"AWS":"audit-role"},` +
			`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::reports/*"]},` +
			`{"Sid":"apphub-public-read","Effect":"Allow","Principal":"*",` +
			`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::reports/*"]}]}`
		unblocked := `<PublicAccessBlockConfiguration><BlockPublicPolicy>false</BlockPublicPolicy>` +
			`<RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
		stub := newStoreStub().
			on("PUT", "/reports", http.StatusOK, "").
			on("GET", "/reports?publicAccessBlock=", http.StatusOK, unblocked).
			on("GET", "/reports?policy=", http.StatusOK, withOurs).
			on("PUT", "/reports?policy=", http.StatusOK, "").
			on("PUT", "/reports?publicAccessBlock=", http.StatusOK, "").
			on("PUT", "/reports?tagging=", http.StatusOK, "")
		store := newS3Store(t, stub)

		if err := store.PutBucket(ctx, k8s.BucketState{
			Name: "reports", Class: compute.ObjectClassStandard, PublicRead: false, Claim: k8s.ClaimOurs,
		}); err != nil {
			t.Fatalf("PutBucket: %v", err)
		}
		var wrote, deleted bool
		written := ""
		for _, r := range stub.recorded() {
			if !strings.Contains(r.Query, "policy") {
				continue
			}
			switch r.Method {
			case http.MethodPut:
				wrote, written = true, r.Body
			case http.MethodDelete:
				deleted = true
			}
		}
		if deleted {
			t.Error("the whole policy was deleted, taking the operator's statement with it")
		}
		if !wrote {
			t.Fatal("no policy was written on revoke")
		}
		if !strings.Contains(written, "operator-audit-reader") {
			t.Errorf("the operator's statement was destroyed by a private reconcile:\n%s", written)
		}
		if strings.Contains(written, "apphub-public-read") {
			t.Errorf("our grant survived a private reconcile:\n%s", written)
		}
	})

	t.Run("revoking the last statement removes the document", func(t *testing.T) {
		t.Parallel()
		// An empty Statement list is not a valid policy, so the document must be
		// deleted rather than written empty.
		onlyOurs := `{"Version":"2012-10-17","Statement":[` +
			`{"Sid":"apphub-public-read","Effect":"Allow","Principal":"*",` +
			`"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::reports/*"]}]}`
		unblocked := `<PublicAccessBlockConfiguration><BlockPublicPolicy>false</BlockPublicPolicy>` +
			`<RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
		stub := newStoreStub().
			on("PUT", "/reports", http.StatusOK, "").
			on("GET", "/reports?publicAccessBlock=", http.StatusOK, unblocked).
			on("GET", "/reports?policy=", http.StatusOK, onlyOurs).
			on("DELETE", "/reports?policy=", http.StatusNoContent, "").
			on("PUT", "/reports?publicAccessBlock=", http.StatusOK, "").
			on("PUT", "/reports?tagging=", http.StatusOK, "")
		store := newS3Store(t, stub)

		if err := store.PutBucket(ctx, k8s.BucketState{
			Name: "reports", Class: compute.ObjectClassStandard, PublicRead: false, Claim: k8s.ClaimOurs,
		}); err != nil {
			t.Fatalf("PutBucket: %v", err)
		}
		deleted := false
		for _, r := range stub.recorded() {
			if r.Method == http.MethodDelete && strings.Contains(r.Query, "policy") {
				deleted = true
			}
		}
		if !deleted {
			t.Error("the policy was not deleted when nothing was left in it; an empty Statement " +
				"list is not a valid policy document")
		}
	})
}

// --- ordering and content, after the count-based tests were retired -------------
//
// Three earlier tests asserted an exact request count and a fixed sequence. They
// broke the moment the reconcile learned to read its current state and skip writes
// it does not need, and they broke for a good reason: a count is not a property.
// The safety ordering is carried by TestNoPartialPutBucketLeavesABucketReadable,
// which models the state and checks an invariant across every interleaving instead
// of pinning one sequence. What is left below is what that property test cannot
// see — the content of the writes, and the ordering facts that are about ownership
// and exposure rather than about how many requests it took.

// requestLog renders a stub's recorded requests as "METHOD ?subresource", so an
// ordering assertion does not depend on how many reads the reconcile makes.
func requestLog(stub *storeStub) []string {
	var out []string
	for _, r := range stub.recorded() {
		q := r.Query
		if i := strings.IndexByte(q, '='); i >= 0 {
			q = q[:i]
		}
		out = append(out, r.Method+" ?"+q)
	}
	return out
}

func indexOf(log []string, want string) int {
	for i, v := range log {
		if v == want {
			return i
		}
	}
	return -1
}

func lastIndexOf(log []string, want string) int {
	found := -1
	for i, v := range log {
		if v == want {
			found = i
		}
	}
	return found
}

// unblockedNoGrant is a store whose blocks are off and which has no policy, so
// both directions have work to do.
func unblockedNoGrant(bucket string) *storeStub {
	return newStoreStub().
		on("PUT", "/"+bucket, http.StatusOK, "").
		on("GET", "/"+bucket+"?publicAccessBlock=", http.StatusOK,
			`<PublicAccessBlockConfiguration><BlockPublicPolicy>false</BlockPublicPolicy>`+
				`<RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>`).
		on("GET", "/"+bucket+"?policy=", http.StatusNotFound, "").
		on("PUT", "/"+bucket+"?policy=", http.StatusOK, "").
		on("DELETE", "/"+bucket+"?policy=", http.StatusNoContent, "").
		on("PUT", "/"+bucket+"?publicAccessBlock=", http.StatusOK, "").
		on("PUT", "/"+bucket+"?tagging=", http.StatusOK, "").
		on("GET", "/"+bucket+"?tagging=", http.StatusOK,
			`<Tagging><TagSet><Tag><Key>apphub.dev/managed-by</Key>`+
				`<Value>apphub</Value></Tag></TagSet></Tagging>`)
}

// TestPutBucketWritesAreExplicitAndTheTagComesFirst checks the write contents and
// the one ordering fact that is about ownership rather than exposure.
//
// **This test previously asserted the opposite**, and it was wrong for a reason
// worth keeping visible. It required the ownership tag to be written *last*, on the
// reasoning that a bucket should never briefly carry the marker saying it is ours
// while its access configuration is unsettled. That reasoning was weak — carrying
// the marker is not itself an exposure — and it cost two defects:
//
//   - a tagging failure after the unblock returned an error with a formerly-private
//     bucket public, which a reviewer reproduced;
//   - a failed access write left the bucket created and untagged, so the next
//     EnsureBucket read it as existing-but-not-ours and refused it for ever.
//
// The tag now goes first, before anything that can change exposure. A tagging
// failure cannot expose a bucket, and claiming ownership first is what lets a
// failed reconcile be retried.
func TestPutBucketWritesAreExplicitAndTheTagComesFirst(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, public := range []bool{false, true} {
		stub := unblockedNoGrant("reports")
		store := newS3Store(t, stub)

		if err := store.PutBucket(ctx, k8s.BucketState{
			Name:       "reports",
			Class:      compute.ObjectClassStandard,
			PublicRead: public,
			Labels:     map[string]string{"app": "web"},
			Claim:      k8s.ClaimOurs,
		}); err != nil {
			t.Fatalf("PutBucket(public=%v): %v", public, err)
		}

		log := requestLog(stub)
		tag := indexOf(log, "PUT ?tagging")
		if tag < 0 {
			t.Fatalf("public=%v: no ownership tag was written: %v", public, log)
		}
		// Every write that can change exposure must come after it. That is the
		// property, rather than a fixed index: it holds however many reads the
		// reconcile makes.
		for i, entry := range log {
			if i >= tag {
				continue
			}
			if entry == "PUT ?publicAccessBlock" || entry == "PUT ?policy" ||
				entry == "DELETE ?policy" {
				t.Errorf("public=%v: %q at position %d precedes the ownership tag at %d.\n"+
					"Every write that can change exposure must follow the tag, so a failure in "+
					"one leaves a bucket that is ours and retryable rather than exposed and "+
					"unclaimed. %v", public, entry, i, tag, log)
			}
		}

		// Every field of every public-access body must be explicit. An omitted
		// field means "leave it as it was", so a partial document silently
		// inherits whatever the store already had.
		bodies := 0
		for _, r := range stub.recorded() {
			if r.Method != http.MethodPut || !strings.Contains(r.Query, "publicAccessBlock") {
				continue
			}
			bodies++
			for _, field := range []string{
				"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets",
			} {
				if !strings.Contains(r.Body, "<"+field+">") {
					t.Errorf("public=%v: a public-access body omits %s:\n%s", public, field, r.Body)
				}
			}
		}
		if bodies == 0 {
			t.Errorf("public=%v: no public-access configuration was written at all", public)
		}

		tagBody := ""
		for _, r := range stub.recorded() {
			if r.Method == http.MethodPut && strings.Contains(r.Query, "tagging") {
				tagBody = r.Body
			}
		}
		if !strings.Contains(tagBody, "apphub.dev/managed-by") {
			t.Errorf("public=%v: the tag set carries no ownership marker: %s", public, tagBody)
		}
		if !strings.Contains(tagBody, "apphub.dev/label/app") {
			t.Errorf("public=%v: the caller's label is not under the reserved prefix: %s",
				public, tagBody)
		}
	}
}

// TestAPublicBucketIsActuallyGranted is the regression for the first defect a
// reviewer reproduced: clearing the four PublicAccessBlock flags does not make a
// bucket public.
//
// S3 grants public read through a policy or an ACL; a PublicAccessBlock
// configuration only rejects or ignores such a grant, and a new bucket is private.
// A provider that cleared the blocks and stopped had permitted a grant it never
// made, and then reported the bucket public.
//
// It also pins the ordering fact specific to this direction — the unblock comes
// after the grant — as a relative position rather than an index, so it survives
// the reconcile skipping work it does not need.
func TestAPublicBucketIsActuallyGranted(t *testing.T) {
	t.Parallel()

	stub := newStoreStub().
		on("PUT", "/assets", http.StatusOK, "").
		on("GET", "/assets?publicAccessBlock=", http.StatusOK,
			`<PublicAccessBlockConfiguration><BlockPublicPolicy>true</BlockPublicPolicy>`+
				`<RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`).
		on("GET", "/assets?policy=", http.StatusNotFound, "").
		on("PUT", "/assets?policy=", http.StatusOK, "").
		on("PUT", "/assets?publicAccessBlock=", http.StatusOK, "").
		on("PUT", "/assets?tagging=", http.StatusOK, "")
	store := newS3Store(t, stub)

	if err := store.PutBucket(context.Background(), k8s.BucketState{
		Name: "assets", Class: compute.ObjectClassStandard, PublicRead: true, Claim: k8s.ClaimOurs,
	}); err != nil {
		t.Fatalf("PutBucket(public): %v", err)
	}

	log := requestLog(stub)
	grant := indexOf(log, "PUT ?policy")
	if grant < 0 {
		t.Fatalf("no PutBucketPolicy was issued: %v\nWithout it, clearing the blocks only "+
			"permits a grant that was never made.", log)
	}
	unblock := lastIndexOf(log, "PUT ?publicAccessBlock")
	if unblock < grant {
		t.Errorf("the last public-access write is at %d and the grant at %d: the block must be "+
			"cleared AFTER the grant is in place, or a prior latent grant is exposed before it "+
			"is overwritten. %v", unblock, grant, log)
	}

	policy, cleared := "", false
	for _, r := range stub.recorded() {
		switch {
		case r.Method == http.MethodPut && strings.Contains(r.Query, "policy"):
			policy = r.Body
		case r.Method == http.MethodPut && strings.Contains(r.Query, "publicAccessBlock"):
			if strings.Contains(r.Body, "<BlockPublicPolicy>false</BlockPublicPolicy>") {
				cleared = true
			}
		}
	}
	for _, want := range []string{`"Effect":"Allow"`, `"Principal":"*"`, "s3:GetObject", "assets/*"} {
		if !strings.Contains(policy, want) {
			t.Errorf("the bucket policy does not contain %s:\n%s", want, policy)
		}
	}
	if !cleared {
		t.Error("no public-access write cleared BlockPublicPolicy, so the bucket stays blocked")
	}
}

// TestAnOwnedBucketStillReEnsures is the control for the test above, and it is the
// half that makes the fix a fix rather than a blanket refusal.
//
// Every reconcile of an existing bucket gets `BucketAlreadyOwnedByYou`. If that
// became ErrNotOwned unconditionally, no bucket could ever be re-Ensured — the
// provider would work exactly once per name. The 409 has to fall through to the
// ownership read and *pass* when the marker is there.
func TestAnOwnedBucketStillReEnsures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ourTags := `<Tagging><TagSet>` +
		`<Tag><Key>apphub.dev/managed-by</Key><Value>apphub</Value></Tag>` +
		`<Tag><Key>apphub.dev/object-class</Key><Value>standard</Value></Tag>` +
		`</TagSet></Tagging>`
	blocked := `<PublicAccessBlockConfiguration><BlockPublicPolicy>true</BlockPublicPolicy>` +
		`<RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`

	stub := newStoreStub().
		on("PUT", "/reports", http.StatusConflict,
			`<Error><Code>BucketAlreadyOwnedByYou</Code></Error>`).
		on("GET", "/reports?tagging=", http.StatusOK, ourTags).
		on("GET", "/reports?publicAccessBlock=", http.StatusOK, blocked).
		on("GET", "/reports?policy=", http.StatusNotFound, "").
		on("PUT", "/reports?tagging=", http.StatusOK, "")
	store := newS3Store(t, stub)

	if err := store.PutBucket(ctx, k8s.BucketState{
		Name: "reports", Class: compute.ObjectClassStandard, Claim: k8s.ClaimOurs,
	}); err != nil {
		t.Fatalf("re-Ensuring our own bucket failed: %v\nEvery reconcile of an existing bucket "+
			"answers BucketAlreadyOwnedByYou, so refusing it unconditionally means a bucket can "+
			"be created once and never reconciled.", err)
	}
}

// TestAFailedReconcileLeavesTheBucketReEnsurable is a defect nobody reported,
// found while fixing B1, and it is why the ownership tag moved to the front.
//
// With the tag written last, a failed access write left the bucket created and
// untagged. The next EnsureBucket then read it as existing-but-not-ours and
// refused it with ErrNotOwned — permanently. A bucket this provider created became
// one it would never touch again, and no retry could converge.
func TestAFailedReconcileLeavesTheBucketReEnsurable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A store where the access write fails but tagging works.
	st := &statefulStore{blocked: false, policy: false, failWrite: "PUT ?publicAccessBlock"}
	client, err := k8s.NewS3ObjectStore("https://objects.invalid", testSigner(),
		k8s.S3Options{Transport: st})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}
	if err := client.PutBucket(ctx, k8s.BucketState{
		Name: "reports", Class: compute.ObjectClassStandard, Claim: k8s.ClaimOurs,
	}); err == nil {
		t.Fatal("PutBucket succeeded with the access write failing")
	}

	// The ownership marker must already be there, so a retry recognises the
	// bucket as ours rather than refusing it.
	tagged := false
	for _, m := range st.mutatingWrites() {
		if m == "PUT ?tagging" {
			tagged = true
		}
	}
	if !tagged {
		t.Error("the bucket was created and left untagged by a failed reconcile. The next " +
			"EnsureBucket reads that as existing-but-not-ours and refuses it with ErrNotOwned, " +
			"for ever: the provider can never converge on a bucket it created itself.")
	}
}

// TestA200FromCreateBucketIsNotAnOwnershipAnswer is the fourth route into the
// adoption bug, and the reason the ownership determination is now unconditional.
//
// **`CreateBucket` in us-east-1 answers 200 for a bucket you already own**, not
// 409. So the 200 path — the one that appears to prove we just created the bucket
// — proves nothing, and gating the ownership read on the create's outcome adopted
// a same-account create-race winner through the success path.
//
// The first three routes were all closed by reasoning about which status code came
// back: a 404 that also means NoSuchTagSet, a 409 that means the account owns it,
// an unnamed 409 assumed harmless. Enumerating status codes is what kept producing
// new routes. This asserts the enumeration is gone: every create outcome reaches
// the same marker read.
func TestA200FromCreateBucketIsNotAnOwnershipAnswer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// The store answers 200 to the create — as us-east-1 does for a bucket you
	// already own — and the bucket carries somebody else's tags.
	stub := newStoreStub().
		on("GET", "/reports?tagging=", http.StatusOK,
			`<Tagging><TagSet><Tag><Key>team</Key><Value>analytics</Value></Tag></TagSet></Tagging>`).
		on("HEAD", "/reports", http.StatusOK, "").
		on("PUT", "/reports", http.StatusOK, "")
	store := newS3Store(t, stub)

	err := store.PutBucket(ctx, k8s.BucketState{
		Name: "reports", Class: compute.ObjectClassStandard, Claim: k8s.ClaimOurs,
	})
	if !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("PutBucket returned %v, want compute.ErrNotOwned.\nA 200 from CreateBucket does "+
			"not prove we created the bucket — us-east-1 answers 200 for one you already own — "+
			"so the success path must reach the ownership read like every other outcome.", err)
	}

	// And nothing may have been written to it.
	for _, r := range stub.recorded() {
		if (r.Method == http.MethodPut && r.Query != "") || r.Method == http.MethodDelete {
			t.Errorf("a refused bucket was still modified: %s ?%s", r.Method, r.Query)
		}
	}
}

// TestPutBucketAcceptsAnUntaggedBucket checks the ownership classifier at the seam
// it lives at, and is DEMOTED from being the regression for the untagged-bucket
// trap.
//
// It was the regression, and it was the wrong test for the job: it passed while
// the reported two-Ensure reproduction still failed, because the refusal that
// broke recovery was one layer above it in [objectStore.EnsureBucket]. A test at a
// lower seam than the reproduction can agree with a fix that does not reach the
// defect. [TestTwoEnsuresRecoverFromAStrandedBucket] is the regression now; this
// stays as a unit check on PutBucket, which is worth having but is not evidence
// about the reported failure.
//
// The original note, still true about this seam:
//
// Moving the ownership tag ahead of the access reconcile fixed a failed *access*
// write leaving the bucket untagged. It could not fix the tag write itself
// failing: there is nothing to tag before the bucket exists, so that one write
// cannot be moved earlier. And a two-answer ownership check — marker or not-ours —
// then refused this provider's own bucket for ever.
//
// **The class, named rather than the instance patched:** a bucket this provider
// created but could not mark is a state the provider must be able to recover from,
// and recovery must not require the marker to prove ownership of a bucket nothing
// else claims. So an untagged bucket is *unclaimed*, and claimable.
func TestPutBucketAcceptsAnUntaggedBucket(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// First attempt: the bucket is created and the ownership tag write fails.
	failing := &statefulStore{blocked: false, policy: false, failWrite: "PUT ?tagging"}
	client, err := k8s.NewS3ObjectStore("https://objects.invalid", testSigner(),
		k8s.S3Options{Transport: failing})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}
	if err := client.PutBucket(ctx, k8s.BucketState{
		Name: "reports", Class: compute.ObjectClassStandard, Claim: k8s.ClaimOurs,
	}); err == nil {
		t.Fatal("PutBucket succeeded with the tag write failing")
	}

	// Second attempt against a store where the bucket exists and is untagged —
	// exactly the state the first attempt left. It must converge, not refuse.
	untagged := newStoreStub().
		on("PUT", "/reports", http.StatusOK, "").
		on("GET", "/reports?tagging=", http.StatusNotFound,
			`<Error><Code>NoSuchTagSet</Code></Error>`).
		on("HEAD", "/reports", http.StatusOK, "").
		on("GET", "/reports?publicAccessBlock=", http.StatusNotFound, "").
		on("GET", "/reports?policy=", http.StatusNotFound, "").
		on("PUT", "/reports?tagging=", http.StatusOK, "").
		on("PUT", "/reports?publicAccessBlock=", http.StatusOK, "")
	retry := newS3Store(t, untagged)
	if err := retry.PutBucket(ctx, k8s.BucketState{
		Name: "reports", Class: compute.ObjectClassStandard, Claim: k8s.ClaimOurs,
	}); err != nil {
		t.Fatalf("the retry refused a bucket this provider created and could not mark: %v\n"+
			"Requiring the marker to prove ownership of a bucket nothing else claims makes the "+
			"provider permanently unable to recover from its own partial failure.", err)
	}
	// It must have written the marker this time.
	marked := false
	for _, r := range untagged.recorded() {
		if r.Method == http.MethodPut && strings.Contains(r.Query, "tagging") &&
			strings.Contains(r.Body, "apphub.dev/managed-by") {
			marked = true
		}
	}
	if !marked {
		t.Error("the retry did not write the ownership marker")
	}
}

// TestATaggedForeignBucketIsStillRefused is the control that keeps the previous
// test from being a licence to adopt anything.
//
// "Untagged is unclaimed" is only safe because a tag that is not this platform's
// marker makes a bucket foreign. The boundary is "any tag EXCEPT our own marker",
// not "any tag at all" — an actor who writes the marker is claiming to be this
// platform and is believed, which is stated at [k8s.BucketClaim] rather than
// implied away here.
func TestATaggedForeignBucketIsStillRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for name, tags := range map[string]string{
		"somebody else's tag": `<Tagging><TagSet><Tag><Key>owner</Key>` +
			`<Value>data-platform</Value></Tag></TagSet></Tagging>`,
		"our key with the wrong value": `<Tagging><TagSet>` +
			`<Tag><Key>apphub.dev/managed-by</Key><Value>something-else</Value></Tag>` +
			`</TagSet></Tagging>`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newS3Store(t, newStoreStub().
				on("PUT", "/reports", http.StatusOK, "").
				on("GET", "/reports?tagging=", http.StatusOK, tags))
			err := store.PutBucket(ctx, k8s.BucketState{
				Name: "reports", Class: compute.ObjectClassStandard, Claim: k8s.ClaimOurs,
			})
			if !errors.Is(err, compute.ErrNotOwned) {
				t.Fatalf("PutBucket returned %v for a bucket tagged by %s, want ErrNotOwned",
					err, name)
			}
		})
	}
}

// raceStore answers as a store does when another actor wins a create race: the
// bucket is absent when we look, and present with their tag by the time we create.
//
// A keyed stub cannot express this, because the same request has two different
// answers at two different times — which is exactly what a race is. That is why
// this exists rather than another registration.
type raceStore struct {
	mu      sync.Mutex
	created bool
	writes  []string
}

func (r *raceStore) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	reply := func(status int, body string) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     http.Header{},
			Request:    req,
		}, nil
	}
	q := req.URL.RawQuery
	if isMutation(req.Method) && q != "" {
		r.writes = append(r.writes, requestKey(req.Method, q))
	}
	switch {
	case req.Method == http.MethodPut && q == "":
		// The create. The other actor got here first.
		r.created = true
		return reply(http.StatusConflict, `<Error><Code>BucketAlreadyOwnedByYou</Code></Error>`)
	case strings.HasPrefix(q, "tagging") && req.Method == http.MethodGet:
		if !r.created {
			// Before the create: as far as we can see, nothing is there.
			return reply(http.StatusNotFound, `<Error><Code>NoSuchBucket</Code></Error>`)
		}
		// After: the racing actor's bucket, carrying their tag.
		return reply(http.StatusOK, `<Tagging><TagSet><Tag><Key>owner</Key>`+
			`<Value>data-platform</Value></Tag></TagSet></Tagging>`)
	case req.Method == http.MethodHead:
		if !r.created {
			return reply(http.StatusNotFound, "")
		}
		return reply(http.StatusOK, "")
	}
	return reply(http.StatusNotFound, `<Error><Code>NoSuchKey</Code></Error>`)
}

// TestDoesNotAdoptASameAccountCreateRace is the same-account race, and the
// protection it asserts is **narrower than the previous version claimed**. That is
// a deliberate trade, and worth stating rather than adjusting a fixture around.
//
// A racing actor's bucket is refused when it carries *any* tags. It is **claimed**
// when it carries none — because S3 has no conditional bucket creation, so nothing
// distinguishes "another actor made this a millisecond ago and has not tagged it"
// from "we made this a millisecond ago and our tag write failed". Refusing both
// makes this provider permanently unable to recover from its own partial failure on
// a bucket it really does own; TestTwoEnsuresRecoverFromAStrandedBucket asserts
// that other side.
//
// So the boundary is "untagged means unclaimed", and it is one an operator can act
// on: tag your buckets with anything, and this provider will not touch them.
func TestDoesNotAdoptASameAccountCreateRace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := &raceStore{}
	client, err := k8s.NewS3ObjectStore("https://objects.invalid", testSigner(),
		k8s.S3Options{Transport: store})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}

	cfg := fullConfig()
	registry := k8s.NewMemoryRegistry()
	registry.SetFederatesClusterOIDC(true)
	p := k8s.New(&k8s.Substrate{
		Cluster:  k8s.NewMemoryCluster(),
		Registry: registry,
		Objects:  client,
	}, cfg)

	stores, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}
	if _, err := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "reports"}); !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("EnsureBucket returned %v, want compute.ErrNotOwned.\nThe bucket was absent "+
			"when we looked and present with another actor's tag by the time we created, so a "+
			"409 accepted as idempotence adopts their bucket.", err)
	}

	store.mu.Lock()
	writes := append([]string(nil), store.writes...)
	store.mu.Unlock()
	if len(writes) != 0 {
		t.Errorf("a refused bucket was still modified: %v\nA refusal that half-configures is "+
			"worse than either answer.", writes)
	}
}

// TestEveryCreateOutcomeReachesTheOwnershipRead is the structural half of the
// fourth-route fix, and it is the assertion that would have prevented rounds two,
// three and four of the same bug.
//
// Each earlier fix reasoned about *which status code* the create returned, and each
// left a code it had not considered: a 404 that also means NoSuchTagSet, a 409 that
// means the account owns it, an unnamed 409, and finally a **200** — which
// us-east-1 returns for a bucket you already own. So this asserts the property
// rather than the codes: whatever CreateBucket answers, the tags are read before
// anything is written.
func TestEveryCreateOutcomeReachesTheOwnershipRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	foreign := `<Tagging><TagSet><Tag><Key>owner</Key><Value>someone</Value></Tag></TagSet></Tagging>`

	for name, create := range map[string]stubResponse{
		"200 OK":                      {status: http.StatusOK},
		"201 Created":                 {status: http.StatusCreated},
		"409 BucketAlreadyOwnedByYou": {status: http.StatusConflict, body: `<Error><Code>BucketAlreadyOwnedByYou</Code></Error>`},
		"409 with no code":            {status: http.StatusConflict},
		"409 with an unfamiliar code": {status: http.StatusConflict, body: `<Error><Code>SomethingNew</Code></Error>`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stub := newStoreStub().
				on("PUT", "/reports", create.status, create.body).
				on("GET", "/reports?tagging=", http.StatusOK, foreign)
			store := newS3Store(t, stub)

			err := store.PutBucket(ctx, k8s.BucketState{
				Name: "reports", Class: compute.ObjectClassStandard, Claim: k8s.ClaimOurs,
			})
			if !errors.Is(err, compute.ErrNotOwned) {
				t.Fatalf("create answered %s and PutBucket returned %v, want ErrNotOwned.\n"+
					"No create outcome distinguishes 'we created this' from 'it was already "+
					"here', so none of them may skip the ownership read.", name, err)
			}
			read := false
			for _, r := range stub.recorded() {
				if r.Method == http.MethodGet && strings.Contains(r.Query, "tagging") {
					read = true
				}
			}
			if !read {
				t.Errorf("create answered %s and the ownership tags were never read", name)
			}
		})
	}

	// The one outcome that is refused before the read, and why: a different
	// account's name has no ownership read that could succeed, so refusing here
	// gives the operator "bucket names are global" rather than "no marker found".
	early := newS3Store(t, newStoreStub().
		on("PUT", "/reports", http.StatusConflict,
			`<Error><Code>BucketAlreadyExists</Code></Error>`))
	err := early.PutBucket(ctx, k8s.BucketState{
		Name: "reports", Class: compute.ObjectClassStandard, Claim: k8s.ClaimOurs,
	})
	if !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("BucketAlreadyExists returned %v, want compute.ErrNotOwned", err)
	}
	if !strings.Contains(err.Error(), "different account") {
		t.Errorf("the refusal does not name the cause: %v", err)
	}
}

// recoveringStore models the one thing the shared stub cannot: a bucket whose tag
// set is empty and stays empty until a tag write succeeds.
//
// [statefulStore] answers every tagging GET with the ownership marker, which is
// what most tests need and is exactly what makes it useless here — the trap state
// is "exists, carries no tags at all", and a fixture that always reports the
// marker can never be in it.
type recoveringStore struct {
	mu sync.Mutex
	// exists and tags are the store's ground truth for one bucket.
	exists bool
	tags   map[string]string
	// blocked and policy model the access sub-resources.
	blocked bool
	policy  bool
	// failTagWrite makes PUT ?tagging fail, which is the write that cannot be
	// moved earlier and so is the one that strands a bucket untagged.
	failTagWrite bool
}

func (s *recoveringStore) setFailTagWrite(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failTagWrite = v
}

func (s *recoveringStore) state() (exists bool, tagCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exists, len(s.tags)
}

func (s *recoveringStore) RoundTrip(req *http.Request) (*http.Response, error) {
	body := ""
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(raw)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	reply := func(status int, payload string) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(payload)),
			Header:     http.Header{},
			Request:    req,
		}, nil
	}
	q := req.URL.RawQuery

	switch {
	case q == "" && req.Method == http.MethodPut:
		// CreateBucket. 200 for a bucket already owned, which is the us-east-1
		// answer and proves nothing about ownership either way.
		s.exists = true
		return reply(http.StatusOK, "")

	case req.Method == http.MethodHead:
		if !s.exists {
			return reply(http.StatusNotFound, "")
		}
		return reply(http.StatusOK, "")

	case strings.HasPrefix(q, "tagging"):
		switch req.Method {
		case http.MethodGet:
			if !s.exists {
				return reply(http.StatusNotFound, "<Error><Code>NoSuchBucket</Code></Error>")
			}
			if len(s.tags) == 0 {
				// NoSuchTagSet shares its status with NoSuchBucket, which is the
				// ambiguity the client has to resolve with HeadBucket.
				return reply(http.StatusNotFound, "<Error><Code>NoSuchTagSet</Code></Error>")
			}
			payload := "<Tagging><TagSet>"
			for k, v := range s.tags {
				payload += "<Tag><Key>" + k + "</Key><Value>" + v + "</Value></Tag>"
			}
			return reply(http.StatusOK, payload+"</TagSet></Tagging>")
		case http.MethodPut:
			if s.failTagWrite {
				return reply(http.StatusInternalServerError, "")
			}
			if s.tags == nil {
				s.tags = map[string]string{}
			}
			if strings.Contains(body, "apphub.dev/managed-by") {
				s.tags["apphub.dev/managed-by"] = "apphub"
			}
			return reply(http.StatusOK, "")
		}

	case strings.HasPrefix(q, "publicAccessBlock"):
		if req.Method == http.MethodGet {
			v := "false"
			if s.blocked {
				v = "true"
			}
			return reply(http.StatusOK, `<PublicAccessBlockConfiguration>`+
				`<BlockPublicAcls>`+v+`</BlockPublicAcls>`+
				`<IgnorePublicAcls>`+v+`</IgnorePublicAcls>`+
				`<BlockPublicPolicy>`+v+`</BlockPublicPolicy>`+
				`<RestrictPublicBuckets>`+v+`</RestrictPublicBuckets>`+
				`</PublicAccessBlockConfiguration>`)
		}
		s.blocked = strings.Contains(body, "<BlockPublicPolicy>true</BlockPublicPolicy>")
		return reply(http.StatusOK, "")

	case strings.HasPrefix(q, "policy"):
		switch req.Method {
		case http.MethodGet:
			if !s.policy {
				return reply(http.StatusNotFound, "<Error><Code>NoSuchBucketPolicy</Code></Error>")
			}
			return reply(http.StatusOK, publicReadPolicy("reports"))
		case http.MethodPut:
			s.policy = strings.Contains(body, publicReadStatementIDForTest)
			return reply(http.StatusOK, "")
		case http.MethodDelete:
			s.policy = false
			return reply(http.StatusNoContent, "")
		}
	}
	return reply(http.StatusNotFound, "<Error><Code>NoSuchKey</Code></Error>")
}

// TestTwoEnsuresRecoverFromAStrandedBucket is the untagged-bucket regression, run
// through the entry point the reproduction used.
//
// # Why this test exists when a passing one already covered the same fix
//
// The previous regression called [S3ObjectStore.PutBucket] directly. The
// three-answer ownership logic lives there, so the test passed — and the
// reproduction it was written for still failed, because
// [objectStore.EnsureBucket] calls GetBucket first and refused the untagged
// bucket with [compute.ErrNotOwned] before PutBucket ever ran. **The fix and its
// test agreed with each other and neither was asked the original question.**
//
// The rule that came out of it: *a test written at a lower seam than the
// reproduction can pass while the reproduction still fails*, so a fix for a
// reported defect has to be verified through the entry point the report used. Two
// Ensures is what was reported, so two Ensures is what this runs.
func TestTwoEnsuresRecoverFromAStrandedBucket(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := &recoveringStore{failTagWrite: true}
	client, err := k8s.NewS3ObjectStore("https://objects.invalid", testSigner(),
		k8s.S3Options{Transport: store})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}
	registry := k8s.NewMemoryRegistry()
	registry.SetFederatesClusterOIDC(true)
	p := k8s.New(&k8s.Substrate{
		Cluster:  k8s.NewMemoryCluster(),
		Registry: registry,
		Objects:  client,
	}, fullConfig())
	stores, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}

	// First Ensure: the bucket is created and the ownership tag write fails.
	if _, err := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "reports"}); err == nil {
		t.Fatal("the first EnsureBucket succeeded with the tag write failing")
	}
	// The trap state has to be real, or the second call proves nothing.
	if exists, tags := store.state(); !exists || tags != 0 {
		t.Fatalf("after the failed Ensure the store has exists=%v tags=%d; the reproduction "+
			"needs a bucket that exists and carries no tags", exists, tags)
	}

	// Second Ensure, the store now healthy. This is the call that used to fail.
	store.setFailTagWrite(false)
	if _, err := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "reports"}); err != nil {
		t.Fatalf("the second EnsureBucket refused a bucket this provider created and could not "+
			"mark: %v\nRequiring the marker to prove ownership of a bucket nothing else claims "+
			"makes the provider permanently unable to recover from its own partial failure. "+
			"If this fails with ErrNotOwned the refusal is in EnsureBucket, not in PutBucket.", err)
	}
	if _, tags := store.state(); tags == 0 {
		t.Error("the recovering Ensure did not write the ownership marker, so the next one " +
			"would have to recover all over again")
	}
}

// TestEnsureBucketStillRefusesAForeignBucket is the control for the test above, at
// the same seam.
//
// Moving the recovery assertion up to EnsureBucket is only safe if the refusal
// moved up with it. A bucket carrying somebody else's tag must still be refused
// through the public entry point, not merely inside PutBucket.
func TestEnsureBucketStillRefusesAForeignBucket(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := &recoveringStore{
		exists: true,
		tags:   map[string]string{"team": "platform"},
	}
	client, err := k8s.NewS3ObjectStore("https://objects.invalid", testSigner(),
		k8s.S3Options{Transport: store})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}
	registry := k8s.NewMemoryRegistry()
	registry.SetFederatesClusterOIDC(true)
	p := k8s.New(&k8s.Substrate{
		Cluster:  k8s.NewMemoryCluster(),
		Registry: registry,
		Objects:  client,
	}, fullConfig())
	stores, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}

	if _, err := stores.EnsureBucket(ctx, compute.BucketSpec{Name: "reports"}); !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("EnsureBucket returned %v, want compute.ErrNotOwned. A bucket carrying "+
			"another actor's tag is foreign, and 'untagged is claimable' is only safe while "+
			"that stays true.", err)
	}
}

// TestABackingStoreThatForgetsTheClaimCannotCauseAdoption is the control for the
// limit the round-six review named when it prescribed the three-state seam:
// "removing the outer refusal without moving enforcement into every backing store
// closes this reproduction but can reopen adoption for non-S3 implementations."
//
// The refusal was NOT removed — [objectStore.EnsureBucket] still refuses at the
// public boundary — but the seam now carries three states instead of a bool, and
// that raises a question a bool did not have: what happens when a backing store
// reports a state it never set?
//
// [ClaimUnknown] is the zero value precisely so the answer is "refused". This test
// exists because that is a property of the seam rather than of the S3 client, so no
// test of S3ObjectStore can cover it: any ObjectStore implementation — a future
// MinIO or Ceph adapter, or a test double — that populates Name and Class and
// forgets Claim gets a refusal rather than an adoption. Fail-closed by the zero
// value, verified rather than asserted.
func TestABackingStoreThatForgetsTheClaimCannotCauseAdoption(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := k8s.NewMemoryObjectStore()
	// A bucket that exists and whose claim was never set: exactly what a backing
	// store written against the older bool-shaped seam would produce.
	if err := store.PutBucket(ctx, k8s.BucketState{
		Name:  "reports",
		Class: compute.ObjectClassStandard,
	}); err != nil {
		t.Fatalf("seeding the bucket: %v", err)
	}

	registry := k8s.NewMemoryRegistry()
	registry.SetFederatesClusterOIDC(true)
	p := k8s.New(&k8s.Substrate{
		Cluster:  k8s.NewMemoryCluster(),
		Registry: registry,
		Objects:  store,
	}, fullConfig())
	stores, err := p.ObjectStores()
	if err != nil {
		t.Fatalf("ObjectStores: %v", err)
	}

	_, err = stores.EnsureBucket(ctx, compute.BucketSpec{Name: "reports"})
	if !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("EnsureBucket returned %v, want compute.ErrNotOwned.\nA backing store that "+
			"reports no claim at all must not have its buckets adopted: the three-state seam is "+
			"only safe while its zero value refuses, and ClaimUnknown is the zero value for "+
			"exactly this reason.", err)
	}
}
