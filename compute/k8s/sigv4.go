// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/conductorone/apphub/compute"
)

// Signer authenticates an outgoing request to an object store.
//
// It is an interface, and it is the one place in this package where the honest
// answer is "an operator may have to replace this". Every S3-compatible service
// surveyed accepts AWS Signature Version 4 ([SigV4Signer]), but "accepts SigV4"
// is a claim about a service, and the only way to find out whether a particular
// deployment of MinIO or Ceph agrees with this implementation of it is to send it
// a request. That cannot be done from a hermetic test. Isolating the signing into
// a named, swappable component means a site that disagrees replaces one type
// rather than forking the client.
//
// A Signer must not log, wrap, or otherwise emit the credential it holds.
type Signer interface {
	// Sign adds whatever authentication headers the store requires. payloadSHA256
	// is the lowercase hex SHA-256 of the request body, which SigV4 requires as
	// a header and therefore cannot be computed inside Sign without buffering the
	// body twice.
	Sign(req *http.Request, payloadSHA256 string) error
}

// SigV4Signer signs a request with AWS Signature Version 4.
//
// # What is verified about it, and what is not
//
// Verified, by [TestSigV4SignsDeterministicallyAndSensitively]: the signature is
// deterministic for identical inputs, it changes when any component the algorithm
// covers changes (method, path, query, body, timestamp, region, key), the
// Authorization header carries the credential scope and signed-header list in the
// documented form, and the secret never appears in any header or in an error.
//
// **Not verified: that a real object store accepts the result.** There is no
// reference implementation in this repository to compare against and no store to
// send a request to, so the arithmetic is checked for the properties a signing bug
// would break rather than against a known-good signature. This is the one surface
// on this branch where "the tests pass" carries the least weight, and it is
// deliberately the surface where being wrong is safest: a wrong signature is a 403
// on the first request, immediately and loudly, not a silent misbehaviour.
type SigV4Signer struct {
	// AccessKeyID is the access key identifier. It is not credential material —
	// it travels in the clear inside the Authorization header — so it is a plain
	// string.
	AccessKeyID string
	// SecretAccessKey is credential material and is therefore a
	// [compute.SecretValue], which redacts itself when formatted. A bare string
	// here would be one careless %v away from a log line.
	SecretAccessKey compute.SecretValue
	// Region is the signing region. S3-compatible stores that have no notion of
	// regions still require one in the scope; "us-east-1" is the near-universal
	// placeholder and an operator supplies whatever their store expects.
	Region string
	// Now returns the signing timestamp. Nil means [time.Now]. It is injectable
	// so a signature can be asserted on at all: SigV4 covers the timestamp, so a
	// signer reading the wall clock produces a different answer every call.
	Now func() time.Time
}

var _ Signer = (*SigV4Signer)(nil)

const (
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	sigV4Service   = "s3"
	// sigV4Terminator is the fixed final component of the credential scope.
	sigV4Terminator = "aws4_request"
)

// Sign implements [Signer].
func (s *SigV4Signer) Sign(req *http.Request, payloadSHA256 string) error {
	switch {
	case s.AccessKeyID == "":
		return errors.New("k8s: the object-store signer has no access key identifier")
	case compute.RevealSecret(s.SecretAccessKey) == "":
		return errors.New("k8s: the object-store signer has no secret access key")
	case s.Region == "":
		return errors.New("k8s: the object-store signer has no region; SigV4 requires one in " +
			"the credential scope even for a store with no regions")
	case payloadSHA256 == "":
		return errors.New("k8s: SigV4 requires the payload digest as a signed header")
	}

	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	stamp := now().UTC()
	amzDate := stamp.Format("20060102T150405Z")
	dateOnly := stamp.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadSHA256)
	if req.Host == "" {
		req.Host = req.URL.Host
	}

	// The signed header set is fixed rather than "every header present", so that
	// a header added elsewhere in the stack cannot invalidate a signature
	// computed here. Host is signed by name even though net/http carries it
	// outside Header.
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonicalHeaders := strings.Join([]string{
		"host:" + req.Host,
		"x-amz-content-sha256:" + payloadSHA256,
		"x-amz-date:" + amzDate,
	}, "\n") + "\n"

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalPath(req.URL.EscapedPath()),
		canonicalQuery(req),
		canonicalHeaders,
		strings.Join(signed, ";"),
		payloadSHA256,
	}, "\n")

	scope := strings.Join([]string{dateOnly, s.Region, sigV4Service, sigV4Terminator}, "/")
	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		amzDate,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	// The HMAC key for the first derivation step is literally "AWS4" followed by
	// the secret: SigV4 specifies it, and there is no formulation that avoids
	// materialising the material. The bytes are built with append rather than by
	// concatenating strings so that no second immutable copy is created, and the
	// slice dies with this function. Flagged by USOSS-43 during their secret-leak
	// audit as something a reviewer would reasonably stop on; it is inherent to
	// the algorithm rather than a defect.
	key := hmacSHA256(append([]byte("AWS4"), compute.RevealSecret(s.SecretAccessKey)...), dateOnly)
	key = hmacSHA256(key, s.Region)
	key = hmacSHA256(key, sigV4Service)
	key = hmacSHA256(key, sigV4Terminator)
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm, s.AccessKeyID, scope, strings.Join(signed, ";"), signature))
	return nil
}

// canonicalPath is the path component of a canonical request. An empty path is
// "/", and the path is already escaped by net/url.
func canonicalPath(escaped string) string {
	if escaped == "" {
		return "/"
	}
	return escaped
}

// canonicalQuery renders the query string in the canonical form: parameters
// sorted by name, each name and value URI-encoded, a value-less parameter
// rendered with an empty value.
//
// The value-less case is the one that matters here and the one an implementation
// gets wrong: every S3 sub-resource this client uses — "?tagging", "?policy",
// "?publicAccessBlock" — is a parameter with no value, so a signer that omitted
// the "=" would produce a signature that never matches for any of them.
func canonicalQuery(req *http.Request) string {
	values := req.URL.Query()
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		vals := append([]string(nil), values[name]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, uriEncode(name)+"="+uriEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

// uriEncode is SigV4's encoding: unreserved characters pass through, everything
// else becomes uppercase percent-encoding. It differs from url.QueryEscape,
// which encodes a space as "+" and leaves "~" alone — both of which produce a
// signature the server will not reproduce.
func uriEncode(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
