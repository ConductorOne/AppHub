// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package errhygiene

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// The doubles below are here rather than in each subject's test file because they
// carry no knowledge of any package under test -- they are a transport that fails
// and a transport that answers, both saying the sentinel everywhere they can. Four
// subjects need the same two, and four copies of a fixture drift the way four
// copies of anything else do.

// ErroringTransport returns a http.RoundTripper that fails with an error whose text
// carries the sentinel.
//
// This is the round-two blocker as a fixture rather than as a comment: a transport
// has already seen the authenticated request, so its error is the most direct way
// foreign text reaches a provider's return value.
func ErroringTransport(sentinel string) http.RoundTripper {
	return erroringTransport{sentinel: sentinel}
}

type erroringTransport struct{ sentinel string }

func (e erroringTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("dial tcp %s:443: connect: %s", e.sentinel, e.sentinel)
}

// RespondingTransport returns a http.RoundTripper that answers with a response
// whose status line, headers and body all carry the sentinel. A zero status means
// 500.
func RespondingTransport(sentinel string, status int) http.RoundTripper {
	return respondingTransport{sentinel: sentinel, status: status}
}

type respondingTransport struct {
	sentinel string
	status   int
}

func (r respondingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	status := r.status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, r.sentinel),
		Header: http.Header{
			"X-Upstream-Note": []string{r.sentinel},
			"Location":        []string{"https://" + r.sentinel + ".example.com/collect"},
		},
		Body: io.NopCloser(strings.NewReader(
			`{"data":{"id":"` + r.sentinel + `","type":"` + r.sentinel + `"},"errors":["` + r.sentinel + `"]}`)),
		Request: req,
	}, nil
}

// RSAKeyPEM returns a PEM-encoded RSA private key, generated once per process.
//
// Once matters twice: key generation is slow, and a fresh key per sentinel would
// make the two runs of a driver differ for a reason that is not the input.
func RSAKeyPEM() string { return rsaKey() }

var rsaKey = sync.OnceValue(func() string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("errhygiene: generating the shared test key: " + err.Error())
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
})
