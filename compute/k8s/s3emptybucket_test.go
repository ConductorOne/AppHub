// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/conductorone/apphub/compute/k8s"
)

// versionedStub serves one page of versions until a batch delete arrives, and an
// empty listing after it. Static answers cannot model this: a listing that never
// changes is what a store that ignores its deletes looks like.
type versionedStub struct {
	mu       sync.Mutex
	deleted  bool
	result   string
	requests []recordedRequest
}

const versionedPage = `<ListVersionsResult>` +
	`<Version><Key>a</Key><VersionId>v1</VersionId></Version>` +
	`<DeleteMarker><Key>b</Key><VersionId>v2</VersionId></DeleteMarker>` +
	`</ListVersionsResult>`

func (s *versionedStub) RoundTrip(req *http.Request) (*http.Response, error) {
	var raw []byte
	if req.Body != nil {
		var err error
		if raw, err = io.ReadAll(req.Body); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, recordedRequest{
		Method: req.Method, Path: req.URL.Path, Query: req.URL.RawQuery,
		Body: string(raw), Header: req.Header.Clone(),
	})
	body := "<ListVersionsResult></ListVersionsResult>"
	switch {
	case req.Method == http.MethodPost && req.URL.RawQuery == "delete=":
		body = s.result
		if body == "" {
			s.deleted = true
			body = "<DeleteResult></DeleteResult>"
		}
	case req.Method == http.MethodGet && !s.deleted:
		body = versionedPage
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/xml"}},
		Request:    req,
	}, nil
}

func newVersionedStore(t *testing.T, stub *versionedStub) *k8s.S3ObjectStore {
	t.Helper()
	store, err := k8s.NewS3ObjectStore("https://objects.invalid", testSigner(),
		k8s.S3Options{Transport: stub})
	if err != nil {
		t.Fatalf("NewS3ObjectStore: %v", err)
	}
	return store
}

// TestS3EmptyBucketDeletesVersionsAndDeleteMarkers pins the wire shape: a
// versions listing, then one batch delete naming every version and delete marker
// with the Content-MD5 the API requires, then a listing that ends the loop.
func TestS3EmptyBucketDeletesVersionsAndDeleteMarkers(t *testing.T) {
	t.Parallel()
	stub := &versionedStub{}
	if err := newVersionedStore(t, stub).EmptyBucket(context.Background(), "b1"); err != nil {
		t.Fatalf("EmptyBucket: %v", err)
	}
	if len(stub.requests) != 3 {
		t.Fatalf("EmptyBucket issued %d requests, want 3 (list, delete, list): %+v",
			len(stub.requests), stub.requests)
	}
	list, del := stub.requests[0], stub.requests[1]
	if list.Method != http.MethodGet || list.Query != "max-keys=1000&versions=" {
		t.Errorf("the listing was %s ?%s, want a GET of ?versions with max-keys=1000",
			list.Method, list.Query)
	}
	for _, want := range []string{
		"<Key>a</Key><VersionId>v1</VersionId>", "<Key>b</Key><VersionId>v2</VersionId>",
		"<Quiet>true</Quiet>",
	} {
		if !strings.Contains(del.Body, want) {
			t.Errorf("the batch delete body does not contain %s: %s", want, del.Body)
		}
	}
	sum := md5.Sum([]byte(del.Body))
	if got, want := del.Header.Get("Content-MD5"), base64.StdEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("Content-MD5 = %q, want %q; S3 refuses a batch delete without it", got, want)
	}
	if del.Header.Get("Authorization") == "" {
		t.Error("the batch delete was not signed")
	}
}

// TestS3EmptyBucketReadsTheRefusalsInA200 is the reason the body is parsed: a
// batch delete that refuses a key still answers 200.
func TestS3EmptyBucketReadsTheRefusalsInA200(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		code string
		want error
	}{
		{"SlowDown", k8s.ErrBackingTransient},
		{"AccessDenied", k8s.ErrObjectStoreDenied},
	} {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			stub := &versionedStub{result: "<DeleteResult><Error><Key>a</Key><VersionId>v1</VersionId>" +
				"<Code>" + tc.code + "</Code><Message>no</Message></Error></DeleteResult>"}
			err := newVersionedStore(t, stub).EmptyBucket(context.Background(), "b1")
			if !errors.Is(err, tc.want) {
				t.Errorf("a 200 carrying %s = %v, want %v", tc.code, err, tc.want)
			}
		})
	}
}

// TestS3EmptyBucketOnAnAbsentBucketIsNil: a 404 listing is a bucket already gone.
func TestS3EmptyBucketOnAnAbsentBucketIsNil(t *testing.T) {
	t.Parallel()
	if err := newS3Store(t, newStoreStub()).EmptyBucket(context.Background(), "gone"); err != nil {
		t.Errorf("EmptyBucket on an absent bucket = %v, want nil", err)
	}
}
