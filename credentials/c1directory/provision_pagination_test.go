// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1directory_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func TestProvisionGoLinkFindsOwnedLinkOnLaterPage(t *testing.T) {
	marker := "Managed by AppHub for application " + provisionedAppHubID + "."
	listCalls := 0
	transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/golinks" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		if got := request.URL.Query().Get("page_size"); got != "100" {
			t.Fatalf("page_size = %q, want 100", got)
		}
		listCalls++
		switch listCalls {
		case 1:
			if token := request.URL.Query().Get("page_token"); token != "" {
				t.Fatalf("first page token = %q, want empty", token)
			}
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"golink":{"id":%q,"description":"another owner","routes":[{"routeTemplate":"unrelated","isCanonical":true}]}}],"nextPageToken":"next"}`, provisionedExternalGoLinkID), request), nil
		case 2:
			if token := request.URL.Query().Get("page_token"); token != "next" {
				t.Fatalf("second page token = %q, want next", token)
			}
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"golink":{"id":%q,"displayName":"payments","description":%q,"target":{"redirect":{"urlTemplate":"https://payments.example.com"}},"routes":[{"routeTemplate":"payments","isCanonical":true}]}}]}`, provisionedGoLinkID, marker), request), nil
		default:
			t.Fatalf("unexpected list request %d", listCalls)
			return nil, nil
		}
	}}

	err := newTestProvisioner(t, transport).ProvisionGoLink(context.Background(), provisionedAppHubID, "payments", "https://payments.example.com")
	if err != nil {
		t.Fatalf("ProvisionGoLink: %v", err)
	}
	if requests := transport.apiRequests(); len(requests) != 2 {
		t.Fatalf("API requests = %d, want two reads and no create: %#v", len(requests), requests)
	}
}
