// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1directory_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials/c1directory"
)

func TestProvisionApplicationRejectsForeignOwnershipMarker(t *testing.T) {
	transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/apps" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"id":%q,"annotations":{"apphub.app_id":%q,"apphub.provisioner":"another-provisioner"}}]}`, provisionedC1AppID, provisionedAppHubID), request), nil
	}}

	err := newTestProvisioner(t, transport).ProvisionApplication(context.Background(), provisionedAppHubID, "Payments", "")
	if !errors.Is(err, c1directory.ErrProvisioningConflict) {
		t.Fatalf("ProvisionApplication error = %v, want ErrProvisioningConflict", err)
	}
	if requests := transport.apiRequests(); len(requests) != 1 {
		t.Fatalf("API requests = %d, want only ownership lookup: %#v", len(requests), requests)
	}
}

func TestProvisioningErrorsDoNotExposeUpstreamBodies(t *testing.T) {
	transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/apps" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		return jsonResponse(http.StatusBadRequest, `client_secret=must-not-escape`, request), nil
	}}

	err := newTestProvisioner(t, transport).ProvisionApplication(context.Background(), provisionedAppHubID, "Payments", "")
	if err == nil {
		t.Fatal("ProvisionApplication accepted failed C1 lookup")
	}
	if strings.Contains(err.Error(), "must-not-escape") || strings.Contains(err.Error(), "client_secret") {
		t.Fatalf("ProvisionApplication leaked upstream body: %v", err)
	}
}
