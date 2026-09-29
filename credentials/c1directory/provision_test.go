// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1directory_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/c1directory"
)

var (
	provisionedC1AppID          = strings.Repeat("a", 27)
	provisionedResourceTypeID   = strings.Repeat("b", 27)
	provisionedResourceID       = strings.Repeat("c", 27)
	provisionedAccessID         = strings.Repeat("d", 27)
	provisionedAdminID          = strings.Repeat("e", 27)
	provisionedGoLinkID         = strings.Repeat("f", 27)
	provisionedExternalGoLinkID = strings.Repeat("g", 27)
)

const provisionedAppHubID = "apphub-application-42"

func newTestProvisioner(t *testing.T, transport *fakeTransport) c1directory.Provisioner {
	t.Helper()
	provisioner, err := c1directory.NewProvisioner(testConfig(), c1directory.Deps{
		Secrets:   &stubSecrets{secret: credentials.NewSecret("directory-client-secret")},
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	return provisioner
}

func recordedJSON(t *testing.T, request recordedRequest) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(request.Body), &payload); err != nil {
		t.Fatalf("request %s %s body %q: %v", request.Method, request.Path, request.Body, err)
	}
	return payload
}

func annotationValue(t *testing.T, payload map[string]any, key string) string {
	t.Helper()
	annotations, ok := payload["annotations"].(map[string]any)
	if !ok {
		t.Fatalf("annotations = %#v, want JSON object", payload["annotations"])
	}
	value, ok := annotations[key].(string)
	if !ok {
		t.Fatalf("annotations[%q] = %#v, want string", key, annotations[key])
	}
	return value
}

func TestProvisionApplicationCreatesAppResourceAndEntitlements(t *testing.T) {
	resourceTypesPath := "/api/v1/apps/" + provisionedC1AppID + "/resource_types"
	resourcesPath := resourceTypesPath + "/" + provisionedResourceTypeID + "/resources"
	entitlementsPath := "/api/v1/apps/" + provisionedC1AppID + "/entitlements"

	entitlementPosts := 0

	transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
		switch request.Method + " " + request.URL.Path {
		case http.MethodGet + " /api/v1/apps":
			return jsonResponse(http.StatusOK, `{"list":[]}`, request), nil
		case http.MethodPost + " /api/v1/apps":
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"app":{"id":%q}}`, provisionedC1AppID), request), nil
		case http.MethodGet + " " + resourceTypesPath:
			return jsonResponse(http.StatusOK, `{"list":[]}`, request), nil
		case http.MethodPost + " " + resourceTypesPath:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"appResourceType":{"id":%q}}`, provisionedResourceTypeID), request), nil
		case http.MethodGet + " " + resourcesPath:
			return jsonResponse(http.StatusOK, `{"list":[]}`, request), nil
		case http.MethodPost + " " + resourcesPath:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"appResource":{"id":%q}}`, provisionedResourceID), request), nil
		case http.MethodGet + " " + entitlementsPath:
			return jsonResponse(http.StatusOK, `{"list":[]}`, request), nil
		case http.MethodPost + " " + entitlementsPath:
			entitlementPosts++
			id := provisionedAccessID
			if entitlementPosts == 2 {
				id = provisionedAdminID
			}
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"appEntitlementView":{"appEntitlement":{"id":%q}}}`, id), request), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	}}

	err := newTestProvisioner(t, transport).ProvisionApplication(context.Background(), provisionedAppHubID, "Payments", "")
	if err != nil {
		t.Fatalf("ProvisionApplication: %v", err)
	}

	requests := transport.apiRequests()
	if len(requests) != 9 {
		t.Fatalf("API requests = %d, want 9: %#v", len(requests), requests)
	}
	if got, want := requests[0].Method+" "+requests[0].Path, http.MethodGet+" /api/v1/apps"; got != want {
		t.Fatalf("first request = %s, want %s", got, want)
	}
	if got, want := requests[1].Method+" "+requests[1].Path, http.MethodPost+" /api/v1/apps"; got != want {
		t.Fatalf("app create request = %s, want %s", got, want)
	}

	appCreate := recordedJSON(t, requests[1])
	if got := appCreate["displayName"]; got != "Payments" {
		t.Errorf("app displayName = %#v, want Payments", got)
	}
	if got := annotationValue(t, appCreate, "apphub.app_id"); got != provisionedAppHubID {
		t.Errorf("apphub.app_id = %q, want %q", got, provisionedAppHubID)
	}
	if got := annotationValue(t, appCreate, "apphub.provisioner"); got != "apphub" {
		t.Errorf("apphub.provisioner = %q, want apphub", got)
	}
	annotations, ok := appCreate["annotations"].(map[string]any)
	if !ok {
		t.Fatalf("app annotations = %#v, want object", appCreate["annotations"])
	}
	if _, exists := annotations["apphub.public_url"]; exists {
		t.Errorf("app create sent public URL metadata for an empty URL: %#v", annotations)
	}

	resourceTypeCreate := recordedJSON(t, requests[3])
	if got := resourceTypeCreate["appId"]; got != provisionedC1AppID {
		t.Errorf("resource type appId = %#v, want %q", got, provisionedC1AppID)
	}
	if got := resourceTypeCreate["resourceType"]; got != "CUSTOM" {
		t.Errorf("resource type = %#v, want CUSTOM", got)
	}
	if got := resourceTypeCreate["displayName"]; got != "AppHub Application" {
		t.Errorf("resource type displayName = %#v, want AppHub Application", got)
	}

	resourceCreate := recordedJSON(t, requests[5])
	if got := resourceCreate["appResourceTypeId"]; got != provisionedResourceTypeID {
		t.Errorf("resource appResourceTypeId = %#v, want %q", got, provisionedResourceTypeID)
	}
	if got := annotationValue(t, resourceCreate, "apphub.kind"); got != "application" {
		t.Errorf("resource apphub.kind = %q, want application", got)
	}

	createdRoles := map[string]bool{}
	for _, request := range requests[7:] {
		payload := recordedJSON(t, request)
		name, _ := payload["displayName"].(string)
		createdRoles[name] = true
		if got := payload["purpose"]; got != "APP_ENTITLEMENT_PURPOSE_VALUE_ASSIGNMENT" {
			t.Errorf("%s purpose = %#v, want assignment", name, got)
		}
		if got := annotationValue(t, payload, "apphub.app_id"); got != provisionedAppHubID {
			t.Errorf("%s apphub.app_id = %q, want %q", name, got, provisionedAppHubID)
		}
	}
	if !createdRoles["Access"] || !createdRoles["Admin"] || len(createdRoles) != 2 {
		t.Errorf("created entitlement roles = %#v, want Access and Admin", createdRoles)
	}
}

func TestDeleteApplicationRemovesOnlyOwnedC1App(t *testing.T) {
	transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
		switch request.Method + " " + request.URL.Path {
		case http.MethodGet + " /api/v1/apps":
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"id":%q,"annotations":{"apphub.provisioner":"apphub","apphub.app_id":%q}},{"id":%q,"annotations":{"apphub.provisioner":"apphub","apphub.app_id":"another-app"}}]}`, provisionedC1AppID, provisionedAppHubID, provisionedExternalGoLinkID), request), nil
		case http.MethodDelete + " /api/v1/apps/" + provisionedC1AppID:
			return jsonResponse(http.StatusOK, `{}`, request), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	}}
	if err := newTestProvisioner(t, transport).DeleteApplication(context.Background(), provisionedAppHubID); err != nil {
		t.Fatal(err)
	}
	requests := transport.apiRequests()
	if len(requests) != 2 || requests[1].Method != http.MethodDelete || requests[1].Path != "/api/v1/apps/"+provisionedC1AppID {
		t.Fatalf("C1 requests = %#v, want lookup and deletion of owned app", requests)
	}
}

func TestDeleteApplicationIsIdempotentAndRejectsConflictingOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, list string
		wantErr    error
	}{
		{"absent", `{"list":[]}`, nil},
		{"foreign marker", fmt.Sprintf(`{"list":[{"id":%q,"annotations":{"apphub.app_id":%q}}]}`, provisionedC1AppID, provisionedAppHubID), c1directory.ErrProvisioningConflict},
		{"duplicate", fmt.Sprintf(`{"list":[{"id":%q,"annotations":{"apphub.provisioner":"apphub","apphub.app_id":%q}},{"id":%q,"annotations":{"apphub.provisioner":"apphub","apphub.app_id":%q}}]}`, provisionedC1AppID, provisionedAppHubID, provisionedExternalGoLinkID, provisionedAppHubID), c1directory.ErrProvisioningConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
				if request.Method != http.MethodGet {
					t.Fatalf("unexpected mutation %s %s", request.Method, request.URL.Path)
				}
				return jsonResponse(http.StatusOK, tc.list, request), nil
			}}
			err := newTestProvisioner(t, transport).DeleteApplication(context.Background(), provisionedAppHubID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DeleteApplication error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDeleteApplicationAcceptsNotFoundAndReportsSafeFailure(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet {
					return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"id":%q,"annotations":{"apphub.provisioner":"apphub","apphub.app_id":%q}}]}`, provisionedC1AppID, provisionedAppHubID), request), nil
				}
				return jsonResponse(status, `{"secret":"must not escape"}`, request), nil
			}}
			err := newTestProvisioner(t, transport).DeleteApplication(context.Background(), provisionedAppHubID)
			if status == http.StatusNotFound && err != nil {
				t.Fatalf("already deleted C1 app: %v", err)
			}
			if status == http.StatusForbidden && (!errors.Is(err, c1directory.ErrUnauthenticated) || strings.Contains(err.Error(), "must not escape")) {
				t.Fatalf("unsafe or missing forbidden error: %v", err)
			}
		})
	}
}

func TestProvisionApplicationReconcilesOwnedAppWithoutDuplicateObjects(t *testing.T) {
	resourceTypesPath := "/api/v1/apps/" + provisionedC1AppID + "/resource_types"
	resourcesPath := resourceTypesPath + "/" + provisionedResourceTypeID + "/resources"
	entitlementsPath := "/api/v1/apps/" + provisionedC1AppID + "/entitlements"

	transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
		switch request.Method + " " + request.URL.Path {
		case http.MethodGet + " /api/v1/apps":
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"id":%q,"displayName":"Old Payments","annotations":{"apphub.provisioner":"apphub","apphub.app_id":%q,"apphub.public_url":"https://old.example.com","operator.note":"keep"}}]}`, provisionedC1AppID, provisionedAppHubID), request), nil
		case http.MethodPost + " /api/v1/apps/" + provisionedC1AppID:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"app":{"id":%q}}`, provisionedC1AppID), request), nil
		case http.MethodGet + " " + resourceTypesPath:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"appResourceType":{"id":%q,"displayName":"AppHub Application"}}]}`, provisionedResourceTypeID), request), nil
		case http.MethodGet + " " + resourcesPath:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"appResource":{"id":%q,"appId":%q,"appResourceTypeId":%q,"annotations":{"apphub.provisioner":"apphub","apphub.app_id":%q,"apphub.kind":"application"}}}]}`, provisionedResourceID, provisionedC1AppID, provisionedResourceTypeID, provisionedAppHubID), request), nil
		case http.MethodGet + " " + entitlementsPath:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"appEntitlement":{"id":%q,"appId":%q,"appResourceTypeId":%q,"appResourceId":%q,"displayName":"Access","description":"General access to this AppHub application.","slug":"access","purpose":"APP_ENTITLEMENT_PURPOSE_VALUE_ASSIGNMENT","annotations":{"apphub.provisioner":"apphub","apphub.app_id":%q,"apphub.role":"access"}}},{"appEntitlement":{"id":%q,"appId":%q,"appResourceTypeId":%q,"appResourceId":%q,"displayName":"Admin","description":"Administrative access to this AppHub application.","slug":"admin","purpose":"APP_ENTITLEMENT_PURPOSE_VALUE_ASSIGNMENT","annotations":{"apphub.provisioner":"apphub","apphub.app_id":%q,"apphub.role":"admin"}}}]}`, provisionedAccessID, provisionedC1AppID, provisionedResourceTypeID, provisionedResourceID, provisionedAppHubID, provisionedAdminID, provisionedC1AppID, provisionedResourceTypeID, provisionedResourceID, provisionedAppHubID), request), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	}}

	err := newTestProvisioner(t, transport).ProvisionApplication(context.Background(), provisionedAppHubID, "Payments", "https://payments.example.com")
	if err != nil {
		t.Fatalf("ProvisionApplication: %v", err)
	}

	requests := transport.apiRequests()
	if len(requests) != 5 {
		t.Fatalf("API requests = %d, want only app update plus four reads: %#v", len(requests), requests)
	}
	update := recordedJSON(t, requests[1])
	if got := update["updateMask"]; got != "displayName,annotations" {
		t.Errorf("app updateMask = %#v, want displayName,annotations", got)
	}
	app, ok := update["app"].(map[string]any)
	if !ok {
		t.Fatalf("updated app = %#v, want object", update["app"])
	}
	if got := app["displayName"]; got != "Payments" {
		t.Errorf("updated app displayName = %#v, want Payments", got)
	}
	if got := annotationValue(t, app, "apphub.public_url"); got != "https://payments.example.com" {
		t.Errorf("updated public URL = %q, want current URL", got)
	}
	if got := annotationValue(t, app, "operator.note"); got != "keep" {
		t.Errorf("updated annotations lost operator.note = %q, want keep", got)
	}
}

func TestProvisionApplicationForbiddenNamesStatusPathAndStage(t *testing.T) {
	transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusForbidden, `{"error":"insufficient_scope"}`, request), nil
	}}

	provisioner := newTestProvisioner(t, transport)
	err := provisioner.ProvisionApplication(context.Background(), provisionedAppHubID, "Payments", "")
	if !errors.Is(err, c1directory.ErrUnauthenticated) {
		t.Fatalf("error = %v, want ErrUnauthenticated", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %v, want the status code named", err)
	}
	if !strings.Contains(err.Error(), "/api/v1/apps") {
		t.Fatalf("error = %v, want the request path named", err)
	}
	if !strings.Contains(err.Error(), "list applications") {
		t.Fatalf("error = %v, want the failing stage named", err)
	}
	if strings.Contains(err.Error(), "insufficient_scope") {
		t.Fatalf("error leaked the upstream response body: %v", err)
	}
}

func TestProvisionGoLinkRenamesOwnedLinkAndUpdatesTarget(t *testing.T) {
	marker := "Managed by AppHub for application " + provisionedAppHubID + "."
	transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
		switch request.Method + " " + request.URL.Path {
		case http.MethodGet + " /api/v1/golinks":
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"golink":{"id":%q,"displayName":"old-payments","description":%q,"target":{"redirect":{"urlTemplate":"https://old.example.com"}},"routes":[{"routeTemplate":"old-payments","isCanonical":true}]}}]}`, provisionedGoLinkID, marker), request), nil
		case http.MethodPatch + " /api/v1/golinks/" + provisionedGoLinkID:
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"golink":{"id":%q}}`, provisionedGoLinkID), request), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	}}

	err := newTestProvisioner(t, transport).ProvisionGoLink(context.Background(), provisionedAppHubID, "payments", "https://payments.example.com")
	if err != nil {
		t.Fatalf("ProvisionGoLink: %v", err)
	}

	requests := transport.apiRequests()
	if len(requests) != 2 {
		t.Fatalf("API requests = %d, want list and update: %#v", len(requests), requests)
	}
	update := recordedJSON(t, requests[1])
	if got := update["updateMask"]; got != "displayName,target,routes" {
		t.Errorf("GoLink updateMask = %#v, want displayName,target,routes", got)
	}
	link, ok := update["golink"].(map[string]any)
	if !ok {
		t.Fatalf("golink update = %#v, want object", update["golink"])
	}
	if got := link["displayName"]; got != "payments" {
		t.Errorf("GoLink displayName = %#v, want payments", got)
	}
	target, ok := link["target"].(map[string]any)
	if !ok {
		t.Fatalf("GoLink target = %#v, want object", link["target"])
	}
	redirect, ok := target["redirect"].(map[string]any)
	if !ok || redirect["urlTemplate"] != "https://payments.example.com" {
		t.Errorf("GoLink redirect = %#v, want supplied HTTPS target", target["redirect"])
	}
	routes, ok := link["routes"].([]any)
	if !ok || len(routes) != 1 {
		t.Fatalf("GoLink routes = %#v, want one canonical route", link["routes"])
	}
	route, ok := routes[0].(map[string]any)
	if !ok || route["routeTemplate"] != "payments" || route["isCanonical"] != true {
		t.Errorf("GoLink route = %#v, want canonical payments route", routes[0])
	}
}

func TestProvisionGoLinkRecoversAcceptedCreateWithoutRetryingIt(t *testing.T) {
	marker := "Managed by AppHub for application " + provisionedAppHubID + "."
	listCalls := 0
	transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
		switch request.Method + " " + request.URL.Path {
		case http.MethodGet + " /api/v1/golinks":
			listCalls++
			if listCalls == 1 {
				return jsonResponse(http.StatusOK, `{"list":[]}`, request), nil
			}
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"golink":{"id":%q,"displayName":"payments","description":%q,"target":{"redirect":{"urlTemplate":"https://payments.example.com"}},"routes":[{"routeTemplate":"payments","isCanonical":true}]}}]}`, provisionedGoLinkID, marker), request), nil
		case http.MethodPost + " /api/v1/golinks":
			return jsonResponse(http.StatusServiceUnavailable, `upstream body must not escape`, request), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	}}

	err := newTestProvisioner(t, transport).ProvisionGoLink(context.Background(), provisionedAppHubID, "payments", "https://payments.example.com")
	if err != nil {
		t.Fatalf("ProvisionGoLink: %v", err)
	}
	requests := transport.apiRequests()
	if len(requests) != 3 {
		t.Fatalf("API requests = %d, want list, create, recovery list: %#v", len(requests), requests)
	}
	if got := requests[0].Method + " " + requests[0].Path; got != http.MethodGet+" /api/v1/golinks" {
		t.Errorf("first request = %s, want GoLink list", got)
	}
	if got := requests[1].Method + " " + requests[1].Path; got != http.MethodPost+" /api/v1/golinks" {
		t.Errorf("second request = %s, want exactly one GoLink create", got)
	}
	create := recordedJSON(t, requests[1])
	if got := create["description"]; got != marker {
		t.Errorf("GoLink ownership marker = %#v, want %q", got, marker)
	}
	if got := create["displayName"]; got != "payments" {
		t.Errorf("GoLink create displayName = %#v, want payments", got)
	}
	if got := requests[2].Method + " " + requests[2].Path; got != http.MethodGet+" /api/v1/golinks" {
		t.Errorf("third request = %s, want recovery list", got)
	}
}

func TestProvisionGoLinkRejectsForeignAliasAndInvalidInput(t *testing.T) {
	t.Run("foreign alias", func(t *testing.T) {
		transport := &fakeTransport{api: func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet || request.URL.Path != "/api/v1/golinks" {
				t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			}
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"list":[{"golink":{"id":%q,"description":"another owner","routes":[{"routeTemplate":"/PAYMENTS/","isCanonical":true}]}}]}`, provisionedExternalGoLinkID), request), nil
		}}
		err := newTestProvisioner(t, transport).ProvisionGoLink(context.Background(), provisionedAppHubID, "payments", "https://payments.example.com")
		if !errors.Is(err, c1directory.ErrGoLinkAliasCollision) {
			t.Fatalf("ProvisionGoLink error = %v, want ErrGoLinkAliasCollision", err)
		}
		if requests := transport.apiRequests(); len(requests) != 1 {
			t.Fatalf("API requests = %d, want list only: %#v", len(requests), requests)
		}
	})

	t.Run("spaced alias", func(t *testing.T) {
		transport := &fakeTransport{}
		err := newTestProvisioner(t, transport).ProvisionGoLink(context.Background(), provisionedAppHubID, "Payments App", "https://payments.example.com")
		if !errors.Is(err, c1directory.ErrGoLinkAliasInvalid) {
			t.Fatalf("ProvisionGoLink error = %v, want ErrGoLinkAliasInvalid", err)
		}
		if requests := transport.apiRequests(); len(requests) != 0 {
			t.Fatalf("API requests = %#v, want none for invalid alias", requests)
		}
		if calls := transport.tokenRequests(); calls != 0 {
			t.Fatalf("token requests = %d, want none for invalid alias", calls)
		}
	})

	t.Run("non-HTTPS target", func(t *testing.T) {
		transport := &fakeTransport{}
		err := newTestProvisioner(t, transport).ProvisionGoLink(context.Background(), provisionedAppHubID, "payments", "http://payments.example.com")
		if !errors.Is(err, c1directory.ErrGoLinkURLInvalid) {
			t.Fatalf("ProvisionGoLink error = %v, want ErrGoLinkURLInvalid", err)
		}
		if requests := transport.apiRequests(); len(requests) != 0 {
			t.Fatalf("API requests = %#v, want none for invalid target", requests)
		}
	})
}
