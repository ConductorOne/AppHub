// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/testutil"
)

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	authenticated := request.Clone(request.Context())
	authenticated.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(authenticated)
}

func mcpSession(ctx context.Context, t *testing.T, p *portal, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "AppHub integration client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: p.origin + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token: token}}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func toolValue[T any](t *testing.T, result *mcp.CallToolResult) T {
	t.Helper()
	var output T
	if result == nil || result.IsError {
		t.Fatalf("MCP tool failed: %+v", result)
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("MCP structured output invalid: %v (%s)", err, data)
	}
	return output
}

func TestOfficialMCPClientAndBrowserObserveSameOperation(t *testing.T) {
	p := newPortal(t, false, testutil.NewRepository())
	browser, me := browserLogin(t, p)
	apiToken := authorizeToken(t, p, browser, me, p.origin+"/api", "applications:read deployments:read")
	requestJSON(t, &http.Client{}, "GET", p.origin+"/mcp", nil, http.Header{"Authorization": {"Bearer " + apiToken}}, 401, nil)
	mcpToken := authorizeToken(t, p, browser, me, p.origin+"/mcp", "applications:read applications:write deployments:read deployments:write")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session := mcpSession(ctx, t, p, mcpToken)
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "applications_create", Arguments: map[string]any{"application": applicationInput(), "idempotencyKey": cp.NewID()}})
	if err != nil {
		t.Fatal(err)
	}
	app := toolValue[cp.ApplicationView](t, result)
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "deployments_create", Arguments: map[string]any{"applicationId": app.ID, "deployment": cp.SubmitDeploymentInput{ApplicationRevision: app.Revision}, "idempotencyKey": cp.NewID()}})
	if err != nil {
		t.Fatal(err)
	}
	accepted := toolValue[cp.DeploymentAccepted](t, result)
	var operation cp.DeploymentView
	for {
		requestJSON(t, browser, "GET", p.origin+accepted.StatusURL, nil, nil, 200, &operation)
		if operation.Terminal {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("MCP-submitted worker operation did not settle")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if operation.State != cp.Succeeded {
		t.Fatalf("MCP-submitted operation failed: %+v", operation)
	}
	var visible cp.ApplicationView
	requestJSON(t, browser, "GET", p.origin+"/api/v1/applications/"+app.ID, nil, nil, 200, &visible)
	if visible.LastSuccessfulDeploymentID != accepted.DeploymentID {
		t.Fatal("browser and MCP disagree on durable operation")
	}
	readOnly := authorizeToken(t, p, browser, me, p.origin+"/mcp", "applications:read deployments:read")
	readSession := mcpSession(ctx, t, p, readOnly)
	denied, err := readSession.CallTool(ctx, &mcp.CallToolParams{Name: "applications_create", Arguments: map[string]any{"application": applicationInput(), "idempotencyKey": cp.NewID()}})
	if err != nil {
		t.Fatal(err)
	}
	if denied == nil || !denied.IsError {
		t.Fatal("read-only MCP token created an application")
	}
}
