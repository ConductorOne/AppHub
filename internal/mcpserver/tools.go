// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	cp "github.com/conductorone/apphub/internal/controlplane"
	sdk "github.com/conductorone/apphub/sdk/go"
)

// Only transport metadata is defined here. Application and deployment payloads
// are the service DTOs also described by OpenAPI; there is no second spec model.
type emptyInput struct{}
type listInput struct {
	Limit  int    `json:"limit,omitempty" jsonschema:"Page size, at most 100"`
	Cursor string `json:"cursor,omitempty" jsonschema:"Opaque cursor returned by the previous page"`
	All    bool   `json:"all,omitempty" jsonschema:"Admin-only organization inventory"`
}
type applicationIDInput struct {
	ApplicationID string `json:"applicationId"`
}
type deploymentIDInput struct {
	DeploymentID string `json:"deploymentId"`
}
type createInput struct {
	Application    cp.ApplicationInput `json:"application"`
	IdempotencyKey string              `json:"idempotencyKey" jsonschema:"Retain and reuse this key when retrying the same draft creation"`
}
type updateInput struct {
	ApplicationID string              `json:"applicationId"`
	Application   cp.ApplicationInput `json:"application"`
	Revision      int64               `json:"revision" jsonschema:"Exact current revision; conflicts require reloading, not overwriting"`
}
type submitInput struct {
	ApplicationID  string                   `json:"applicationId"`
	Deployment     cp.SubmitDeploymentInput `json:"deployment"`
	IdempotencyKey string                   `json:"idempotencyKey" jsonschema:"Retain and reuse this key when retrying the same deployment submission"`
}
type deleteInput struct {
	ApplicationID  string `json:"applicationId"`
	ConfirmName    string `json:"confirmName" jsonschema:"The application's exact current name. Confirm with the user before deleting; this destroys its database and bucket contents without a snapshot"`
	IdempotencyKey string `json:"idempotencyKey" jsonschema:"Retain and reuse this key when retrying the same deletion request; use a new key to retry a failed teardown"`
}

// deleteOutput reports either an immediate deletion or the teardown to observe.
type deleteOutput struct {
	Deleted  bool                   `json:"deleted" jsonschema:"true when the application had never been deployed and is already gone"`
	Teardown *cp.DeploymentAccepted `json:"teardown,omitempty" jsonschema:"The queued teardown; observe it with deployments_get until terminal or not found"`
}

type ownerAddInput struct {
	ApplicationID string        `json:"applicationId"`
	Owner         cp.OwnerInput `json:"owner" jsonschema:"A user or group from principals_search: kind user or group, and its id"`
}
type ownerRemoveInput struct {
	ApplicationID string `json:"applicationId"`
	OwnerKey      string `json:"ownerKey" jsonschema:"The owner's key from owners_list, kind:id"`
}
type principalSearchInput struct {
	Query string `json:"query,omitempty" jsonschema:"Case-insensitive part of a name, email or group name"`
}

type usageInput struct {
	ApplicationID string `json:"applicationId"`
	Range         string `json:"range,omitempty" jsonschema:"24h, 7d (default) or 30d"`
}
type secretsDeployInput struct {
	ApplicationID  string                `json:"applicationId"`
	Changes        cp.SecretChangesInput `json:"changes"`
	IdempotencyKey string                `json:"idempotencyKey" jsonschema:"Retain and reuse this key when retrying the same secret changes"`
}
type historyInput struct {
	ApplicationID string `json:"applicationId"`
	Limit         int    `json:"limit,omitempty"`
	Cursor        string `json:"cursor,omitempty"`
}

type backend interface {
	targets(context.Context) ([]cp.TargetView, error)
	categories(context.Context) ([]cp.CategoryView, error)
	applications(context.Context, listInput) (cp.Page[cp.ApplicationView], error)
	application(context.Context, applicationIDInput) (cp.ApplicationView, error)
	create(context.Context, createInput) (cp.ApplicationView, error)
	update(context.Context, updateInput) (cp.ApplicationView, error)
	submit(context.Context, submitInput) (cp.DeploymentAccepted, error)
	remove(context.Context, deleteInput) (deleteOutput, error)
	owners(context.Context, applicationIDInput) (cp.OwnerList, error)
	addOwner(context.Context, ownerAddInput) (cp.OwnerList, error)
	removeOwner(context.Context, ownerRemoveInput) (cp.OwnerList, error)
	searchPrincipals(context.Context, principalSearchInput) (cp.PrincipalSearchResult, error)
	secrets(context.Context, applicationIDInput) (cp.SecretList, error)
	usage(context.Context, usageInput) (cp.UsageView, error)
	directory(context.Context, listInput) (cp.Page[cp.ApplicationSummary], error)
	deploySecrets(context.Context, secretsDeployInput) (cp.DeploymentAccepted, error)
	deployment(context.Context, deploymentIDInput) (cp.DeploymentView, error)
	history(context.Context, historyInput) (cp.Page[cp.DeploymentView], error)
}

func newServer(b backend) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "apphub", Title: "AppHub", Version: "1.0.0"}, &mcp.ServerOptions{
		PageSize:     50,
		Instructions: "AppHub deploys approved source repositories to organization-managed targets. Read deployment options before creating an application. Creation makes a draft only; submit its exact revision using a separate stable idempotency key. An accepted deployment is queued, not ready. Observe deployments_get until terminal. A scheduled success means the schedule was installed, not that a job ran. Interrupted deployments require operator resolution; never claim automatic retry or rollback. Every application address, public or private, is behind the platform sign-in, and the application receives the user as X-Auth-Request-User and X-Auth-Request-Email. For an application that serves MCP, public exposure may set mcpAuthEnabled to authenticate /mcp with AppHub OAuth instead, so MCP clients can connect with a bearer token; every other path stays behind the platform sign-in.",
	})
	addTool(server, "targets_list", "Read safe target readiness, repository, sizing and deployment options.", true, false, func(ctx context.Context, _ emptyInput) ([]cp.TargetView, error) { return b.targets(ctx) })
	addTool(server, "categories_list", "Read the application categories; an application's optional category must be one of these keys.", true, false, func(ctx context.Context, _ emptyInput) ([]cp.CategoryView, error) { return b.categories(ctx) })
	addTool(server, "applications_list", "List caller-visible applications with bounded pagination; all requires admin authority.", true, false, b.applications)
	addTool(server, "applications_get", "Read an owned or admin-visible application, current revision and deployment pointers.", true, false, b.application)
	addTool(server, "applications_create", "Create an application draft without cloud effects. Requires a retained idempotency key; deployment is a separate operation.", false, false, b.create)
	addTool(server, "applications_update", "Replace an application's editable specification using its exact revision. Target and ownership are immutable; active or unresolved deployments block edits.", false, true, b.update)
	addTool(server, "applications_delete", "Delete an application and every resource it owns: workload, database, key-value table, bucket and its objects, secrets, identity and images. Data is destroyed without a snapshot, so confirm with the user first. A never-deployed draft is deleted at once; otherwise a teardown is queued. Observe it with deployments_get; transient failures and lost workers are retried automatically, and once it succeeds the application and teardown return not found. If it fails, call again with a new idempotency key to retry; completed steps are skipped.", false, true, b.remove)
	addTool(server, "owners_list", "List an application's owners: users and directory groups, all with equal control.", true, false, b.owners)
	addTool(server, "owners_add", "Add a user or directory group as an owner. Every owner can edit, deploy, delete and change owners; a group makes everyone in it an owner. Confirm with the user who should be added. Refused while a deployment or deletion is active.", false, false, b.addOwner)
	addTool(server, "owners_remove", "Remove an owner by key. The last owner cannot be removed; removing the caller's own ownership ends their access unless a group or admin role still grants it.", false, true, b.removeOwner)
	addTool(server, "principals_search", "Find AppHub users and directory groups to add as owners.", true, false, b.searchPrincipals)
	addTool(server, "applications_directory", "Discover every application in the workspace: name, owner, category, status and URL. owned=false entries cannot be opened with applications_get; ask their owner.", true, false, b.directory)
	addTool(server, "applications_usage", "Read hourly ingress request counts, first and last request times for an application's public routes. tracked=false means private (never counted); collecting=false means collection is not configured.", true, false, b.usage)
	addTool(server, "secrets_list", "List an application's secret names. Values are never returned by any tool.", true, false, b.secrets)
	addTool(server, "secrets_deploy", "Set or delete secrets and deploy the exact current revision as one operation. Values are write-only and injected as environment variables. Acceptance is not readiness; observe deployments_get.", false, true, b.deploySecrets)
	addTool(server, "deployments_create", "Durably enqueue one deployment of the exact application revision. Acceptance is not readiness. Retain its ID and key and observe deployments_get.", false, true, b.submit)
	addTool(server, "deployments_get", "Observe durable deployment state, terminal outcome, safe progress, resolved commit and partial resources.", true, false, b.deployment)
	addTool(server, "deployments_list", "Read immutable attempt history for an owned or admin-visible application.", true, false, b.history)
	server.AddResource(&mcp.Resource{URI: deploymentOptionsURI, Name: "deployment-options", Title: "Deployment options", Description: "The same safe target options returned by targets_list; requires applications:read.", MIMEType: "application/json"}, func(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		targets, err := b.targets(ctx)
		if err != nil {
			return nil, toolError(err).Error
		}
		data, err := json.Marshal(targets)
		if err != nil {
			return nil, safeProblem(err)
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: deploymentOptionsURI, MIMEType: "application/json", Text: string(data)}}}, nil
	})
	return server
}

func addTool[In, Out any](server *mcp.Server, name, description string, readOnly, destructive bool, call func(context.Context, In) (Out, error)) {
	openWorld := true
	mcp.AddTool(server, &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly, DestructiveHint: &destructive, IdempotentHint: true, OpenWorldHint: &openWorld}}, func(ctx context.Context, _ *mcp.CallToolRequest, input In) (*mcp.CallToolResult, any, error) {
		output, err := call(ctx, input)
		if err != nil {
			return &mcp.CallToolResult{IsError: true}, toolError(err), nil
		}
		return nil, output, nil
	})
}

func toolError(err error) cp.ErrorResponse {
	// The remote service produces safe domain errors. The local SDK preserves the
	// API's structured envelope, including its correlation ID and field errors.
	var apiError *sdk.APIError
	if errors.As(err, &apiError) {
		data, marshalErr := json.Marshal(apiError.Response)
		var response cp.ErrorResponse
		if marshalErr == nil && json.Unmarshal(data, &response) == nil && response.Error != nil {
			return response
		}
	}
	var uncertain *sdk.UncertainError
	if errors.As(err, &uncertain) {
		return cp.ErrorResponse{Error: cp.Problem(503, "outcome_uncertain", "The mutation outcome is uncertain. Inspect the durable resource, or retry the identical request with its original idempotency key. Do not create a new key.")}
	}
	if errors.Is(err, sdk.ErrReauthenticationRequired) {
		return cp.ErrorResponse{Error: cp.Problem(401, "authentication_required", "Sign in with apphub login for this server before using local MCP.")}
	}
	return cp.ErrorResponse{Error: safeProblem(err)}
}
