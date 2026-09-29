// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	cp "github.com/conductorone/apphub/internal/controlplane"
	sdk "github.com/conductorone/apphub/sdk/go"
)

type serviceBackend struct{ service *cp.Service }

func (b serviceBackend) targets(ctx context.Context) ([]cp.TargetView, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsRead)
	if err != nil {
		return nil, err
	}
	return b.service.ListTargets(ctx, p)
}

func (b serviceBackend) categories(ctx context.Context) ([]cp.CategoryView, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsRead)
	if err != nil {
		return nil, err
	}
	return b.service.ListCategories(ctx, p)
}
func (b serviceBackend) applications(ctx context.Context, input listInput) (cp.Page[cp.ApplicationView], error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsRead)
	if err != nil {
		return cp.Page[cp.ApplicationView]{}, err
	}
	return b.service.ListApplications(ctx, p, cp.ListOptions{Limit: input.Limit, Cursor: input.Cursor, All: input.All})
}
func (b serviceBackend) application(ctx context.Context, input applicationIDInput) (cp.ApplicationView, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsRead)
	if err != nil {
		return cp.ApplicationView{}, err
	}
	return b.service.GetApplication(ctx, p, input.ApplicationID)
}
func (b serviceBackend) create(ctx context.Context, input createInput) (cp.ApplicationView, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsWrite)
	if err != nil {
		return cp.ApplicationView{}, err
	}
	return b.service.CreateApplication(ctx, p, input.Application, input.IdempotencyKey)
}
func (b serviceBackend) update(ctx context.Context, input updateInput) (cp.ApplicationView, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsWrite)
	if err != nil {
		return cp.ApplicationView{}, err
	}
	return b.service.UpdateApplication(ctx, p, input.ApplicationID, input.Application, input.Revision)
}
func (b serviceBackend) submit(ctx context.Context, input submitInput) (cp.DeploymentAccepted, error) {
	p, err := scopedPrincipal(ctx, cp.DeploymentsWrite)
	if err != nil {
		return cp.DeploymentAccepted{}, err
	}
	return b.service.SubmitDeployment(ctx, p, input.ApplicationID, input.Deployment, input.IdempotencyKey)
}
func (b serviceBackend) remove(ctx context.Context, input deleteInput) (deleteOutput, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsWrite)
	if err != nil {
		return deleteOutput{}, err
	}
	accepted, err := b.service.DeleteApplication(ctx, p, input.ApplicationID, cp.DeleteApplicationInput{ConfirmName: input.ConfirmName}, input.IdempotencyKey)
	if err != nil {
		return deleteOutput{}, err
	}
	return deleteOutput{Deleted: accepted == nil, Teardown: accepted}, nil
}
func (b serviceBackend) owners(ctx context.Context, input applicationIDInput) (cp.OwnerList, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsRead)
	if err != nil {
		return cp.OwnerList{}, err
	}
	return b.service.ListOwners(ctx, p, input.ApplicationID)
}
func (b serviceBackend) addOwner(ctx context.Context, input ownerAddInput) (cp.OwnerList, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsWrite)
	if err != nil {
		return cp.OwnerList{}, err
	}
	return b.service.AddOwner(ctx, p, input.ApplicationID, input.Owner)
}
func (b serviceBackend) removeOwner(ctx context.Context, input ownerRemoveInput) (cp.OwnerList, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsWrite)
	if err != nil {
		return cp.OwnerList{}, err
	}
	return b.service.RemoveOwner(ctx, p, input.ApplicationID, input.OwnerKey)
}
func (b serviceBackend) searchPrincipals(ctx context.Context, input principalSearchInput) (cp.PrincipalSearchResult, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsRead)
	if err != nil {
		return cp.PrincipalSearchResult{}, err
	}
	return b.service.SearchPrincipals(ctx, p, input.Query)
}
func (b serviceBackend) directory(ctx context.Context, input listInput) (cp.Page[cp.ApplicationSummary], error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsRead)
	if err != nil {
		return cp.Page[cp.ApplicationSummary]{}, err
	}
	return b.service.ListDirectory(ctx, p, cp.ListOptions{Limit: input.Limit, Cursor: input.Cursor})
}
func (b serviceBackend) usage(ctx context.Context, input usageInput) (cp.UsageView, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsRead)
	if err != nil {
		return cp.UsageView{}, err
	}
	return b.service.GetUsage(ctx, p, input.ApplicationID, input.Range)
}
func (b serviceBackend) secrets(ctx context.Context, input applicationIDInput) (cp.SecretList, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsRead)
	if err != nil {
		return cp.SecretList{}, err
	}
	return b.service.ListSecrets(ctx, p, input.ApplicationID)
}
func (b serviceBackend) deploySecrets(ctx context.Context, input secretsDeployInput) (cp.DeploymentAccepted, error) {
	p, err := scopedPrincipal(ctx, cp.ApplicationsWrite)
	if err != nil {
		return cp.DeploymentAccepted{}, err
	}
	return b.service.DeploySecretChanges(ctx, p, input.ApplicationID, input.Changes, input.IdempotencyKey)
}
func (b serviceBackend) deployment(ctx context.Context, input deploymentIDInput) (cp.DeploymentView, error) {
	p, err := scopedPrincipal(ctx, cp.DeploymentsRead)
	if err != nil {
		return cp.DeploymentView{}, err
	}
	return b.service.GetDeployment(ctx, p, input.DeploymentID)
}
func (b serviceBackend) history(ctx context.Context, input historyInput) (cp.Page[cp.DeploymentView], error) {
	p, err := scopedPrincipal(ctx, cp.DeploymentsRead)
	if err != nil {
		return cp.Page[cp.DeploymentView]{}, err
	}
	return b.service.ListDeployments(ctx, p, input.ApplicationID, cp.ListOptions{Limit: input.Limit, Cursor: input.Cursor})
}

type clientBackend struct{ client *sdk.Client }

func (b clientBackend) targets(ctx context.Context) ([]cp.TargetView, error) {
	var result []cp.TargetView
	err := b.client.Do(ctx, http.MethodGet, "/api/v1/targets", nil, &result, nil)
	return result, err
}
func (b clientBackend) categories(ctx context.Context) ([]cp.CategoryView, error) {
	var result []cp.CategoryView
	err := b.client.Do(ctx, http.MethodGet, "/api/v1/categories", nil, &result, nil)
	return result, err
}
func (b clientBackend) applications(ctx context.Context, input listInput) (cp.Page[cp.ApplicationView], error) {
	var result cp.Page[cp.ApplicationView]
	err := b.client.Do(ctx, http.MethodGet, "/api/v1/applications"+listQuery(input.Limit, input.Cursor, input.All), nil, &result, nil)
	return result, err
}
func (b clientBackend) application(ctx context.Context, input applicationIDInput) (cp.ApplicationView, error) {
	var result cp.ApplicationView
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return result, err
	}
	err = b.client.Do(ctx, http.MethodGet, path, nil, &result, nil)
	return result, err
}
func (b clientBackend) create(ctx context.Context, input createInput) (cp.ApplicationView, error) {
	var result cp.ApplicationView
	err := b.client.Do(ctx, http.MethodPost, "/api/v1/applications", input.Application, &result, http.Header{"Idempotency-Key": []string{input.IdempotencyKey}})
	return result, err
}
func (b clientBackend) update(ctx context.Context, input updateInput) (cp.ApplicationView, error) {
	var result cp.ApplicationView
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return result, err
	}
	err = b.client.Do(ctx, http.MethodPut, path, input.Application, &result, http.Header{"If-Match": []string{`"` + strconv.FormatInt(input.Revision, 10) + `"`}})
	return result, err
}
func (b clientBackend) submit(ctx context.Context, input submitInput) (cp.DeploymentAccepted, error) {
	var result cp.DeploymentAccepted
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return result, err
	}
	err = b.client.Do(ctx, http.MethodPost, path+"/deployments", input.Deployment, &result, http.Header{"Idempotency-Key": []string{input.IdempotencyKey}})
	return result, err
}
func (b clientBackend) remove(ctx context.Context, input deleteInput) (deleteOutput, error) {
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return deleteOutput{}, err
	}
	var accepted cp.DeploymentAccepted
	err = b.client.Do(ctx, http.MethodPost, path+"/deletion", cp.DeleteApplicationInput{ConfirmName: input.ConfirmName}, &accepted, http.Header{"Idempotency-Key": []string{input.IdempotencyKey}})
	if err != nil {
		return deleteOutput{}, err
	}
	if accepted.DeploymentID == "" {
		return deleteOutput{Deleted: true}, nil
	}
	return deleteOutput{Teardown: &accepted}, nil
}
func (b clientBackend) owners(ctx context.Context, input applicationIDInput) (cp.OwnerList, error) {
	var result cp.OwnerList
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return result, err
	}
	err = b.client.Do(ctx, http.MethodGet, path+"/owners", nil, &result, nil)
	return result, err
}
func (b clientBackend) addOwner(ctx context.Context, input ownerAddInput) (cp.OwnerList, error) {
	var result cp.OwnerList
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return result, err
	}
	err = b.client.Do(ctx, http.MethodPost, path+"/owners", input.Owner, &result, nil)
	return result, err
}
func (b clientBackend) removeOwner(ctx context.Context, input ownerRemoveInput) (cp.OwnerList, error) {
	var result cp.OwnerList
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return result, err
	}
	if _, ok := cp.ParseOwnerKey(input.OwnerKey); !ok {
		return result, cp.Problem(400, "invalid_owner", "The owner key must be user:<id> or group:<id>.")
	}
	err = b.client.Do(ctx, http.MethodDelete, path+"/owners/"+url.PathEscape(input.OwnerKey), nil, &result, nil)
	return result, err
}
func (b clientBackend) searchPrincipals(ctx context.Context, input principalSearchInput) (cp.PrincipalSearchResult, error) {
	var result cp.PrincipalSearchResult
	err := b.client.Do(ctx, http.MethodGet, "/api/v1/directory/principals?"+url.Values{"q": {input.Query}}.Encode(), nil, &result, nil)
	return result, err
}
func (b clientBackend) directory(ctx context.Context, input listInput) (cp.Page[cp.ApplicationSummary], error) {
	var result cp.Page[cp.ApplicationSummary]
	query := url.Values{}
	if input.Limit > 0 {
		query.Set("limit", strconv.Itoa(input.Limit))
	}
	if input.Cursor != "" {
		query.Set("cursor", input.Cursor)
	}
	path := "/api/v1/directory/applications"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	err := b.client.Do(ctx, http.MethodGet, path, nil, &result, nil)
	return result, err
}
func (b clientBackend) usage(ctx context.Context, input usageInput) (cp.UsageView, error) {
	var result cp.UsageView
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return result, err
	}
	query := ""
	if input.Range != "" {
		query = "?range=" + url.QueryEscape(input.Range)
	}
	err = b.client.Do(ctx, http.MethodGet, path+"/usage"+query, nil, &result, nil)
	return result, err
}
func (b clientBackend) secrets(ctx context.Context, input applicationIDInput) (cp.SecretList, error) {
	var result cp.SecretList
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return result, err
	}
	err = b.client.Do(ctx, http.MethodGet, path+"/secrets", nil, &result, nil)
	return result, err
}
func (b clientBackend) deploySecrets(ctx context.Context, input secretsDeployInput) (cp.DeploymentAccepted, error) {
	var result cp.DeploymentAccepted
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return result, err
	}
	err = b.client.Do(ctx, http.MethodPost, path+"/secrets/deployments", input.Changes, &result, http.Header{"Idempotency-Key": []string{input.IdempotencyKey}})
	return result, err
}
func (b clientBackend) deployment(ctx context.Context, input deploymentIDInput) (cp.DeploymentView, error) {
	var result cp.DeploymentView
	path, err := objectPath("deployments", input.DeploymentID)
	if err != nil {
		return result, err
	}
	err = b.client.Do(ctx, http.MethodGet, path, nil, &result, nil)
	return result, err
}
func (b clientBackend) history(ctx context.Context, input historyInput) (cp.Page[cp.DeploymentView], error) {
	var result cp.Page[cp.DeploymentView]
	path, err := objectPath("applications", input.ApplicationID)
	if err != nil {
		return result, err
	}
	err = b.client.Do(ctx, http.MethodGet, path+"/deployments"+listQuery(input.Limit, input.Cursor, false), nil, &result, nil)
	return result, err
}

func listQuery(limit int, cursor string, all bool) string {
	query := url.Values{}
	if limit != 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	if all {
		query.Set("all", "true")
	}
	if len(query) == 0 {
		return ""
	}
	return "?" + query.Encode()
}

func objectPath(kind, id string) (string, error) {
	// IDs are opaque single path segments, never paths supplied by a tool caller.
	// Forbid encoded separators too, rather than relying on proxy normalization.
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/%\\?#") || strings.ContainsFunc(id, func(r rune) bool { return r <= 32 || r == 127 }) {
		return "", cp.Problem(400, "invalid_id", "A valid resource ID is required.")
	}
	return "/api/v1/" + kind + "/" + url.PathEscape(id), nil
}
