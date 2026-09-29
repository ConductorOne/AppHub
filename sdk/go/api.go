// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func objectPath(collection, id string) (string, error) {
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\?#%\x00\r\n") {
		return "", errors.New("invalid resource ID")
	}
	return "/api/v1/" + collection + "/" + url.PathEscape(id), nil
}

func pageQuery(limit *Limit, cursor *Cursor) string {
	q := url.Values{}
	if limit != nil {
		q.Set("limit", strconv.Itoa(*limit))
	}
	if cursor != nil && *cursor != "" {
		q.Set("cursor", *cursor)
	}
	return q.Encode()
}

func idempotencyHeaders(key string) (http.Header, error) {
	if strings.TrimSpace(key) == "" || len(key) > 256 || strings.ContainsFunc(key, unicode.IsControl) {
		return nil, errors.New("a nonempty idempotency key of at most 256 bytes without control characters is required")
	}
	return http.Header{"Idempotency-Key": {key}}, nil
}

// WhoAmI returns the current server-verified identity and effective permissions,
// not claims inferred from locally stored credentials.
func (c *Client) WhoAmI(ctx context.Context) (*UserView, error) {
	var result UserView
	err := c.Do(ctx, http.MethodGet, "/api/v1/users/me", nil, &result, nil)
	return &result, err
}

// ListTargets returns operator-approved deployment options without cloud credentials.
// The server requires applications:read.
func (c *Client) ListTargets(ctx context.Context) ([]TargetView, error) {
	var result []TargetView
	err := c.Do(ctx, http.MethodGet, "/api/v1/targets", nil, &result, nil)
	return result, err
}

// ListApplications returns a bounded page of caller-visible applications.
// Setting params.All requests organization-wide inventory only for admins.
func (c *Client) ListApplications(ctx context.Context, params ListApplicationsParams) (*ApplicationPage, error) {
	q, _ := url.ParseQuery(pageQuery(params.Limit, params.Cursor))
	if params.All != nil {
		q.Set("all", strconv.FormatBool(*params.All))
	}
	var result ApplicationPage
	err := c.Do(ctx, http.MethodGet, "/api/v1/applications?"+q.Encode(), nil, &result, nil)
	return &result, err
}

// GetApplication retrieves an owned application, or any application for an admin.
// Inaccessible IDs return the same server error as missing applications.
func (c *Client) GetApplication(ctx context.Context, id string) (*ApplicationView, error) {
	path, err := objectPath("applications", id)
	if err != nil {
		return nil, err
	}
	var result ApplicationView
	err = c.Do(ctx, http.MethodGet, path, nil, &result, nil)
	return &result, err
}

// CreateApplication creates a draft only; deploying is a separate operation.
func (c *Client) CreateApplication(ctx context.Context, input ApplicationInput, key string) (*ApplicationView, error) {
	headers, err := idempotencyHeaders(key)
	if err != nil {
		return nil, err
	}
	var result ApplicationView
	err = c.Do(ctx, http.MethodPost, "/api/v1/applications", input, &result, headers)
	return &result, err
}

// UpdateApplication replaces the editable specification only at the supplied
// revision. The server rejects active deployments and owner or target changes.
func (c *Client) UpdateApplication(ctx context.Context, id string, revision int64, input ApplicationInput) (*ApplicationView, error) {
	if revision < 1 {
		return nil, errors.New("revision must be positive")
	}
	path, err := objectPath("applications", id)
	if err != nil {
		return nil, err
	}
	var result ApplicationView
	err = c.Do(ctx, http.MethodPut, path, input, &result, http.Header{"If-Match": {fmt.Sprintf("\"%d\"", revision)}})
	return &result, err
}

// SubmitDeployment durably queues the requested application revision; acceptance
// is not deployment success. Retain key for identical retries after uncertainty.
func (c *Client) SubmitDeployment(ctx context.Context, applicationID string, input SubmitDeploymentInput, key string) (*DeploymentAccepted, error) {
	path, err := objectPath("applications", applicationID)
	if err != nil {
		return nil, err
	}
	headers, err := idempotencyHeaders(key)
	if err != nil {
		return nil, err
	}
	var result DeploymentAccepted
	err = c.Do(ctx, http.MethodPost, path+"/deployments", input, &result, headers)
	return &result, err
}

// DeleteApplication accepts deletion of an application and every resource it
// owns, destroying its data without a snapshot. It returns nil for a
// never-deployed application, which is deleted at once; otherwise it returns
// the queued teardown, which WaitDeployment observes until it reports
// not-found on success. Retry a failed teardown with a new key.
func (c *Client) DeleteApplication(ctx context.Context, applicationID string, input DeleteApplicationInput, key string) (*DeploymentAccepted, error) {
	path, err := objectPath("applications", applicationID)
	if err != nil {
		return nil, err
	}
	headers, err := idempotencyHeaders(key)
	if err != nil {
		return nil, err
	}
	var result DeploymentAccepted
	if err := c.Do(ctx, http.MethodPost, path+"/deletion", input, &result, headers); err != nil {
		return nil, err
	}
	if result.DeploymentId == (DeploymentAccepted{}).DeploymentId {
		return nil, nil
	}
	return &result, nil
}

// GetDeployment retrieves an authorized attempt's durable state and partial
// effects; an interrupted outcome does not imply rollback.
func (c *Client) GetDeployment(ctx context.Context, id string) (*DeploymentView, error) {
	path, err := objectPath("deployments", id)
	if err != nil {
		return nil, err
	}
	var result DeploymentView
	err = c.Do(ctx, http.MethodGet, path, nil, &result, nil)
	return &result, err
}

// ListDeployments returns a bounded history page for an application the caller
// owns or may administer, newest first, subject to deployments:read.
func (c *Client) ListDeployments(ctx context.Context, applicationID string, params ListDeploymentsParams) (*DeploymentPage, error) {
	path, err := objectPath("applications", applicationID)
	if err != nil {
		return nil, err
	}
	var result DeploymentPage
	err = c.Do(ctx, http.MethodGet, path+"/deployments?"+pageQuery(params.Limit, params.Cursor), nil, &result, nil)
	return &result, err
}

// ResolveInterruptedDeployment records an admin's acknowledgement that the old
// worker has stopped and releases the execution lock. It does not resume,
// roll back, or declare the deployment successful.
func (c *Client) ResolveInterruptedDeployment(ctx context.Context, id string, input ResolveInterruptedInput) (*DeploymentView, error) {
	path, err := objectPath("deployments", id)
	if err != nil {
		return nil, err
	}
	var result DeploymentView
	err = c.Do(ctx, http.MethodPost, path+"/resolve-interrupted", input, &result, nil)
	return &result, err
}

// ListSessions returns a bounded page of the caller's browser and delegated
// sessions using nonsecret display IDs.
func (c *Client) ListSessions(ctx context.Context, params ListSessionsParams) (*SessionPage, error) {
	var result SessionPage
	err := c.Do(ctx, http.MethodGet, "/api/v1/sessions?"+pageQuery(params.Limit, params.Cursor), nil, &result, nil)
	return &result, err
}

// RevokeSession revokes the caller's identified browser session or entire OAuth
// family on the server; it does not remove the local CLI credential record.
func (c *Client) RevokeSession(ctx context.Context, id string) error {
	path, err := objectPath("sessions", id)
	if err != nil {
		return err
	}
	return c.Do(ctx, http.MethodDelete, path, nil, nil, nil)
}

// DeploymentOutcomeError indicates that a durable attempt ended unsuccessfully.
// Interrupted does not imply rollback or that the old worker has stopped.
type DeploymentOutcomeError struct{ Deployment *DeploymentView }

func (e *DeploymentOutcomeError) Error() string {
	return fmt.Sprintf("deployment %s ended %s: %s", e.Deployment.Id, e.Deployment.State, e.Deployment.Message)
}

// WaitDeployment observes the operation, not the application's latest status.
// Canceling observation never cancels execution. The most recent snapshot is
// returned even on an observation error; callers retain the supplied durable ID.
func (c *Client) WaitDeployment(ctx context.Context, id string, progress func(DeploymentView)) (*DeploymentView, error) {
	var last *DeploymentView
	for {
		view, err := c.GetDeployment(ctx, id)
		if err != nil {
			return last, err
		}
		if view.Id.String() != id {
			return last, errors.New("deployment response identity mismatch")
		}
		last = view
		terminalState := view.State == "succeeded" || view.State == "failed" || view.State == "interrupted"
		if terminalState != view.Terminal || (!terminalState && view.State != "queued" && view.State != "running") {
			return last, errors.New("invalid deployment state/terminal response")
		}
		if progress != nil {
			progress(*view)
		}
		if view.Terminal {
			if view.State != "succeeded" {
				return view, &DeploymentOutcomeError{Deployment: view}
			}
			return view, nil
		}
		delay := time.Duration(view.PollAfterMs) * time.Millisecond
		if delay < time.Second || delay > 30*time.Second {
			delay = 2 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return last, ctx.Err()
		case <-timer.C:
		}
	}
}

// ListOwners returns an application's owners: users and directory groups, all
// with equal control.
func (c *Client) ListOwners(ctx context.Context, applicationID string) (*OwnerList, error) {
	path, err := objectPath("applications", applicationID)
	if err != nil {
		return nil, err
	}
	var result OwnerList
	err = c.Do(ctx, http.MethodGet, path+"/owners", nil, &result, nil)
	return &result, err
}

// AddOwner adds a user or directory group as an owner. Adding an existing
// owner changes nothing.
func (c *Client) AddOwner(ctx context.Context, applicationID string, input OwnerInput) (*OwnerList, error) {
	path, err := objectPath("applications", applicationID)
	if err != nil {
		return nil, err
	}
	var result OwnerList
	err = c.Do(ctx, http.MethodPost, path+"/owners", input, &result, nil)
	return &result, err
}

// RemoveOwner removes an owner by its kind:id key. The last owner cannot be
// removed.
func (c *Client) RemoveOwner(ctx context.Context, applicationID, ownerKey string) (*OwnerList, error) {
	path, err := objectPath("applications", applicationID)
	if err != nil {
		return nil, err
	}
	kind, id, ok := strings.Cut(ownerKey, ":")
	if !ok || id == "" || (kind != string(OwnerKindUser) && kind != string(OwnerKindGroup)) {
		return nil, errors.New("owner key must be user:<id> or group:<id>")
	}
	var result OwnerList
	err = c.Do(ctx, http.MethodDelete, path+"/owners/"+url.PathEscape(ownerKey), nil, &result, nil)
	return &result, err
}

// SearchPrincipals finds users and directory groups to add as owners.
func (c *Client) SearchPrincipals(ctx context.Context, query string) (*PrincipalSearchResult, error) {
	var result PrincipalSearchResult
	err := c.Do(ctx, http.MethodGet, "/api/v1/directory/principals?"+url.Values{"q": {query}}.Encode(), nil, &result, nil)
	return &result, err
}
