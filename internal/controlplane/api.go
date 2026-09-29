// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package controlplane owns authenticated application intent and durable deployment operations.
package controlplane

import (
	"context"
	"time"

	"github.com/conductorone/apphub/internal/detect"
)

// Error contains only service-authored safe text. Causes are never serialized.
type Error struct {
	Status      int               `json:"-"`
	Code        string            `json:"code"`
	Message     string            `json:"message"`
	FieldErrors map[string]string `json:"fieldErrors,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Problem constructs an error whose message is safe to return to a client.
func Problem(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// ErrorResponse associates a safe service error with its diagnostic request ID.
type ErrorResponse struct {
	Error     *Error `json:"error"`
	RequestID string `json:"requestId"`
}

// ApplicationView exposes authorized application state without provider credentials.
type ApplicationView struct {
	ID                         string           `json:"id"`
	Owners                     []OwnerView      `json:"owners"`
	Revision                   int64            `json:"revision"`
	Specification              ApplicationInput `json:"specification"`
	Status                     string           `json:"status"`
	ActiveDeploymentID         string           `json:"activeDeploymentId,omitempty"`
	LatestDeploymentID         string           `json:"latestDeploymentId,omitempty"`
	LastSuccessfulDeploymentID string           `json:"lastSuccessfulDeploymentId,omitempty"`
	LastDeployedAt             *time.Time       `json:"lastDeployedAt,omitempty"`
	DeletionRequestedAt        *time.Time       `json:"deletionRequestedAt,omitempty"`
	// URL is where the application is published, derived from its route and
	// the target's domain, so it is known before the first deploy. Addresses
	// says whether it is live. Empty when the application has no route.
	URL              string    `json:"url,omitempty"`
	URLScope         string    `json:"urlScope,omitempty"`
	Addresses        []string  `json:"addresses"`
	PermittedActions []string  `json:"permittedActions"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

// SubmitDeploymentInput pins execution to the application revision the caller reviewed.
type SubmitDeploymentInput struct {
	ApplicationRevision int64 `json:"applicationRevision"`
}

// DeleteApplicationInput confirms a destructive deletion by the application's
// current name, so neither a stale page nor an agent acting on the wrong ID
// deletes something its caller did not name.
type DeleteApplicationInput struct {
	ConfirmName string `json:"confirmName"`
}

// DeploymentAccepted identifies an already-durable operation and its polling location.
type DeploymentAccepted struct {
	DeploymentID  string          `json:"deploymentId"`
	ApplicationID string          `json:"applicationId"`
	State         DeploymentState `json:"state"`
	StatusURL     string          `json:"statusUrl"`
	PollAfterMs   int             `json:"pollAfterMs"`
}

// DeploymentView exposes safe progress and partial-resource categories, not provider errors.
type DeploymentView struct {
	ID                  string          `json:"id"`
	ApplicationID       string          `json:"applicationId"`
	ApplicationRevision int64           `json:"applicationRevision"`
	TargetID            string          `json:"targetId"`
	Execution           string          `json:"execution"`
	RequestedSourceRef  string          `json:"requestedSourceRef"`
	ResolvedCommit      string          `json:"resolvedCommit,omitempty"`
	Operation           string          `json:"operation"`
	PlannedSteps        []string        `json:"plannedSteps"`
	Attempt             int             `json:"attempt"`
	State               DeploymentState `json:"state"`
	Terminal            bool            `json:"terminal"`
	Step                string          `json:"step,omitempty"`
	Progress            string          `json:"progress,omitempty"`
	ErrorCode           string          `json:"errorCode,omitempty"`
	Message             string          `json:"message"`
	PartialResources    []string        `json:"partialResources"`
	Addresses           []string        `json:"addresses"`
	PollAfterMs         int             `json:"pollAfterMs"`
	CreatedAt           time.Time       `json:"createdAt"`
	StartedAt           time.Time       `json:"startedAt,omitempty"`
	StepStartedAt       time.Time       `json:"stepStartedAt,omitzero"`
	FinishedAt          time.Time       `json:"finishedAt,omitempty"`
	ResolutionReason    string          `json:"resolutionReason,omitempty"`
}

// TargetView advertises the operator-approved choices and current readiness of a target.
type TargetView struct {
	ID             string          `json:"id"`
	Label          string          `json:"label"`
	Ready          bool            `json:"ready"`
	ExecutionModes []string        `json:"executionModes"`
	ResourceSizes  []ResourceInput `json:"resourceSizes"`
	MaxReplicas    int             `json:"maxReplicas"`
	PublicExposure bool            `json:"publicExposure"`
	// InternalExposure reports that private services get an address on the
	// internal ingress.
	InternalExposure bool `json:"internalExposure"`
	// Repositories is an optional extra allowlist. Empty means the Workspace
	// GitHub App installation is the allowlist.
	Repositories []string `json:"repositories"`
	// RepositorySuggestions are repositories synced from GitHub App
	// installations, offered on the deploy form when Repositories is empty.
	// They are not an allowlist: a pasted URL is still checked against the
	// installation's account. Omitted when the operator list is in effect.
	RepositorySuggestions []string `json:"repositorySuggestions,omitempty"`
	DatabaseKinds         []string `json:"databaseKinds"`
	BucketKinds           []string `json:"bucketKinds"`
}

// DetectionInput selects a repository and ref to scan. The URL must pass the
// same allowlist MapApplication enforces at create time (operator list, or a
// synced GitHub App installation when that list is empty). The target is a
// path parameter, not a body field, mirroring how SubmitDeploymentInput's
// application is named by the URL rather than repeated in the body.
type DetectionInput struct {
	URL string `json:"url"`
	Ref string `json:"ref"`
}

// DetectionAccepted identifies an already-durable advisory scan and its polling location.
type DetectionAccepted struct {
	DetectionID string         `json:"detectionId"`
	State       DetectionState `json:"state"`
	StatusURL   string         `json:"statusUrl"`
	PollAfterMs int            `json:"pollAfterMs"`
}

// DetectionView exposes an advisory scan's safe result, never provider
// credentials. Result is entirely derived from repository content this
// requester's target already approved fetching, so unlike DeploymentView it
// is safe to return in full rather than reduced to derived-safe fields.
type DetectionView struct {
	ID          string         `json:"id"`
	TargetID    string         `json:"targetId"`
	URL         string         `json:"url"`
	Ref         string         `json:"ref"`
	State       DetectionState `json:"state"`
	Terminal    bool           `json:"terminal"`
	Result      *detect.Result `json:"result,omitempty"`
	Message     string         `json:"message,omitempty"`
	PollAfterMs int            `json:"pollAfterMs"`
	CreatedAt   time.Time      `json:"createdAt"`
	FinishedAt  time.Time      `json:"finishedAt,omitempty"`
}

// ListOptions controls bounded pagination and the explicit administrator-wide view.
type ListOptions struct {
	Limit  int
	Cursor string
	All    bool
}

// ResolveInterruptedInput records the operator's stop confirmation and audit reason.
type ResolveInterruptedInput struct {
	WorkerStopped bool   `json:"workerStopped"`
	Reason        string `json:"reason"`
}

// Eligibility must reread the user's current record and the external identity
// that established the session/family, then enforce current operator policy.
type Eligibility interface {
	CheckPrincipal(ctx context.Context, principal Principal) (Principal, error)
	// ResolveRole computes email's current AppHub role and vulnerability-admin
	// authority from its held directory entitlements -- the same computation
	// CheckPrincipal applies to a signing-in identity, used by the
	// Workspace's Members roster to show a listed user's current effective
	// role without requiring them to sign back in. Unlike CheckPrincipal, it
	// never applies the legacy auth.admins override, which is keyed by
	// provider/subject rather than email: a legacy-admin identity may
	// therefore list here with a lower role than it actually resolves to at
	// sign-in.
	ResolveRole(ctx context.Context, email string) (role string, vulnAdmin bool)
}
