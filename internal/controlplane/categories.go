// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"slices"
)

// CategoryView is one application category that groups apps on the portal
// launcher. Key is the stable value stored in ApplicationInput.Category.
type CategoryView struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// KnownCategories is the fixed set of categories an application may carry.
// An application with no category is listed as uncategorized.
var KnownCategories = []CategoryView{
	{Key: "customer-facing", Label: "Customer-facing", Description: "Anything a customer can reach from the public internet."},
	{Key: "internal-tools", Label: "Internal tools", Description: "Back-office apps for staff only."},
	{Key: "data-jobs", Label: "Data and jobs", Description: "Workers, pipelines, and scheduled jobs with no UI."},
	{Key: "developer-tools", Label: "Developer tools", Description: "Bots, CI helpers, and services engineers use to ship."},
	{Key: "ai-agents", Label: "AI and agents", Description: "LLM apps, agents, and MCP servers."},
	{Key: "security", Label: "Security and compliance", Description: "Access reviews, scanners, and audit tooling."},
	{Key: "observability", Label: "Monitoring and ops", Description: "Dashboards, alerting, and operational tooling."},
	{Key: "docs", Label: "Docs and content", Description: "Documentation, marketing pages, and static sites."},
}

// ListCategories returns every category an application may be assigned.
func (s *Service) ListCategories(ctx context.Context, p Principal) ([]CategoryView, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return nil, err
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return nil, err
	}
	return slices.Clone(KnownCategories), nil
}

// validateCategory accepts an empty category, a known one, or previous when
// it is unchanged -- so retiring a category never blocks unrelated edits.
// Deploy-time validation deliberately ignores Category for the same reason.
func validateCategory(category, previous string) error {
	if category == "" || category == previous {
		return nil
	}
	if slices.ContainsFunc(KnownCategories, func(c CategoryView) bool { return c.Key == category }) {
		return nil
	}
	return &Error{Status: 422, Code: "invalid_specification", Message: "Application specification is invalid.", FieldErrors: map[string]string{"category": "Choose one of the listed categories."}}
}
