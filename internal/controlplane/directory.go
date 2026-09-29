// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"errors"
	"net/url"
	"time"
)

// The directory lets every signed-in member discover the workspace's
// applications without being able to read them. An ApplicationSummary is a
// deliberately separate type rather than a redacted ApplicationView: a field
// added to the full view does not appear here unless somebody adds it to this
// struct, so the default for anything new is "owners and admins only". It
// carries what the launcher needs to answer "what is this and who do I ask"
// and nothing from the specification, deployments, secrets or usage.

// ApplicationSummary is what any member may see about any application.
type ApplicationSummary struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Category string      `json:"category,omitempty"`
	Owners   []OwnerView `json:"owners"`
	Owned    bool        `json:"owned"`
	// Yours is ownership without the administrator override.
	Yours          bool       `json:"yours"`
	Status         string     `json:"status"`
	URL            string     `json:"url,omitempty"`
	URLScope       string     `json:"urlScope,omitempty"`
	Live           bool       `json:"live"`
	LastDeployedAt *time.Time `json:"lastDeployedAt,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
}

// ListDirectory returns every application in the workspace as a summary.
// Owned reports whether the caller may open the full application.
func (s *Service) ListDirectory(ctx context.Context, p Principal, options ListOptions) (Page[ApplicationSummary], error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return Page[ApplicationSummary]{}, err
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return Page[ApplicationSummary]{}, err
	}
	limit, err := listLimit(options)
	if err != nil {
		return Page[ApplicationSummary]{}, err
	}
	page, err := s.repo.Query(ctx, Query{Kind: ApplicationKind, Limit: limit, Cursor: options.Cursor})
	if err != nil {
		return Page[ApplicationSummary]{}, queryError(err)
	}
	names := ownerNames{}
	result := Page[ApplicationSummary]{Items: make([]ApplicationSummary, 0, len(page.Records)), Cursor: page.Cursor}
	for _, row := range page.Records {
		app, err := Decode[ApplicationRecord](row)
		if err != nil || app.ID != row.ID || len(app.Owners) == 0 {
			return Page[ApplicationSummary]{}, unavailable()
		}
		summary, err := s.summary(ctx, p, app, names)
		if err != nil {
			return Page[ApplicationSummary]{}, err
		}
		result.Items = append(result.Items, summary)
	}
	return result, nil
}

// GetDirectoryEntry returns one application's summary, for a member opening an
// application they do not own.
func (s *Service) GetDirectoryEntry(ctx context.Context, p Principal, id string) (ApplicationSummary, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return ApplicationSummary{}, err
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return ApplicationSummary{}, err
	}
	r, err := s.repo.Read(ctx, RecordID{Kind: ApplicationKind, ID: id})
	if errors.Is(err, ErrNotFound) {
		return ApplicationSummary{}, notFound()
	}
	if err != nil {
		return ApplicationSummary{}, unavailable()
	}
	app, err := Decode[ApplicationRecord](r)
	if err != nil || app.ID != id || len(app.Owners) == 0 {
		return ApplicationSummary{}, unavailable()
	}
	return s.summary(ctx, p, app, ownerNames{})
}

func (s *Service) summary(ctx context.Context, p Principal, app ApplicationRecord, names ownerNames) (ApplicationSummary, error) {
	status, lastDeployed, err := s.applicationStatus(ctx, app)
	if err != nil {
		return ApplicationSummary{}, err
	}
	published, scope := s.publishedURL(app)
	return ApplicationSummary{
		ID: app.ID, Name: app.Input.Name, Category: app.Input.Category,
		Owners: memberVisible(s.ownerViews(ctx, app.Owners, names)), Owned: owns(p, app), Yours: ownedDirectly(p, app.Owners),
		Status: status, URL: published, URLScope: scope, Live: live(app, published),
		LastDeployedAt: optionalTime(lastDeployed), CreatedAt: app.CreatedAt,
	}, nil
}

// live reports whether the published URL is one the provider reported after a
// successful deploy.
func live(app ApplicationRecord, published string) bool {
	want, err := url.Parse(published)
	if published == "" || err != nil {
		return false
	}
	addresses := app.Addresses
	if len(addresses) == 0 {
		addresses = app.LastSuccessfulArtifacts.Addresses
	}
	for _, address := range safeAddresses(addresses) {
		if u, err := url.Parse(address); err == nil && u.Host == want.Host {
			return true
		}
	}
	return false
}

// memberVisible drops what a summary must not show every member: an owner's
// email. Names are already what the directory shows.
func memberVisible(owners []OwnerView) []OwnerView {
	for i := range owners {
		owners[i].Email = ""
	}
	return owners
}
