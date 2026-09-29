// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/conductorone/apphub/internal/credhttp"
)

const (
	appsPath    = "/api/v1/apps"
	goLinksPath = "/api/v1/golinks"

	appHubProvisionerAnnotation     = "apphub.provisioner"
	appHubApplicationIDAnnotation   = "apphub.app_id"
	appHubPublicURLAnnotation       = "apphub.public_url"
	appHubObjectKindAnnotation      = "apphub.kind"
	appHubEntitlementRoleAnnotation = "apphub.role"
	appHubProvisioner               = "apphub"

	appHubApplicationResourceTypeName = "AppHub Application"
	appHubApplicationResourceName     = "Application"
	appHubApplicationResourceKind     = "application"

	appHubAccessEntitlementRole = "access"
	appHubAdminEntitlementRole  = "admin"
)

var (
	annotationValuePattern = regexp.MustCompile(`^[A-Za-z0-9 ._:/?&=+%#~@!*'(),;\[\]\-]{1,256}$`)
	goLinkAliasPattern     = regexp.MustCompile(`^[a-z0-9._/-]+$`)
	c1IDPattern            = regexp.MustCompile(`^[A-Za-z0-9]{27}$`)

	// ErrApplicationIdentityInvalid means the AppHub application ID cannot be
	// safely stored in C1's annotations bag.
	ErrApplicationIdentityInvalid = errors.New("c1directory: application identity is invalid for C1 provisioning")
	// ErrApplicationNameInvalid means the AppHub name is outside the C1 app
	// display-name contract.
	ErrApplicationNameInvalid = errors.New("c1directory: application name must be between 1 and 512 bytes")
	// ErrApplicationURLInvalid means a supplied public application URL cannot
	// be represented safely in the C1 app metadata.
	ErrApplicationURLInvalid = errors.New("c1directory: application URL must be an absolute HTTP(S) URL no longer than 256 bytes")
	// ErrGoLinkAliasInvalid means the supplied alias would be normalized or
	// rejected by C1 rather than creating exactly the alias requested.
	ErrGoLinkAliasInvalid = errors.New("c1directory: GoLink alias must be a lowercase C1 route with 1-10 slash-separated segments and no spaces")
	// ErrGoLinkURLInvalid means the supplied redirect URL is not a C1-valid
	// external HTTPS target.
	ErrGoLinkURLInvalid = errors.New("c1directory: GoLink target URL must be an absolute HTTPS URL no longer than 2048 bytes")
	// ErrProvisioningConflict means C1 contains multiple or incompatible
	// AppHub-managed objects, so choosing one could mutate another deployment.
	ErrProvisioningConflict = errors.New("c1directory: C1 provisioning ownership conflict")
	// ErrGoLinkAliasCollision means an alias belongs to a GoLink AppHub does
	// not own. The operator must choose a different application name or resolve
	// the existing C1 GoLink before retrying.
	ErrGoLinkAliasCollision = errors.New("c1directory: requested GoLink alias is already owned by another C1 GoLink")
	// ErrProvisioningResponseIncomplete means a successful C1 response omitted
	// identity fields needed to continue without guessing.
	ErrProvisioningResponseIncomplete = errors.New("c1directory: C1 returned an incomplete provisioning response")
	// ErrProvisioningPagination means an ownership lookup could not be
	// completed without exceeding the client's safety bound.
	ErrProvisioningPagination = errors.New("c1directory: C1 provisioning reconciliation exceeded the pagination safety limit")
)

// Provisioner creates and reconciles the optional C1 representation of an
// AppHub application. It is intentionally separate from Client: callers that
// only synchronize directory membership never need a write-capable interface.
type Provisioner interface {
	// ProvisionApplication creates or reconciles the C1 app associated with the
	// stable AppHub appID. It ensures the application's general Access and Admin
	// entitlements. publicURL may be empty for deployments with no route; in
	// that case existing public-URL metadata is left untouched.
	ProvisionApplication(ctx context.Context, appID, name, publicURL string) error

	// DeleteApplication removes only the C1 app bearing AppHub's ownership
	// marker for appID. An absent app is already deleted.
	DeleteApplication(ctx context.Context, appID string) error

	// ProvisionGoLink creates or reconciles the GoLink owned by appID. alias is
	// used verbatim as the C1 route after validation; it is never normalized or
	// silently changed. targetURL must be an absolute HTTPS URL accepted by C1.
	ProvisionGoLink(ctx context.Context, appID, alias, targetURL string) error
}

// NewProvisioner returns a C1 provisioner using the directory client's
// isolated credentials and HTTP transport. It performs no network I/O.
func NewProvisioner(cfg Config, deps Deps) (Provisioner, error) {
	client, err := newHTTPClient(cfg, deps)
	if err != nil {
		return nil, err
	}
	return client, nil
}

var _ Provisioner = (*httpClient)(nil)

// ProvisionApplication reconciles only AppHub-owned C1 objects. Its ownership
// annotations make retries after a partial deployment resume instead of
// creating another resource or entitlement.
func (c *httpClient) ProvisionApplication(ctx context.Context, appID, name, publicURL string) error {
	if err := validateApplicationInput(appID, name, publicURL); err != nil {
		return err
	}

	application, err := c.ensureApplication(ctx, appID, name, publicURL)
	if err != nil {
		return err
	}
	resourceType, err := c.ensureApplicationResourceType(ctx, application.ID)
	if err != nil {
		return fmt.Errorf("ensure resource type: %w", err)
	}
	resource, err := c.ensureApplicationResource(ctx, application.ID, resourceType.ID, appID)
	if err != nil {
		return fmt.Errorf("ensure resource: %w", err)
	}
	entitlementsErr := c.ensureApplicationEntitlements(
		ctx, application.ID, resourceType.ID, resource.ID, appID)
	if entitlementsErr != nil {
		return fmt.Errorf("ensure entitlements: %w", entitlementsErr)
	}
	return nil
}

// DeleteApplication resolves the C1 identity from AppHub's stable ownership
// marker rather than trusting a display name or a stale local ID. Repeating it
// after a successful or ambiguous delete is safe.
func (c *httpClient) DeleteApplication(ctx context.Context, appID string) error {
	if !annotationValuePattern.MatchString(appID) {
		return ErrApplicationIdentityInvalid
	}
	applications, err := c.listApplications(ctx)
	if err != nil {
		return fmt.Errorf("list applications for deletion: %w", err)
	}
	managed, err := selectManagedApplication(applications, appID)
	if err != nil || managed == nil {
		return err
	}
	op := credhttp.OpC1DirectorySearchEntitlements()
	resp, err := c.do(ctx, http.MethodDelete, appsPath+"/"+url.PathEscape(managed.ID), op, nil)
	if err != nil {
		return provisioningOperationError("deleting the C1 application", err)
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		drain(resp)
		return nil
	}
	return provisioningOperationError("deleting the C1 application", statusError(op, resp))
}

// ProvisionGoLink reconciles a GoLink independently of application
// provisioning. A deployment may expose a route without provisioning its C1
// app, and vice versa.
func (c *httpClient) ProvisionGoLink(ctx context.Context, appID, alias, targetURL string) error {
	if err := validateGoLinkInput(appID, alias, targetURL); err != nil {
		return err
	}

	links, err := c.listGoLinks(ctx)
	if err != nil {
		return fmt.Errorf("list GoLinks: %w", err)
	}
	managed, err := selectManagedGoLink(links, appID, alias)
	if err != nil {
		return err
	}
	if managed != nil {
		if err := c.reconcileGoLink(ctx, *managed, appID, alias, targetURL); err != nil {
			return fmt.Errorf("reconcile GoLink: %w", err)
		}
		return nil
	}

	created, err := c.createGoLink(ctx, appID, alias, targetURL)
	if err == nil {
		if !isC1ID(created.ID) {
			return ErrProvisioningResponseIncomplete
		}
		return nil
	}

	// A network failure or a C1 conflict can happen after C1 accepted the
	// create. Re-read ownership before reporting an error so the next deploy
	// does not create a duplicate.
	recoveredLinks, recoveryErr := c.listGoLinks(ctx)
	if recoveryErr != nil {
		return fmt.Errorf("create GoLink: %w", err)
	}
	recovered, selectionErr := selectManagedGoLink(recoveredLinks, appID, alias)
	if selectionErr != nil {
		return selectionErr
	}
	if recovered != nil {
		if err := c.reconcileGoLink(ctx, *recovered, appID, alias, targetURL); err != nil {
			return fmt.Errorf("reconcile GoLink: %w", err)
		}
		return nil
	}
	return fmt.Errorf("create GoLink: %w", err)
}

func validateApplicationInput(appID, name, publicURL string) error {
	if !annotationValuePattern.MatchString(appID) {
		return ErrApplicationIdentityInvalid
	}
	if len(name) < 1 || len(name) > 512 {
		return ErrApplicationNameInvalid
	}
	if publicURL == "" {
		return nil
	}
	if len(publicURL) > 256 || !annotationValuePattern.MatchString(publicURL) || !isAbsoluteHTTPURL(publicURL) {
		return ErrApplicationURLInvalid
	}
	return nil
}

func validateGoLinkInput(appID, alias, targetURL string) error {
	if !annotationValuePattern.MatchString(appID) {
		return ErrApplicationIdentityInvalid
	}
	if !isExactGoLinkAlias(alias) {
		return ErrGoLinkAliasInvalid
	}
	if len(targetURL) > 2048 || !isAbsoluteHTTPSURL(targetURL) {
		return ErrGoLinkURLInvalid
	}
	return nil
}

func isAbsoluteHTTPURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false
	}
	return parsed.Scheme == "https" || parsed.Scheme == "http"
}

func isAbsoluteHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return false
	}
	return !strings.ContainsAny(parsed.RawQuery, " \t\r\n")
}

func isC1ID(value string) bool {
	return c1IDPattern.MatchString(value)
}

func isExactGoLinkAlias(alias string) bool {
	if len(alias) == 0 || len(alias) > 256 || !goLinkAliasPattern.MatchString(alias) {
		return false
	}
	if strings.Trim(alias, "/") != alias || strings.Contains(alias, "//") || strings.Count(alias, "/") >= 10 {
		return false
	}
	// C1 resolves these routes before tenant-authored GoLinks, so its source
	// rejects them. Reject locally rather than leaving a deployment to discover
	// a generic API error after making other writes.
	return alias != "request" && alias != "myaccess"
}

func (c *httpClient) ensureApplication(ctx context.Context, appID, name, publicURL string) (c1Application, error) {
	applications, err := c.listApplications(ctx)
	if err != nil {
		return c1Application{}, fmt.Errorf("list applications: %w", err)
	}
	managed, err := selectManagedApplication(applications, appID)
	if err != nil {
		return c1Application{}, err
	}
	if managed != nil {
		return c.reconcileApplication(ctx, *managed, appID, name, publicURL)
	}

	created, err := c.createApplication(ctx, appID, name, publicURL)
	if err == nil {
		if !isC1ID(created.ID) {
			return c1Application{}, ErrProvisioningResponseIncomplete
		}
		return created, nil
	}

	// Re-read after an unsuccessful create to handle accepted-but-unobserved
	// requests without issuing a second create.
	recoveredApplications, recoveryErr := c.listApplications(ctx)
	if recoveryErr != nil {
		return c1Application{}, fmt.Errorf("create application: %w", err)
	}
	recovered, selectionErr := selectManagedApplication(recoveredApplications, appID)
	if selectionErr != nil {
		return c1Application{}, selectionErr
	}
	if recovered != nil {
		return c.reconcileApplication(ctx, *recovered, appID, name, publicURL)
	}
	return c1Application{}, fmt.Errorf("create application: %w", err)
}

func selectManagedApplication(applications []c1Application, appID string) (*c1Application, error) {
	var managed *c1Application
	for i := range applications {
		application := &applications[i]
		if application.Annotations[appHubApplicationIDAnnotation] != appID {
			continue
		}
		if application.Annotations[appHubProvisionerAnnotation] != appHubProvisioner {
			return nil, ErrProvisioningConflict
		}
		if !isC1ID(application.ID) {
			return nil, ErrProvisioningResponseIncomplete
		}
		if managed != nil {
			return nil, ErrProvisioningConflict
		}
		managed = application
	}
	return managed, nil
}

func (c *httpClient) reconcileApplication(ctx context.Context, current c1Application, appID, name, publicURL string) (c1Application, error) {
	update := c1Application{ID: current.ID}
	paths := make([]string, 0, 2)
	if current.DisplayName != name {
		update.DisplayName = name
		paths = append(paths, "displayName")
	}

	annotations := applicationAnnotations(appID, publicURL)
	if !applicationAnnotationsMatch(current.Annotations, annotations) {
		// Updating an annotations field replaces the whole C1 bag. Keep
		// annotations outside AppHub's ownership marker intact.
		for key, value := range annotations {
			current.Annotations[key] = value
		}
		update.Annotations = current.Annotations
		paths = append(paths, "annotations")
	}
	if len(paths) == 0 {
		return current, nil
	}

	var response updateApplicationResponse
	err := c.provisionJSON(ctx, http.MethodPost, appsPath+"/"+url.PathEscape(current.ID), "updating the C1 application", updateApplicationRequest{
		App:        update,
		UpdateMask: strings.Join(paths, ","),
	}, &response)
	if err != nil {
		return c1Application{}, err
	}
	if !isC1ID(response.App.ID) || response.App.ID != current.ID {
		return c1Application{}, ErrProvisioningResponseIncomplete
	}
	return response.App, nil
}

func applicationAnnotations(appID, publicURL string) map[string]string {
	annotations := map[string]string{
		appHubProvisionerAnnotation:   appHubProvisioner,
		appHubApplicationIDAnnotation: appID,
	}
	if publicURL != "" {
		annotations[appHubPublicURLAnnotation] = publicURL
	}
	return annotations
}

func applicationAnnotationsMatch(current, desired map[string]string) bool {
	for key, value := range desired {
		if current[key] != value {
			return false
		}
	}
	return true
}

func (c *httpClient) createApplication(ctx context.Context, appID, name, publicURL string) (c1Application, error) {
	var response createApplicationResponse
	err := c.provisionJSON(ctx, http.MethodPost, appsPath, "creating the C1 application", createApplicationRequest{
		DisplayName: name,
		Annotations: applicationAnnotations(appID, publicURL),
	}, &response)
	if err != nil {
		return c1Application{}, err
	}
	return response.App, nil
}

func (c *httpClient) ensureApplicationResourceType(ctx context.Context, c1ApplicationID string) (c1ResourceType, error) {
	resourceTypes, err := c.listResourceTypes(ctx, c1ApplicationID)
	if err != nil {
		return c1ResourceType{}, err
	}
	managed, err := selectApplicationResourceType(resourceTypes)
	if err != nil {
		return c1ResourceType{}, err
	}
	if managed != nil {
		return *managed, nil
	}

	created, err := c.createApplicationResourceType(ctx, c1ApplicationID)
	if err == nil {
		if !isC1ID(created.ID) {
			return c1ResourceType{}, ErrProvisioningResponseIncomplete
		}
		return created, nil
	}

	recoveredResourceTypes, recoveryErr := c.listResourceTypes(ctx, c1ApplicationID)
	if recoveryErr != nil {
		return c1ResourceType{}, err
	}
	recovered, selectionErr := selectApplicationResourceType(recoveredResourceTypes)
	if selectionErr != nil {
		return c1ResourceType{}, selectionErr
	}
	if recovered != nil {
		return *recovered, nil
	}
	return c1ResourceType{}, err
}

func selectApplicationResourceType(resourceTypes []c1ResourceType) (*c1ResourceType, error) {
	var managed *c1ResourceType
	for i := range resourceTypes {
		resourceType := &resourceTypes[i]
		if resourceType.DisplayName != appHubApplicationResourceTypeName {
			continue
		}
		if !isC1ID(resourceType.ID) {
			return nil, ErrProvisioningResponseIncomplete
		}
		if managed != nil {
			return nil, ErrProvisioningConflict
		}
		managed = resourceType
	}
	return managed, nil
}

func (c *httpClient) createApplicationResourceType(ctx context.Context, c1ApplicationID string) (c1ResourceType, error) {
	var response createResourceTypeResponse
	err := c.provisionJSON(ctx, http.MethodPost, appResourceTypesPath(c1ApplicationID), "creating the C1 application resource type", createResourceTypeRequest{
		AppID: c1ApplicationID,
		// CUSTOM is deliberately used because C1's other manual resource type
		// IDs are app-scoped well-known IDs and create is an upsert. Reusing,
		// for example, ROLE could overwrite an unrelated type on an AppHub app.
		ResourceType: "CUSTOM",
		DisplayName:  appHubApplicationResourceTypeName,
	}, &response)
	if err != nil {
		return c1ResourceType{}, err
	}
	return response.AppResourceType, nil
}

func (c *httpClient) ensureApplicationResource(ctx context.Context, c1ApplicationID, c1ResourceTypeID, appID string) (c1Resource, error) {
	resources, err := c.listResources(ctx, c1ApplicationID, c1ResourceTypeID)
	if err != nil {
		return c1Resource{}, err
	}
	managed, err := selectManagedApplicationResource(resources, appID, c1ApplicationID, c1ResourceTypeID)
	if err != nil {
		return c1Resource{}, err
	}
	if managed != nil {
		return *managed, nil
	}

	created, err := c.createApplicationResource(ctx, c1ApplicationID, c1ResourceTypeID, appID)
	if err == nil {
		if !isC1ID(created.ID) {
			return c1Resource{}, ErrProvisioningResponseIncomplete
		}
		return created, nil
	}

	recoveredResources, recoveryErr := c.listResources(ctx, c1ApplicationID, c1ResourceTypeID)
	if recoveryErr != nil {
		return c1Resource{}, err
	}
	recovered, selectionErr := selectManagedApplicationResource(recoveredResources, appID, c1ApplicationID, c1ResourceTypeID)
	if selectionErr != nil {
		return c1Resource{}, selectionErr
	}
	if recovered != nil {
		return *recovered, nil
	}
	return c1Resource{}, err
}

func selectManagedApplicationResource(resources []c1Resource, appID, c1ApplicationID, c1ResourceTypeID string) (*c1Resource, error) {
	var managed *c1Resource
	for i := range resources {
		resource := &resources[i]
		if resource.Annotations[appHubApplicationIDAnnotation] != appID {
			continue
		}
		if resource.Annotations[appHubProvisionerAnnotation] != appHubProvisioner || resource.Annotations[appHubObjectKindAnnotation] != appHubApplicationResourceKind || resource.AppID != c1ApplicationID || resource.AppResourceTypeID != c1ResourceTypeID {
			return nil, ErrProvisioningConflict
		}
		if !isC1ID(resource.ID) {
			return nil, ErrProvisioningResponseIncomplete
		}
		if managed != nil {
			return nil, ErrProvisioningConflict
		}
		managed = resource
	}
	return managed, nil
}

func (c *httpClient) createApplicationResource(ctx context.Context, c1ApplicationID, c1ResourceTypeID, appID string) (c1Resource, error) {
	var response createResourceResponse
	err := c.provisionJSON(ctx, http.MethodPost, appResourcesPath(c1ApplicationID, c1ResourceTypeID), "creating the C1 application resource", createResourceRequest{
		AppID:             c1ApplicationID,
		AppResourceTypeID: c1ResourceTypeID,
		DisplayName:       appHubApplicationResourceName,
		Annotations: map[string]string{
			appHubProvisionerAnnotation:   appHubProvisioner,
			appHubApplicationIDAnnotation: appID,
			appHubObjectKindAnnotation:    appHubApplicationResourceKind,
		},
	}, &response)
	if err != nil {
		return c1Resource{}, err
	}
	return response.AppResource, nil
}

type entitlementDefinition struct {
	Role        string
	DisplayName string
	Description string
	Slug        string
}

var applicationEntitlementDefinitions = []entitlementDefinition{
	{
		Role:        appHubAccessEntitlementRole,
		DisplayName: "Access",
		Description: "General access to this AppHub application.",
		Slug:        "access",
	},
	{
		Role:        appHubAdminEntitlementRole,
		DisplayName: "Admin",
		Description: "Administrative access to this AppHub application.",
		Slug:        "admin",
	},
}

func (c *httpClient) ensureApplicationEntitlements(ctx context.Context, c1ApplicationID, c1ResourceTypeID, c1ResourceID, appID string) error {
	entitlements, err := c.listEntitlementsForApplication(ctx, c1ApplicationID)
	if err != nil {
		return err
	}
	for _, definition := range applicationEntitlementDefinitions {
		managed, err := selectManagedEntitlement(entitlements, appID, c1ApplicationID, c1ResourceTypeID, c1ResourceID, definition.Role)
		if err != nil {
			return err
		}
		if managed != nil {
			if err := c.reconcileEntitlement(ctx, *managed, c1ApplicationID, definition); err != nil {
				return err
			}
			continue
		}

		created, err := c.createEntitlement(ctx, c1ApplicationID, c1ResourceTypeID, c1ResourceID, appID, definition)
		if err == nil {
			if !isC1ID(created.ID) {
				return ErrProvisioningResponseIncomplete
			}
			continue
		}

		// As with the app and resource creates, recover an accepted-but-
		// unobserved entitlement creation by looking it up before returning the
		// original safe error.
		recoveredEntitlements, recoveryErr := c.listEntitlementsForApplication(ctx, c1ApplicationID)
		if recoveryErr != nil {
			return err
		}
		recovered, selectionErr := selectManagedEntitlement(recoveredEntitlements, appID, c1ApplicationID, c1ResourceTypeID, c1ResourceID, definition.Role)
		if selectionErr != nil {
			return selectionErr
		}
		if recovered == nil {
			return err
		}
		if err := c.reconcileEntitlement(ctx, *recovered, c1ApplicationID, definition); err != nil {
			return err
		}
		entitlements = recoveredEntitlements
	}
	return nil
}

func selectManagedEntitlement(entitlements []c1Entitlement, appID, c1ApplicationID, c1ResourceTypeID, c1ResourceID, role string) (*c1Entitlement, error) {
	var managed *c1Entitlement
	for i := range entitlements {
		entitlement := &entitlements[i]
		if entitlement.Annotations[appHubApplicationIDAnnotation] != appID {
			continue
		}
		if entitlement.Annotations[appHubProvisionerAnnotation] != appHubProvisioner || entitlement.AppID != c1ApplicationID || entitlement.AppResourceTypeID != c1ResourceTypeID || entitlement.AppResourceID != c1ResourceID {
			return nil, ErrProvisioningConflict
		}
		if !isC1ID(entitlement.ID) {
			return nil, ErrProvisioningResponseIncomplete
		}
		managedRole := entitlement.Annotations[appHubEntitlementRoleAnnotation]
		if managedRole != appHubAccessEntitlementRole && managedRole != appHubAdminEntitlementRole {
			return nil, ErrProvisioningConflict
		}
		if managedRole != role {
			continue
		}
		if managed != nil {
			return nil, ErrProvisioningConflict
		}
		managed = entitlement
	}
	return managed, nil
}

func (c *httpClient) createEntitlement(ctx context.Context, c1ApplicationID, c1ResourceTypeID, c1ResourceID, appID string, definition entitlementDefinition) (c1Entitlement, error) {
	var response createEntitlementResponse
	err := c.provisionJSON(ctx, http.MethodPost, appEntitlementsPath(c1ApplicationID), "creating the C1 application entitlement", createEntitlementRequest{
		AppID:             c1ApplicationID,
		DisplayName:       definition.DisplayName,
		Description:       definition.Description,
		AppResourceTypeID: c1ResourceTypeID,
		AppResourceID:     c1ResourceID,
		Slug:              definition.Slug,
		Purpose:           "APP_ENTITLEMENT_PURPOSE_VALUE_ASSIGNMENT",
		Annotations: map[string]string{
			appHubProvisionerAnnotation:     appHubProvisioner,
			appHubApplicationIDAnnotation:   appID,
			appHubEntitlementRoleAnnotation: definition.Role,
		},
	}, &response)
	if err != nil {
		return c1Entitlement{}, err
	}
	return response.AppEntitlementView.AppEntitlement, nil
}

func (c *httpClient) reconcileEntitlement(ctx context.Context, current c1Entitlement, c1ApplicationID string, definition entitlementDefinition) error {
	update := c1Entitlement{ID: current.ID}
	paths := make([]string, 0, 4)
	if current.DisplayName != definition.DisplayName {
		update.DisplayName = definition.DisplayName
		paths = append(paths, "displayName")
	}
	if current.Description != definition.Description {
		update.Description = definition.Description
		paths = append(paths, "description")
	}
	if current.Slug != definition.Slug {
		update.Slug = definition.Slug
		paths = append(paths, "slug")
	}
	if current.Purpose != "APP_ENTITLEMENT_PURPOSE_VALUE_ASSIGNMENT" {
		update.Purpose = "APP_ENTITLEMENT_PURPOSE_VALUE_ASSIGNMENT"
		paths = append(paths, "purpose")
	}
	if len(paths) == 0 {
		return nil
	}

	var response updateEntitlementResponse
	err := c.provisionJSON(ctx, http.MethodPost, appEntitlementPath(c1ApplicationID, current.ID), "updating the C1 application entitlement", updateEntitlementRequest{
		AppID:       c1ApplicationID,
		Entitlement: update,
		UpdateMask:  strings.Join(paths, ","),
	}, &response)
	if err != nil {
		return err
	}
	updatedID := response.AppEntitlementView.AppEntitlement.ID
	if !isC1ID(updatedID) || updatedID != current.ID {
		return ErrProvisioningResponseIncomplete
	}
	return nil
}

func selectManagedGoLink(links []c1GoLink, appID, alias string) (*c1GoLink, error) {
	marker := goLinkDescription(appID)
	var managed *c1GoLink
	for i := range links {
		link := &links[i]
		ownsLink := link.Description == marker
		if ownsLink {
			if !isC1ID(link.ID) {
				return nil, ErrProvisioningResponseIncomplete
			}
			if managed != nil {
				return nil, ErrProvisioningConflict
			}
			managed = link
		}
		if link.hasRoute(alias) && !ownsLink {
			return nil, ErrGoLinkAliasCollision
		}
	}
	return managed, nil
}

func (c *httpClient) reconcileGoLink(ctx context.Context, current c1GoLink, appID, alias, targetURL string) error {
	if !goLinkNeedsUpdate(current, appID, alias, targetURL) {
		return nil
	}
	var response updateGoLinkResponse
	err := c.provisionJSON(ctx, http.MethodPatch, goLinksPath+"/"+url.PathEscape(current.ID), "updating the C1 GoLink", updateGoLinkRequest{
		GoLink: c1GoLink{
			ID:          current.ID,
			DisplayName: alias,
			Target:      redirectGoLinkTarget(targetURL),
			Routes: []c1GoLinkRoute{{
				RouteTemplate: alias,
				IsCanonical:   true,
			}},
		},
		UpdateMask: "displayName,target,routes",
	}, &response)
	if err != nil {
		return err
	}
	if !isC1ID(response.GoLink.ID) || response.GoLink.ID != current.ID {
		return ErrProvisioningResponseIncomplete
	}
	return nil
}

func goLinkNeedsUpdate(current c1GoLink, appID, alias, targetURL string) bool {
	if current.Description != goLinkDescription(appID) || current.DisplayName != alias || current.Target.redirectURL() != targetURL || len(current.Routes) != 1 {
		return true
	}
	return current.Routes[0].RouteTemplate != alias || !current.Routes[0].IsCanonical
}

func (c *httpClient) createGoLink(ctx context.Context, appID, alias, targetURL string) (c1GoLink, error) {
	var response createGoLinkResponse
	err := c.provisionJSON(ctx, http.MethodPost, goLinksPath, "creating the C1 GoLink", createGoLinkRequest{
		DisplayName: alias,
		Description: goLinkDescription(appID),
		Target:      redirectGoLinkTarget(targetURL),
		Routes: []c1GoLinkRoute{{
			RouteTemplate: alias,
			IsCanonical:   true,
		}},
	}, &response)
	if err != nil {
		return c1GoLink{}, err
	}
	return response.GoLink, nil
}

func goLinkDescription(appID string) string {
	return "Managed by AppHub for application " + appID + "."
}

func redirectGoLinkTarget(targetURL string) c1GoLinkTarget {
	return c1GoLinkTarget{Redirect: &c1GoLinkRedirectTarget{URLTemplate: targetURL}}
}

func (c *httpClient) listApplications(ctx context.Context) ([]c1Application, error) {
	var applications []c1Application
	pageToken := ""
	for page := 0; page < maxSearchPages; page++ {
		var response listApplicationsResponse
		if err := c.provisionJSON(ctx, http.MethodGet, paginatedPath(appsPath, page, pageToken), "listing C1 applications", nil, &response); err != nil {
			return nil, err
		}
		applications = append(applications, response.List...)
		if response.NextPageToken == "" {
			return applications, nil
		}
		if response.NextPageToken == pageToken {
			return nil, ErrProvisioningPagination
		}
		pageToken = response.NextPageToken
	}
	return nil, ErrProvisioningPagination
}

func (c *httpClient) listResourceTypes(ctx context.Context, c1ApplicationID string) ([]c1ResourceType, error) {
	var resourceTypes []c1ResourceType
	pageToken := ""
	for page := 0; page < maxSearchPages; page++ {
		var response listResourceTypesResponse
		if err := c.provisionJSON(ctx, http.MethodGet, paginatedPath(appResourceTypesPath(c1ApplicationID), page, pageToken), "listing C1 application resource types", nil, &response); err != nil {
			return nil, err
		}
		for _, view := range response.List {
			resourceTypes = append(resourceTypes, view.AppResourceType)
		}
		if response.NextPageToken == "" {
			return resourceTypes, nil
		}
		if response.NextPageToken == pageToken {
			return nil, ErrProvisioningPagination
		}
		pageToken = response.NextPageToken
	}
	return nil, ErrProvisioningPagination
}

func (c *httpClient) listResources(ctx context.Context, c1ApplicationID, c1ResourceTypeID string) ([]c1Resource, error) {
	var resources []c1Resource
	pageToken := ""
	for page := 0; page < maxSearchPages; page++ {
		var response listResourcesResponse
		if err := c.provisionJSON(ctx, http.MethodGet, paginatedPath(appResourcesPath(c1ApplicationID, c1ResourceTypeID), page, pageToken), "listing C1 application resources", nil, &response); err != nil {
			return nil, err
		}
		for _, view := range response.List {
			resources = append(resources, view.AppResource)
		}
		if response.NextPageToken == "" {
			return resources, nil
		}
		if response.NextPageToken == pageToken {
			return nil, ErrProvisioningPagination
		}
		pageToken = response.NextPageToken
	}
	return nil, ErrProvisioningPagination
}

func (c *httpClient) listEntitlementsForApplication(ctx context.Context, c1ApplicationID string) ([]c1Entitlement, error) {
	var entitlements []c1Entitlement
	pageToken := ""
	for page := 0; page < maxSearchPages; page++ {
		var response listEntitlementsResponse
		if err := c.provisionJSON(ctx, http.MethodGet, paginatedPath(appEntitlementsPath(c1ApplicationID), page, pageToken), "listing C1 application entitlements", nil, &response); err != nil {
			return nil, err
		}
		for _, view := range response.List {
			entitlements = append(entitlements, view.AppEntitlement)
		}
		if response.NextPageToken == "" {
			return entitlements, nil
		}
		if response.NextPageToken == pageToken {
			return nil, ErrProvisioningPagination
		}
		pageToken = response.NextPageToken
	}
	return nil, ErrProvisioningPagination
}

func (c *httpClient) listGoLinks(ctx context.Context) ([]c1GoLink, error) {
	var links []c1GoLink
	pageToken := ""
	for page := 0; page < maxSearchPages; page++ {
		var response listGoLinksResponse
		if err := c.provisionJSON(ctx, http.MethodGet, paginatedPath(goLinksPath, page, pageToken), "listing C1 GoLinks", nil, &response); err != nil {
			return nil, err
		}
		for _, view := range response.List {
			links = append(links, view.GoLink)
		}
		if response.NextPageToken == "" {
			return links, nil
		}
		if response.NextPageToken == pageToken {
			return nil, ErrProvisioningPagination
		}
		pageToken = response.NextPageToken
	}
	return nil, ErrProvisioningPagination
}

func paginatedPath(base string, page int, pageToken string) string {
	values := url.Values{}
	values.Set("page_size", strconv.Itoa(pageSize))
	if page > 0 && pageToken != "" {
		values.Set("page_token", pageToken)
	}
	return base + "?" + values.Encode()
}

func appResourceTypesPath(c1ApplicationID string) string {
	return appsPath + "/" + url.PathEscape(c1ApplicationID) + "/resource_types"
}

func appResourcesPath(c1ApplicationID, c1ResourceTypeID string) string {
	return appResourceTypesPath(c1ApplicationID) + "/" + url.PathEscape(c1ResourceTypeID) + "/resources"
}

func appEntitlementsPath(c1ApplicationID string) string {
	return appsPath + "/" + url.PathEscape(c1ApplicationID) + "/entitlements"
}

func appEntitlementPath(c1ApplicationID, c1EntitlementID string) string {
	return appEntitlementsPath(c1ApplicationID) + "/" + url.PathEscape(c1EntitlementID)
}

// provisionJSON performs one authenticated C1 provisioning request. All
// caller-visible errors are constructed locally; upstream response bodies are
// never included because URLs, aliases, and credential details can appear in
// them.
func (c *httpClient) provisionJSON(ctx context.Context, method, path, operation string, request, response any) error {
	var body []byte
	var err error
	if request != nil {
		body, err = json.Marshal(request)
		if err != nil {
			return errors.New("c1directory: encoding a C1 provisioning request failed")
		}
	}

	// Provisioning shares c1directory's isolated credential boundary. The
	// existing credhttp operation family is the only operation taxonomy exposed
	// for that boundary.
	op := credhttp.OpC1DirectorySearchEntitlements()
	resp, err := c.do(ctx, method, path, op, body)
	if err != nil {
		return provisioningOperationError(operation, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return provisioningOperationError(operation, statusError(op, resp))
	}

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("c1directory: %s response could not be read: %w", operation, classifyRead(readErr))
	}
	if len(raw) > maxResponseBodyBytes {
		return fmt.Errorf("c1directory: %s response was not expected JSON: %w (%s, %d bytes)", operation, errTruncatedJSON, bodyKind(raw[:maxResponseBodyBytes]), maxResponseBodyBytes)
	}
	if err := json.Unmarshal(raw, response); err != nil {
		return fmt.Errorf("c1directory: %s response was not expected JSON: %w (%s, %d bytes)", operation, classifyDecode(err), bodyKind(raw), len(raw))
	}
	return nil
}

// provisioningOperationError names the provisioning step that failed. err is
// always wrapped with %w -- never reconstructed -- so a caller's errors.Is
// still matches a classified sentinel (ErrUnauthenticated,
// ErrClientSecretUnresolved, credentials.ErrTransient, a canceled or expired
// context) and the status code and method+path statusError attached are
// never dropped.
func provisioningOperationError(operation string, err error) error {
	return fmt.Errorf("c1directory: %s: %w", operation, err)
}

type c1Application struct {
	ID          string            `json:"id,omitempty"`
	DisplayName string            `json:"displayName,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type c1ResourceType struct {
	ID          string `json:"id,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

type c1Resource struct {
	ID                string            `json:"id,omitempty"`
	AppID             string            `json:"appId,omitempty"`
	AppResourceTypeID string            `json:"appResourceTypeId,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
}

type c1Entitlement struct {
	ID                string            `json:"id,omitempty"`
	AppID             string            `json:"appId,omitempty"`
	AppResourceTypeID string            `json:"appResourceTypeId,omitempty"`
	AppResourceID     string            `json:"appResourceId,omitempty"`
	DisplayName       string            `json:"displayName,omitempty"`
	Description       string            `json:"description,omitempty"`
	Slug              string            `json:"slug,omitempty"`
	Purpose           string            `json:"purpose,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
}

type c1GoLink struct {
	ID          string          `json:"id,omitempty"`
	DisplayName string          `json:"displayName,omitempty"`
	Description string          `json:"description,omitempty"`
	Target      c1GoLinkTarget  `json:"target,omitempty"`
	Routes      []c1GoLinkRoute `json:"routes,omitempty"`
}

func (link c1GoLink) hasRoute(alias string) bool {
	for _, route := range link.Routes {
		if normalizedGoLinkRoute(route.RouteTemplate) == alias {
			return true
		}
	}
	return false
}

// normalizedGoLinkRoute mirrors C1's route-key normalization for collision
// detection. AppHub still rejects an input alias that needs normalization; this
// only prevents creation against an existing differently-cased or slash-padded
// C1 route that resolves to the same key.
func normalizedGoLinkRoute(template string) string {
	normalized := strings.ToLower(strings.TrimSpace(template))
	normalized = strings.Trim(normalized, "/")
	for strings.Contains(normalized, "//") {
		normalized = strings.ReplaceAll(normalized, "//", "/")
	}
	return normalized
}

type c1GoLinkRoute struct {
	RouteTemplate string `json:"routeTemplate,omitempty"`
	IsCanonical   bool   `json:"isCanonical"`
}

type c1GoLinkTarget struct {
	Redirect *c1GoLinkRedirectTarget `json:"redirect,omitempty"`
}

func (target c1GoLinkTarget) redirectURL() string {
	if target.Redirect == nil {
		return ""
	}
	return target.Redirect.URLTemplate
}

type c1GoLinkRedirectTarget struct {
	URLTemplate string `json:"urlTemplate,omitempty"`
}

type createApplicationRequest struct {
	DisplayName string            `json:"displayName"`
	Annotations map[string]string `json:"annotations"`
}

type updateApplicationRequest struct {
	App        c1Application `json:"app"`
	UpdateMask string        `json:"updateMask"`
}

type createResourceTypeRequest struct {
	AppID        string `json:"appId"`
	ResourceType string `json:"resourceType"`
	DisplayName  string `json:"displayName"`
}

type createResourceRequest struct {
	AppID             string            `json:"appId"`
	AppResourceTypeID string            `json:"appResourceTypeId"`
	DisplayName       string            `json:"displayName"`
	Annotations       map[string]string `json:"annotations"`
}

type createEntitlementRequest struct {
	AppID             string            `json:"appId"`
	DisplayName       string            `json:"displayName"`
	Description       string            `json:"description"`
	AppResourceTypeID string            `json:"appResourceTypeId"`
	AppResourceID     string            `json:"appResourceId"`
	Slug              string            `json:"slug"`
	Purpose           string            `json:"purpose"`
	Annotations       map[string]string `json:"annotations"`
}

type updateEntitlementRequest struct {
	AppID       string        `json:"appId"`
	Entitlement c1Entitlement `json:"entitlement"`
	UpdateMask  string        `json:"updateMask"`
}

type createGoLinkRequest struct {
	DisplayName string          `json:"displayName"`
	Description string          `json:"description"`
	Target      c1GoLinkTarget  `json:"target"`
	Routes      []c1GoLinkRoute `json:"routes"`
}

type updateGoLinkRequest struct {
	GoLink     c1GoLink `json:"golink"`
	UpdateMask string   `json:"updateMask"`
}

type createApplicationResponse struct {
	App c1Application `json:"app"`
}

type updateApplicationResponse struct {
	App c1Application `json:"app"`
}

type listApplicationsResponse struct {
	List          []c1Application `json:"list"`
	NextPageToken string          `json:"nextPageToken"`
}

type createResourceTypeResponse struct {
	AppResourceType c1ResourceType `json:"appResourceType"`
}

type listResourceTypesResponse struct {
	List []struct {
		AppResourceType c1ResourceType `json:"appResourceType"`
	} `json:"list"`
	NextPageToken string `json:"nextPageToken"`
}

type createResourceResponse struct {
	AppResource c1Resource `json:"appResource"`
}

type listResourcesResponse struct {
	List []struct {
		AppResource c1Resource `json:"appResource"`
	} `json:"list"`
	NextPageToken string `json:"nextPageToken"`
}

type createEntitlementResponse struct {
	AppEntitlementView struct {
		AppEntitlement c1Entitlement `json:"appEntitlement"`
	} `json:"appEntitlementView"`
}

type updateEntitlementResponse struct {
	AppEntitlementView struct {
		AppEntitlement c1Entitlement `json:"appEntitlement"`
	} `json:"appEntitlementView"`
}

type listEntitlementsResponse struct {
	List []struct {
		AppEntitlement c1Entitlement `json:"appEntitlement"`
	} `json:"list"`
	NextPageToken string `json:"nextPageToken"`
}

type createGoLinkResponse struct {
	GoLink c1GoLink `json:"golink"`
}

type updateGoLinkResponse struct {
	GoLink c1GoLink `json:"golink"`
}

type listGoLinksResponse struct {
	List []struct {
		GoLink c1GoLink `json:"golink"`
	} `json:"list"`
	NextPageToken string `json:"nextPageToken"`
}
