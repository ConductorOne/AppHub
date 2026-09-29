// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/internal/githubapp"
	"github.com/conductorone/apphub/modules/deploy"
)

// Service is the shared authorization and durable intent boundary. It never
// constructs a provider, starts a build, or ties execution to a request lifetime.
type Service struct {
	repo        Repository
	eligibility Eligibility
	targets     map[string]TargetPolicy

	// githubAppKey and logReader/logGroups back the admin Workspace surface
	// (internal/controlplane/admin.go) and are both optional at this layer:
	// nil disables the corresponding admin capability rather than failing
	// construction. In a real deployment cmd/apphub always supplies
	// githubAppKey (see githubAppKeyLocation -- there is no operator toggle
	// for it); Observability remains genuinely operator-optional.
	githubAppKey GitHubAppKeyStore
	auditReader  AuditReader
	auditWriter  AuditWriter
	logReader    LogReader
	// sealer enables secret changes; nil leaves secrets read-only.
	sealer SecretSealer
	// trafficCollection reports whether the worker counts ingress traffic.
	trafficCollection bool
	logGroups         []LogGroup
	// publicOrigin is this deployment's own public origin, used only to build
	// the GitHub App Manifest flow's "url" and "redirect_url" fields
	// (StartGitHubAppManifest) and the browser redirect back into the
	// Workspace once it completes (CompleteGitHubAppManifest). Empty disables
	// that one-click flow; the Workspace's manual GitHub App form is
	// unaffected either way.
	publicOrigin string
	// manifestConverter performs the Manifest flow's one-time GitHub
	// exchange. Always set (NewService installs the production
	// implementation); WithManifestConverter overrides it for tests, so
	// CompleteGitHubAppManifest never has to reach a real network.
	manifestConverter ManifestConverter
}

// ManifestConverter exchanges a GitHub App Manifest flow's one-time code for
// the App it just created. A function type, not an interface: there is
// exactly one operation and no state a fake needs to carry beyond a
// closure. internal/githubapp.ConvertManifest, called against a real
// network transport, is the production implementation NewService installs
// by default.
type ManifestConverter func(ctx context.Context, code, baseURL string) (githubapp.ManifestConversion, error)

// ServiceOption configures an optional Service capability. See WithGitHubAppAdmin
// and WithLogs.
type ServiceOption func(*Service)

// WithGitHubAppAdmin enables the Workspace's GitHub App configuration surface,
// backed by store for the app's private key. store is typically
// internal/ghappkey.Store, constructed by the composition root -- this package
// depends only on the narrow interface, never on the AWS SDK
// (internal/boundary's aws-sdk-confined rule denies it to every package that
// is not a named provider boundary).
func WithGitHubAppAdmin(store GitHubAppKeyStore) ServiceOption {
	return func(s *Service) { s.githubAppKey = store }
}

// WithLogs enables the Workspace's log viewer over exactly the named groups.
// reader is typically internal/logs.Reader, for the same reason
// WithGitHubAppAdmin takes an interface rather than a concrete AWS type.
func WithLogs(reader LogReader, groups []LogGroup) ServiceOption {
	return func(s *Service) { s.logReader = reader; s.logGroups = slices.Clone(groups) }
}

// WithPublicOrigin enables the Workspace's one-click "Create via GitHub"
// GitHub App Manifest flow, which needs this deployment's own reachable
// origin to build the manifest's url/redirect_url and the browser redirect
// back once it completes. origin must be a bare scheme+host[:port], matching
// serverconfig.Config.PublicOrigin.
func WithPublicOrigin(origin string) ServiceOption {
	return func(s *Service) { s.publicOrigin = origin }
}

// WithManifestConverter overrides the GitHub App Manifest flow's code
// exchange. Production callers should not need this: NewService already
// installs internal/githubapp.ConvertManifest against a real network
// transport. It exists so tests can exercise CompleteGitHubAppManifest
// against a fake GitHub response instead of a real network call.
func WithManifestConverter(convert ManifestConverter) ServiceOption {
	return func(s *Service) { s.manifestConverter = convert }
}

// NewService validates and owns an isolated copy of the configured target policies.
func NewService(repo Repository, eligibility Eligibility, targets map[string]TargetPolicy, opts ...ServiceOption) (*Service, error) {
	if repo == nil || eligibility == nil {
		return nil, fmt.Errorf("repository and eligibility are required")
	}
	owned := make(map[string]TargetPolicy, len(targets))
	for id, t := range targets {
		if id == "" || t.ID != id || t.ConfigHash == "" || t.Label == "" || len(t.ResourceSizes) == 0 || t.MaxReplicas < 1 || len(t.ExecutionModes) == 0 {
			return nil, fmt.Errorf("target policy is incomplete")
		}
		if t.MaxRelationalCapacityUnits < 0 || math.IsNaN(t.MaxRelationalCapacityUnits) || math.IsInf(t.MaxRelationalCapacityUnits, 0) {
			return nil, fmt.Errorf("target relational capacity ceiling is invalid")
		}
		if err := t.DeployConfig.Validate(); err != nil {
			return nil, fmt.Errorf("target deployment configuration is invalid")
		}
		for _, r := range t.ResourceSizes {
			if r.CPU <= 0 || r.Memory <= 0 {
				return nil, fmt.Errorf("target resource sizes are invalid")
			}
		}
		for _, mode := range t.ExecutionModes {
			if mode != "service" && mode != "scheduled" {
				return nil, fmt.Errorf("target execution mode is invalid")
			}
		}
		t.ResourceSizes = slices.Clone(t.ResourceSizes)
		t.ExecutionModes = slices.Clone(t.ExecutionModes)
		t.Repositories = slices.Clone(t.Repositories)
		if t.Repositories == nil {
			t.Repositories = []string{}
		}
		t.DeployConfig.AllowedSourceHosts = slices.Clone(t.DeployConfig.AllowedSourceHosts)
		owned[id] = t
	}
	s := &Service{repo: repo, eligibility: eligibility, targets: owned, manifestConverter: func(ctx context.Context, code, baseURL string) (githubapp.ManifestConversion, error) {
		return githubapp.ConvertManifest(ctx, code, baseURL, nil)
	}}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func unavailable() *Error {
	return Problem(503, "unavailable", "A required dependency is unavailable. Try again later.")
}
func notFound() *Error { return Problem(404, "not_found", "The requested resource was not found.") }
func deletionConflict() *Error {
	return Problem(409, "application_deleting", "This application is being deleted and can no longer change.")
}
func activeConflict() *Error {
	return Problem(409, "deployment_active", "An active or unresolved deployment prevents this change.")
}
func revisionConflict() *Error {
	return Problem(409, "revision_conflict", "The application revision changed. Reload before trying again.")
}

func sourceNotApproved() *Error {
	return Problem(422, "invalid_specification", "Repository is not approved by the operator.")
}

func sourceNotInstalled() *Error {
	return &Error{Status: 422, Code: "invalid_specification", Message: "Application specification is invalid.", FieldErrors: map[string]string{"source.url": "Repository is not covered by the configured GitHub App."}}
}

// requireApprovedSource is the product allowlist: an operator-configured URL
// list when one is present, otherwise a synced (non-suspended) GitHub App
// installation whose account owns the repository.
func (s *Service) requireApprovedSource(ctx context.Context, target TargetPolicy, rawURL string) error {
	if len(target.Repositories) > 0 {
		if !slices.Contains(target.Repositories, rawURL) {
			return sourceNotApproved()
		}
		return nil
	}
	owner, _, ok := githubOwnerRepo(rawURL)
	if !ok {
		return sourceNotInstalled()
	}
	page, err := s.repo.Query(ctx, Query{Kind: GitHubInstallationKind, Limit: 100})
	if err != nil {
		return unavailable()
	}
	for _, r := range page.Records {
		inst, err := Decode[GitHubInstallationRecord](r)
		if err != nil {
			continue
		}
		if !inst.SuspendedAt.IsZero() {
			continue
		}
		if strings.EqualFold(inst.AccountLogin, owner) {
			return nil
		}
	}
	return sourceNotInstalled()
}

func (s *Service) principal(ctx context.Context, p Principal) (Principal, error) {
	if p.UserID == "" {
		return Principal{}, Problem(401, "unauthorized", "Sign in is required.")
	}
	effective, err := s.eligibility.CheckPrincipal(ctx, p)
	if err != nil {
		var problem *Error
		if errors.As(err, &problem) && (problem.Status == 401 || problem.Status == 403) {
			return Principal{}, Problem(problem.Status, "unauthorized", "This identity is not eligible to access AppHub.")
		}
		return Principal{}, unavailable()
	}
	if effective.UserID == "" || effective.UserID != p.UserID || effective.Issuer != p.Issuer || effective.Subject != p.Subject || effective.ProviderID != p.ProviderID {
		return Principal{}, Problem(401, "unauthorized", "This identity is not eligible to access AppHub.")
	}
	// Eligibility owns current role, not the credential's granted scopes or type.
	effective.Bearer = p.Bearer
	effective.Scopes = slices.Clone(p.Scopes)
	effective.SessionID = p.SessionID
	return effective, nil
}

func (s *Service) application(ctx context.Context, p Principal, id string) (ApplicationRecord, Record, error) {
	r, err := s.repo.Read(ctx, RecordID{Kind: ApplicationKind, ID: id})
	if errors.Is(err, ErrNotFound) {
		return ApplicationRecord{}, Record{}, notFound()
	}
	if err != nil {
		return ApplicationRecord{}, Record{}, unavailable()
	}
	app, err := Decode[ApplicationRecord](r)
	if err != nil || app.ID != id || len(app.Owners) == 0 {
		return ApplicationRecord{}, Record{}, unavailable()
	}
	if !owns(p, app) {
		return ApplicationRecord{}, Record{}, notFound()
	}
	return app, r, nil
}

func (s *Service) deployment(ctx context.Context, id string) (DeploymentRecord, Record, error) {
	r, err := s.repo.Read(ctx, RecordID{Kind: DeploymentKind, ID: id})
	if errors.Is(err, ErrNotFound) {
		return DeploymentRecord{}, Record{}, notFound()
	}
	if err != nil {
		return DeploymentRecord{}, Record{}, unavailable()
	}
	d, err := Decode[DeploymentRecord](r)
	if err != nil || d.ID != id || d.ApplicationID == "" {
		return DeploymentRecord{}, Record{}, unavailable()
	}
	return d, r, nil
}

func mutation(id RecordID, version int64, value any) (Mutation, error) {
	r, err := Encode(id, version+1, value)
	if err != nil {
		return Mutation{}, unavailable()
	}
	// Leave headroom for storage envelopes and indexes under DynamoDB's item cap.
	if len(r.Value) > 128<<10 {
		return Mutation{}, Problem(413, "record_too_large", "The operation exceeds the supported document size.")
	}
	if id.Kind == ApplicationKind || id.Kind == DeploymentKind {
		var document struct {
			Application json.RawMessage `json:"application"`
			Input       json.RawMessage `json:"input"`
		}
		if err := json.Unmarshal(r.Value, &document); err != nil {
			return Mutation{}, unavailable()
		}
		if len(document.Application) > 64<<10 || len(document.Input) > 64<<10 {
			return Mutation{}, Problem(413, "specification_too_large", "Application specification exceeds 64 KiB.")
		}
	}
	return Mutation{Record: r, ExpectedVersion: version}, nil
}

func idempotencyID(p Principal, operation, key string) (RecordID, error) {
	if len(key) == 0 || len(key) > 256 || strings.TrimSpace(key) == "" || strings.ContainsFunc(key, unicode.IsControl) {
		return RecordID{}, Problem(400, "invalid_idempotency_key", "A nonempty Idempotency-Key of at most 256 characters is required.")
	}
	return RecordID{Kind: IdempotencyKind, ParentID: p.UserID, ID: operation + "\x00" + Hash(key)}, nil
}

func (s *Service) idempotency(ctx context.Context, id RecordID, operation, hash string) (IdempotencyRecord, bool, error) {
	r, err := s.repo.Read(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return IdempotencyRecord{}, false, nil
	}
	if err != nil {
		return IdempotencyRecord{}, false, unavailable()
	}
	result, err := Decode[IdempotencyRecord](r)
	if err != nil || result.PrincipalID != id.ParentID || result.Operation != operation || result.ApplicationID == "" {
		return IdempotencyRecord{}, false, unavailable()
	}
	if result.RequestHash != hash {
		return IdempotencyRecord{}, false, Problem(409, "idempotency_conflict", "This idempotency key was already used for a different request.")
	}
	return result, true, nil
}

func (s *Service) descriptor(ctx context.Context, t TargetPolicy) (TargetDescriptor, bool, error) {
	r, err := s.repo.Read(ctx, RecordID{Kind: TargetKind, ID: t.ID})
	if errors.Is(err, ErrNotFound) {
		return TargetDescriptor{}, false, nil
	}
	if err != nil {
		return TargetDescriptor{}, false, unavailable()
	}
	d, err := Decode[TargetDescriptor](r)
	if err != nil || d.ID != t.ID {
		return TargetDescriptor{}, false, unavailable()
	}
	age := time.Since(d.HeartbeatAt)
	ready := d.ConfigHash == t.ConfigHash && d.ProviderName != "" && age >= 0 && age < 60*time.Second
	return d, ready, nil
}

func (s *Service) validate(ctx context.Context, id string, input ApplicationInput) (deploy.Application, error) {
	t, ok := s.targets[input.TargetID]
	if !ok {
		return deploy.Application{}, Problem(422, "invalid_target", "Select an enabled target.")
	}
	app, err := MapApplication(id, input, t)
	if err != nil {
		return deploy.Application{}, err
	}
	if err := s.requireApprovedSource(ctx, t, input.Source.URL); err != nil {
		return deploy.Application{}, err
	}
	d, ready, err := s.descriptor(ctx, t)
	if err != nil {
		return deploy.Application{}, err
	}
	if !ready {
		return deploy.Application{}, Problem(503, "target_unavailable", "The target worker is not ready for this configuration.")
	}
	if err := deploy.ValidateApplication(t.DeployConfig, &app, d.ProviderName, d.Capabilities); err != nil {
		return deploy.Application{}, &Error{Status: 422, Code: "invalid_specification", Message: "The specification is not supported by this target.", FieldErrors: map[string]string{"specification": "Check execution, schedule, data and exposure settings against the target options."}}
	}
	data, err := json.Marshal(app)
	if err != nil {
		return deploy.Application{}, Problem(422, "invalid_specification", "The specification is invalid.")
	}
	if len(data) > 64<<10 {
		return deploy.Application{}, Problem(413, "specification_too_large", "Application specification exceeds 64 KiB.")
	}
	return app, nil
}

func (s *Service) claimHostname(ctx context.Context, appID, targetID, hostname string) (Mutation, error) {
	id := RecordID{Kind: HostnameKind, ParentID: targetID, ID: hostname}
	_, err := s.repo.Read(ctx, id)
	if err == nil {
		return Mutation{}, Problem(409, "hostname_conflict", "The requested hostname is already reserved.")
	}
	if !errors.Is(err, ErrNotFound) {
		return Mutation{}, unavailable()
	}
	return mutation(id, 0, HostnameReservation{TargetID: targetID, Hostname: hostname, ApplicationID: appID})
}

// CreateApplication atomically records owned intent, route claims and idempotent creation.
func (s *Service) CreateApplication(ctx context.Context, p Principal, input ApplicationInput, key string) (ApplicationView, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return ApplicationView{}, err
	}
	if err := requireScope(p, ApplicationsWrite); err != nil {
		return ApplicationView{}, err
	}
	if !p.Admin && p.Role == RoleMember {
		return ApplicationView{}, Problem(403, "forbidden", "Your role does not permit creating applications. Ask an administrator for the application owner role.")
	}
	const operation = "applications.create"
	idemID, err := idempotencyID(p, operation, key)
	if err != nil {
		return ApplicationView{}, err
	}
	hash, err := requestHash(input)
	if err != nil {
		return ApplicationView{}, err
	}
	if result, found, err := s.idempotency(ctx, idemID, operation, hash); err != nil {
		return ApplicationView{}, err
	} else if found {
		return s.replayedApplication(ctx, p, result)
	}
	if err := validateCategory(input.Category, ""); err != nil {
		return ApplicationView{}, err
	}
	id := NewID()
	input = withKeyValueDefaults(input)
	input = withRelationalDefaults(input, deploy.Database{})
	mapped, err := s.validate(ctx, id, input)
	if err != nil {
		return ApplicationView{}, err
	}
	now := time.Now().UTC()
	app := ApplicationRecord{ID: id, Owners: []ApplicationOwner{{Kind: OwnerUser, ID: p.UserID}}, TargetID: input.TargetID, Revision: 1, Input: input, Application: mapped, CreatedAt: now, UpdatedAt: now}
	hostname := EffectiveHostname(id, input)
	if hostname != "" {
		app.ReservedHostnames = []string{hostname}
	}
	appMutation, err := mutation(RecordID{Kind: ApplicationKind, ID: id}, 0, app)
	if err != nil {
		return ApplicationView{}, err
	}
	idemMutation, err := mutation(idemID, 0, IdempotencyRecord{PrincipalID: p.UserID, Operation: operation, RequestHash: hash, ApplicationID: id})
	if err != nil {
		return ApplicationView{}, err
	}
	index, err := OwnerIndexMutations(id, nil, app.Owners, nil)
	if err != nil {
		return ApplicationView{}, unavailable()
	}
	mutations := append([]Mutation{appMutation, idemMutation}, index...)
	if hostname != "" {
		claim, err := s.claimHostname(ctx, id, input.TargetID, hostname)
		if err != nil {
			// A concurrent identical create can win the hostname before this read.
			if result, found, readErr := s.idempotency(ctx, idemID, operation, hash); readErr != nil {
				return ApplicationView{}, readErr
			} else if found {
				return s.replayedApplication(ctx, p, result)
			}
			return ApplicationView{}, err
		}
		mutations = append(mutations, claim)
	}
	if err := s.repo.Commit(auditPrincipal(ctx, p, "application.create", "application:"+id), mutations); err != nil {
		if !errors.Is(err, ErrConflict) {
			return ApplicationView{}, unavailable()
		}
		if result, found, err := s.idempotency(ctx, idemID, operation, hash); err != nil {
			return ApplicationView{}, err
		} else if found {
			return s.replayedApplication(ctx, p, result)
		}
		if hostname != "" {
			if _, err := s.claimHostname(ctx, id, input.TargetID, hostname); err != nil {
				return ApplicationView{}, err
			}
		}
		return ApplicationView{}, Problem(409, "conflict", "The application changed concurrently. Retry with the same idempotency key.")
	}
	return s.applicationView(ctx, p, app)
}

func (s *Service) replayedApplication(ctx context.Context, p Principal, result IdempotencyRecord) (ApplicationView, error) {
	app, _, err := s.application(ctx, p, result.ApplicationID)
	if err != nil {
		return ApplicationView{}, err
	}
	return s.applicationView(ctx, p, app)
}

// UpdateApplication replaces owned intent only at the caller's exact observed revision.
func (s *Service) UpdateApplication(ctx context.Context, p Principal, id string, input ApplicationInput, revision int64) (ApplicationView, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return ApplicationView{}, err
	}
	app, r, err := s.application(ctx, p, id)
	if err != nil {
		return ApplicationView{}, err
	}
	if err := requireScope(p, ApplicationsWrite); err != nil {
		return ApplicationView{}, err
	}
	if revision < 1 {
		return ApplicationView{}, Problem(400, "invalid_revision", "A positive If-Match revision is required.")
	}
	if app.Revision != revision {
		return ApplicationView{}, revisionConflict()
	}
	if !app.DeletionRequestedAt.IsZero() {
		return ApplicationView{}, deletionConflict()
	}
	if app.ActiveDeploymentID != "" {
		return ApplicationView{}, activeConflict()
	}
	if input.TargetID != app.TargetID {
		return ApplicationView{}, Problem(422, "immutable_target", "An application's target cannot change.")
	}
	if err := validateCategory(input.Category, app.Input.Category); err != nil {
		return ApplicationView{}, err
	}
	input = withKeyValueDefaults(input)
	input = withRelationalDefaults(input, app.Application.Database)
	mapped, err := s.validate(ctx, id, input)
	if err != nil {
		return ApplicationView{}, err
	}
	var mutations []Mutation
	oldHostname, newHostname := EffectiveHostname(id, app.Input), EffectiveHostname(id, input)
	if oldHostname != newHostname {
		held := append([]string(nil), app.ReservedHostnames...)
		if len(held) == 0 && oldHostname != "" {
			held = []string{oldHostname}
		}
		if app.LatestDeploymentID == "" {
			// A never-submitted draft cannot have published a route.
			for _, hostname := range held {
				reservation, err := s.repo.Read(ctx, RecordID{Kind: HostnameKind, ParentID: app.TargetID, ID: hostname})
				if err != nil {
					return ApplicationView{}, unavailable()
				}
				value, err := Decode[HostnameReservation](reservation)
				if err != nil || value.ApplicationID != id {
					return ApplicationView{}, unavailable()
				}
				mutations = append(mutations, Mutation{Record: reservation, ExpectedVersion: reservation.Version, Delete: true})
			}
			held = nil
		}
		alreadyHeld := false
		for _, hostname := range held {
			if hostname == newHostname {
				alreadyHeld = true
				break
			}
		}
		if newHostname != "" && !alreadyHeld {
			if len(held) >= 64 {
				return ApplicationView{}, Problem(422, "pending_hostnames", "Deploy the current specification successfully before reserving another hostname.")
			}
			claim, err := s.claimHostname(ctx, id, app.TargetID, newHostname)
			if err != nil {
				return ApplicationView{}, err
			}
			mutations = append(mutations, claim)
			held = append(held, newHostname)
		}
		app.ReservedHostnames = held
	}
	// Update only the editable fields. Every existing output, including partial
	// artifacts and last successful runtime state, survives a specification edit.
	app.Application.Name = mapped.Name
	app.Application.Source = mapped.Source
	app.Application.Workload = mapped.Workload
	app.Application.Execution = mapped.Execution
	app.Application.Schedule = mapped.Schedule
	app.Application.Resources = mapped.Resources
	app.Application.Replicas = mapped.Replicas
	app.Application.Port = mapped.Port
	app.Application.Database = mapped.Database
	app.Application.Bucket = mapped.Bucket
	app.Application.Routes = mapped.Routes
	app.Input = input
	app.Revision++
	app.UpdatedAt = time.Now().UTC()
	update, err := mutation(r.RecordID, r.Version, app)
	if err != nil {
		return ApplicationView{}, err
	}
	mutations = append(mutations, update)
	if err := s.repo.Commit(auditPrincipal(ctx, p, "application.update", "application:"+id), mutations); err != nil {
		if !errors.Is(err, ErrConflict) {
			return ApplicationView{}, unavailable()
		}
		current, _, err := s.application(ctx, p, id)
		if err != nil {
			return ApplicationView{}, err
		}
		if current.ActiveDeploymentID != "" {
			return ApplicationView{}, activeConflict()
		}
		if current.Revision != revision {
			return ApplicationView{}, revisionConflict()
		}
		return ApplicationView{}, Problem(409, "hostname_conflict", "The hostname reservation changed concurrently.")
	}
	return s.applicationView(ctx, p, app)
}

// GetApplication returns the caller-authorized projection of one application.
func (s *Service) GetApplication(ctx context.Context, p Principal, id string) (ApplicationView, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return ApplicationView{}, err
	}
	app, _, err := s.application(ctx, p, id)
	if err != nil {
		return ApplicationView{}, err
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return ApplicationView{}, err
	}
	return s.applicationView(ctx, p, app)
}

func queryError(err error) error {
	if errors.Is(err, ErrInvalidCursor) {
		return Problem(400, "invalid_cursor", "The pagination cursor is invalid for this request.")
	}
	return unavailable()
}

func listLimit(options ListOptions) (int, error) {
	if options.Limit < 0 || options.Limit > 100 || len(options.Cursor) > 4096 || strings.ContainsFunc(options.Cursor, unicode.IsControl) {
		return 0, Problem(400, "invalid_pagination", "Limit must be between 1 and 100 and cursor must be valid.")
	}
	if options.Limit == 0 {
		return 50, nil
	}
	return options.Limit, nil
}

// ListApplications pages owned applications; All requires current administrator eligibility.
func (s *Service) ListApplications(ctx context.Context, p Principal, options ListOptions) (Page[ApplicationView], error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return Page[ApplicationView]{}, err
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return Page[ApplicationView]{}, err
	}
	if options.All && !p.Admin {
		return Page[ApplicationView]{}, Problem(403, "forbidden", "Administrator access is required to list all applications.")
	}
	limit, err := listLimit(options)
	if err != nil {
		return Page[ApplicationView]{}, err
	}
	if !options.All {
		return s.listOwnedApplications(ctx, p, limit, options.Cursor)
	}
	page, err := s.repo.Query(ctx, Query{Kind: ApplicationKind, Limit: limit, Cursor: options.Cursor})
	if err != nil {
		return Page[ApplicationView]{}, queryError(err)
	}
	ids := make([]string, 0, len(page.Records))
	for _, row := range page.Records {
		ids = append(ids, row.ID)
	}
	return s.applicationPage(ctx, p, ids, page.Cursor)
}

// listOwnedApplications pages the applications a principal owns directly or
// through a group, from the owner index.
func (s *Service) listOwnedApplications(ctx context.Context, p Principal, limit int, cursor string) (Page[ApplicationView], error) {
	ids, err := s.ownedApplicationIDs(ctx, p)
	if err != nil {
		return Page[ApplicationView]{}, err
	}
	page, next, err := ownedPage(p, ids, cursor, limit)
	if err != nil {
		return Page[ApplicationView]{}, err
	}
	return s.applicationPage(ctx, p, page, next)
}

// applicationPage reads and authorizes each listed application. An index entry
// can briefly outlive a removed owner, so a row the caller no longer owns is
// skipped rather than an error.
func (s *Service) applicationPage(ctx context.Context, p Principal, ids []string, cursor string) (Page[ApplicationView], error) {
	result := Page[ApplicationView]{Items: make([]ApplicationView, 0, len(ids)), Cursor: cursor}
	for _, id := range ids {
		app, _, err := s.application(ctx, p, id)
		if err != nil {
			var problem *Error
			if errors.As(err, &problem) && problem.Status == 404 {
				continue
			}
			return Page[ApplicationView]{}, err
		}
		view, err := s.applicationView(ctx, p, app)
		if err != nil {
			return Page[ApplicationView]{}, err
		}
		result.Items = append(result.Items, view)
	}
	return result, nil
}

// SubmitDeployment atomically accepts one immutable revision without starting request-owned work.
func (s *Service) SubmitDeployment(ctx context.Context, p Principal, appID string, input SubmitDeploymentInput, key string) (DeploymentAccepted, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return DeploymentAccepted{}, err
	}
	app, r, err := s.application(ctx, p, appID)
	if err != nil {
		return DeploymentAccepted{}, err
	}
	if err := requireScope(p, DeploymentsWrite); err != nil {
		return DeploymentAccepted{}, err
	}
	const operation = "deployments.create"
	idemID, err := idempotencyID(p, operation, key)
	if err != nil {
		return DeploymentAccepted{}, err
	}
	hash, err := requestHash(struct {
		ApplicationID string                `json:"applicationId"`
		Input         SubmitDeploymentInput `json:"input"`
	}{appID, input})
	if err != nil {
		return DeploymentAccepted{}, err
	}
	if result, found, err := s.idempotency(ctx, idemID, operation, hash); err != nil {
		return DeploymentAccepted{}, err
	} else if found {
		return s.replayedDeployment(ctx, appID, result)
	}
	if input.ApplicationRevision < 1 {
		return DeploymentAccepted{}, Problem(400, "invalid_revision", "A positive application revision is required.")
	}
	if app.Revision != input.ApplicationRevision {
		return DeploymentAccepted{}, revisionConflict()
	}
	if !app.DeletionRequestedAt.IsZero() {
		return DeploymentAccepted{}, deletionConflict()
	}
	if app.ActiveDeploymentID != "" {
		return DeploymentAccepted{}, activeConflict()
	}
	if _, err := s.validate(ctx, appID, app.Input); err != nil {
		return DeploymentAccepted{}, err
	}
	return s.enqueue(ctx, p, app, r, enqueueRequest{idemID: idemID, operation: operation, hash: hash, revision: input.ApplicationRevision})
}

// enqueueRequest is the idempotency identity of one deployment submission and
// the optional changes to secrets it carries.
type enqueueRequest struct {
	idemID    RecordID
	operation string
	hash      string
	revision  int64
	// prepare, when set, amends the new deployment and the application in the
	// same commit, before either is written. It receives the deployment's ID.
	prepare func(d *DeploymentRecord, app *ApplicationRecord) error
	// extra mutations commit atomically with the enqueue, such as ending the
	// operation a teardown supersedes.
	extra []Mutation
}

// enqueue atomically records deployment intent, the application's active
// pointer, and the idempotency result. Callers have already checked access,
// revision, the active lock, and the specification.
func (s *Service) enqueue(ctx context.Context, p Principal, app ApplicationRecord, r Record, req enqueueRequest) (DeploymentAccepted, error) {
	appID := app.ID
	now := time.Now().UTC()
	d := DeploymentRecord{ID: NewID(), ApplicationID: appID, RequesterUserID: p.UserID, Requester: p, ApplicationRevision: app.Revision, TargetID: app.TargetID, Application: app.Application, RequestedSourceRef: app.Input.Source.Ref, State: Queued, Message: "Deployment queued.", Artifacts: app.Application.Artifacts, CreatedAt: now}
	if req.prepare != nil {
		if err := req.prepare(&d, &app); err != nil {
			return DeploymentAccepted{}, err
		}
	}
	d.Application.EnvSecrets = secretNames(app.Secrets)
	app.ActiveDeploymentID = d.ID
	app.LatestDeploymentID = d.ID
	app.UpdatedAt = now
	appMutation, err := mutation(r.RecordID, r.Version, app)
	if err != nil {
		return DeploymentAccepted{}, err
	}
	deploymentMutation, err := mutation(RecordID{Kind: DeploymentKind, ParentID: appID, ID: d.ID}, 0, d)
	if err != nil {
		return DeploymentAccepted{}, err
	}
	idemMutation, err := mutation(req.idemID, 0, IdempotencyRecord{PrincipalID: p.UserID, Operation: req.operation, RequestHash: req.hash, ApplicationID: appID, DeploymentID: d.ID})
	if err != nil {
		return DeploymentAccepted{}, err
	}
	if err := s.repo.Commit(auditPrincipal(ctx, p, req.operation, "application:"+appID), append([]Mutation{appMutation, deploymentMutation, idemMutation}, req.extra...)); err != nil {
		if !errors.Is(err, ErrConflict) {
			return DeploymentAccepted{}, unavailable()
		}
		if result, found, err := s.idempotency(ctx, req.idemID, req.operation, req.hash); err != nil {
			return DeploymentAccepted{}, err
		} else if found {
			return s.replayedDeployment(ctx, appID, result)
		}
		current, _, err := s.application(ctx, p, appID)
		if err != nil {
			return DeploymentAccepted{}, err
		}
		if current.ActiveDeploymentID != "" {
			return DeploymentAccepted{}, activeConflict()
		}
		if current.Revision != req.revision {
			return DeploymentAccepted{}, revisionConflict()
		}
		return DeploymentAccepted{}, Problem(409, "conflict", "The application changed concurrently. Retry with the same idempotency key.")
	}
	return accepted(d), nil
}

func accepted(d DeploymentRecord) DeploymentAccepted {
	return DeploymentAccepted{DeploymentID: d.ID, ApplicationID: d.ApplicationID, State: d.State, StatusURL: "/api/v1/deployments/" + d.ID, PollAfterMs: 2000}
}
func (s *Service) replayedDeployment(ctx context.Context, appID string, result IdempotencyRecord) (DeploymentAccepted, error) {
	if result.ApplicationID != appID || result.DeploymentID == "" {
		return DeploymentAccepted{}, unavailable()
	}
	d, _, err := s.deployment(ctx, result.DeploymentID)
	if err != nil {
		return DeploymentAccepted{}, err
	}
	if d.ApplicationID != appID {
		return DeploymentAccepted{}, unavailable()
	}
	return accepted(d), nil
}

// GetDeployment checks access through its parent application before exposing safe progress.
func (s *Service) GetDeployment(ctx context.Context, p Principal, id string) (DeploymentView, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return DeploymentView{}, err
	}
	d, _, err := s.deployment(ctx, id)
	if err != nil {
		return DeploymentView{}, err
	}
	if _, _, err := s.application(ctx, p, d.ApplicationID); err != nil {
		return DeploymentView{}, err
	}
	if err := requireScope(p, DeploymentsRead); err != nil {
		return DeploymentView{}, err
	}
	return deploymentView(d), nil
}

// ListDeployments pages the authorized application's durable operation history,
// newest first. A limit therefore returns that many of the latest attempts.
func (s *Service) ListDeployments(ctx context.Context, p Principal, appID string, options ListOptions) (Page[DeploymentView], error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return Page[DeploymentView]{}, err
	}
	if _, _, err := s.application(ctx, p, appID); err != nil {
		return Page[DeploymentView]{}, err
	}
	if err := requireScope(p, DeploymentsRead); err != nil {
		return Page[DeploymentView]{}, err
	}
	limit, err := listLimit(options)
	if err != nil {
		return Page[DeploymentView]{}, err
	}
	page, err := s.repo.Query(ctx, Query{Kind: DeploymentKind, ApplicationID: appID, Limit: limit, Cursor: options.Cursor})
	if err != nil {
		return Page[DeploymentView]{}, queryError(err)
	}
	result := Page[DeploymentView]{Items: make([]DeploymentView, 0, len(page.Records)), Cursor: page.Cursor}
	for _, row := range page.Records {
		d, _, err := s.deployment(ctx, row.ID)
		if err != nil {
			return Page[DeploymentView]{}, err
		}
		if d.ApplicationID != appID {
			return Page[DeploymentView]{}, unavailable()
		}
		result.Items = append(result.Items, deploymentView(d))
	}
	return result, nil
}

// ListTargets combines operator policy with current worker readiness evidence.
// githubRepositorySuggestions collects repository URLs the worker synced
// onto non-suspended installations, keeping only those the target's source
// host allowlist accepts. A query failure yields no suggestions rather than
// failing the target list: the field is a convenience, and a pasted URL is
// still checked by requireApprovedSource.
func (s *Service) githubRepositorySuggestions(ctx context.Context, allowedHosts []string) []string {
	page, err := s.repo.Query(ctx, Query{Kind: GitHubInstallationKind, Limit: 100})
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var urls []string
	for _, r := range page.Records {
		inst, err := Decode[GitHubInstallationRecord](r)
		if err != nil || !inst.SuspendedAt.IsZero() {
			continue
		}
		for _, raw := range inst.Repositories {
			canonical, err := deploy.ValidateSourceURL(raw, allowedHosts)
			if err != nil || seen[canonical] {
				continue
			}
			seen[canonical] = true
			urls = append(urls, canonical)
		}
	}
	slices.Sort(urls)
	return urls
}

// ListTargets returns every target the caller may read, with the deployment
// options its worker currently advertises. A target whose worker is not ready
// is listed with no options.
func (s *Service) ListTargets(ctx context.Context, p Principal) ([]TargetView, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return nil, err
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return nil, err
	}
	result := make([]TargetView, 0, len(s.targets))
	for _, t := range s.targets {
		d, ready, err := s.descriptor(ctx, t)
		if err != nil {
			return nil, err
		}
		v := TargetView{ID: t.ID, Label: t.Label, Ready: ready, ExecutionModes: []string{}, ResourceSizes: slices.Clone(t.ResourceSizes), MaxReplicas: t.MaxReplicas, Repositories: slices.Clone(t.Repositories), DatabaseKinds: []string{}, BucketKinds: []string{}}
		if len(t.Repositories) == 0 {
			v.RepositorySuggestions = s.githubRepositorySuggestions(ctx, t.DeployConfig.AllowedSourceHosts)
		}
		if ready {
			c := d.Capabilities
			base := c.Has(compute.CapImageBuild) && c.Has(compute.CapImageRegistry) && c.Has(compute.CapContainerService)
			for _, mode := range t.ExecutionModes {
				if base && (mode == "service" || c.Has(compute.CapScheduledJob)) {
					v.ExecutionModes = append(v.ExecutionModes, mode)
				}
			}
			v.PublicExposure = t.PublicExposure && c.Has(compute.CapPlatformIngress) && c.Has(compute.CapIngressAuth) && t.DeployConfig.RouteDomain != "" && t.DeployConfig.RouteCertificate != "" && slices.Contains(v.ExecutionModes, "service")
			v.InternalExposure = c.Has(compute.CapPlatformIngress) && c.Has(compute.CapIngressAuth) && t.DeployConfig.InternalRouteDomain != "" && t.DeployConfig.InternalRouteCertificate != "" && slices.Contains(v.ExecutionModes, "service")
			if c.Has(compute.CapRelationalDatabase) && c.Has(compute.CapSecretStore) {
				v.DatabaseKinds = append(v.DatabaseKinds, string(deploy.DatabaseRelational))
			}
			if c.Has(compute.CapKeyValueTable) && c.Has(compute.CapWorkloadGrants) {
				v.DatabaseKinds = append(v.DatabaseKinds, string(deploy.DatabaseKeyValue))
			}
			if c.Has(compute.CapObjectStore) && c.Has(compute.CapWorkloadGrants) {
				v.BucketKinds = append(v.BucketKinds, string(deploy.BucketStandard))
				if c.Has(compute.CapObjectStoreZonal) {
					v.BucketKinds = append(v.BucketKinds, string(deploy.BucketZonal))
				}
			}
		}
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// RequestDetection validates a repository/ref against the same target policy
// MapApplication enforces at create time, then durably queues an advisory
// scan for the worker to perform. It never touches application or deployment
// state and takes no idempotency key: unlike SubmitDeployment, a duplicate
// request costs the worker one redundant, side-effect-free Git fetch rather
// than a second cloud resource, so there is nothing here an idempotency key
// would protect.
func (s *Service) RequestDetection(ctx context.Context, p Principal, targetID string, input DetectionInput) (DetectionAccepted, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return DetectionAccepted{}, err
	}
	if err := requireScope(p, ApplicationsWrite); err != nil {
		return DetectionAccepted{}, err
	}
	if !p.Admin && p.Role == RoleMember {
		return DetectionAccepted{}, Problem(403, "forbidden", "Your role does not permit requesting repository detection. Ask an administrator for the application owner role.")
	}
	t, ok := s.targets[targetID]
	if !ok {
		return DetectionAccepted{}, Problem(422, "invalid_target", "Select an enabled target.")
	}
	if err := s.requireApprovedSource(ctx, t, input.URL); err != nil {
		return DetectionAccepted{}, err
	}
	if _, err := deploy.ValidateSourceURL(input.URL, t.DeployConfig.AllowedSourceHosts); err != nil {
		return DetectionAccepted{}, Problem(422, "invalid_specification", "Repository URL is not permitted.")
	}
	if len(input.Ref) > 256 || strings.HasPrefix(input.Ref, "-") || strings.ContainsFunc(input.Ref, unicode.IsControl) {
		return DetectionAccepted{}, Problem(422, "invalid_specification", "Source ref is invalid.")
	}
	d := DetectionRecord{ID: NewID(), RequesterUserID: p.UserID, TargetID: targetID, URL: input.URL, Ref: input.Ref, State: DetectionQueued, CreatedAt: time.Now().UTC()}
	m, err := mutation(RecordID{Kind: DetectionKind, ID: d.ID}, 0, d)
	if err != nil {
		return DetectionAccepted{}, err
	}
	if err := s.repo.Commit(auditPrincipal(ctx, p, "detection.request", "detection:"+d.ID), []Mutation{m}); err != nil {
		return DetectionAccepted{}, unavailable()
	}
	return DetectionAccepted{DetectionID: d.ID, State: d.State, StatusURL: "/api/v1/detections/" + d.ID, PollAfterMs: 1000}, nil
}

// GetDetection returns an advisory scan only to the requester who queued it
// (or an administrator), matching how deployment access is scoped to
// ownership rather than to possession of the ID.
func (s *Service) GetDetection(ctx context.Context, p Principal, id string) (DetectionView, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return DetectionView{}, err
	}
	r, err := s.repo.Read(ctx, RecordID{Kind: DetectionKind, ID: id})
	if errors.Is(err, ErrNotFound) {
		return DetectionView{}, notFound()
	}
	if err != nil {
		return DetectionView{}, unavailable()
	}
	d, err := Decode[DetectionRecord](r)
	if err != nil || d.ID != id {
		return DetectionView{}, unavailable()
	}
	if d.RequesterUserID != p.UserID && !p.Admin {
		return DetectionView{}, notFound()
	}
	if err := requireScope(p, ApplicationsRead); err != nil {
		return DetectionView{}, err
	}
	return detectionView(d), nil
}

func detectionView(d DetectionRecord) DetectionView {
	v := DetectionView{ID: d.ID, TargetID: d.TargetID, URL: d.URL, Ref: d.Ref, State: d.State, Terminal: d.State.Terminal(), Message: d.Message, CreatedAt: d.CreatedAt, FinishedAt: d.FinishedAt, PollAfterMs: 1000}
	if d.State == DetectionSucceeded {
		result := d.Result
		v.Result = &result
	}
	return v
}

// ResolveInterrupted releases an execution lock only after an audited administrator stop confirmation.
func (s *Service) ResolveInterrupted(ctx context.Context, p Principal, id string, input ResolveInterruptedInput) (DeploymentView, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return DeploymentView{}, err
	}
	d, r, err := s.deployment(ctx, id)
	if err != nil {
		return DeploymentView{}, err
	}
	app, appRecord, err := s.application(ctx, p, d.ApplicationID)
	if err != nil {
		return DeploymentView{}, err
	}
	if err := requireScope(p, DeploymentsWrite); err != nil {
		return DeploymentView{}, err
	}
	if !p.Admin {
		return DeploymentView{}, Problem(403, "forbidden", "Administrator access is required to resolve an interrupted deployment.")
	}
	reason := strings.TrimSpace(input.Reason)
	if !input.WorkerStopped || reason == "" || len(reason) > 2000 || strings.ContainsFunc(reason, unicode.IsControl) {
		return DeploymentView{}, Problem(422, "invalid_resolution", "Confirm the old worker and build container are stopped and provide a reason of at most 2000 characters.")
	}
	if d.State != Interrupted || app.ActiveDeploymentID != id || !d.ResolvedAt.IsZero() {
		return DeploymentView{}, Problem(409, "not_interrupted", "This operation does not hold an unresolved interrupted deployment lock.")
	}
	now := time.Now().UTC()
	d.ResolutionReason = reason
	d.SealedSecrets = nil
	d.ResolvedBy = p.UserID
	d.ResolvedAt = now
	app.ActiveDeploymentID = ""
	app.UpdatedAt = now
	deploymentMutation, err := mutation(r.RecordID, r.Version, d)
	if err != nil {
		return DeploymentView{}, err
	}
	appMutation, err := mutation(appRecord.RecordID, appRecord.Version, app)
	if err != nil {
		return DeploymentView{}, err
	}
	if err := s.repo.Commit(auditPrincipal(ctx, p, "deployment.resolveInterrupted", "deployment:"+id), []Mutation{deploymentMutation, appMutation}); err != nil {
		if errors.Is(err, ErrConflict) {
			return DeploymentView{}, Problem(409, "conflict", "The deployment changed concurrently. Reload its current state.")
		}
		return DeploymentView{}, unavailable()
	}
	return deploymentView(d), nil
}

// applicationStatus derives the lifecycle status from the latest deployment,
// and when the last successful deployment finished.
func (s *Service) applicationStatus(ctx context.Context, app ApplicationRecord) (string, time.Time, error) {
	status := "draft"
	lastDeployed := app.LastDeployedAt
	if !app.DeletionRequestedAt.IsZero() {
		return s.deletionStatus(ctx, app), lastDeployed, nil
	}
	if app.LatestDeploymentID == "" {
		return status, lastDeployed, nil
	}
	d, _, err := s.deployment(ctx, app.LatestDeploymentID)
	if err != nil {
		return "", time.Time{}, err
	}
	if d.ApplicationID != app.ID {
		return "", time.Time{}, unavailable()
	}
	// Records written before LastDeployedAt existed: the latest deployment is
	// the last successful one often enough to be worth the read already made.
	if lastDeployed.IsZero() && d.State == Succeeded && d.ID == app.LastSuccessfulDeploymentID {
		lastDeployed = d.FinishedAt
	}
	switch d.State {
	case Queued, Running:
		status = "deploying"
	case Succeeded:
		status = "running"
	case Failed:
		status = "failed"
	case Interrupted:
		status = "interrupted"
	default:
		return "", time.Time{}, unavailable()
	}
	return status, lastDeployed, nil
}

func (s *Service) applicationView(ctx context.Context, p Principal, app ApplicationRecord) (ApplicationView, error) {
	status, lastDeployed, err := s.applicationStatus(ctx, app)
	if err != nil {
		return ApplicationView{}, err
	}
	actions := []string{}
	if requireScope(p, ApplicationsRead) == nil {
		actions = append(actions, "applications:read")
	}
	if requireScope(p, DeploymentsRead) == nil {
		actions = append(actions, "deployments:read")
	}
	if app.ActiveDeploymentID == "" {
		if requireScope(p, ApplicationsWrite) == nil {
			actions = append(actions, "applications:write")
		}
		if requireScope(p, DeploymentsWrite) == nil {
			actions = append(actions, "deployments:write")
		}
	}
	if requireScope(p, ApplicationsWrite) == nil && deletable(status) {
		actions = append(actions, "applications:delete")
	}
	if requireScope(p, ApplicationsWrite) == nil && app.ActiveDeploymentID == "" && app.DeletionRequestedAt.IsZero() {
		actions = append(actions, "owners:write")
	}
	addresses := app.Addresses
	if len(addresses) == 0 {
		addresses = app.LastSuccessfulArtifacts.Addresses
	}
	url, scope := s.publishedURL(app)
	return ApplicationView{ID: app.ID, Owners: s.ownerViews(ctx, app.Owners, ownerNames{}), Revision: app.Revision, Specification: app.Input, Status: status, ActiveDeploymentID: app.ActiveDeploymentID, LatestDeploymentID: app.LatestDeploymentID, LastSuccessfulDeploymentID: app.LastSuccessfulDeploymentID, LastDeployedAt: optionalTime(lastDeployed), DeletionRequestedAt: optionalTime(app.DeletionRequestedAt), URL: url, URLScope: scope, Addresses: safeAddresses(addresses), PermittedActions: actions, CreatedAt: app.CreatedAt, UpdatedAt: app.UpdatedAt}, nil
}

// publishedURL is the address an application's first route is served at, and
// whether that is on the public or the internal ingress. It is composed the
// same way the deploy module composes the route's host.
func (s *Service) publishedURL(app ApplicationRecord) (string, string) {
	if len(app.Application.Routes) == 0 {
		return "", ""
	}
	r := app.Application.Routes[0]
	cfg := s.targets[app.TargetID].DeployConfig
	domain, scope := cfg.RouteDomain, "public"
	if r.Internal {
		domain, scope = cfg.InternalRouteDomain, "internal"
	}
	host := strings.ToLower(strings.TrimSpace(r.Hostname))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return "", ""
	}
	return "https://" + host + "." + domain, scope
}

func safeAddresses(addresses []string) []string {
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		u, err := url.Parse(address)
		if err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
			result = append(result, address)
		}
	}
	return result
}

func safeStep(step string) string {
	switch step {
	case "preflight", "source-prepared", "starting", "workload-identity", "image-repository", "source-fetch", "image-build", "relational-database", "key-value-table", "object-store", "attestation-rotate", "attestation-materials", "workload-retire", "workload-retire-ready", "scheduled-job", "service", "service-ready", "database-ingress", "complete", "image-registry", "secret-store", "secret-binding", "workload":
		return step
	}
	return ""
}

func deploymentView(d DeploymentRecord) DeploymentView {
	v := DeploymentView{ID: d.ID, ApplicationID: d.ApplicationID, ApplicationRevision: d.ApplicationRevision, TargetID: d.TargetID, Execution: string(d.Application.Execution), RequestedSourceRef: d.RequestedSourceRef, ResolvedCommit: d.ResolvedCommit, State: d.State, Terminal: d.State.Terminal(), Step: safeStep(d.Step), PartialResources: []string{}, Addresses: safeAddresses(d.Addresses), CreatedAt: d.CreatedAt, StartedAt: d.StartedAt, FinishedAt: d.FinishedAt, ResolutionReason: d.ResolutionReason}
	if len(v.Addresses) == 0 {
		v.Addresses = safeAddresses(d.Artifacts.Addresses)
	}
	v.Progress = v.Step
	v.Operation, v.PlannedSteps, v.Attempt = "deploy", []string{}, max(1, d.Attempt)
	if d.Operation == OperationTeardown {
		teardownView(d, &v)
		return v
	}
	switch d.State {
	case Queued:
		v.Message = "Deployment queued."
		v.PollAfterMs = 2000
	case Running:
		v.Message = "Deployment in progress."
		v.PollAfterMs = 2000
	case Succeeded:
		if d.Application.Execution == deploy.ExecutionScheduled {
			v.Message = "Schedule installed."
		} else {
			v.Message = "Deployment ready."
		}
	case Failed:
		if d.ErrorCode == "external_provisioning_failed" {
			v.ErrorCode = "external_provisioning_failed"
			v.Message = "The application is deployed, but external access provisioning failed. Check the integration and redeploy."
		} else {
			v.ErrorCode = "deployment_failed"
			v.Message = "Deployment failed. Partial resources may remain."
		}
	case Interrupted:
		v.ErrorCode = "deployment_interrupted"
		v.Message = "Deployment outcome is uncertain. Operator resolution is required."
		if !d.ResolvedAt.IsZero() {
			v.Message = "Operator acknowledged the stopped worker. The previous deployment outcome remains uncertain."
		}
	}
	a := d.Artifacts
	if a.Identity.ID != "" {
		v.PartialResources = append(v.PartialResources, "workload identity")
	}
	if a.Repository.ID != "" {
		v.PartialResources = append(v.PartialResources, "image repository")
	}
	if a.Image != "" {
		v.PartialResources = append(v.PartialResources, "container image")
	}
	if a.Workload.ID != "" {
		v.PartialResources = append(v.PartialResources, "workload")
	}
	if a.Bucket.ID != "" {
		v.PartialResources = append(v.PartialResources, "object storage")
	}
	if a.Relational.ID != "" {
		v.PartialResources = append(v.PartialResources, "relational database")
	}
	if a.KeyValue.ID != "" {
		v.PartialResources = append(v.PartialResources, "key-value table")
	}
	if len(a.Secrets) > 0 {
		v.PartialResources = append(v.PartialResources, "application secrets")
	}
	return v
}
