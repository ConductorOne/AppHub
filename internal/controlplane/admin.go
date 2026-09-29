// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/githubapp"
)

// This file is the Workspace: the admin-only surface for configuring the
// GitHub App and reading operator-named platform logs. Every method here
// additionally requires Principal.Admin, on top of the ordinary scope check
// every other Service method already enforces -- the same "requireScope,
// then also require Admin" shape ResolveInterrupted uses.

// GitHubAppKeyStore is the write side of the admin-managed GitHub App
// private key. Declared here, narrowed to exactly what this package calls,
// so that Service depends on an interface rather than an AWS-backed
// implementation: internal/boundary's aws-sdk-confined rule denies the AWS
// SDK to every package that is not a named provider boundary, and this one
// is not. internal/ghappkey.Store satisfies it.
//
// There is no method here that can return the key's value. That is not a
// convention this package promises to respect -- it is what makes the
// interface satisfiable only by a type that cannot leak the key back to a
// caller of this Service, independent of whether ghappkey's own
// implementation ever changes.
type GitHubAppKeyStore interface {
	Put(ctx context.Context, key credentials.Secret) error
	Delete(ctx context.Context) error
}

// LogGroup binds one operator-chosen display name to one CloudWatch log
// group name, mirroring serverconfig.LogGroupConfig -- declared again here so
// this package does not import serverconfig, the same reason GitHubAppKeyStore
// is an interface and not internal/ghappkey.Store.
type LogGroup struct {
	Name     string
	LogGroup string
}

// LogQuery bounds one log read, mirroring internal/logs.Query.
type LogQuery struct {
	Start, End    time.Time
	FilterPattern string
	NextToken     string
	Limit         int32
}

// LogEvent is one log line.
type LogEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	Message       string    `json:"message"`
	LogStreamName string    `json:"logStreamName"`
}

// LogResult is one page of matching events.
type LogResult struct {
	Events    []LogEvent `json:"events"`
	NextToken string     `json:"nextToken,omitempty"`
}

// LogReader is the read-only CloudWatch Logs port the Workspace's log viewer
// uses. internal/logs.Reader satisfies it.
type LogReader interface {
	Filter(ctx context.Context, logGroup string, q LogQuery) (LogResult, error)
}

// maskedSecret is what a caller sends in GitHubAppConfigInput.PrivateKey to
// mean "keep the currently stored key". It can never collide with a real PEM
// (which starts with "-----BEGIN"), and a caller sends it back exactly
// because GetGitHubAppStatus never returns the real key for a form to echo.
const maskedSecret = "MASKED:****"

// GitHubAppConfigInput is a full replacement of the admin-managed GitHub
// App's configuration -- not a patch, the same rule ApplicationInput's PUT
// follows. PrivateKey is three-valued by content: maskedSecret keeps the
// existing key, "" clears it, anything else replaces it after validation.
// Changing APIBaseURL while retaining a key is forbidden: a retained key
// must never sign requests sent to a newly chosen destination.
type GitHubAppConfigInput struct {
	AppID      int64  `json:"appId"`
	APIBaseURL string `json:"apiBaseUrl,omitempty"`
	PrivateKey string `json:"privateKey"`
}

// GitHubAppStatusView exposes the admin-managed GitHub App's safe status: an
// App ID, whether a key is stored, and the installations the worker has
// synced. It never contains the key itself.
type GitHubAppStatusView struct {
	// Available reports whether this Service was constructed with a GitHub
	// App key store at all (see WithGitHubAppAdmin) -- always true for a real
	// deployment, which cmd/apphub always supplies one for. False means every
	// other field is zero and the Workspace should show setup instructions
	// rather than a form; only reachable from a Service built without that
	// option, e.g. in tests.
	Available            bool                     `json:"available"`
	Configured           bool                     `json:"configured"`
	AppID                int64                    `json:"appId,omitempty"`
	APIBaseURL           string                   `json:"apiBaseUrl,omitempty"`
	PrivateKeyConfigured bool                     `json:"privateKeyConfigured"`
	UpdatedAt            time.Time                `json:"updatedAt,omitempty"`
	UpdatedBy            string                   `json:"updatedBy,omitempty"`
	Installations        []GitHubInstallationView `json:"installations"`
}

// GitHubInstallationView is the safe projection of a synced installation.
type GitHubInstallationView struct {
	ID                  string            `json:"id"`
	AccountLogin        string            `json:"accountLogin"`
	AccountType         string            `json:"accountType"`
	RepositorySelection string            `json:"repositorySelection"`
	Permissions         map[string]string `json:"permissions"`
	HTMLURL             string            `json:"htmlUrl,omitempty"`
	SuspendedAt         time.Time         `json:"suspendedAt,omitempty"`
	SyncedAt            time.Time         `json:"syncedAt"`
}

func installationView(r GitHubInstallationRecord) GitHubInstallationView {
	return GitHubInstallationView{ID: r.ID, AccountLogin: r.AccountLogin, AccountType: r.AccountType, RepositorySelection: r.RepositorySelection, Permissions: r.Permissions, HTMLURL: r.HTMLURL, SuspendedAt: r.SuspendedAt, SyncedAt: r.SyncedAt}
}

// DirectoryEntitlementView is the safe projection of a synced directory
// entitlement.
type DirectoryEntitlementView struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"displayName"`
	Description string    `json:"description,omitempty"`
	AppID       string    `json:"appId,omitempty"`
	Bindable    bool      `json:"bindable"`
	SyncedAt    time.Time `json:"syncedAt"`
}

func directoryEntitlementView(r DirectoryEntitlementRecord) DirectoryEntitlementView {
	// The record and view are identical today. A straight conversion, not a
	// field-by-field copy, so the two staying identical is checked by the
	// compiler rather than left to a reviewer to notice, and the moment they
	// diverge -- the record gaining an internal-only field, say -- this stops
	// compiling instead of silently leaking it into the view.
	return DirectoryEntitlementView(r)
}

// ListDirectoryEntitlements returns every ConductorOne group synced for
// role assignment and feature-flag targeting, or an empty list when none is
// configured or none has synced yet -- there is no separate "not configured"
// signal for this read-only surface, the same way ListLogGroups reports an
// unconfigured observability surface as an empty list rather than an error.
func (s *Service) ListDirectoryEntitlements(ctx context.Context, p Principal) ([]DirectoryEntitlementView, error) {
	if _, err := s.requireAdmin(ctx, p, ApplicationsRead); err != nil {
		return nil, err
	}
	ents, err := s.listBindableDirectoryEntitlements(ctx)
	if err != nil {
		return nil, unavailable()
	}
	views := make([]DirectoryEntitlementView, 0, len(ents))
	for _, ent := range ents {
		views = append(views, directoryEntitlementView(ent))
	}
	sort.Slice(views, func(i, j int) bool { return views[i].DisplayName < views[j].DisplayName })
	return views, nil
}

// listBindableDirectoryEntitlements pages through the synced catalog and
// keeps only ConductorOne groups. A previous full-catalog sync can leave
// thousands of non-group rows; the Role assignment picker must not show them.
func (s *Service) listBindableDirectoryEntitlements(ctx context.Context) ([]DirectoryEntitlementRecord, error) {
	var out []DirectoryEntitlementRecord
	cursor := ""
	for range 200 {
		page, err := s.repo.Query(ctx, Query{Kind: DirectoryEntitlementKind, Limit: 100, Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, r := range page.Records {
			ent, err := Decode[DirectoryEntitlementRecord](r)
			if err != nil || !ent.Bindable {
				continue
			}
			out = append(out, ent)
		}
		if page.Cursor == "" {
			return out, nil
		}
		cursor = page.Cursor
	}
	return out, nil
}

// RoleMappingInput sets the role one directory entitlement maps to.
type RoleMappingInput struct {
	Role string `json:"role"`
}

// RoleMappingView is one RoleMappingRecord joined with the entitlement's
// synced display name, when still available. An entitlement the directory
// stopped syncing keeps its mapping (an administrator may still see and
// delete it) but shows no display name.
type RoleMappingView struct {
	EntitlementID string    `json:"entitlementId"`
	DisplayName   string    `json:"displayName,omitempty"`
	Role          string    `json:"role"`
	UpdatedAt     time.Time `json:"updatedAt"`
	UpdatedBy     string    `json:"updatedBy"`
}

func (s *Service) directoryEntitlement(ctx context.Context, id string) (DirectoryEntitlementRecord, error) {
	r, err := s.repo.Read(ctx, RecordID{Kind: DirectoryEntitlementKind, ID: id})
	if err != nil {
		return DirectoryEntitlementRecord{}, err
	}
	ent, err := Decode[DirectoryEntitlementRecord](r)
	if err != nil {
		return DirectoryEntitlementRecord{}, unavailable()
	}
	return ent, nil
}

// ListRoleMappings returns every directory entitlement an administrator has
// mapped to an AppHub role.
func (s *Service) ListRoleMappings(ctx context.Context, p Principal) ([]RoleMappingView, error) {
	if _, err := s.requireAdmin(ctx, p, ApplicationsRead); err != nil {
		return nil, err
	}
	page, err := s.repo.Query(ctx, Query{Kind: RoleMappingKind, Limit: 100})
	if err != nil {
		return nil, unavailable()
	}
	views := make([]RoleMappingView, 0, len(page.Records))
	for _, r := range page.Records {
		mapping, err := Decode[RoleMappingRecord](r)
		if err != nil {
			continue
		}
		view := RoleMappingView{EntitlementID: mapping.ID, Role: mapping.Role, UpdatedAt: mapping.UpdatedAt, UpdatedBy: mapping.UpdatedBy}
		if ent, err := s.directoryEntitlement(ctx, mapping.ID); err == nil {
			view.DisplayName = ent.DisplayName
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].EntitlementID < views[j].EntitlementID })
	return views, nil
}

// SetRoleMapping designates the AppHub role every identity holding a current
// ConductorOne grant on entitlementID resolves to. entitlementID must name a
// currently synced entitlement with Bindable set -- the "Group" the
// Workspace's Role assignment tab distinguishes from a finer-grained
// directory-synced entry, because only a group is a meaningful stand-in for
// organizational membership.
func (s *Service) SetRoleMapping(ctx context.Context, p Principal, entitlementID string, input RoleMappingInput) (RoleMappingView, error) {
	p, err := s.requireAdmin(ctx, p, ApplicationsWrite)
	if err != nil {
		return RoleMappingView{}, err
	}
	role := input.Role
	if !slices.Contains(MappableRoles, role) {
		return RoleMappingView{}, Problem(422, "invalid_specification", "Choose a known role.")
	}
	ent, err := s.directoryEntitlement(ctx, entitlementID)
	if errors.Is(err, ErrNotFound) {
		return RoleMappingView{}, Problem(422, "invalid_specification", "That entitlement is not currently synced.")
	}
	if err != nil {
		return RoleMappingView{}, unavailable()
	}
	if !ent.Bindable {
		return RoleMappingView{}, Problem(422, "invalid_specification", "Only entitlements synced as groups can be mapped to a role.")
	}

	recID := RecordID{Kind: RoleMappingKind, ID: entitlementID}
	var version int64
	existing, err := s.repo.Read(ctx, recID)
	switch {
	case err == nil:
		version = existing.Version
	case errors.Is(err, ErrNotFound):
		version = 0
	default:
		return RoleMappingView{}, unavailable()
	}
	rec := RoleMappingRecord{ID: entitlementID, Role: role, UpdatedAt: time.Now().UTC(), UpdatedBy: p.UserID}
	m, err := mutation(recID, version, rec)
	if err != nil {
		return RoleMappingView{}, err
	}
	if err := s.repo.Commit(auditPrincipal(ctx, p, "roleMapping.set", "roleMapping:"+entitlementID), []Mutation{m}); err != nil {
		if errors.Is(err, ErrConflict) {
			return RoleMappingView{}, Problem(409, "conflict", "The mapping changed concurrently. Reload and retry.")
		}
		return RoleMappingView{}, unavailable()
	}
	return RoleMappingView{EntitlementID: entitlementID, DisplayName: ent.DisplayName, Role: role, UpdatedAt: rec.UpdatedAt, UpdatedBy: rec.UpdatedBy}, nil
}

// DeleteRoleMapping removes a directory entitlement's role mapping. Every
// identity that previously resolved a role through it falls back to
// whatever its remaining mapped entitlements (if any) grant.
func (s *Service) DeleteRoleMapping(ctx context.Context, p Principal, entitlementID string) error {
	if _, err := s.requireAdmin(ctx, p, ApplicationsWrite); err != nil {
		return err
	}
	recID := RecordID{Kind: RoleMappingKind, ID: entitlementID}
	r, err := s.repo.Read(ctx, recID)
	if errors.Is(err, ErrNotFound) {
		return notFound()
	}
	if err != nil {
		return unavailable()
	}
	if err := s.repo.Commit(auditPrincipal(ctx, p, "roleMapping.delete", "roleMapping:"+entitlementID), []Mutation{{Record: Record{RecordID: recID}, ExpectedVersion: r.Version, Delete: true}}); err != nil {
		if errors.Is(err, ErrConflict) {
			return Problem(409, "conflict", "The mapping changed concurrently. Reload and retry.")
		}
		return unavailable()
	}
	return nil
}

// FeatureFlagInput sets one known feature flag's mode. GroupEntitlementIDs is
// required when Mode is FeatureFlagGroup and ignored otherwise.
type FeatureFlagInput struct {
	Mode                string   `json:"mode"`
	GroupEntitlementIDs []string `json:"groupEntitlementIds,omitempty"`
}

// FeatureFlagGroupView is one gating directory entitlement joined with its
// synced display name when that entitlement is still available.
type FeatureFlagGroupView struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName,omitempty"`
}

// FeatureFlagView is one known feature flag's current configuration, joined
// with each gating entitlement's synced display name when still available.
type FeatureFlagView struct {
	Key       string                 `json:"key"`
	Mode      string                 `json:"mode"`
	Groups    []FeatureFlagGroupView `json:"groups,omitempty"`
	UpdatedAt time.Time              `json:"updatedAt,omitempty"`
	UpdatedBy string                 `json:"updatedBy,omitempty"`
}

func (s *Service) featureFlagView(ctx context.Context, key string) FeatureFlagView {
	view := FeatureFlagView{Key: key, Mode: FeatureFlagOff}
	r, err := s.repo.Read(ctx, RecordID{Kind: FeatureFlagKind, ID: key})
	if err != nil {
		return view
	}
	rec, err := Decode[FeatureFlagRecord](r)
	if err != nil {
		return view
	}
	view.Mode, view.UpdatedAt, view.UpdatedBy = rec.Mode, rec.UpdatedAt, rec.UpdatedBy
	if rec.Mode != FeatureFlagGroup {
		return view
	}
	ids := rec.GatingGroupIDs()
	if len(ids) == 0 {
		return view
	}
	view.Groups = make([]FeatureFlagGroupView, 0, len(ids))
	for _, id := range ids {
		g := FeatureFlagGroupView{ID: id}
		if ent, err := s.directoryEntitlement(ctx, id); err == nil {
			g.DisplayName = ent.DisplayName
		}
		view.Groups = append(view.Groups, g)
	}
	return view
}

// ListFeatureFlags returns every known feature flag (KnownFeatureFlags),
// defaulting to FeatureFlagOff for a key an administrator has never
// configured -- there is no separate "unconfigured" signal, the same way
// ListDirectoryEntitlements reports an unconfigured directory as empty.
func (s *Service) ListFeatureFlags(ctx context.Context, p Principal) ([]FeatureFlagView, error) {
	if _, err := s.requireAdmin(ctx, p, ApplicationsRead); err != nil {
		return nil, err
	}
	views := make([]FeatureFlagView, 0, len(KnownFeatureFlags))
	for _, key := range KnownFeatureFlags {
		views = append(views, s.featureFlagView(ctx, key))
	}
	return views, nil
}

// SetFeatureFlag replaces one known feature flag's configuration. key must
// name a KnownFeatureFlags entry; a key an operator invented but nothing
// checks would be a flag with no effect. In FeatureFlagGroup mode,
// groupEntitlementIds must name currently synced, bindable directory
// entitlements -- the same requirement SetRoleMapping applies to its own
// entitlement argument, for the same reason: only a group is a meaningful
// stand-in for a population of identities. An identity holding any of the
// listed groups sees the feature.
func (s *Service) SetFeatureFlag(ctx context.Context, p Principal, key string, input FeatureFlagInput) (FeatureFlagView, error) {
	p, err := s.requireAdmin(ctx, p, ApplicationsWrite)
	if err != nil {
		return FeatureFlagView{}, err
	}
	if !slices.Contains(KnownFeatureFlags, key) {
		return FeatureFlagView{}, Problem(404, "not_found", "Unknown feature flag.")
	}
	if !slices.Contains(FeatureFlagModes, input.Mode) {
		return FeatureFlagView{}, Problem(422, "invalid_specification", "Choose a known mode.")
	}
	if input.Mode == FeatureFlagGroup && (key == FeatureProvisionAppCatalog || key == FeatureProvisionShortLink) {
		return FeatureFlagView{}, Problem(422, "invalid_specification", "Deployment integrations are workspace-wide and cannot be limited to groups.")
	}
	var groupEntitlementIDs []string
	if input.Mode == FeatureFlagGroup {
		ids := uniqueNonEmpty(input.GroupEntitlementIDs)
		if len(ids) == 0 {
			return FeatureFlagView{}, Problem(422, "invalid_specification", "Group mode requires at least one directory entitlement.")
		}
		for _, id := range ids {
			ent, err := s.directoryEntitlement(ctx, id)
			if errors.Is(err, ErrNotFound) {
				return FeatureFlagView{}, Problem(422, "invalid_specification", "That entitlement is not currently synced.")
			}
			if err != nil {
				return FeatureFlagView{}, unavailable()
			}
			if !ent.Bindable {
				return FeatureFlagView{}, Problem(422, "invalid_specification", "Only entitlements synced as groups can gate a feature.")
			}
		}
		groupEntitlementIDs = ids
	}

	recID := RecordID{Kind: FeatureFlagKind, ID: key}
	var version int64
	existing, err := s.repo.Read(ctx, recID)
	switch {
	case err == nil:
		version = existing.Version
	case errors.Is(err, ErrNotFound):
		version = 0
	default:
		return FeatureFlagView{}, unavailable()
	}
	rec := FeatureFlagRecord{ID: key, Mode: input.Mode, GroupEntitlementIDs: groupEntitlementIDs, UpdatedAt: time.Now().UTC(), UpdatedBy: p.UserID}
	m, err := mutation(recID, version, rec)
	if err != nil {
		return FeatureFlagView{}, err
	}
	if err := s.repo.Commit(auditPrincipal(ctx, p, "featureFlag.set", "featureFlag:"+key), []Mutation{m}); err != nil {
		if errors.Is(err, ErrConflict) {
			return FeatureFlagView{}, Problem(409, "conflict", "The flag changed concurrently. Reload and retry.")
		}
		return FeatureFlagView{}, unavailable()
	}
	return s.featureFlagView(ctx, key), nil
}

// MemberView is the safe projection of a persisted User, joined with the
// role and vulnerability-admin authority Eligibility currently resolves for
// their email -- role is never stored per user (see Eligibility.ResolveRole),
// so this is a live computation, not a cached field on User.
type MemberView struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Avatar    string    `json:"avatar"`
	Role      string    `json:"role"`
	VulnAdmin bool      `json:"vulnAdmin"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"createdAt"`
	// LastSeenAt is this user's record's last write, which happens on every
	// successful sign-in (see auth.Manager's session establishment) -- an
	// approximation of "last active", not a dedicated login-audit timestamp.
	LastSeenAt time.Time `json:"lastSeenAt"`
}

// ListMembers returns every AppHub user who has signed in at least once,
// most recently active first. There is no invite flow: an identity's User
// record is created automatically on its first admitted sign-in (see
// Eligibility.CheckPrincipal), so a person who has never signed in never
// appears here.
func (s *Service) ListMembers(ctx context.Context, p Principal) ([]MemberView, error) {
	if _, err := s.requireAdmin(ctx, p, ApplicationsRead); err != nil {
		return nil, err
	}
	page, err := s.repo.Query(ctx, Query{Kind: UserKind, Limit: 100})
	if err != nil {
		return nil, unavailable()
	}
	views := make([]MemberView, 0, len(page.Records))
	for _, r := range page.Records {
		u, err := Decode[User](r)
		if err != nil {
			continue
		}
		role, vulnAdmin := s.eligibility.ResolveRole(ctx, u.Email)
		views = append(views, MemberView{
			ID: u.ID, Email: u.Email, Name: u.Name, Avatar: u.Avatar,
			Role: role, VulnAdmin: vulnAdmin, Disabled: u.Disabled,
			CreatedAt: u.CreatedAt, LastSeenAt: u.UpdatedAt,
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].LastSeenAt.After(views[j].LastSeenAt) })
	return views, nil
}

func (s *Service) requireAdmin(ctx context.Context, p Principal, scope string) (Principal, error) {
	p, err := s.principal(ctx, p)
	if err != nil {
		return Principal{}, err
	}
	if err := requireScope(p, scope); err != nil {
		return Principal{}, err
	}
	if !p.Admin {
		return Principal{}, Problem(403, "forbidden", "Administrator access is required.")
	}
	return p, nil
}

func (s *Service) githubAppConfig(ctx context.Context) (GitHubAppConfigRecord, int64, error) {
	r, err := s.repo.Read(ctx, RecordID{Kind: GitHubAppConfigKind, ID: GitHubAppConfigID})
	if errors.Is(err, ErrNotFound) {
		return GitHubAppConfigRecord{ID: GitHubAppConfigID}, 0, nil
	}
	if err != nil {
		return GitHubAppConfigRecord{}, 0, unavailable()
	}
	cfg, err := Decode[GitHubAppConfigRecord](r)
	if err != nil || cfg.ID != GitHubAppConfigID {
		return GitHubAppConfigRecord{}, 0, unavailable()
	}
	return cfg, r.Version, nil
}

func (s *Service) listGitHubInstallations(ctx context.Context) ([]GitHubInstallationView, error) {
	page, err := s.repo.Query(ctx, Query{Kind: GitHubInstallationKind, Limit: 100})
	if err != nil {
		return nil, unavailable()
	}
	views := make([]GitHubInstallationView, 0, len(page.Records))
	for _, r := range page.Records {
		inst, err := Decode[GitHubInstallationRecord](r)
		if err != nil {
			continue
		}
		views = append(views, installationView(inst))
	}
	sort.Slice(views, func(i, j int) bool { return views[i].AccountLogin < views[j].AccountLogin })
	return views, nil
}

func (s *Service) githubAppStatusView(ctx context.Context, cfg GitHubAppConfigRecord) (GitHubAppStatusView, error) {
	installs, err := s.listGitHubInstallations(ctx)
	if err != nil {
		return GitHubAppStatusView{}, err
	}
	return GitHubAppStatusView{
		Available: true, Configured: cfg.AppID > 0 && cfg.PrivateKeyConfigured,
		AppID: cfg.AppID, APIBaseURL: cfg.APIBaseURL, PrivateKeyConfigured: cfg.PrivateKeyConfigured,
		UpdatedAt: cfg.UpdatedAt, UpdatedBy: cfg.UpdatedBy, Installations: installs,
	}, nil
}

// GetGitHubAppStatus reads the admin-managed GitHub App's safe status:
// identity, whether a key is stored, and synced installations. It never
// returns the key.
func (s *Service) GetGitHubAppStatus(ctx context.Context, p Principal) (GitHubAppStatusView, error) {
	if _, err := s.requireAdmin(ctx, p, ApplicationsRead); err != nil {
		return GitHubAppStatusView{}, err
	}
	if s.githubAppKey == nil {
		return GitHubAppStatusView{}, nil
	}
	cfg, _, err := s.githubAppConfig(ctx)
	if err != nil {
		return GitHubAppStatusView{}, err
	}
	return s.githubAppStatusView(ctx, cfg)
}

// SetGitHubAppConfig replaces the admin-managed GitHub App's identity and,
// depending on input.PrivateKey, keeps, clears, or replaces its private key.
// A replacement key is validated (parseable RS256 material under the given
// App ID) before anything is written, and the key reaches
// internal/ghappkey.Store before the durable record is updated, so a
// crash between the two leaves an orphaned but harmless SSM value rather than
// a record that claims a key nothing backs.
func (s *Service) SetGitHubAppConfig(ctx context.Context, p Principal, input GitHubAppConfigInput) (GitHubAppStatusView, error) {
	p, err := s.requireAdmin(ctx, p, ApplicationsWrite)
	if err != nil {
		return GitHubAppStatusView{}, err
	}
	if s.githubAppKey == nil {
		return GitHubAppStatusView{}, Problem(503, "not_configured", "GitHub App admin storage is not configured on this deployment.")
	}
	if input.AppID <= 0 {
		return GitHubAppStatusView{}, Problem(422, "invalid_specification", "A positive App ID is required.")
	}
	if len(input.APIBaseURL) > 512 || strings.ContainsFunc(input.APIBaseURL, unicode.IsControl) {
		return GitHubAppStatusView{}, Problem(422, "invalid_specification", "API base URL is invalid.")
	}
	// Validate even when the key is kept or cleared: NewApp only validates the
	// URL on the fresh-key branch, but the worker will use this persisted URL.
	if _, err := githubapp.NormalizeBaseURL(input.APIBaseURL); err != nil {
		return GitHubAppStatusView{}, Problem(422, "invalid_specification", "API base URL is invalid.")
	}

	existing, version, err := s.githubAppConfig(ctx)
	if err != nil {
		return GitHubAppStatusView{}, err
	}

	switch input.PrivateKey {
	case maskedSecret:
		if !existing.PrivateKeyConfigured {
			return GitHubAppStatusView{}, Problem(422, "invalid_specification", "No private key is stored to keep.")
		}
		// Compare the stored value rather than only the normalized destination:
		// any URL edit requires a fresh key, including a manifest-created App
		// whose stored URL is empty (the github.com default).
		if input.APIBaseURL != existing.APIBaseURL {
			return GitHubAppStatusView{}, Problem(422, "invalid_specification", "Changing the API base URL requires a new private key.")
		}
	case "":
		if err := s.githubAppKey.Delete(ctx); err != nil {
			return GitHubAppStatusView{}, unavailable()
		}
		if existing.PrivateKeyConfigured && s.auditWriter != nil {
			if err := s.auditWriter.AppendAudit(ctx, p.UserID, "githubApp.privateKey.delete", "githubAppConfig:config", nil); err != nil {
				return GitHubAppStatusView{}, unavailable()
			}
		}
		existing.PrivateKeyConfigured = false
	default:
		secret := credentials.NewSecret(input.PrivateKey)
		if _, err := githubapp.NewApp(githubapp.AppConfig{AppID: input.AppID, PrivateKeyPEM: secret, BaseURL: input.APIBaseURL}); err != nil {
			return GitHubAppStatusView{}, Problem(422, "invalid_specification", "The private key or API base URL is invalid.")
		}
		if err := s.githubAppKey.Put(ctx, secret); err != nil {
			return GitHubAppStatusView{}, unavailable()
		}
		if s.auditWriter != nil {
			if err := s.auditWriter.AppendAudit(ctx, p.UserID, "githubApp.privateKey.replace", "githubAppConfig:config", nil); err != nil {
				return GitHubAppStatusView{}, unavailable()
			}
		}
		existing.PrivateKeyConfigured = true
	}

	existing.ID, existing.AppID, existing.APIBaseURL = GitHubAppConfigID, input.AppID, input.APIBaseURL
	existing.UpdatedAt, existing.UpdatedBy = time.Now().UTC(), p.UserID
	m, err := mutation(RecordID{Kind: GitHubAppConfigKind, ID: GitHubAppConfigID}, version, existing)
	if err != nil {
		return GitHubAppStatusView{}, err
	}
	if err := s.repo.Commit(auditPrincipal(ctx, p, "githubApp.config.set", "githubAppConfig:config"), []Mutation{m}); err != nil {
		if errors.Is(err, ErrConflict) {
			return GitHubAppStatusView{}, Problem(409, "conflict", "The configuration changed concurrently. Reload and retry.")
		}
		return GitHubAppStatusView{}, unavailable()
	}
	return s.githubAppStatusView(ctx, existing)
}

// GitHubAppManifestInput selects where to create the admin-managed GitHub
// App via the Manifest flow: the administrator's personal account
// (Organization empty) or a named organization.
type GitHubAppManifestInput struct {
	Organization string `json:"organization,omitempty"`
}

// GitHubAppManifestStart is what a browser needs to submit GitHub's App
// Manifest form: the JSON manifest itself (posted as the form's "manifest"
// field) and the URL to post it to, with State appended as that URL's own
// query parameter -- GitHub echoes State back on the redirect it issues once
// an administrator confirms creating the App, which
// CompleteGitHubAppManifest requires to match the token this call durably
// stored.
type GitHubAppManifestStart struct {
	ManifestJSON string `json:"manifestJson"`
	State        string `json:"state"`
	CreateURL    string `json:"createUrl"`
}

// githubAppManifest is the JSON body GitHub's App Manifest flow expects.
// DefaultEvents is always empty: the manifest does not subscribe the new
// App to deliveries. An operator who turns the webhook on points it at
// /api/v1/github/webhook and uses the HMAC secret injected into serve;
// GitHub's own webhook_secret from the conversion response is discarded.
// The manifest requests only the one permission GitHubSyncer's installation listing and
// repository-content discovery need -- the same minimal grant
// docs/design/github-app.md documents for the separate, statically
// configured source.repositories GitHub App.
type githubAppManifest struct {
	Name               string            `json:"name"`
	URL                string            `json:"url"`
	RedirectURL        string            `json:"redirect_url"`
	Public             bool              `json:"public"`
	DefaultPermissions map[string]string `json:"default_permissions"`
	DefaultEvents      []string          `json:"default_events"`
}

// manifestStateSecret mints a 256-bit single-use token. It is never itself
// persisted -- only hashManifestState's digest is -- matching how
// internal/auth's login state is handled, for the same reason: a repository
// read or leak must not hand back a usable token.
func manifestStateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", unavailable()
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hashManifestState(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// StartGitHubAppManifest begins the Workspace's one-click "Create via
// GitHub" flow: it durably records a short-lived, single-use state token
// bound to this administrator, and returns the manifest JSON and target URL
// a browser must submit as a form POST to GitHub. GitHub creates the App
// after the administrator reviews and confirms it there, then redirects the
// browser to this deployment's own callback with a one-time code and this
// same state.
//
// This flow only ever creates the App against github.com: GitHub Enterprise
// Server operators continue to use the manual App ID/private key form
// (SetGitHubAppConfig), which is unaffected either way.
func (s *Service) StartGitHubAppManifest(ctx context.Context, p Principal, input GitHubAppManifestInput) (GitHubAppManifestStart, error) {
	p, err := s.requireAdmin(ctx, p, ApplicationsWrite)
	if err != nil {
		return GitHubAppManifestStart{}, err
	}
	if s.githubAppKey == nil {
		return GitHubAppManifestStart{}, Problem(503, "not_configured", "GitHub App admin storage is not configured on this deployment.")
	}
	if s.publicOrigin == "" {
		return GitHubAppManifestStart{}, Problem(503, "not_configured", "This deployment has no public origin configured for the GitHub App Manifest flow.")
	}
	org := strings.TrimSpace(input.Organization)
	if len(org) > 64 || strings.ContainsFunc(org, unicode.IsControl) {
		return GitHubAppManifestStart{}, Problem(422, "invalid_specification", "Organization name is invalid.")
	}

	manifest := githubAppManifest{
		Name:               "AppHub",
		URL:                s.publicOrigin,
		RedirectURL:        s.publicOrigin + "/api/v1/admin/github-app/manifest/callback",
		Public:             false,
		DefaultPermissions: map[string]string{"contents": "read"},
		DefaultEvents:      []string{},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return GitHubAppManifestStart{}, unavailable()
	}

	secret, err := manifestStateSecret()
	if err != nil {
		return GitHubAppManifestStart{}, err
	}
	now := time.Now().UTC()
	rec := GitHubManifestStateRecord{ID: hashManifestState(secret), UserID: p.UserID, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	m, err := mutation(RecordID{Kind: GitHubManifestKind, ID: rec.ID}, 0, rec)
	if err != nil {
		return GitHubAppManifestStart{}, err
	}
	if err := s.repo.Commit(ctx, []Mutation{m}); err != nil {
		return GitHubAppManifestStart{}, unavailable()
	}

	createURL := "https://github.com/settings/apps/new"
	if org != "" {
		createURL = "https://github.com/organizations/" + url.PathEscape(org) + "/settings/apps/new"
	}
	return GitHubAppManifestStart{ManifestJSON: string(manifestJSON), State: secret, CreateURL: createURL}, nil
}

// CompleteGitHubAppManifest finishes the flow StartGitHubAppManifest began.
// state must name a still-valid, not-yet-consumed token this same
// administrator's own earlier call created -- consumed here before anything
// else, so a replayed or shared callback URL can never re-exchange the same
// GitHub-issued code twice -- then exchanges code for the App GitHub just
// created and stores its ID and private key exactly as SetGitHubAppConfig
// would, clearing any previously configured Enterprise Server API base URL
// (this flow only ever targets github.com).
func (s *Service) CompleteGitHubAppManifest(ctx context.Context, p Principal, code, state string) (GitHubAppStatusView, error) {
	p, err := s.requireAdmin(ctx, p, ApplicationsWrite)
	if err != nil {
		return GitHubAppStatusView{}, err
	}
	if s.githubAppKey == nil {
		return GitHubAppStatusView{}, Problem(503, "not_configured", "GitHub App admin storage is not configured on this deployment.")
	}
	if strings.TrimSpace(code) == "" || strings.TrimSpace(state) == "" {
		return GitHubAppStatusView{}, Problem(422, "invalid_specification", "A code and state are required.")
	}
	invalidState := Problem(409, "invalid_state", "This GitHub App creation link has expired, was already used, or belongs to a different administrator. Start again from the Workspace.")
	recID := RecordID{Kind: GitHubManifestKind, ID: hashManifestState(state)}
	rec, err := s.repo.Read(ctx, recID)
	if errors.Is(err, ErrNotFound) {
		return GitHubAppStatusView{}, invalidState
	}
	if err != nil {
		return GitHubAppStatusView{}, unavailable()
	}
	tx, err := Decode[GitHubManifestStateRecord](rec)
	if err != nil || tx.UserID != p.UserID || !time.Now().Before(tx.ExpiresAt) {
		return GitHubAppStatusView{}, invalidState
	}
	if err := s.repo.Commit(ctx, []Mutation{{Record: rec, ExpectedVersion: rec.Version, Delete: true}}); err != nil {
		if errors.Is(err, ErrConflict) {
			return GitHubAppStatusView{}, invalidState
		}
		return GitHubAppStatusView{}, unavailable()
	}

	existing, version, err := s.githubAppConfig(ctx)
	if err != nil {
		return GitHubAppStatusView{}, err
	}
	converted, err := s.manifestConverter(ctx, code, "")
	if err != nil {
		return GitHubAppStatusView{}, Problem(502, "github_unavailable", "GitHub did not return the created App. Try creating it again.")
	}
	if err := s.githubAppKey.Put(ctx, converted.PrivateKeyPEM); err != nil {
		return GitHubAppStatusView{}, unavailable()
	}
	if s.auditWriter != nil {
		if err := s.auditWriter.AppendAudit(ctx, p.UserID, "githubApp.privateKey.replace", "githubAppConfig:config", nil); err != nil {
			return GitHubAppStatusView{}, unavailable()
		}
	}
	existing.ID, existing.AppID, existing.APIBaseURL, existing.PrivateKeyConfigured = GitHubAppConfigID, converted.AppID, "", true
	existing.UpdatedAt, existing.UpdatedBy = time.Now().UTC(), p.UserID
	m, err := mutation(RecordID{Kind: GitHubAppConfigKind, ID: GitHubAppConfigID}, version, existing)
	if err != nil {
		return GitHubAppStatusView{}, err
	}
	if err := s.repo.Commit(auditPrincipal(ctx, p, "githubApp.manifest.complete", "githubAppConfig:config"), []Mutation{m}); err != nil {
		if errors.Is(err, ErrConflict) {
			return GitHubAppStatusView{}, Problem(409, "conflict", "The configuration changed concurrently. Reload and retry.")
		}
		return GitHubAppStatusView{}, unavailable()
	}
	return s.githubAppStatusView(ctx, existing)
}

// ForgetGitHubAppInstallation removes a locally synced installation record.
// It does not uninstall the app from GitHub: if the installation still
// exists there, the worker's next sync recreates the record.
func (s *Service) ForgetGitHubAppInstallation(ctx context.Context, p Principal, id string) error {
	if _, err := s.requireAdmin(ctx, p, ApplicationsWrite); err != nil {
		return err
	}
	recID := RecordID{Kind: GitHubInstallationKind, ID: id}
	r, err := s.repo.Read(ctx, recID)
	if errors.Is(err, ErrNotFound) {
		return notFound()
	}
	if err != nil {
		return unavailable()
	}
	if err := s.repo.Commit(auditPrincipal(ctx, p, "githubInstallation.forget", "githubInstallation:"+id), []Mutation{{Record: Record{RecordID: recID}, ExpectedVersion: r.Version, Delete: true}}); err != nil {
		if errors.Is(err, ErrConflict) {
			return Problem(409, "conflict", "The installation changed concurrently. Reload and retry.")
		}
		return unavailable()
	}
	return nil
}

// ListLogGroups returns the operator-named log groups the Workspace's log
// viewer may read.
func (s *Service) ListLogGroups(ctx context.Context, p Principal) ([]string, error) {
	if _, err := s.requireAdmin(ctx, p, ApplicationsRead); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(s.logGroups))
	for _, g := range s.logGroups {
		names = append(names, g.Name)
	}
	return names, nil
}

// QueryLogs reads one bounded page from the named log group. name must be
// one of the operator-configured display names ListLogGroups returns, never
// a raw CloudWatch log group name: this is what keeps a caller from reading
// any log group the operator did not explicitly name.
func (s *Service) QueryLogs(ctx context.Context, p Principal, name string, q LogQuery) (LogResult, error) {
	if _, err := s.requireAdmin(ctx, p, ApplicationsRead); err != nil {
		return LogResult{}, err
	}
	if s.logReader == nil {
		return LogResult{}, Problem(503, "not_configured", "Log viewing is not configured on this deployment.")
	}
	var group string
	for _, g := range s.logGroups {
		if g.Name == name {
			group = g.LogGroup
			break
		}
	}
	if group == "" {
		return LogResult{}, Problem(422, "invalid_specification", "Unknown log group name.")
	}
	res, err := s.logReader.Filter(ctx, group, q)
	if err != nil {
		return LogResult{}, unavailable()
	}
	return res, nil
}
