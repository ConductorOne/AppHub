// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/serverconfig"
)

// membershipLookupTimeout bounds the live ConductorOne membership fetch on
// the admission path. GET /api/v1/users/me runs CheckPrincipal, and the
// HTTP server's write timeout is 30s; a full grants crawl for a busy C1
// user exceeded that and Vite proxied it as "socket hang up". This stays
// well under that deadline. A timeout fails open to the last cache
// unless that cache is an oversized leftover of an all-grants crawl.
var membershipLookupTimeout = 8 * time.Second

// maxCachedMembershipIDs is an upper bound on a trusted GroupMembershipRecord.
// Role assignment and group-gated flags only consult the synced group
// catalog (tens of IDs). A cache larger than this is the leftover of an
// all-grants crawl and must not be treated as fresh.
const maxCachedMembershipIDs = 200

// GroupLookup resolves which directory entitlement IDs an email currently
// holds a grant on -- live membership, not a cached read. Declared here,
// narrowed to the one method Eligibility needs, so this package carries no
// ConductorOne idiom: internal/boundary's c1-idiom-fenced rule confines that
// to credentials/c1 and credentials/c1directory, and internal/auth is not
// one of those two. The composition root adapts
// credentials/c1directory.Client to this interface, the same pattern
// internal/worker's directoryAPI uses for the entitlement catalog sync.
type GroupLookup interface {
	ListUserGroupIDs(ctx context.Context, email string) ([]string, error)
}

// Eligibility rechecks local user status and admission through the identity's
// bound provider, without requiring upstream credentials or discovery.
type Eligibility struct {
	cfg    serverconfig.AuthConfig
	repo   cp.Repository
	groups GroupLookup
}

// NewEligibility binds operator admission policy to authoritative stored
// identities. groups is optional: nil means this deployment has no directory
// configured, so every identity's role resolves to its pre-role-mapping
// default (RoleMember) unless the legacy auth.admins list names it.
func NewEligibility(cfg serverconfig.AuthConfig, repo cp.Repository, groups GroupLookup) *Eligibility {
	return &Eligibility{cfg: cfg, repo: repo, groups: groups}
}

// CheckPrincipal revalidates an authenticated identity and recomputes admin
// authority from exact provider/subject policy; it does not authenticate tokens.
func (e *Eligibility) CheckPrincipal(ctx context.Context, p cp.Principal) (cp.Principal, error) {
	if p.UserID == "" || p.Subject == "" || p.Issuer == "" || e.repo == nil {
		return cp.Principal{}, unauthorized()
	}
	userRecord, err := e.repo.Read(ctx, cp.RecordID{Kind: cp.UserKind, ID: p.UserID})
	if err != nil {
		return cp.Principal{}, readAuthError(err)
	}
	user, err := cp.Decode[cp.User](userRecord)
	if err != nil {
		return cp.Principal{}, unavailable()
	}
	if user.ID != p.UserID || user.Disabled {
		return cp.Principal{}, unauthorized()
	}
	rec, err := e.repo.Read(ctx, cp.RecordID{Kind: cp.IdentityKind, ID: p.Subject, ParentID: p.Issuer})
	if err != nil {
		return cp.Principal{}, readAuthError(err)
	}
	identity, err := cp.Decode[cp.ExternalIdentity](rec)
	if err != nil {
		return cp.Principal{}, unavailable()
	}
	if identity.UserID != p.UserID || identity.Issuer != p.Issuer || identity.Subject != p.Subject {
		return cp.Principal{}, unauthorized()
	}
	// The issuer/subject identity can be observed through multiple configured
	// clients. Its latest profile provenance does not replace the provider bound
	// to an existing session or OAuth family; evaluate that provider independently.
	admitted := false
	for _, provider := range e.cfg.Providers {
		if provider.ID == p.ProviderID && providerIssuer(provider) == p.Issuer && provider.Admits(identity.Email, identity.EmailVerified) {
			admitted = true
			break
		}
	}
	if !admitted {
		return cp.Principal{}, unauthorized()
	}
	legacyAdmin := false
	for _, admin := range e.cfg.Admins {
		if admin.ProviderID == p.ProviderID && admin.Subject == p.Subject {
			legacyAdmin = true
			break
		}
	}
	granted := e.resolveAccess(ctx, identity.Email)
	role := granted.role
	if legacyAdmin {
		role = cp.RoleAdmin
	}
	p.Role = role
	p.Admin = p.Role == cp.RoleAdmin
	// Admin implies every other authority in this package, VulnAdmin
	// included; Features does not receive the same treatment (see its own
	// doc comment on cp.Principal).
	p.VulnAdmin = granted.vulnAdmin || p.Admin
	p.Features = granted.features
	p.Groups = granted.groups
	return p, nil
}

// ResolveRole computes email's current AppHub role and vulnerability-admin
// authority, the same computation CheckPrincipal applies while an identity is
// signing in, without requiring one -- see cp.Eligibility's doc comment for
// how this differs from CheckPrincipal's legacy auth.admins override.
func (e *Eligibility) ResolveRole(ctx context.Context, email string) (role string, vulnAdmin bool) {
	granted := e.resolveAccess(ctx, email)
	return granted.role, granted.vulnAdmin
}

// resolveAccess computes email's AppHub role, vulnerability-admin
// authority, and enabled feature flags in one pass over its currently held
// directory entitlements.
//
// Only the role ladder and FeatureFlagGroup mode depend on a directory:
// FeatureFlagOn and FeatureFlagOff apply to every identity regardless of
// whether one is configured, so this must not return early just because
// e.groups is nil -- doing so once meant an "on" flag had no effect at all
// on a deployment with no directory configured. Group-mode gating (a role
// mapping, or a flag in FeatureFlagGroup mode) simply has no membership
// signal to match against without a directory, so it resolves as if the
// identity holds nothing -- fails safe (disabled), not by touching
// e.groups, which is nil.
// access is what an identity's directory entitlements grant it.
type access struct {
	role      string
	vulnAdmin bool
	features  []string
	// groups are the held entitlement IDs, sorted: an application owned by
	// one of them is owned by this identity (see cp.Owns).
	groups []string
}

func (e *Eligibility) resolveAccess(ctx context.Context, email string) access {
	granted := access{role: cp.RoleMember}
	if email == "" {
		return granted
	}

	var mappings map[string]string
	if e.groups != nil {
		mappings = e.roleMappings(ctx)
	}
	flags := e.featureFlags(ctx)

	var held map[string]bool
	if e.groups != nil {
		// Always refresh the per-identity cache on admission (subject to
		// GroupMembershipCacheTTL), even when nothing is mapped yet. A
		// later role mapping or group-mode flag then has membership ready
		// instead of waiting for the next live lookup.
		groupIDs := e.membership(ctx, email)
		held = make(map[string]bool, len(groupIDs))
		for _, id := range groupIDs {
			held[id] = true
		}
	}

	var matched []string
	for id := range held {
		if r, ok := mappings[id]; ok {
			matched = append(matched, r)
		}
	}
	granted.role = cp.HighestRole(matched)
	granted.vulnAdmin = slices.Contains(matched, cp.RoleVulnAdmin)
	for id := range held {
		granted.groups = append(granted.groups, id)
	}
	slices.Sort(granted.groups)

	for _, key := range cp.KnownFeatureFlags {
		f, configured := flags[key]
		enabled := false
		switch {
		case configured && f.Mode == cp.FeatureFlagOn:
			enabled = true
		case configured && f.Mode == cp.FeatureFlagGroup:
			for _, id := range f.GatingGroupIDs() {
				if held[id] {
					enabled = true
					break
				}
			}
		}
		if enabled {
			granted.features = append(granted.features, key)
		}
	}
	return granted
}

// roleMappings reads every configured RoleMappingRecord as entitlement ID ->
// role. Returns an empty map, never an error, on an outage or an empty
// directory: a mapping read that cannot complete must not block sign-in, the
// same reasoning ListDirectoryEntitlements applies to its own read.
func (e *Eligibility) roleMappings(ctx context.Context) map[string]string {
	page, err := e.repo.Query(ctx, cp.Query{Kind: cp.RoleMappingKind, Limit: 100})
	if err != nil {
		return nil
	}
	mapped := make(map[string]string, len(page.Records))
	for _, r := range page.Records {
		m, decodeErr := cp.Decode[cp.RoleMappingRecord](r)
		if decodeErr != nil {
			continue
		}
		mapped[m.ID] = m.Role
	}
	return mapped
}

// featureFlags reads every configured FeatureFlagRecord as key -> record.
// Returns an empty map, never an error, on the same terms roleMappings does.
func (e *Eligibility) featureFlags(ctx context.Context) map[string]cp.FeatureFlagRecord {
	page, err := e.repo.Query(ctx, cp.Query{Kind: cp.FeatureFlagKind, Limit: 100})
	if err != nil {
		return nil
	}
	flags := make(map[string]cp.FeatureFlagRecord, len(page.Records))
	for _, r := range page.Records {
		f, decodeErr := cp.Decode[cp.FeatureFlagRecord](r)
		if decodeErr != nil {
			continue
		}
		flags[f.ID] = f
	}
	return flags
}

// membership returns email's currently held directory entitlement IDs, from
// a durable per-identity cache refreshed at most once every
// cp.GroupMembershipCacheTTL. Admission always calls this when a directory
// is configured, so sign-in populates the cache even before any role
// mapping exists. On a stale or missing cache it looks ConductorOne up live
// and persists the result; on a live-lookup failure it falls back to
// whatever was last cached (possibly nil, for an identity never
// successfully looked up) rather than treating an unreachable directory as
// "holds nothing" -- the same trade the source system's own C1Syncer documents:
// a transient upstream failure must not silently strip a role that was
// granted moments ago.
func (e *Eligibility) membership(ctx context.Context, email string) []string {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		return nil
	}
	recID := cp.RecordID{Kind: cp.GroupMembershipKind, ID: key}
	var version int64
	var cachedGroupIDs []string
	cached, err := e.repo.Read(ctx, recID)
	switch {
	case err == nil:
		version = cached.Version
		if rec, decodeErr := cp.Decode[cp.GroupMembershipRecord](cached); decodeErr == nil {
			cachedGroupIDs = rec.GroupIDs
			// A previous all-grants crawl could cache thousands of IDs under
			// the TTL. That snapshot is not membership in the synced group
			// catalog, and treating it as fresh hid group-gated features.
			if time.Since(rec.SyncedAt) < cp.GroupMembershipCacheTTL && len(rec.GroupIDs) <= maxCachedMembershipIDs {
				return rec.GroupIDs
			}
		}
	case errors.Is(err, cp.ErrNotFound):
		version = 0
	default:
		// A repository outage on the read: fall through to a live lookup
		// attempt below rather than failing this identity's role closed on
		// a persistence blip unrelated to ConductorOne.
	}

	lookupCtx, cancel := context.WithTimeout(ctx, membershipLookupTimeout)
	fresh, lookupErr := e.groups.ListUserGroupIDs(lookupCtx, email)
	cancel()
	if lookupErr != nil {
		if len(cachedGroupIDs) > maxCachedMembershipIDs {
			return nil
		}
		return cachedGroupIDs
	}

	rec := cp.GroupMembershipRecord{ID: key, GroupIDs: fresh, SyncedAt: time.Now().UTC()}
	if m, encodeErr := cp.Encode(recID, version+1, rec); encodeErr == nil {
		// A CAS loss here means a concurrent request already refreshed this
		// identity's cache; this request's own fresh read is still correct
		// to return, so the write is best-effort.
		_ = e.repo.Commit(ctx, []cp.Mutation{{Record: m, ExpectedVersion: version}})
	}
	return fresh
}

func providerIssuer(p serverconfig.ProviderConfig) string {
	if p.Kind == "google" {
		return GoogleIssuerURL
	}
	return canonicalIssuer(p.Issuer)
}
func readAuthError(err error) error {
	if errors.Is(err, cp.ErrNotFound) {
		return unauthorized()
	}
	return unavailable()
}

var _ cp.Eligibility = (*Eligibility)(nil)
