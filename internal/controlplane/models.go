// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"time"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/internal/detect"
	"github.com/conductorone/apphub/modules/deploy"
)

// OAuth scopes bind delegated access independently of ownership.
const (
	ApplicationsRead  = "applications:read"
	ApplicationsWrite = "applications:write"
	DeploymentsRead   = "deployments:read"
	DeploymentsWrite  = "deployments:write"
	AppAccess         = "app:access"
)

// Roles a directory entitlement may be mapped to, ordered least to most
// privileged. RoleAdmin is equivalent to the legacy static auth.admins grant:
// either sets Principal.Admin. RoleMember and RoleAppOwner otherwise differ
// only in CreateApplication -- an app owner may create and thereby own
// applications; a member may only read what they are shared or already own.
const (
	RoleMember   = "member"
	RoleAppOwner = "app-owner"
	RoleAdmin    = "admin"
)

// RoleVulnAdmin grants Principal.VulnAdmin: cross-application vulnerability
// finding visibility, the same way RoleAdmin grants Principal.Admin. It is
// deliberately not one of Roles -- it is not a rung on the
// member/app-owner/admin ladder HighestRole ranks, but an orthogonal
// capability an identity holds alongside whichever of those three it also
// resolves to (an app-owner can also be a vuln admin). RoleAdmin implies it
// the same way it implies everything else in this package: see
// Eligibility.CheckPrincipal.
const RoleVulnAdmin = "vuln-admin"

// Roles lists every role a RoleMappingRecord may name that HighestRole
// ranks, in privilege order.
var Roles = []string{RoleMember, RoleAppOwner, RoleAdmin}

// MappableRoles lists every role SetRoleMapping accepts: Roles, plus the
// orthogonal capabilities that are not part of that ladder.
var MappableRoles = append(append([]string{}, Roles...), RoleVulnAdmin)

// roleRank orders Roles for resolving the highest-privilege role among
// several matched directory entitlements. An unranked role (never written by
// admin.go's validated SetRoleMapping, but a request path is not the place to
// trust that invariant absolutely) sorts lowest rather than panicking or
// erroring: an admission recheck must always resolve to *some* role.
func roleRank(role string) int {
	for i, r := range Roles {
		if r == role {
			return i
		}
	}
	return -1
}

// HighestRole returns the most-privileged role among candidates, or
// RoleMember when candidates is empty or names nothing ranked -- every
// identity starts at the least-privileged role until an operator maps a
// directory entitlement (or the legacy auth.admins list) to something else.
func HighestRole(candidates []string) string {
	best, bestRank := "", -1
	for _, c := range candidates {
		if rank := roleRank(c); rank > bestRank {
			best, bestRank = c, rank
		}
	}
	if bestRank < 0 {
		return RoleMember
	}
	return best
}

// Principal carries authenticated identity and scope evidence that policy must revalidate.
type Principal struct {
	UserID     string
	ProviderID string
	Issuer     string
	Subject    string
	Admin      bool
	// Role is the resolved general role (see RoleMember, RoleAppOwner,
	// RoleAdmin), set by Eligibility alongside Admin and revalidated on every
	// request. RoleAdmin implies Admin; application creation and repository
	// detection reject RoleMember even with a write scope.
	Role string
	// VulnAdmin grants cross-application vulnerability finding visibility.
	// Set by Eligibility from a directory entitlement mapped to
	// RoleVulnAdmin; Admin implies it, the same way Admin implies everything
	// else.
	VulnAdmin bool
	// Features lists the feature-flag keys currently enabled for this
	// identity (see FeatureFlagRecord), set by Eligibility alongside Role
	// and revalidated on every request the same way. Unlike Admin and
	// VulnAdmin, Admin does not imply any Features entry: an operator-set
	// "off" mode hides a feature from every identity, administrators
	// included.
	Features []string
	// Groups are the directory entitlements this identity currently holds,
	// from the synced catalog only, set by Eligibility and revalidated on
	// every request like Role. A group that owns an application makes its
	// holders owners (see Owns).
	Groups    []string
	Bearer    bool
	Scopes    []string
	SessionID string
}

// User is the durable local account; email and profile fields are not identity keys.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Avatar    string    `json:"avatar"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ExternalIdentity binds an exact issuer/subject pair to one local account.
type ExternalIdentity struct {
	UserID        string    `json:"userId"`
	ProviderID    string    `json:"providerId"`
	Issuer        string    `json:"issuer"`
	Subject       string    `json:"subject"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	Name          string    `json:"name"`
	Avatar        string    `json:"avatar"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// Session is a revocable browser session, separate from delegated OAuth families.
type Session struct {
	ID         string    `json:"id"`
	UserID     string    `json:"userId"`
	ProviderID string    `json:"providerId"`
	Issuer     string    `json:"issuer"`
	Subject    string    `json:"subject"`
	CSRF       string    `json:"csrf"`
	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Revoked    bool      `json:"revoked"`
}

// SourceInput selects an approved repository and a ref resolved once per deployment.
type SourceInput struct {
	URL        string `json:"url"`
	Ref        string `json:"ref"`
	Dockerfile string `json:"dockerfile"`
}

// ResourceInput requests CPU and memory within the target's allowed size set.
type ResourceInput struct {
	CPU    int `json:"cpu"`
	Memory int `json:"memory"`
}

// ScheduleInput defines future dispatch timing, not proof of a completed execution.
type ScheduleInput struct {
	Expression string `json:"expression"`
	Timezone   string `json:"timezone"`
	Paused     bool   `json:"paused"`
}

// CapacityInput bounds the requested database capacity.
type CapacityInput struct {
	MinUnits float64 `json:"minUnits"`
	MaxUnits float64 `json:"maxUnits"`
}

// DatabaseInput describes an optional database without accepting credentials.
type DatabaseInput struct {
	Kind          deploy.DatabaseKind `json:"kind"`
	Engine        compute.SQLEngine   `json:"engine,omitempty"`
	EngineVersion string              `json:"engineVersion,omitempty"`
	DatabaseName  string              `json:"databaseName,omitempty"`
	AdminUsername string              `json:"adminUsername,omitempty"`
	Capacity      CapacityInput       `json:"capacity,omitempty"`
	Extensions    []string            `json:"extensions,omitempty"`
	PartitionKey  string              `json:"partitionKey,omitempty"`
	SortKey       string              `json:"sortKey,omitempty"`
}

// BucketInput describes an optional object store within the target's capabilities.
type BucketInput struct {
	Kind   deploy.BucketKind   `json:"kind"`
	Zone   string              `json:"zone,omitempty"`
	Access compute.AccessLevel `json:"access,omitempty"`
}

// PublicPathInput exempts one path from sign-in on a route that otherwise
// requires it. Path is the exact string the platform proxy matches against;
// Note is a free-text reminder of what calls it, never interpreted.
type PublicPathInput struct {
	Path string `json:"path"`
	Note string `json:"note,omitempty"`
}

// ExposureInput requests private exposure or a target-scoped reserved hostname.
type ExposureInput struct {
	Mode     string `json:"mode"`
	Hostname string `json:"hostname,omitempty"`
	// SignInRequired gates this exposure's route behind the platform's
	// sign-in proxy. Absent (nil) means true -- an unset field keeps today's
	// behavior for every record and client that predates this field, so a
	// route already deployed cannot silently go public on the next read. A
	// caller must set it to false explicitly to publish the route to anyone
	// who can open its URL.
	SignInRequired *bool `json:"signInRequired,omitempty"`
	// PublicPaths exempts individual paths from sign-in while SignInRequired
	// is true. Kept on the record and inert (see [MapApplication]) while
	// SignInRequired is false -- every path is already public then, and the
	// rules stay ready to take effect again the moment sign-in is turned back
	// on, rather than having to be re-entered.
	PublicPaths    []PublicPathInput `json:"publicPaths,omitempty"`
	MCPAuthEnabled bool              `json:"mcpAuthEnabled,omitempty"`
}

// ApplicationInput is user-authored intent; operator infrastructure is supplied separately.
type ApplicationInput struct {
	Name      string               `json:"name"`
	TargetID  string               `json:"targetId"`
	Source    SourceInput          `json:"source"`
	Execution deploy.ExecutionMode `json:"execution"`
	Port      int                  `json:"port"`
	Resources ResourceInput        `json:"resources"`
	Replicas  int                  `json:"replicas"`
	Schedule  *ScheduleInput       `json:"schedule,omitempty"`
	Database  *DatabaseInput       `json:"database,omitempty"`
	Bucket    *BucketInput         `json:"bucket,omitempty"`
	Exposure  ExposureInput        `json:"exposure"`
	// Category is a KnownCategories key used only for portal listing; empty is uncategorized.
	Category string `json:"category,omitempty"`
}

// ApplicationRecord stores revisioned intent, operation pointers and retained route ownership.
type ApplicationRecord struct {
	ID string `json:"id"`
	// Owners is never empty. See ApplicationOwner; every change to it commits
	// with its ApplicationOwnerRecord index entries.
	Owners                     []ApplicationOwner `json:"owners"`
	TargetID                   string             `json:"targetId"`
	Revision                   int64              `json:"revision"`
	Input                      ApplicationInput   `json:"input"`
	Application                deploy.Application `json:"application"`
	ActiveDeploymentID         string             `json:"activeDeploymentId"`
	LatestDeploymentID         string             `json:"latestDeploymentId"`
	LastSuccessfulDeploymentID string             `json:"lastSuccessfulDeploymentId"`
	LastSuccessfulArtifacts    deploy.Artifacts   `json:"lastSuccessfulArtifacts"`
	// LastDeployedAt is when the last successful deployment finished.
	LastDeployedAt time.Time `json:"lastDeployedAt"`
	Addresses      []string  `json:"addresses"`
	// Reservations include live or uncertain routes from earlier specifications.
	// Only a successful worker reconciliation may release a published hostname.
	ReservedHostnames []string `json:"reservedHostnames,omitempty"`
	// Secrets lists the owner's environment secrets by name; values live only
	// in the target's secret store. See secrets.go.
	Secrets []SecretEntry `json:"secrets,omitempty"`
	// DeletionRequestedAt is set once, when deletion is first accepted. From
	// then on the application is only ever deleted: ActiveDeploymentID holds
	// its latest teardown even after that teardown fails, so every write path's
	// active-operation check refuses an update or deploy without knowing about
	// deletion. See DeleteApplication.
	DeletionRequestedAt time.Time `json:"deletionRequestedAt,omitzero"`
	DeletionRequestedBy string    `json:"deletionRequestedBy,omitempty"`
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

// DeploymentState identifies a durable operation's lifecycle phase.
type DeploymentState string

// Deployment lifecycle states distinguish known failure from uncertain interruption.
const (
	Queued      DeploymentState = "queued"
	Running     DeploymentState = "running"
	Succeeded   DeploymentState = "succeeded"
	Failed      DeploymentState = "failed"
	Interrupted DeploymentState = "interrupted"
)

// Terminal reports whether polling can stop; interruption still needs operator resolution.
func (s DeploymentState) Terminal() bool { return s == Succeeded || s == Failed || s == Interrupted }

// OperationKind distinguishes the two durable operations the worker executes.
// Both share one record kind, queue, lease and heartbeat, so a teardown gets the
// same fencing and observation a deployment has.
type OperationKind string

// OperationDeploy is stored as the empty string, so records written before
// teardown existed read as deployments.
const (
	OperationDeploy   OperationKind = ""
	OperationTeardown OperationKind = "teardown"
)

// MaxTeardownAttempts bounds automatic requeueing of a teardown whose worker
// stopped heartbeating. Every step is idempotent, so a requeue is safe; the
// bound stops a teardown that kills its worker from looping forever.
const MaxTeardownAttempts = 3

// DeploymentRecord freezes execution intent and checkpoints effects behind an attempt fence.
type DeploymentRecord struct {
	ID string `json:"id"`
	// Operation is empty for a deployment. A teardown deletes the application.
	Operation OperationKind `json:"operation,omitempty"`
	// PlannedSteps are a teardown's ordered deploy.TeardownStep values.
	PlannedSteps []string `json:"plannedSteps,omitempty"`
	// Attempt counts automatic teardown requeues; zero reads as one.
	Attempt int `json:"attempt,omitempty"`
	// StepStartedAt is when Step last changed, so a slow step can be told
	// apart from a stalled one.
	StepStartedAt       time.Time          `json:"stepStartedAt,omitzero"`
	ApplicationID       string             `json:"applicationId"`
	RequesterUserID     string             `json:"requesterUserId"`
	Requester           Principal          `json:"requester"`
	ApplicationRevision int64              `json:"applicationRevision"`
	TargetID            string             `json:"targetId"`
	Application         deploy.Application `json:"application"`
	RequestedSourceRef  string             `json:"requestedSourceRef"`
	ResolvedCommit      string             `json:"resolvedCommit"`
	State               DeploymentState    `json:"state"`
	Progress            string             `json:"progress"`
	Step                string             `json:"step"`
	ErrorCode           string             `json:"errorCode"`
	Message             string             `json:"message"`
	Artifacts           deploy.Artifacts   `json:"artifacts"`
	Addresses           []string           `json:"addresses"`
	AttemptID           string             `json:"attemptId"`
	HeartbeatAt         time.Time          `json:"heartbeatAt"`
	CreatedAt           time.Time          `json:"createdAt"`
	StartedAt           time.Time          `json:"startedAt"`
	FinishedAt          time.Time          `json:"finishedAt"`
	ResolutionReason    string             `json:"resolutionReason"`
	ResolvedBy          string             `json:"resolvedBy"`
	ResolvedAt          time.Time          `json:"resolvedAt"`
	// SealedSecrets are values this deployment sets, encrypted for the worker
	// and cleared when the deployment reaches a terminal state.
	SealedSecrets []SealedSecret `json:"sealedSecrets,omitempty"`
}

// IdempotencyRecord binds a principal and request hash to the original durable result.
type IdempotencyRecord struct {
	PrincipalID   string `json:"principalId"`
	Operation     string `json:"operation"`
	RequestHash   string `json:"requestHash"`
	ApplicationID string `json:"applicationId"`
	DeploymentID  string `json:"deploymentId,omitempty"`
}

// HostnameReservation prevents two applications from claiming the same target route.
type HostnameReservation struct {
	TargetID      string `json:"targetId"`
	Hostname      string `json:"hostname"`
	ApplicationID string `json:"applicationId"`
}

// DetectionState identifies an advisory repository scan's lifecycle phase.
//
// There is deliberately no "running" state between Queued and terminal. A
// deployment needs Running to fence a heartbeat and to make an interrupted
// worker's outcome visible as uncertain rather than lost, because it changes
// durable cloud resources. A detection changes nothing: it is a read of a
// repository the operator already approved, so if a worker dies mid-scan the
// record is simply still Queued, and the worst any replica does by retrying it
// is a redundant, side-effect-free Git fetch. See Detector.
type DetectionState string

// Detection lifecycle states. A scan starts Queued and ends Succeeded or Failed.
const (
	DetectionQueued    DetectionState = "queued"
	DetectionSucceeded DetectionState = "succeeded"
	DetectionFailed    DetectionState = "failed"
)

// Terminal reports whether polling can stop.
func (s DetectionState) Terminal() bool { return s == DetectionSucceeded || s == DetectionFailed }

// DetectionRecord is a durable, single-shot advisory repository scan: given an
// operator-approved repository and ref, discover a Dockerfile, its EXPOSE
// port, any compose services, and a best-effort database guess, ahead of
// creating or editing an application. It never touches application or
// deployment state and is performed by the worker, never by the authenticated
// API process, which does not hold source credentials.
type DetectionRecord struct {
	ID              string         `json:"id"`
	RequesterUserID string         `json:"requesterUserId"`
	TargetID        string         `json:"targetId"`
	URL             string         `json:"url"`
	Ref             string         `json:"ref"`
	State           DetectionState `json:"state"`
	Result          detect.Result  `json:"result,omitempty"`
	// Message is safe, service-authored text only -- never a provider's raw
	// error, matching how DeploymentRecord already treats a failure reason.
	Message    string    `json:"message,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
}

// GitHubAppConfigID is the fixed ID of the singleton GitHubAppConfigRecord.
// There is exactly one admin-managed GitHub App per deployment.
const GitHubAppConfigID = "config"

// GitHubAppConfigRecord is the admin-managed GitHub App's non-secret
// identity. The private key is never part of this record, in this store, or
// in any YAML -- only whether one is currently stored. See
// internal/ghappkey, which durably holds the key in SSM Parameter Store and
// is the only thing that can write or read it.
type GitHubAppConfigRecord struct {
	// ID is always GitHubAppConfigID.
	ID string `json:"id"`
	// AppID is the numeric GitHub App ID. Zero means unconfigured.
	AppID int64 `json:"appId"`
	// APIBaseURL overrides the API root for GitHub Enterprise Server. Empty
	// means github.com.
	APIBaseURL string `json:"apiBaseUrl,omitempty"`
	// PrivateKeyConfigured reports whether internal/ghappkey currently holds
	// a key for this app, without saying anything about its content.
	PrivateKeyConfigured bool `json:"privateKeyConfigured"`
	// UpdatedAt and UpdatedBy record the last administrator to change this
	// configuration, for the same audit reasons every other admin action in
	// this repository is attributed.
	UpdatedAt time.Time `json:"updatedAt"`
	UpdatedBy string    `json:"updatedBy"`
}

// GitHubManifestStateRecord is one administrator's started GitHub App
// Manifest flow: a durable, short-lived, single-use state token binding the
// callback that completes it to the admin who started it. ID is a hash of
// the random state secret handed to GitHub, never the secret itself --
// mirroring how internal/auth's LoginKind transactions are keyed, so a
// repository read or leak cannot hand back a usable token. Deleted on first
// use (successful or not) by admin.go's CompleteGitHubAppManifest; an
// unconsumed token expires via ExpiresAt's TTL regardless.
type GitHubManifestStateRecord struct {
	// ID is sha256(state secret), hex-encoded.
	ID string `json:"id"`
	// UserID is the administrator who started this flow. The callback
	// requires the completing admin's Principal.UserID to match, so one
	// admin's browser cannot be tricked into completing another admin's
	// (or an attacker's) started flow.
	UserID    string    `json:"userId"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// GitHubInstallationRecord is one GitHub App installation: an organization or
// user account that has installed the admin-managed app. It is synced from
// GitHub by the worker -- the only process holding the app's private key --
// and read by the Workspace admin UI. Deleting this record only forgets it
// locally; it does not uninstall the app from GitHub.
type GitHubInstallationRecord struct {
	// ID is the installation ID rendered as decimal, matching InstallationID.
	ID                  string `json:"id"`
	InstallationID      int64  `json:"installationId"`
	AccountLogin        string `json:"accountLogin"`
	AccountType         string `json:"accountType"`
	RepositorySelection string `json:"repositorySelection"`
	// Repositories are canonical https://github.com/owner/name URLs the
	// installation could access at the last sync, for the deploy form's
	// suggestions. A cap means the list can be incomplete; it is not the
	// allowlist. Empty when the installation is suspended or the listing
	// has not succeeded yet.
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions"`
	HTMLURL      string            `json:"htmlUrl"`
	// SuspendedAt is the zero time when the installation is not suspended.
	SuspendedAt time.Time `json:"suspendedAt,omitempty"`
	// SyncedAt is when the worker last confirmed this installation from
	// GitHub. A caller showing this record to an administrator should
	// surface it: it is evidence of freshness, not a guarantee of it.
	SyncedAt time.Time `json:"syncedAt"`
}

// DirectoryEntitlementRecord is one entitlement read from an operator-configured
// identity directory: a group, or a finer-grained grant, depending on what the
// directory calls it. This package has no idea which directory synced it or
// what its provider-specific fields mean beyond these -- see
// credentials/c1directory for the one source a composition root may wire in
// today, and internal/worker's DirectorySyncer for how it gets here. Deleting
// this record only forgets it locally; the next sync recreates it if the
// directory still has it.
type DirectoryEntitlementRecord struct {
	// ID is the directory's own identifier for this entitlement.
	ID string `json:"id"`
	// DisplayName is what an operator sees.
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	// AppID is the directory's identifier for the application or resource
	// this entitlement grants access to. Empty for a directory-wide group.
	AppID string `json:"appId,omitempty"`
	// Bindable reports whether the directory's own automation can grant this
	// entitlement programmatically, as opposed to one that is directory-synced
	// membership only. It is the directory's own distinction, carried through
	// rather than inferred.
	Bindable bool `json:"bindable"`
	// SyncedAt is when the worker last confirmed this entitlement from the
	// directory. A caller showing this record to an administrator should
	// surface it: it is evidence of freshness, not a guarantee of it.
	SyncedAt time.Time `json:"syncedAt"`
}

// RoleMappingRecord binds one synced directory entitlement to the AppHub
// role it grants every identity holding a current grant on it. ID is the
// entitlement's ID (DirectoryEntitlementKind), so at most one role maps to
// any given entitlement; several entitlements may map to the same role.
// Admin-authored: see admin.go's SetRoleMapping and DeleteRoleMapping.
type RoleMappingRecord struct {
	// ID is the directory entitlement ID this mapping covers.
	ID   string `json:"id"`
	Role string `json:"role"`
	// UpdatedAt and UpdatedBy record the administrator who set this mapping,
	// for the same audit reasons GitHubAppConfigRecord's do.
	UpdatedAt time.Time `json:"updatedAt"`
	UpdatedBy string    `json:"updatedBy"`
}

// GroupMembershipCacheTTL bounds how long a cached GroupMembershipRecord is
// trusted before Eligibility re-reads ConductorOne. Matches
// internal/worker's directorySyncInterval: group and entitlement membership
// changes rarely enough that a bounded staleness window is an acceptable
// trade against a live ConductorOne call on every authenticated request.
const GroupMembershipCacheTTL = 5 * time.Minute

// GroupMembershipRecord is one identity's cached snapshot of which directory
// entitlement IDs it currently holds a grant on, keyed by normalized email.
// Populated lazily by Eligibility, never by internal/worker's
// DirectorySyncer: that syncer maintains the org-wide entitlement catalog,
// this record is per-identity membership, fetched only for identities that
// actually sign in.
type GroupMembershipRecord struct {
	// ID is the identity's normalized (lowercased) email.
	ID       string    `json:"id"`
	GroupIDs []string  `json:"groupIds"`
	SyncedAt time.Time `json:"syncedAt"`
}

// Feature flag modes. Off hides a feature from every identity, including
// administrators. On shows it to every identity. Group shows it only to an
// identity currently holding a grant on any of the mapped directory
// entitlements -- FeatureFlagRecord.GatingGroupIDs -- the same membership
// check RoleMappingRecord uses, but gating visibility rather than granting
// a role.
const (
	FeatureFlagOff   = "off"
	FeatureFlagOn    = "on"
	FeatureFlagGroup = "group"
)

// FeatureFlagModes lists every mode SetFeatureFlag accepts.
var FeatureFlagModes = []string{FeatureFlagOff, FeatureFlagOn, FeatureFlagGroup}

// FeatureVulnerabilities gates the Workspace's vulnerability finding surface.
// Provisioning flags are workspace-wide deployment settings, not identity gates.
const (
	FeatureVulnerabilities     = "vulnerabilities"
	FeatureProvisionAppCatalog = "provision-application-catalog"
	FeatureProvisionShortLink  = "provision-shortlink"
)

// KnownFeatureFlags lists every supported flag key. Unset keys default to off.
var KnownFeatureFlags = []string{FeatureVulnerabilities, FeatureProvisionAppCatalog, FeatureProvisionShortLink}

// FeatureFlagRecord configures one known feature flag. ID is always the flag
// key (one of KnownFeatureFlags); a key with no record defaults to
// FeatureFlagOff, the same way an unmapped directory entitlement defaults to
// no role. Admin-authored: see admin.go's SetFeatureFlag.
type FeatureFlagRecord struct {
	// ID is the flag key.
	ID   string `json:"id"`
	Mode string `json:"mode"`
	// GroupEntitlementIDs names the directory entitlements that gate
	// visibility when Mode is FeatureFlagGroup. An identity holding any
	// of them sees the feature. Empty otherwise.
	GroupEntitlementIDs []string `json:"groupEntitlementIds,omitempty"`
	// GroupEntitlementID is the legacy singular gate. Decode still
	// accepts it so a FeatureFlagGroup record written before multi-group
	// support keeps working; new writes always use GroupEntitlementIDs.
	GroupEntitlementID string    `json:"groupEntitlementId,omitempty"`
	UpdatedAt          time.Time `json:"updatedAt"`
	UpdatedBy          string    `json:"updatedBy"`
}

// GatingGroupIDs returns the directory entitlements that gate this flag in
// FeatureFlagGroup mode. Prefers GroupEntitlementIDs; falls back to the
// legacy singular GroupEntitlementID so an existing record still gates.
func (f FeatureFlagRecord) GatingGroupIDs() []string {
	if len(f.GroupEntitlementIDs) > 0 {
		return uniqueNonEmpty(f.GroupEntitlementIDs)
	}
	if f.GroupEntitlementID != "" {
		return []string{f.GroupEntitlementID}
	}
	return nil
}

func uniqueNonEmpty(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// TargetDescriptor publishes a worker's capability/configuration evidence and heartbeat.
type TargetDescriptor struct {
	ID           string                `json:"id"`
	ProviderName string                `json:"providerName"`
	Capabilities compute.CapabilitySet `json:"capabilities"`
	ConfigHash   string                `json:"configHash"`
	HeartbeatAt  time.Time             `json:"heartbeatAt"`
}

// OAuthFamily is the independently revocable grant shared by rotated delegated tokens.
type OAuthFamily struct {
	ID              string    `json:"id"`
	UserID          string    `json:"userId"`
	ProviderID      string    `json:"providerId"`
	Issuer          string    `json:"issuer"`
	Subject         string    `json:"subject"`
	ClientID        string    `json:"clientId"`
	Resource        string    `json:"resource"`
	Scopes          []string  `json:"scopes"`
	ApplicationID   string    `json:"applicationId,omitempty"`
	ApplicationHost string    `json:"applicationHost,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
	Revoked         bool      `json:"revoked"`
}

// OAuthToken stores hashed-token lookup metadata and one-use consumption state.
type OAuthToken struct {
	FamilyID  string    `json:"familyId"`
	ExpiresAt time.Time `json:"expiresAt"`
	Consumed  bool      `json:"consumed"`
}

// Page contains a bounded result set and an opaque continuation cursor.
type Page[T any] struct {
	Items  []T    `json:"items"`
	Cursor string `json:"cursor,omitempty"`
}
