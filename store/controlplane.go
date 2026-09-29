// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/conductorone/apphub/internal/controlplane"
)

// ControlPlaneRecords persists the control plane's domain transaction boundary.
// No SDK values, key encodings, or index consistency decisions escape this type.
type ControlPlaneRecords struct{ client *Client }

var _ controlplane.Repository = (*ControlPlaneRecords)(nil)

// NewControlPlaneRecords requires an explicitly configured persistent client.
func NewControlPlaneRecords(client *Client) (*ControlPlaneRecords, error) {
	if client == nil || client.api == nil || client.tableName == "" {
		return nil, errors.New("store: configured client is required")
	}
	return &ControlPlaneRecords{client: client}, nil
}

const cpPayloadLimit = 128 << 10
const cpSpecificationLimit = 64 << 10
const cpCursorLimit = 8192

func cpString(value string) types.AttributeValue { return &types.AttributeValueMemberS{Value: value} }
func cpNumber(value int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(value, 10)}
}
func cpText(item map[string]types.AttributeValue, name string) string {
	v, _ := item[name].(*types.AttributeValueMemberS)
	if v == nil {
		return ""
	}
	return v.Value
}
func cpKey(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: cpString(pk), attrSK: cpString(sk)}
}
func cpComponent(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && !strings.Contains(value, "#") && strings.IndexFunc(value, unicode.IsControl) < 0
}
func cpInvalid() error { return errors.New("store: invalid control plane record or query") }

func cpBaseKey(id controlplane.RecordID) (map[string]types.AttributeValue, error) {
	if id.Kind == controlplane.IdentityKind {
		if id.ID == "" || id.ParentID == "" || len(id.ID) > 2048 || len(id.ParentID) > 2048 || strings.ContainsRune(id.ID, 0) || strings.ContainsRune(id.ParentID, 0) || !utf8.ValidString(id.ID) || !utf8.ValidString(id.ParentID) {
			return nil, cpInvalid()
		}
		hash := sha256.Sum256([]byte(id.ParentID + "\x00" + id.ID))
		return cpKey("IDENTITY#"+hex.EncodeToString(hash[:]), skMetadata), nil
	}
	if id.Kind == controlplane.IdempotencyKind {
		op, hash, ok := strings.Cut(id.ID, "\x00")
		if !ok || !cpComponent(op) || !cpComponent(hash) || !cpComponent(id.ParentID) {
			return nil, cpInvalid()
		}
		return cpKey("IDEMPOTENCY#"+id.ParentID+"#"+op+"#"+hash, skMetadata), nil
	}
	if !cpComponent(id.ID) {
		return nil, cpInvalid()
	}
	if id.Kind == controlplane.HostnameKind {
		if !cpComponent(id.ParentID) || id.ID != strings.ToLower(id.ID) {
			return nil, cpInvalid()
		}
		return cpKey("HOSTNAME#"+id.ParentID+"#"+id.ID, skMetadata), nil
	}
	if id.Kind == controlplane.DeploymentKind {
		if id.ParentID != "" && !cpComponent(id.ParentID) {
			return nil, cpInvalid()
		}
		return cpKey("DEPLOY#"+id.ID, skMetadata), nil
	}
	// An owner index entry lives in its application's partition, beside the
	// deployment history, so an application and everything filed under it
	// share one partition key. Unlike a deployment it has no globally unique
	// ID of its own -- the owner key is unique only within one application --
	// so there is no direct-lookup companion and no Read without ParentID: the
	// service always names the application (controlplane.ownerRecordID), and a
	// lookup that cannot say which application it means is refused rather than
	// guessed.
	if id.Kind == controlplane.ApplicationOwnerKind {
		if !cpComponent(id.ParentID) {
			return nil, cpInvalid()
		}
		return cpKey("APP#"+id.ParentID, "OWNER#"+id.ID), nil
	}
	if id.ParentID != "" {
		return nil, cpInvalid()
	}
	var prefix string
	switch id.Kind {
	case controlplane.UserKind:
		prefix = "USER#"
	case controlplane.SessionKind:
		prefix = "SESSION#"
	case controlplane.LoginKind:
		prefix = "LOGIN#"
	case controlplane.ConsentKind:
		prefix = "CONSENT#"
	case controlplane.CodeKind:
		prefix = "AUTHCODE#"
	case controlplane.OAuthClientKind:
		prefix = "OAUTHCLIENT#"
	case controlplane.FamilyKind:
		prefix = "OAUTHFAMILY#"
	case controlplane.AccessKind:
		prefix = "ACCESSTOKEN#"
	case controlplane.RefreshKind:
		prefix = "REFRESHTOKEN#"
	case controlplane.ApplicationKind:
		prefix = "APP#"
	case controlplane.TargetKind:
		prefix = "TARGET#"
	case controlplane.DetectionKind:
		prefix = "DETECT#"
	case controlplane.GitHubAppConfigKind:
		prefix = "GHAPP#"
	case controlplane.GitHubInstallationKind:
		prefix = "GHINSTALL#"
	case controlplane.DirectoryEntitlementKind:
		prefix = "DIRENT#"
	case controlplane.RoleMappingKind:
		prefix = "ROLEMAP#"
	case controlplane.GroupMembershipKind:
		prefix = "GROUPMEMBER#"
	case controlplane.FeatureFlagKind:
		prefix = "FEATUREFLAG#"
	case controlplane.BuildSlotLeaseKind:
		prefix = "BUILDSLOT#"
	case controlplane.GitHubManifestKind:
		prefix = "GHMANIFEST#"
	case controlplane.ApplicationUsageKind:
		prefix = "APPUSAGE#"
	default:
		return nil, cpInvalid()
	}
	return cpKey(prefix+id.ID, skMetadata), nil
}

// Only fields needed for persistence invariants and directories are inspected.
// The JSON payload remains domain-owned, including expiry authorization policy.
type cpFields struct {
	ID            string                       `json:"id"`
	UserID        string                       `json:"userId"`
	ApplicationID string                       `json:"applicationId"`
	TargetID      string                       `json:"targetId"`
	Hostname      string                       `json:"hostname"`
	Issuer        string                       `json:"issuer"`
	Subject       string                       `json:"subject"`
	PrincipalID   string                       `json:"principalId"`
	Operation     string                       `json:"operation"`
	State         controlplane.DeploymentState `json:"state"`
	CreatedAt     time.Time                    `json:"createdAt"`
	ExpiresAt     time.Time                    `json:"expiresAt"`
	Application   json.RawMessage              `json:"application"`
	Input         json.RawMessage              `json:"input"`
	// legacyOwner is a legacy application's single ownerUserId, set only
	// when the row predates owner sets. See cpApplicationOwners.
	legacyOwner string
}

// cpOwnerKey reports whether key is an owner index key exactly as
// controlplane.ApplicationOwner.Key spells it, and fits one key component.
// The round trip matters: ParseOwnerKey alone would accept a key whose
// kind/ID split it re-spells differently, and the index key must be the one
// the service asks for.
func cpOwnerKey(key string) bool {
	owner, ok := controlplane.ParseOwnerKey(key)
	return ok && owner.Key() == key && cpComponent(key) && cpComponent(owner.ID)
}

// cpApplicationOwners checks an application's owner set and returns the
// legacy single owner of a row that has none. A current row carries a
// non-empty owners array -- each entry a user or group whose ID and index key
// are key components, at most controlplane.MaxApplicationOwners, no entry
// twice -- and no ownerUserId. A row written before owner sets carries only
// ownerUserId, which controlplane.ApplicationRecord.UnmarshalJSON reads as a
// one-user set; it stays readable, but Commit refuses to write that shape
// again. A row with both is neither, and is refused either way.
//
// The owners are decoded here rather than through cpFields because "owners"
// and "kind" mean different things in other record kinds' payloads, and a
// shared decode would make one kind's shape reject another's.
func cpApplicationOwners(value json.RawMessage) (string, error) {
	var decoded struct {
		Owners      []controlplane.ApplicationOwner `json:"owners"`
		OwnerUserID *string                         `json:"ownerUserId"`
	}
	if json.Unmarshal(value, &decoded) != nil {
		return "", cpInvalid()
	}
	if len(decoded.Owners) == 0 {
		if decoded.OwnerUserID == nil || !cpComponent(*decoded.OwnerUserID) {
			return "", cpInvalid()
		}
		return *decoded.OwnerUserID, nil
	}
	if decoded.OwnerUserID != nil || len(decoded.Owners) > controlplane.MaxApplicationOwners {
		return "", cpInvalid()
	}
	seen := make(map[string]bool, len(decoded.Owners))
	for _, owner := range decoded.Owners {
		key := owner.Key()
		if (owner.Kind != controlplane.OwnerUser && owner.Kind != controlplane.OwnerGroup) || !cpComponent(owner.ID) || !cpComponent(key) || seen[key] {
			return "", cpInvalid()
		}
		seen[key] = true
	}
	return "", nil
}

// cpOwnerRecord checks an owner index entry against the identity it is filed
// under: the application it names is its parent, and its owner key is its ID,
// spelled exactly as the kind and owner ID it carries would spell it.
func cpOwnerRecord(rec controlplane.Record) bool {
	var entry controlplane.ApplicationOwnerRecord
	owner, ok := controlplane.ParseOwnerKey(rec.ID)
	if !ok || !cpOwnerKey(rec.ID) || json.Unmarshal(rec.Value, &entry) != nil {
		return false
	}
	return entry.ApplicationID == rec.ParentID && entry.OwnerKey == rec.ID && entry.Kind == owner.Kind && entry.OwnerID == owner.ID
}

func cpInspect(rec controlplane.Record) (cpFields, error) {
	var fields cpFields
	payload := bytes.TrimSpace(rec.Value)
	if len(payload) == 0 || len(rec.Value) > cpPayloadLimit || !utf8.Valid(rec.Value) || payload[0] != '{' || json.Unmarshal(rec.Value, &fields) != nil {
		return fields, cpInvalid()
	}
	if len(fields.Application) > cpSpecificationLimit || len(fields.Input) > cpSpecificationLimit {
		return fields, cpInvalid()
	}
	switch rec.Kind {
	case controlplane.ApplicationKind:
		if fields.ID != rec.ID || !cpComponent(fields.TargetID) {
			return fields, cpInvalid()
		}
		legacy, err := cpApplicationOwners(rec.Value)
		if err != nil {
			return fields, err
		}
		fields.legacyOwner = legacy
	case controlplane.ApplicationOwnerKind:
		if !cpOwnerRecord(rec) {
			return fields, cpInvalid()
		}
	case controlplane.DeploymentKind:
		if fields.ID != rec.ID || !cpComponent(fields.ApplicationID) || fields.ApplicationID != rec.ParentID || fields.CreatedAt.IsZero() || fields.CreatedAt.Year() < 1 || fields.CreatedAt.Year() > 9999 {
			return fields, cpInvalid()
		}
		if fields.State != controlplane.Queued && fields.State != controlplane.Running && !fields.State.Terminal() {
			return fields, cpInvalid()
		}
	case controlplane.SessionKind, controlplane.FamilyKind:
		if !cpComponent(fields.ID) || !cpComponent(fields.UserID) {
			return fields, cpInvalid()
		}
	case controlplane.IdentityKind:
		if fields.Issuer != rec.ParentID || fields.Subject != rec.ID || !cpComponent(fields.UserID) {
			return fields, cpInvalid()
		}
	case controlplane.IdempotencyKind:
		op, _, _ := strings.Cut(rec.ID, "\x00")
		if fields.PrincipalID != rec.ParentID || fields.Operation != op {
			return fields, cpInvalid()
		}
	case controlplane.HostnameKind:
		if fields.TargetID != rec.ParentID || fields.Hostname != rec.ID || !cpComponent(fields.ApplicationID) {
			return fields, cpInvalid()
		}
	case controlplane.UserKind, controlplane.TargetKind, controlplane.GitHubAppConfigKind, controlplane.GitHubInstallationKind, controlplane.DirectoryEntitlementKind, controlplane.RoleMappingKind, controlplane.GroupMembershipKind, controlplane.FeatureFlagKind, controlplane.GitHubManifestKind, controlplane.ApplicationUsageKind, controlplane.BuildSlotLeaseKind:
		if fields.ID != rec.ID {
			return fields, cpInvalid()
		}
	case controlplane.DetectionKind:
		if fields.ID != rec.ID {
			return fields, cpInvalid()
		}
		switch controlplane.DetectionState(fields.State) {
		case controlplane.DetectionQueued, controlplane.DetectionSucceeded, controlplane.DetectionFailed:
		default:
			return fields, cpInvalid()
		}
	}
	// Decode the complete known domain shape as well, so malformed nested
	// specifications or security fields fail at the persistence boundary.
	var shape any
	switch rec.Kind {
	case controlplane.ApplicationKind:
		shape = &controlplane.ApplicationRecord{}
	case controlplane.DeploymentKind:
		shape = &controlplane.DeploymentRecord{}
	case controlplane.UserKind:
		shape = &controlplane.User{}
	case controlplane.IdentityKind:
		shape = &controlplane.ExternalIdentity{}
	case controlplane.SessionKind:
		shape = &controlplane.Session{}
	case controlplane.FamilyKind:
		shape = &controlplane.OAuthFamily{}
	case controlplane.AccessKind, controlplane.RefreshKind:
		shape = &controlplane.OAuthToken{}
	case controlplane.IdempotencyKind:
		shape = &controlplane.IdempotencyRecord{}
	case controlplane.HostnameKind:
		shape = &controlplane.HostnameReservation{}
	case controlplane.TargetKind:
		shape = &controlplane.TargetDescriptor{}
	case controlplane.DetectionKind:
		shape = &controlplane.DetectionRecord{}
	case controlplane.GitHubAppConfigKind:
		shape = &controlplane.GitHubAppConfigRecord{}
	case controlplane.GitHubInstallationKind:
		shape = &controlplane.GitHubInstallationRecord{}
	case controlplane.DirectoryEntitlementKind:
		shape = &controlplane.DirectoryEntitlementRecord{}
	case controlplane.RoleMappingKind:
		shape = &controlplane.RoleMappingRecord{}
	case controlplane.GroupMembershipKind:
		shape = &controlplane.GroupMembershipRecord{}
	case controlplane.FeatureFlagKind:
		shape = &controlplane.FeatureFlagRecord{}
	case controlplane.GitHubManifestKind:
		shape = &controlplane.GitHubManifestStateRecord{}
	case controlplane.BuildSlotLeaseKind:
		shape = &controlplane.BuildSlotLease{}
	case controlplane.ApplicationUsageKind:
		shape = &controlplane.ApplicationUsageRecord{}
	case controlplane.ApplicationOwnerKind:
		shape = &controlplane.ApplicationOwnerRecord{}
	}
	if shape != nil && json.Unmarshal(rec.Value, shape) != nil {
		return fields, cpInvalid()
	}
	return fields, nil
}

func cpItem(rec controlplane.Record) (map[string]types.AttributeValue, error) {
	key, err := cpBaseKey(rec.RecordID)
	if err != nil {
		return nil, err
	}
	fields, err := cpInspect(rec)
	if err != nil || rec.Version <= 0 {
		return nil, cpInvalid()
	}
	if rec.Kind == controlplane.DeploymentKind {
		key = cpKey("APP#"+rec.ParentID, "DEPLOY#"+encodeInstant(fields.CreatedAt)+"#"+rec.ID)
	}
	key["Kind"] = cpString(string(rec.Kind))
	key["ID"] = cpString(rec.ID)
	if rec.ParentID != "" {
		key["ParentID"] = cpString(rec.ParentID)
	}
	key["Version"] = cpNumber(rec.Version)
	key["Payload"] = cpString(string(rec.Value))
	switch rec.Kind {
	case controlplane.ApplicationKind:
		// An application row no longer indexes its owner: the owner set is
		// many-valued, and ApplicationOwnerKind rows index each member. A row
		// written before owner sets still carries the single-owner entry the
		// old layout gave it until its next write replaces the whole item, so
		// the expected row reproduces that entry exactly and cpRecord accepts
		// it. Commit never writes it (see cpWritable). Those partitions are
		// OWNER#<user ID>, and user IDs are UUIDs (controlplane.NewID), so they
		// never share a partition with an owner key's OWNER#user:<ID>.
		if fields.legacyOwner != "" {
			key["GSI1PK"], key["GSI1SK"] = cpString("OWNER#"+fields.legacyOwner), cpString("APP#"+rec.ID)
		}
	case controlplane.ApplicationOwnerKind:
		// The owner row's own GSI1 entry is the owner index: one partition
		// per owner key, sorted by application, so "what does this owner own"
		// is one bounded, paged query with no companion row. A stale page is
		// re-read strongly in Query like every other index.
		key["GSI1PK"], key["GSI1SK"] = cpString("OWNER#"+rec.ID), cpString("APP#"+rec.ParentID)
	case controlplane.DeploymentKind:
		if fields.State == controlplane.Queued || fields.State == controlplane.Running {
			key["GSI1PK"], key["GSI1SK"] = cpString("DEPLOYQUEUE#"+string(fields.State)), cpString(encodeInstant(fields.CreatedAt)+"#"+rec.ID)
		}
	case controlplane.SessionKind, controlplane.FamilyKind:
		key["GSI1PK"], key["GSI1SK"] = cpString("USER#"+fields.UserID), cpString(string(rec.Kind)+"#"+fields.ID+"#"+rec.ID)
	case controlplane.DetectionKind:
		// Only a queued detection needs to be found by the worker's poll; a
		// terminal one is only ever read back by its own ID, exactly as a
		// terminal deployment's queue entry is dropped once it leaves
		// Queued/Running.
		if controlplane.DetectionState(fields.State) == controlplane.DetectionQueued {
			key["GSI1PK"], key["GSI1SK"] = cpString("DETECTQUEUE#"+string(fields.State)), cpString(encodeInstant(fields.CreatedAt)+"#"+rec.ID)
		}
	case controlplane.GitHubInstallationKind:
		// One flat directory: installations have no owner, and the admin
		// Workspace is the only reader, so there is exactly one listing shape
		// to support -- unlike ApplicationKind, which needs both an
		// owner-scoped view (the ApplicationOwnerKind rows) and an admin-wide
		// one (its companion row). See cpScope.
		key["GSI1PK"], key["GSI1SK"] = cpString("GITHUB_INSTALLATIONS"), cpString("INSTALL#"+rec.ID)
	case controlplane.DirectoryEntitlementKind:
		// One flat directory, same reasoning as GitHubInstallationKind above:
		// entitlements have no owner, and the admin Workspace is the only
		// reader.
		key["GSI1PK"], key["GSI1SK"] = cpString("DIRECTORY_ENTITLEMENTS"), cpString("ENT#"+rec.ID)
	case controlplane.RoleMappingKind:
		// One flat directory, same reasoning as DirectoryEntitlementKind
		// above: mappings have no owner, and the admin Workspace is the only
		// reader. GroupMembershipKind, by contrast, is read only by its own
		// ID (one identity's cached membership) and so gets no GSI entry at
		// all -- there is no "list every cached membership" reader.
		key["GSI1PK"], key["GSI1SK"] = cpString("ROLE_MAPPINGS"), cpString("MAP#"+rec.ID)
	case controlplane.FeatureFlagKind:
		// One flat directory, same reasoning as RoleMappingKind above: flags
		// have no owner, and the admin Workspace is the only reader.
		key["GSI1PK"], key["GSI1SK"] = cpString("FEATURE_FLAGS"), cpString("FLAG#"+rec.ID)
	}
	// Refresh tombstones must survive until family expiry, not token expiry.
	// They, idempotency records, and non-auth records intentionally have no TTL.
	switch rec.Kind {
	case controlplane.SessionKind, controlplane.LoginKind, controlplane.ConsentKind, controlplane.CodeKind, controlplane.FamilyKind, controlplane.AccessKind, controlplane.GitHubManifestKind:
		if !fields.ExpiresAt.IsZero() {
			key["TTL"] = cpNumber(fields.ExpiresAt.Unix())
		}
	}
	return key, nil
}

func cpRecord(item map[string]types.AttributeValue) (controlplane.Record, error) {
	rec := controlplane.Record{RecordID: controlplane.RecordID{Kind: controlplane.RecordKind(cpText(item, "Kind")), ID: cpText(item, "ID"), ParentID: cpText(item, "ParentID")}, Value: json.RawMessage(cpText(item, "Payload"))}
	v, ok := item["Version"].(*types.AttributeValueMemberN)
	if !ok {
		return controlplane.Record{}, controlplane.ErrUnavailable
	}
	var err error
	rec.Version, err = strconv.ParseInt(v.Value, 10, 64)
	if err != nil {
		return controlplane.Record{}, controlplane.ErrUnavailable
	}
	expected, err := cpItem(rec)
	if err != nil {
		return controlplane.Record{}, controlplane.ErrUnavailable
	}
	for _, name := range []string{attrPK, attrSK, "GSI1PK", "GSI1SK"} {
		if cpText(expected, name) != cpText(item, name) {
			return controlplane.Record{}, controlplane.ErrUnavailable
		}
	}
	return rec, nil
}

func (r *ControlPlaneRecords) get(ctx context.Context, key map[string]types.AttributeValue) (map[string]types.AttributeValue, error) {
	out, err := r.client.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(r.client.tableName), Key: key, ConsistentRead: aws.Bool(true)})
	if err != nil || out == nil {
		return nil, controlplane.ErrUnavailable
	}
	if len(out.Item) == 0 {
		return nil, controlplane.ErrNotFound
	}
	return out.Item, nil
}

func (r *ControlPlaneRecords) Read(ctx context.Context, id controlplane.RecordID) (controlplane.Record, error) {
	key, err := cpBaseKey(id)
	if err != nil {
		return controlplane.Record{}, err
	}
	item, err := r.get(ctx, key)
	if err != nil {
		return controlplane.Record{}, err
	}
	if id.Kind == controlplane.DeploymentKind {
		version, ok := item["Version"].(*types.AttributeValueMemberN)
		if !ok {
			return controlplane.Record{}, controlplane.ErrUnavailable
		}
		n, parseErr := strconv.ParseInt(version.Value, 10, 64)
		if parseErr != nil || n <= 0 || cpText(item, attrPK) != cpText(key, attrPK) || cpText(item, attrSK) != skMetadata {
			return controlplane.Record{}, controlplane.ErrUnavailable
		}
		parent, sk := cpText(item, "ParentID"), cpText(item, "HistorySK")
		if !cpComponent(parent) || cpText(item, "ID") != id.ID || cpText(item, "Kind") != string(id.Kind) || !strings.HasPrefix(sk, "DEPLOY#") || !strings.HasSuffix(sk, "#"+id.ID) {
			return controlplane.Record{}, controlplane.ErrUnavailable
		}
		if id.ParentID != "" && parent != id.ParentID {
			return controlplane.Record{}, controlplane.ErrNotFound
		}
		id.ParentID = parent
		item, err = r.get(ctx, cpKey("APP#"+parent, sk))
		if err != nil {
			return controlplane.Record{}, err
		}
	}
	rec, err := cpRecord(item)
	if err != nil {
		return controlplane.Record{}, err
	}
	if rec.RecordID != id {
		return controlplane.Record{}, controlplane.ErrUnavailable
	}
	return rec, nil
}

func cpCompanion(rec controlplane.Record, item map[string]types.AttributeValue) map[string]types.AttributeValue {
	var companion map[string]types.AttributeValue
	switch rec.Kind {
	case controlplane.ApplicationKind:
		companion = cpKey("APP#"+rec.ID, "DIRECTORY")
		companion["GSI1PK"], companion["GSI1SK"] = cpString("APPLICATIONS"), cpString("APP#"+rec.ID)
	case controlplane.DeploymentKind:
		companion = cpKey("DEPLOY#"+rec.ID, skMetadata)
		companion["ParentID"], companion["HistorySK"] = cpString(rec.ParentID), item[attrSK]
	case controlplane.UserKind:
		// One flat directory, same reasoning as GitHubInstallationKind: users
		// have no owner, and the Workspace's Members tab is the only reader.
		// Unlike that kind, User predates this directory -- existing rows
		// were written before any companion existed, so this one row's
		// condition is relaxed in Commit to tolerate a first appearance at a
		// nonzero expected version. It is a companion, not a GSI1 attribute on
		// the primary row itself, so an existing user's session can still be
		// read and rewritten (see Read, cpRecord) before it ever gets one.
		companion = cpKey("USER#"+rec.ID, "DIRECTORY")
		companion["GSI1PK"], companion["GSI1SK"] = cpString("USERS"), cpString("USER#"+rec.ID)
	default:
		return nil
	}
	companion["Kind"], companion["ID"], companion["Version"] = cpString(string(rec.Kind)), cpString(rec.ID), cpNumber(rec.Version)
	return companion
}

// cpWritable is what a write must satisfy beyond what a read accepts. Reads
// keep accepting a legacy single-owner application (see cpApplicationOwners);
// a write must carry the owner set, so no new row is ever written in the
// shape whose owner the index no longer covers.
func cpWritable(rec controlplane.Record) bool {
	if rec.Kind != controlplane.ApplicationKind {
		return true
	}
	legacy, err := cpApplicationOwners(rec.Value)
	return err == nil && legacy == ""
}

// Commit atomically checks versions and writes all aggregate and directory rows.
func (r *ControlPlaneRecords) Commit(ctx context.Context, mutations []controlplane.Mutation) error {
	if len(mutations) == 0 || len(mutations) > 100 {
		return cpInvalid()
	}
	writes := make([]types.TransactWriteItem, 0, len(mutations))
	seen := make(map[string]bool, len(mutations))
	total := 0
	for _, mutation := range mutations {
		if mutation.ExpectedVersion < 0 || mutation.ExpectedVersion == math.MaxInt64 {
			return cpInvalid()
		}
		rec := mutation.Record
		if !mutation.Delete && !cpWritable(rec) {
			return cpInvalid()
		}
		key, err := cpBaseKey(rec.RecordID)
		if err != nil {
			return err
		}
		rec.Version = mutation.ExpectedVersion + 1
		var item map[string]types.AttributeValue
		if rec.Kind == controlplane.DeploymentKind && mutation.ExpectedVersion > 0 {
			old, readErr := r.Read(ctx, rec.RecordID)
			if errors.Is(readErr, controlplane.ErrNotFound) {
				return controlplane.ErrConflict
			}
			if readErr != nil {
				return readErr
			}
			if old.Version != mutation.ExpectedVersion {
				return controlplane.ErrConflict
			}
			rec.ParentID = old.ParentID
			oldItem, _ := cpItem(old)
			key = cpKey(cpText(oldItem, attrPK), cpText(oldItem, attrSK))
			if !mutation.Delete {
				item, err = cpItem(rec)
				if err != nil {
					return err
				}
				if cpText(item, attrSK) != cpText(oldItem, attrSK) {
					return cpInvalid()
				}
			}
		}
		if !mutation.Delete && item == nil {
			item, err = cpItem(rec)
			if err != nil {
				return err
			}
			key = cpKey(cpText(item, attrPK), cpText(item, attrSK))
		}
		if item == nil {
			item = key
		}
		items := []map[string]types.AttributeValue{item}
		// An absent deployment has only a direct key: there is no history
		// timestamp to locate or companion to remove.
		if rec.Kind != controlplane.DeploymentKind || !mutation.Delete || mutation.ExpectedVersion != 0 {
			if companion := cpCompanion(rec, item); companion != nil {
				items = append(items, companion)
			}
		}
		for i, row := range items {
			pk, sk := cpText(row, attrPK), cpText(row, attrSK)
			identity := pk + "\x00" + sk
			if seen[identity] {
				return cpInvalid()
			}
			seen[identity] = true
			// Attribute overhead is bounded by the fixed schema and bounded IDs.
			total += len(cpText(row, "Payload")) + 16*1024
			condition := "attribute_not_exists(PK)"
			var values map[string]types.AttributeValue
			var names map[string]string
			expectExisting := mutation.ExpectedVersion > 0
			// The Users directory companion (see cpCompanion) was introduced
			// after user records already existed without one: an existing
			// user's next login must still succeed even though this row has
			// never been written. Check its actual presence directly, rather
			// than a same-transaction OR condition, so only this one row's
			// requirement relaxes to "not yet created" -- the primary row
			// alongside it keeps requiring its exact expected version. Every
			// other companion (Application, Deployment) has existed since its
			// kind's own introduction and never needs this.
			if i > 0 && expectExisting && rec.Kind == controlplane.UserKind {
				_, getErr := r.get(ctx, cpKey(pk, sk))
				if getErr != nil && !errors.Is(getErr, controlplane.ErrNotFound) {
					return getErr
				}
				expectExisting = getErr == nil
			}
			if expectExisting {
				condition = "attribute_exists(PK) AND #version = :version"
				values = map[string]types.AttributeValue{":version": cpNumber(mutation.ExpectedVersion)}
				names = map[string]string{"#version": "Version"}
			}
			if mutation.Delete {
				writes = append(writes, types.TransactWriteItem{Delete: &types.Delete{TableName: aws.String(r.client.tableName), Key: cpKey(pk, sk), ConditionExpression: aws.String(condition), ExpressionAttributeNames: names, ExpressionAttributeValues: values}})
			} else {
				writes = append(writes, types.TransactWriteItem{Put: &types.Put{TableName: aws.String(r.client.tableName), Item: row, ConditionExpression: aws.String(condition), ExpressionAttributeNames: names, ExpressionAttributeValues: values}})
			}
		}
	}
	if r.client.auditTableName != "" && auditableCommit(ctx, mutations) {
		if len(writes) >= 100 || total+1024 > 4<<20 {
			return cpInvalid()
		}
		writes = append(writes, r.auditPut(ctx, mutations))
	}
	if len(writes) > 100 || total > 4<<20 {
		return cpInvalid()
	}
	_, err := r.client.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: writes})
	if err == nil {
		return nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(err, &canceled) {
		for _, reason := range canceled.CancellationReasons {
			if aws.ToString(reason.Code) == "ConditionalCheckFailed" || aws.ToString(reason.Code) == "TransactionConflict" {
				return controlplane.ErrConflict
			}
		}
	}
	var conflict *types.TransactionConflictException
	if conditionFailed(err) || errors.As(err, &conflict) {
		return controlplane.ErrConflict
	}
	return controlplane.ErrUnavailable
}

type cpQueryScope struct{ index, partition, prefix string }

func cpScope(q controlplane.Query) (cpQueryScope, error) {
	if q.Limit < 0 || q.Limit > 100 || (q.OwnerUserID != "" && !cpComponent(q.OwnerUserID)) || (q.ApplicationID != "" && !cpComponent(q.ApplicationID)) {
		return cpQueryScope{}, cpInvalid()
	}
	// OwnerKey selects exactly one directory, so it is refused with any other
	// kind here rather than repeated as an "and no OwnerKey" in every shape
	// below.
	if q.OwnerKey != "" && (q.Kind != controlplane.ApplicationOwnerKind || !cpOwnerKey(q.OwnerKey)) {
		return cpQueryScope{}, cpInvalid()
	}
	// Applications have one listing, the admin-wide directory. "The
	// applications an owner owns" is the owner index below, not an
	// application query: an owner set has many members, and a group member
	// owns through a key no application row could index on its own.
	if q.Kind == controlplane.ApplicationKind && q.OwnerUserID == "" && q.ApplicationID == "" && q.State == "" {
		return cpQueryScope{indexGSI1, "APPLICATIONS", "APP#"}, nil
	}
	if q.Kind == controlplane.ApplicationOwnerKind && q.OwnerKey != "" && q.OwnerUserID == "" && q.ApplicationID == "" && q.State == "" {
		return cpQueryScope{indexGSI1, "OWNER#" + q.OwnerKey, "APP#"}, nil
	}
	if q.Kind == controlplane.DeploymentKind && q.OwnerUserID == "" {
		if q.ApplicationID != "" && q.State == "" {
			return cpQueryScope{"", "APP#" + q.ApplicationID, "DEPLOY#"}, nil
		}
		if q.ApplicationID == "" && (q.State == string(controlplane.Queued) || q.State == string(controlplane.Running)) {
			return cpQueryScope{indexGSI1, "DEPLOYQUEUE#" + q.State, ""}, nil
		}
	}
	if (q.Kind == controlplane.SessionKind || q.Kind == controlplane.FamilyKind) && q.OwnerUserID != "" && q.ApplicationID == "" && q.State == "" {
		return cpQueryScope{indexGSI1, "USER#" + q.OwnerUserID, string(q.Kind) + "#"}, nil
	}
	if q.Kind == controlplane.DetectionKind && q.OwnerUserID == "" && q.ApplicationID == "" && q.State == string(controlplane.DetectionQueued) {
		return cpQueryScope{indexGSI1, "DETECTQUEUE#" + q.State, ""}, nil
	}
	if q.Kind == controlplane.GitHubInstallationKind && q.OwnerUserID == "" && q.ApplicationID == "" && q.State == "" {
		return cpQueryScope{indexGSI1, "GITHUB_INSTALLATIONS", "INSTALL#"}, nil
	}
	if q.Kind == controlplane.DirectoryEntitlementKind && q.OwnerUserID == "" && q.ApplicationID == "" && q.State == "" {
		return cpQueryScope{indexGSI1, "DIRECTORY_ENTITLEMENTS", "ENT#"}, nil
	}
	if q.Kind == controlplane.RoleMappingKind && q.OwnerUserID == "" && q.ApplicationID == "" && q.State == "" {
		return cpQueryScope{indexGSI1, "ROLE_MAPPINGS", "MAP#"}, nil
	}
	if q.Kind == controlplane.FeatureFlagKind && q.OwnerUserID == "" && q.ApplicationID == "" && q.State == "" {
		return cpQueryScope{indexGSI1, "FEATURE_FLAGS", "FLAG#"}, nil
	}
	if q.Kind == controlplane.UserKind && q.OwnerUserID == "" && q.ApplicationID == "" && q.State == "" {
		return cpQueryScope{indexGSI1, "USERS", "USER#"}, nil
	}
	return cpQueryScope{}, cpInvalid()
}

type cpCursor struct {
	Scope string            `json:"scope"`
	Key   map[string]string `json:"key"`
}

func (s cpQueryScope) fingerprint() string {
	hash := sha256.Sum256([]byte(s.index + "\x00" + s.partition + "\x00" + s.prefix))
	return hex.EncodeToString(hash[:])
}
func (s cpQueryScope) cursorKey(encoded string) (map[string]types.AttributeValue, error) {
	if encoded == "" {
		return nil, nil
	}
	if len(encoded) > cpCursorLimit {
		return nil, cpInvalid()
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, cpInvalid()
	}
	var cursor cpCursor
	if json.Unmarshal(data, &cursor) != nil || cursor.Scope != s.fingerprint() {
		return nil, cpInvalid()
	}
	count := 2
	if s.index != "" {
		count = 4
	}
	if len(cursor.Key) != count {
		return nil, cpInvalid()
	}
	key := make(map[string]types.AttributeValue, count)
	for _, name := range []string{attrPK, attrSK, "GSI1PK", "GSI1SK"} {
		value, exists := cursor.Key[name]
		if !exists && s.index == "" && strings.HasPrefix(name, "GSI1") {
			continue
		}
		if value == "" || len(value) > 1024 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, cpInvalid()
		}
		key[name] = cpString(value)
	}
	pk, sk := attrPK, attrSK
	if s.index != "" {
		pk, sk = "GSI1PK", "GSI1SK"
	}
	if cpText(key, pk) != s.partition || !strings.HasPrefix(cpText(key, sk), s.prefix) {
		return nil, cpInvalid()
	}
	return key, nil
}
func (s cpQueryScope) encodeCursor(key map[string]types.AttributeValue) (string, error) {
	if len(key) == 0 {
		return "", nil
	}
	cursor := cpCursor{Scope: s.fingerprint(), Key: make(map[string]string, len(key))}
	for name, value := range key {
		text, ok := value.(*types.AttributeValueMemberS)
		if !ok {
			return "", controlplane.ErrUnavailable
		}
		cursor.Key[name] = text.Value
	}
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", controlplane.ErrUnavailable
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	if _, err := s.cursorKey(encoded); err != nil {
		return "", controlplane.ErrUnavailable
	}
	return encoded, nil
}

// Query reads a bounded supported directory and binds continuation cursors to its scope.
func (r *ControlPlaneRecords) Query(ctx context.Context, q controlplane.Query) (controlplane.RecordPage, error) {
	scope, err := cpScope(q)
	if err != nil {
		return controlplane.RecordPage{}, err
	}
	start, err := scope.cursorKey(q.Cursor)
	if err != nil {
		return controlplane.RecordPage{}, controlplane.ErrInvalidCursor
	}
	limit := q.Limit
	if limit == 0 {
		limit = 50
	}
	pk, sk := attrPK, attrSK
	if scope.index != "" {
		pk, sk = "GSI1PK", "GSI1SK"
	}
	// Application history sorts on DEPLOY#<instant>#<id>. A forward scan is
	// oldest first, so a limit would return the earliest attempts. Newest first
	// makes that limit the latest page. Queue listings stay oldest first.
	forward := q.Kind != controlplane.DeploymentKind || q.ApplicationID == "" || q.State != ""
	input := &dynamodb.QueryInput{TableName: aws.String(r.client.tableName), KeyConditionExpression: aws.String("#pk = :pk"), ExpressionAttributeNames: map[string]string{"#pk": pk}, ExpressionAttributeValues: map[string]types.AttributeValue{":pk": cpString(scope.partition)}, ExclusiveStartKey: start, Limit: aws.Int32(int32(limit)), ScanIndexForward: aws.Bool(forward)}
	if scope.prefix != "" {
		input.KeyConditionExpression = aws.String("#pk = :pk AND begins_with(#sk, :prefix)")
		input.ExpressionAttributeNames["#sk"] = sk
		input.ExpressionAttributeValues[":prefix"] = cpString(scope.prefix)
	}
	if scope.index != "" {
		input.IndexName = aws.String(scope.index)
	} else {
		input.ConsistentRead = aws.Bool(true)
	}
	out, err := r.client.api.Query(ctx, input)
	if err != nil || out == nil {
		return controlplane.RecordPage{}, controlplane.ErrUnavailable
	}
	page := controlplane.RecordPage{Records: make([]controlplane.Record, 0, len(out.Items))}
	for _, item := range out.Items {
		id := controlplane.RecordID{Kind: controlplane.RecordKind(cpText(item, "Kind")), ID: cpText(item, "ID"), ParentID: cpText(item, "ParentID")}
		if id.Kind != q.Kind {
			return controlplane.RecordPage{}, controlplane.ErrUnavailable
		}
		rec, err := r.Read(ctx, id)
		if errors.Is(err, controlplane.ErrNotFound) {
			continue
		}
		if err != nil {
			return controlplane.RecordPage{}, controlplane.ErrUnavailable
		}
		fields, _ := cpInspect(rec)
		if q.OwnerUserID != "" && fields.UserID != q.OwnerUserID {
			continue
		}
		if q.OwnerKey != "" && rec.ID != q.OwnerKey {
			continue
		}
		if q.ApplicationID != "" && rec.ParentID != q.ApplicationID {
			continue
		}
		if q.State != "" && string(fields.State) != q.State {
			continue
		}
		page.Records = append(page.Records, rec)
	}
	page.Cursor, err = scope.encodeCursor(out.LastEvaluatedKey)
	if err != nil {
		return controlplane.RecordPage{}, err
	}
	return page, nil
}

// Ready performs one bounded authoritative read. An absent sentinel is healthy;
// a transport, permissions, or missing-table failure is not.
func (r *ControlPlaneRecords) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := r.get(ctx, cpKey("CONTROLPLANE#READINESS", skMetadata))
	if err != nil && !errors.Is(err, controlplane.ErrNotFound) {
		return fmt.Errorf("control plane storage: %w", controlplane.ErrUnavailable)
	}
	if r.client.auditTableName != "" {
		_, err = r.client.api.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(r.client.auditTableName), Key: cpKey(auditPartition, "READINESS"), ConsistentRead: aws.Bool(true)})
		if err != nil {
			return fmt.Errorf("audit storage: %w", controlplane.ErrUnavailable)
		}
	}
	return nil
}
