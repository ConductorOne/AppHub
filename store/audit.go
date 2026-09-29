// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/conductorone/apphub/internal/controlplane"
)

const auditPartition = "AUDIT"

// Ephemeral protocol challenges, idempotency receipts, periodically refreshed
// membership caches, unchanged worker heartbeats and the directory sync's
// per-group writes are not independent user-visible changes. The directory sync
// records one summary entry per run through AppendAudit instead. Target
// configuration and deployment state transitions remain audited.
func auditableCommit(ctx context.Context, mutations []controlplane.Mutation) bool {
	_, action, _ := controlplane.AuditContext(ctx)
	if action == "target.heartbeat" && len(mutations) == 1 && mutations[0].Record.Kind == controlplane.TargetKind {
		return false
	}
	if action == controlplane.DirectorySyncAction && onlyKind(mutations, controlplane.DirectoryEntitlementKind) {
		return false
	}
	if action == "deployment.heartbeat" && len(mutations) == 2 &&
		mutations[0].Record.Kind == controlplane.DeploymentKind && mutations[1].Record.Kind == controlplane.ApplicationKind {
		return false
	}
	for _, mutation := range mutations {
		switch mutation.Record.Kind {
		case controlplane.LoginKind, controlplane.GitHubManifestKind,
			controlplane.IdempotencyKind, controlplane.GroupMembershipKind:
			continue
		default:
			return true
		}
	}
	return false
}

func onlyKind(mutations []controlplane.Mutation, kind controlplane.RecordKind) bool {
	for _, mutation := range mutations {
		if mutation.Record.Kind != kind {
			return false
		}
	}
	return len(mutations) > 0
}

var (
	_ controlplane.AuditReader = (*ControlPlaneRecords)(nil)
	_ controlplane.AuditWriter = (*ControlPlaneRecords)(nil)
)

// auditPut creates a write in the same DynamoDB transaction as the domain
// changes. A failed or conflicting transaction creates no entry; a committed
// mutation cannot be acknowledged without its audit event. Only a known-safe
// local user ID may be read from a domain envelope; payloads are never logged.
func (r *ControlPlaneRecords) auditPut(ctx context.Context, mutations []controlplane.Mutation) types.TransactWriteItem {
	actor, action, target := controlplane.AuditContext(ctx)
	if actor == "" {
		actor = "system"
		for _, mutation := range mutations {
			if mutation.Record.Kind == controlplane.UserKind && len(mutation.Record.ID) == 36 {
				actor = mutation.Record.ID
				break
			}
			if mutation.Record.Kind == controlplane.SessionKind || mutation.Record.Kind == controlplane.FamilyKind {
				// Project only the known-safe local user ID, never session
				// secrets or token fields from the domain envelope.
				var owner struct {
					UserID string `json:"userId"`
				}
				if json.Unmarshal(mutation.Record.Value, &owner) == nil && len(owner.UserID) == 36 {
					actor = owner.UserID
					break
				}
			}
		}
	}
	primary := mutations[0]
	for _, mutation := range mutations {
		switch mutation.Record.Kind {
		case controlplane.ApplicationKind, controlplane.DeploymentKind, controlplane.RoleMappingKind,
			controlplane.FeatureFlagKind, controlplane.GitHubAppConfigKind, controlplane.GitHubInstallationKind,
			controlplane.SessionKind, controlplane.FamilyKind, controlplane.UserKind:
			primary = mutation
			goto selected
		}
	}
selected:
	if action == "" {
		action = string(primary.Record.Kind) + ".update"
		if primary.Delete {
			action = string(primary.Record.Kind) + ".delete"
		} else if primary.ExpectedVersion == 0 {
			action = string(primary.Record.Kind) + ".create"
		}
	}
	if target == "" {
		switch primary.Record.Kind {
		case controlplane.ApplicationKind, controlplane.DeploymentKind, controlplane.HostnameKind,
			controlplane.DetectionKind, controlplane.TargetKind, controlplane.GitHubAppConfigKind, controlplane.GitHubInstallationKind,
			controlplane.RoleMappingKind, controlplane.FeatureFlagKind, controlplane.DirectoryEntitlementKind:
			target = string(primary.Record.Kind) + ":" + primary.Record.ID
		default:
			// Authentication keys, tokens, session IDs and identity subjects
			// must not become audit targets.
			target = string(primary.Record.Kind)
		}
	}
	details := map[string]string{"records": strconv.Itoa(len(mutations))}
	if !primary.Delete {
		switch primary.Record.Kind {
		case controlplane.FeatureFlagKind, controlplane.RoleMappingKind, controlplane.DeploymentKind:
			// Read only allowlisted enum fields. Never copy an application's
			// specification, deployment message, secret names or raw payload.
			var metadata struct {
				Mode  string                       `json:"mode"`
				Role  string                       `json:"role"`
				State controlplane.DeploymentState `json:"state"`
			}
			if json.Unmarshal(primary.Record.Value, &metadata) == nil {
				switch primary.Record.Kind {
				case controlplane.FeatureFlagKind:
					switch metadata.Mode {
					case controlplane.FeatureFlagOff, controlplane.FeatureFlagOn, controlplane.FeatureFlagGroup:
						details["mode"] = metadata.Mode
					}
				case controlplane.RoleMappingKind:
					switch metadata.Role {
					case controlplane.RoleMember, controlplane.RoleAppOwner, controlplane.RoleAdmin, controlplane.RoleVulnAdmin:
						details["role"] = metadata.Role
					}
				case controlplane.DeploymentKind:
					switch metadata.State {
					case controlplane.Queued, controlplane.Running, controlplane.Succeeded, controlplane.Failed, controlplane.Interrupted:
						details["state"] = string(metadata.State)
					}
				}
			}
		}
	}
	item := newAuditItem(actor, action, target, details)
	return types.TransactWriteItem{Put: &types.Put{
		TableName: aws.String(r.client.auditTableName), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	}}
}

func newAuditItem(actor, action, target string, details map[string]string) map[string]types.AttributeValue {
	now := time.Now().UTC()
	// Fixed-width fractional seconds preserve chronological sort order.
	occurredAt := now.Format("2006-01-02T15:04:05.000000000Z")
	id := controlplane.NewID()
	item := cpKey(auditPartition, occurredAt+"#"+id)
	item["id"] = cpString(id)
	item["occurredAt"] = cpString(occurredAt)
	item["actor"] = cpString(actor)
	item["action"] = cpString(action)
	item["target"] = cpString(target)
	if len(details) > 0 {
		attributes := make(map[string]types.AttributeValue, len(details))
		for key, value := range details {
			attributes[key] = cpString(value)
		}
		item["details"] = &types.AttributeValueMemberM{Value: attributes}
	}
	item["expiresAt"] = cpNumber(now.Add(400 * 24 * time.Hour).Unix())
	return item
}

// AppendAudit logs an external side effect after it succeeds. SSM and DynamoDB
// cannot share a transaction; failure is returned to the caller rather than
// silently claiming that an unaudited mutation succeeded.
func (r *ControlPlaneRecords) AppendAudit(ctx context.Context, actor, action, target string, details map[string]string) error {
	if r.client.auditTableName == "" || actor == "" || action == "" || target == "" {
		return controlplane.ErrUnavailable
	}
	_, err := r.client.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(r.client.auditTableName),
		Item:                newAuditItem(actor, action, target, details),
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})
	if err != nil {
		return controlplane.ErrUnavailable
	}
	return nil
}

// ListAudit uses a consistent reverse-chronological Query against only the
// audit table. The cursor encodes a sort key, never arbitrary DynamoDB input.
func (r *ControlPlaneRecords) ListAudit(ctx context.Context, limit int, cursor string) (controlplane.AuditPage, error) {
	if r.client.auditTableName == "" {
		return controlplane.AuditPage{}, controlplane.ErrUnavailable
	}
	if limit < 1 || limit > 100 || len(cursor) > 512 {
		return controlplane.AuditPage{}, controlplane.ErrInvalidCursor
	}
	var start map[string]types.AttributeValue
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || len(decoded) > 128 {
			return controlplane.AuditPage{}, controlplane.ErrInvalidCursor
		}
		timestamp, id, ok := strings.Cut(string(decoded), "#")
		if !ok || len(id) != 36 || !strings.HasSuffix(timestamp, "Z") {
			return controlplane.AuditPage{}, controlplane.ErrInvalidCursor
		}
		if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
			return controlplane.AuditPage{}, controlplane.ErrInvalidCursor
		}
		start = cpKey(auditPartition, string(decoded))
	}
	out, err := r.client.api.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(r.client.auditTableName),
		KeyConditionExpression:    aws.String("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": cpString(auditPartition)},
		ExclusiveStartKey:         start,
		Limit:                     aws.Int32(int32(limit)),
		ConsistentRead:            aws.Bool(true),
		ScanIndexForward:          aws.Bool(false),
	})
	if err != nil {
		return controlplane.AuditPage{}, controlplane.ErrUnavailable
	}
	page := controlplane.AuditPage{Items: make([]controlplane.AuditEntry, 0, len(out.Items))}
	for _, item := range out.Items {
		entry := controlplane.AuditEntry{ID: cpText(item, "id"), OccurredAt: cpText(item, "occurredAt"), Actor: cpText(item, "actor"), Action: cpText(item, "action"), Target: cpText(item, "target")}
		if entry.ID == "" || entry.OccurredAt == "" || entry.Actor == "" || entry.Action == "" || entry.Target == "" {
			return controlplane.AuditPage{}, controlplane.ErrUnavailable
		}
		if details, ok := item["details"].(*types.AttributeValueMemberM); ok {
			entry.Details = make(map[string]string, len(details.Value))
			for key, value := range details.Value {
				text, ok := value.(*types.AttributeValueMemberS)
				if !ok {
					return controlplane.AuditPage{}, controlplane.ErrUnavailable
				}
				entry.Details[key] = text.Value
			}
		}
		page.Items = append(page.Items, entry)
	}
	if len(out.LastEvaluatedKey) != 0 {
		sk := cpText(out.LastEvaluatedKey, attrSK)
		if sk == "" {
			return controlplane.AuditPage{}, errors.New("store: malformed audit continuation key")
		}
		page.Cursor = base64.RawURLEncoding.EncodeToString([]byte(sk))
	}
	return page, nil
}
