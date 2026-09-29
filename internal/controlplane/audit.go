// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
)

// AuditEntry is safe metadata about one committed state change. It must never
// contain record values, credentials, request bodies, OAuth codes or tokens.
type AuditEntry struct {
	ID         string            `json:"id"`
	OccurredAt string            `json:"occurredAt"`
	Actor      string            `json:"actor"`
	Action     string            `json:"action"`
	Target     string            `json:"target"`
	Details    map[string]string `json:"details,omitempty"`
}

// AuditPage contains newest-first entries and an opaque cursor (empty at end).
type AuditPage struct {
	Items  []AuditEntry `json:"items"`
	Cursor string       `json:"cursor"`
}

// AuditWriter records events that are not one state-table transaction: non-Dynamo
// side effects (such as replacement of a private key in SSM), and summaries of
// periodic syncs whose individual record writes are not audited. Details must be
// allowlisted, nonsecret values.
type AuditWriter interface {
	AppendAudit(ctx context.Context, actor, action, target string, details map[string]string) error
}

// DirectorySyncAction labels the directory catalog sync. Its per-group record
// writes are not audited one by one; the sync appends a single summary entry
// under this action instead, so the log shows one row per sync rather than one
// per group every few minutes.
const DirectorySyncAction = "directory.sync"

// AuditReader is implemented by the separate-table storage adapter.
type AuditReader interface {
	ListAudit(context.Context, int, string) (AuditPage, error)
}

type auditContextKey struct{}
type auditContextValue struct{ Actor, Action, Target string }

// WithAuditContext labels repository commits made by this request. Actor must
// come from verified authentication, never a client-supplied header. Action and
// Target must be fixed routing metadata and validated resource IDs, not bodies.
func WithAuditContext(ctx context.Context, actor, action, target string) context.Context {
	return context.WithValue(ctx, auditContextKey{}, auditContextValue{actor, action, target})
}

// AuditContext returns an empty value outside authenticated request paths.
func AuditContext(ctx context.Context) (actor, action, target string) {
	v, _ := ctx.Value(auditContextKey{}).(auditContextValue)
	return v.Actor, v.Action, v.Target
}

// auditPrincipal uses the verified HTTP actor when present, but the domain
// operation supplies the action and target so the viewer shows meaningful
// events rather than route templates. MCP callers use the rechecked principal.
func auditPrincipal(ctx context.Context, p Principal, action, target string) context.Context {
	actor, _, _ := AuditContext(ctx)
	if actor == "" {
		actor = p.UserID
	}
	return WithAuditContext(ctx, actor, action, target)
}

// WithAuditReader wires the admin viewer without exposing storage SDK types.
func WithAuditReader(reader AuditReader) ServiceOption {
	return func(s *Service) { s.auditReader = reader }
}

// WithAuditWriter enables audit of successful external side effects.
func WithAuditWriter(writer AuditWriter) ServiceOption {
	return func(s *Service) { s.auditWriter = writer }
}

// ListAuditLogs enforces the same administrative eligibility recheck as other
// workspace surfaces, and never falls back to an unscoped table read.
func (s *Service) ListAuditLogs(ctx context.Context, p Principal, limit int, cursor string) (AuditPage, error) {
	if _, err := s.requireAdmin(ctx, p, ApplicationsRead); err != nil {
		return AuditPage{}, err
	}
	if s.auditReader == nil {
		return AuditPage{}, unavailable()
	}
	return s.auditReader.ListAudit(ctx, limit, cursor)
}
