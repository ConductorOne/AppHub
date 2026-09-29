// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package modules

import "context"

// Result is what a module has to say about an execution.
//
// It is not "the success case", and the two off-diagonal combinations both
// occur in the code this was ported from. One of the nine modules there returns
// a populated Result alongside a non-nil error, to preserve what it had already
// created (deploy/lambda.go:328-332); one returns Success false with a nil
// error, computed from a rolled-up delivery status (announce/delivery.go:222-232).
// So a caller that reads a Result only when err == nil throws information away,
// and one that reads Success as a restatement of err == nil is wrong in the
// other direction. See [Module]'s Execute.
//
// Data is deliberately untyped: it is the return channel for whatever a
// particular module has to say, serialised to JSON for the caller, and the
// caller knows which module it invoked.
type Result struct {
	Success   bool           `json:"success"`
	RequestID string         `json:"requestId,omitempty"`
	Message   string         `json:"message"`
	Data      map[string]any `json:"data,omitempty"`
}

// JSONSchema is a module's published parameter contract.
//
// It is a deliberately small subset of JSON Schema — enough to describe a flat
// parameter map, and no more. It is published to callers alongside the module's
// metadata, so it is what a caller has to go on when deciding what to send.
//
// It is not a general validator and is not meant to become one. All nine ported
// modules check more in their own Validate than Properties and Required can
// express — required-field presence, string enums, integer bounds, mode-
// dependent requirements — and that is where such checks belong.
type JSONSchema struct {
	Type       string                        `json:"type"`
	Properties map[string]JSONSchemaProperty `json:"properties,omitempty"`
	Required   []string                      `json:"required,omitempty"`
}

// JSONSchemaProperty describes one parameter.
//
// Minimum and Maximum are pointers so that a bound of zero is distinguishable
// from an absent bound.
type JSONSchemaProperty struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Default     any      `json:"default,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Minimum     *int     `json:"minimum,omitempty"`
	Maximum     *int     `json:"maximum,omitempty"`
}

// Module is the contract every AppHub capability implements.
//
// The first five methods are metadata: with Schema they are what a caller needs
// to list and describe what is available without executing any of it.
// [BaseModule] supplies all five, so an implementation embeds it and writes only
// the last three.
//
// The parameter map is the general shape on purpose, and changing it is not a
// local decision — see the package doc and docs/decisions/.
//
// What to do with a capability whose inputs do not fit a flat map is an open
// question, not a solved one. Nesting a structured value under a single key
// works, and the framework carries it through untouched, but it is untried: no
// module in the code this was ported from does it, and the one capability there
// with genuinely rich inputs was deliberately left outside this interface and
// invoked directly instead. So do not narrow this interface, because that
// closes options still needed -- but do not read its generality as having
// already settled how such a capability arrives.
type Module interface {
	// ID is the module's unique identifier, and the key it is registered and
	// invoked under. It must be stable across releases: in the code this was
	// ported from it is persisted on every request row and used as a queue job
	// type, so changing one orphans stored work.
	//
	// [Registry] does not depend on that being honoured. It snapshots the ID at
	// registration and never asks again, so an implementation that changes what
	// it reports cannot corrupt the registry -- it only makes itself disagree
	// with the key it was registered under. Stability is still the contract;
	// the registry simply does not rely on an implementation keeping it.
	ID() string

	// Name is the human-readable display name.
	Name() string

	// Description says what the module does, for a human choosing between them.
	Description() string

	// Icon names an icon for the module. The vocabulary is the caller's. The
	// source declared it as a Material icon name in its own comment, and all
	// nine of its modules pass a lowercase snake_case identifier of that form
	// ("docker", "bug_report", "auto_fix_high") -- form, not membership:
	// nothing here checks the name against any icon set, and nothing requires
	// that one.
	Icon() string

	// Category groups related modules. Registry.ListByCategory filters on it.
	Category() string

	// Execute runs the module.
	//
	// userID identifies the requester. Authorisation happens before dispatch:
	// it is not an authorisation token, none of the nine ported modules derives
	// a permission from it, and a module must not read one into its presence.
	//
	// What a module does with it beyond that is the module's choice, and the
	// ported ones do not agree. Two record it on what they write
	// (security/agent_scan.go:488 and security/deepsec_scan.go:191, both as a
	// requestedBy field); one discards it explicitly (security/agent_fix.go:692,
	// `_ = userID`); the other six never reference it. It can also be empty:
	// one of the five dispatch paths in the source (cmd/job-runner/main.go:540)
	// has no requester to pass and passes "". So a module that needs it must
	// handle its absence, and this repository does not require every module to
	// record it -- doing so would be a new obligation invented in a comment.
	//
	// The two return values are INDEPENDENT, and a caller must inspect both. A
	// non-nil error does not imply a nil Result, and a non-nil Result does not
	// imply a nil error. A module that got part of the way and then failed
	// returns both: the error says it failed, and the Result carries what it
	// managed to do -- a deploy that created the function but could not attach
	// its load balancer returns the function's identifiers alongside the error,
	// because that state exists and the caller needs it to clean up or resume.
	// Discarding the Result because the error is non-nil loses it.
	//
	// Success is likewise the module's own statement about the outcome, not a
	// restatement of err == nil. Do not derive either from the other.
	//
	// A module validates before it acts, rather than assuming its caller did.
	// That is the convention here, and seven of the nine ported implementations
	// already open Execute with their own Validate call -- the two deploy
	// modules are the exceptions, and they rely on the dispatch path having
	// validated. Relying on that makes every future call path a place the check
	// can be forgotten, so it is not the convention adopted here.
	Execute(ctx context.Context, userID string, params map[string]any) (*Result, error)

	// Validate reports whether params are acceptable, without executing.
	//
	// In this repository every implementation begins by rejecting parameters its
	// schema does not declare -- see [ValidateDeclaredParams] -- and then checks
	// the ones it did. That is a rule adopted here, not an inherited habit: in
	// the code this was ported from the check existed but only two of the nine
	// modules called it.
	Validate(params map[string]any) error

	// Schema is the module's published parameter contract. A module that
	// returns nil declares nothing, and [ValidateDeclaredParams] will then
	// reject every parameter it is given.
	Schema() *JSONSchema
}

// BaseModule supplies the five metadata methods of [Module] from stored
// strings. Embed it by value and implement Execute, Validate, and Schema:
//
//	type ExampleModule struct {
//		modules.BaseModule
//		store FindingsWriter // an interface this package declares
//	}
//
// BaseModule's methods are on the pointer receiver, so a type embedding it
// satisfies [Module] as a pointer (*ExampleModule) rather than as a value. That
// is a property of the embedding, not a requirement of the interface: a type
// implementing all eight methods itself may do so on value receivers.
// The fields are unexported and there is no setter, so a module's metadata is
// fixed at construction.
//
// They were exported, and that was a defect in delivered behaviour rather than a
// matter of taste: [Registry] is keyed by module ID, rejects a duplicate ID, and
// orders by ID, and an ordinary assignment to an exported field after
// registration broke all three. No race and no malformed implementation were
// needed — `m.ModuleID = "other"` was a legal cross-package state transition
// through this API.
//
// This closes it for the type this package ships. It cannot close it for an
// arbitrary [Module] implementation, which is why the Registry does not rely on
// it: see the snapshot Register takes.
type BaseModule struct {
	id          string
	name        string
	description string
	icon        string
	category    string
}

// NewBaseModule returns a BaseModule carrying the given metadata.
//
// It is the only way to set any of it. A zero BaseModule reports empty strings,
// and a module with an empty ID is refused by [Registry.Register] rather than
// registered under a key nothing can name.
func NewBaseModule(id, name, description, icon, category string) BaseModule {
	return BaseModule{
		id:          id,
		name:        name,
		description: description,
		icon:        icon,
		category:    category,
	}
}

// ID implements [Module].
func (m *BaseModule) ID() string { return m.id }

// Name implements [Module].
func (m *BaseModule) Name() string { return m.name }

// Description implements [Module].
func (m *BaseModule) Description() string { return m.description }

// Icon implements [Module].
func (m *BaseModule) Icon() string { return m.icon }

// Category implements [Module].
func (m *BaseModule) Category() string { return m.category }
