// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review

import "context"

// Depth selects how hard a scan works.
type Depth string

const (
	// DepthQuick is a single pass over a curated bundle of the tree.
	DepthQuick Depth = "scan-quick"
	// DepthDeep is an agentic loop that reads what it decides to read. More
	// thorough and more expensive.
	DepthDeep Depth = "scan-deep"
)

// Depths returns the two depths, in the order the schema publishes them.
func Depths() []Depth { return []Depth{DepthQuick, DepthDeep} }

// Usage counts what a scan consumed. The fields are provider-neutral on
// purpose: they are the counters every metered model API reports, and a
// provider that reports fewer leaves the rest zero.
type Usage struct {
	// InputTokens is the prompt token count summed over every call.
	InputTokens int64 `json:"inputTokens,omitempty"`
	// OutputTokens is the completion token count summed over every call.
	OutputTokens int64 `json:"outputTokens,omitempty"`
	// CacheReadTokens is the count served from a prompt cache.
	CacheReadTokens int64 `json:"cacheReadTokens,omitempty"`
	// CacheCreationTokens is the count written to a prompt cache.
	CacheCreationTokens int64 `json:"cacheCreationTokens,omitempty"`
	// Calls is the number of model calls made.
	Calls int `json:"calls,omitempty"`
}

// Add accumulates other into u.
func (u *Usage) Add(other Usage) {
	u.InputTokens += other.InputTokens
	u.OutputTokens += other.OutputTokens
	u.CacheReadTokens += other.CacheReadTokens
	u.CacheCreationTokens += other.CacheCreationTokens
	u.Calls += other.Calls
}

// Cost is what a scan consumed and what it was billed.
//
// EstimatedCostMicros is supplied by the [Scanner], not computed here. That is
// a deliberate departure from the source, which held a per-model rate card
// inside the module: a rate card belongs to whoever is being billed by whom,
// it goes stale the week it is written, and a module that carries one cannot
// be pointed at a different provider. The provider prices its own calls.
type Cost struct {
	// Model identifies what ran, in the provider's own vocabulary.
	Model string `json:"model,omitempty"`
	// Usage is what was consumed.
	Usage Usage `json:"usage"`
	// EstimatedCostMicros is millionths of a currency unit, as the provider
	// estimates it. Zero means "not priced", which is distinct from free.
	EstimatedCostMicros int64 `json:"estimatedCostMicros,omitempty"`
}

// Empty reports whether this cost records no model activity at all. A store
// may skip writing an empty cost.
func (c Cost) Empty() bool { return c.Usage.Calls == 0 }

// ScanRequest is what a [Scanner] is asked to do.
//
// Owner, Repo and Ref are context for the provider's prompt and nothing else.
// They have already been validated, and a [Scanner] must not perform I/O
// against them: [Tree] is the only thing a scan reads.
type ScanRequest struct {
	// Depth selects the scan strategy.
	Depth Depth
	// Tree is the snapshot to analyse.
	Tree Tree
	// Owner, Repo and Ref describe where the snapshot came from.
	Owner string
	Repo  string
	Ref   string
}

// ScanResult is what a [Scanner] found.
type ScanResult struct {
	// Findings is what the scan reported, unsanitised. [Module.Execute]
	// sanitises every one before it is stored, so an implementation does not
	// have to.
	Findings []Finding
	// Iterations counts the provider's internal rounds, for diagnostics.
	Iterations int
	// BytesRead counts what the scan read out of the tree, for diagnostics.
	BytesRead int64
	// Cost is what the scan consumed and was billed.
	Cost Cost
}

// Scanner is the AI-provider seam: the one thing in this port that knows how
// to look at code and say what is wrong with it.
//
// Nothing in this package implements it, and nothing in this package describes
// what a scan should look for. An adopter brings their own provider, and the
// detection strategy stays with them.
//
// Scan may return a non-nil result alongside a non-nil error, and
// [Module.Execute] relies on that: a scan that made several billable calls and
// then failed has a cost that must still be recorded. An implementation that
// spent nothing before failing returns a nil result, and one that spent
// something returns what it spent.
type Scanner interface {
	Scan(ctx context.Context, req ScanRequest) (*ScanResult, error)
}
