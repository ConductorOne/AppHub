// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Severity ranks a finding. The five values are the whole set; anything a
// scanner returns outside it is not guessed at, it is [SeverityInfo] -- see
// [NormaliseSeverity].
type Severity string

// The severity ladder, most severe first.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// severityRank orders the ladder for [HighestSeverity]. It is derived from one
// declaration rather than restated: [Severities] is built from this map's keys,
// so a value added here cannot be missed by the ordering or by the validator.
var severityRank = map[Severity]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
}

// Severities returns the severity ladder, most severe first. The order is
// derived from the same ranking [HighestSeverity] uses, so the two cannot
// disagree.
func Severities() []Severity {
	out := make([]Severity, 0, len(severityRank))
	for s := range severityRank {
		out = append(out, s)
	}
	// Insertion sort by descending rank: the population is five entries and a
	// stable, obviously-correct sort beats importing one.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && severityRank[out[j]] > severityRank[out[j-1]]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// NormaliseSeverity maps a scanner's free-text severity onto the ladder.
//
// A value outside the ladder becomes [SeverityInfo] rather than being carried
// through. The reason is that the result is written to a record and rendered,
// and a scanner is a model: an invented severity must never be able to reach
// [HighestSeverity] and misrank a whole scan.
func NormaliseSeverity(s string) Severity {
	if _, ok := severityRank[Severity(s)]; ok {
		return Severity(s)
	}
	return SeverityInfo
}

// HighestSeverity returns the most severe severity among findings, or
// [SeverityInfo] for an empty set. Each finding's severity is normalised
// first, so an unrecognised value cannot win.
func HighestSeverity(findings []Finding) Severity {
	highest := SeverityInfo
	for _, f := range findings {
		s := NormaliseSeverity(string(f.Severity))
		if severityRank[s] > severityRank[highest] {
			highest = s
		}
	}
	return highest
}

// Finding is one thing a scan reported.
//
// Every field except Severity is free text produced by a model reading a
// repository that this process does not control, so every consumer treats it
// as untrusted input. [Sanitise] is what this package does about that, and it
// is applied to everything that leaves [Module.Execute].
type Finding struct {
	// CheckID is a stable slug for the class of issue.
	//
	// The shape is a scanner's to choose and this package does not constrain
	// it. There is deliberately no example here: an example of a check
	// identifier is an example of something a scanner looks for, and what this
	// repository's scanner looks for is not this repository's to publish. See
	// docs/decisions/, USOSS-17.
	CheckID string `json:"checkId,omitempty"`
	// Severity ranks the finding. See [NormaliseSeverity].
	Severity Severity `json:"severity"`
	// Title is a one-line description.
	Title string `json:"title"`
	// Detail explains the issue.
	Detail string `json:"detail,omitempty"`
	// Remediation describes the fix.
	Remediation string `json:"remediation,omitempty"`
	// Path is the repository-relative file the finding is in, or empty. A path
	// that does not satisfy [SanitisePath] is dropped rather than carried,
	// because its only use is to be spliced into a link.
	Path string `json:"path,omitempty"`
	// Line is a 1-indexed line number, or zero for none.
	Line int `json:"line,omitempty"`
	// Snippet is a short excerpt, capped at [MaxSnippetBytes].
	Snippet string `json:"snippet,omitempty"`
	// Category is whatever classifier the scanner assigns. modules/fix reads it
	// to decide whether a fix may touch a protected path, so a scanner that
	// does not populate it gets the narrower permission rather than the wider
	// one. As with CheckID, no example is given.
	Category string `json:"category,omitempty"`
}

// MaxSnippetBytes caps a persisted snippet. A scanner is asked for a couple of
// lines; this is the ceiling that holds when it is not listened to.
const MaxSnippetBytes = 1024

// MaxPathBytes caps a finding path. It matches the path-length ceiling a
// repository archive can carry, so a path longer than this could not have come
// from the tree that was scanned.
const MaxPathBytes = 4096

// Sanitise returns f with every field brought inside this package's
// guarantees: the severity is on the ladder, the path is either safe to splice
// into a link or absent, the snippet is within [MaxSnippetBytes] and valid
// UTF-8, and a negative line number is dropped.
//
// It is applied to every finding on the way out of [Module.Execute], so a
// caller reading a stored result does not have to repeat any of it.
func (f Finding) Sanitise() Finding {
	f.Severity = NormaliseSeverity(string(f.Severity))
	f.Path = SanitisePath(f.Path)
	f.Snippet = TruncateUTF8(f.Snippet, MaxSnippetBytes)
	if f.Line < 0 {
		f.Line = 0
	}
	if f.Path == "" {
		// A line number without a path points at nothing.
		f.Line = 0
	}
	return f
}

// TruncateUTF8 returns s capped at maxBytes bytes, cut on a rune boundary and
// marked with an ellipsis when anything was removed.
//
// Slicing at a fixed byte offset can split a multi-byte codepoint. The result
// of that is invalid UTF-8, which encoding/json refuses to emit, so a runaway
// snippet would turn a successful scan into a serialisation failure. The cut
// is backed off to the previous rune start instead.
func TruncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	take := maxBytes
	for take > 0 && !utf8.RuneStart(s[take]) {
		take--
	}
	return s[:take] + "..."
}

// pathRE is the shape a repository-relative path may take. It is an allowlist
// of characters, not a denylist of dangerous ones: scheme punctuation, query
// and fragment markers, whitespace and control bytes are all outside it
// because none of them is enumerated as forbidden -- they are simply not
// letters, digits, dot, slash, dash or underscore.
var pathRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// SanitisePath returns p when it is a repository-relative path safe to splice
// into a link, and "" otherwise. There is no third outcome and no repair: a
// path this function cannot vouch for is dropped.
//
// All of the following must hold: non-empty and at most [MaxPathBytes];
// matches pathRE; no leading slash; and no segment that is empty, "." or "..".
func SanitisePath(p string) string {
	if p == "" || len(p) > MaxPathBytes {
		return ""
	}
	if strings.HasPrefix(p, "/") {
		return ""
	}
	if !pathRE.MatchString(p) {
		return ""
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return ""
		}
	}
	return p
}
