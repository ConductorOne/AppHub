// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package hermetic asserts that this repository's CI needs no credentials.
//
// The upstream suite had that property, but it had it by luck: nothing stopped
// a future job from wiring in a secret and nothing would have noticed. In a
// public repository that is worse than a slow test suite -- it is a standing
// invitation to exfiltrate a token from a fork's pull request. So the property
// is asserted rather than assumed.
//
// # Why this is not a grep
//
// It was a grep, and review defeated it with ordinary valid YAML:
//
//	permissions:
//	  id-token: "write"
//	env:
//	  AWS_ACCESS_KEY_ID: "${{ secrets['AWS_KEY'] }}"
//
// Both lines are quoted, and the patterns matched only the unquoted spellings,
// so a workflow holding both an OIDC write permission and a secret passed. The
// lesson generalises: YAML has too many ways to write the same value for a
// regular expression to enumerate them. Quoting, flow mappings, anchors and
// aliases, block scalars, and explicit tags are all equivalent to the parser
// and all different to a grep.
//
// So the workflow is parsed. Values are compared after the parser has resolved
// them, which means `write`, `"write"`, `'write'`, `!!str write`, and an alias
// to any of those are one case rather than five.
//
// The rules, in the order a reader should think about them:
//
//  1. No expression may touch the secrets context, in any spelling.
//  2. No job may hold `id-token: write`, which mints cloud credentials over
//     OIDC without a stored secret at all.
//  3. No credential environment variable may be given a value. Blanking one to
//     the empty string is the point and stays allowed.
//
// Deleting a rule here is the deliberate act that permits the thing it forbids.
package hermetic

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kind classifies a finding, so a reader can tell "this job can mint cloud
// credentials" apart from "this job reads a stored secret".
type Kind string

const (
	// KindSecretsContext is any read of the secrets context.
	KindSecretsContext Kind = "secrets-context"
	// KindSecretsInput is a `secrets:` block passing secrets to a called
	// workflow, which needs no expression to leak one.
	KindSecretsInput Kind = "secrets-input"
	// KindIDTokenWrite is permission to mint an OIDC token, which is how a job
	// gets cloud credentials with no stored secret.
	KindIDTokenWrite Kind = "id-token-write"
	// KindCredentialValue is a cloud or vendor credential variable given a value.
	//nolint:gosec // G101 reads this constant's name as a hardcoded credential; it is the name of a finding category
	KindCredentialValue Kind = "credential-value"
)

// Finding is one reason a workflow is not credential-free.
type Finding struct {
	File   string
	Path   string
	Kind   Kind
	Detail string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: %s [%s] %s", f.File, f.Path, f.Kind, f.Detail)
}

// credentialVars are environment variables whose presence with a value means a
// job has been handed a credential. Blanking them is how the test job proves
// the suite does not need them, so only a non-empty value is a finding.
var credentialVars = map[string]bool{
	"AWS_ACCESS_KEY_ID":             true,
	"AWS_SECRET_ACCESS_KEY":         true,
	"AWS_SESSION_TOKEN":             true,
	"AWS_PROFILE":                   true,
	"AWS_ROLE_ARN":                  true,
	"AWS_WEB_IDENTITY_TOKEN_FILE":   true,
	"AWS_CONTAINER_CREDENTIALS_URI": true,
	"CONDUCTORONE_CLIENT_SECRET":    true,
	"CONDUCTORONE_CLIENT_ID":        true,
	"C1_CLIENT_SECRET":              true,
	"ANTHROPIC_API_KEY":             true,
	"OPENAI_API_KEY":                true,
	"GITLEAKS_LICENSE":              true,
	"GITHUB_TOKEN":                  true,
	"GH_TOKEN":                      true,
	"NPM_TOKEN":                     true,
	"DOCKERHUB_TOKEN":               true,
}

// expression matches a GitHub Actions expression. (?s) so a block scalar that
// wraps an expression over several lines is still one match.
var expression = regexp.MustCompile(`(?s)\$\{\{.*?\}\}`)

// secretsWord matches the secrets context however it is subscripted: dotted,
// bracketed, or handed whole to a function such as toJSON.
var secretsWord = regexp.MustCompile(`(?i)\bsecrets\b`)

// CheckWorkflow parses one workflow and reports every way it could obtain a
// credential.
func CheckWorkflow(file string, data []byte) ([]Finding, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var findings []Finding
	for {
		// Decoding into any resolves aliases and normalises scalars, which is
		// the entire reason this is a parser and not a pattern.
		var doc any
		if err := dec.Decode(&doc); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if doc == nil {
			continue
		}
		findings = append(findings, walk(file, "", doc)...)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Kind < findings[j].Kind
	})
	return findings, nil
}

func walk(file, path string, node any) []Finding {
	var out []Finding
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, checkPair(file, join(path, k), k, v[k])...)
			out = append(out, walk(file, join(path, k), v[k])...)
		}
	case map[any]any:
		// yaml.v3 produces map[string]any for string keys, but a document with
		// a non-string key still has to be traversed rather than skipped.
		for k, val := range v {
			key := scalarString(k)
			out = append(out, checkPair(file, join(path, key), key, val)...)
			out = append(out, walk(file, join(path, key), val)...)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	case []any:
		for i, item := range v {
			// walk reaches checkScalar for a scalar item; calling it here too
			// would report the same expression twice.
			out = append(out, walk(file, fmt.Sprintf("%s[%d]", path, i), item)...)
		}
	default:
		out = append(out, checkScalar(file, path, node)...)
	}
	return out
}

// checkPair applies the rules that depend on a key's name.
func checkPair(file, path, key string, value any) []Finding {
	var out []Finding
	lowerKey := strings.ToLower(key)

	// Rule 2: OIDC write permission, however the value is spelled.
	if lowerKey == "id-token" && normalized(value) == "write" {
		out = append(out, Finding{
			File: file, Path: path, Kind: KindIDTokenWrite,
			Detail: "id-token: write lets a job mint cloud credentials over OIDC with no stored secret",
		})
	}
	// `permissions: write-all` grants every scope, id-token included.
	if lowerKey == "permissions" && normalized(value) == "write-all" {
		out = append(out, Finding{
			File: file, Path: path, Kind: KindIDTokenWrite,
			Detail: "permissions: write-all grants id-token: write along with everything else",
		})
	}
	// Rule 1b: a `secrets:` block hands secrets to a called workflow directly,
	// with no expression for rule 1 to catch.
	//
	// Position matters here in a way it does not for the other rules: a job may
	// legitimately be *named* "secrets" (this repository has one), and that key
	// sits at the same depth as a job id. Only the two places where the key
	// actually means secret-passing count.
	if lowerKey == "secrets" && isSecretsBlock(path) {
		out = append(out, Finding{
			File: file, Path: path, Kind: KindSecretsInput,
			Detail: "a secrets: block passes stored secrets into a called workflow",
		})
	}
	// Rule 3: a credential variable given any value at all.
	if credentialVars[strings.ToUpper(key)] {
		if v := normalized(value); v != "" {
			out = append(out, Finding{
				File: file, Path: path, Kind: KindCredentialValue,
				Detail: fmt.Sprintf("%s is set to a non-empty value; blank it instead if the job must prove it does not need it", key),
			})
		}
	}
	return out
}

// checkScalar applies the rules that depend only on a value.
func checkScalar(file, path string, value any) []Finding {
	s, ok := value.(string)
	if !ok {
		return nil
	}
	var out []Finding
	// Rule 1: any expression that reads the secrets context, in any spelling --
	// secrets.NAME, secrets['NAME'], toJSON(secrets), or a multiline variant.
	for _, expr := range expression.FindAllString(s, -1) {
		if secretsWord.MatchString(expr) {
			out = append(out, Finding{
				File: file, Path: path, Kind: KindSecretsContext,
				Detail: "expression reads the secrets context: " + collapse(expr),
			})
			break
		}
	}
	return out
}

// normalized renders a parsed value the way a comparison should see it, so
// write, "write", 'write' and !!str write are one case.
func normalized(v any) string {
	return strings.ToLower(strings.TrimSpace(scalarString(v)))
}

func scalarString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

// isSecretsBlock reports whether a "secrets" key at this path is the GitHub
// Actions secret-passing block rather than an identifier that happens to be
// spelled the same.
//
// The two real positions are jobs.<job_id>.secrets (calling a reusable
// workflow) and on.workflow_call.secrets (declaring what a caller must pass).
// Job ids cannot contain a dot, so splitting on one is safe. The trigger key is
// checked as both "on" and "true" because YAML 1.1 parsers resolve a bare `on`
// to a boolean, and a workflow written for one should not slip past here.
func isSecretsBlock(path string) bool {
	segs := strings.Split(path, ".")
	if len(segs) == 3 && segs[0] == "jobs" && segs[2] == "secrets" {
		return true
	}
	if len(segs) >= 3 && (segs[0] == "on" || segs[0] == "true") &&
		segs[1] == "workflow_call" && segs[2] == "secrets" {
		return true
	}
	return false
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
