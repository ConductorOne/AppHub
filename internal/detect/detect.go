// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package detect provides advisory repository introspection for the "simple
// deploy" flow: given a repository's file tree, best-effort locate a
// Dockerfile, parse its EXPOSE directive to suggest a container port, preview
// any docker-compose services, and guess which managed database the repository
// wants.
//
// Everything here is advisory. FromTree never errors; an empty [Result] means
// "nothing detected", and a caller must fall back to its own defaults (a root
// Dockerfile, a default port) rather than treating that as a failure. This
// package is a port of the source system's repository-detection logic (its
// "simple deploy" repo introspection, github/detect.go), with
// one change: [Tree] is host-agnostic (no GitHub-specific fetch concern lives
// here) and it is walked from a shallow Git checkout
// ([github.com/conductorone/apphub/internal/source].Checkout.Discover), not an
// in-memory tarball. See that method's doc comment for why: this repository's
// authenticated API process never holds source credentials, so acquiring the
// tree happens in the worker either way, and the worker already shallow-clones
// with Git for a real deploy.
//
// This package lives under internal/, not modules/deploy, even though it
// exists for modules/deploy's benefit: it parses YAML with a third-party
// library, and no package under modules/ may import anything third-party at
// all (modules/doc.go, enforced by modules/review's
// TestNoModuleImportsAnythingThirdParty) -- a module reaches an external
// concern through a declared interface, never an SDK or library import. A
// compose file is untrusted repository content, not a cloud API, so there is
// no interface here to declare; the rule is simply obeyed by keeping this
// package outside the tree it governs.
package detect

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Tree is a repository snapshot: repo-relative POSIX paths mapped to file
// content. A caller that builds one from a real checkout is free to include
// only the files this package can use (see source.Checkout.Discover); FromTree
// makes no assumption that every repository file is present.
type Tree struct {
	Files map[string][]byte
}

// Result is the advisory output of FromTree.
type Result struct {
	// DockerfilePath is the best-guess Dockerfile (repo-relative POSIX path),
	// or "" if none was found.
	DockerfilePath string `json:"dockerfilePath,omitempty"`
	// SuggestedPort is the first numeric EXPOSE port in the chosen Dockerfile,
	// or 0 if none was found.
	SuggestedPort int `json:"suggestedPort,omitempty"`
	// DockerfileCandidates lists every Dockerfile-like path found, ordered
	// best-first (root first, then shallowest/lexical).
	DockerfileCandidates []string `json:"dockerfileCandidates,omitempty"`
	// DockerfilePorts maps each candidate Dockerfile path to the first numeric
	// EXPOSE port it declares (0 when it exposes none). A caller re-evaluates
	// the suggested port when the requester overrides the chosen Dockerfile,
	// rather than reusing the port parsed from the first candidate.
	DockerfilePorts map[string]int `json:"dockerfilePorts,omitempty"`
	// ComposePreview is populated when a docker-compose / compose file is
	// present. It is informational only.
	ComposePreview *ComposePreview `json:"composePreview,omitempty"`
	// SuggestedDatabase is a best-effort guess at the managed database the
	// repository needs: "postgres", "dynamodb", or "" when nothing was
	// confidently detected. Any relational signal maps to "postgres".
	SuggestedDatabase string `json:"suggestedDatabase,omitempty"`
	// DatabaseReason is a short human-readable explanation of why
	// SuggestedDatabase was chosen (e.g. `found "pg" in package.json`).
	DatabaseReason string `json:"databaseReason,omitempty"`
}

// ComposePreview is a non-binding summary of a docker-compose file.
type ComposePreview struct {
	// Path is the repo-relative path of the compose file parsed.
	Path string `json:"path"`
	// Services lists the discovered services.
	Services []ComposeService `json:"services"`
}

// ComposeService is one service entry from a compose file.
type ComposeService struct {
	Name     string `json:"name"`
	Port     int    `json:"port,omitempty"`
	HasBuild bool   `json:"hasBuild"`
	Image    string `json:"image,omitempty"`
}

// FromTree inspects a repository snapshot and returns advisory deployment
// hints. It never errors; a zero-value [Tree] or [Result] means "nothing
// detected".
func FromTree(tree Tree) Result {
	var res Result
	if len(tree.Files) == 0 {
		return res
	}

	res.DockerfileCandidates = findDockerfiles(tree)
	if len(res.DockerfileCandidates) > 0 {
		res.DockerfilePath = res.DockerfileCandidates[0]
		// Parse the EXPOSE port for every candidate so a caller can re-derive
		// the suggested port when the requester overrides the chosen
		// Dockerfile.
		res.DockerfilePorts = make(map[string]int, len(res.DockerfileCandidates))
		for _, candidate := range res.DockerfileCandidates {
			if content, ok := tree.Files[candidate]; ok {
				res.DockerfilePorts[candidate] = parseExposePort(content)
			}
		}
		res.SuggestedPort = res.DockerfilePorts[res.DockerfilePath]
	}

	if composePath := findComposeFile(tree); composePath != "" {
		if preview := parseCompose(composePath, tree.Files[composePath]); preview != nil {
			res.ComposePreview = preview
		}
	}

	res.SuggestedDatabase, res.DatabaseReason = detectDatabase(tree, res.ComposePreview)

	return res
}

// findDockerfiles returns Dockerfile-like paths ordered best-first. A root
// "Dockerfile" wins; otherwise candidates are sorted by path depth then
// lexically for stable, predictable output.
func findDockerfiles(tree Tree) []string {
	var candidates []string
	for p := range tree.Files {
		base := path.Base(p)
		if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
			candidates = append(candidates, p)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		// Root-level files first.
		di, dj := strings.Count(candidates[i], "/"), strings.Count(candidates[j], "/")
		if di != dj {
			return di < dj
		}
		// Plain "Dockerfile" beats "Dockerfile.<suffix>".
		bi, bj := path.Base(candidates[i]), path.Base(candidates[j])
		if (bi == "Dockerfile") != (bj == "Dockerfile") {
			return bi == "Dockerfile"
		}
		return candidates[i] < candidates[j]
	})
	return candidates
}

// parseExposePort scans a Dockerfile for the first EXPOSE directive and
// returns the first valid port (stripping any "/tcp" / "/udp" suffix).
// Returns 0 when no parseable port is present.
func parseExposePort(content []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "EXPOSE") {
			continue
		}
		for _, tok := range fields[1:] {
			// Skip ARG-style references like ${PORT}; only take literals.
			tok = strings.SplitN(tok, "/", 2)[0]
			if n, err := strconv.Atoi(tok); err == nil && n > 0 && n <= 65535 {
				return n
			}
		}
	}
	return 0
}

// composeNames are the filenames treated as compose files, in preference order.
var composeNames = []string{
	"compose.yaml",
	"compose.yml",
	"docker-compose.yaml",
	"docker-compose.yml",
}

// findComposeFile returns the best compose file path (root preferred), or ""
// if none exists.
func findComposeFile(tree Tree) string {
	// Prefer a root-level compose file.
	for _, name := range composeNames {
		if _, ok := tree.Files[name]; ok {
			return name
		}
	}
	// Otherwise take the shallowest match, deterministically.
	var matches []string
	for p := range tree.Files {
		base := path.Base(p)
		for _, name := range composeNames {
			if base == name {
				matches = append(matches, p)
				break
			}
		}
	}
	if len(matches) == 0 {
		return ""
	}
	sort.Slice(matches, func(i, j int) bool {
		di, dj := strings.Count(matches[i], "/"), strings.Count(matches[j], "/")
		if di != dj {
			return di < dj
		}
		return matches[i] < matches[j]
	})
	return matches[0]
}

// parseCompose extracts a non-binding service preview from a compose file.
// Unknown/odd shapes are tolerated; on a total parse failure it returns nil.
func parseCompose(composePath string, content []byte) *ComposePreview {
	if len(content) == 0 {
		return nil
	}
	var root map[string]any
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil
	}
	servicesRaw, ok := root["services"].(map[string]any)
	if !ok {
		return nil
	}

	preview := &ComposePreview{Path: composePath}
	names := make([]string, 0, len(servicesRaw))
	for name := range servicesRaw {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		svcMap, ok := servicesRaw[name].(map[string]any)
		if !ok {
			preview.Services = append(preview.Services, ComposeService{Name: name})
			continue
		}
		svc := ComposeService{Name: name}
		if img, ok := svcMap["image"].(string); ok {
			svc.Image = img
		}
		if _, ok := svcMap["build"]; ok {
			svc.HasBuild = true
		}
		svc.Port = firstComposePort(svcMap["ports"])
		preview.Services = append(preview.Services, svc)
	}
	return preview
}

// firstComposePort returns the first container/target port from a compose
// "ports" value, supporting short ("8080:80", "80") and long (map with
// "target") forms. Returns 0 when none is parseable.
func firstComposePort(raw any) int {
	list, ok := raw.([]any)
	if !ok {
		return 0
	}
	for _, entry := range list {
		if p := extractComposePort(entry); p > 0 {
			return p
		}
	}
	return 0
}

func extractComposePort(entry any) int {
	switch v := entry.(type) {
	case string:
		// Forms: "80", "8080:80", "127.0.0.1:8080:80", "80/tcp".
		parts := strings.Split(v, ":")
		last := parts[len(parts)-1]
		last = strings.SplitN(last, "/", 2)[0]
		if n, err := strconv.Atoi(strings.TrimSpace(last)); err == nil {
			return n
		}
	case map[string]any:
		return asPortInt(v["target"])
	default:
		// Bare numeric scalar (yaml.v3 may decode as int, int64, or float64).
		return asPortInt(entry)
	}
	return 0
}

// asPortInt coerces a YAML-decoded numeric (or numeric-string) value to a port
// number, returning 0 when it is not a usable port.
func asPortInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		if p, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return p
		}
	}
	return 0
}

// Suggested database engines. Only these two ever come back from
// detectDatabase; any relational signal (postgres/mysql/mariadb) maps to
// dbPostgres since Postgres is the only managed relational engine this
// repository's compute providers offer (see
// [github.com/conductorone/apphub/modules/deploy.DatabaseRelational]).
const (
	dbPostgres = "postgres"
	dbDynamoDB = "dynamodb"
)

// dbURLRE matches a relational connection-string scheme in an env file.
var dbURLRE = regexp.MustCompile(`(?i)\b(postgres(?:ql)?|mysql)://`)

// prismaProviderRE captures a Prisma `provider = "<name>"` value. A Prisma
// schema contains both a datasource and a generator provider; the caller
// filters to known database providers so the generator ("prisma-client-js")
// is ignored.
var prismaProviderRE = regexp.MustCompile(`(?i)provider\s*=\s*"([a-z0-9_]+)"`)

// Dependency-manifest tokens that indicate a relational driver/client. Kept to
// concrete driver names (not generic ORMs) to minimize false positives.
var (
	nodeDBTokens = []string{`"pg"`, `"pg-promise"`, `"postgres"`, `"mysql"`, `"mysql2"`}
	goDBTokens   = []string{"github.com/lib/pq", "github.com/jackc/pgx", "gorm.io/driver/postgres", "github.com/go-sql-driver/mysql"}
	pyDBTokens   = []string{"psycopg2", "psycopg", "asyncpg", "pg8000", "pymysql", "mysqlclient"}
	rubyDBTokens = []string{`"pg"`, `'pg'`, `"mysql2"`, `'mysql2'`}
)

// detectDatabase makes a best-effort guess at the managed database the
// repository needs. It returns the suggested engine ("postgres" / "dynamodb")
// and a short human-readable reason, or ("", "") when nothing confident is
// found. It never errors.
//
// Precedence (strongest first): an explicit compose database service, then a
// relational connection string in an env file, then a relational
// driver/client in a dependency manifest. DynamoDB is only ever inferred from
// a dynamodb-local compose image, since code-level Dynamo usage is not
// reliably distinguishable from incidental AWS SDK usage.
func detectDatabase(tree Tree, compose *ComposePreview) (db, reason string) {
	// 1) Strongest: an explicit database service in docker-compose.
	if compose != nil {
		for _, svc := range compose.Services {
			if d := dbFromImage(svc.Image); d != "" {
				return d, fmt.Sprintf("docker-compose service %q uses image %q", svc.Name, svc.Image)
			}
		}
	}

	// 2/3) Scan known manifest/env files in a single pass over the tree.
	// Strong signals (env connection string, Prisma datasource) return
	// immediately; weaker dependency-manifest mentions are held and only
	// returned if no strong signal is found.
	var weakDB, weakReason string
	for p, content := range tree.Files {
		base := strings.ToLower(path.Base(p))
		switch {
		case isEnvFile(base):
			if scheme := relationalURLScheme(content); scheme != "" {
				return dbPostgres, fmt.Sprintf("%s connection string in %s", scheme, p)
			}
		case base == "schema.prisma":
			if provider := prismaDBProvider(content); provider != "" {
				if d := dbFromPrismaProvider(provider); d != "" {
					return d, fmt.Sprintf("Prisma datasource provider %q in %s", provider, p)
				}
			}
		case base == "package.json":
			if hit := scanForAny(content, nodeDBTokens); hit != "" && weakDB == "" {
				weakDB, weakReason = dbPostgres, fmt.Sprintf("found %s dependency in %s", strings.Trim(hit, `"`), p)
			}
		case base == "go.mod":
			if hit := scanForAny(content, goDBTokens); hit != "" && weakDB == "" {
				weakDB, weakReason = dbPostgres, fmt.Sprintf("found %s in %s", hit, p)
			}
		case base == "requirements.txt" || base == "pyproject.toml" || base == "pipfile":
			if hit := scanForAny(content, pyDBTokens); hit != "" && weakDB == "" {
				weakDB, weakReason = dbPostgres, fmt.Sprintf("found %s in %s", hit, p)
			}
		case base == "gemfile":
			if hit := scanForAny(content, rubyDBTokens); hit != "" && weakDB == "" {
				weakDB, weakReason = dbPostgres, fmt.Sprintf("found %s gem in %s", strings.Trim(hit, `"'`), p)
			}
		}
	}
	return weakDB, weakReason
}

// dbFromImage maps a container image reference to a suggested database
// engine, or "" when the image is not a recognized database. It strips any
// registry/path prefix and tag so "bitnami/postgresql:16" and
// "amazon/dynamodb-local" both match.
func dbFromImage(image string) string {
	if image == "" {
		return ""
	}
	name := image
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	name = strings.ToLower(name)
	switch {
	case strings.Contains(name, "dynamodb"):
		return dbDynamoDB
	case strings.Contains(name, "postgres"), strings.Contains(name, "postgis"),
		strings.Contains(name, "mysql"), strings.Contains(name, "mariadb"):
		return dbPostgres
	}
	return ""
}

// relationalURLScheme returns the relational connection-string scheme (e.g.
// "postgres", "mysql") found in content, or "" when none is present.
func relationalURLScheme(content []byte) string {
	if m := dbURLRE.FindSubmatch(content); m != nil {
		return strings.ToLower(string(m[1]))
	}
	return ""
}

// prismaDBProvider returns the first recognized Prisma database provider in a
// schema (skipping the generator's non-database provider), or "".
func prismaDBProvider(content []byte) string {
	for _, m := range prismaProviderRE.FindAllSubmatch(content, -1) {
		switch p := strings.ToLower(string(m[1])); p {
		case "postgresql", "postgres", "mysql", "mongodb", "sqlite", "sqlserver", "cockroachdb":
			return p
		}
	}
	return ""
}

// dbFromPrismaProvider maps a Prisma datasource provider to a supported
// engine, or "" for providers no compute provider here provisions (mongodb,
// sqlite, ...).
func dbFromPrismaProvider(provider string) string {
	switch provider {
	case "postgresql", "postgres", "mysql", "cockroachdb":
		return dbPostgres
	}
	return ""
}

// scanForAny returns the first token (case-insensitive substring) found in
// content, or "" when none match.
func scanForAny(content []byte, tokens []string) string {
	lc := strings.ToLower(string(content))
	for _, tok := range tokens {
		if strings.Contains(lc, strings.ToLower(tok)) {
			return tok
		}
	}
	return ""
}

// isEnvFile reports whether base is a dotenv-style filename (".env",
// ".env.example", ".env.local", ...).
func isEnvFile(base string) bool {
	return base == ".env" || strings.HasPrefix(base, ".env.")
}
