// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/modules/deploy"
	"github.com/conductorone/apphub/postgres"
)

// TargetPolicy limits user intent to an operator-approved deployment configuration.
type TargetPolicy struct {
	ID            string
	Label         string
	DeployConfig  deploy.Config
	ConfigHash    string
	ResourceSizes []ResourceInput
	MaxReplicas   int
	// MaxRelationalCapacityUnits bounds both ends of an owner-requested
	// relational capacity range in abstract units. Zero uses the default of 2.
	MaxRelationalCapacityUnits float64
	ExecutionModes             []string
	PublicExposure             bool
	// Repositories is an optional extra allowlist of exact canonical source
	// URLs. Empty means synced GitHub App installations decide; a present list
	// still refuses any URL it does not contain.
	Repositories []string
}

// NewID produces an opaque RFC 9562 UUID independent of upstream identity IDs.
func NewID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("operating system randomness unavailable")
	}
	value[6] = (value[6] & 15) | 64
	value[8] = (value[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[:4], value[4:6], value[6:8], value[8:10], value[10:])
}

// Hash returns a deterministic SHA-256 lookup identifier without retaining its input.
func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func requestHash(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", Problem(400, "invalid_request", "Request cannot be encoded.")
	}
	return Hash(string(data)), nil
}

func requireScope(principal Principal, scope string) error {
	if principal.UserID == "" {
		return Problem(401, "unauthorized", "Sign in is required.")
	}
	if principal.Bearer && !slices.Contains(principal.Scopes, scope) {
		return Problem(403, "insufficient_scope", "The granted token cannot perform this action.")
	}
	return nil
}

func owns(principal Principal, app ApplicationRecord) bool {
	return Owns(principal, app)
}

// The key names a key-value table gets when its request names no partition key.
const (
	DefaultPartitionKey = "pk"
	DefaultSortKey      = "sk"
)

// withKeyValueDefaults names the keys of a key-value table whose request left
// the partition key out. A request that names a partition key and no sort key
// keeps meaning a table without one.
func withKeyValueDefaults(input ApplicationInput) ApplicationInput {
	d := input.Database
	if d == nil || d.Kind != deploy.DatabaseKeyValue || strings.TrimSpace(d.PartitionKey) != "" {
		return input
	}
	defaulted := *d
	defaulted.PartitionKey = DefaultPartitionKey
	if strings.TrimSpace(defaulted.SortKey) == "" {
		defaulted.SortKey = DefaultSortKey
	}
	input.Database = &defaulted
	return input
}

// Relational database defaults, so that a caller who only knows they want a
// SQL database -- the frontend form and an API/MCP caller alike -- does not
// also have to know an engine, a database name, or an admin username. Modeled
// on the source system's own fixed choices for its one per-application
// cluster: an "appuser" master account (deploy/container.go:271-272) and a
// PostgreSQL engine (there is no working alternative -- see
// [compute.RelationalConfig.engineName]).
//
// EngineVersion and Capacity are deliberately not defaulted here.
// [RelationalConfig.checkVersion] already refuses an empty version rather
// than substituting one, because a version the caller did not ask for may not
// run the application's schema; adding a silent default above that layer
// would just move the substitution the interface forbids to an earlier line.
// An omitted Capacity already gets the source system's 0.5-4 ACU range from
// [RelationalConfig.acuRange]'s own zero-value handling, so there is nothing
// for this layer to add.
const (
	// DefaultAdminUsername is the master account name a relational request
	// gets when it names none.
	DefaultAdminUsername = "appuser"
	// DefaultDatabaseName is the logical database name a relational request
	// gets when the application name sanitizes away to nothing.
	DefaultDatabaseName = "app"
)

// reservedDatabaseNames are identifiers RDS refuses as a Postgres cluster's
// initial database name: two are reserved for RDS's own internal use and two
// are PostgreSQL's built-in template databases.
var reservedDatabaseNames = map[string]bool{
	"rdsadmin":  true,
	"postgres":  true,
	"template0": true,
	"template1": true,
}

// sanitizeDatabaseName derives a Postgres-legal database name from an
// application name: lowercase letters, digits and single underscores,
// starting with a letter, at most 63 characters (RDS's own DBName ceiling),
// and never a reserved word. Falls back to [DefaultDatabaseName] when nothing
// survives the sanitization.
func sanitizeDatabaseName(name string) string {
	var b strings.Builder
	sep := true // true means the last rune written (if any) was a separator, so leading separators collapse away
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			sep = false
		case !sep:
			b.WriteByte('_')
			sep = true
		}
	}
	out := strings.TrimRight(b.String(), "_")
	for len(out) > 0 && (out[0] < 'a' || out[0] > 'z') {
		out = out[1:]
	}
	if len(out) > 63 {
		out = strings.TrimRight(out[:63], "_")
	}
	if out == "" || reservedDatabaseNames[out] {
		return DefaultDatabaseName
	}
	return out
}

// withRelationalDefaults fills in the fields of a relational database request
// a caller left empty, preferring the previously-deployed specification
// (empty on a create, or when the database is new to this application) over
// a freshly computed default.
//
// The previous spec comes first because the fields this fills are the ones
// [checkClusterImmutables] refuses to change on an existing cluster: engine,
// database name, and admin username. A caller who renames the application and
// resubmits the database section blank is not asking to rename the database
// too, and recomputing sanitizeDatabaseName(input.Name) in that case would
// silently ask the provider to do exactly that -- succeeding here and failing
// at the next deploy with an error that does not mention the rename that
// caused it. Only when previous names no database at all (there is nothing to
// preserve) does an empty field get a fresh default.
func withRelationalDefaults(input ApplicationInput, previous deploy.Database) ApplicationInput {
	d := input.Database
	if d == nil || d.Kind != deploy.DatabaseRelational {
		return input
	}
	hadPrevious := previous.Kind == deploy.DatabaseRelational
	defaulted := *d
	if defaulted.Engine == "" {
		if hadPrevious && previous.Engine != "" {
			defaulted.Engine = previous.Engine
		} else {
			defaulted.Engine = compute.EnginePostgres
		}
	}
	if strings.TrimSpace(defaulted.AdminUsername) == "" {
		if hadPrevious && previous.AdminUsername != "" {
			defaulted.AdminUsername = previous.AdminUsername
		} else {
			defaulted.AdminUsername = DefaultAdminUsername
		}
	}
	if strings.TrimSpace(defaulted.DatabaseName) == "" {
		if hadPrevious && previous.DatabaseName != "" {
			defaulted.DatabaseName = previous.DatabaseName
		} else {
			defaulted.DatabaseName = sanitizeDatabaseName(input.Name)
		}
	}
	input.Database = &defaulted
	return input
}

// maxPublicPaths bounds how many sign-in exemptions a single route may carry.
// Matches ExposureInput's openapi.yaml maxItems, so a request the schema
// would accept and this check would refuse -- or the reverse -- is a
// documentation bug rather than a possible outcome.
const maxPublicPaths = 32

// publicPathPattern is deliberately narrower than a general URL path: no
// percent-encoding, so a request whose path a proxy decodes before matching
// (%2e, %2f, and friends) cannot land on an exemption this input never
// literally named, and no query or fragment characters, so neither can ever
// be what decided whether a path is exempt.
var publicPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()+,;=:@/*-]*$`)

// signInRequired resolves ExposureInput.SignInRequired's default. Absent
// (nil) means true, so a record written before this field existed, or a
// client that has not learned it yet, keeps requiring sign-in rather than
// going public the next time it is read back and resubmitted.
func signInRequired(e ExposureInput) bool {
	return e.SignInRequired == nil || *e.SignInRequired
}

// validatePublicPaths checks the exemption rules an owner sees in the
// portal -- exact match, a wildcard only as a final /*, no bare /*, no
// duplicates -- plus a conservative charset and structure check aimed at a
// proxy that might normalize a path differently than this one matches it.
//
// It validates unconditionally, independent of SignInRequired: [MapApplication]
// keeps a disabled route's paths on the record so they take effect again the
// moment sign-in is turned back on, and a rule that could never resolve is a
// rule to refuse now rather than store and revalidate later.
func validatePublicPaths(input []PublicPathInput, bad func(field, message string) (deploy.Application, error)) ([]string, error) {
	if len(input) > maxPublicPaths {
		_, err := bad("exposure.publicPaths", fmt.Sprintf("At most %d public paths are allowed.", maxPublicPaths))
		return nil, err
	}
	seen := make(map[string]bool, len(input))
	out := make([]string, 0, len(input))
	for _, p := range input {
		path := p.Path
		switch {
		case path == "":
			_, err := bad("exposure.publicPaths", "Enter a path.")
			return nil, err
		case len(path) > 256:
			_, err := bad("exposure.publicPaths", "Paths must be 256 characters or fewer.")
			return nil, err
		case path[0] != '/':
			_, err := bad("exposure.publicPaths", "Paths start with /.")
			return nil, err
		case strings.ContainsFunc(path, unicode.IsSpace):
			_, err := bad("exposure.publicPaths", "Paths cannot contain spaces.")
			return nil, err
		case strings.Contains(path, "*") && !strings.HasSuffix(path, "/*"):
			_, err := bad("exposure.publicPaths", "A wildcard is only allowed as a final /*.")
			return nil, err
		case path == "/*":
			_, err := bad("exposure.publicPaths", "That makes every path public. Turn off sign-in instead.")
			return nil, err
		case !publicPathPattern.MatchString(path):
			_, err := bad("exposure.publicPaths", "Path contains characters that are not allowed.")
			return nil, err
		case strings.Contains(path, "//"):
			_, err := bad("exposure.publicPaths", "Path cannot contain an empty segment.")
			return nil, err
		case slices.Contains(strings.Split(path, "/"), ".."):
			_, err := bad("exposure.publicPaths", "Path cannot contain a .. segment.")
			return nil, err
		case seen[path]:
			_, err := bad("exposure.publicPaths", "This path is already public.")
			return nil, err
		case len(p.Note) > 120:
			_, err := bad("exposure.publicPaths", "Note must be 120 characters or fewer.")
			return nil, err
		case strings.ContainsFunc(p.Note, unicode.IsControl):
			_, err := bad("exposure.publicPaths", "Note contains characters that are not allowed.")
			return nil, err
		}
		seen[path] = true
		out = append(out, path)
	}
	return out, nil
}

// MapApplication accepts only editable product inputs; provider references,
// owner, IDs, execution artifacts, IAM capabilities and raw secrets cannot enter.
func MapApplication(id string, input ApplicationInput, target TargetPolicy) (deploy.Application, error) {
	bad := func(field, message string) (deploy.Application, error) {
		return deploy.Application{}, &Error{Status: 422, Code: "invalid_specification", Message: "Application specification is invalid.", FieldErrors: map[string]string{field: message}}
	}
	data, err := json.Marshal(input)
	if err != nil {
		return bad("specification", "Invalid specification.")
	}
	if len(data) > 64<<10 {
		return deploy.Application{}, Problem(413, "specification_too_large", "Application specification exceeds 64 KiB.")
	}
	if id == "" || target.ID == "" || input.TargetID != target.ID {
		return bad("targetId", "Select an enabled target.")
	}
	if strings.TrimSpace(input.Name) == "" || len(input.Name) > 100 || strings.ContainsFunc(input.Name, unicode.IsControl) {
		return bad("name", "Enter a name of at most 100 characters.")
	}
	if len(target.Repositories) > 0 {
		if !slices.Contains(target.Repositories, input.Source.URL) {
			return bad("source.url", "Repository is not approved by the operator.")
		}
	} else if _, _, ok := githubOwnerRepo(input.Source.URL); !ok {
		return bad("source.url", "Enter a GitHub owner/repository URL.")
	}
	u, err := url.Parse(input.Source.URL)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return bad("source.url", "Repository URLs must not contain queries or fragments.")
	}
	if _, err := deploy.ValidateSourceURL(input.Source.URL, target.DeployConfig.AllowedSourceHosts); err != nil {
		return bad("source.url", "Repository URL is not permitted.")
	}
	if len(input.Source.Ref) > 256 || strings.HasPrefix(input.Source.Ref, "-") || strings.ContainsFunc(input.Source.Ref, unicode.IsControl) {
		return bad("source.ref", "Source ref is invalid.")
	}
	df := input.Source.Dockerfile
	if df == "" || path.IsAbs(df) || path.Clean(df) != df || df == ".." || strings.HasPrefix(df, "../") || strings.ContainsAny(df, "\\\x00") {
		return bad("source.dockerfile", "Enter a relative Dockerfile path within the repository.")
	}
	if input.Execution != deploy.ExecutionService && input.Execution != deploy.ExecutionScheduled {
		return bad("execution", "Choose service or scheduled.")
	}
	if !slices.Contains(target.ExecutionModes, string(input.Execution)) {
		return bad("execution", "Execution mode is unavailable on this target.")
	}
	if input.Port < 1 || input.Port > 65535 {
		return bad("port", "Port must be between 1 and 65535.")
	}
	if input.Resources.CPU <= 0 || input.Resources.Memory <= 0 || !slices.Contains(target.ResourceSizes, input.Resources) {
		return bad("resources", "Select an operator-approved resource size.")
	}
	if input.Replicas < 1 || input.Replicas > target.MaxReplicas {
		return bad("replicas", "Replica count exceeds target policy.")
	}
	app := deploy.Application{ID: id, Name: input.Name, Workload: deploy.WorkloadContainer, Execution: input.Execution, Source: deploy.Source{URL: input.Source.URL, Ref: input.Source.Ref, Dockerfile: df}, Port: input.Port, Replicas: input.Replicas, Resources: compute.Resources{CPUMillicores: input.Resources.CPU, MemoryMiB: input.Resources.Memory}}
	if input.Schedule != nil {
		app.Schedule = compute.Schedule{Expression: input.Schedule.Expression, Timezone: input.Schedule.Timezone, Paused: input.Schedule.Paused}
	}
	if input.Execution == deploy.ExecutionScheduled && input.Schedule == nil {
		return bad("schedule", "A schedule is required.")
	}
	if input.Execution == deploy.ExecutionService && input.Schedule != nil {
		return bad("schedule", "A service must not contain a schedule.")
	}
	if d := input.Database; d != nil && len(d.Extensions) != 0 {
		if d.Kind != deploy.DatabaseRelational || d.Engine != compute.EnginePostgres {
			return bad("database.extensions", "Extensions require a PostgreSQL relational database.")
		}
		seen := make(map[string]bool, len(d.Extensions))
		for _, name := range d.Extensions {
			if !postgres.IsAllowedExtension(name) {
				return bad("database.extensions", fmt.Sprintf("Extension %q is not allowed.", name))
			}
			if seen[name] {
				return bad("database.extensions", fmt.Sprintf("Extension %q is listed more than once.", name))
			}
			seen[name] = true
		}
	}
	if d := input.Database; d != nil {
		if d.Kind == deploy.DatabaseRelational {
			maxUnits := target.MaxRelationalCapacityUnits
			if maxUnits == 0 {
				maxUnits = 2
			}
			if d.Capacity.MinUnits > maxUnits || d.Capacity.MaxUnits > maxUnits {
				return bad("database.capacity", fmt.Sprintf("Relational capacity must not exceed %g units.", maxUnits))
			}
		}
		app.Database = deploy.Database{Kind: d.Kind, Engine: d.Engine, EngineVersion: d.EngineVersion, DatabaseName: d.DatabaseName, AdminUsername: d.AdminUsername, Capacity: compute.CapacityRange{MinUnits: d.Capacity.MinUnits, MaxUnits: d.Capacity.MaxUnits}, Extensions: slices.Clone(d.Extensions), PartitionKey: d.PartitionKey, SortKey: d.SortKey}
	}
	if input.Bucket != nil {
		b := input.Bucket
		app.Bucket = deploy.Bucket{Kind: b.Kind, Zone: b.Zone, Access: b.Access}
	}
	switch input.Exposure.Mode {
	case "private":
		if input.Exposure.MCPAuthEnabled {
			return bad("exposure.mcpAuthEnabled", "MCP authentication requires public exposure.")
		}
		internal := input.Execution == deploy.ExecutionService && target.DeployConfig.InternalRouteDomain != ""
		if input.Exposure.Hostname != "" && !internal {
			return bad("exposure.hostname", "This target has no internal ingress, so a private application cannot request a hostname.")
		}
		if !internal {
			// No route means nothing for sign-in or a path exemption to act
			// on. A submitted non-default value here is silently discarded
			// nowhere else in this module, and it should not start here: an
			// owner who set it believes it does something.
			if input.Exposure.SignInRequired != nil && !*input.Exposure.SignInRequired {
				return bad("exposure.signInRequired", "This application has no route, so sign-in has nothing to require.")
			}
			if len(input.Exposure.PublicPaths) > 0 {
				return bad("exposure.publicPaths", "This application has no route, so public path rules would do nothing.")
			}
			break
		}
		h := EffectiveHostname(id, input)
		if !validLabel(h) {
			return bad("exposure.hostname", "Use one lowercase DNS label.")
		}
		privatePaths, err := validatePublicPaths(input.Exposure.PublicPaths, bad)
		if err != nil {
			return deploy.Application{}, err
		}
		// A private service is published on the internal ingress only,
		// reachable inside the network. By default it sits behind the same
		// platform sign-in as a public route, and its requests pass through
		// the proxy whose access log counts traffic; an owner may turn
		// sign-in off, which is then their explicit choice rather than one
		// this module made for them.
		privateAuth := signInRequired(input.Exposure)
		privateRoute := deploy.Route{Hostname: h, Internal: true, RequireAuth: privateAuth}
		if privateAuth {
			privateRoute.PublicPaths = privatePaths
		}
		app.Routes = []deploy.Route{privateRoute}
	case "public":
		h := input.Exposure.Hostname
		if !target.PublicExposure || input.Execution != deploy.ExecutionService {
			return bad("exposure.mode", "Public exposure is unavailable for this workload.")
		}
		if !validLabel(h) {
			return bad("exposure.hostname", "Use one lowercase DNS label.")
		}
		publicPaths, err := validatePublicPaths(input.Exposure.PublicPaths, bad)
		if err != nil {
			return deploy.Application{}, err
		}
		// A published HTTP route is authenticated by the platform proxy by
		// default. An owner may turn sign-in off for the rest of the route --
		// an explicit choice recorded here, not a default this module picks --
		// which publishes it to anyone who can open the URL; PublicPaths then
		// stays on the record, inert, for when sign-in is turned back on.
		// MCP authentication, when requested, protects /mcp with AppHub OAuth
		// on its own higher-priority router regardless of this choice.
		publicAuth := signInRequired(input.Exposure)
		route := deploy.Route{Hostname: h, AllowPlaintext: false, RequireAuth: publicAuth}
		if publicAuth {
			route.PublicPaths = publicPaths
		}
		if input.Exposure.MCPAuthEnabled {
			route.MCPAuthApplicationID = id
		}
		app.Routes = []deploy.Route{route}
	default:
		return bad("exposure.mode", "Choose private or public exposure.")
	}
	return app, nil
}

// EffectiveHostname is the hostname label an application's route is published
// under: the one requested, or for a private service that requested none, one
// derived from the application ID. Derived from the ID rather than the name so
// it never changes, and reserved like a requested one.
func EffectiveHostname(id string, input ApplicationInput) string {
	if input.Exposure.Hostname != "" {
		return input.Exposure.Hostname
	}
	if input.Exposure.Mode != "private" || input.Execution != deploy.ExecutionService {
		return ""
	}
	compact := strings.ReplaceAll(id, "-", "")
	if len(compact) > 12 {
		compact = compact[:12]
	}
	return "app-" + strings.ToLower(compact)
}

func validLabel(h string) bool {
	return len(h) >= 1 && len(h) <= 63 && h == strings.ToLower(h) && h[0] != '-' && h[len(h)-1] != '-' &&
		!strings.ContainsFunc(h, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' })
}

// githubOwnerRepo extracts the owner and repository name from a canonical
// HTTPS Git URL with a two-segment path, such as https://github.com/org/app.git.
func githubOwnerRepo(raw string) (owner, name string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 {
		return "", "", false
	}
	owner, name = parts[0], strings.TrimSuffix(parts[1], ".git")
	if owner == "" || name == "" || owner == "." || name == "." {
		return "", "", false
	}
	return owner, name, true
}
