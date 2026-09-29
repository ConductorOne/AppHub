// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package boundary checks the architectural constraint that makes ConductorOne
// optional: no package may depend on ConductorOne unless it is explicitly
// allowed to. It enforces the DynamoDB fence the same way.
//
// The constraint is a project decision (docs/decisions/), and decisions that
// are only enforced by a reviewer remembering them do not survive twenty pull
// requests. This package turns it into a build failure instead. Widening it
// requires editing DefaultConfig below, which shows up in a diff and gets
// argued about on its merits.
//
// # The proof is a union graph, not a list of builds
//
// The policy is universal -- *no supported build configuration* may give a
// disallowed package a dependency path to a denied one -- and for four rounds
// this package tried to prove it by running `go list` over a matrix of concrete
// configurations. `go list` answers an existential question instead: what did
// this one configuration select? Review defeated that four times (a transitive
// import through a third-party wrapper; a `*_windows.go` blank import; an
// `arm64`-only import behind an accepted-but-unexecuted selector; coverage
// blessing a success line from a subset of targets). Every fix was correct and
// every time the hole reappeared one level up, because no finite enumeration
// proves a universal property.
//
// So the primitive changed. [Union] is a single import graph built from source
// with build constraints ignored entirely -- every import declared by every Go
// file in every reachable package, plus test imports for first-party packages.
// Because any configuration can only *select* edges, every concrete graph is a
// subgraph of it, and a union with no forbidden path proves that none of them
// has one. See union.go for the argument in full, including what it deliberately
// over-approximates and what it does not claim.
//
// # The concrete targets remain, demoted
//
// [LoadGraph] and [Config.CheckGraph] still run over a small documented target
// matrix, and [ScanFiles] with [Config.CheckFiles] and [Config.CheckBuildTags]
// still read the tree file by file. They are **compatibility checks, not the
// boundary proof**: they catch code that does not compile on a supported
// platform, invalid `//go:build` combinations, cgo and toolchain problems, and --
// through [Union.Differential] -- any disagreement between the union parser and
// the real toolchain. The last of those is what keeps the proof honest: an edge
// a real build reports that the union does not contain means the resolver missed
// a toolchain behaviour, and the gate fails.
package boundary

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultModulePrefix is the import path of this module. Packages beneath it
// are the ones the rules govern; everything else is a dependency being
// inspected, not a subject being judged.
const DefaultModulePrefix = "github.com/conductorone/apphub"

// ImportKind distinguishes where an offending import was declared, because a
// test-only dependency and a build dependency are not equally severe -- but
// neither is acceptable, so both are reported.
type ImportKind string

const (
	// KindBuild is an import reachable from the package's non-test sources.
	// This is the serious one: it puts the dependency in an adopter's build.
	KindBuild ImportKind = "build"
	// KindTest is an import reachable only from the package's tests.
	KindTest ImportKind = "test"
	// KindExternalTest is an import from an external (package foo_test) test.
	KindExternalTest ImportKind = "external test"
)

// Rule forbids a set of import-path prefixes to every package except those
// under an allowed prefix.
type Rule struct {
	// Name identifies the rule in output.
	Name string
	// Reason explains, in one sentence, why the dependency is constrained.
	Reason string
	// DeniedPrefixes are import-path prefixes that count as the dependency.
	// Matching is by path segment: "example.com/a" matches "example.com/a" and
	// "example.com/a/b" but not "example.com/ab".
	DeniedPrefixes []string
	// ExemptImportPrefixes carve import paths back out of DeniedPrefixes. The
	// longest matching prefix across both lists decides, so an exemption can
	// sit inside a denial and a denial inside an exemption. It exists because
	// this module is published under the same organization as the SDK the
	// c1-optional rule denies: "github.com/conductorone" must keep denying every
	// other module there without denying AppHub's own packages, while
	// credentials/c1 inside the exemption stays denied.
	ExemptImportPrefixes []string
	// AllowedPrefixes are package-path prefixes permitted to reach those
	// imports, directly or transitively.
	//
	// This list is the entire mechanism. Adding to it is how the constraint gets
	// relaxed, and it should be hard to do by accident and easy to spot in review.
	AllowedPrefixes []string
	// CompositionRoots may directly wire an existing AllowedPrefixes boundary
	// without inheriting that boundary's SDK imports. Keys are exact packages,
	// never prefixes. KindTest restricts this permission to test imports;
	// KindBuild permits executable production wiring as well.
	// Direct SDK imports and paths through non-boundary wrappers remain denied.
	CompositionRoots map[string]ImportKind
	// PermittedImportPrefixes inverts the rule: instead of naming what a subject
	// may not reach, it names everything a subject MAY reach, and anything else
	// is a violation. The standard library is permitted implicitly, since no
	// rule here is about it.
	//
	// It exists because a denylist is blind to a population that does not exist
	// yet, and the deploy fence's whole purpose is to be right about the next
	// substrate as well as this one. Review demonstrated it: a compileable
	// import of a cloud SDK from a fourth vendor passed the substrate denylist,
	// because the denylist names three vendors and that one was not among them.
	// Adding a fourth prefix would have closed that spelling and left the
	// population defect exactly where it was.
	//
	// An allowlist has the opposite failure mode, and it is the one worth
	// having: a dependency nobody anticipated fails the build, and the failure
	// lands on the person adding it, which is the only place it is cheap.
	//
	// Mutually exclusive with DeniedPrefixes: a rule states one kind of claim or
	// the other, and [Config.Validate] refuses one that tries to state both.
	PermittedImportPrefixes []string
	// SubjectPrefixes bounds which packages the rule judges. Empty means every
	// package under the module prefix, which is what the two original fences
	// want: "nobody may reach ConductorOne except the c1 provider" is a claim
	// about the whole tree.
	//
	// A rule with subjects makes the opposite kind of claim -- "this package may
	// not reach that dependency" -- and the difference matters. Expressing
	// "modules/deploy must not import an AWS SDK" as a tree-wide denial with an
	// allowlist would put every present and future AWS-touching package on the
	// allowlist, so the list, not the claim, would become the thing under
	// review, and the claim would silently widen every time somebody added an
	// entry (USOSS-15).
	//
	// A subject set is the population the rule is quantified over, so an empty
	// one is a rule that checks nothing: see [Findings.Validate], which fails a
	// run in which a subject-scoped rule judged no package at all. That is the
	// case a renamed or deleted subject package produces, and it is exactly the
	// case a green tick must not cover.
	SubjectPrefixes []string
}

// Config is the full set of rules the repository enforces.
type Config struct {
	// ModulePrefix bounds which packages are judged. Empty means every package
	// in the graph, which is what the fixtures use.
	ModulePrefix string
	Rules        []Rule
	// GOOS and GOARCH are the support matrix: every pair is a build
	// configuration the dependency closure runs, and -- because acceptance is
	// derived from coverage -- the set of platform selectors a file may carry.
	//
	// Adding a platform here adds a closure pass. Removing one stops accepting
	// its build constraint. There is deliberately no second list to keep in
	// step with this one.
	GOOS   []string
	GOARCH []string
	// AllowedBuildTags are custom build constraints this repository permits.
	// Each one also adds a closure pass with the tag enabled, so declaring a
	// tag buys coverage rather than an exemption.
	//
	// It is empty, and that is the point: an unselected tag is a place the
	// dependency closure does not look.
	AllowedBuildTags []string
	// CgoEnabled adds a CGO_ENABLED=1 pass per platform, and is what makes
	// `cgo` an acceptable build constraint. Off, because nothing here uses cgo
	// and an uncovered selector must not be accepted.
	CgoEnabled bool
	// StandardPackages is the toolchain's own answer to "what is in the
	// standard library", from [StandardPackages]. An allowlist rule permits
	// membership of this set without naming it, so it is required whenever one
	// is configured and [Config.Validate] refuses a configuration that has an
	// allowlist and no set.
	//
	// It is not defaulted here for the same reason [Config.ReleaseTags] is not:
	// the answer comes from the toolchain running the check, and a compiled-in
	// guess is a claim about somebody else's Go installation.
	StandardPackages map[string]bool
	// ReleaseTags are the go1.N constraints the toolchain running the closure
	// reports, and therefore the ones a pass would actually select.
	//
	// Not the module's `go` directive: review showed a Go 1.26 toolchain
	// selecting a //go:build go1.25 file in a module declaring go 1.21. The
	// directive governs language semantics, which is a different question from
	// which files get compiled. The loader asks the toolchain
	// (ToolchainReleaseTags); the default mirrors the toolchain that built this
	// binary, and a test asserts the two agree.
	ReleaseTags []string
}

// DefaultConfig is the constraint set for this repository.
//
// Note that these rules have nothing to bite on until the packages they name
// exist. That is the intended state at bootstrap: the rules are correct now, and
// start guarding something the moment a real ConductorOne or DynamoDB import
// lands.
func DefaultConfig() Config {
	return Config{
		ModulePrefix:     DefaultModulePrefix,
		GOOS:             DefaultGOOS,
		GOARCH:           DefaultGOARCH,
		AllowedBuildTags: nil,
		CgoEnabled:       false,
		ReleaseTags:      DefaultReleaseTags(),
		Rules: []Rule{
			{
				// This is the import half of a fence with two of them. It is a
				// proof -- a union import graph, so no build configuration can
				// hide an edge from it -- and it is exactly as wide as its
				// subject, which is imports. A package that names ConductorOne,
				// reads APPHUB_C1_* or branches on the provider's registry id
				// couples to it with no import to find, and that half is
				// [DefaultC1IdiomRule] in idiom.go (USOSS-34).
				Name: "c1-optional",
				Reason: "ConductorOne is optional; an adopter with no ConductorOne account " +
					"must still be able to build and run AppHub, so only the c1 credential " +
					"provider may depend on it (docs/decisions/)",
				DeniedPrefixes: []string{
					// The ConductorOne SDKs and any other module published under the org.
					"github.com/conductorone",
					// AppHub's own ConductorOne-backed provider: reaching it pulls the
					// dependency in just as surely as importing the SDK directly.
					"github.com/conductorone/apphub/credentials/c1",
					// The read-only directory client. A separate entry rather than a
					// widening of the one above -- hasPathPrefix is segment-aware, so
					// "credentials/c1" does not already cover "credentials/c1directory"
					// -- for the same reason it is a separate package: a different
					// trust relationship, holding a different credential
					// (docs/design/credential-vending.md §3.1).
					"github.com/conductorone/apphub/credentials/c1directory",
				},
				// This module lives under the organization denied above; its own
				// packages are not the ConductorOne dependency. The two
				// credentials/c1 denials are longer, so they still win.
				ExemptImportPrefixes: []string{DefaultModulePrefix},
				AllowedPrefixes: []string{
					"github.com/conductorone/apphub/credentials/c1",
					"github.com/conductorone/apphub/credentials/c1directory",
					// The one allowlisted composition root, added by USOSS-8. It
					// exists because the rule read strictly means no binary in this
					// repository can register the ConductorOne provider: any
					// composition root that imports the package to register it is
					// itself a violation, so AppHub would ship no runnable binary
					// capable of its own flagship capability.
					//
					// The reason is recorded in docs/design/credential-vending.md
					// §11.3 rather than only here, because an entry in a security
					// boundary's allowlist with no recorded reason looks like drift
					// and is the kind of thing a later reader deletes as cleanup.
					//
					// The property being protected survives: no *library* package
					// depends on ConductorOne, which is what an adopter who does not
					// want it actually relies on. A second entry requires supervisor
					// approval -- one entry is a composition root, two is a pattern.
					// credentials/c1directory now shares this same composition root
					// rather than gaining a second one of its own, for that reason.
					//
					// Note what this does and does not permit, because the rule is a
					// path-prefix match and not an exact one: it names one leaf main
					// package, but any package created beneath that path would be
					// allowed too. Nothing beneath it exists, and
					// TestC1AllowlistPermitsOnlyTheNamedCompositionRoot pins both
					// halves so the true extent of the widening is visible rather
					// than inferred.
					"github.com/conductorone/apphub/cmd/apphub",
				},
			},
			{
				Name: "ext-is-optional",
				Reason: "compute/ext holds ports only one substrate can implement; every " +
					"package that can reach one is a place AWS specifics can grow back " +
					"into portable code, so the set of importers is an allowlist rather " +
					"than a convention (docs/design/compute-provider.md)",
				DeniedPrefixes: []string{
					"github.com/conductorone/apphub/compute/ext",
				},
				CompositionRoots: map[string]ImportKind{
					"github.com/conductorone/apphub/internal/integration": KindTest,
					"github.com/conductorone/apphub/internal/worker":      KindTest,
				},
				AllowedPrefixes: []string{
					// The package itself, so its own tests can import it.
					"github.com/conductorone/apphub/compute/ext",
					// Providers implement these ports; a provider that has the
					// substrate feature must be able to name the interface.
					"github.com/conductorone/apphub/compute/aws",
					"github.com/conductorone/apphub/compute/fake",
					"github.com/conductorone/apphub/compute/k8s",
					// The provider conformance suite, which has to check that an ext
					// lookup succeeds exactly when the provider documents that it
					// implements the port. That check is the mechanism by which a
					// substrate's inability becomes explicit rather than a skipped
					// resource, so the suite has to be able to name the ports; it
					// contains no AWS specifics of its own and implements nothing.
					"github.com/conductorone/apphub/compute/conformance",
					// The one core package permitted, and it is permitted reluctantly:
					// an application may be configured for an AWS-only bucket type, so
					// the deploy module has to be able to ask for one. Its use must go
					// through the lookup helpers and must surface the refusal to the
					// operator rather than skipping the resource.
					"github.com/conductorone/apphub/modules/deploy",
					// The ConductorOne integration needs the cross-domain grant port.
					"github.com/conductorone/apphub/credentials/c1",
					// Wiring.
					"github.com/conductorone/apphub/cmd",
				},
			},
			{
				Name: "deploy-is-substrate-free",
				Reason: "the deploy module is the abstraction's acceptance test: if it can " +
					"be written without naming a substrate SDK then the Compute interface " +
					"is real, and if it needs an exception the interface is wrong and gets " +
					"fixed rather than exempted (USOSS-15)",
				// The whole vendor namespace of each substrate, not the specific
				// SDK module paths. A list of module paths is a restatement of
				// somebody else's release history and goes stale the first time
				// they publish a new one; the organisation prefix cannot. It is
				// deliberately wider than "the SDK" -- smithy-go, the Lambda
				// runtime library and the Kubernetes API machinery are all
				// substrate detail this package must not carry either.
				DeniedPrefixes: []string{
					"github.com/aws",
					"k8s.io",
					"sigs.k8s.io",
				},
				// Scoped to the one package the claim is about. Stated tree-wide
				// it would need an allowlist naming compute/aws, compute/k8s,
				// credentials/aws and everything added later, and reviewing that
				// list is not the same as reviewing this claim.
				SubjectPrefixes: []string{
					"github.com/conductorone/apphub/modules/deploy",
				},
			},
			{
				Name: "deploy-imports-are-an-allowlist",
				Reason: "the deploy module's dependencies are a decided list, because a " +
					"denylist of substrates is blind to the next substrate: review planted a " +
					"compileable cloud SDK from a vendor the denylist did not name and it " +
					"passed. This rule forbids everything it does not name, so a dependency " +
					"nobody anticipated fails the build of whoever adds it (USOSS-15)",
				// Everything modules/deploy may reach, and it is short because
				// the module's whole claim is that it talks to one abstraction.
				// The standard library is permitted implicitly; see Rule.denies.
				//
				// This is a DECIDED population, not a derived one, and it is the
				// half of the fence that has to be. There is no semantic
				// authority for "is this module a substrate SDK" -- that is a
				// judgement -- so the construction inverts the question into one
				// that has an authority: what does this package actually need.
				// Widening it is an edit somebody makes on purpose and a
				// reviewer sees.
				PermittedImportPrefixes: []string{
					// The portable interface, which is the point of the module.
					// compute/ext lies beneath this prefix and is governed
					// separately by ext-is-optional above; compute/fake, which
					// the tests drive, lies beneath it too.
					"github.com/conductorone/apphub/compute",
					// The credential vocabulary. The workload-identity contract
					// puts the SecretRef conversion in the deploy layer, so this
					// module has to be able to name the type.
					"github.com/conductorone/apphub/credentials",
					// The framework this module implements.
					"github.com/conductorone/apphub/modules",
					// PostgreSQL extension allowlist and SQL-neutral provisioning
					// contract. The deploy planner validates names against this
					// security control; the concrete pgx driver stays in the
					// worker composition rather than broadening this fence to
					// database drivers.
					"github.com/conductorone/apphub/postgres",
				},
				SubjectPrefixes: []string{
					"github.com/conductorone/apphub/modules/deploy",
				},
			},
			{
				Name: "dynamodb-fenced",
				Reason: "v1 persistence is DynamoDB behind a single fence; every DynamoDB " +
					"call belongs in store/ so a second backend is one package to rewrite " +
					"rather than a hunt through all of them (USOSS-5)",
				DeniedPrefixes: []string{
					"github.com/aws/aws-sdk-go-v2/service/dynamodb",
					"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams",
					"github.com/aws/aws-sdk-go-v2/feature/dynamodb",
				},
				CompositionRoots: map[string]ImportKind{
					"github.com/conductorone/apphub/cmd/apphub":           KindBuild,
					"github.com/conductorone/apphub/internal/integration": KindTest,
				},
				AllowedPrefixes: []string{
					"github.com/conductorone/apphub/store",
					// Provisioning a DynamoDB table FOR a deployed application
					// is not apphub's own persistence, and the two are on
					// opposite sides of the port this rule guards.
					//
					// The rule's reason is storage-backend portability: v1
					// persistence is DynamoDB, a second backend should be one
					// package to rewrite, and every call that would have to be
					// rewritten belongs in store/. A table an application asks
					// for through compute.KeyValueProvisioner is not part of
					// that rewrite — it is a capability the compute interface
					// declares, derived from this substrate, and the only place
					// compute.Granter's presence on that port can be
					// implemented at all. Swapping apphub's persistence to
					// Postgres would not touch it; swapping the compute
					// provider to Kubernetes makes the whole port decline
					// (compute/k8s does).
					//
					// This entry was approved rather than assumed, and it is
					// narrow: the package, not a prefix under it, and only for
					// the SDK's DynamoDB clients. USOSS-14, and recorded in
					// docs/decisions/usoss-14-the-dynamodb-fence-is-widened-for-provisioning-in-both-halves-one-package-and-one-file.md.
					"github.com/conductorone/apphub/compute/aws",
				},
			},
			{
				Name: "aws-sdk-confined",
				Reason: "the AWS SDK belongs behind a provider boundary; a package outside one " +
					"that reaches for it is a package where cloud specifics have grown back into " +
					"portable code, which is exactly what compute/ and postgres/ exist to " +
					"prevent (USOSS-14)",
				// The whole SDK, by module prefix. Naming the SDK root rather
				// than enumerating services is what makes this rule not go
				// stale: a service package added tomorrow is denied without
				// anybody editing a list, which is the failure mode a
				// hand-maintained restatement of somebody else's set has on this
				// project twice already.
				DeniedPrefixes: []string{
					"github.com/aws/aws-sdk-go-v2",
					"github.com/aws/smithy-go",
				},
				CompositionRoots: map[string]ImportKind{
					"github.com/conductorone/apphub/cmd/apphub":           KindBuild,
					"github.com/conductorone/apphub/internal/integration": KindTest,
				},
				AllowedPrefixes: []string{
					// The AWS compute provider. Its whole job is to be the one
					// place AWS specifics live.
					"github.com/conductorone/apphub/compute/aws",
					// The persistence fence, which the dynamodb-fenced rule
					// above already constrains more tightly.
					"github.com/conductorone/apphub/store",
					// The AWS credential path. An AWS credential provider
					// cannot be written without the SDK's signer and STS, so
					// this is the same kind of package as compute/aws: a named
					// place where AWS specifics are the point.
					//
					// Added when USOSS-9 landed on main (#41) after this rule
					// had already gone green. The rule was written before that
					// package existed, so nothing was wrong with either half --
					// and the composition would have turned main red on merge,
					// because a PR's CI tests it against the main it was rebased
					// onto rather than the current one. It is the prefix
					// credentials/aws and not credentials, so the root package
					// -- the one postgres/ depends on -- stays denied.
					"github.com/conductorone/apphub/credentials/aws",
					// The narrow, read-only CloudWatch Logs surface the
					// authenticated API process ("serve") holds directly --
					// the one deliberate exception to "a real cloud
					// credential lives only in the worker". See
					// internal/logs's package doc for why a log tail cannot
					// wait for the durable worker-dispatch pattern the rest
					// of this repository uses.
					"github.com/conductorone/apphub/internal/logs",
					// The admin-managed GitHub App private key's SSM Parameter
					// Store binding. Like credentials/aws, this package cannot
					// exist without the SDK's SSM client, and it is the one
					// place that specific AWS capability belongs -- narrower
					// than compute/aws, since it never touches ECS, IAM or a
					// registry. See internal/ghappkey's package doc for why it
					// is split into a write-only half ("serve" holds) and a
					// read half ("worker" holds).
					"github.com/conductorone/apphub/internal/ghappkey",
					// The application-secret handoff's KMS binding: the same
					// shape as ghappkey, one AWS capability in one package,
					// split into an encrypt-only half ("serve") and a
					// decrypt-only half ("worker"). It never touches SSM,
					// ECS or IAM -- the worker writes the value through
					// compute/aws. See internal/secrethandoff's package doc.
					"github.com/conductorone/apphub/internal/secrethandoff",
					// The checker's own fixtures name SDK paths as data.
					"github.com/conductorone/apphub/internal/boundary",
				},
			},
		},
	}
}

// Violation is one disallowed dependency.
type Violation struct {
	// RuleName is the rule that was broken.
	RuleName string
	// Package is the offending package, with any test-variant decoration
	// resolved back to the package a reader would recognise.
	Package string
	// Import is the disallowed package that was reached.
	Import string
	// Via is the chain from Package to Import, exclusive of both ends. Empty
	// for a direct import; populated when the dependency arrived through
	// something else, which is the case a direct-imports check cannot see.
	Via []string
	// Chain is the same path with a file and line for every hop, as the union
	// graph found it. This is what makes a transitive finding actionable: it
	// names the exact import declaration at each step rather than leaving a
	// reader to guess which of a package's imports carried the dependency in.
	// Empty for a finding that came from the dependency-graph view, which knows
	// packages but not files.
	Chain []ChainEdge
	// Introducer is the package that declared the denied import -- the last hop
	// of Chain. For a direct import it is Package itself; for a transitive one
	// it is the package that created the reachability, which is the one somebody
	// has to deal with.
	Introducer string
	// Kind says whether the dependency is in the build or only in tests.
	Kind ImportKind
	// File and Line locate the import when the finding came from the file scan.
	// Empty for findings that came from the dependency graph.
	File string
	Line int
	// GOOS records which build target surfaced a graph finding, so a
	// platform-specific violation is legible as one.
	GOOS string
	// Tag is the offending build constraint, for a build-tag finding. When it
	// is set the finding is about a file the other two checks could not see,
	// rather than about a dependency.
	Tag string
	// Reason is the rule's human-readable justification.
	Reason string
}

func (v Violation) String() string {
	var b strings.Builder
	if v.Tag != "" {
		fmt.Fprintf(&b, "%s declares build tag %q, which no build selects", v.File, v.Tag)
		if v.Line > 0 {
			fmt.Fprintf(&b, " at line %d", v.Line)
		}
		fmt.Fprintf(&b, ": %s", v.Reason)
		return b.String()
	}
	fmt.Fprintf(&b, "%s imports %s", v.Package, v.Import)
	if len(v.Via) > 0 {
		fmt.Fprintf(&b, " via %s", strings.Join(v.Via, " -> "))
	}
	fmt.Fprintf(&b, " (%s import)", v.Kind)
	if v.File != "" {
		fmt.Fprintf(&b, " at %s:%d", v.File, v.Line)
	}
	if v.Introducer != "" && v.Introducer != v.Package {
		fmt.Fprintf(&b, " [declared by %s]", v.Introducer)
	}
	if v.GOOS != "" {
		fmt.Fprintf(&b, " [GOOS=%s]", v.GOOS)
	}
	fmt.Fprintf(&b, ": %s", v.Reason)
	return b.String()
}

// key identifies a finding for deduplication. Several views of the tree find
// the same problem, and a reader wants to be told once.
func (v Violation) key() string {
	// A build-tag finding is about one file, so two files declaring the same
	// tag are two findings. A dependency finding is about a pair of packages,
	// and the file is deliberately excluded so the same dependency found by the
	// file scan and by the closure collapses into one -- that is what lets
	// Merge keep whichever version names a line.
	if v.Tag != "" {
		return strings.Join([]string{v.RuleName, v.File, v.Tag}, "|")
	}
	return strings.Join([]string{v.RuleName, v.Package, v.Import, string(v.Kind)}, "|")
}

// Node is one package in a dependency graph: a subset of what `go list -json`
// emits, so the loader can stay a thin adapter and the logic here stays
// testable without a toolchain in the loop.
type Node struct {
	// ImportPath is the package's path, possibly a test-variant decoration
	// such as "example.com/a [example.com/a.test]".
	ImportPath string
	// Imports are the paths this node depends on, as `go list` reports them.
	Imports []string
	// ForTest is set by `go list -test` on a variant compiled for a test
	// binary, and names the package under test.
	ForTest string
}

// FileImports is one Go file's declared imports, read without consulting build
// constraints.
type FileImports struct {
	// File is a path for humans; it is not interpreted.
	File string
	// Package is the import path of the directory the file lives in.
	Package string
	// Kind distinguishes source, in-package test, and external test files.
	Kind ImportKind
	// Imports maps an imported path to the line it appears on.
	Imports []Import
	// BuildTags are the identifiers named by the file's build constraints,
	// whether written as //go:build, as a legacy // +build line, or implied by
	// the filename (foo_windows_amd64.go).
	BuildTags []BuildTag
}

// BuildTag is one identifier from a file's build constraints and where it came
// from.
type BuildTag struct {
	Name string
	Line int
	// Implicit is true for a tag the filename implies rather than a comment
	// declaring it. Those are always GOOS or GOARCH values and are reported
	// with the file rather than a line.
	Implicit bool
}

// Import is one import spec and where to find it.
type Import struct {
	Path string
	Line int
}

// CheckGraph reports every rule violation reachable in the transitive closure
// of any package under the configured module prefix.
//
// goos is recorded on findings so a platform-specific violation reads as one;
// it does not affect the analysis, which is entirely determined by the graph
// it is handed.
func (c Config) CheckGraph(nodes []Node, goos string) []Violation {
	byPath := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		byPath[n.ImportPath] = n
	}

	var out []Violation
	for _, n := range nodes {
		owner, kind := n.owner()
		if c.ModulePrefix != "" && !hasPathPrefix(owner, c.ModulePrefix) {
			continue
		}
		for _, rule := range c.Rules {
			if !rule.judges(owner) {
				continue
			}
			for _, r := range rule.reachable(n, byPath, c.StandardPackages) {
				out = append(out, Violation{
					RuleName: rule.Name,
					Package:  owner,
					Import:   r.target,
					Via:      r.via,
					Kind:     kind,
					GOOS:     goos,
					Reason:   rule.Reason,
				})
			}
		}
	}
	return dedupe(out)
}

// CheckFiles reports every rule violation declared by a Go file, regardless of
// whether the current build context would compile that file. This is the half
// of the check that a `*_windows.go` cannot hide from.
func (c Config) CheckFiles(files []FileImports) []Violation {
	var out []Violation
	for _, f := range files {
		for _, rule := range c.Rules {
			if !rule.judges(f.Package) {
				continue
			}
			for _, imp := range f.Imports {
				denied, ok := rule.denies(imp.Path, c.StandardPackages)
				if !ok {
					continue
				}
				out = append(out, Violation{
					RuleName: rule.Name,
					Package:  f.Package,
					Import:   denied,
					Kind:     f.Kind,
					File:     f.File,
					Line:     imp.Line,
					Reason:   rule.Reason,
				})
			}
		}
	}
	return dedupe(out)
}

// Merge combines findings from several views of the tree into one list, keeping
// the most actionable version of each. A finding with a file and line beats the
// same finding discovered only as a graph edge, because it tells the reader
// which line to delete.
func Merge(sets ...[]Violation) []Violation {
	best := map[string]Violation{}
	for _, set := range sets {
		for _, v := range set {
			cur, seen := best[v.key()]
			if !seen || better(v, cur) {
				best[v.key()] = v
			}
		}
	}
	out := make([]Violation, 0, len(best))
	for _, v := range best {
		out = append(out, v)
	}
	sortViolations(out)
	return out
}

// better reports whether a should replace b in the merged output.
func better(a, b Violation) bool {
	// A located finding is the most useful thing to show.
	if (a.File != "") != (b.File != "") {
		return a.File != ""
	}
	// Then the shortest explanation of how the dependency arrives.
	if len(a.Via) != len(b.Via) {
		return len(a.Via) < len(b.Via)
	}
	// Then a per-hop chain over a bare package path, since the union view can
	// name the declaration at every step and the graph view cannot.
	if (len(a.Chain) > 0) != (len(b.Chain) > 0) {
		return len(a.Chain) > 0
	}
	return false
}

type reach struct {
	target string
	via    []string
}

// reachable walks the dependency closure from n, breadth-first so the chain it
// reports is the shortest one, and returns each denied package it can get to.
func (r Rule) reachable(n Node, byPath map[string]Node, std map[string]bool) []reach {
	type state struct {
		path string
		via  []string
	}
	seen := map[string]bool{n.ImportPath: true}
	owner, kind := n.owner()
	queue := make([]state, 0, len(n.Imports))
	for _, imp := range n.Imports {
		if seen[imp] {
			continue
		}
		seen[imp] = true
		queue = append(queue, state{path: imp})
	}

	var found []reach
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		// A test variant is decorated; judge the package it stands for.
		target := ownerPath(cur.path, byPath[cur.path].ForTest)
		// go list adds a synthetic test-main -> same-owner test-variant hop.
		// It is not a source-level wrapper around the provider import.
		direct := len(cur.via) == 0 || (kind != KindBuild && len(cur.via) == 1 && cur.via[0] == owner)
		if direct && r.composesBoundary(owner, kind, target) {
			continue
		}
		if denied, ok := r.denies(target, std); ok {
			found = append(found, reach{target: denied, via: append([]string(nil), cur.via...)})
			// Stop here. What the forbidden package itself depends on is its
			// own business, and walking through it would bury the finding.
			continue
		}
		for _, next := range byPath[cur.path].Imports {
			if seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, state{path: next, via: append(append([]string(nil), cur.via...), target)})
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].target < found[j].target })
	return found
}

// denies reports whether the rule forbids path, and returns the path that
// matched.
//
// Two shapes, and a rule uses exactly one. A denylist rule forbids what it
// names. An allowlist rule ([Rule.PermittedImportPrefixes]) forbids everything
// it does not name.
func (r Rule) denies(path string, std map[string]bool) (string, bool) {
	if len(r.PermittedImportPrefixes) > 0 {
		// The standard library is permitted without being listed, and
		// membership is the toolchain's answer rather than a guess about how
		// standard paths are spelled.
		//
		// The guess was that a module path's first element contains a dot and a
		// standard-library path's does not. Review falsified it with a module
		// reached through a `replace` directive and named `cloud`: a real,
		// compileable Go module, providing cloud/sdk/azidentity, waved through
		// this allowlist as standard library. A `replace` target may declare
		// any module path, dot or no dot. See [StandardPackages] for why the
		// same inference was sound for the denylist rules and unsound the
		// moment the implication reversed.
		if std[path] {
			return "", false
		}
		for _, permitted := range r.PermittedImportPrefixes {
			if hasPathPrefix(path, permitted) {
				return "", false
			}
		}
		return path, true
	}
	deniedLen := longestPrefixMatch(path, r.DeniedPrefixes)
	if deniedLen > 0 && deniedLen > longestPrefixMatch(path, r.ExemptImportPrefixes) {
		return path, true
	}
	return "", false
}

// longestPrefixMatch returns the length of the longest prefix in prefixes that
// path matches by segment, or 0 when none does.
func longestPrefixMatch(path string, prefixes []string) int {
	longest := 0
	for _, prefix := range prefixes {
		if hasPathPrefix(path, prefix) && len(prefix) > longest {
			longest = len(prefix)
		}
	}
	return longest
}

func (r Rule) allows(pkgPath string) bool {
	for _, allowed := range r.AllowedPrefixes {
		if hasPathPrefix(pkgPath, allowed) {
			return true
		}
	}
	return false
}

func (r Rule) composesBoundary(root string, kind ImportKind, target string) bool {
	mode, ok := r.CompositionRoots[root]
	return ok && (mode == KindBuild || kind != KindBuild) && r.allows(target)
}

// judges reports whether pkgPath is a package this rule has anything to say
// about: inside the subject set, if there is one, and not exempted.
//
// It is the single predicate every view of the tree asks, so the graph view,
// the file view and the union proof cannot come to different answers about who
// a rule applies to.
func (r Rule) judges(pkgPath string) bool {
	if len(r.SubjectPrefixes) > 0 && !r.subjects(pkgPath) {
		return false
	}
	return !r.allows(pkgPath)
}

// subjects reports whether pkgPath is inside the rule's subject set.
func (r Rule) subjects(pkgPath string) bool {
	for _, subject := range r.SubjectPrefixes {
		if hasPathPrefix(pkgPath, subject) {
			return true
		}
	}
	return false
}

// owner resolves a node to the package a reader would recognise, and says
// whether the node is a test artefact.
//
// `go list -test` invents packages: "a [a.test]" is a compiled for its own test
// binary, "a_test [a.test]" is the external test package, and "a.test" is the
// generated main. All three have to be judged as the package they belong to,
// or the external test of an allowed package looks like a violation because
// "a_test" is not beneath the "a" prefix.
func (n Node) owner() (string, ImportKind) {
	if n.ForTest != "" {
		kind := KindTest
		if strings.HasSuffix(stripVariant(n.ImportPath), "_test") {
			kind = KindExternalTest
		}
		return n.ForTest, kind
	}
	if strings.HasSuffix(n.ImportPath, ".test") {
		return strings.TrimSuffix(n.ImportPath, ".test"), KindTest
	}
	return n.ImportPath, KindBuild
}

// ownerPath is owner() for a path whose node may not be in the graph.
func ownerPath(path, forTest string) string {
	if forTest != "" {
		return forTest
	}
	if strings.HasSuffix(path, ".test") {
		return strings.TrimSuffix(path, ".test")
	}
	return stripVariant(path)
}

func stripVariant(path string) string {
	if i := strings.Index(path, " ["); i >= 0 {
		return path[:i]
	}
	return path
}

// hasPathPrefix reports whether path is prefix or lies beneath it, matching on
// whole path segments. Plain strings.HasPrefix would make
// ".../credentials/c1inder" match ".../credentials/c1", which is the kind of
// near-miss that turns a security boundary into a suggestion.
func hasPathPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func dedupe(in []Violation) []Violation {
	return Merge(in)
}

func sortViolations(v []Violation) {
	sort.Slice(v, func(i, j int) bool {
		a, b := v[i], v[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Import != b.Import {
			return a.Import < b.Import
		}
		if a.RuleName != b.RuleName {
			return a.RuleName < b.RuleName
		}
		return a.Kind < b.Kind
	})
}
