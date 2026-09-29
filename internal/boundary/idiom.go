// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// The import rule in boundary.go closes one half of the DynamoDB fence: no
// package outside store may import the SDK. This file closes the other half.
//
// The halves are not the same check, and the first does not imply the second. An
// import is a dependency; an idiom is a shape. A type carrying `dynamodbav` tags,
// a function taking a `"PK = :pk AND begins_with(SK, :sk)"` string, a struct
// field named GSI1SK -- none of these need the SDK in scope, all of them are
// DynamoDB leaking into business logic, and all of them would survive an
// import-only check untouched. The source system is the evidence that this is the
// real failure mode: 1,456 `dynamodbav` tags and 328 GSI1 references spread
// across 38 files, because nothing ever said they should not.
//
// The rule is one sentence: if a caller outside store can tell which database is
// underneath, the fence has failed.
//
// # Match meaning, not spelling
//
// The first version of this rule compared needles against the raw token text and
// was defeated in review by ordinary Go: a field tag written
// "\x64ynamodbav:\"PK\"" is the real dynamodbav tag as far as reflect is
// concerned, and an expression assembled with fmt.Sprintf from escaped fragments
// is the real expression as far as DynamoDB is concerned. Neither spelling
// contains a needle, both compile, and the gate passed.
//
// That is the third time on this project that a lexical check matching source
// spelling lost to a language feature -- the import checker fell to build tags
// twice and the secret gate to quoting twice. So this rule now compares what the
// compiler computes: string literals are unquoted, concatenations are folded, and
// constant fmt.Sprintf calls are expanded. See foldConstString.
//
// What it still cannot do is follow a value that is not a constant. A string
// built from runtime input, assembled a rune at a time, or read from a file will
// not be caught, and no lexical rule can catch it. That bound is worth stating
// rather than implying: this rule exists to stop the fence eroding by ordinary
// convenience -- which is how the source system reached 1,456 tags -- not to beat
// an author determined to hide something from it.

// SourceFile is one Go file to inspect. Path is module-relative with forward
// slashes, so rules read the same on every platform.
type SourceFile struct {
	Path    string
	Content []byte
}

// Leak is one piece of fenced idiom found outside its fence.
type Leak struct {
	// Rule is the name of the [IdiomRule] that recognised it. There is more than
	// one idiom rule now, and a finding that does not say which fence it broke
	// makes the reader guess at the reason.
	Rule string
	// Path is the file it was found in.
	Path string
	// Line is the 1-indexed line.
	Line int
	// Token is the resolved text that matched, trimmed for display. It is the
	// computed value rather than the source spelling, so a leak written with
	// escapes reports what it actually means.
	Token string
	// Needle is the idiom that was recognised.
	Needle string
	// Reason explains why it does not belong outside store.
	Reason string
}

func (l Leak) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s (%s): %s", l.Path, l.Line, l.Rule, l.Needle, l.Token, l.Reason)
}

// IdiomRule forbids a vocabulary outside a set of allowed path prefixes.
type IdiomRule struct {
	// Name identifies the rule in output.
	Name string
	// Subject names, in a few words, what the rule is about and where the
	// vocabulary is allowed: "DynamoDB idiom outside store/". It is the sentence
	// the command prints, so a second rule cannot be reported as the first one.
	Subject string
	// Advice is printed under this rule's findings and says what to do about
	// them. It belongs to the rule rather than to the command for the same
	// reason Reason does: the rule knows what it is protecting.
	Advice string
	// Needles are the idiom fragments that count as a leak, each with the reason
	// it is one.
	Needles []Needle
	// AllowedPrefixes are the module-relative path prefixes permitted to contain
	// the idiom. As with the import rule, this list is the entire mechanism:
	// widening it is a diff a reviewer sees.
	AllowedPrefixes []string
	// Masked are exact, case-sensitive substrings blanked out of a candidate
	// before any needle is tried. It exists for this module's own path: AppHub is
	// published under the vendor's organization, so every import-path string in
	// the tree spells the vendor's name without being coupled to it. Only the
	// exact path is masked -- any other spelling, and anything after the path
	// such as /credentials/c1, is still matched.
	Masked []string
}

// Match is how a needle is compared against a candidate string.
type Match uint8

const (
	// MatchSubstring finds the needle anywhere in the text. It is the zero value
	// and what every DynamoDB needle uses: "dynamodbav" and "GSI1SK" are long
	// enough that an occurrence is never an accident.
	MatchSubstring Match = iota
	// MatchToken requires the needle to stand alone -- neither preceded nor
	// followed by a letter or a digit.
	//
	// It exists for "c1", the ConductorOne provider's registry id. Two characters
	// matched by substring is not a check, it is a random number generator:
	// "Func1", "doc1", "svc1" and every hex digest in the tree contain it. Matched
	// as a delimited token it means what it says -- "c1: mint credential",
	// `id=c1`, `APPHUB_C1_TENANT_URL` -- and ordinary Go does not trip it.
	//
	// A camel-case boundary (so that OpC1FetchToken would match) was tried and
	// rejected: it makes doc1, svc1 and rec1 findings, and a gate that fires on
	// ordinary Go is a gate somebody deletes. That bound is stated rather than
	// implied, and pinned by
	// TestTokenNeedleIsDelimitedNotCamelCase.
	MatchToken
)

// Needle is one recognisable piece of a fenced vocabulary.
type Needle struct {
	// Text is matched against identifiers and resolved string values.
	Text string
	// Reason says what it would mean for this to appear in business logic.
	Reason string
	// Match is how Text is compared; the zero value is MatchSubstring.
	Match Match
	// StringsOnly matches the needle against computed string values only, never
	// against identifiers.
	//
	// It is the second half of what makes "c1" a check rather than noise. As a
	// string, "c1" is the ConductorOne provider's registry id and means exactly
	// that. As an identifier it is a local abbreviation -- `c1, c2 := clientA,
	// clientB` is ordinary Go, and it appears in test code everywhere. A gate
	// that fires on that is a gate somebody deletes.
	//
	// The cost is stated rather than implied: an identifier that names the
	// provider without spelling the vendor out, such as credhttp's
	// OpC1FetchToken, is not matched. Its label string is, which is how that
	// package was found. Pinned by TestTokenNeedleIsDelimitedNotCamelCase and
	// TestC1IdiomRuleCleanFilesAreClean.
	StringsOnly bool
	// Fold compares without regard to case. ConductorOne is spelled
	// "ConductorOne" in a display name, "conductorone" in a hostname and an error
	// string, and "C1" in an environment variable, and all three are the same
	// coupling.
	Fold bool
}

// Found reports whether the needle occurs in text under its own match rules.
//
// It is exported because a needle's match rules are now more than
// strings.Contains, and a caller that reimplements them is a restatement that
// drifts: credentials/aws derives an exclusion list from this fence's needles,
// and before this was exported it did its own substring test, which would have
// quietly disagreed the first time a needle gained Fold or MatchToken.
func (n Needle) Found(text string) bool {
	if n.Text == "" {
		return false
	}
	hay, needle := text, n.Text
	if n.Fold {
		hay, needle = strings.ToLower(hay), strings.ToLower(needle)
	}
	if n.Match == MatchSubstring {
		return strings.Contains(hay, needle)
	}
	for i := 0; i+len(needle) <= len(hay); {
		j := strings.Index(hay[i:], needle)
		if j < 0 {
			return false
		}
		at := i + j
		if !alphanumericAt(hay, at-1) && !alphanumericAt(hay, at+len(needle)) {
			return true
		}
		i = at + 1
	}
	return false
}

// alphanumericAt reports whether s[i] is an ASCII letter or digit. An index off
// either end is not, which is what makes the ends of a string count as
// delimiters.
func alphanumericAt(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// Validate refuses a rule that cannot report a finding a reader could act on.
//
// The discipline is the same one Config.Validate and Findings.Validate keep: a
// gate configured with nothing to look for inspects every file in the tree and
// reports that the rule held, which is the one thing a gate must never do.
func (r IdiomRule) Validate() error {
	switch {
	case r.Name == "":
		return fmt.Errorf("idiom rule has no name")
	case r.Subject == "":
		return fmt.Errorf("idiom rule %s has no subject, so its findings cannot say what fence they broke", r.Name)
	case r.Advice == "":
		return fmt.Errorf("idiom rule %s has no advice, so its findings cannot say what to do", r.Name)
	case len(r.Needles) == 0:
		return fmt.Errorf("idiom rule %s has no needles, so it would hold over every file in the tree", r.Name)
	}
	for i, n := range r.Needles {
		if n.Text == "" {
			return fmt.Errorf("idiom rule %s: needle %d has no text", r.Name, i)
		}
		if n.Reason == "" {
			return fmt.Errorf("idiom rule %s: needle %q has no reason", r.Name, n.Text)
		}
	}
	return nil
}

// ValidateIdiomRules refuses a rule set with a duplicate name, because two rules
// reporting under one name make a finding impossible to attribute.
func ValidateIdiomRules(rules []IdiomRule) error {
	if len(rules) == 0 {
		return fmt.Errorf("no idiom rules configured")
	}
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return err
		}
		if _, dup := seen[r.Name]; dup {
			return fmt.Errorf("two idiom rules are named %s", r.Name)
		}
		seen[r.Name] = struct{}{}
	}
	return nil
}

// DefaultIdiomRules are every idiom fence this repository enforces, in the order
// they are reported.
//
// There are two, and they close the same class of hole in two different fences:
// a coupling the import graph cannot see because there is no import to see. See
// [DefaultDynamoDBIdiomRule] and [DefaultC1IdiomRule].
func DefaultIdiomRules() []IdiomRule {
	return []IdiomRule{DefaultDynamoDBIdiomRule(), DefaultC1IdiomRule()}
}

// DefaultDynamoDBIdiomRule is the DynamoDB idiom fence for this repository.
func DefaultDynamoDBIdiomRule() IdiomRule {
	const (
		reasonTag = "a dynamodbav struct tag makes the type a DynamoDB record; " +
			"the storage shape belongs to an unexported type inside store"
		reasonExpr = "a hand-written DynamoDB expression string is a query in a " +
			"language only DynamoDB speaks; store owns every one of them"
		reasonRequest = "this is a field of a DynamoDB request or response; a caller " +
			"that sets or reads one is talking to DynamoDB through a gap in the fence"
		reasonKey = "this names the single-table key layout; outside store, nothing " +
			"should know records have partition keys at all"
	)

	return IdiomRule{
		Name:    "dynamodb-idiom-fenced",
		Subject: "DynamoDB idiom outside store/",
		Advice: "The store fence is not only about imports: business logic that knows about\n" +
			"partition keys, expression strings, or dynamodbav tags is coupled to DynamoDB\n" +
			"whether or not it imports the SDK. Move the storage shape into store/.\n",
		AllowedPrefixes: []string{
			// The fence itself.
			"store",
			// This checker and its adapter necessarily spell out what they look
			// for. Exempting them is not a loophole for persistence code: neither
			// package may import the SDK, which the import rule still enforces.
			"internal/boundary",
			"hack/boundarycheck",
			// One FILE, not a package, and not the AWS provider as a whole.
			//
			// compute/aws provisions a DynamoDB table *for a deployed
			// application* through compute.KeyValueProvisioner, which is the
			// other side of the port this fence guards — apphub's own
			// persistence is store/ and always will be. CreateTable's billing
			// mode has to be named to get an on-demand table, and "BillingMode"
			// is a needle here, so one exemption is unavoidable.
			//
			// It is scoped to the SDK adapter file rather than to the package
			// because the package is 5,000 lines that six tickets are extending,
			// and a package-wide exemption would take the idiom half of the
			// fence off all of it. hasPathPrefix is segment-aware, so this
			// matches exactly this file. Every other file in compute/aws is
			// still checked, and a dynamodbav tag or a GSI1PK anywhere in the
			// provider is still a failure — which is the shape of leak this rule
			// was written for, and the shape a provisioning adapter has no
			// reason to contain.
			//
			// USOSS-14. The import half is widened for the same package in
			// boundary.go, with the same reasoning; see
			// docs/decisions/usoss-14-the-dynamodb-fence-is-widened-for-provisioning-in-both-halves-one-package-and-one-file.md.
			"compute/aws/awssdkdb.go",
			// And that adapter's own test, which has to name the exception types
			// whose classification it checks.
			//
			// This is a second file rather than a second package, and it is a
			// widening — said plainly, because the alternative considered was
			// worse: a fixture helper in the adapter's production file, which
			// would put a test seam in production code to satisfy a lint. The
			// needle exists to stop *business logic* knowing DynamoDB's shapes,
			// and an adapter's test is the adapter.
			//
			// TestTheIdiomExemptionIsTwoAdapterFilesNotThePackage pins that it is
			// exactly these two, including that another test file in the same
			// package is still refused.
			"compute/aws/awssdkdb_internal_test.go",
		},
		Needles: []Needle{
			{Text: "dynamodbav", Reason: reasonTag},

			{Text: "attribute_exists", Reason: reasonExpr},
			{Text: "attribute_not_exists", Reason: reasonExpr},
			{Text: "attribute_type", Reason: reasonExpr},
			{Text: "begins_with", Reason: reasonExpr},
			{Text: "if_not_exists", Reason: reasonExpr},
			{Text: "list_append", Reason: reasonExpr},

			{Text: "KeyConditionExpression", Reason: reasonRequest},
			{Text: "FilterExpression", Reason: reasonRequest},
			{Text: "ConditionExpression", Reason: reasonRequest},
			{Text: "ProjectionExpression", Reason: reasonRequest},
			{Text: "UpdateExpression", Reason: reasonRequest},
			{Text: "ExpressionAttributeNames", Reason: reasonRequest},
			{Text: "ExpressionAttributeValues", Reason: reasonRequest},
			{Text: "ExclusiveStartKey", Reason: reasonRequest},
			{Text: "LastEvaluatedKey", Reason: reasonRequest},
			{Text: "ScanIndexForward", Reason: reasonRequest},
			{Text: "ConsistentRead", Reason: reasonRequest},
			{Text: "ReturnValuesOnConditionCheckFailure", Reason: reasonRequest},
			{Text: "ConditionalCheckFailed", Reason: reasonRequest},
			{Text: "AttributeValueMember", Reason: reasonRequest},
			{Text: "ProvisionedThroughput", Reason: reasonRequest},
			{Text: "BillingMode", Reason: reasonRequest},

			{Text: "GSI1PK", Reason: reasonKey},
			{Text: "GSI1SK", Reason: reasonKey},
			{Text: "GSI2PK", Reason: reasonKey},
			{Text: "GSI2SK", Reason: reasonKey},
		},
	}
}

// DefaultC1IdiomRule is the ConductorOne idiom fence for this repository.
//
// # Why an import rule was not enough
//
// The c1-optional rule in boundary.go is an *import-prefix* rule: it denies
// imports of github.com/conductorone and of this module's credentials/c1. USOSS-28
// made that rule a proof -- a union import graph, so no build configuration can
// hide an edge from it -- and the proof is exactly as wide as its subject. Its
// subject is imports.
//
// Behavioural coupling has no import to find. The USOSS-11 worker demonstrated
// this rather than arguing it: a faithful stand-in for the source system's
// EnsureC1DatasourceRole -- an IAM role trusting a named vendor's tenant accounts,
// keyed by external IDs that vendor issues -- was placed in compute/aws, and
// `make boundary` passed, reporting that the c1-optional rule held. It takes
// strings and an IAM client, so it imports nothing c1-related and there is nothing
// for an import graph to see. That is recorded in
// docs/decisions/usoss-11-ensurec1datasourcerole-is-not-ported-and-the-import-graph-does-not-enforce-that.md,
// which ends by saying nothing enforces this boundary by construction and a
// decision record is the only thing holding it. This rule is the gate that
// sentence asked for (USOSS-34).
//
// The shape of the argument is the one already made for store/ at the top of this
// file: an import is a dependency, an idiom is a shape, and the first does not
// imply the second. The claim here is one sentence -- if a package outside
// credentials/c1 can tell that ConductorOne exists, the optionality is a
// convention rather than a property.
//
// # What it can and cannot establish
//
// It is a lexical net over computed string values and identifiers, so it inherits
// every bound stated at the top of this file: a value built from runtime input,
// assembled a rune at a time, or read from a file is invisible to it, and no
// lexical rule can see one. It is emphatically *not* a second proof beside
// USOSS-28's; the import rule proves a universal property over every build
// configuration, and this rule stops a fence eroding by ordinary convenience --
// which is the way it actually erodes, and the way the source system reached
// 1,456 dynamodbav tags.
//
// USOSS-28 lists reflection- and configuration-driven calls to a ConductorOne
// endpoint as deliberately out of scope for the import proof. They are in scope
// here whenever they are spelled in the source, which is the common case and the
// only one a checker gets to have an opinion about.
func DefaultC1IdiomRule() IdiomRule {
	const (
		reasonVendor = "the vendor's name, in code an adopter with no ConductorOne " +
			"account still builds; ConductorOne is optional, and a package that names it " +
			"has quietly decided otherwise"
		reasonConfig = "the ConductorOne configuration namespace; a package that reads one " +
			"of these variables changes its behaviour for ConductorOne with no import to " +
			"show for it"
		reasonID = "the ConductorOne provider's registry id. Special-casing a provider by " +
			"its string id is provider-specific behaviour keyed on a name -- ask the " +
			"provider for a capability instead, which is what credentials.Capabilities and " +
			"the compute/ext lookups exist for"
	)

	return IdiomRule{
		Name:    "c1-idiom-fenced",
		Subject: "ConductorOne idiom outside credentials/c1",
		Advice: "The c1-optional boundary is not only about imports: a package that names\n" +
			"ConductorOne, reads its environment variables, or branches on its provider id\n" +
			"is coupled to it whether or not it imports credentials/c1 -- and the import\n" +
			"graph, which is the proof for the import half, has nothing to see (USOSS-34).\n" +
			"\n" +
			"Provider-specific behaviour belongs behind a capability or an interface the\n" +
			"provider answers for, not behind a comparison against a name. If the coupling\n" +
			"is decided rather than accidental, widen the allowlist in\n" +
			"internal/boundary/idiom.go with the reason -- deliberately, in a diff a\n" +
			"reviewer sees.\n",
		AllowedPrefixes: []string{
			// The provider itself, and its tests.
			"credentials/c1",
			// The read-only directory client, and its tests. A second,
			// independent ConductorOne package rather than a widening of
			// credentials/c1 -- docs/design/credential-vending.md §3.1
			// decided this in advance: different trust relationship,
			// different credential, own package, and "the boundary allowlist
			// gains one reviewable entry" when it was ported. This is that
			// entry.
			"credentials/c1directory",
			// The one allowlisted composition root. It is the same entry, for the
			// same reason, as the one the c1-optional import rule carries: a
			// composition root that registers the provider has to be able to name
			// it, and without it this repository ships no runnable binary capable
			// of its own flagship capability (USOSS-8).
			//
			// The two halves of the fence deliberately share one exception rather
			// than growing two differently-shaped ones. A second entry in either
			// half requires supervisor approval; one entry is a composition root,
			// two is a pattern.
			"cmd/apphub",
			// The gates, which necessarily spell out what they police. This is one
			// category rather than four ad-hoc holes, and it is worth reading as
			// one: a checker that may not name the thing it checks cannot be
			// written.
			//
			// It is not a loophole. Every package here is still bound by the
			// import half -- the half that is a proof over the union graph -- so
			// none of them may reach ConductorOne, and what they are permitted is
			// to hold its name as data.
			//
			//   - internal/boundary: this rule and the import rules; the needles
			//     and the denied prefixes are literally the vocabulary.
			//   - hack/boundarycheck: the adapter that prints them.
			//   - internal/astaudit: derives its evidence table from the target
			//     repository's boundary Rules literal and checks the rule set by
			//     name, of which "c1-optional" is one.
			//   - internal/hermetic: asserts that CI carries no cloud or vendor
			//     credentials, and names ConductorOne's environment variables
			//     alongside AWS's and GitHub's. A gate that forbids a credential
			//     has to say which credential.
			"internal/boundary",
			"hack/boundarycheck",
			"internal/astaudit",
			"internal/hermetic",
			// One FILE, not a package.
			//
			// credhttp owns the HTTP policy for every credential-bearing request in
			// this repository, and its operation labels are a deliberately CLOSED
			// set: Op cannot be constructed from outside the package, which is what
			// stops response-controlled text reaching a log line or an error. The
			// package comment argues that closure at length, and it is the reason
			// the four "c1: ..." labels are here rather than in the provider.
			//
			// So this is a decided coupling, not drift, and the first thing this
			// rule found. The fix for a decided coupling is an allowlist entry with
			// the reason attached, not a redesign of the construction that decided
			// it -- opening the Op set to satisfy a lint would sell back the exact
			// property credhttp exists to buy.
			//
			// It is also narrow in what it gives up. The labels are strings an
			// operator reads; they carry no ConductorOne behaviour, and credhttp
			// still may not import ConductorOne. It is scoped to the one file
			// because hasPathPrefix is segment-aware, so credhttp_test.go and
			// opset_test.go are still checked -- pinned by
			// TestTheC1IdiomExemptionIsOneCredhttpFileNotThePackage.
			"internal/credhttp/credhttp.go",
		},
		Masked: []string{DefaultModulePrefix},
		Needles: []Needle{
			// The vendor's name, in every spelling. Case-folded because
			// "ConductorOne" is the display name, "conductorone" is the error text
			// and the hostname label, and both are the same coupling.
			{Text: "conductorone", Reason: reasonVendor, Fold: true},
			// There is deliberately no needle for the vendor's public domains.
			//
			// The first version of this rule had one, invented rather than looked
			// up, and .gitleaks.toml settled it: the two apexes this repository is
			// allowed to name are recorded in that file's hostname allowlist, and
			// the "conductorone" needle above already matches one of them while the
			// "c1" needle below matches the other in any URL, because a host label
			// is delimited by dots and slashes. A third needle would have been a
			// restatement with no coverage of its own.
			//
			// It also could not be written down here. The disclosure gate forbids
			// spelling a vendor hostname anywhere in this repository -- that is what
			// it is for -- so the needle literal would itself have been a finding.
			// The configuration namespace credentials/c1 reads. os.Getenv of one of
			// these is the textbook case: no import, and behaviour that changes for
			// ConductorOne. Listed before the token needle below so the finding
			// carries this reason rather than the more general one.
			{Text: "APPHUB_C1_", Reason: reasonConfig, Fold: true},
			// The provider's registry id. MatchToken, because two characters
			// matched by substring is noise rather than a check -- see [MatchToken].
			{Text: "c1", Reason: reasonID, Match: MatchToken, Fold: true, StringsOnly: true},
		},
	}
}

// Check returns every leak in files, sorted for stable output.
//
// Comments are never inspected, so documentation is free to discuss the fence --
// explaining a constraint must not be what violates it. Everything else is
// matched on its computed value; see the note at the top of this file for what
// that covers and what it cannot.
func (r IdiomRule) Check(files []SourceFile) []Leak {
	var out []Leak
	for _, f := range files {
		if r.allows(f.Path) {
			continue
		}
		out = append(out, r.leaksIn(f)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Needle < out[j].Needle
	})
	return out
}

func (r IdiomRule) allows(path string) bool {
	for _, allowed := range r.AllowedPrefixes {
		if hasPathPrefix(path, allowed) {
			return true
		}
	}
	return false
}

// match returns the first needle found in a computed string value. Order is the
// rule's, so a needle with a specific reason can be placed ahead of a more
// general one that would also match.
func (r IdiomRule) match(text string) (Needle, bool) {
	return r.matchIn(text, true)
}

// matchIn is match with the one distinction a StringsOnly needle needs: whether
// text is a computed string value or an identifier.
func (r IdiomRule) matchIn(text string, inString bool) (Needle, bool) {
	text = r.mask(text)
	for _, needle := range r.Needles {
		if needle.StringsOnly && !inString {
			continue
		}
		if needle.Found(text) {
			return needle, true
		}
	}
	return Needle{}, false
}

// mask blanks every [IdiomRule.Masked] substring out of text. A space rather
// than nothing, so the text either side cannot join into a token.
func (r IdiomRule) mask(text string) string {
	for _, masked := range r.Masked {
		text = strings.ReplaceAll(text, masked, " ")
	}
	return text
}

func (r IdiomRule) leaksIn(f SourceFile) []Leak {
	fset := token.NewFileSet()
	// Mode 0 rather than parser.ParseComments: comments are not parsed at all,
	// which is what lets this file document the idiom it forbids.
	file, err := parser.ParseFile(fset, f.Path, f.Content, 0)
	if err != nil {
		// A file that will not parse is the compiler's problem, not this rule's,
		// but it must not become a hole: fall back to a token scan, which still
		// resolves escapes.
		return r.scanTokens(f, fset)
	}

	var out []Leak
	// report emits at most one leak for a node, taking the first candidate that
	// matches. Candidates are ordered computed-value first, so the message shows
	// what the code means rather than how it was spelled.
	report := func(pos token.Pos, inString bool, candidates ...string) {
		for _, text := range candidates {
			if needle, ok := r.matchIn(text, inString); ok {
				out = append(out, Leak{
					Rule:   r.Name,
					Path:   f.Path,
					Line:   fset.Position(pos).Line,
					Token:  truncate(text, 60),
					Needle: needle.Text,
					Reason: needle.Reason,
				})
				return
			}
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ImportSpec:
			// An import path is the import rules' subject and is judged over the
			// union graph, which is a proof rather than a lexical net. Judging it
			// again here would report one coupling twice and misdescribe the second
			// report -- "idiom leak" is a lie about an import, and a gate that
			// misnames its own finding teaches people to distrust it.
			//
			// It closes nothing: a package importing credentials/c1 is a c1-optional
			// violation, blank imports included (USOSS-28's second bypass was a blank
			// import and the union graph catches it). A path spelled as a string
			// somewhere other than an import declaration -- a plugin lookup, a
			// registry key -- is not an ImportSpec and is still matched.
			//
			// The token fallback in scanTokens has no AST and therefore cannot make
			// this distinction; it over-approximates, which is the direction a
			// fallback for an unparseable file should err in.
			return false

		case *ast.Ident:
			// Type, field and variable names: GSI1SK, FilterExpression.
			report(node.Pos(), false, node.Name)

		case *ast.BasicLit:
			if node.Kind != token.STRING {
				return true
			}
			// The unquoted value is the only spelling that ever reaches DynamoDB
			// or reflect. A struct tag is required by the language to be a single
			// literal, so for tags this is not merely better -- it is complete.
			// The raw spelling is kept as a second candidate because it costs
			// nothing and cannot cause a miss.
			report(node.Pos(), true, unquoteString(node.Value), node.Value)

		case *ast.BinaryExpr:
			// "attribute" + "_exists(PK)" is one string to the compiler.
			if v, ok := foldConstString(node); ok {
				report(node.Pos(), true, v)
			}

		case *ast.CallExpr:
			// An exactly-folded call is matched on its value, because that value
			// is what the expression produces and nothing else needs guessing at.
			if v, exact := foldFormatCall(node); exact {
				report(node.Pos(), true, v)
				return true
			}
			// Everything else -- a form deliberately refused, or a helper this rule
			// has never heard of -- is matched on whether its constant fragments
			// can be assembled into a needle *in any order*.
			//
			// Order-independence is the whole point, and it is the fix for a real
			// bypass. The first net joined fragments in source order, which quietly
			// undid the refusal it existed to make safe:
			// fmt.Sprintf("%[1]*[3]s_%[2]s(PK)", 0, "exists", "attribute") was
			// refused by the folder (correctly, at the time) and then missed by the
			// net too, because source order reads "exists" before "attribute". A
			// refusal that degrades to a pass is exactly the failure the refusal was
			// supposed to prevent.
			if needle, ok := r.assemblableNeedle(constantFragments(node)); ok {
				out = append(out, Leak{
					Rule:   r.Name,
					Path:   f.Path,
					Line:   fset.Position(node.Pos()).Line,
					Token:  truncate(strings.Join(constantFragments(node), "|"), 60),
					Needle: needle.Text,
					Reason: needle.Reason,
				})
			}
		}
		return true
	})

	// Folding means a concatenation and its own operands can both match, so the
	// same leak can be reported from several nested nodes. One report per line
	// per needle is all anyone needs to find it.
	return dedupeLeaks(out)
}

// scanTokens is the fallback for a file that does not parse: no folding is
// possible without an AST, but escapes are still resolved.
func (r IdiomRule) scanTokens(f SourceFile, fset *token.FileSet) []Leak {
	file := fset.AddFile(f.Path, fset.Base(), len(f.Content))

	var s scanner.Scanner
	// A nil error handler and mode 0: comments are not emitted.
	s.Init(file, f.Content, nil, 0)

	var out []Leak
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.IDENT && tok != token.STRING {
			continue
		}
		candidates := []string{lit}
		inString := tok == token.STRING
		if inString {
			candidates = []string{unquoteString(lit), lit}
		}
		for _, text := range candidates {
			if needle, ok := r.matchIn(text, inString); ok {
				out = append(out, Leak{
					Rule:   r.Name,
					Path:   f.Path,
					Line:   file.Position(pos).Line,
					Token:  truncate(text, 60),
					Needle: needle.Text,
					Reason: needle.Reason,
				})
				break
			}
		}
	}
	return dedupeLeaks(out)
}

func dedupeLeaks(in []Leak) []Leak {
	type key struct {
		line   int
		needle string
	}
	seen := make(map[key]struct{}, len(in))
	out := make([]Leak, 0, len(in))
	for _, l := range in {
		k := key{l.Line, l.Needle}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, l)
	}
	return out
}

// unquoteString returns the value a string literal denotes.
//
// This is the whole fix for the escape bypass: strconv.Unquote turns
// "\x64ynamodbav:\"PK\"" into the tag the compiler will hand to reflect. A
// literal that will not unquote is returned as-is rather than dropped -- failing
// to resolve a value is not a reason to stop looking at it.
func unquoteString(raw string) string {
	if v, err := strconv.Unquote(raw); err == nil {
		return v
	}
	return raw
}

// unfoldable stands in for an operand whose value is not known statically. NUL
// cannot appear in a needle, so a partially-folded string can never match on the
// strength of a piece that was never resolved.
const unfoldable = "\x00"

// foldConstString evaluates a string-valued expression built from constants.
//
// It covers literals, parenthesised expressions, `+` concatenation and constant
// fmt.Sprintf/fmt.Sprint calls -- which between them are how a forbidden string
// gets assembled without ever being written down. It deliberately does not use
// go/types: constant folding here needs no type information, and requiring a
// resolvable import graph would make the gate fail for reasons unrelated to the
// fence.
func foldConstString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		return unquoteString(x.Value), true

	case *ast.ParenExpr:
		return foldConstString(x.X)

	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		left, ok := foldConstString(x.X)
		if !ok {
			return "", false
		}
		right, ok := foldConstString(x.Y)
		if !ok {
			return "", false
		}
		return left + right, true

	case *ast.CallExpr:
		// Only an exactly-modelled call may stand in for a constant string; the
		// conservative net is a matching candidate, never a value.
		return foldFormatCall(x)
	}
	return "", false
}

// constantFragments concatenates every constant string literal inside e, in
// source order.
//
// This deliberately over-approximates. It is the answer to a question the exact
// folder cannot settle: fmt is one library, and the moment a forbidden string is
// assembled by anything else -- strings.Join, a local helper, a method chain --
// modelling fmt exactly buys nothing. Joining the fragments catches every such
// helper that concatenates its constant arguments in the order they are written,
// which is what nearly all of them do.
//
// What it can produce is a false positive: literals whose concatenation contains
// a needle that the call never actually emits. That direction is the acceptable
// one. It also cannot cover a helper that reorders its operands, which is why
// indexed fmt directives are modelled exactly rather than left to this.
func constantFragments(e ast.Expr) []string {
	var out []string
	ast.Inspect(e, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v := unquoteString(lit.Value); v != "" {
				out = append(out, v)
			}
		}
		return true
	})
	return out
}

// assemblableNeedle reports whether any needle can be built by concatenating
// fragments, in any order, with repetition.
//
// This replaces a source-order concatenation, which was order-dependent and
// therefore useless for precisely the calls the folder refuses -- a refused
// %[1]*[3]s form has its operands written in the wrong order by construction.
//
// The test is: does there exist a sequence of fragments whose concatenation
// contains the needle? Equivalently the needle is a suffix of one fragment, then
// whole fragments, then a prefix of a last one. That is a reachability problem
// over the needle's positions, so it is linear rather than the factorial the
// phrase "in any order" suggests.
//
// It over-approximates, deliberately and in the safe direction: fragments that
// could tile a needle are flagged even if the call would never emit them in that
// arrangement. Being told about a call that spells out a DynamoDB expression in
// pieces is the correct outcome even when the pieces are innocent, and the
// alternative -- a refusal that silently passes -- is the bug this exists to fix.
func (r IdiomRule) assemblableNeedle(fragments []string) (Needle, bool) {
	if len(fragments) == 0 {
		return Needle{}, false
	}
	masked := make([]string, len(fragments))
	for i, f := range fragments {
		masked[i] = r.mask(f)
	}
	for _, needle := range r.Needles {
		// A MatchToken needle is deliberately not run through this net. The net
		// asks whether fragments could tile the needle in any order, and what sits
		// either side of the result is a runtime value it cannot see -- so the
		// delimiter test that makes a two-character needle mean anything cannot be
		// applied, and "c1" would then be assemblable from any pair of fragments
		// ending in "c" and beginning with "1". That is not a check.
		//
		// It costs less than it looks. The exact folder still evaluates "c" + "1"
		// and a constant fmt.Sprintf to the value they produce, and matches it with
		// the delimiter test intact; only an *inexactly* modelled call hides a
		// two-character id, and hiding one that way is not ordinary convenience.
		// The long needles -- conductorone, APPHUB_C1_ -- are the ones assembly
		// plausibly hides, and they are all still in the net.
		if needle.Match == MatchToken {
			continue
		}
		fold := needle.Fold
		text := needle.Text
		if fold {
			text = strings.ToLower(text)
		}
		if assemblable(text, foldFragments(masked, fold)) {
			return needle, true
		}
	}
	return Needle{}, false
}

// foldFragments lowercases fragments when a needle is case-insensitive, so the
// tiling below compares the same alphabet the needle does.
func foldFragments(fragments []string, fold bool) []string {
	if !fold {
		return fragments
	}
	out := make([]string, len(fragments))
	for i, f := range fragments {
		out[i] = strings.ToLower(f)
	}
	return out
}

func assemblable(needle string, fragments []string) bool {
	// A fragment containing the whole needle needs no assembly.
	for _, f := range fragments {
		if strings.Contains(f, needle) {
			return true
		}
	}

	// reached[i] means "the needle's first i bytes can be produced".
	reached := make([]bool, len(needle)+1)
	// Seed: some fragment ends with a non-empty prefix of the needle, which is the
	// boundary the needle straddles.
	for _, f := range fragments {
		for i := 1; i <= len(needle) && i <= len(f); i++ {
			if strings.HasSuffix(f, needle[:i]) {
				reached[i] = true
			}
		}
	}

	for i := 1; i < len(needle); i++ {
		if !reached[i] {
			continue
		}
		rest := needle[i:]
		for _, f := range fragments {
			switch {
			case strings.HasPrefix(rest, f):
				// The fragment is consumed whole and the needle continues.
				reached[i+len(f)] = true
			case strings.HasPrefix(f, rest):
				// The fragment covers the remainder, with anything after it
				// harmless trailing context.
				return true
			}
		}
	}
	return reached[len(needle)]
}

// foldFormatCall expands a constant formatting call exactly, or reports that it
// could not.
//
// Matched on the written callee (fmt.Sprintf) rather than a resolved symbol,
// which is the same trade-off the import rule makes: it is what a reader sees,
// and an alias contrived to evade it is no longer ordinary Go.
//
// The second return value is the whole discipline here. This function evaluates
// a small language, and review found the first version silently mis-evaluating a
// corner of it -- indexed directives, which are not sequential. A folder that
// returns a confident wrong answer is worse than one that declines, because the
// wrong answer is what gets matched against. So anything not modelled below
// returns false, and the conservative net in constantFragments is what still
// looks at the pieces.
//
// What true means, precisely: every directive's *argument selection* was
// modelled. It does not promise a byte-identical copy of fmt's output -- width
// padding is dropped and an unknown verb's error decoration is not reproduced.
// Both omissions can only join fragments fmt would have separated, so they risk a
// false positive rather than a miss, and no needle contains a space anyway. See
// TestRenderingIsNotByteIdentical.
func foldFormatCall(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}

	switch {
	case pkg.Name == "fmt" && sel.Sel.Name == "Sprintf":
		if len(call.Args) == 0 {
			return "", false
		}
		format, ok := foldConstString(call.Args[0])
		if !ok {
			return "", false
		}
		return expandFormat(format, call.Args[1:])

	case pkg.Name == "fmt" && sel.Sel.Name == "Sprint":
		// Sprint concatenates its operands and adds a space between operands when
		// neither side is a string. Only string constants fold here, so the
		// no-space case is the one that can be exact; a non-constant operand
		// becomes an unmatchable placeholder either way.
		return joinArgs(call.Args, "")

	case pkg.Name == "fmt" && sel.Sel.Name == "Sprintln":
		// Sprintln always separates operands with a space and appends a newline.
		// Modelled because it is cheap, and harmless because no needle contains a
		// space -- so it can never assemble one across operands.
		v, exact := joinArgs(call.Args, " ")
		return v + "\n", exact

	case pkg.Name == "strings" && sel.Sel.Name == "Join":
		// The construct that bypassed the fmt-only folder while this finding was
		// being reproduced: strings.Join([]string{"attribute", "_exists(PK)"}, "").
		if len(call.Args) != 2 {
			return "", false
		}
		sep, ok := foldConstString(call.Args[1])
		if !ok {
			return "", false
		}
		lit, ok := call.Args[0].(*ast.CompositeLit)
		if !ok {
			return "", false
		}
		return joinArgs(lit.Elts, sep)

	case pkg.Name == "strings" && sel.Sel.Name == "Repeat":
		if len(call.Args) != 2 {
			return "", false
		}
		unit, ok := foldConstString(call.Args[0])
		if !ok {
			return "", false
		}
		count, ok := constInt(call.Args[1])
		// A bounded repeat only; an enormous count is not worth materialising to
		// decide whether it contains a needle that one copy would already show.
		if !ok || count < 0 || count > 64 {
			return "", false
		}
		return strings.Repeat(unit, count), true
	}
	return "", false
}

// joinArgs folds every operand and joins them with sep.
//
// A non-constant operand becomes unfoldable rather than failing the whole fold:
// that is a correctly-modelled runtime hole, not an unmodelled construct, and NUL
// cannot appear in a needle so it can never complete one by accident.
func joinArgs(args []ast.Expr, sep string) (string, bool) {
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		v, ok := foldConstString(arg)
		if !ok {
			v = unfoldable
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, sep), true
}

func constInt(e ast.Expr) (int, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.Atoi(lit.Value)
	if err != nil {
		return 0, false
	}
	return n, true
}

// expandFormat substitutes constant arguments into a format string.
//
// It is not an implementation of fmt and does not need to be: reassembling the
// string only requires knowing *which argument* each directive consumes, and that
// is a small, closed language. It is enumerated exhaustively below, because the
// bug this replaced came from assuming one of its rules (sequential arguments)
// held universally.
//
// The directive grammar, and how each part is handled:
//
//	%%              literal percent, consumes nothing
//	flags   + - # space 0    consume nothing
//	%[n]v           explicit argument index; the next argument becomes n
//	width   123     consumes nothing
//	width   *       consumes one argument (and discards it)
//	prec    .123    consumes nothing
//	prec    .*      consumes one argument (and discards it)
//	verb    any     consumes one argument
//
// Anything outside that grammar -- a truncated directive, an out-of-range index,
// an index appearing after the width as in %[1]*[2]d -- returns exact=false
// rather than a guess. A runtime (non-constant) argument is different: that is a
// hole the grammar models perfectly well, so it stays exact and contributes an
// unmatchable placeholder.
func expandFormat(format string, args []ast.Expr) (string, bool) {
	var b strings.Builder
	next := 0
	exact := true

	// consume takes the argument at next, advancing it. Out of range is fmt's
	// %!s(MISSING), which is a mistake in the source rather than something to
	// model.
	consume := func() string {
		if next < 0 || next >= len(args) {
			exact = false
			return unfoldable
		}
		v, ok := foldConstString(args[next])
		next++
		if !ok {
			return unfoldable
		}
		return v
	}
	digits := func(i int) int {
		for i < len(format) && format[i] >= '0' && format[i] <= '9' {
			i++
		}
		return i
	}

	// One directive per iteration. Within a directive, flags / an explicit index /
	// width / precision may appear in more than one order -- fmt accepts both
	// %[2]*[1]d and %*[2]d -- so they are accepted in any order until a verb byte
	// turns up, rather than encoding a positional grammar that would be one more
	// thing to get subtly wrong. Accepting an arrangement fmt would reject is the
	// safe direction: it can only cause a spurious fold of an expression that never
	// compiles cleanly anyway.
	for i := 0; i < len(format) && exact; {
		if format[i] != '%' {
			b.WriteByte(format[i])
			i++
			continue
		}
		i++
		if i >= len(format) {
			exact = false
			break
		}
		if format[i] == '%' {
			b.WriteByte('%')
			i++
			continue
		}

		verb := byte(0)
		for i < len(format) {
			c := format[i]
			switch {
			case strings.IndexByte("+-# 0", c) >= 0:
				// A flag. Consumes nothing.
				i++

			case c == '[':
				// An explicit operand index. This is what makes a directive
				// non-sequential, and missing it was the first bypass; allowing it
				// only before the width was the second.
				j := digits(i + 1)
				if j == i+1 || j >= len(format) || format[j] != ']' {
					exact = false
				} else if n, err := strconv.Atoi(format[i+1 : j]); err != nil || n < 1 {
					exact = false
				} else {
					next = n - 1
					i = j + 1
				}

			case c == '*':
				// Width taken from an operand: it consumes one of its own.
				consume()
				i++

			case c == '.':
				i++
				if i < len(format) && format[i] == '*' {
					consume()
					i++
				} else {
					i = digits(i)
				}

			case c >= '0' && c <= '9':
				i = digits(i)

			default:
				verb = c
				i++
			}
			if verb != 0 || !exact {
				break
			}
		}
		if !exact {
			break
		}
		if verb == 0 {
			// Ran off the end of the format without finding a verb.
			exact = false
			break
		}
		// Every verb consumes exactly one operand, including ones fmt does not
		// recognise -- an unknown verb still eats its operand.
		b.WriteString(consume())
	}

	if !exact {
		return "", false
	}
	return b.String(), true
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// SourcesFrom reads the contents of the Go files a scan already selected.
//
// It contains no directory rules, and that absence is the point.
//
// Deciding which directories the go command would expand is a rule this
// repository has now got wrong twice, in opposite directions: a walker that
// skipped `node_modules`, which `go build ./...` compiles like any other
// package, and a walker that skipped every directory named `vendor`, when Go
// only excludes descendants beneath a vendor path segment -- so `cmd/vendor` is
// a real package. Both were hand-written restatements of somebody else's rules.
//
// A third copy here would be a third divergence waiting for its own review, so
// the selection is taken from ScanFiles -- the same list the import half of the
// check already judges. One definition, one place to fix, and this rule inherits
// the fix without being touched. All that happens here is reading bytes.
//
// The consequence worth stating plainly: while ScanFiles skips a directory the
// toolchain builds, this rule is blind there too. That is a real gap and it is
// deliberately not patched locally (USOSS-28 owns the predicate). Sharing one
// wrong answer that gets fixed once beats maintaining two.
func SourcesFrom(root string, scanned []FileImports) ([]SourceFile, error) {
	out := make([]SourceFile, 0, len(scanned))
	seen := make(map[string]struct{}, len(scanned))
	for _, f := range scanned {
		if f.File == "" {
			continue
		}
		// A scan reports test files alongside their package, and an external test
		// file shares neither. Reading each path once is enough.
		if _, dup := seen[f.File]; dup {
			continue
		}
		seen[f.File] = struct{}{}

		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.File))) //nolint:gosec // path comes from the scan of the repository being checked
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f.File, err)
		}
		out = append(out, SourceFile{Path: f.File, Content: content})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
