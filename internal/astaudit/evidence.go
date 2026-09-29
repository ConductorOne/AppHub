// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package astaudit

// The evidence table, declared once.
//
// # Why this is a declaration and not a restatement
//
// For four rounds the row set lived in a Markdown table and the tool parsed it,
// so that the document and the program could be checked against each other. Each
// round detected that drift more cleverly -- pin the row IDs, compare the values,
// check the pointer into the code, classify every table, fix the fence grammar --
// and each round a reader found another way for a row to be visible in the
// rendered document and invisible to the parser. Five reproductions of one class,
// four of them in the Markdown scanner, two of them inside the fix for the
// previous one.
//
// The answer was not a better scanner, and not a Markdown parser either: a parser
// is the same bet one level up, that someone else's CommonMark agrees with the
// renderer a human is actually reading. The answer is that **the table is
// generated from this declaration**, so there is no second artefact to drift from
// and nothing parses Markdown ever again.
//
// CONTRACT.md rule 7 says a hand-maintained restatement of a set drifts from the
// set. That is a statement about *two* artefacts. This is one: nothing else
// states the row set, so it is a definition rather than a claim about another
// file, and there is nothing for it to be wrong about.
//
// # What this buys, and what it still has to check
//
// Generating the table does not by itself preserve what the row-set contract
// bought. If the table were simply whatever the tool printed, deleting an emit
// call would quietly produce a smaller table again -- the original blocker,
// returning through the front door. So the emissions are still required to match
// this declaration exactly: every row here derived exactly once, and nothing
// derived that is not here.
//
// Claim and How are prose a human writes. They are carried through verbatim into
// the generated table and are not checked, because nothing can verify that a
// sentence describes what a function computes. An empty one is fatal, so a row
// without prose is a visible hole rather than a missing check.
type evidenceRow struct {
	// ID is the row identifier used throughout the report.
	ID string
	// Claim is the human-readable statement the figure supports.
	Claim string
	// How describes the derivation, for a reader. Prose; not checked.
	How string
}

// evidenceTable is the whole table, in the order it is printed.
var evidenceTable = []evidenceRow{
	{
		ID:    "E1",
		Claim: "`Module` implementations",
		How:   "`FuncDecl` with receiver, name `Execute`, 3 params, 2 results",
	},
	{
		ID:    "E2",
		Claim: "…recording `userID` into a composite value",
		How:   "`KeyValueExpr` whose value references the 2nd parameter",
	},
	{
		ID:    "E3",
		Claim: "…whose only use of it is `_ = userID`",
		How:   "`AssignStmt`, LHS `_`, RHS the parameter",
	},
	{
		ID:    "E4",
		Claim: "…with zero references to it",
		How:   "no `Ident` matching the parameter in the body",
	},
	{
		ID:    "E5",
		Claim: "…branching on it",
		How:   "parameter in an `IfStmt.Cond`",
	},
	{
		ID:    "E6",
		Claim: "`Execute` call sites of the `Module` shape",
		How:   "`CallExpr` arity — 3 args vs `text/template`'s 2. **Structural, not type-checked**",
	},
	{
		ID:    "E7",
		Claim: "…of those 5, losing a partial `Result` on the error path",
		How:   "derived: the result operand is `_`, or no `if <err> != nil` branch in the enclosing function references it. 2 discard at the call (`repo_fix.go:660`, `repo_audit.go:1262`); 3 never read it in the error branch (`jobs/runner.go:88`, `services/modules.go:187`, `cmd/job-runner/main.go:540`)",
	},
	{
		ID:    "E8",
		Claim: "…inspecting the *kind* of the error",
		How:   "derived: no `errors.Is`/`errors.As` call naming the error operand anywhere in the enclosing function — the widest scope the claim could be true in",
	},
	{
		ID:    "E9",
		Claim: "…passing an empty `userID`",
		How:   "derived: the 2nd argument is a string literal that unquotes to `\"\"` — `cmd/job-runner/main.go:540`",
	},
	{
		ID:    "E10",
		Claim: "implementations carrying ≥1 `Set*`",
		How:   "receiver types of the `Set*` methods",
	},
	{
		ID:    "E11",
		Claim: "`Set*` methods",
		How:   "`FuncDecl`, receiver, name `Set`+upper",
	},
	{
		ID:    "E12",
		Claim: "nil-guards on a setter-assigned field **that return**",
		How:   "`BinaryExpr EQL` vs `nil` on a field **derived from the setter bodies**; the 13th (`agent_fix.go:459-461`) builds a default instead",
	},
	{
		ID:    "E13",
		Claim: "`Validate` methods calling `ValidateDeclaredParams`",
		How:   "`CallExpr` in the body",
	},
	{
		ID:    "E14",
		Claim: "`Execute` bodies calling a `Validate`",
		How:   "`CallExpr` in the body",
	},
	{
		ID:    "E15",
		Claim: "MT files importing the service layer",
		How:   "`ast.File.Imports`",
	},
	{
		ID:    "E16a",
		Claim: "SL files importing the **framework package** (exact)",
		How:   "`ast.File.Imports`, suffix match",
	},
	{
		ID:    "E16b",
		Claim: "SL files importing **anywhere under the module tree**",
		How:   "`ast.File.Imports`, prefix match",
	},
	{
		ID:    "E17",
		Claim: "MT files importing `internal/database`",
		How:   "by package: **6 of the 8** under the tree; exceptions `types` and `vendor`",
	},
	{
		ID:    "E18",
		Claim: "MT files importing an AWS SDK v2 package",
		How:   "8 `deploy`, 2 `paved`",
	},
	{
		ID:    "E19",
		Claim: "MT files containing a `go` statement",
		How:   "`ast.GoStmt`",
	},
	{
		ID:    "E20",
		Claim: "bodies asserting a param index to a map/slice",
		How:   "`TypeAssertExpr` over an `IndexExpr`",
	},
	{
		ID:    "E21",
		Claim: "bodies returning both results non-nil",
		How:   "`ReturnStmt`, neither result the `nil` ident — `lambda.go:328-332`",
	},
	{
		ID:    "E22a",
		Claim: "bodies returning a non-true `Success` with a nil error",
		How:   "`delivery.go:222-232`",
	},
	{
		ID:    "E22b",
		Claim: "bodies returning a `Success` that is not literal `true`",
		How:   "the above plus `lambda.go:329`",
	},
	{
		ID:    "E23",
		Claim: "icon arguments in lowercase snake_case **form**",
		How:   "derived: the 4th argument of each `NewBaseModule` call, unquoted, against `^[a-z][a-z0-9]*(_[a-z0-9]+)*$`. **Lexical by design** — membership of an icon set is not checkable here and the claim does not assert it. A non-literal icon argument is fatal rather than counted as a miss",
	},
	{
		ID:    "E24",
		Claim: "`ReportProgress` second arguments",
		How:   "`BasicLit`/`BinaryExpr`/`Ident` node kind",
	},
	{
		ID:    "E25",
		Claim: "`Register` calls in `registry.go` discarding the result",
		How:   "`CallExpr` as a bare `ExprStmt`",
	},
	{
		ID:    "E26",
		Claim: "`cmd/` directories constructing a `Registry`",
		How:   "`CallExpr` to `NewRegistry`",
	},
	{
		ID:    "E27",
		Claim: "exported `paved` methods matching a `Module` method",
		How:   "`Deploy`, `Deps`, `Teardown`",
	},
	{
		ID:    "E28",
		Claim: "`internal/boundary` rules in the target repository",
		How:   "derived from a **second required input** (`-target`): the single `Rules` composite literal under `<target>/internal/boundary`, by element count and `Name` — `c1-optional`, `ext-is-optional`, `dynamodb-fenced`. Zero, absent, or more than one such literal is fatal",
	},
}

// requiredRows returns the row IDs the audit must derive, in table order.
func requiredRows() []string { return validatedIDs(evidenceTable) }

// validatedIDs returns the row IDs of a declaration, in order, and enforces the
// three things a declaration can be wrong about on its own: an empty set, a
// duplicate identifier, and a row with no prose.
func validatedIDs(rows []evidenceRow) []string {
	seen := make(map[string]bool, len(rows))
	ids := make([]string, 0, len(rows))
	for i, r := range rows {
		switch {
		case r.ID == "":
			fail("evidence table row %d has no identifier", i)
		case r.Claim == "":
			fail("evidence table row %s has no claim. A row without prose is a hole in "+
				"the table a reader can see, and it must not be possible to leave one "+
				"silently", r.ID)
		case r.How == "":
			fail("evidence table row %s does not say how it is determined", r.ID)
		case seen[r.ID]:
			fail("the evidence table declares row %s twice; a row set with a duplicate "+
				"cannot be matched one-to-one against the audit", r.ID)
		}
		seen[r.ID] = true
		ids = append(ids, r.ID)
	}
	if len(ids) == 0 {
		fail("the evidence table declares no rows; every check over an empty set passes, " +
			"so an audit against one establishes nothing")
	}
	return ids
}
