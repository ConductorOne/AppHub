// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package astaudit derives the USOSS-6 source-claim evidence table from the Go
// AST of the the source tree, and refuses to report success unless it
// derived every row the table claims.
//
// It exists because five separate defect classes on this port have been
// documentation rather than code, and each fix was aimed one level below the
// shape of the failure. The three contracts below are the three levels the tool
// has been holed at, in the order they were found.
//
// # 1. The derivation contract
//
// Every row is computed from go/ast, not from a text search, because one
// failure this tool exists to stop is a regex whose boundary does not match the
// semantic category the claim names: go/ast can tell an integer literal from an
// expression that merely begins with digits, an import from a commented-out
// one, a discarded call result from a checked one, and a go statement from the
// word "go" in a string. A regex can tell none of those.
//
// # 2. The completeness contract
//
// A derivation that returns nothing passes every check over it. Pointed at a
// path that did not exist, the first version of this tool printed a full,
// internally consistent table of 0 / 0 rows and exited 0. Given one production
// file that would not parse, it printed the parse error, dropped that file from
// every denominator, and exited 0 with a table that looked exactly like a
// correct one.
//
// A 0 / 0 row is not a count. It is the absence of a count wearing a count's
// clothes, and it is indistinguishable from a true zero unless something asserts
// otherwise. So the tool fails closed, per population rather than globally: the
// root must exist and be a directory; a filepath.Walk error is fatal; a parse
// error on a production file is fatal, so a file is never dropped from a
// denominator it belongs in; every population asserts non-emptiness at
// construction; and a row refuses a zero denominator. A numerator of zero is
// fine and expected -- several rows legitimately are zero. It is the
// denominator that carries the completeness claim.
//
// If a population ever is legitimately empty, that is a fact about the source
// worth stating, so the tool must be edited to say so. There is deliberately no
// flag for it.
//
// # 3. The traversal contract
//
// The contract above was still too narrow, because it assumed the only ways a
// walk can be incomplete are the ways it reports. Review then symlinked a
// directory containing a malformed file under internal/modules, and the tool
// exited 0 with the same table as before -- while printing, in its own summary
// line, that every population had been parsed in full. filepath.Walk uses Lstat
// and does not follow symlinks, so a symlinked subtree is not an error; it
// simply is not there. Absence that does not announce itself.
//
// So the contract is "I traversed everything, or I failed", derived from
// enumerating the states that make a traversal incomplete without erroring:
//
//   - A symlinked directory is never descended into, silently. Refused, naming
//     the link and its target. Refusing beats following: a symlink inside a Go
//     source tree is unusual enough that a human should look at it, and
//     following one needs cycle detection that is itself a place to be wrong.
//   - A symlinked file would be parsed, but its target can live outside the
//     population being counted, so the count would not mean what it says.
//     Refused for the same reason.
//   - A non-regular entry -- FIFO, socket, device -- named *.go would make the
//     parser block or fail for reasons unrelated to Go syntax. Refused.
//   - Concurrent modification: a file created after its parent directory was
//     read is silently absent. Guarded by traversing twice and requiring the two
//     path sets to be identical, which turns a race into a failure.
//   - A permission or stat error is fatal.
//   - filepath.SkipDir would prune a subtree silently. Nothing here returns it,
//     and that is load-bearing rather than incidental.
//
// Two states are deliberately not treated as incompleteness, because they are
// not: crossing a mount boundary, which Walk traverses normally, and including
// directories Go's own build rules would ignore (_foo, .foo). The population is
// defined by the .go suffix rather than by what the toolchain would compile,
// which can only make a denominator larger than go/build's, never smaller -- so
// it cannot hide anything, and it is stated rather than fixed.
//
// # 4. The row-set contract
//
// The contract above still only covered the populations. Nothing covered the
// rows. The tool printed "audit complete: 29 rows" while asserting nothing about
// which rows: five of the evidence table's rows were never derived at all, and
// deleting an emit call reported a smaller number and still exited 0. A count of
// rows is not a check on the row set, exactly as a count that runs without error
// is not a count of the right population.
//
// This is contract lesson 7 -- a hand-maintained restatement of a set drifts
// from the set -- so a []string of row IDs inside this package would be the same
// defect one level out. Instead the required set is parsed out of the evidence
// table in the report document itself and the tool requires a bijection: every
// row ID in the document is emitted exactly once, and every row emitted is a row
// ID in the document. A missing row, a duplicated row, and a row the document
// does not have are each fatal and named.
//
// Both sides are asserted non-empty, because a derivation returning nothing
// passes every check over it -- including this one.
//
// The bijection is between report rows and emitted rows, not between report rows
// and printed numbers. A row whose claim carries several figures (E17 counts
// files and packages; E24 partitions its population four ways) emits one row
// carrying several facts, so the mapping needs no table to state it and no table
// to drift.
//
// # 5. The table is generated, and nothing is parsed
//
// Contracts 1-4 left one artefact reading another: the row set, the figures and
// the pointer into the code all lived in a Markdown table that this package read
// back. Each round detected the drift between the two more cleverly -- pin the
// row IDs, compare the values, check the pointer, classify every table, fix the
// fence grammar -- and each round a reader found another way for a row to be
// visible in the rendered document and invisible to the parser:
//
//  1. the row set was not pinned at all;
//  2. `_E99_` -- Markdown emphasis, stripped by a known-decoration list, and any
//     cell the list did not recognise was silently skipped;
//  3. backticks in the "Derived by" column, in the fix for 2, ninety seconds
//     after it was written;
//  4. a four-space-indented fence marker, which opens no fence in Markdown but
//     opened one in the scanner, hiding every table after it;
//  5. an info string containing a backtick, which is not a valid fence opener --
//     in the function written to close 4, in the same change.
//
// Five reproductions of one class, four of them in the Markdown scanner, two
// inside the fix for the previous one. The answer is not a better scanner, and
// not a Markdown parser either: a parser is the same bet one level up, that
// someone else's CommonMark agrees with the renderer a human is actually
// reading.
//
// So the table is **generated** from the declaration in evidence.go, and this
// package parses nothing. There is one artefact, so there is no drift to detect.
//
// What that costs, and how it is paid: generating the table would make "every
// row was derived" vacuous, because the table would be whatever the tool
// printed -- reopening contract 4 through the front door. So the emissions are
// still held to the declaration: every declared row derived exactly once, and
// nothing derived that is not declared. A declaration that nothing else restates
// is not the hand-maintained restatement rule 7 warns about; rule 7 is about two
// artefacts drifting, and this is one.
//
// The only check over the generated document is [Options.Check], a byte
// comparison against a freshly generated copy. It catches a stale committed
// artefact, and it is the one check that cannot have the failure above: there is
// nothing to parse, so there is no grammar to disagree with a renderer about.
//
// # 6. What is left, and what it is bounded by
//
// Stated here so the package does not read as a complete gate. A gate that
// overstates itself is the defect this whole tool has been about.
//
//   - **The audit does not run in CI, and cannot.** Twenty-nine of its thirty
//     rows are claims about a source repository CI does not have. What CI gates
//     is this package's hermetic test suite; a human runs the audit. Note that
//     the reason usually given -- that referencing the source repository would
//     disclose it -- is already false of this repository, which names it in
//     docs/DECISIONS.md; the real obstacle is that the tree is not there.
//   - **Claim and How are prose.** Nothing can verify that the sentence beside
//     E7 describes what the code computes. They are carried through verbatim
//     from the declaration, attached to their row by construction rather than by
//     a lookup that could miss, and an empty one is fatal -- so a row without
//     prose is a visible hole rather than a silent one. That is all they are.
//   - **The figures and the deriving function are emitted, not compared.** With
//     one artefact there is nothing to compare against; the value comparison and
//     the pointer check that earlier rounds added were drift detectors for a
//     second artefact that no longer exists. The property is stronger, not
//     weaker.
package astaudit
