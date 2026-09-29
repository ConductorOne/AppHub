// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/fake"
	"github.com/conductorone/apphub/compute/k8s"
	"github.com/conductorone/apphub/compute/matrix"
)

// update regenerates the committed matrix document instead of comparing against
// it. Run: go test ./compute/k8s -run TestCapabilityMatrixDocument -update
var update = flag.Bool("update", false,
	"rewrite docs/design/capability-matrix.md from the providers rather than checking it")

// matrixDocument is the committed artifact this test owns.
const matrixDocument = "docs/design/capability-matrix.md"

// TestCapabilityMatrixDocument is the anti-drift mechanism for the published
// capability matrix, which USOSS-20 needs.
//
// # Why the document is generated and checked rather than written
//
// "Which capabilities does each provider support" is a factual claim about code,
// and five separate defect classes on this project have been a document that
// stopped agreeing with the thing it described. A hand-written table is
// unfalsifiable after the day it is written; this one is derived from the
// providers on every test run and compared byte for byte with what is committed,
// so a provider whose capabilities change turns the build red and the fix is to
// regenerate.
//
// # What is in it, and what is deliberately not
//
// Every provider that exists today with something to say: compute/fake,
// compute/aws over its in-memory substrate, and compute/k8s in both of the
// configurations its own conformance suite runs -- because a Kubernetes
// provider's capability set is mostly a fact about what else the operator
// installed, so one column would misrepresent it.
//
// # Probing is on
//
// Options.ProbePorts calls every method of every port with zero-valued
// arguments, so a port that exists and refuses everything is reported as a stub
// rather than as available. Both providers here are pointed at in-memory
// substrates created by this test, so there is nothing to damage. That condition
// is the reason probing is opt-in — see the package documentation.
func TestCapabilityMatrixDocument(t *testing.T) {
	// Not parallel: it may write a file in the repository.

	rendered, err := renderMatrix(t)
	if err != nil {
		t.Fatalf("rendering the matrix: %v", err)
	}

	path := repoPath(t, matrixDocument)
	if *update {
		if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
			t.Fatalf("writing %s: %v", matrixDocument, err)
		}
		t.Logf("rewrote %s", matrixDocument)
		return
	}

	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v\nRun: go test ./compute/matrix -run "+
			"TestCapabilityMatrixDocument -update", matrixDocument, err)
	}
	if string(committed) == rendered {
		return
	}
	t.Errorf("%s does not match what the providers report.\n\n"+
		"This is the document drifting from the code, which is the defect class this test "+
		"exists for. Regenerate it:\n\n    go test ./compute/matrix -run "+
		"TestCapabilityMatrixDocument -update\n\nThen read the diff: a capability that changed "+
		"is either the change you intended or a regression.\n\nfirst difference at %s",
		matrixDocument, firstDifference(string(committed), rendered))
}

// TestTheMatrixDocumentIsNotEmptyOrUniform is the emptiness gate on the
// generated artifact.
//
// A derivation that produced nothing would render as a table of providers that
// support nothing, and the byte comparison above would happily accept it as long
// as the committed file said the same. So the content is checked for the two ways
// it could be uniformly wrong: no rows at all, and every answer the same.
func TestTheMatrixDocumentIsNotEmptyOrUniform(t *testing.T) {
	t.Parallel()

	rendered, err := renderMatrix(t)
	if err != nil {
		t.Fatalf("rendering the matrix: %v", err)
	}
	yes := strings.Count(rendered, "| yes") + strings.Count(rendered, " yes |")
	no := strings.Count(rendered, "| no") + strings.Count(rendered, " no |")
	if yes == 0 {
		t.Error("no provider supports any capability in the rendered matrix; the derivation " +
			"produced an empty answer that looks like a complete one")
	}
	if no == 0 {
		t.Error("no provider lacks any capability in the rendered matrix; a matrix where " +
			"everything is supported is the other way this can be uniformly wrong, and it would " +
			"tell a reader there is nothing to check")
	}
	for _, want := range []string{"declined", "available"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("no port in the rendered matrix is %q; the port axis is not distinguishing "+
				"anything", want)
		}
	}
	if strings.Contains(rendered, "**partial**") {
		t.Error("a port in the rendered matrix is partial: its accessor succeeded and some of " +
			"its methods refuse. That is not something to publish as a capability, and " +
			"USOSS-20's documentation consumes this table")
	}
	if strings.Contains(rendered, "**stub**") {
		t.Error("a port in the rendered matrix is a stub: it exists, it was handed out, and " +
			"every one of its methods refuses. That is the failure mode compute.Provider's " +
			"accessor-returns-an-error design exists to prevent, and it must be fixed rather " +
			"than published")
	}
	if strings.Contains(rendered, "**unknown**") {
		t.Error("a port in the rendered matrix is unknown: its accessor returned neither a " +
			"usable port nor a compute.ErrUnsupported refusal, which is a provider bug")
	}
}

// renderMatrix derives every provider's matrix and renders the document.
func renderMatrix(t *testing.T) (string, error) {
	t.Helper()
	ctx := context.Background()

	var matrices []*matrix.Matrix
	for _, p := range providers(t) {
		m, err := matrix.Derive(ctx, p, matrix.Options{ProbePorts: true})
		if err != nil {
			return "", err
		}
		matrices = append(matrices, m)
	}
	table, err := matrix.Markdown(matrices...)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(matrixPreamble)
	b.WriteString(table)
	b.WriteString(backingDisclosure())
	b.WriteString(matrixPostamble)
	return b.String(), nil
}

// backingDisclosure names the concrete types behind the Kubernetes columns.
//
// # Why this is generated rather than written
//
// A reviewer's should-fix, and it is a real one: the Kubernetes columns report
// Registry and Builder as available, and this repository deliberately ships no
// registry client. "Available" means the provider logic works when an operator
// supplies the whole backing seam — it does not mean a production assembly exists
// here. Left implicit, the column reads as capability when it is scaffolding.
//
// The disclosure is derived from the substrate this function actually built, with
// %T, rather than asserted in prose. If somebody swaps a memory implementation for
// a real one the sentence changes with it, and if somebody adds a fourth seam it
// appears. A hand-written note would have gone stale the first time either
// happened — which is the whole reason this document is generated.
func backingDisclosure() string {
	sub := newSubstrate(matrixFullCluster())
	return fmt.Sprintf(`
### What "available" means for the Kubernetes columns

The Kubernetes columns are derived from a provider assembled over these
implementations:

| Seam | Implementation behind these columns |
| --- | --- |
| `+"`Cluster`"+` | `+"`%T`"+` |
| `+"`Registry`"+` | `+"`%T`"+` |
| `+"`ObjectStore`"+` | `+"`%T`"+` |

Read `+"`available`"+` in those columns as **"the provider's translation for this port
is complete and conformant when an operator supplies a working implementation of
the seam behind it"** — not as "this repository contains a production assembly for
it". The distinction matters most for `+"`Registry`"+` and `+"`Builder`"+`: every obligation
`+"`compute.ImageRegistry`"+` has beyond pull and push is a vendor control-plane API,
four vendors express them four ways, and this repository deliberately ships no
client for any of them. An operator running Kubernetes supplies that seam, or those
two columns describe nothing they can deploy.

`+"`ClientCluster`"+` and `+"`S3ObjectStore`"+` are shipped, so the `+"`Cluster`"+` and
`+"`ObjectStore`"+` seams have real implementations available even though the table
above is generated over the in-memory ones — the in-memory substrate is what keeps
generating this document hermetic.
`, sub.Cluster, sub.Registry, sub.Objects)
}

// providers returns one provider per column, in column order.
//
// Every one is constructed over a substrate this function creates, so probing
// them mutates nothing that outlives the test.
func providers(t *testing.T) []compute.Provider {
	t.Helper()
	return []compute.Provider{
		fake.New(fake.NewStore(), fake.Config{Name: "fake"}),
		k8s.New(newSubstrate(matrixFullCluster()), matrixFullCluster()),
		k8s.New(newSubstrate(matrixPlainCluster()), matrixPlainCluster()),
	}
}

// matrixFullCluster and matrixPlainCluster are this package's own conformance
// configurations, with the provider names the published matrix uses as column
// headings.
//
// They are the suite's configurations rather than new ones on purpose: a matrix
// derived from a configuration nothing else exercises would describe a provider
// nobody has tested.
func matrixFullCluster() k8s.Config {
	cfg := fullConfig()
	cfg.Name = "kubernetes"
	return cfg
}

func matrixPlainCluster() k8s.Config {
	cfg := ingressOnlyConfig()
	cfg.Name = "kubernetes-plain"
	cfg.IngressProxy = k8s.PodSelector{}
	cfg.KubeletCredentialProvider = false
	return cfg
}

// repoPath resolves a repository-relative path from this test's own source
// location, so it does not depend on the working directory.
func repoPath(t *testing.T, rel string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test's source file")
	}
	// .../compute/matrix/document_test.go -> repository root
	root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("%s does not look like the repository root (no go.mod): %v", root, err)
	}
	return filepath.Join(root, filepath.FromSlash(rel))
}

// firstDifference describes where two documents diverge, by line, so a failure
// message points at the change rather than at two whole documents.
func firstDifference(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := range max(len(al), len(bl)) {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return "line " + itoa(i+1) + ":\n  committed: " + x + "\n  derived:   " + y
		}
	}
	return "nowhere (the documents are equal, so this message is a bug)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

const matrixPreamble = `<!--
GENERATED FILE. Do not edit.

Produced by TestCapabilityMatrixDocument in compute/k8s/matrixdoc_test.go, which
derives every row from the providers themselves and fails if this file disagrees.
Regenerate with:

    go test ./compute/k8s -run TestCapabilityMatrixDocument -update
-->

# Compute provider capability matrix

Which capabilities each provider supports, and what each of its ports does. Every
row is derived from the provider at test time rather than written down, because a
table about code that nothing checks stops being true.

## How to read it

**Capabilities** are what ` + "`Provider.Capabilities()`" + ` reports. A capability is a whole port
or a whole class of behaviour a substrate may structurally lack; it is not a flag
for a knob on a spec.

**Ports** are the accessors on ` + "`compute.Provider`" + `. Each is one of:

| Value | Meaning |
| --- | --- |
| ` + "`available`" + ` | The accessor succeeded and no probed method refused. **This is negative evidence, not positive**: a zero-argument probe can show that a port refuses and cannot show that a port works, because the one input it can construct is the input a well-written port rejects on validation grounds. Driving a port with real specifications is ` + "`compute/conformance`" + `'s job, not this table's. |
| ` + "`declined (cap)`" + ` | The accessor refuses at acquisition with ` + "`compute.ErrUnsupported`" + `, naming the capability. A caller discovers this **before** calling anything. |
| ` + "`stub`" + ` | The accessor returns a port whose every probed method refuses. This is a defect, not a configuration: the refusal has moved from acquisition to call time. Nothing should ever be published in this state. |
| ` + "`partial`" + ` | Some but not all of the port's probed methods refuse. Not necessarily a defect, but never a capability claim — the port is not usable as a whole. |
| ` + "`unknown`" + ` | The accessor returned neither a port nor a typed refusal. A provider bug. |

The Kubernetes provider appears twice on purpose. Almost every capability it has
is a fact about what an operator installed *beside* the cluster — a registry, a
builder, an object store, a Postgres operator, the Gateway API — so a single
column would describe one deployment and misrepresent the rest. **kubernetes** is
a cluster with all of them; **kubernetes-plain** is a cluster with none.

`

const matrixPostamble = `
## Matrix scope

This table covers provider configurations that can be constructed without cloud
credentials or live infrastructure.

**Anything a capability does not cover.** A provider can support a capability and
still refuse a particular specification — an unknown engine version, a placement
it has no configuration for, a retention policy its registry cannot apply. Those
are ` + "`compute.ErrInvalidSpec`" + ` and ` + "`compute.ErrUnsupported`" + ` on the call, not entries here.
This table answers "can this provider do this at all", which is the question a
caller can act on before it starts.
`
