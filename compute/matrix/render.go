// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package matrix

import (
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
)

// Markdown renders one or more matrices as two Markdown tables — one row per
// capability, one row per port — with a column per provider.
//
// This is the artifact USOSS-20 needs. It is generated rather than written so
// that the published table cannot drift from the providers it describes: the
// documentation job is to run this and commit the output, and a provider whose
// capabilities changed shows up as a diff.
//
// It returns an error rather than an empty document when handed nothing, or when
// a matrix's own populations are empty. A table with no rows published as "what
// our providers support" reads as "nothing", and that has already happened on
// this project: an auditor emitted a complete, internally consistent table
// derived from a tree it had only partly traversed.
func Markdown(matrices ...*Matrix) (string, error) {
	if len(matrices) == 0 {
		return "", fmt.Errorf("%w: no matrix was supplied to render", errNothingDerived)
	}
	names := make([]string, 0, len(matrices))
	for i, m := range matrices {
		switch {
		case m == nil:
			return "", fmt.Errorf("%w: matrix %d is nil", errNothingDerived, i)
		case len(m.Capabilities) == 0:
			return "", fmt.Errorf("%w: provider %q has no capability rows", errNothingDerived, m.Provider)
		case len(m.Ports) == 0:
			return "", fmt.Errorf("%w: provider %q has no port rows", errNothingDerived, m.Provider)
		case m.Provider == "":
			return "", fmt.Errorf("%w: matrix %d names no provider", errNothingDerived, i)
		}
		names = append(names, m.Provider)
	}
	if dup := firstDuplicate(names); dup != "" {
		return "", fmt.Errorf("%w: two matrices both name provider %q, so one column would "+
			"silently overwrite the other", errNothingDerived, dup)
	}

	var b strings.Builder
	b.WriteString("### Capabilities\n\n")
	writeRow(&b, append([]string{"Capability"}, names...))
	writeRule(&b, len(names)+1)
	for _, c := range unionCapabilities(matrices) {
		cells := []string{"`" + string(c) + "`"}
		for _, m := range matrices {
			cells = append(cells, capabilityCell(m, c))
		}
		writeRow(&b, cells)
	}

	b.WriteString("\n### Ports\n\n")
	writeRow(&b, append([]string{"Accessor", "Port"}, names...))
	writeRule(&b, len(names)+2)
	for _, a := range unionAccessors(matrices) {
		cells := []string{"`" + a.accessor + "`", "`" + a.iface + "`"}
		for _, m := range matrices {
			cells = append(cells, portCell(m, a.accessor))
		}
		writeRow(&b, cells)
	}
	return b.String(), nil
}

// unionCapabilities is every capability any matrix mentions, in
// [compute.AllCapabilities] order, with anything unexpected appended so a
// capability a matrix carries and the population does not cannot be dropped.
func unionCapabilities(matrices []*Matrix) []compute.Capability {
	seen := map[compute.Capability]bool{}
	var out []compute.Capability
	for _, c := range compute.AllCapabilities() {
		seen[c] = true
		out = append(out, c)
	}
	var extra []compute.Capability
	for _, m := range matrices {
		for _, row := range m.Capabilities {
			if !seen[row.Capability] {
				seen[row.Capability] = true
				extra = append(extra, row.Capability)
			}
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
	return append(out, extra...)
}

type accessorKey struct{ accessor, iface string }

// unionAccessors is every accessor any matrix mentions, sorted.
func unionAccessors(matrices []*Matrix) []accessorKey {
	seen := map[string]accessorKey{}
	for _, m := range matrices {
		for _, p := range m.Ports {
			seen[p.Accessor] = accessorKey{accessor: p.Accessor, iface: p.Interface}
		}
	}
	out := make([]accessorKey, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].accessor < out[j].accessor })
	return out
}

func capabilityCell(m *Matrix, c compute.Capability) string {
	for _, row := range m.Capabilities {
		if row.Capability != c {
			continue
		}
		if row.Present {
			return "yes"
		}
		return "no"
	}
	// The matrix does not carry this capability at all, which is different from
	// carrying it as absent: it means the two were derived against different
	// versions of the population.
	return "—"
}

func portCell(m *Matrix, accessor string) string {
	for _, p := range m.Ports {
		if p.Accessor != accessor {
			continue
		}
		switch p.Support {
		case SupportAvailable:
			return "available"
		case SupportDeclined:
			if p.Capability != "" {
				return "declined (`" + string(p.Capability) + "`)"
			}
			return "declined"
		case SupportStub:
			return "**stub**"
		case SupportPartial:
			return "**partial**"
		default:
			return "**" + string(p.Support) + "**"
		}
	}
	return "—"
}

func writeRow(b *strings.Builder, cells []string) {
	b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
}

func writeRule(b *strings.Builder, columns int) {
	cells := make([]string, columns)
	for i := range cells {
		cells[i] = "---"
	}
	writeRow(b, cells)
}

func firstDuplicate(values []string) string {
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] {
			return v
		}
		seen[v] = true
	}
	return ""
}
