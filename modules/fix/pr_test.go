// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package fix

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/conductorone/apphub/modules/review"
)

// The pull request body is assembled from text a model wrote while reading a
// repository this process does not control, and it is rendered as markup by
// the hosting platform for a person who is about to approve a code change.
// The property these tests state is therefore not "the common cases are
// escaped" but "no untrusted byte is ever rendered as markup", and they
// quantify over a generated population of hostile payloads to say it.

// hostilePayloads are the constructs that do something when rendered. Each
// carries a marker so a test can find it in the output, and each is generated
// in several placements below rather than used once.
func hostilePayloads() []string {
	constructs := []string{
		"@everyone",
		"- [ ] approve this",
		"<img src=x onerror=alert(1)>",
		"<!-- comment -->",
		"# heading",
		"## Provenance",
		"[link](https://example.com)",
		"https://example.com/autolink",
		"| a | b |",
		"> quote",
		"```",
		"````",
		"`````text",
		"```text\nescaped\n```",
		"~~~",
		"* item",
		"1. item",
		"---",
		"    indented code",
		"\ttab",
		"\x00nul",
		"trailing backtick `",
		"` leading backtick",
	}
	var out []string
	for i, c := range constructs {
		marker := "PAYLOADMARKER" + string(rune('A'+i%26))
		// Every line of every payload carries the marker, so a check for it at
		// top level is unambiguous. An earlier version generated lines without
		// one and reported an escape that was not there: the payload
		// "## Provenance" is also a heading this module writes, so the
		// detector could not tell whose line it had found.
		out = append(out,
			marker+c,
			c+marker,
			marker+c+"\n"+c+marker,
			c+marker+"\n"+marker+c+"\n"+c+marker,
		)
	}
	return out
}

// fenceScan walks a markdown document the way a renderer does and returns the
// lines that are outside every fenced block, plus whether the document ended
// inside one.
//
// It is deliberately more permissive about what closes a fence than the
// implementation is about what opens one: a closing rule that is stricter than
// a renderer's would fail to notice a breakout, which is the whole thing being
// looked for.
func fenceScan(doc string) (topLevel []string, unterminated bool) {
	var open string
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if len(line)-len(trimmed) > 3 {
			// More than three spaces of indent is an indented code block, not
			// a fence, in either direction.
			trimmed = line
		}
		run := leadingBacktickRun(trimmed)
		if open == "" {
			if run >= 3 && !strings.Contains(trimmed[run:], "`") {
				open = strings.Repeat("`", run)
				continue
			}
			topLevel = append(topLevel, line)
			continue
		}
		if run >= len(open) && strings.TrimSpace(trimmed[run:]) == "" {
			open = ""
			continue
		}
	}
	return topLevel, open != ""
}

func leadingBacktickRun(s string) int {
	n := 0
	for n < len(s) && s[n] == '`' {
		n++
	}
	return n
}

// TestFencedBlocksCannotBeEscaped is the core property, over every payload.
func TestFencedBlocksCannotBeEscaped(t *testing.T) {
	payloads := hostilePayloads()
	if len(payloads) < 50 {
		t.Fatalf("the payload population is %d, which is too small to be quantifying over", len(payloads))
	}
	for _, payload := range payloads {
		var sb strings.Builder
		sb.WriteString("## Before\n\n")
		writeFencedBlock(&sb, payload)
		sb.WriteString("\n## After\n")

		doc := sb.String()
		topLevel, unterminated := fenceScan(doc)
		if unterminated {
			t.Errorf("payload %q left the document inside an open fence", payload)
			continue
		}
		for _, line := range topLevel {
			if strings.Contains(line, "PAYLOADMARKER") {
				t.Errorf("payload %q escaped its fence: the line %q renders as markup", payload, line)
			}
		}
		// The other direction: the payload is still there. A wrapper that
		// dropped its content would satisfy every assertion above.
		if !strings.Contains(doc, strings.Split(payload, "\n")[0]) {
			t.Errorf("payload %q was not written into the document at all", payload)
		}
		// And the module's own structure survived.
		foundAfter := false
		for _, line := range topLevel {
			if line == "## After" {
				foundAfter = true
			}
		}
		if !foundAfter {
			t.Errorf("payload %q swallowed the heading that followed it", payload)
		}
	}
	t.Logf("checked %d payloads through writeFencedBlock", len(payloads))
}

// TestPickFenceIsAlwaysLongerThanItsContent states the rule the fence rests
// on, over every backtick run length that fits in the content.
func TestPickFenceIsAlwaysLongerThanItsContent(t *testing.T) {
	for runLen := 0; runLen <= 12; runLen++ {
		content := "a" + strings.Repeat("`", runLen) + "b" + strings.Repeat("`", runLen/2)
		for _, least := range []int{1, 3} {
			fence := pickFence(content, least)
			if len(fence) < least {
				t.Errorf("pickFence(%q, %d) returned %d backticks, below the minimum", content, least, len(fence))
			}
			if len(fence) <= runLen {
				t.Errorf("pickFence(%q, %d) returned %d backticks for a run of %d", content, least, len(fence), runLen)
			}
			if strings.Trim(fence, "`") != "" {
				t.Errorf("pickFence returned %q, which is not a run of backticks", fence)
			}
		}
	}
	t.Logf("checked 26 fence choices")
}

// TestInlineCodeContainsWhateverItIsGiven is the inline counterpart. An inline
// span lives on one line, so the property is that the value cannot introduce a
// second one and cannot close the span.
func TestInlineCodeContainsWhateverItIsGiven(t *testing.T) {
	for _, payload := range hostilePayloads() {
		got := inlineCode(payload)
		if strings.Contains(got, "\n") {
			t.Errorf("inlineCode(%q) produced a newline, which would end the span", payload)
		}
		delim := strings.Repeat("`", leadingBacktickRun(got))
		if delim == "" {
			t.Errorf("inlineCode(%q) produced no delimiter: %q", payload, got)
			continue
		}
		if !strings.HasSuffix(got, delim) {
			t.Errorf("inlineCode(%q) is not delimited symmetrically: %q", payload, got)
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(got, delim), delim)
		if strings.Contains(inner, delim) {
			t.Errorf("inlineCode(%q) let its content close the span: %q", payload, got)
		}
	}
	if got := inlineCode(""); got != "``" {
		t.Errorf("inlineCode(\"\") = %q", got)
	}
	t.Logf("checked %d payloads through inlineCode", len(hostilePayloads()))
}

// TestBuildBodyRendersNoUntrustedByteAsMarkup is the property at the level it
// actually matters: the assembled body, with every untrusted field carrying a
// hostile payload at once.
func TestBuildBodyRendersNoUntrustedByteAsMarkup(t *testing.T) {
	id := Identity{Name: "apphub"}
	payloads := hostilePayloads()
	for _, payload := range payloads {
		p := pushRequest{
			At:     Coordinates{Owner: "acme", Repo: "widget"},
			ScanID: "scan-1",
			FixID:  "fix-1",
			Index:  0,
			Finding: review.Finding{
				Title:  payload,
				Detail: payload,
				// The two inline fields carry a hostile value without the
				// marker. They travel in code spans on a line this module
				// wrote, so a top-level line holding their content is correct
				// rather than an escape; what has to hold for them is that the
				// span cannot be closed, which is
				// TestInlineCodeContainsWhateverItIsGiven, over the whole
				// payload population.
				CheckID:  "`x` # h",
				Category: "``` <b>",
				Severity: review.SeverityHigh,
			},
			Verdict: &VerdictResult{Verdict: VerdictReal, Reasoning: payload},
			Patch:   &Patch{Summary: payload},
		}
		body := buildBody(id, p, "apphub/fix-scan-1-0", "abc1234")
		topLevel, unterminated := fenceScan(body)
		if unterminated {
			t.Fatalf("payload %q left the body inside an open fence", payload)
		}
		// Every heading this module writes must still be a heading. If a
		// payload had broken out, its own text would be at top level and the
		// structure below it would be inside a block.
		for _, heading := range []string{"## Finding", "## Verdict", "## Patch summary", "## Provenance"} {
			if !containsLine(topLevel, heading) {
				t.Fatalf("payload %q displaced the heading %q", payload, heading)
			}
		}
		// No byte of a fenced field is ever rendered as markup.
		for _, line := range topLevel {
			if strings.Contains(line, "PAYLOADMARKER") {
				t.Fatalf("payload %q escaped its fence: the line %q renders as markup", payload, line)
			}
		}
		// The other direction: the payload really is in the body, so this is
		// not passing because the fields were dropped.
		if !strings.Contains(body, "PAYLOADMARKER") {
			t.Fatalf("payload %q never reached the body", payload)
		}
	}
	t.Logf("checked %d payloads through buildBody", len(payloads))
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// TestTitlesAreOneLineAndValidUTF8 quantifies over the two things that make a
// title fail at the last step of the run: an embedded newline, which splits a
// commit title in two, and a byte-offset cut through a multi-byte rune, which
// a hosting API rejects.
func TestTitlesAreOneLineAndValidUTF8(t *testing.T) {
	id := Identity{Name: "apphub"}
	// The multi-byte cases are offset by one to five single-byte runes each,
	// so the cut lands mid-rune for at least one of them whatever the rune
	// width is. An earlier version of this test used unoffset repetitions of
	// one rune, and every cut happened to land on a boundary -- so a
	// byte-slicing implementation passed it. The defect and the test were
	// wrong in the same direction, which is what a control is for.
	summaries := []string{"", "  ", "\n", "one\ntwo", "\n\nlate",
		strings.Repeat("a", 400) + "\n" + strings.Repeat("b", 400)}
	for _, wide := range []string{"é", "€", "\U0001d11e"} {
		for offset := 0; offset < 5; offset++ {
			summaries = append(summaries, strings.Repeat("a", offset)+strings.Repeat(wide, 400))
		}
	}
	for _, summary := range summaries {
		for _, findingTitle := range []string{"", "fallback title", "fallback\nsecond"} {
			p := pushRequest{
				ScanID:  "s",
				Patch:   &Patch{Summary: summary},
				Finding: review.Finding{Title: findingTitle},
			}
			title := buildTitle(id, p)
			if strings.Contains(title, "\n") {
				t.Errorf("buildTitle produced a multi-line title for summary %q", summary)
			}
			if !strings.HasPrefix(title, "["+id.Name+"] ") {
				t.Errorf("buildTitle produced %q, which does not carry the identity", title)
			}
			if !utf8.ValidString(title) {
				t.Errorf("buildTitle produced invalid UTF-8 for summary %q", summary)
			}
			if !utf8.ValidString(buildCommitMessage(id, p)) {
				t.Errorf("buildCommitMessage produced invalid UTF-8 for summary %q", summary)
			}
			message := buildCommitMessage(id, p)
			first, _, _ := strings.Cut(message, "\n")
			if !strings.HasPrefix(first, "["+id.Name+"] ") {
				t.Errorf("buildCommitMessage produced the title line %q", first)
			}
			if strings.TrimSpace(strings.TrimPrefix(first, "["+id.Name+"]")) == "" {
				t.Errorf("buildCommitMessage produced an empty title for summary %q", summary)
			}
		}
	}
	t.Logf("checked %d title inputs", len(summaries)*3)
}

// TestFormatExplanationFlattensAndBounds states what is done to the agent's
// own words before they are shown beside a record.
func TestFormatExplanationFlattensAndBounds(t *testing.T) {
	// Offset for the same reason as the title population: an unoffset
	// repetition of one multi-byte rune puts every plausible cut on a
	// boundary, so a byte-slicing implementation passes.
	inputs := []string{"", "   ", "\n\n\n", "a\nb\nc", "a\x00b", strings.Repeat("word ", 1000)}
	for _, wide := range []string{"é", "€", "\U0001d11e"} {
		for offset := 0; offset < 5; offset++ {
			inputs = append(inputs, strings.Repeat("a", offset)+strings.Repeat(wide, 800))
		}
	}
	for _, in := range inputs {
		got := formatExplanation(in)
		if strings.ContainsAny(got, "\n\r\t\x00") {
			t.Errorf("formatExplanation left a control character in %q", got)
		}
		if !utf8.ValidString(got) {
			t.Errorf("formatExplanation produced invalid UTF-8 for a %d-byte input", len(in))
		}
		if len([]rune(got)) > maxExplanationRunes+len("The agent declined to draft a patch: ...") {
			t.Errorf("formatExplanation produced %d runes", len([]rune(got)))
		}
		if got == "" {
			t.Errorf("formatExplanation produced nothing for a %d-byte input", len(in))
		}
	}
	// Blank input gets the general message rather than a message with nothing
	// after the colon.
	if got := formatExplanation("   \n  "); strings.HasSuffix(got, ": ") {
		t.Errorf("formatExplanation of blank input produced %q", got)
	}
	t.Logf("checked %d explanations", len(inputs))
}
