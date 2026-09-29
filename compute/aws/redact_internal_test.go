// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"fmt"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials"
)

// TestTheRedactingWriterDoesNotCorruptTheStreamItFilters.
//
// The redactor is between the builder and the caller's log writer, so a caller
// that reads its build logs reads whatever this produces. It has to be
// transparent to everything that is not the credential.
//
// This is a regression test for a bug in the redactor itself, found by auditing
// the newest code in the branch rather than by review: the held-back tail was
// copied to the front of a buffer that the pending write was still pointing
// into, so the first byte of every emitted chunk was overwritten. It survived
// large writes — those force a reallocation and the two stop aliasing — and
// corrupted byte-at-a-time ones, which is what a line-buffered builder actually
// produces. The hostile-runner test wrote byte by byte and could not see it,
// because it asserted only that the credential was absent.
//
// The write sizes are the population, since the defect was invisible at one size
// and total at another.
func TestTheRedactingWriterDoesNotCorruptTheStreamItFilters(t *testing.T) {
	t.Parallel()
	const secret = "apphub-test-session-token"

	for _, chunk := range []int{1, 2, 3, 7, 25, 26, 27, 64, 4096} {
		t.Run(fmt.Sprintf("writes of %d bytes", chunk), func(t *testing.T) {
			t.Parallel()
			for _, body := range []string{
				strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789", 40),
				"before " + secret + " after",
				secret,
				secret + secret,
				"x" + secret,
				strings.Repeat(secret+" padding ", 5),
				"",
			} {
				var out strings.Builder
				w := newRedactingWriter(&out,
					PushCredentials{SessionToken: credentials.NewSecret(secret)})
				for i := 0; i < len(body); i += chunk {
					end := min(i+chunk, len(body))
					if _, err := w.Write([]byte(body[i:end])); err != nil {
						t.Fatalf("Write: %v", err)
					}
				}
				flush(w)

				want := strings.ReplaceAll(body, secret, "[REDACTED]")
				if got := out.String(); got != want {
					t.Errorf("chunk=%d body=%q\n got %q\nwant %q", chunk, body, got, want)
				}
			}
		})
	}
}

// TestTheRedactingWriterReportsTheWholeInputAsWritten.
//
// io.Writer defines a short write as an error, so reporting the post-redaction
// length would fail a build because its own output mentioned its own credential.
func TestTheRedactingWriterReportsTheWholeInputAsWritten(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	w := newRedactingWriter(&out,
		PushCredentials{SessionToken: credentials.NewSecret("apphub-test-session-token")})
	in := []byte("leading apphub-test-session-token trailing")
	n, err := w.Write(in)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(in) {
		t.Errorf("Write reported %d of %d bytes; a short write is an error to io.Writer, so a "+
			"build whose output mentioned its own credential would fail", n, len(in))
	}
}

// TestTheRedactorsClaimIsNoWiderThanTheHold.
//
// Review's should-fix, taken as a narrowing of the claim rather than as a fix,
// because the residue is architectural: an all-but-one-byte prefix of a secret
// at the end of a stream is flushed raw, since the hold is at most maxSecret-1
// bytes and Flush has to emit what it is holding.
//
// This asserts the boundary in both directions, so the documented guarantee and
// the code cannot drift: the whole secret never passes however it is divided,
// and a prefix at the end of the stream does. The second half is a test that
// something is *not* protected, which is unusual and deliberate — it is what
// stops the comment being read as a stronger promise than the code makes.
func TestTheRedactorsClaimIsNoWiderThanTheHold(t *testing.T) {
	t.Parallel()
	const secret = "apphub-test-session-token"

	// The guarantee: contiguous, however divided.
	for _, chunk := range []int{1, 5, len(secret) - 1, len(secret), len(secret) + 1} {
		var out strings.Builder
		w := newRedactingWriter(&out, PushCredentials{SessionToken: credentials.NewSecret(secret)})
		body := "head " + secret + " tail"
		for i := 0; i < len(body); i += chunk {
			end := min(i+chunk, len(body))
			if _, err := w.Write([]byte(body[i:end])); err != nil {
				t.Fatal(err)
			}
		}
		flush(w)
		if strings.Contains(out.String(), secret) {
			t.Errorf("chunk=%d: the whole secret reached the caller", chunk)
		}
	}

	// The boundary: a prefix at the end of the stream is emitted, and the
	// comment says so. If this ever starts passing, the guarantee widened and
	// the documentation has to widen with it.
	var out strings.Builder
	w := newRedactingWriter(&out, PushCredentials{SessionToken: credentials.NewSecret(secret)})
	prefix := secret[:len(secret)-1]
	if _, err := w.Write([]byte("trailing " + prefix)); err != nil {
		t.Fatal(err)
	}
	flush(w)
	if !strings.Contains(out.String(), prefix) {
		t.Errorf("a %d-byte prefix of the secret was withheld at the end of the stream. That is "+
			"stronger than the documented guarantee, which covers contiguous whole occurrences "+
			"only — update the comment on redactingWriter to match, rather than leaving the code "+
			"and the claim disagreeing in the caller's favour", len(prefix))
	}
}
