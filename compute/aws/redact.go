// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"io"
	"sync"

	"github.com/conductorone/apphub/credentials"
)

// redactingWriter removes this build's own credential from a stream on its way
// to the caller.
//
// # Why the redaction is here and not in the pusher
//
// [ImagePusher] carries an obligation not to put its own output into an error.
// That is a contract on a component this package does not control, and a contract
// is not a construction: the process holding the credential is a tool an operator
// configured, and tools echo their environment when a call fails.
//
// So the provider redacts where it *consumes* pusher output, on the assumption
// that the pusher is hostile or careless, rather than where the output is
// produced.
//
// # What it no longer has to defend against
//
// It used to wrap the *builder's* output, and the reason was the sharper one:
// kaniko unpacks the image into the container it runs in and shares a PID
// namespace with the commands it runs, so a RUN instruction written by whoever
// owns the repository could read the executor's own environment and print it.
// Review demonstrated exactly that — the session token arriving in
// [compute.BuildRequest.Logs], which a caller persists.
//
// USOSS-41 removed the credential from that environment rather than filtering
// what came out of it, so the build phase's output is no longer wrapped: at the
// moment it is produced, no credential for the build exists. This writer stays,
// on the phase that does hold material, because the class of careless-tool leak
// is real and because — see [ImagePusher] — a same-user sibling process is not
// perfectly isolated from a concurrent build.
//
// # Exactly what it guarantees
//
// The claim is narrow on purpose, because an overclaim here is what made two
// review rounds necessary. What the hold guarantees:
//
//	A contiguous byte-for-byte occurrence of a credential this build minted does
//	not reach the caller's writer, however it is divided across Write calls.
//
// Everything outside that sentence is open, and the near misses are worth naming
// because they look closed:
//
//   - **A prefix of a secret at the end of the stream is flushed raw.** The
//     writer holds back at most maxSecret-1 bytes; at Flush it has to emit them,
//     and a build whose final output is all but the last byte of an access key
//     emits it. Prefixes are not the material, but an AKIA/ASIA-shaped fragment
//     is still a disclosure to whatever reads the log.
//   - Material the build re-encodes (base64, hex, URL-escaped), splits with
//     characters of its own, or derives.
//   - Material this package never held, so was never told to look for.
//
// Nothing a writer can do closes those. This is a mitigation with a boundary,
// not a control.
//
// # The complete remedy, which has landed
//
// The credential must not be reachable by repository-authored code at all: build
// with no push credential and push the result from a process that never ran the
// Dockerfile. That is USOSS-41, and it is implemented — [BuildCommand] has no
// credential field, and the mint happens after the builder returns. This
// redaction stayed, deliberately: a mitigation deleted because its stated reason
// was removed is how a closed hole reopens, and its reason is not fully removed
// while build and push are sibling processes of one user (again: [ImagePusher]).
//
// What still bounds the residue is the design already in place: the credential is
// scoped to this build's destination repositories and lives fifteen minutes, now
// starting after the build rather than before it.
type redactingWriter struct {
	mu     sync.Mutex
	dst    io.Writer
	secret [][]byte
	// hold is the tail of what has been written but not yet forwarded, kept
	// because it may be a prefix of a secret that the next write completes.
	hold []byte
	// maxSecret is the length of the longest secret, and therefore the most
	// that ever has to be held back.
	maxSecret int
}

// redactionPlaceholder is what replaces the material.
const redactionPlaceholder = "[REDACTED]"

// newRedactingWriter wraps dst so that creds cannot pass through it.
//
// A nil dst yields nil: the caller asked for no logs, and there is nothing to
// redact. This is the one place besides [withCredentials] where credential
// material becomes a string, and it exists to take material out of a stream
// rather than to put it in.
func newRedactingWriter(dst io.Writer, creds PushCredentials) io.Writer {
	if dst == nil {
		return nil
	}
	w := &redactingWriter{dst: dst}
	for _, material := range []string{
		credentials.Reveal(creds.AccessKeyID),
		credentials.Reveal(creds.SecretAccessKey),
		credentials.Reveal(creds.SessionToken),
	} {
		if material == "" {
			continue
		}
		w.secret = append(w.secret, []byte(material))
		if len(material) > w.maxSecret {
			w.maxSecret = len(material)
		}
	}
	if len(w.secret) == 0 {
		return dst
	}
	return w
}

// Write implements io.Writer.
//
// It always reports the whole input as written. Reporting the post-redaction
// length would be a short write, which io.Writer defines as an error and which
// would make a build fail because its own output mentioned its own credential.
func (w *redactingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	buf := append(w.hold, p...)
	buf = w.scrub(buf)

	// Hold back the tail that could still be the beginning of a secret. Nothing
	// shorter than the longest secret can be ruled out yet.
	keep := w.maxSecret - 1
	if keep < 0 {
		keep = 0
	}
	if len(buf) <= keep {
		w.hold = buf
		return len(p), nil
	}
	emit, hold := buf[:len(buf)-keep], buf[len(buf)-keep:]

	// The write happens before the hold is updated, and the order is
	// load-bearing rather than stylistic.
	//
	// buf comes from append(w.hold, p...), which reuses w.hold's backing array
	// whenever its capacity allows — and it usually does, because the hold is
	// bounded by the longest secret while its capacity persists. So emit and
	// hold are two windows onto one array, and copying the hold to the front of
	// it first overwrites the bytes emit is about to send.
	//
	// It survives large writes, because those force a reallocation and the two
	// stop aliasing. It corrupts byte-at-a-time ones, which is what a
	// line-buffered builder actually produces.
	if _, err := w.dst.Write(emit); err != nil {
		return 0, err
	}
	w.hold = append(w.hold[:0], hold...)
	return len(p), nil
}

// Flush forwards whatever is still held back. It is called when the build
// finishes, so the tail of the last line is not lost.
func (w *redactingWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.hold) == 0 {
		return nil
	}
	out := w.scrub(w.hold)
	w.hold = w.hold[:0]
	_, err := w.dst.Write(out)
	return err
}

// scrub replaces every occurrence of every secret. It runs on each write as
// well as at flush, so a secret that arrives whole never sits in the buffer.
func (w *redactingWriter) scrub(buf []byte) []byte {
	for _, secret := range w.secret {
		buf = replaceAll(buf, secret, []byte(redactionPlaceholder))
	}
	return buf
}

// replaceAll is bytes.ReplaceAll, written out so the allocation behaviour is
// obvious on a stream that is usually clean: when there is no match, the input
// is returned untouched.
func replaceAll(buf, old, replacement []byte) []byte {
	if len(old) == 0 || indexBytes(buf, old) < 0 {
		return buf
	}
	var out []byte
	for {
		i := indexBytes(buf, old)
		if i < 0 {
			return append(out, buf...)
		}
		out = append(out, buf[:i]...)
		out = append(out, replacement...)
		buf = buf[i+len(old):]
	}
}

func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// flusher is what Build calls on whatever newRedactingWriter returned, without
// having to know which of the two it got.
type flusher interface{ Flush() error }

func flush(w io.Writer) {
	if f, ok := w.(flusher); ok {
		_ = f.Flush()
	}
}
