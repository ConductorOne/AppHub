// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
)

// redacted is what a Secret renders as everywhere except Reveal.
const redacted = "[REDACTED]"

// ErrSecretMarshal is returned when something tries to serialize credential
// material. Vending a credential means exactly one caller sees the material
// exactly once; every other path that reaches for it -- a debug dump of a
// struct, an error wrapped with %v, a response body assembled from the wrong
// type, a gob stream -- is a leak, and this error is how that leak surfaces as a
// failed request instead of a line in a log aggregator.
var ErrSecretMarshal = errors.New("credentials: refusing to serialize credential material; call credentials.Reveal explicitly")

// ErrSecretUnmarshal is returned when a JSON value cannot be read into a Secret.
//
// It is a constant rather than encoding/json's own error on purpose. A json
// diagnostic is derived from the input -- "invalid character 'R' looking for
// beginning of value" names a byte of it, and a type error quotes more than that
// -- and the input here is a provider's response body, which is where credential
// material arrives. Review demonstrated exactly that: a foreign sentinel driven
// through UnmarshalJSON came back in the error. A response body that is not the
// shape we expect is one fact, and the caller can act on it without being told
// which byte was wrong.
//
// # What this does NOT close, which the wording above used to imply
//
// It closes every path where the value reaches this type. It cannot close the
// path where this type is never consulted, and that path exists: when the OUTER
// document is malformed, encoding/json fails in its top-level scanner and never
// delegates to a custom UnmarshalJSON at all. So
//
//	json.Unmarshal([]byte(`{"token": REVIEWER-FOREIGN-7d1c}`), &payload)
//
// returns the decoder's own "invalid character 'R' looking for beginning of
// value" -- naming a byte of the body -- while this sentinel is never reached.
// Verified rather than reasoned about, and pinned as an asserted limit by
// TestTheUnmarshalSentinelDoesNotCoverAMalformedDocument.
//
// That is a property of encoding/json and not of Secret, so the fix belongs at
// the decode site: a caller must not propagate a decoder error derived from a
// provider response body. It is filed separately. Recording the boundary here
// because the paragraph above, on its own, reads as though the class is closed --
// and the next reader would inherit a stronger promise than the code makes.
var ErrSecretUnmarshal = errors.New("credentials: credential material was not a JSON string")

// Secret holds credential material: an API key, a bearer token, a session
// secret, a private key.
//
// It is an opaque struct with unexported, non-string fields, and that shape is
// the whole design. An earlier version was a defined string type, which the
// language hands back through any generic path that inspects kind rather than
// methods: encoding/gob wrote the raw value, reflect.Value.String returned it,
// and text/template could call an exported Reveal method by name.
//
// # Why the mask is no longer stored beside the material
//
// It was, for one release, and the justification was that "a generic dumper does
// not XOR field pairs". USOSS-46 retired that argument, and the reason is worth
// keeping: **it is a claim about what readers do, not a property of the type.**
// It is the same shape as two other claims this project falsified in a day —
// "unexported closes reflection" and "a caller passes a constant provider ID" —
// and the reproduction took eleven lines of ordinary reflection:
//
//	for every pair of reachable byte fields, XOR them and compare
//	-> recovers the material
//
// So the mask is gone and the material is masked against a keystream derived
// from a package-level key that no Secret references. Recombining every field
// reachable from a Secret now yields nothing, because the term that reverses it
// is not among them.
//
// The derivation itself is [keystream], which this package already had for
// [Foreign] and which both types now share. It is deliberately NOT a second copy
// living here: a first draft of this change added one, and the compiler rejected
// it, which is the cheapest possible version of that lesson. Two copies of a
// masking derivation drift, and the one that falls behind is the one holding the
// credential. compute.SecretValue has the same construction and is a genuine
// copy, because this package has no dependencies at all — that is what makes it
// importable from anywhere without a cycle, and an internal import would spend
// the property on forty lines of XOR.
//
// # What this defends against, and what it does not
//
// It defends against accidental exposure: generic serializers, log and error
// formatting, reflection-based dumpers, template rendering. Those are the leaks
// that actually happen, and each one fails closed.
//
// It does not defend against code in the same process that is trying to read the
// material. unsafe can read the fields, a memory dump contains everything, and a
// provider that writes Reveal(s) into an error message defeats the type
// entirely. This is a guardrail, not a vault, and claiming more would be worse
// than claiming nothing.
type Secret struct {
	// masked is the material XOR a keystream derived from nonce and the package
	// key; nonce is drawn per Secret. Neither field, nor both together, yields
	// anything without the key -- which is deliberately not here.
	masked []byte
	nonce  [nonceLen]byte
}

// NewSecret wraps credential material.
//
// This is the only way to construct a populated Secret, which means the points
// where material enters the type are as greppable as the points where it leaves.
func NewSecret(material string) Secret {
	if material == "" {
		return Secret{}
	}
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic("credentials: no system randomness for a secret nonce: " + err.Error())
	}
	ks := keystream(nonce, len(material))
	masked := make([]byte, len(material))
	for i := range len(material) {
		masked[i] = material[i] ^ ks[i]
	}
	return Secret{masked: masked, nonce: nonce}
}

// Reveal returns the material inside a Secret.
//
// It is a package-level function rather than a method on purpose: a method named
// Reveal is discoverable by name, and text/template will happily call one for
// anybody who writes {{.Reveal}}. A function cannot be reached that way. That
// decision was made once here, was not carried to compute.SecretValue, and
// USOSS-43 was the bill for it -- so it is restated rather than assumed.
//
// Every call site is a place where material crosses a boundary, so keep them few
// and obvious: handing the credential to the requester once, writing it to the
// secret store, or putting it on the wire to the platform that will use it. Never
// into a log, an error, a metric label, or a cache.
func Reveal(s Secret) string {
	if len(s.masked) == 0 {
		return ""
	}
	ks := keystream(s.nonce, len(s.masked))
	out := make([]byte, len(s.masked))
	for i := range s.masked {
		out[i] = s.masked[i] ^ ks[i]
	}
	return string(out)
}

// IsZero reports whether the secret is empty. Useful for validating a provider
// response without revealing it.
func (s Secret) IsZero() bool { return len(s.masked) == 0 }

// Format implements fmt.Formatter for every verb, and it is the ONLY formatting
// method this type has.
//
// # Why there is no String or GoString
//
// There were, and they redacted, and they were still the wrong shape. fmt.Formatter
// takes precedence over fmt.Stringer and fmt.GoStringer for every verb, so they were
// redundant for their stated purpose -- verified, not assumed: with Format alone,
// %v %s %q %x %#v all redact, and so does a template over the value or over a
// struct containing it.
//
// What they were not redundant for is the hazard this type exists to close. An
// exported zero-argument method returning a string is reachable by name from
// text/template, so {{.String}} was a live template call into a type holding
// credential material. It rendered a placeholder today, and it left the shape in
// place -- so any future edit to either body would have made the material
// template-reachable with nothing to catch it.
//
// This is the same removal USOSS-43 made on compute.SecretValue, for the same
// reason, and the surface is now asserted structurally over the union of Secret
// and *Secret rather than argued about. Keeping them behind a whitelist would be
// "allowed because the body redacts today", which is a claim about a method body,
// and a method body is what an edit changes.
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, redacted)
}

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON always fails. See ErrSecretMarshal: a response that must carry
// material builds a dedicated wire type from Reveal, deliberately.
func (s Secret) MarshalJSON() ([]byte, error) { return nil, ErrSecretMarshal }

// MarshalText always fails, for the same reason as MarshalJSON. It also covers
// the encoders that prefer encoding.TextMarshaler.
func (s Secret) MarshalText() ([]byte, error) { return nil, ErrSecretMarshal }

// GobEncode always fails. encoding/gob does not consult MarshalJSON or
// MarshalText, so without this a gob stream carrying any struct that contains a
// Secret would write the material out in the clear.
func (s Secret) GobEncode() ([]byte, error) { return nil, ErrSecretMarshal }

// GobDecode always fails. gob requires a GobEncoder to be a GobDecoder as well,
// and a Secret arriving over a gob stream is a Secret that was serialized
// somewhere it should not have been.
func (s *Secret) GobDecode([]byte) error { return ErrSecretMarshal }

// UnmarshalJSON accepts material from a provider's response body. Reading in is
// safe; it is writing out that leaks -- including writing out through an error,
// which is why the failure is ErrSecretUnmarshal and not the decoder's own
// input-derived diagnostic.
func (s *Secret) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return ErrSecretUnmarshal
	}
	*s = NewSecret(v)
	return nil
}

// Metadata is the per-provider configuration bag carried on a credential
// request: a region, an API base URL, an installation ID -- and also admin API
// keys, app keys and private keys, because that is what a provider needs to act
// on an operator's behalf.
//
// Because the values are frequently secret and the keys never are, Metadata
// renders as its sorted key set. That keeps the useful half of the debugging
// information ("which keys did the resolver actually supply?") and drops the half
// that must not be written down.
//
// It is a map[string]string underneath, so ported provider code that does
// req.Metadata["region"] or ranges over it needs no change at all. That
// compatibility is the reason it is not an opaque type like Secret, and it has a
// cost worth stating: a map's values are reachable by reflection, so Metadata
// stops the formatting, logging and serialization leaks but cannot stop code that
// deliberately walks it. Material that must survive nothing but a single call
// belongs in a Secret.
type Metadata map[string]string

// Keys returns the sorted key set. Keys are configuration names, never material,
// so they are safe to log.
func (m Metadata) Keys() []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Format implements fmt.Formatter for every verb, so no verb reaches the
// underlying map's values.
func (m Metadata) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, m.String())
}

// String renders the key set only.
func (m Metadata) String() string {
	if len(m) == 0 {
		return "credentials.Metadata{}"
	}
	return fmt.Sprintf("credentials.Metadata{keys: %v, values: %s}", m.Keys(), redacted)
}

// GoString renders the key set only.
func (m Metadata) GoString() string { return m.String() }

// LogValue implements slog.LogValuer.
func (m Metadata) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("keys", m.Keys()),
		slog.String("values", redacted),
	)
}

// MarshalJSON always fails: a metadata bag has no business in a response body or
// an audit record. Callers that need to persist a non-secret subset name the
// fields they want explicitly.
func (m Metadata) MarshalJSON() ([]byte, error) { return nil, ErrSecretMarshal }

// GobEncode always fails, for the same reason as Secret.GobEncode.
func (m Metadata) GobEncode() ([]byte, error) { return nil, ErrSecretMarshal }

// GobDecode always fails; gob requires the pair.
func (m *Metadata) GobDecode([]byte) error { return ErrSecretMarshal }

// SecretRef locates credential material in a secret store without containing it.
// Records, audit rows, and container definitions carry a SecretRef; only the
// secret store itself and the workload it belongs to see the value.
//
// Converting a SecretRef into whatever a compute provider binds into a workload
// is the deploy layer's job, not this package's and not the compute package's --
// see /shared/apphub/contracts/workload-identity.md, which owns that rule.
//
// The zero value means "no material was stored".
type SecretRef struct {
	// Store names the backing store, e.g. "aws-ssm". Empty means the deployment's
	// default store.
	Store string
	// Name is the store-scoped identifier: an SSM parameter path, a Secrets
	// Manager name, a Kubernetes secret key. Opaque to everything but the store
	// that issued it.
	Name string
	// Version pins a specific revision when the store supports it. Empty means
	// "current".
	Version string
	// EnvVar is the environment variable a workload expects the material under,
	// when this reference exists to be injected into a workload. Empty for
	// references that are only read back by the platform.
	EnvVar string
}

// IsZero reports whether the reference points at nothing.
func (r SecretRef) IsZero() bool { return r.Name == "" && r.EnvVar == "" }

// String renders the locator. A locator is not material, but it is internal
// topology, so it is worth keeping out of third-party log sinks -- see the
// handling in docs/design/credential-vending.md.
func (r SecretRef) String() string {
	if r.IsZero() {
		return "credentials.SecretRef{}"
	}
	loc := r.Name
	if loc == "" {
		loc = r.EnvVar
	}
	if r.Store == "" {
		return loc
	}
	return r.Store + ":" + loc
}
