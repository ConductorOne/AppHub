// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// redactedValue is what a SecretValue renders as everywhere except Reveal.
const redactedValue = "[REDACTED]"

// ErrSecretSerialize is returned by the serialization paths a SecretValue does
// not support. Unlike JSON and text, which redact so that spec hashing keeps
// working (see [SecretValue.MarshalJSON]), a gob stream has no redacted form to
// emit, so it fails instead.
var ErrSecretSerialize = errors.New("compute: refusing to serialize credential material; call compute.RevealSecret explicitly")

// SecretValue carries credential material across this boundary without letting
// it reach a log line, an error string, or a JSON payload by accident.
//
// The source system passes generated database passwords around as plain strings
// (source system @ backend/internal/modules/deploy/container.go and
// postgres_roles.go). Nothing there logs one
// today, but nothing there prevents it either, and this repository is going
// public. A wrapper that redacts on every stringification path makes the safe
// behaviour the default and the unsafe one an explicit [RevealSecret] call that
// a reviewer can grep for.
//
// The zero value is an empty secret; [SecretValue.IsZero] distinguishes it from
// a real one.
//
// # Why the material is masked rather than held in a string
//
// Two leaks that no amount of method-writing closes, both measured rather than
// assumed:
//
//   - reflect.Value.String does not panic on an unexported field, so a plain
//     string field returned the material in one call:
//     reflect.ValueOf(s).Field(0).String(). Reflection-based dumpers do exactly
//     this. Masked, the same call returns noise.
//   - fmt handles %p before it consults [fmt.Formatter], so a Format method
//     cannot redact it; the fallback prints the struct's fields, unexported
//     ones included. Verified with a control, in
//     TestFormatCannotCoverThePointerVerb: a Format-only type leaks under %p and
//     this one does not.
//
// So masking and [SecretValue.Format] are not redundant defences. Each closes
// something the other cannot, which is why both are here and why neither may be
// dropped on the grounds that the other exists.
//
// # Why the mask is not stored beside the material
//
// It was, in the first version of this type and in [credentials.Secret], on the
// recorded justification that "a generic dumper does not XOR field pairs". That
// is a claim about what readers do, not a property of the type, and eleven lines
// of ordinary reflection — no unsafe, no build tags — recovered the material
// from both. USOSS-46 retired the justification and the shape with it.
//
// So the keystream is derived from a package-level key that no SecretValue
// references. A reflective walk over one of these reaches the masked bytes and a
// nonce; recombining every reachable field, in every pairing, yields nothing,
// and TestRecombiningEveryReachableFieldDoesNotReverseASecret asserts exactly
// that rather than asserting the field count.
//
// This is still a guardrail, not a vault. It defends against accidental
// exposure — generic serializers, log and error formatting, reflective dumpers,
// template rendering. It does not defend against code in the same process that
// is trying to read the material: unsafe can read the fields, a memory dump
// contains everything, and a caller that writes RevealSecret(v) into an error
// message defeats the type entirely. The property is "material does not escape
// by accident", and claiming more than that would be worse than claiming
// nothing.
//
// [credentials.Secret] holds credential material under the same construction
// for the same reasons. The two types deliberately differ on serialization, and
// [SecretValue.MarshalJSON] records why.
type SecretValue struct {
	// masked is the material XOR a keystream derived from nonce and the
	// package key. nonce is per value. Neither field, nor both together,
	// yields anything without the key — which is deliberately not here.
	masked []byte
	nonce  [16]byte
}

// secretKey is the process-wide key the keystream is derived from.
//
// A package-level value that no [SecretValue] references, which is the whole
// reason a reflective walk over one cannot reverse it. It is drawn once, lazily,
// so a program that never handles a secret never draws it.
//
// crypto/rand.Read does not fail on any supported platform — it panics if the
// system source is unavailable, which is the correct outcome here, because a
// zero key would silently turn the masking into a no-op.
var secretKey = sync.OnceValue(func() [32]byte {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		panic("compute: no system randomness for the secret-value key: " + err.Error())
	}
	return k
})

// secretKeystream derives n bytes from the package key and a per-value nonce.
//
// SHA-256 of key||nonce||counter. Not a cipher and not claimed to be one: the
// property needed is that the bytes are not derivable from anything reachable
// through a SecretValue, and a keyed hash whose key the value does not carry
// gives that.
func secretKeystream(nonce [16]byte, n int) []byte {
	key := secretKey()
	out := make([]byte, 0, n+sha256.Size)
	buf := make([]byte, 0, len(key)+len(nonce)+8)
	for block := uint64(0); len(out) < n; block++ {
		buf = buf[:0]
		buf = append(buf, key[:]...)
		buf = append(buf, nonce[:]...)
		buf = binary.BigEndian.AppendUint64(buf, block)
		sum := sha256.Sum256(buf)
		out = append(out, sum[:]...)
	}
	return out[:n]
}

// NewSecretValue wraps credential material.
//
// This is the only way to construct a populated SecretValue, so the points
// where material enters the type are as greppable as the points where it
// leaves.
func NewSecretValue(v string) SecretValue {
	if v == "" {
		return SecretValue{}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic("compute: no system randomness for a secret-value nonce: " + err.Error())
	}
	ks := secretKeystream(nonce, len(v))
	masked := make([]byte, len(v))
	for i := range len(v) {
		masked[i] = v[i] ^ ks[i]
	}
	return SecretValue{masked: masked, nonce: nonce}
}

// RevealSecret returns the material inside a SecretValue.
//
// A package-level function rather than a method, and that is the whole point: a
// method named Reveal is reachable by name from text/template, so any template
// that walks a value carrying one renders the material. It WAS a method here,
// and {{.Reveal}} rendered the plaintext with no reflection at all.
// credentials.Reveal is a package function for exactly this reason and this is
// the same decision applied to the same hazard.
//
// Every call site is a place material crosses a boundary, so keep them few and
// obvious: writing it into the secret store, or handing it to the one component
// documented to need it. Never into a log, an error, a metric label, or a cache.
func RevealSecret(s SecretValue) string {
	if len(s.masked) == 0 {
		return ""
	}
	ks := secretKeystream(s.nonce, len(s.masked))
	out := make([]byte, len(s.masked))
	for i := range s.masked {
		out[i] = s.masked[i] ^ ks[i]
	}
	return string(out)
}

// IsZero reports whether the value is empty.
func (s SecretValue) IsZero() bool { return len(s.masked) == 0 }

// Format implements [fmt.Formatter] for every verb, which is what makes %d, %q
// and %x as safe as %s.
//
// Without it, fmt consults [fmt.Stringer] only for the v, s, q, x and X verbs
// and falls back to printing the struct for everything else, so
// fmt.Sprintf("%d", spec) on a struct holding a secret printed the material in
// the clear. That is not a hypothetical verb: it is what a caller reaches for
// after changing a field's type and not the format string.
//
// # Why there is no String or GoString
//
// There were, and they redacted, and they were still wrong. fmt.Formatter takes
// precedence over [fmt.Stringer] and [fmt.GoStringer] for every verb, so they
// were redundant for their stated purpose — verified: with Format alone, %v, %s,
// %q, %x and %#v all redact, and so does a template rendering the value or a
// struct containing it.
//
// What they were not redundant for is the hazard this type exists to close. Any
// exported method is reachable by name from text/template, so {{.String}} was a
// live template call into this type. It rendered "[REDACTED]" today — and it
// left the SHAPE in place, so a future edit to either body would have made the
// material template-reachable with nothing to catch it.
//
// The invariant is therefore not a prohibition on a shape. Two reviewers in
// succession defeated shape rules here: first a pointer-receiver method, which a
// gate enumerating only the value method set could not see; then an arg-taking
// method and a (string, error) method, which text/template calls perfectly well.
// So over the method SETS of SecretValue and *SecretValue, promotions included,
// the exported methods permitted on this type are exactly the ones named in
// secretValueSurface — anything else fails, whatever its arity and whatever it
// returns. See TestTheSecretSurfaceIsExactlyTheAllowlist. String and GoString
// were the first two things the earlier version of that gate found; removing
// them was cheaper than carving them out.
func (s SecretValue) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedValue) }

// LogValue implements [slog.LogValuer], so a SecretValue logged as an attribute
// redacts regardless of which verb the handler happens to format with.
//
// The text and JSON handlers both route through a Stringer today, so this
// changes no output. It is here so the property is a promise of this type
// rather than a consequence of a handler's implementation choice.
func (s SecretValue) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON redacts, so a SecretValue embedded in a struct that gets logged
// as JSON, or returned from an API handler, cannot carry material out.
//
// # Why this redacts where credentials.Secret refuses
//
// [credentials.Secret.MarshalJSON] returns an error, on the reasoning that
// vending a credential means one caller sees it once and every serialization
// path is therefore a leak. That reasoning is right for that type and wrong for
// this one, and the difference is not a style choice.
//
// A SecretValue lives inside specs that are legitimately serialized for reasons
// that have nothing to do with reading the secret. A provider computes a
// revision by hashing the effective spec, so that a caller can tell a real
// rollout from a no-op Ensure — compute/fake/fake.go's revisionOf marshals the
// whole spec and panics if it cannot. Under a failing MarshalJSON every spec
// carrying a password would panic there, and the fix would be to strip secrets
// before hashing, which is more code on a path whose whole job is to be
// mechanical.
//
// The redaction is also load-bearing rather than incidental: because it is
// stable, an admin password change does not alter the revision, which is
// correct twice over — the password is not part of the effective configuration,
// and a provider must not rotate it.
//
// So: material must not appear, and marshalling must succeed. A constant
// redaction is the only thing that does both. Anyone tempted to align this with
// credentials.Secret should read revisionOf first.
func (s SecretValue) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedValue + `"`), nil }

// MarshalText redacts, for the same reason as MarshalJSON. It covers the
// encoders that prefer [encoding.TextMarshaler] — a URL query builder, a YAML
// encoder, a map key — which never consult MarshalJSON and so were not covered
// by it.
func (s SecretValue) MarshalText() ([]byte, error) { return []byte(redactedValue), nil }

// UnmarshalJSON accepts back exactly what [SecretValue.MarshalJSON] writes,
// and nothing else, always producing the zero value.
//
// Before this existed, a struct embedding a SecretValue field had no
// [json.Unmarshaler] for it, so the default reflection-based decoder tried to
// unmarshal the redacted marker string into an unexported struct field and
// failed with a type-mismatch error on every single decode -- not only on a
// genuinely corrupted annotation, but on every effective spec this package
// ever correctly wrote, because [SecretValue.MarshalJSON] never emits
// anything else. USOSS-69 found this the hard way: fixing decodeSpec
// (compute/k8s/names.go) to stop discarding its unmarshal error turned that
// permanent, silent failure into a permanent, loud one for every relational
// database's effective spec, which is what TestDecodeSpecDistinguishesAbsentFromMalformed
// and the k8s conformance suite caught.
//
// There is no material to recover -- the marker is one-way by construction --
// so the only question this method can usefully ask is whether the bytes it
// was given are the marker this build writes. They are, on every value this
// package ever produced; a value that is not the marker was hand-edited,
// predates this format, or is genuinely corrupt, and any of those is worth
// reporting rather than silently zeroing.
func (s *SecretValue) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("compute: SecretValue: %w", err)
	}
	if str != redactedValue {
		return fmt.Errorf("compute: SecretValue: expected the redacted marker %q, got %q; a "+
			"SecretValue decodes only from what MarshalJSON wrote, never from material",
			redactedValue, str)
	}
	*s = SecretValue{}
	return nil
}

// GobEncode always fails. encoding/gob consults neither MarshalJSON nor
// MarshalText, and a gob stream is not a path this type supports.
//
// gob already refused a SecretValue before this method existed, because it has
// no exported fields. That is an accident of the current field set rather than
// a property of the type, and it would disappear the moment somebody added an
// exported field for an unrelated reason. This makes the refusal deliberate.
func (s SecretValue) GobEncode() ([]byte, error) { return nil, ErrSecretSerialize }

// GobDecode always fails. gob requires a GobEncoder to be a GobDecoder as well,
// and a SecretValue arriving over a gob stream is one that was serialized
// somewhere it should not have been.
func (s *SecretValue) GobDecode([]byte) error { return ErrSecretSerialize }

// SecretBinding attaches a stored secret to a workload under an environment
// variable name.
//
// The value is never read by apphub at deploy time: the provider hands the
// runtime a reference and the runtime resolves it at launch. That is what the
// ECS Secrets/ValueFrom mechanism does (source system @
// backend/internal/modules/deploy/container.go) and what a
// Kubernetes secretKeyRef does, and it is the property worth preserving —
// injecting a resolved value would put every application secret through
// apphub's own memory and, worse, into its task definitions.
//
// # Where these come from
//
// Some bindings the deploy layer builds itself, from secrets it stored through
// [SecretStore] — a generated database password, say. Others originate in the
// credential layer, which hands back its own reference type naming a store, a
// name, a version and a target variable.
//
// Converting one to the other is the deploy layer's job and nobody else's, and
// that assignment is normative rather than stylistic. The conversion has to
// validate that the named store belongs to the selected compute provider, and
// only the deploy layer knows which provider is in play: putting the adapter in
// the credential package would make it aware of a provider selection it has no
// business seeing, and putting it here would make compute import a credential
// locator it otherwise never touches. A provider that receives a binding whose
// [Ref] it did not issue returns [ErrForeignRef], which is the backstop for a
// conversion done wrong.
type SecretBinding struct {
	// EnvName is the environment variable the workload sees.
	EnvName string
	// Secret refers to a secret held by the same provider's [SecretStore].
	// A binding to a foreign store is [ErrForeignRef]: see [SecretStore] for
	// why the two cannot be mixed in v1.
	//
	// A binding whose secret is in a different [Placement] from the workload is
	// [ErrInvalidSpec]. A provider MUST NOT copy secret material between
	// placements to satisfy one.
	Secret Ref

	// Version pins the binding to one revision of the secret, as reported by
	// [StoredSecret.Version]. Empty means whatever the store currently holds.
	//
	// It exists because the credential layer's own locator has it and the
	// conversion into this type was losing it. `credentials.SecretRef.Version`
	// pins a revision, [Ref] addresses the current value, and before this field
	// a version-pinned credential reference silently became an unpinned one —
	// which is worth spelling out, because "silently" is the whole defect: a
	// caller that asked for a specific revision, in order to bound what a leaked
	// credential is worth, got the latest one and was told nothing.
	//
	// A provider whose store has no revisions MUST refuse a non-empty Version
	// with [ErrVersionPinningUnsupported] rather than ignore it. Ignoring it
	// reproduces the original defect one layer further in, which is the only
	// outcome worse than not having the field. compute/k8s is the concrete
	// decliner: a Kubernetes Secret has no content version anywhere in the
	// object, and its resourceVersion is an optimistic-concurrency token that
	// changes on writes the caller never made — mapping one onto the other would
	// look like honouring the pin while silently following the latest value.
	//
	// Pinning is not capability-gated. A capability is a whole port or a class of
	// behaviour a substrate may structurally lack, and this is one field on one
	// spec; the refusal is what a caller acts on, and it arrives from the call
	// that could not be satisfied.
	Version string
}

// StoredSecret is what [SecretStore.Put] reports about the write it performed.
//
// It is a struct rather than a bare [Ref] for one reason, and the reason is
// worth stating because the bare Ref was the obvious design: the writer has to
// be able to learn which revision it just created. Otherwise
// [SecretBinding.Version] is a field only a caller who obtained a version from
// somewhere outside this interface can fill, and a field nobody can fill
// correctly is a worse artefact than the gap it replaced.
//
// The version is deliberately NOT part of [Ref]. A Ref is the identity of a
// resource, and encoding a mutable revision into it would make Ref equality stop
// meaning "the same resource" — a semantic overload every future reader who
// compares two Refs would inherit, and one that quietly breaks the conformance
// suite's "the same spec yields the same Ref" invariant.
type StoredSecret struct {
	// Ref addresses the secret. It does not change when the value does.
	Ref Ref

	// Version identifies the revision this Put created, in whatever form the
	// store uses. Opaque: a caller passes it back through
	// [SecretBinding.Version] and never parses it.
	//
	// Empty means the store has no revisions, which is a fact about the
	// substrate rather than a failure. A caller that needs a pin and gets an
	// empty version here knows, before it builds a workload specification, that
	// this provider cannot give it one.
	Version string
}

// SecretSpec describes a secret to store.
type SecretSpec struct {
	// Name is the logical name, unique within Scope. AppHub's own path
	// convention (the "{prefix}/apps/{appId}/{name}" layout in source system @
	// backend/internal/modules/deploy/container.go) is a caller concern: the
	// provider namespaces however
	// its substrate requires and returns a [Ref].
	Name string

	// Placement says where the secret lives, and it must match the placement of
	// every workload that binds it.
	//
	// Same reasoning as [WorkloadIdentitySpec.Placement], and the same evidence:
	// an SSM parameter is account-global while a Kubernetes secretKeyRef
	// resolves only within the pod's own namespace. The alternative to this
	// field is a provider that copies secret material into a second namespace to
	// satisfy a binding, which doubles the places an audit has to look for
	// material this interface is otherwise careful never to let apphub read.
	//
	// Empty means the provider's default placement; a provider with no default
	// returns [ErrInvalidSpec]. A provider whose substrate does not scope secrets
	// at all still validates the name: it has one placement, and a spec naming a
	// placement it was not configured with is [ErrInvalidSpec] rather than
	// something to ignore. An earlier draft of this comment said such a provider
	// "ignores this", which is wrong in the fail-open direction — a caller that
	// asked for one region and silently got another has been handed a resource
	// it did not ask for.
	Placement Placement
	// Scope groups related secrets so they can be enumerated and deleted
	// together on teardown — in practice, the owning application's ID.
	Scope string
	// Value is the material.
	Value SecretValue
	// Labels are non-secret metadata for operator tooling. Never put secret
	// material here: labels are expected to appear in listings and logs.
	Labels map[string]string
}

// SecretInfo is what a store will say about a secret WITHOUT returning it.
//
// # Why a metadata read exists at all
//
// A caller that binds a secret into a workload holds a [Ref] and can establish
// nothing else about it: whether it still exists, and where it lives. Both are
// ordinary operator transitions — somebody deletes or rotates external secret
// state, somebody moves an application to a different [Placement] and keeps its
// bindings — and both make a binding invalid. Without a metadata read the only
// way to find out is to create the workload and be refused, which means a
// rejected deploy has already built an image, an identity and a database.
//
// # Why it carries no value, and how that is kept true
//
// Every field here is a locator or a location. There is deliberately no
// [SecretValue] and no string that could hold one, and the conformance suite
// asserts it two ways: structurally, that no field of this type is a
// SecretValue, and behaviourally, that nothing a Describe returns contains
// planted material. [SecretStore.Get] remains the only operation that returns
// a value, and remains the one a caller must justify.
// # What it carries, and what it does not
//
// The two facts a caller needs and no more. The logical name and the scope are
// deliberately absent: a provider that derives its physical name from them
// cannot recover either without storing them a second time, so a field for them
// would be one some providers filled and others left empty — and a field that is
// sometimes empty is a field callers learn to ignore.
type SecretInfo struct {
	// Ref is the reference that was asked about, as the provider recognises it.
	Ref Ref
	// PlacementScope says whether placement constrains binding this secret at
	// all. Required: the zero value is not a valid answer.
	PlacementScope SecretPlacementScope
	// Placement is where the secret lives, for a [SecretPlacementScoped] store.
	// Empty, and meaningless, for a [SecretPlacementGlobal] one.
	Placement Placement
}

// SecretPlacementScope says how [Placement] constrains binding a secret.
//
// It exists because the two answers are genuinely different and one of them
// cannot be expressed as a placement. A Kubernetes secretKeyRef resolves only
// within the pod's own namespace, so a secret there IS somewhere and a workload
// elsewhere cannot bind it. An SSM parameter is account-global — [SecretSpec]
// says in as many words that an AWS provider ignores the field — so a secret
// there is nowhere in particular and every workload the provider runs can bind
// it.
//
// Collapsing that into a single Placement field produced a real defect: the AWS
// store accepted a non-default placement in Put, reported the default from
// Describe, and a caller comparing the two would refuse a perfectly valid
// deployment as cross-placement. **An invariant that is too strong manufactures
// findings**, and a caller that trusts one acts on it.
//
// So the third answer is named rather than folded into either pole. A caller
// asks the scope first and compares placements only when there is something to
// compare.
type SecretPlacementScope string

const (
	// SecretPlacementScoped means the secret lives in [SecretInfo.Placement]
	// and only a workload in that placement may bind it.
	SecretPlacementScoped SecretPlacementScope = "scoped"
	// SecretPlacementGlobal means placement does not constrain binding: every
	// workload this provider runs may bind the secret, and
	// [SecretInfo.Placement] is empty.
	SecretPlacementGlobal SecretPlacementScope = "global"
)

// SecretStore holds named secret material and makes it bindable into a
// workload.
//
// This is the most portable capability in the whole interface — Put/Get/Delete
// over an encrypted namespace maps onto SSM Parameter Store, Secrets Manager,
// Vault, GCP Secret Manager, Azure Key Vault, and a Kubernetes Secret with
// almost no impedance. The one real constraint is the binding side: a runtime
// can only resolve a reference to a store it natively understands, so in v1 a
// workload's [SecretBinding] values must come from the same [Provider] that
// runs the workload. Mixing (Vault secrets into ECS, say) needs a sidecar or an
// init container and is deliberately out of scope; a provider must return
// [ErrForeignRef] rather than pretend.
type SecretStore interface {
	// Put stores or replaces a secret and reports what it wrote.
	// Idempotent: storing the same name twice replaces the value and returns
	// the same [Ref]. The [StoredSecret.Version] changes; the Ref does not.
	Put(ctx context.Context, spec SecretSpec) (StoredSecret, error)

	// Get reads a secret back. Used only where apphub genuinely needs the
	// material itself — the master database password, which it must present to
	// Postgres to create roles (postgres_roles.go:154-165). Injection into
	// workloads never goes through Get.
	Get(ctx context.Context, ref Ref) (SecretValue, error)

	// Describe reports what the store holds about a secret without returning
	// its value: it exists, and where it is. [ErrNotFound] when there is no
	// such secret, [ErrForeignRef] for a Ref this provider did not issue.
	//
	// It exists so a caller can validate a binding BEFORE it creates anything.
	// A provider MUST NOT return secret material through it, in any field —
	// see [SecretInfo].
	Describe(ctx context.Context, ref Ref) (*SecretInfo, error)

	// Delete removes a secret. Deleting an absent secret returns nil: teardown
	// must be re-runnable.
	Delete(ctx context.Context, ref Ref) error

	// DeleteScope removes every secret in a scope. Teardown needs this because
	// the set of secrets an application accumulated over its lifetime is not
	// reliably known to the caller — the source system tracked it in a
	// SecretNames slice on the application row (source system @
	// backend/internal/modules/deploy/container.go) that any
	// failed deploy could leave incomplete.
	//
	// It removes the named scope and nothing else, and it is re-runnable: a
	// scope that is already empty, or was never used, returns nil.
	//
	// An empty scope is [ErrInvalidSpec]. It must never be read as "every
	// secret", which is the one reading that would make a caller bug delete a
	// whole deployment's credentials — and it is the reading a substrate whose
	// scopes are a path prefix arrives at by doing nothing special. All three
	// implementations already refuse it; this says so, so that the fourth does
	// too.
	DeleteScope(ctx context.Context, scope string) error
}
