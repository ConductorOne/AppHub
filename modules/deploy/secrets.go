// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/credentials"
)

// secretBinder is the deploy layer's half of the workload-identity contract:
// the one conversion from [github.com/conductorone/apphub/credentials.SecretRef] to
// [github.com/conductorone/apphub/compute.SecretBinding].
//
// # Why it lives here and why it is stateful
//
// The contract assigns this conversion to the deploy layer and to nothing else,
// because only the deploy layer knows which compute provider is in play. What
// the contract does not say, and what falls out of the two interfaces, is that
// the conversion cannot be a pure function: a credentials.SecretRef names a
// store and a store-scoped name, while a compute.SecretBinding needs a
// provider-issued compute.Ref, and [compute.SecretStore] has no operation that
// turns a name into a Ref. There is Put, Get, Describe, Delete and DeleteScope,
// and both of the two that answer anything about one secret — Get and Describe —
// already need the Ref.
//
// So the only sound conversion is a lookup in a table the deploy layer built
// itself, one entry per secret it wrote through this provider on this deploy.
// A reference this table does not contain is refused. That is not a
// consolation: it is exactly the property the contract asks for — "validate
// that the named store belongs to the selected compute provider and fail loudly
// otherwise" — obtained by construction instead of by comparing two strings
// that were never guaranteed to be drawn from the same vocabulary.
//
// The alternative, composing a Ref from the provider name and the secret's
// path, is a restatement of a provider's internal naming: compute/fake keys a
// secret by "placement/scope/name" and compute/aws by an SSM path. Getting that
// right for two providers is getting it wrong for the third.
type secretBinder struct {
	provider  string
	store     compute.SecretStore
	scope     string
	placement compute.Placement
	// storeName is the name the credential side uses for this provider's secret
	// store, from [Config.SecretStoreName]. Empty means only a reference that
	// names no store at all is accepted.
	storeName string
	// issued maps a secret's logical name to the reference this provider issued
	// when this module stored it.
	issued map[string]compute.Ref
}

func newSecretBinder(provider string, store compute.SecretStore, cfg Config, scope string) *secretBinder {
	return &secretBinder{
		provider:  provider,
		store:     store,
		scope:     scope,
		placement: cfg.Placement,
		storeName: strings.TrimSpace(cfg.SecretStoreName),
		issued:    map[string]compute.Ref{},
	}
}

// put stores a secret and records the reference the provider issued.
//
// The value is passed straight through: this module constructs a
// [compute.SecretValue] and never converts one back to a string, so the only
// place the material exists in this package is the argument to this call.
func (b *secretBinder) put(ctx context.Context, name string, value compute.SecretValue, labels map[string]string) (compute.Ref, error) {
	stored, err := b.store.Put(ctx, compute.SecretSpec{
		Name:      name,
		Placement: b.placement,
		Scope:     b.scope,
		Value:     value,
		Labels:    labels,
	})
	b.adopt(name, stored.Ref)
	if err != nil {
		return b.issued[name], fmt.Errorf("storing secret %q: %w", name, err)
	}
	if stored.Ref.IsZero() {
		return compute.Ref{}, fmt.Errorf("%w: secret store returned no reference", compute.ErrInvalidSpec)
	}
	// The revision Put reported is deliberately not recorded here. A pin is the
	// credential layer's decision -- it travels in credentials.SecretRef.Version
	// and this module passes it through in bind -- and a version this module
	// remembered from its own write would pin every later deploy to the revision
	// THIS one happened to create, which is a pin nobody asked for.
	return stored.Ref, nil
}

// adopt records a reference this module did not issue on this deploy — one read
// back from the application's recorded artifacts, say — so a secret stored by
// an earlier deploy can still be bound by this one.
func (b *secretBinder) adopt(name string, ref compute.Ref) {
	if ref.IsZero() {
		return
	}
	b.issued[name] = ref
}

// refs returns everything the binder knows about, for recording on the
// application.
func (b *secretBinder) refs() map[string]compute.Ref {
	if len(b.issued) == 0 {
		return nil
	}
	out := make(map[string]compute.Ref, len(b.issued))
	for k, v := range b.issued {
		out[k] = v
	}
	return out
}

// bindName binds an already-known secret to an environment variable.
//
// version pins a revision, empty meaning "current". It is passed through
// unvalidated on purpose: a revision is provider-issued and opaque here, so the
// only place that can say whether one exists is the provider, which refuses an
// unknown pin rather than falling back to current (compute.SecretBinding.Version).
// Validating it here would be this module guessing at another package's
// vocabulary -- the same mistake as composing a Ref from a path.
func (b *secretBinder) bindName(envName, secretName, version string) (compute.SecretBinding, error) {
	ref, ok := b.issued[secretName]
	if !ok {
		return compute.SecretBinding{}, fmt.Errorf("%w: secret %q is named by the application "+
			"but is not held by provider %q under scope %q, so there is nothing to bind %q to",
			ErrInvalidApplication, secretName, b.provider, b.scope, envName)
	}
	return compute.SecretBinding{EnvName: envName, Secret: ref, Version: version}, nil
}

// bind converts one credential-layer reference into a provider binding.
//
// Every refusal below is loud on purpose. A binding this module cannot make
// correctly is a workload that starts without a credential it was promised, and
// the failure then surfaces inside the application at some later moment as a
// missing environment variable — which is a much worse place to find out.
func (b *secretBinder) bind(ref credentials.SecretRef) (compute.SecretBinding, error) {
	if ref.IsZero() {
		return compute.SecretBinding{}, fmt.Errorf("%w: a workload material reference names no "+
			"secret", ErrInvalidApplication)
	}
	if ref.EnvVar == "" {
		return compute.SecretBinding{}, fmt.Errorf("%w: the reference to %s carries no target "+
			"environment variable, so there is nothing to bind it to", ErrInvalidApplication, ref)
	}
	if ref.Store != "" && ref.Store != b.storeName {
		if b.storeName == "" {
			return compute.SecretBinding{}, fmt.Errorf("%w: the reference to %s names store %q, "+
				"and no SecretStoreName is configured for compute provider %q, so this module "+
				"cannot establish that the two are the same store",
				ErrNotConfigured, ref, ref.Store, b.provider)
		}
		return compute.SecretBinding{}, fmt.Errorf("%w: the reference to %s is held by store %q, "+
			"and compute provider %q backs store %q; a provider handed a reference it did not "+
			"issue refuses it, and doing so here names the mismatch instead",
			ErrInvalidApplication, ref, ref.Store, b.provider, b.storeName)
	}
	// The pin travels through. USOSS-35 gave compute.SecretBinding a version
	// precisely so this conversion does not have to choose between refusing a
	// pinned reference and silently binding the current revision, and the
	// provider refuses a revision it cannot honour rather than falling back.
	binding, err := b.bindName(ref.EnvVar, ref.Name, ref.Version)
	if err != nil {
		return compute.SecretBinding{}, fmt.Errorf("%w (known here: %s)", err, b.knownNames())
	}
	return binding, nil
}

// knownNames lists what the binder holds, so a refusal tells an operator what
// the deploy did store rather than only what it could not find.
//
// Secret *names* are not material. They are already in the application record,
// in the workload's environment, and in the provider's own listings.
func (b *secretBinder) knownNames() string {
	if len(b.issued) == 0 {
		return "nothing"
	}
	names := make([]string, 0, len(b.issued))
	for name := range b.issued {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
