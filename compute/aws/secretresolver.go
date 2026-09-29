// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/conductorone/apphub/compute"
)

// providerSecretResolver adapts this provider's own SSM secret store to the
// container port's [SecretResolver] seam.
//
// # Why an adapter rather than converged signatures
//
// [SecretResolver] and the store's methods disagree in both directions, and
// each spelling is right for its own side:
//
//   - The seam takes [SecretBindingRef] — a flattened mirror of
//     [compute.SecretBinding] — so that a secret store implementing it carries
//     no dependency in the direction that would let it reach back into the
//     compute types it is being called from. The store, being in this package
//     and already holding [compute.SecretStore], has no such need and takes the
//     compute type directly.
//   - The seam returns a rendered document rather than a [PolicyDocument] for
//     the same reason: a policy document is this package's type, and a resolver
//     an operator writes must not need it.
//
// Converging them would mean picking one side's convenience over the other's
// isolation. Adapting them costs one small type that is the only thing in the
// package required to know both, and a compile-time assertion that it does.
//
// This is the wiring that was missing. [SecretResolver]'s doc comment claimed
// the store satisfied it while the compiler disagreed, no adapter existed
// anywhere in the repository, and every test and conformance run resolved
// secrets through a stub — so the port's headline capability, secret injection
// by reference from this provider's own store, had never once been composed.
type providerSecretResolver struct{ p *Provider }

// The claim in [SecretResolver]'s doc comment, made checkable. This is the
// assertion whose absence let the two spellings drift apart unnoticed.
var _ SecretResolver = providerSecretResolver{}

// SecretResolver returns a [SecretResolver] backed by this provider's own
// SSM-backed secret store.
//
// It is what [Config.ContainerConfig.Secrets] is defaulted to when an operator
// configures a secret store and a container runtime and does not name a
// resolver, which is the composition the ports were written for. It is exported
// so that the same wiring is available to an operator who builds the config by
// hand, and so that a caller with two providers can bind one's container port to
// the other's store deliberately rather than by accident.
//
// The returned resolver refuses everything if this provider has no secret store
// configured; see [Provider.SecretParameterARNs].
func (p *Provider) SecretResolver() SecretResolver { return providerSecretResolver{p: p} }

// SecretParameterARNs resolves each binding through the store, reading every
// ARN back from the substrate.
func (r providerSecretResolver) SecretParameterARNs(
	ctx context.Context, bindings []SecretBindingRef,
) ([]SecretParameterRef, error) {
	in := make([]compute.SecretBinding, 0, len(bindings))
	for _, b := range bindings {
		in = append(in, compute.SecretBinding{
			EnvName: b.EnvName,
			Secret:  b.ref(),
			Version: b.Version,
		})
	}
	return r.p.SecretParameterARNs(ctx, in)
}

// SecretReadPolicy renders the store's least-privilege document.
//
// The empty document is reported as an error rather than as an empty string.
// [Provider.SecretReadPolicy] returns a statement-less document for an empty
// ref list — correctly, because no references means no grant — but this method
// is only ever called with references, and rendering `{"Statement":[]}` into
// the execution role would attach a document IAM rejects. Saying so here is
// louder than an API error from the substrate.
func (r providerSecretResolver) SecretReadPolicy(refs []SecretParameterRef) (string, error) {
	doc, err := r.p.SecretReadPolicy(refs)
	if err != nil {
		return "", err
	}
	if doc.IsEmpty() {
		return "", fmt.Errorf("%w: the secret store produced a grant with no statements for %d "+
			"reference(s); an identity policy with no statements is not a valid document",
			compute.ErrFailed, len(refs))
	}
	rendered, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("%w: rendering the secret-read policy: %w", compute.ErrFailed, err)
	}
	return string(rendered), nil
}

// SecretPlacement reads back the placement the store recorded at Put.
func (r providerSecretResolver) SecretPlacement(
	ctx context.Context, binding SecretBindingRef,
) (string, error) {
	return r.p.SecretPlacement(ctx, binding.ref())
}

// ref reassembles the [compute.Ref] the flattened binding was built from.
//
// The seam flattens it so a resolver can say which part is wrong; this puts it
// back together, and the round trip is lossless because [compute.Ref] is
// exactly those three fields.
func (b SecretBindingRef) ref() compute.Ref {
	return compute.Ref{Provider: b.Provider, Kind: compute.Kind(b.Kind), ID: b.ID}
}

// secretResolver is the resolver the container port resolves bindings through:
// the one an operator named, or this provider's own store.
//
// SELF-COMPOSITION IS THE DEFAULT, and it is the whole reason this exists.
// [ContainerConfig.Secrets] is an interface so an operator CAN bind one
// provider's container port to another provider's store — a real need, and the
// reason the seam is not a direct call. But the overwhelmingly common
// configuration is one provider with both a secret store and a container
// runtime, and requiring an operator to hand-write glue to connect a provider to
// ITSELF is how the headline capability shipped uncomposed: nothing in the
// repository implemented the seam, so every test and every conformance run
// resolved secrets through a stub.
//
// Nil still refuses when there is nothing to fall back to. A provider with no
// [Config.Secrets] and a spec that binds secrets is [compute.ErrInvalidSpec],
// which is the direction [ContainerConfig.Secrets] documents: a workload
// silently started without the secrets it asked for either crashes on a missing
// variable — the good case — or runs degraded in a way nobody can see.
func (p *Provider) secretResolver() SecretResolver {
	if p.cfg.Container != nil && p.cfg.Container.Secrets != nil {
		return p.cfg.Container.Secrets
	}
	if p.secret == nil {
		return nil
	}
	return p.SecretResolver()
}
