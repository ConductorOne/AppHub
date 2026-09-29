// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// material is the value every test in this file stores. It is distinctive so
// that finding it anywhere it should not be is unambiguous, and it is the same
// shape of check the conformance suite makes with its own sentinel.
const material = "usoss26-material-never-log-4d91be07"

func newStore(t *testing.T, mutate func(*aws.Config)) (*aws.Provider, *aws.MemoryParameters, compute.SecretStore) {
	t.Helper()
	sub := aws.NewMemorySubstrate()
	params := sub.Parameters.(*aws.MemoryParameters)
	cfg := secretStoreConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	p := providerOver(t, sub, cfg)
	store, err := p.Secrets()
	if err != nil {
		t.Fatalf("Secrets(): %v", err)
	}
	return p, params, store
}

func put(t *testing.T, store compute.SecretStore, scope, name, value string, labels map[string]string) compute.Ref {
	t.Helper()
	return putStored(t, store, scope, name, value, labels).Ref
}

// putStored is put where the caller also wants the revision the write created.
func putStored(t *testing.T, store compute.SecretStore, scope, name, value string, labels map[string]string) compute.StoredSecret {
	t.Helper()
	stored, err := store.Put(context.Background(), compute.SecretSpec{
		Name:   name,
		Scope:  scope,
		Value:  compute.NewSecretValue(value),
		Labels: labels,
	})
	if err != nil {
		t.Fatalf("Put(%s/%s): %v", scope, name, err)
	}
	return stored
}

// --- the three behaviours the ticket requires be defined rather than inherited
// from whatever the SDK does ------------------------------------------------

// TestPutExistingOwnedReplaces is the "parameter already exists" case for a
// parameter this platform created: the interface documents Put as idempotent, so
// the second write has to succeed, return the same reference, and be visible.
func TestPutExistingOwnedReplaces(t *testing.T) {
	t.Parallel()
	_, params, store := newStore(t, nil)
	first := put(t, store, "app-1", "TOKEN", material, nil)
	second := put(t, store, "app-1", "TOKEN", material+"-rotated", nil)
	if first != second {
		t.Fatalf("re-Put returned %s, want %s: a teardown that reconstructs the reference from the "+
			"logical name would address nothing", second, first)
	}
	got, err := store.Get(context.Background(), second)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if compute.RevealSecret(got) != material+"-rotated" {
		t.Fatal("the second Put did not replace the value")
	}
	if names := params.Names(); len(names) != 1 {
		t.Fatalf("the store holds %d parameters after two Puts of one secret: %v", len(names), names)
	}
}

// TestPutExistingUnownedIsConflict is the same case for a parameter this
// platform did not create. Adopting it would replace somebody else's
// credential, and parameter names derive from mutable application names, so the
// collision is reachable without anybody doing anything strange.
func TestPutExistingUnownedIsConflict(t *testing.T) {
	t.Parallel()
	_, params, store := newStore(t, nil)
	ref := put(t, store, "app-1", "TOKEN", material, nil)
	if err := store.Delete(context.Background(), ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	params.PutUnowned(paramOf(t, ref), compute.NewSecretValue("somebody-elses-material"))

	_, err := store.Put(context.Background(), compute.SecretSpec{
		Name: "TOKEN", Scope: "app-1", Value: compute.NewSecretValue(material),
	})
	if !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("Put over an unowned parameter returned %v, want compute.ErrNotOwned", err)
	}
	// And it did not write.
	got, err := params.Get(context.Background(), paramOf(t, ref))
	if err != nil {
		t.Fatalf("the unowned parameter is gone: %v", err)
	}
	if compute.RevealSecret(got) != "somebody-elses-material" {
		t.Fatal("the refusal still overwrote the unowned parameter's value")
	}
}

// TestPutValueTooLargeForTier is the "value too large for the tier" case.
//
// Three things are asserted, and the second and third are the ones an
// implementation is likely to miss: the refusal is a caller-fixable spec error
// rather than an infrastructure failure, the value never reached the substrate,
// and the error does not carry the material.
func TestPutValueTooLargeForTier(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		tier  aws.ParameterTier
		limit int
	}{
		{aws.TierStandard, aws.MaxStandardValueBytes},
		{aws.TierAdvanced, aws.MaxAdvancedValueBytes},
	} {
		t.Run(string(tc.tier), func(t *testing.T) {
			t.Parallel()
			_, params, store := newStore(t, func(c *aws.Config) { c.Secrets.Tier = tc.tier })
			oversize := material + strings.Repeat("x", tc.limit)
			_, err := store.Put(context.Background(), compute.SecretSpec{
				Name: "BIG", Scope: "app-1", Value: compute.NewSecretValue(oversize),
			})
			if !errors.Is(err, compute.ErrInvalidSpec) {
				t.Fatalf("Put of an oversize value returned %v, want compute.ErrInvalidSpec", err)
			}
			if names := params.Names(); len(names) != 0 {
				t.Fatalf("the oversize value reached the substrate: %v", names)
			}
			if strings.Contains(err.Error(), material) {
				t.Fatal("the refusal carries the material")
			}
			if !strings.Contains(err.Error(), fmt.Sprint(tc.limit)) {
				t.Fatalf("the refusal does not name the %d-byte limit, so a caller cannot act on "+
					"it: %v", tc.limit, err)
			}
			// A value exactly at the limit is accepted: the boundary is the
			// limit, not one below it.
			atLimit := strings.Repeat("y", tc.limit)
			if _, err := store.Put(context.Background(), compute.SecretSpec{
				Name: "EXACT", Scope: "app-1", Value: compute.NewSecretValue(atLimit),
			}); err != nil {
				t.Fatalf("a value of exactly %d bytes was refused: %v", tc.limit, err)
			}
		})
	}
}

// TestGetNonexistentReference is the "read of a nonexistent reference" case.
//
// The three shapes of "nonexistent" are kept apart on purpose, because a caller
// acts differently on each: a deleted secret is ErrNotFound and can be
// recreated, another provider's reference is ErrForeignRef and must not be,
// and a reference outside this store's configured prefix is a spec error.
func TestGetNonexistentReference(t *testing.T) {
	t.Parallel()
	p, _, store := newStore(t, nil)
	ctx := context.Background()

	ref := put(t, store, "app-1", "TOKEN", material, nil)
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, ref); !errors.Is(err, compute.ErrNotFound) {
		t.Fatalf("Get of a deleted secret returned %v, want compute.ErrNotFound", err)
	}

	foreign := compute.Ref{Provider: "somebody-else", Kind: compute.KindSecret, ID: ref.ID}
	_, err := store.Get(ctx, foreign)
	if !errors.Is(err, compute.ErrForeignRef) {
		t.Fatalf("Get of a foreign reference returned %v, want compute.ErrForeignRef", err)
	}
	if errors.Is(err, compute.ErrNotFound) {
		t.Fatal("a foreign reference reported as ErrNotFound: a caller would conclude the secret " +
			"had been deleted and write material somewhere it does not belong")
	}

	outside := compute.Ref{Provider: p.Name(), Kind: compute.KindSecret, ID: "/somebody/elses/tree/TOKEN"}
	if _, err := store.Get(ctx, outside); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("Get outside the configured prefix returned %v, want compute.ErrInvalidSpec", err)
	}
	if err := store.Delete(ctx, outside); !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("Delete outside the configured prefix returned %v; a stale reference from a "+
			"differently-configured provider must not be able to delete anything", err)
	}
}

// --- the security bar -------------------------------------------------------

// TestNoMaterialInAnyError states the invariant as a property rather than as a
// list of cases: every way this store can be made to fail while holding
// material produces an error that does not contain it.
//
// The list of ways is what makes it useful, and it is deliberately every failure
// path the port has rather than the two the conformance suite drives.
func TestNoMaterialInAnyError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secret := compute.NewSecretValue(material)

	cases := []struct {
		what string
		call func(t *testing.T) error
	}{
		{"an empty name", func(t *testing.T) error {
			_, _, store := newStore(t, nil)
			_, err := store.Put(ctx, compute.SecretSpec{Name: "", Scope: "app-1", Value: secret})
			return err
		}},
		{"an empty scope", func(t *testing.T) error {
			_, _, store := newStore(t, nil)
			_, err := store.Put(ctx, compute.SecretSpec{Name: "TOKEN", Scope: "", Value: secret})
			return err
		}},
		{"a value over the tier limit", func(t *testing.T) error {
			_, _, store := newStore(t, nil)
			big := compute.NewSecretValue(material + strings.Repeat("x", aws.MaxStandardValueBytes))
			_, err := store.Put(ctx, compute.SecretSpec{Name: "TOKEN", Scope: "app-1", Value: big})
			return err
		}},
		{"a label AWS cannot carry as a tag", func(t *testing.T) error {
			_, _, store := newStore(t, nil)
			_, err := store.Put(ctx, compute.SecretSpec{
				Name: "TOKEN", Scope: "app-1", Value: secret,
				Labels: map[string]string{"a": strings.Repeat("v", 4096)},
			})
			return err
		}},
		{"a hierarchy deeper than SSM allows", func(t *testing.T) error {
			_, _, store := newStore(t, func(c *aws.Config) {
				c.Secrets.PathPrefix = strings.Repeat("/l", 14)
			})
			_, err := store.Put(ctx, compute.SecretSpec{Name: "TOKEN", Scope: "app-1", Value: secret})
			return err
		}},
		{"a collision with an unowned parameter", func(t *testing.T) error {
			_, params, store := newStore(t, nil)
			// The colliding name is DERIVED, not spelled out. It used to be
			// spelled "/…/app-1/TOKEN", and that stopped colliding the moment the
			// naming function folded case and appended a digest -- so the case
			// silently became "Put over an empty path", which succeeds, and a
			// test that must fail was passing for the wrong reason. Deriving it
			// costs one Put and one Delete and cannot drift.
			ref := put(t, store, "app-1", "TOKEN", material, nil)
			name := paramOf(t, ref)
			if err := params.Delete(ctx, name); err != nil {
				t.Fatalf("clearing the derived name: %v", err)
			}
			params.PutUnowned(name, compute.NewSecretValue("other"))
			_, err := store.Put(ctx, compute.SecretSpec{Name: "TOKEN", Scope: "app-1", Value: secret})
			return err
		}},
		{"a substrate that throttles the create", func(t *testing.T) error {
			_, params, store := newStore(t, nil)
			params.FailNext(fmt.Errorf("%w: slow down", aws.ErrThrottled))
			_, err := store.Put(ctx, compute.SecretSpec{Name: "TOKEN", Scope: "app-1", Value: secret})
			return err
		}},
		{"a substrate that fails the tag convergence after the value is written", func(t *testing.T) error {
			_, params, store := newStore(t, nil)
			put(t, store, "app-1", "TOKEN", material, map[string]string{"a": "1"})
			// The re-Put's call sequence is: the create-only Put (which
			// collides), the ownership read, the tier read, the overwriting Put,
			// and then the tag convergence. Failing the last of those is the
			// case the source system got wrong by ignoring it.
			params.FailAfter(4, errors.New("aws: tagging refused"))
			_, err := store.Put(ctx, compute.SecretSpec{
				Name: "TOKEN", Scope: "app-1", Value: secret,
				Labels: map[string]string{"b": "2"},
			})
			return err
		}},
		{"a read of a deleted secret", func(t *testing.T) error {
			_, _, store := newStore(t, nil)
			ref := put(t, store, "app-1", "TOKEN", material, nil)
			if err := store.Delete(ctx, ref); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			_, err := store.Get(ctx, ref)
			return err
		}},
		{"a tier downgrade over an advanced parameter", func(t *testing.T) error {
			params := aws.NewMemoryParameters()
			sub := aws.NewMemorySubstrate()
			sub.Parameters = params
			advanced := secretStoreConfig()
			advanced.Secrets.Tier = aws.TierAdvanced
			hi := providerOver(t, sub, advanced)
			hiStore, err := hi.Secrets()
			if err != nil {
				t.Fatalf("Secrets(): %v", err)
			}
			put(t, hiStore, "app-1", "TOKEN", material, nil)
			standard := secretStoreConfig()
			standard.Secrets.Tier = aws.TierStandard
			lo := providerOver(t, sub, standard)
			loStore, err := lo.Secrets()
			if err != nil {
				t.Fatalf("Secrets(): %v", err)
			}
			_, err = loStore.Put(ctx, compute.SecretSpec{Name: "TOKEN", Scope: "app-1", Value: secret})
			return err
		}},
		{"a DeleteScope with no scope", func(t *testing.T) error {
			_, _, store := newStore(t, nil)
			return store.DeleteScope(ctx, "")
		}},
		{"a DeleteScope over somebody else's parameter", func(t *testing.T) error {
			_, params, store := newStore(t, nil)
			put(t, store, "app-1", "TOKEN", material, nil)
			params.PutUnowned("/apphub/conformance/apps/app-1/THEIRS", compute.NewSecretValue("other"))
			return store.DeleteScope(ctx, "app-1")
		}},
	}

	failed := 0
	for _, tc := range cases {
		t.Run(tc.what, func(t *testing.T) {
			err := tc.call(t)
			if err == nil {
				t.Fatalf("expected %s to fail; a case that succeeds searches no error path", tc.what)
			}
			// Every formatting verb, not just %v: the one a developer reaches
			// for when debugging is the one that leaks.
			for _, rendered := range []string{
				err.Error(),
				fmt.Sprintf("%v", err),
				fmt.Sprintf("%+v", err),
				fmt.Sprintf("%#v", err),
				fmt.Sprintf("%q", err),
			} {
				if strings.Contains(rendered, material) {
					t.Fatalf("the error from %s contains the material", tc.what)
				}
			}
		})
		failed++
	}
	if failed != len(cases) {
		t.Fatalf("%d of %d cases ran", failed, len(cases))
	}
}

// TestSpecFormattingDoesNotLeak is the other half of the same invariant. An
// error is not the only thing that gets logged; a provider that logged the spec
// it could not satisfy would leak just as surely, so the spec itself has to
// redact under every verb.
func TestSpecFormattingDoesNotLeak(t *testing.T) {
	t.Parallel()
	spec := compute.SecretSpec{
		Name: "TOKEN", Scope: "app-1", Value: compute.NewSecretValue(material),
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		rendered := fmt.Sprintf(verb, spec)
		if strings.Contains(rendered, material) {
			t.Fatalf("compute.SecretSpec formatted with %s contains the material", verb)
		}
	}
}

// TestRenderedArtefactsCarryNoMaterial covers the operator-facing dump the
// conformance suite inspects, and covers it directly rather than only through
// the suite: Parameter Store is where this provider's material lives, so a dump
// of it is the most likely place for a value to appear by accident.
func TestRenderedArtefactsCarryNoMaterial(t *testing.T) {
	t.Parallel()
	p, _, store := newStore(t, nil)
	put(t, store, "app-1", "TOKEN", material, map[string]string{"owner": "test"})
	rendered, err := p.Harness().Rendered(context.Background())
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	if len(rendered) == 0 {
		t.Fatal("nothing was rendered, so the check proved nothing")
	}
	joined := strings.Join(rendered, "\n")
	if strings.Contains(joined, material) {
		t.Fatal("a rendered artefact contains the material")
	}
	// The metadata that makes the dump worth having is there.
	for _, want := range []string{"type=SecureString", "owner=test", "managedBy=apphub"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the rendered artefacts do not mention %q: %s", want, joined)
		}
	}
}

// TestEveryParameterIsSecureString is a small check on a decision that has no
// configuration behind it. If a knob for the parameter type is ever added, this
// is where it fails.
func TestEveryParameterIsSecureString(t *testing.T) {
	t.Parallel()
	p, _, store := newStore(t, nil)
	put(t, store, "app-1", "TOKEN", material, nil)
	rendered, err := p.Harness().Rendered(context.Background())
	if err != nil {
		t.Fatalf("Rendered: %v", err)
	}
	for _, line := range rendered {
		if strings.HasPrefix(line, "role/") {
			continue
		}
		if !strings.Contains(line, "type=SecureString") {
			t.Fatalf("parameter rendered as %q, which is not a SecureString", line)
		}
	}
}

// --- ownership, naming and scope isolation ---------------------------------

// TestLabelCannotForgeOwnership is the check behind namespacing the caller's
// labels. Without the prefix, a caller could pass a label named exactly like the
// ownership tag and make its own parameter look like this platform's — or, worse,
// make somebody else's look adoptable.
func TestLabelCannotForgeOwnership(t *testing.T) {
	t.Parallel()
	_, params, store := newStore(t, nil)
	ref := put(t, store, "app-1", "TOKEN", material,
		map[string]string{"apphub:managed-by": "apphub", "apphub.dev/scope": "elsewhere"})
	tags, err := params.Tags(context.Background(), paramOf(t, ref))
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if tags["apphub:managed-by"] != "apphub" {
		t.Fatal("the provider's own ownership tag is missing")
	}
	// The caller's versions landed under the label namespace, not on top of the
	// provider's.
	if got := tags["apphub:label/apphub:managed-by"]; got != "apphub" {
		t.Fatalf("the caller's label was not namespaced: %v", tags)
	}
	if got := tags["apphub:label/apphub.dev/scope"]; got != "elsewhere" {
		t.Fatalf("the caller's label was not namespaced: %v", tags)
	}
	if tags["apphub.dev/scope"] == "elsewhere" {
		t.Fatal("a caller label overwrote the provider's scope tag")
	}
}

// The operator-tag version of the property above is GONE, and deliberately so
// rather than overlooked.
//
// This branch's own AWS spine had a Config.Tags: operator-wide tags applied to
// every resource, with a check that they could not name anything under the
// reserved prefix and so could not forge the ownership marker. The spine landed
// upstream in USOSS-10 without that feature, so there are no operator tags to
// forge, and a test asserting that a non-existent input is rejected is a green
// tick with no input -- the same shape as a check whose precondition is gone.
//
// The caller-label half is still asserted, above: a caller's label cannot reach
// the reserved namespace, because tagLabelPrefix makes it unsayable rather than
// merely forbidden. If operator tags come back, this property comes back with
// them, and it belongs to whoever adds the field.

// TestDistinctScopesCannotShareAPath is a privilege boundary rather than a
// naming nicety. Two scopes that collapsed onto one path would put one
// application's secrets where another application's least-privilege grant
// already reaches.
func TestDistinctScopesCannotShareAPath(t *testing.T) {
	t.Parallel()
	_, _, store := newStore(t, nil)
	// Scopes that a naive slug would flatten together: different case,
	// different separators, and one that is not a legal path segment at all.
	scopes := []string{
		"app-1", "APP-1", "app_1", "app.1", "app/1", "app 1", "../app-1",
		"app-1-" + strings.Repeat("z", 80), "app-1-" + strings.Repeat("y", 80),
	}
	seen := map[string]string{}
	for _, scope := range scopes {
		ref := put(t, store, scope, "TOKEN", material, nil)
		name := paramOf(t, ref)
		if other, clash := seen[name]; clash {
			t.Fatalf("scopes %q and %q both produced parameter %s", other, scope, name)
		}
		seen[name] = scope
		if strings.Contains(name, "..") {
			t.Fatalf("scope %q produced a path with a traversal in it: %s", scope, name)
		}
		if !strings.HasPrefix(name, "/apphub/conformance/apps/") {
			t.Fatalf("scope %q escaped the configured prefix: %s", scope, name)
		}
		if strings.Count(name, "/") != 5 {
			t.Fatalf("scope %q produced %d hierarchy levels, so it added or removed one: %s",
				scope, strings.Count(name, "/"), name)
		}
	}
	if len(seen) != len(scopes) {
		t.Fatalf("%d scopes produced %d paths", len(scopes), len(seen))
	}
}

// TestDeleteScopeIsHierarchical is the other half of that: a scope path must not
// enumerate a sibling whose name merely starts with it.
func TestDeleteScopeIsHierarchical(t *testing.T) {
	t.Parallel()
	_, params, store := newStore(t, nil)
	keep := put(t, store, "app-1x", "TOKEN", material, nil)
	put(t, store, "app-1", "TOKEN", material, nil)
	if err := store.DeleteScope(context.Background(), "app-1"); err != nil {
		t.Fatalf("DeleteScope: %v", err)
	}
	names := params.Names()
	if want := paramOf(t, keep); len(names) != 1 || names[0] != want {
		t.Fatalf("DeleteScope(app-1) left %v, want only %s", names, want)
	}
}

// TestDeleteScopeLeavesForeignParametersAndSaysSo is the fail-closed half of
// teardown. Deleting a parameter this platform did not create would destroy
// somebody else's material; skipping it silently would make a teardown that left
// credentials behind look like a clean one.
func TestDeleteScopeLeavesForeignParametersAndSaysSo(t *testing.T) {
	t.Parallel()
	_, params, store := newStore(t, nil)
	mine := put(t, store, "app-1", "MINE", material, nil)
	theirs := "/apphub/conformance/apps/app-1/THEIRS"
	params.PutUnowned(theirs, compute.NewSecretValue("somebody-elses-material"))

	err := store.DeleteScope(context.Background(), "app-1")
	if !errors.Is(err, compute.ErrNotOwned) {
		t.Fatalf("DeleteScope returned %v, want compute.ErrNotOwned", err)
	}
	if !strings.Contains(err.Error(), theirs) {
		t.Fatalf("the refusal does not name what it left behind: %v", err)
	}
	names := params.Names()
	if len(names) != 1 || names[0] != theirs {
		t.Fatalf("after DeleteScope the store holds %v; it should have deleted %s and kept %s",
			names, mine.ID, theirs)
	}
}

// TestDeleteScopeIsRerunnable covers teardown after a partial failure: the
// second run finds its work done and says nothing.
func TestDeleteScopeIsRerunnable(t *testing.T) {
	t.Parallel()
	_, _, store := newStore(t, nil)
	put(t, store, "app-1", "A", material, nil)
	put(t, store, "app-1", "B", material, nil)
	for i := range 3 {
		if err := store.DeleteScope(context.Background(), "app-1"); err != nil {
			t.Fatalf("DeleteScope run %d: %v", i+1, err)
		}
	}
}

// TestTagsConvergeOnTheSpec is the declarative half of Put. A label present in
// one deploy's spec and absent from the next has to be gone, and a tag this
// provider does not manage has to survive.
func TestTagsConvergeOnTheSpec(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, params, store := newStore(t, nil)
	ref := put(t, store, "app-1", "TOKEN", material, map[string]string{"owner": "a", "extra": "present"})
	// Somebody else's tag, applied out of band.
	if err := params.SetTags(ctx, paramOf(t, ref), map[string]string{"cost-centre": "theirs"}, nil); err != nil {
		t.Fatalf("SetTags: %v", err)
	}
	put(t, store, "app-1", "TOKEN", material, map[string]string{"owner": "b"})

	tags, err := params.Tags(ctx, paramOf(t, ref))
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if got, ok := tags["apphub:label/extra"]; ok {
		t.Fatalf("the removed label is still present as %q; Put added rather than converged", got)
	}
	if tags["apphub:label/owner"] != "b" {
		t.Fatalf("the changed label did not converge: %v", tags)
	}
	if tags["cost-centre"] != "theirs" {
		t.Fatal("convergence removed a tag this provider does not manage")
	}
	if !strings.HasPrefix(tags["apphub:managed-by"], "apphub") {
		t.Fatal("convergence dropped the ownership tag")
	}
}

// The operator-tag convergence test is gone with the feature, and the property it
// carried is not lost: "a tag this provider manages is removed when it stops
// being desired" is exactly what TestTagsConvergeOnTheSpec asserts over a caller
// LABEL, which is a live input on this branch. Operator tags are not.
//
// Worth naming, because it was one of this ticket's own findings: the first draft
// applied operator tags and never removed one when the configuration dropped it,
// and the fix was to record which keys had been applied. That defect cannot exist
// without the feature, and re-adding the feature means re-adding the test.

// TestPutRejectsAnEmptyValue keeps a fail-open case closed: an empty
// SecureString would inject an empty credential into a workload.
func TestPutRejectsAnEmptyValue(t *testing.T) {
	t.Parallel()
	_, params, store := newStore(t, nil)
	_, err := store.Put(context.Background(), compute.SecretSpec{
		Name: "TOKEN", Scope: "app-1", Value: compute.SecretValue{},
	})
	if !errors.Is(err, compute.ErrInvalidSpec) {
		t.Fatalf("Put of an empty value returned %v, want compute.ErrInvalidSpec", err)
	}
	if names := params.Names(); len(names) != 0 {
		t.Fatalf("an empty secret was written: %v", names)
	}
}

// TestWrongKindReferenceIsRefused covers the Kind field's whole purpose: a
// reference read back out of persistence is checked against the method it is
// about to be passed to.
func TestWrongKindReferenceIsRefused(t *testing.T) {
	t.Parallel()
	p, _, store := newStore(t, nil)
	wrong := compute.Ref{Provider: p.Name(), Kind: compute.KindBucket, ID: "/apphub/conformance/apps/a/B"}
	if _, err := store.Get(context.Background(), wrong); err == nil {
		t.Fatal("Get accepted a bucket reference")
	}
	if err := store.Delete(context.Background(), wrong); err == nil {
		t.Fatal("Delete accepted a bucket reference and reported success; Delete is idempotent for " +
			"its own kind, not for every kind")
	}
}

// TestConfigRefusals is the fail-closed half of construction. Each of these was
// a default or a silent degradation somewhere in the source system.
func TestConfigRefusals(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		what string
		// wrapped says whether the refusal carries compute.ErrInvalidSpec.
		//
		// It is a per-case field rather than a blanket assertion because the two
		// halves are refused by different code with different contracts. A bad
		// SecretConfig is refused by this port, which wraps the sentinel because
		// a caller may reasonably branch on it. A bad Config or an incomplete
		// Substrate is refused by the provider's own construction, in main's
		// spine, with a plain error -- and that is right: New is not a port call,
		// there is no provider yet to have a taxonomy, and the only caller is the
		// operator's wiring code, which cannot usefully branch.
		//
		// The earlier version of this table asserted the sentinel for every case,
		// which was a claim about a convention this package does not have. Making
		// it a field states the boundary instead of quietly forking the
		// convention or quietly dropping the assertion.
		wrapped bool
		mutate  func(*aws.Config)
		sub     *aws.Substrate
	}{
		{"no region", false, func(c *aws.Config) { c.Region = "" }, aws.NewMemorySubstrate()},
		// "a region that is not one" is gone: main's spine requires the region to
		// be non-empty and does not check its shape, and a wrong-but-well-formed
		// region is caught by the first API call rather than by a pattern this
		// package would have to keep up to date. Not a defect -- a different and
		// defensible line, and this package does not get to hold two.
		{"a colon in the provider name", false, func(c *aws.Config) { c.Name = "aws:prod" }, aws.NewMemorySubstrate()},
		{"no parameter prefix", true, func(c *aws.Config) { c.Secrets.PathPrefix = "" }, aws.NewMemorySubstrate()},
		{"a relative parameter prefix", true, func(c *aws.Config) { c.Secrets.PathPrefix = "apphub" }, aws.NewMemorySubstrate()},
		{"a trailing slash on the prefix", true, func(c *aws.Config) { c.Secrets.PathPrefix = "/apphub/" }, aws.NewMemorySubstrate()},
		{"an SSM-reserved prefix", true, func(c *aws.Config) { c.Secrets.PathPrefix = "/aws/apphub" }, aws.NewMemorySubstrate()},
		{"an SSM-reserved prefix in another case", true, func(c *aws.Config) { c.Secrets.PathPrefix = "/SSM/apphub" }, aws.NewMemorySubstrate()},
		{"a KMS key that is not an ARN", true, func(c *aws.Config) { c.Secrets.KMSKeyARN = "alias/k" }, aws.NewMemorySubstrate()},
		{"intelligent tiering", true, func(c *aws.Config) { c.Secrets.Tier = "Intelligent-Tiering" }, aws.NewMemorySubstrate()},
		{"a tier that is not one", true, func(c *aws.Config) { c.Secrets.Tier = "cheap" }, aws.NewMemorySubstrate()},
		{"no parameter store in the substrate", false, nil, &aws.Substrate{IAM: aws.NewMemoryIAM()}},
		{"no role store in the substrate", false, nil, &aws.Substrate{Parameters: aws.NewMemoryParameters()}},
		{"an empty substrate", false, nil, &aws.Substrate{}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			cfg := secretStoreConfig()
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}
			p, err := aws.New(tc.sub, cfg)
			if err == nil {
				t.Fatalf("New with %s returned a usable provider", tc.what)
			}
			if tc.wrapped && !errors.Is(err, compute.ErrInvalidSpec) {
				t.Fatalf("New with %s returned %v, want it to wrap compute.ErrInvalidSpec", tc.what, err)
			}
			if !tc.wrapped && errors.Is(err, compute.ErrInvalidSpec) {
				t.Fatalf("New with %s wraps compute.ErrInvalidSpec (%v); this table records which "+
					"half refuses which, so a change of convention should update the field rather "+
					"than pass silently", tc.what, err)
			}
			if p != nil {
				t.Fatalf("New returned both an error and a provider for %s", tc.what)
			}
		})
	}
	t.Run("a nil substrate", func(t *testing.T) {
		t.Parallel()
		if _, err := aws.New(nil, secretStoreConfig()); err == nil {
			t.Fatal("New(nil, …) returned a usable provider")
		}
	})
}

// TestNoAccountIdentifierInAReference is the property that keeps the account out
// of every persisted application record: a Ref is the thing a caller stores, and
// it carries a parameter path, not an ARN.
func TestNoAccountIdentifierInAReference(t *testing.T) {
	t.Parallel()
	_, _, store := newStore(t, nil)
	ref := put(t, store, "app-1", "TOKEN", material, nil)
	for _, rendered := range []string{ref.ID, ref.String()} {
		if strings.Contains(rendered, aws.MemoryAccount) {
			t.Fatalf("the reference carries the account identifier: %s", rendered)
		}
		if strings.Contains(rendered, "arn:") {
			t.Fatalf("the reference is an ARN: %s", rendered)
		}
	}
}

// TestNoForeignErrorTextReachesACaller is the (a) fix, and it is stated over
// EVERY arm of the classifier rather than over the one that was reproduced.
//
// Substrate.Parameters is an interface, so a caller supplies the adapter and
// writes its error text. Review planted a marker in a plain error and read it
// back out of SecretStore.Put. The reproduction went through one arm; four of the
// five retained the chain. Sanitising the reproduced arm would have left three
// live, and a green test against the plain-error case would have read as closure
// -- so the population here is the classifier's arms, and every arm is driven
// with BOTH shapes:
//
//   - a plain foreign error, which falls to the default arm; and
//   - a foreign error WRAPPING one of this package's sentinels, which is how a
//     real adapter reports a recognised condition and which reaches the four
//     classified arms.
//
// A test planting only errors.New exercises one arm of five. That is the same
// route-versus-population shape as the defect itself.
func TestNoForeignErrorTextReachesACaller(t *testing.T) {
	t.Parallel()

	const marker = "REVIEW-CREDENTIAL-MATERIAL-7b5c2a"

	// Every sentinel the classifier branches on, plus the unclassified case.
	// Derived from wrap's arms rather than chosen: if an arm is added without a
	// row here, the count assertion below fails.
	arms := map[string]error{
		"default (unrecognised)": errors.New(marker),
		"not-found":              fmt.Errorf("%w: %s", aws.ErrParameterNotFound, marker),
		"too-large":              fmt.Errorf("%w: %s", aws.ErrParameterTooLarge, marker),
		"already-exists":         fmt.Errorf("%w: %s", aws.ErrParameterExists, marker),
		"throttled":              fmt.Errorf("%w: %s", aws.ErrThrottled, marker),
		"denied":                 fmt.Errorf("%w: %s", aws.ErrDenied, marker),

		// The two arms round two found, and note the SHAPE: the marker wraps the
		// sentinel rather than following it. A plain context.Canceled cannot
		// reproduce the defect, because the leak was "return the error you
		// recognised" and a bare sentinel has nothing to leak. An adapter's
		// cancellation arrives wrapped in the adapter's own text.
		"cancelled": fmt.Errorf("%s: %w", marker, context.Canceled),
		"deadline":  fmt.Errorf("%s: %w", marker, context.DeadlineExceeded),
	}
	// The arm count is NOT asserted here against a literal. It is derived from
	// wrap's own switch by TestEveryArmOfWrapIsCovered, because the check this
	// replaces compared a literal map against a literal 6 -- two hand-written
	// numbers agreeing, which is how the seventh arm slipped past.

	// Every method of the port, because the classifier is shared but each method
	// reaches it by its own path -- and a path that returned the substrate error
	// without classifying would be invisible to a single-method test.
	for armName, foreign := range arms {
		for _, call := range []struct {
			what string
			do   func(compute.SecretStore, compute.Ref) error
		}{
			{"Put", func(st compute.SecretStore, _ compute.Ref) error {
				_, err := st.Put(context.Background(), compute.SecretSpec{
					Name: "TOKEN", Scope: "app-1", Value: compute.NewSecretValue(material),
				})
				return err
			}},
			{"Get", func(st compute.SecretStore, ref compute.Ref) error {
				_, err := st.Get(context.Background(), ref)
				return err
			}},
			{"Delete", func(st compute.SecretStore, ref compute.Ref) error {
				return st.Delete(context.Background(), ref)
			}},
			{"DeleteScope", func(st compute.SecretStore, _ compute.Ref) error {
				return st.DeleteScope(context.Background(), "app-1")
			}},
		} {
			t.Run(armName+"/"+call.what, func(t *testing.T) {
				t.Parallel()
				_, params, store := newStore(t, nil)
				ref := put(t, store, "app-1", "TOKEN", material, nil)

				params.Fail(foreign)
				defer params.Fail(nil)

				err := call.do(store, ref)
				if err == nil {
					// One cell legitimately succeeds and it is named rather than
					// tolerated: Delete is documented idempotent, so a substrate
					// that reports the parameter absent is the outcome Delete
					// wanted. Any OTHER combination succeeding means the case
					// exercised no error path and proves nothing.
					//
					// RETIRES WHEN: Delete stops treating a missing parameter as
					// success. Then this branch fires and the exemption is gone.
					if armName == "not-found" && call.what == "Delete" {
						return
					}
					t.Fatalf("%s succeeded against a failing substrate, so this case searches no "+
						"error path", call.what)
				}
				// Every verb, not just %v: the one a developer reaches for when
				// debugging is the one that leaks.
				for _, format := range []string{"%v", "%s", "%+v", "%#v", "%q"} {
					if rendered := fmt.Sprintf(format, err); strings.Contains(rendered, marker) {
						t.Errorf("the %s arm of wrap carried caller-supplied text out of %s under "+
							"%s: %s", armName, call.what, format, rendered)
					}
				}
				// And not through the chain either: errors.Unwrap walks to the
				// foreign error if it was retained, and its Error() is the text.
				for u := errors.Unwrap(err); u != nil; u = errors.Unwrap(u) {
					if strings.Contains(u.Error(), marker) {
						t.Errorf("the %s arm of %s retained the foreign error in its chain: %v",
							armName, call.what, u)
					}
				}
			})
		}
	}
}

// TestTheClassificationSurvivesTheSanitising is the other half: dropping the
// foreign chain must not drop the taxonomy, which is the only thing a caller can
// act on. Without this, the fix above is satisfied by returning a bare string.
func TestTheClassificationSurvivesTheSanitising(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		what    string
		foreign error
		want    error
		wantNot []error
	}{
		{"not-found", fmt.Errorf("%w: x", aws.ErrParameterNotFound), compute.ErrNotFound, nil},
		{"too-large", fmt.Errorf("%w: x", aws.ErrParameterTooLarge), compute.ErrInvalidSpec, nil},
		{"already-exists", fmt.Errorf("%w: x", aws.ErrParameterExists), compute.ErrTransient, nil},
		{"throttled", fmt.Errorf("%w: x", aws.ErrThrottled), compute.ErrTransient,
			[]error{compute.ErrFailed, compute.ErrNotOwned}},
		{"denied", fmt.Errorf("%w: x", aws.ErrDenied), compute.ErrNotPermitted,
			[]error{compute.ErrFailed}},
		{"unrecognised", errors.New("x"), compute.ErrFailed, nil},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			_, params, store := newStore(t, nil)
			params.Fail(tc.foreign)
			defer params.Fail(nil)
			_, err := store.Put(context.Background(), compute.SecretSpec{
				Name: "TOKEN", Scope: "app-1", Value: compute.NewSecretValue(material),
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("a %s substrate error classified as %v, want %v", tc.what, err, tc.want)
			}
			for _, w := range tc.wantNot {
				if errors.Is(err, w) {
					t.Errorf("a %s substrate error also classified as %v", tc.what, w)
				}
			}
		})
	}
}

// TestThePlacementIsRecordedAndNotJustValidated is the fix for the invariant
// USOSS-11 could not satisfy from the other side.
//
// Put refused an unconfigured placement and then discarded the resolved one, and
// A VALIDATED-THEN-DISCARDED INPUT LOOKS EXACTLY LIKE AN HONOURED ONE: the
// refusal is right there in Put, so nobody reviewing Put notices that nothing is
// kept. It only became visible when a second port tried to USE what had been
// validated -- a container runtime asked to refuse a cross-placement binding has
// only a compute.Ref to go on.
//
// Three properties, because recording it is not enough on its own:
//   - the resolved placement NAME is recorded, so an empty "use the default"
//     from one side compares equal to an explicit default from the other;
//   - it is readable back through a seam a consumer can call;
//   - and a placement in another REGION is refused rather than recorded, so the
//     tag can never claim a placement the store did not honour.
func TestThePlacementIsRecordedAndNotJustValidated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("an explicit placement is recorded", func(t *testing.T) {
		t.Parallel()
		p, _, store := newStore(t, nil)
		stored, err := store.Put(ctx, compute.SecretSpec{
			Name: "TOKEN", Scope: "app-1", Value: compute.NewSecretValue(material),
			Placement: compute.Placement{Name: "secondary"},
		})
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := p.SecretPlacement(ctx, stored.Ref)
		if err != nil {
			t.Fatalf("SecretPlacement: %v", err)
		}
		if got != "secondary" {
			t.Fatalf("the secret records placement %q, want %q", got, "secondary")
		}
	})

	t.Run("an empty placement records the resolved default", func(t *testing.T) {
		t.Parallel()
		p, _, store := newStore(t, nil)
		ref := put(t, store, "app-1", "TOKEN", material, nil)
		got, err := p.SecretPlacement(ctx, ref)
		if err != nil {
			t.Fatalf("SecretPlacement: %v", err)
		}
		// "default" and not "": a consumer comparing a workload's resolved
		// placement against a secret's has to see the same spelling from both
		// sides, or an empty spec silently matches everything.
		if got != "default" {
			t.Fatalf("an empty placement recorded %q, want the resolved default", got)
		}
	})

	t.Run("a placement in another region is refused", func(t *testing.T) {
		t.Parallel()
		_, _, store := newStore(t, func(c *aws.Config) {
			// Everything else a placement needs to be otherwise legal, so the
			// refusal below is provably about the region and not about an
			// unrelated placement validation this config's Function, Endpoint,
			// Relational and KeyValue configuration also runs.
			elsewhere := fullPlacement("")
			elsewhere.Region = "another-region"
			c.Placements["elsewhere"] = elsewhere
		})
		_, err := store.Put(ctx, compute.SecretSpec{
			Name: "TOKEN", Scope: "app-1", Value: compute.NewSecretValue(material),
			Placement: compute.Placement{Name: "elsewhere"},
		})
		if !errors.Is(err, compute.ErrInvalidSpec) {
			t.Fatalf("a cross-region placement returned %v, want compute.ErrInvalidSpec: an SSM "+
				"parameter is regional, so storing it here would hand the workload an ARN in "+
				"another region", err)
		}
	})

	t.Run("a parameter with no placement tag is an error, not a default", func(t *testing.T) {
		t.Parallel()
		p, params, store := newStore(t, nil)
		ref := put(t, store, "app-1", "TOKEN", material, nil)
		name := paramOf(t, ref)
		// Strip the tag, as a parameter created before the store recorded one.
		if err := params.SetTags(ctx, name, nil, []string{"apphub:placement"}); err != nil {
			t.Fatalf("SetTags: %v", err)
		}
		if got, err := p.SecretPlacement(ctx, ref); err == nil {
			t.Fatalf("an untagged parameter reported placement %q; \"no placement recorded\" and "+
				"\"the default placement\" are different facts and a consumer comparing them "+
				"would treat the first as the second", got)
		}
	})
}

// --- version pinning (USOSS-35) ---------------------------------------------

// TestPutReportsTheRevisionItCreated is the write half of the pinning contract.
// Without it, [compute.SecretBinding.Version] would be a field the write path
// cannot fill, which is a worse artefact than the gap it replaced.
func TestPutReportsTheRevisionItCreated(t *testing.T) {
	t.Parallel()
	_, _, store := newStore(t, nil)

	first := putStored(t, store, "app-1", "TOKEN", material, nil)
	if first.Version == "" {
		t.Fatal("Put reported no version, so nothing can pin to the revision it wrote")
	}
	// A repeat write of the same value is not a rotation. A store that minted a
	// revision per call would make a redeploy that changed nothing look like one.
	again := putStored(t, store, "app-1", "TOKEN", material, nil)
	if again.Version != first.Version {
		t.Fatalf("an identical Put minted revision %q after %q", again.Version, first.Version)
	}
	rotated := putStored(t, store, "app-1", "TOKEN", material+"-rotated", nil)
	if rotated.Version == first.Version {
		t.Fatalf("a Put of a new value reported the same revision %q, so a pin names nothing",
			first.Version)
	}
	// The Ref is the identity and does not move when the value does.
	if rotated.Ref != first.Ref {
		t.Fatalf("the reference changed from %s to %s when only the value did", first.Ref, rotated.Ref)
	}
}

// TestPinnedBindingResolvesToTheRevision is the read half: SSM honours a
// "name:version" selector, so this provider honours a pin rather than refusing
// it, and the selector belongs to the reference and not to the grant.
func TestPinnedBindingResolvesToTheRevision(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, store := newStore(t, nil)
	first := putStored(t, store, "app-1", "TOKEN", material, nil)
	putStored(t, store, "app-1", "TOKEN", material+"-rotated", nil)

	refs, err := p.SecretParameterARNs(ctx, []compute.SecretBinding{
		{EnvName: "PINNED", Secret: first.Ref, Version: first.Version},
		{EnvName: "CURRENT", Secret: first.Ref},
	})
	if err != nil {
		t.Fatalf("SecretParameterARNs: %v", err)
	}
	base := "arn:aws:ssm:" + aws.MemoryRegion + ":" + aws.MemoryAccount + ":parameter" + paramOf(t, first.Ref)
	if refs[0].ARN != base+":"+first.Version {
		t.Fatalf("the pinned reference is %q, want the version selector appended to %q",
			refs[0].ARN, base)
	}
	if refs[0].Version != first.Version {
		t.Fatalf("the pinned reference reports version %q, want %q", refs[0].Version, first.Version)
	}
	if refs[1].ARN != base || refs[1].Version != "" {
		t.Fatalf("the unpinned reference is %q@%q, want %q with no version",
			refs[1].ARN, refs[1].Version, base)
	}

	// The GRANT names the parameter, not the revision. An IAM Resource element
	// for an SSM parameter has no version component, so a policy naming
	// "…:parameter/x:1" authorises nothing — it fails closed, but it fails closed
	// on every deploy that pins anything, and the failure surfaces as a task that
	// will not start.
	doc, err := p.SecretReadPolicy(refs)
	if err != nil {
		t.Fatalf("SecretReadPolicy: %v", err)
	}
	want := []string{base}
	if !slices.Equal(doc.Statement[0].Resource, want) {
		t.Fatalf("the grant names %v, want %v: a pinned and an unpinned binding to one parameter "+
			"are one resource", doc.Statement[0].Resource, want)
	}
	if strings.Contains(mustJSON(t, doc), ":"+first.Version+"\"") {
		t.Fatal("the grant carries a version selector, which matches no SSM resource ARN")
	}
}

// TestAValidatedRevisionIsTheOneThatReachesTheSubstrate.
//
// [secretStore.revision] normalises a version through strconv.ParseInt and
// returns the parsed value, and the call site used to append the caller's raw
// string instead. ParseInt accepts "007" and "+7", so both validated and both
// produced a selector SSM does not resolve — a normalisation that is computed and
// discarded is only a check, and the value it checked still reaches the
// substrate.
//
// Both fields are asserted, not just the ARN: SecretParameterRef.baseARN
// recovers the unversioned ARN by trimming Version off ARN, so the two
// disagreeing would silently stop a grant deduplicating a pinned and an unpinned
// binding to one parameter.
func TestAValidatedRevisionIsTheOneThatReachesTheSubstrate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, store := newStore(t, nil)
	first := putStored(t, store, "app-1", "TOKEN", material, nil)
	base := "arn:aws:ssm:" + aws.MemoryRegion + ":" + aws.MemoryAccount + ":parameter" + paramOf(t, first.Ref)

	for _, spelling := range []string{first.Version, "0" + first.Version, "+" + first.Version} {
		t.Run(spelling, func(t *testing.T) {
			t.Parallel()
			refs, err := p.SecretParameterARNs(ctx, []compute.SecretBinding{
				{EnvName: "PINNED", Secret: first.Ref, Version: spelling},
			})
			if err != nil {
				t.Fatalf("SecretParameterARNs(%q): %v", spelling, err)
			}
			if refs[0].ARN != base+":"+first.Version {
				t.Errorf("version %q produced ARN %q, want the canonical selector %q; SSM does "+
					"not resolve a zero-padded or signed version",
					spelling, refs[0].ARN, base+":"+first.Version)
			}
			if refs[0].Version != first.Version {
				t.Errorf("version %q was reported back as %q, want the canonical %q",
					spelling, refs[0].Version, first.Version)
			}
			// And the grant still names the parameter rather than the revision,
			// which is what breaks if ARN and Version disagree.
			doc, err := p.SecretReadPolicy(refs)
			if err != nil {
				t.Fatalf("SecretReadPolicy: %v", err)
			}
			if !slices.Equal(doc.Statement[0].Resource, []string{base}) {
				t.Errorf("the grant names %v, want %v", doc.Statement[0].Resource, []string{base})
			}
		})
	}
}

// TestPinToARevisionThatDoesNotExistIsRefused: falling back to the current value
// on an unrecognised revision is the same defect as ignoring the field, and it
// would surface as a workload that starts with the wrong credential.
func TestPinToARevisionThatDoesNotExistIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _, store := newStore(t, nil)
	stored := putStored(t, store, "app-1", "TOKEN", material, nil)

	for _, tc := range []struct {
		what    string
		version string
		want    error
	}{
		{"a revision beyond the ones that exist", "99", compute.ErrNotFound},
		{"a version that is not a number", "latest", compute.ErrInvalidSpec},
		{"a zero version", "0", compute.ErrInvalidSpec},
		{"a negative version", "-1", compute.ErrInvalidSpec},
		{"a version with a selector a caller composed", stored.Version + ":extra", compute.ErrInvalidSpec},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			_, err := p.SecretParameterARNs(ctx, []compute.SecretBinding{
				{EnvName: "PINNED", Secret: stored.Ref, Version: tc.version},
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("pinning to %s returned %v, want %v", tc.what, err, tc.want)
			}
			if strings.Contains(fmt.Sprint(err), material) {
				t.Fatal("the refusal carries the material")
			}
		})
	}
}
