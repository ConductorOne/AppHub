// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import "k8s.io/apimachinery/pkg/runtime/schema"

// This file is `export_test.go` deliberately, and the suffix is the point.
//
// It was `exports_test_support.go` -- a non-test file, so `go list` counted it in
// GoFiles and `go doc ./compute/k8s` PUBLISHED every accessor in it as part of the
// package's API. Naming a symbol ...ForTest documents an intention; it does not
// scope anything. The `_test.go` suffix is what actually scopes it: the compiler
// excludes the file from the package build, and an in-package test file's exported
// identifiers are still visible to the external k8s_test package, which is the
// whole point of this pattern.
//
// Round ten named RegistryAuthorizationStateForTest. All three accessors were in
// that file with the same problem, so all three moved -- naming one and leaving
// its neighbours would be fixing the route rather than the population.
//
// DeploymentGVKForTest and EffectiveSpecAnnotationForTest expose two internal
// constants to this package's external tests.
//
// They exist so a test can reach past the provider and put the cluster into a
// state the provider itself never writes — a malformed effective-spec annotation.
// That state is reachable in production (a partial write, a foreign writer), and
// the only way to test the provider's response to it is to construct it directly.
//
// Deliberately narrow: two read-only values, no behaviour, and nothing a caller
// outside a test would have any use for.
func DeploymentGVKForTest() schema.GroupVersionKind { return gvkDeployment }

// EffectiveSpecAnnotationForTest returns the annotation key carrying a resource's
// effective spec.
func EffectiveSpecAnnotationForTest() string { return annotationSpec }

// RegistryAuthorizationStateForTest reports the registry authorization state a
// test needs in order to assert that a REFUSED spec changed nothing: how many
// principals hold a grant across all repositories, and how many robot credentials
// have been minted.
//
// It exists because that state is otherwise unobservable from outside the package
// -- RepositoryState deliberately does not carry grants -- and "a refused spec
// must not change authorization state" cannot be a test without a way to read it.
// Round nine found the defect it guards: buildWorkload granted repository read,
// minted a credential and attached a pull secret, so any validation that ran
// after it could refuse a spec that had already been authorized.
//
// Read-only, aggregate, and returns counts rather than principals so it cannot
// become a way to assert on credential material.
func RegistryAuthorizationStateForTest(r *MemoryRegistry) (grants, robots int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, repo := range r.repos {
		grants += len(repo.grants)
	}
	return grants, len(r.robots)
}
