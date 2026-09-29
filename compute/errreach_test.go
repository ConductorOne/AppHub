// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// See credentials/errreach_test.go for the full USOSS-67 reasoning; this file
// pins the same fact for compute.SecretValue, which errors.Is/errors.As call
// sites throughout compute/ (compute/aws/secret.go's Put, in particular) share
// a function with. See
// docs/decisions/usoss-67-a-hostile-chain-member-s-is-as-method-only-ever-
// receives-the-target-its-caller-supplied.md.
package compute_test

import (
	"testing"

	"github.com/conductorone/apphub/compute"
)

func TestSecretValueIsNotAnError(t *testing.T) {
	if _, ok := any(compute.SecretValue{}).(error); ok {
		t.Fatal("compute.SecretValue now implements error. Re-run the USOSS-67 audit: a SecretValue " +
			"can now be the target of errors.Is or the destination of errors.As, so a chain " +
			"containing a caller- or dependency-supplied cause could hand a hostile Is/As method a " +
			"live SecretValue -- compute/aws/secret.go's Put holds one in scope while classifying " +
			"an SSM error.")
	}
	if _, ok := any(&compute.SecretValue{}).(error); ok {
		t.Fatal("*compute.SecretValue now implements error. Re-run the USOSS-67 audit: see " +
			"TestSecretValueIsNotAnError.")
	}
}
