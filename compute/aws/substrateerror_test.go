// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/conductorone/apphub/compute"
	"github.com/conductorone/apphub/compute/aws"
)

// TestNoForeignErrorTextReachesACallerViaSubstrateError is USOSS-76's fix,
// checked from outside the package the way TestNoForeignErrorTextReachesACaller
// (secret_test.go) checks secretStore.wrap's.
//
// [Provider.substrateError] classifies an error from ANY member of [Substrate]
// onto the [compute] taxonomy, and every member is an interface a caller can
// supply an adapter for -- so its text is not this package's to show. Before
// the fix, every arm retained it via `fmt.Errorf("%w: %w", sentinel, err)` (or,
// on the two context arms, returned err verbatim); see provider.go's history
// for the exact shape secretStore.wrap was fixed out of in #19.
//
// The population here is the classifier's arms (derived and named by
// TestEveryArmOfSubstrateErrorIsCovered in substrateerror_internal_test.go),
// driven through the four substrates USOSS-76 named as externally
// implementable: ECR, IAM, STS and Builder. A test that planted only one
// marker on one substrate would have the same route-versus-population gap
// [secretStore.wrap]'s round one had -- fixing the reproduced arm and leaving
// the rest live. So every classified arm is driven through ECR (the substrate
// with the most call sites reachable without extra setup), and the three
// arms actually reachable on IAM, STS and Builder are driven through each of
// those directly.
func TestNoForeignErrorTextReachesACallerViaSubstrateError(t *testing.T) {
	t.Parallel()
	const marker = "USOSS-76-MARKER-4f19ac"

	// Every sentinel substrateError branches on, plus the two context arms and
	// the unclassified case. A plain foreign error falls to the default arm; a
	// foreign error WRAPPING one of the substrate sentinels is how a real
	// adapter reports a recognised condition, which is the shape that reaches
	// a classified arm (see secret_test.go's identical note on this point).
	arms := map[string]error{
		"default (unrecognised)": errors.New(marker),
		"no-such-resource":       fmt.Errorf("%w: %s", aws.ErrNoSuchResource, marker),
		"throttled":              fmt.Errorf("%w: %s", aws.ErrThrottled, marker),
		"name-taken":             fmt.Errorf("%w: %s", aws.ErrNameTaken, marker),
		"already-exists":         fmt.Errorf("%w: %s", aws.ErrAlreadyExists, marker),
		"denied":                 fmt.Errorf("%w: %s", aws.ErrDenied, marker),
		"malformed":              fmt.Errorf("%w: %s", aws.ErrMalformed, marker),
		// The context arms wrap the marker AROUND the sentinel, the same way
		// secret_test.go's do: an adapter's cancellation arrives wrapped in the
		// adapter's own text, and a bare sentinel has nothing to leak.
		"cancelled": fmt.Errorf("%s: %w", marker, context.Canceled),
		"deadline":  fmt.Errorf("%s: %w", marker, context.DeadlineExceeded),
	}
	// ErrConflict has no ECR call site (it is Lambda's), so it is not in the
	// table above; TestEveryArmOfSubstrateErrorIsCovered still guards its
	// presence in the switch, and it retains nothing either -- it goes through
	// the identical `case errors.Is(err, ErrConflict):` shape as the others.

	assertNoMarker := func(t *testing.T, where string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s succeeded against a failing substrate, so this case searches no error path",
				where)
		}
		for _, format := range []string{"%v", "%s", "%+v", "%#v", "%q"} {
			if rendered := fmt.Sprintf(format, err); strings.Contains(rendered, marker) {
				t.Errorf("%s carried the substrate's marker text under %s: %s", where, format, rendered)
			}
		}
		for u := errors.Unwrap(err); u != nil; u = errors.Unwrap(u) {
			if strings.Contains(u.Error(), marker) {
				t.Errorf("%s retained the foreign error in its chain: %v", where, u)
			}
		}
	}

	// ECR and IAM are driven through Describe rather than Ensure: Ensure's
	// first read treats [aws.ErrNoSuchResource] as "create it", which is a
	// legitimate success and not a path that reaches substrateError's error
	// return at all -- the same idempotent-Delete exemption secret_test.go's
	// table names explicitly for its own not-found row. Describe against a
	// substrate injected to fail has no such reading: it is unconditionally an
	// error path.
	t.Run("ECR", func(t *testing.T) {
		t.Parallel()
		for armName, foreign := range arms {
			t.Run(armName, func(t *testing.T) {
				t.Parallel()
				p, sub := newProvider(t, nil)
				reg, err := p.Registry()
				if err != nil {
					t.Fatalf("Registry(): %v", err)
				}
				ref := mustEnsureRepo(t, p, "app").Ref
				sub.ECR.(*aws.MemoryECR).FailNext(foreign)
				_, err = reg.DescribeRepository(context.Background(), ref)
				assertNoMarker(t, "Registry.DescribeRepository/"+armName, err)
			})
		}
	})

	t.Run("IAM", func(t *testing.T) {
		t.Parallel()
		for armName, foreign := range arms {
			t.Run(armName, func(t *testing.T) {
				t.Parallel()
				p, sub := newProvider(t, nil)
				ref := mustEnsureIdentity(t, p, "app").Ref
				sub.IAM.(*aws.MemoryIAM).FailNext(foreign)
				_, err := p.Identities().DescribeWorkloadIdentity(context.Background(), ref)
				assertNoMarker(t, "Identities.DescribeWorkloadIdentity/"+armName, err)
			})
		}
	})

	t.Run("STS", func(t *testing.T) {
		t.Parallel()
		// STS mints the build's push credential, reached only from inside a
		// build (pushcreds.go:mintPushCredentials). Arming it before the first
		// build would have the ECR/IAM setup underneath consume the failure --
		// see registry_test.go's identical "token service alone" note -- so an
		// unarmed build runs first to provision the repository, and STS alone
		// is armed for the build that is actually asserted on.
		for armName, foreign := range arms {
			t.Run(armName, func(t *testing.T) {
				t.Parallel()
				p, sub := newProvider(t, nil)
				prefix := mustEnsureRepo(t, p, "app").Prefix
				b, err := p.Builder()
				if err != nil {
					t.Fatalf("Builder(): %v", err)
				}
				req := compute.BuildRequest{
					Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
					Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
				}
				if _, err := b.Build(context.Background(), req); err != nil {
					t.Fatalf("the unarmed build failed: %v", err)
				}
				sub.STS.(*aws.MemorySTS).FailNext(foreign)
				_, err = b.Build(context.Background(), req)
				assertNoMarker(t, "Builder.Build (token service)/"+armName, err)
			})
		}
	})

	t.Run("Builder", func(t *testing.T) {
		t.Parallel()
		for armName, foreign := range arms {
			t.Run(armName, func(t *testing.T) {
				t.Parallel()
				p, sub := newProvider(t, nil)
				prefix := mustEnsureRepo(t, p, "app").Prefix
				b, err := p.Builder()
				if err != nil {
					t.Fatalf("Builder(): %v", err)
				}
				runner, ok := sub.Builder.(*aws.RecordingBuilder)
				if !ok {
					t.Fatalf("the substrate's builder is a %T", sub.Builder)
				}
				runner.FailNext(foreign)
				_, err = b.Build(context.Background(), compute.BuildRequest{
					Source:       compute.BuildSource{ContextDir: contextDir(t, map[string]string{})},
					Destinations: []compute.ImageRef{compute.ImageRef(prefix + ":latest")},
				})
				assertNoMarker(t, "Builder.Build (runner)/"+armName, err)
			})
		}
	})
}

// TestSubstrateErrorClassificationSurvivesTheSanitising is the other half:
// dropping the foreign chain must not drop the taxonomy, which is the only
// thing a caller can act on. Without this, USOSS-76's fix is satisfied by
// returning a bare string that classifies as nothing.
func TestSubstrateErrorClassificationSurvivesTheSanitising(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		what    string
		foreign error
		want    error
	}{
		{"no-such-resource", aws.ErrNoSuchResource, compute.ErrNotFound},
		{"throttled", aws.ErrThrottled, compute.ErrTransient},
		{"name-taken", aws.ErrNameTaken, compute.ErrNotOwned},
		{"already-exists", aws.ErrAlreadyExists, compute.ErrTransient},
		{"denied", aws.ErrDenied, compute.ErrNotPermitted},
		{"malformed", aws.ErrMalformed, compute.ErrInvalidSpec},
		{"unrecognised", errors.New("x"), compute.ErrFailed},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			p, sub := newProvider(t, nil)
			ref := mustEnsureIdentity(t, p, "app").Ref
			sub.IAM.(*aws.MemoryIAM).FailNext(tc.foreign)
			_, err := p.Identities().DescribeWorkloadIdentity(context.Background(), ref)
			if !errors.Is(err, tc.want) {
				t.Fatalf("a %s substrate error classified as %v, want %v", tc.what, err, tc.want)
			}
		})
	}
}
