// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"fmt"
	"math"

	"github.com/conductorone/apphub/compute"
)

// # Why narrowing to int32 has one bound in one place
//
// The compute interface counts things in `int`. Kubernetes counts the same
// things in `int32`. On a 64-bit platform every conversion between them is a
// silent truncation, and a value past the int32 range does not fail -- it wraps,
// so a caller asking for 2^31 replicas gets a *negative* replica count written to
// the cluster and a caller asking for port 2^31+80 gets port 80.
//
// This package had five such conversions, all in container.go, and they were
// guarded four different ways:
//
//   - three port conversions, each preceded by its own hand-written
//     `<= 0 || > 65535` check with its own message;
//   - `ScaleService`, which carried `//nolint:gosec // bounded by the check
//     above` where the check above bounded only the lower end (found in review
//     round three);
//   - `EnsureService`, which carried the same suppression with the same
//     half-truth plus "and by k8s on apply" -- deferring a bound to a remote
//     system, after the wrong value has already been computed (found in review
//     round seven).
//
// Four hand-placed guards is four chances to place the next one wrong, and the
// two that were wrong were the two behind a suppression asserting they were
// right. So the bound lives here instead, and
// [TestEveryNarrowingConversionIsBounded] derives the population from the source
// rather than listing it: a sixth conversion added anywhere in this package
// either calls one of these functions or fails that test. There is no allowlist
// to forget to update.
//
// # Why a suppression was worse than the bug it hid
//
// `//nolint:gosec // bounded by the check above` is a statement to the next
// reader AND to the linter that somebody checked. Both instances were false. A
// wrong comment is a wrong comment; a wrong suppression also switches off the
// tool that would have reported it, and reads to every later reviewer as evidence
// the question was already settled. Neither function below needs a suppression,
// which is the point: the conversion is unreachable unless the value is in range.

// maxPort is the highest TCP/UDP port number. Port 0 is excluded deliberately:
// it means "any free port" to a kernel and is not something a caller can have
// meant to publish.
const maxPort = 65535

// narrowPort converts a caller-supplied port number to the int32 the Kubernetes
// API types use, refusing anything that is not a port.
//
// `what` names the field for the operator, because "ingress rule port",
// "container port" and a specific route's target port send them to different
// places in their own specification.
func narrowPort(value int, what string) (int32, error) {
	if value <= 0 || value > maxPort {
		return 0, fmt.Errorf("%w: %s %d is not a port (1-%d)",
			compute.ErrInvalidSpec, what, value, maxPort)
	}
	return int32(value), nil
}

// narrowCount converts a caller-supplied count -- replicas, today -- to int32,
// refusing negatives and anything int32 cannot represent.
//
// The upper bound is not theatre. It is the half that both suppressions in this
// package got wrong, and getting it wrong is not a rejected request: it is a
// negative replica count written to a Deployment as though the caller had asked
// for it.
func narrowCount(value int, what string) (int32, error) {
	if value < 0 || value > math.MaxInt32 {
		return 0, fmt.Errorf("%w: %s cannot be %d",
			compute.ErrInvalidSpec, what, value)
	}
	return int32(value), nil
}
