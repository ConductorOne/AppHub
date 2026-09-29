// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"fmt"
	"math"

	"github.com/conductorone/apphub/compute"
)

// The bounds this provider validates caller input against, in one place.
//
// # Why one place rather than a guard at each call site
//
// Every value that reaches an AWS SDK as an int32 is a narrowing conversion from
// the interface's int, and a narrowing conversion that is not bounded first is a
// value that arrives at the API meaning something else — port 70000 becomes
// 4464, and a replica count above MaxInt32 becomes negative. A guard written at
// each site is a guard that is missing from the site nobody thought about, which
// is how this port accepted both of those.
//
// So the bound is derived and named once, and the validators below are the only
// way in. `math.MaxInt32` rather than a typed literal so the bound follows the
// conversion it exists to protect rather than restating it.
const (
	// minPort and maxPort are the TCP/UDP port range. Zero is not a port a
	// workload can listen on, and neither is anything above 65535.
	minPort = 1
	maxPort = 65535

	// maxReplicas is what the substrate's int32 count can hold. A caller asking
	// for more is refused rather than silently wrapped to a negative desired
	// count, which ECS reads as "scale to nothing".
	maxReplicas = math.MaxInt32
)

// narrowToInt32 converts a caller's int for an SDK field that takes int32,
// refusing rather than wrapping.
//
// # Why this exists rather than a //nolint at each conversion
//
// Every one of these conversions used to carry a suppression asserting the value
// was "bounded by the caller's validation" — true, and established in a
// different file. A suppression is a statement to the next reader that somebody
// checked, so one whose supporting fact lives elsewhere is a claim that can go
// stale without touching the line that makes it. A sibling port shipped exactly
// that: a //nolint asserting a value was bounded to 1..65535 while the same file
// set it to -1 eighty lines up.
//
// So the bound is applied AT the conversion and the function returns an error,
// which removes the suppressions rather than making them true. Six became one,
// and that one is in the error path where the wrapped value IS the diagnostic.
func narrowToInt32(field string, n int) (int32, error) {
	if n < 0 || n > math.MaxInt32 {
		return 0, fmt.Errorf("%w: %s is %d, which this substrate's 32-bit field cannot hold; "+
			"refusing rather than wrapping it to %d",
			compute.ErrInvalidSpec, field, n, int32(n)) //nolint:gosec // the wrapped value is the diagnostic.
	}
	// No suppression needed: the bound above is visible to the analyser, which
	// is the point. Making the guard local did not make the //nolint true, it
	// made it unnecessary — nolintlint reported the directive as unused, which
	// is the strongest possible confirmation that the check is where it belongs.
	return int32(n), nil
}

// checkPort refuses a port that is not one, naming the field so a caller with
// several ports knows which.
func checkPort(field string, port int) error {
	if port < minPort || port > maxPort {
		return fmt.Errorf("%w: %s is %d, which is not a port; this substrate takes %d-%d",
			compute.ErrInvalidSpec, field, port, minPort, maxPort)
	}
	return nil
}

// checkReplicas refuses a count the substrate cannot represent.
//
// Zero is legal and means paused, which is why this is not simply "positive".
func checkReplicas(replicas int) error {
	if replicas < 0 {
		return fmt.Errorf("%w: Replicas is %d; zero means paused and negative means nothing",
			compute.ErrInvalidSpec, replicas)
	}
	if replicas > maxReplicas {
		return fmt.Errorf("%w: Replicas is %d, which is more than this substrate's count can "+
			"hold (%d); refusing rather than narrowing it to a negative desired count",
			compute.ErrInvalidSpec, replicas, maxReplicas)
	}
	return nil
}
