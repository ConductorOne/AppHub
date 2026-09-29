// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"fmt"

	"github.com/conductorone/apphub/compute"
)

// Fargate offers a fixed set of task sizes, and this file maps
// [compute.Resources] onto them.
//
// # Why the rounding direction is a correctness question
//
// [compute.Resources] is explicit: a provider that cannot honour a request
// exactly "must round *up* and say so in [compute.Status.Message], or return
// [compute.ErrInvalidSpec] if it cannot even do that. Rounding down is never
// acceptable: it turns a capacity decision into a silent, intermittent
// out-of-memory failure at runtime."
//
// The source system does neither. It passes the caller's numbers straight into
// RegisterTaskDefinition (container.go:746-748), so a combination Fargate does
// not offer is rejected by the API with a message about task sizes rather than
// adjusted — which is at least fail-closed — and nothing anywhere rounds or
// reports. This port resolves the request to the smallest size that is at least
// as large in *both* dimensions and says what it did.

// fargateTier is one CPU size and the memory sizes allowed with it.
//
// The table is Fargate's own, expressed as a range and a step rather than an
// enumeration of every combination, because that is how AWS documents it and a
// hand-enumerated list of ~90 pairs is a list that drifts.
type fargateTier struct {
	// cpuUnits is the CPU size in ECS units. 1024 units is one vCPU.
	cpuUnits int
	// minMiB and maxMiB bound the memory allowed with this CPU size, and step
	// is the granularity between them.
	minMiB, maxMiB, stepMiB int
}

// fargateTiers is ordered by CPU size, smallest first, so the first tier that
// fits is the smallest one that fits.
var fargateTiers = []fargateTier{
	// The 256-unit tier is the one irregular row: it offers three specific
	// memory sizes rather than a range, so it is expressed as a step of 512
	// from 512 to 2048, which yields exactly 512, 1024, 1536 and 2048. AWS
	// lists 512, 1024 and 2048; 1536 is admitted here rather than special-cased
	// because rounding a 1536 MiB request up to 2048 is what the next tier
	// would do anyway and the API is the authority on what it accepts.
	{cpuUnits: 256, minMiB: 512, maxMiB: 2048, stepMiB: 512},
	{cpuUnits: 512, minMiB: 1024, maxMiB: 4096, stepMiB: 1024},
	{cpuUnits: 1024, minMiB: 2048, maxMiB: 8192, stepMiB: 1024},
	{cpuUnits: 2048, minMiB: 4096, maxMiB: 16384, stepMiB: 1024},
	{cpuUnits: 4096, minMiB: 8192, maxMiB: 30720, stepMiB: 1024},
	{cpuUnits: 8192, minMiB: 16384, maxMiB: 61440, stepMiB: 4096},
	{cpuUnits: 16384, minMiB: 32768, maxMiB: 122880, stepMiB: 8192},
}

// cpuUnitsPerCore is how many ECS CPU units make one core. The interface speaks
// millicores, where 1000 is one core.
const cpuUnitsPerCore = 1024

// taskSize resolves a request onto a Fargate size.
//
// It returns the resolved CPU units and memory, and a note describing any
// rounding for [compute.Status.Message]. An empty note means the request was
// honoured exactly.
func taskSize(r compute.Resources) (cpuUnits, memoryMiB int, note string, err error) {
	if r.CPUMillicores <= 0 || r.MemoryMiB <= 0 {
		return 0, 0, "", fmt.Errorf("%w: a task needs both CPUMillicores (%d) and MemoryMiB (%d) "+
			"above zero; this substrate has no burstable or unbounded size to fall back to",
			compute.ErrInvalidSpec, r.CPUMillicores, r.MemoryMiB)
	}
	// Round the requested millicores up to whole CPU units first, so that a
	// request of 1 millicore does not become zero units.
	wantUnits := ceilDiv(r.CPUMillicores*cpuUnitsPerCore, 1000)

	for _, tier := range fargateTiers {
		if tier.cpuUnits < wantUnits || tier.maxMiB < r.MemoryMiB {
			continue
		}
		mem := r.MemoryMiB
		if mem < tier.minMiB {
			mem = tier.minMiB
		} else if rem := (mem - tier.minMiB) % tier.stepMiB; rem != 0 {
			mem += tier.stepMiB - rem
		}
		if mem > tier.maxMiB {
			// The step rounded past the tier's ceiling. The next tier up is the
			// answer, so keep looking rather than clamping down — clamping down
			// is the failure mode this whole file exists to avoid.
			continue
		}
		if tier.cpuUnits == wantUnits && mem == r.MemoryMiB {
			return tier.cpuUnits, mem, "", nil
		}
		return tier.cpuUnits, mem, fmt.Sprintf(
			"the requested %dm CPU / %d MiB was rounded up to the smallest Fargate size that fits, "+
				"%d CPU units / %d MiB", r.CPUMillicores, r.MemoryMiB, tier.cpuUnits, mem), nil
	}

	largest := fargateTiers[len(fargateTiers)-1]
	return 0, 0, "", fmt.Errorf("%w: %dm CPU / %d MiB is larger than the largest Fargate task size "+
		"(%d CPU units / %d MiB); this provider will not round a capacity request down",
		compute.ErrInvalidSpec, r.CPUMillicores, r.MemoryMiB, largest.cpuUnits, largest.maxMiB)
}

// ceilDiv divides rounding away from zero for positive inputs.
func ceilDiv(a, b int) int {
	if a <= 0 {
		return 0
	}
	return (a + b - 1) / b
}
