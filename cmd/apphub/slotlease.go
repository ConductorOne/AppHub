// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"

	awscompute "github.com/conductorone/apphub/compute/aws"
	"github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/worker"
)

// slotLeaser adapts the worker's store-backed leases to the AWS provider's
// port, so every worker process draws build slots from one shared authority.
type slotLeaser struct{ leases *worker.SlotLeases }

var _ awscompute.SlotLeaser = slotLeaser{}

func (s slotLeaser) Acquire(ctx context.Context, slots []string) (awscompute.SlotLease, error) {
	lease, err := s.leases.Acquire(ctx, slots)
	if err != nil {
		return nil, err
	}
	return lease, nil
}

// workerHolderName names this worker process on the leases it holds: the
// host, which on Fargate is the task, plus a random suffix so two processes
// on one host are told apart.
func workerHolderName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "worker"
	}
	return host + "/" + controlplane.NewID()
}
