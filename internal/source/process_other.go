// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package source

import "os/exec"

// Hosted source acquisition requires the dedicated Linux worker. Non-worker
// commands still compile on client platforms; no weakened execution fallback.
//
// The two panics are unreachable by construction rather than by hope:
// NewCheckout refuses to build a Checkout at all when processGroupsSupported
// reports false, so nothing on this platform holds the receiver whose methods
// reach them. They are the backstop for a future caller that finds another way
// in, and a panic rather than a silent no-op because running Git without a
// process group to kill is the weakened fallback this package does not offer.
//
// The parameters are unnamed for the same reason they are unused: there is no
// command to configure on a platform where no command may run.
func processGroupsSupported() bool      { return false }
func configureProcessGroup(_ *exec.Cmd) { panic("source: unsupported worker platform") }
func killProcessGroup(_ *exec.Cmd)      { panic("source: unsupported worker platform") }
