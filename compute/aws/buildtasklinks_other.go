// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package aws

import "os"

// hasMultipleLinks has no portable answer off unix, so it gives the safe one.
//
// The consequence is stated rather than hidden: on such a platform every regular
// file in a build context is treated as hard-linked and the context is refused.
// That is correct for what this package is -- a build runs in a Linux task, and
// the worker that prepares its context runs in a Linux container -- and it fails
// closed on a platform where the check cannot be performed instead of quietly
// skipping it.
func hasMultipleLinks(os.FileInfo) bool { return true }
