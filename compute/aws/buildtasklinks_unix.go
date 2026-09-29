// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package aws

import (
	"os"
	"syscall"
)

// hasMultipleLinks reports whether a file has more than one directory entry.
//
// A build context may not contain one. A hard link is a second name for an
// existing inode, so a link placed in a context is a way to put a file the
// worker can read -- but that nobody put in the repository -- into the tree the
// builder receives. The link count is the only portable way to notice, and a
// file this function cannot inspect is treated as suspect rather than as fine.
//
// Nlink's width differs by platform (uint16 on darwin, uint32 on linux/arm64,
// uint64 on linux/amd64), so it is compared with an untyped constant: a
// conversion to any one width is redundant, and flagged as such, on another.
func hasMultipleLinks(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return !ok || st.Nlink != 1
}
