// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sdk

import (
	"errors"
	"os"
	"path/filepath"
)

func replaceCredentials(source, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	// Persist the rename as well as the file contents, including refresh intent.
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func securePermissions(path string, directory bool) error {
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
