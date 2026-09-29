// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package hermetic

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// WorkflowDir is where GitHub looks for workflows, and therefore the only
// directory whose contents can grant a job anything.
const WorkflowDir = ".github/workflows"

// CheckDir parses every workflow in dir and returns the findings together with
// the files it looked at.
//
// Finding no workflows is an error, not a pass. A check that inspected nothing
// and reported success is the most dangerous kind of green.
func CheckDir(dir string) ([]Finding, []string, error) {
	var files []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, nil, err
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("no workflow files in %s -- refusing to pass a check that inspected nothing", dir)
	}

	var findings []Finding
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // path comes from a glob of a fixed directory
		if err != nil {
			return nil, nil, err
		}
		got, err := CheckWorkflow(filepath.ToSlash(f), data)
		if err != nil {
			return nil, nil, err
		}
		findings = append(findings, got...)
	}
	return findings, files, nil
}
