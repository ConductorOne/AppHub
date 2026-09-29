// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"os/exec"
	"syscall"
)

func processGroupsSupported() bool { return true }
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
