#!/usr/bin/env bash
# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# USOSS-72: golangci-lint has been observed, twice, on two different trees,
# exiting 2 while the tail of its own stdout still read "0 issues". Exit 2
# means "the linters failed to run", not "the linters ran and found nothing"
# -- but a caller who reads the printed count instead of the exit code cannot
# tell those apart, and this project's own pre-publication audit is exactly
# that caller if it ever treats one plausible-looking transcript as decisive.
#
# The cause was never found and two independent hypotheses (a shared cache,
# concurrent build/vet pressure) were each measured and retracted. This
# script does not try again. It accepts that the failure is real, rare, and
# uncaused-as-far-as-anyone-has-shown, and makes it impossible to misread
# instead: it captures everything golangci-lint writes, inspects the exit
# code explicitly, and turns anything other than a clean 0 into a failure
# that names itself and carries the evidence, so the next sighting arrives
# with a transcript instead of a memory.
#
# golangci-lint's own exit codes: 0 = no issues, 1 = issues found,
# anything else = the run itself did not complete (a linter panicked, a
# config was rejected, timeout, etc.) -- see USOSS-72's report for the
# concrete case that motivated this file.
set -uo pipefail

output=$("$@" 2>&1)
code=$?

printf '%s\n' "$output"

case "$code" in
0)
	exit 0
	;;
1)
	# Ordinary lint findings. golangci-lint already printed them above;
	# propagate its exit code so the caller (make, CI) fails normally.
	exit 1
	;;
*)
	cat >&2 <<EOF

================================================================================
GATE FAILURE, NOT A LINT FINDING: golangci-lint exited $code.

Exit code $code means the linters did not finish running -- it is not "zero
issues" and it is not safe to read the transcript above as a clean pass, even
if its tail says "0 issues". See USOSS-72: this exact shape (exit 2, "0
issues" printed) has been observed and was never explained.

The full captured output is above this banner. Do not retry silently and
report the retry's result alone -- record this exit code and the transcript,
per USOSS-72's standing instruction not to close that ticket with a plausible
explanation that has not been measured.
================================================================================
EOF
	exit "$code"
	;;
esac
