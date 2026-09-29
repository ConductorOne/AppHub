#!/usr/bin/env bash
# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Every Go file in a repository that is going public carries its licence on its
# face. Checking it here means a missing header is a red build, not a review
# comment on pull request forty.
set -euo pipefail

cd "$(dirname "$0")/.."

# Walk the filesystem rather than the index: an uncommitted file is precisely
# the one whose header has not been checked yet.
#
# testdata is excluded for the same reason the import checker excludes it: Go
# never compiles it, this repository's gate fixtures live there, and several of
# them are deliberately malformed. Requiring a licence header on a file whose
# job is to be wrong would be theatre.
go_files() {
  find . -type f -name '*.go' \
    -not -path './.git/*' \
    -not -path './.tools/*' \
    -not -path './vendor/*' \
    -not -path './.task-worktrees/*' \
    -not -path '*/testdata/*' \
    | sort
}

expected_copyright='^// Copyright [0-9]{4}(-[0-9]{4})? ConductorOne, Inc\.$'
expected_spdx='^// SPDX-License-Identifier: Apache-2\.0$'

status=0
while IFS= read -r file; do
  if ! head -n 1 "$file" | grep -Eq "$expected_copyright"; then
    echo "$file:1: missing or malformed copyright line" >&2
    status=1
    continue
  fi
  if ! sed -n '2p' "$file" | grep -Eq "$expected_spdx"; then
    echo "$file:2: missing '// SPDX-License-Identifier: Apache-2.0'" >&2
    status=1
  fi
done < <(go_files)

if [ "$status" -eq 0 ]; then
  echo "license headers: ok ($(go_files | wc -l | tr -d ' ') Go files)"
else
  echo >&2
  echo "Add these two lines to the top of each file listed above, followed by a" >&2
  echo "blank line so they do not become the package doc comment:" >&2
  echo >&2
  echo "  // Copyright 2026 ConductorOne, Inc." >&2
  echo "  // SPDX-License-Identifier: Apache-2.0" >&2
fi
exit "$status"
