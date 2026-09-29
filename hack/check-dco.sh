#!/usr/bin/env bash
# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Every commit must carry a Developer Certificate of Origin sign-off.
#
# CONTRIBUTING.md says this, and until now saying it was the entire enforcement.
# A licence provenance rule that lives only in a document is one distracted
# reviewer away from a commit nobody has the right to redistribute -- which, for
# a repository heading to publication under Apache-2.0, is the expensive kind of
# mistake to discover late.
#
# The sign-off must match the commit's author. That is the point of the DCO: the
# person certifying they have the right to submit the work is the person who
# wrote it, not whoever pushed it.
#
# Usage: hack/check-dco.sh [base-ref] [head-ref]
set -euo pipefail

cd "$(dirname "$0")/.."

base="${1:-origin/main}"
head="${2:-HEAD}"

if ! git rev-parse --verify --quiet "$base" >/dev/null; then
  echo "cannot resolve base ref '$base'; pass one explicitly" >&2
  exit 1
fi

# Narrow the range to what this branch actually introduces.
#
# "$base..$head" trusts the base to be an ancestor of the head. A pull
# request's base commit is a snapshot from when the webhook fired, so it goes
# stale the moment the branch is retargeted or the base branch moves, and a
# stale base makes this range enumerate commits that landed on trunk long ago.
# The merge base is the fork point whatever the base ref has done since.
if merge_base="$(git merge-base "$base" "$head" 2>/dev/null)"; then
  range="$merge_base..$head"
else
  # No common ancestor at all. Check everything rather than silently nothing.
  range="$base..$head"
fi

# Commits already on trunk are not this branch's work, and a contributor cannot
# fix them from their pull request. Resolving trunk is best-effort: if it cannot
# be found, every commit in range is checked, which is the safe direction.
trunk=""
for candidate in origin/main main; do
  if git rev-parse --verify --quiet "$candidate" >/dev/null; then
    trunk="$candidate"
    break
  fi
done

commits="$(git rev-list --no-merges "$range")"
if [ -z "$commits" ]; then
  echo "dco: ok (no commits to check in $range)"
  exit 0
fi

status=0
count=0
for sha in $commits; do
  author_email="$(git show -s --format='%ae' "$sha")"
  subject="$(git show -s --format='%s' "$sha")"

  # Already merged to trunk. Not introduced by this branch, so not this check's
  # business -- and re-reporting it would be an unfixable failure on somebody
  # else's pull request. main's own sign-off gaps are audited separately; see
  # docs/decisions/, USOSS-18.
  if [ -n "$trunk" ] && git merge-base --is-ancestor "$sha" "$trunk" 2>/dev/null; then
    printf '  skip  %s  %s (already on %s)\n' "${sha:0:8}" "$subject" "$trunk"
    continue
  fi

  # Bots do not sign off, and cannot: there is no person to certify anything.
  # Dependabot's commits are the reason this exemption exists.
  case "$author_email" in
    *'[bot]@users.noreply.github.com'|*'[bot]@'*)
      printf '  skip  %s  %s (bot author)\n' "${sha:0:8}" "$subject"
      continue
      ;;
  esac

  # Counted here rather than at the top of the loop, so the success message
  # reports commits this check actually certified rather than commits it saw.
  count=$((count + 1))

  signoffs="$(git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$sha")"
  if [ -z "$signoffs" ]; then
    printf '  FAIL  %s  %s\n        no Signed-off-by trailer\n' "${sha:0:8}" "$subject" >&2
    status=1
    continue
  fi

  # Compare on the address only; display names differ harmlessly.
  if ! grep -qiF "<$author_email>" <<<"$signoffs"; then
    printf '  FAIL  %s  %s\n        signed off by someone other than the author (%s)\n' \
      "${sha:0:8}" "$subject" "$author_email" >&2
    status=1
    continue
  fi
  printf '  ok    %s  %s\n' "${sha:0:8}" "$subject"
done

if [ "$status" -ne 0 ]; then
  cat >&2 <<'EOF'

Sign off every commit with `git commit -s`, which appends:

    Signed-off-by: Your Name <your.email@example.com>

To fix the most recent commit:      git commit --amend -s --no-edit
To fix every commit on a branch:    git rebase --signoff origin/main

This is the Developer Certificate of Origin (https://developercertificate.org/),
not a CLA: you keep your copyright and certify you may submit the work under
Apache-2.0. See CONTRIBUTING.md.
EOF
  exit 1
fi

echo "dco: ok ($count commit(s) signed off by their author)"
