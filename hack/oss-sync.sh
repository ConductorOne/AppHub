#!/usr/bin/env bash
# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Publish the internal main branch to the public repository as one snapshot
# commit.
#
# The public repository does not share this repository's history. Each sync is a
# single commit on top of public main whose tree is exactly internal main's tree,
# so nothing from internal history -- commit messages, reverted files, review
# discussion -- is published. The commit carries an Internal-Commit trailer so
# the next sync knows where the last one left off.
#
# Contributions made on the public repository are imported here first (see
# CONTRIBUTING.md); a sync overwrites public main's tree with internal main's.
#
# Usage: hack/oss-sync.sh [--push]
#   Without --push the snapshot commit is built and described but not pushed.
#
# Environment:
#   OSS_REMOTE    public repository URL (default git@github.com:ConductorOne/AppHub.git)
#   SOURCE_REF    internal ref to publish (default origin/main)
set -euo pipefail

cd "$(dirname "$0")/.."
root="$(pwd)"

oss_remote="${OSS_REMOTE:-git@github.com:ConductorOne/AppHub.git}"
source_ref="${SOURCE_REF:-origin/main}"
public_ref="refs/oss-sync/public-main"

push=false
case "${1:-}" in
"") ;;
--push) push=true ;;
*)
  echo "usage: hack/oss-sync.sh [--push]" >&2
  exit 2
  ;;
esac

name="$(git config user.name || true)"
email="$(git config user.email || true)"
if [[ -z "$name" || -z "$email" ]]; then
  echo "git user.name and user.email must be set: the snapshot commit is signed off (DCO) by you" >&2
  exit 1
fi

git fetch --quiet origin
git fetch --quiet "$oss_remote" "+refs/heads/main:$public_ref"

source_commit="$(git rev-parse --verify "$source_ref^{commit}")"
source_tree="$(git rev-parse "$source_commit^{tree}")"
public_commit="$(git rev-parse "$public_ref")"

if [[ "$source_tree" == "$(git rev-parse "$public_commit^{tree}")" ]]; then
  echo "public main already matches $source_ref ($(git rev-parse --short "$source_commit")); nothing to sync"
  exit 0
fi

# The gates run against exactly the tree being published, not the working copy.
worktree="$(mktemp -d)"
cleanup() { git worktree remove --force "$worktree" >/dev/null 2>&1 || true; }
trap cleanup EXIT
git worktree add --quiet --detach "$worktree" "$source_commit"

make --no-print-directory "$root/.tools/gitleaks" >/dev/null
echo "== disclosure gate"
(cd "$worktree" && go run ./hack/disclosurecheck)
echo "== path scan"
(cd "$worktree" && GITLEAKS="$root/.tools/gitleaks" ./hack/check-paths.sh)
echo "== secret scan"
(cd "$worktree" && "$root/.tools/gitleaks" dir . --config .gitleaks.toml --redact --no-banner)

# The internal commit public main was last synced from: its trailer, or, for a
# public commit made before this script existed, the most recent internal commit
# with an identical tree.
last_synced="$(git log -1 --format='%(trailers:key=Internal-Commit,valueonly)' "$public_commit" | tr -d '[:space:]')"
if [[ -z "$last_synced" ]]; then
  public_tree="$(git rev-parse "$public_commit^{tree}")"
  last_synced="$(git log --first-parent --format='%H %T' "$source_commit" |
    awk -v tree="$public_tree" '$2 == tree && !found { print $1; found = 1 }')"
fi
changes=""
if [[ -n "$last_synced" ]] && git merge-base --is-ancestor "$last_synced" "$source_commit" 2>/dev/null; then
  # Merge subjects name internal branches, and internal pull-request numbers
  # would link to unrelated public ones.
  changes="$(git log --reverse --no-merges --format='- %s' "$last_synced..$source_commit" |
    sed -E 's/ \(#[0-9]+\)$//')"
else
  echo "warning: cannot find the internal commit public main came from; the message will not list changes" >&2
fi

message="$(mktemp)"
{
  echo "Sync from internal $(date -u +%Y-%m-%d)"
  if [[ -n "$changes" ]]; then
    echo
    echo "$changes"
  fi
  echo
  echo "Internal-Commit: $source_commit"
  echo "Signed-off-by: $name <$email>"
} >"$message"

snapshot="$(git commit-tree "$source_tree" -p "$public_commit" -F "$message")"
rm -f "$message"

echo
echo "== files changed on public main"
git --no-pager diff --stat "$public_commit" "$snapshot"
echo
echo "== snapshot commit $(git rev-parse --short "$snapshot")"
git --no-pager log -1 --format='%B' "$snapshot"

if [[ "$push" != true ]]; then
  echo "dry run: review the file list and message above -- every line becomes public."
  echo "re-run with --push to publish."
  exit 0
fi

# A plain push: if public main moved since the fetch, or someone committed to it
# directly, this fails instead of discarding their work.
git push "$oss_remote" "$snapshot:refs/heads/main"
echo "published $(git rev-parse --short "$source_commit") to $oss_remote"
