#!/usr/bin/env bash
# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Scans repository *path names* for the same disclosures the content scan looks
# for.
#
# gitleaks reads file contents and diffs; it never looks at the names. Review
# demonstrated the consequence: a file whose name was nothing but a twelve-digit
# account ID passed the entire secret gate. A path is published exactly as surely
# as a line of a file, and an account ID is a perfectly ordinary thing to name a
# fixture, a log dump, or a screenshot after.
#
# (The example is described rather than written out, for the same reason the
# fixtures in hack/check-secret-rules.sh are assembled at run time: a literal
# here would be a disclosure-shaped string in a public repository, and the rules
# below would rightly flag it.)
#
# Rather than restate the rules, this feeds the list of paths back through
# .gitleaks.toml as content. There is one set of patterns and one set of
# allowlists, so a rule fixed in one place is fixed in both.
set -euo pipefail

cd "$(dirname "$0")/.."

target="${1:-.}"
GITLEAKS="${GITLEAKS:-.tools/gitleaks}"
if [ ! -x "$GITLEAKS" ]; then
  echo "gitleaks not found at $GITLEAKS; run 'make tools'" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# One path per line. Skips the same directories the other checks skip: they are
# either not ours or not published.
find "$target" -type f \
  -not -path '*/.git/*' \
  -not -path '*/.tools/*' \
  -not -path '*/.task-worktrees/*' \
  -not -path '*/.dynamodb/*' \
  -not -path '*/.local/*' \
  -not -path '*/vendor/*' \
  -not -path '*/node_modules/*' \
  | sed "s|^$target/||" | sort > "$work/paths.txt"

if [ ! -s "$work/paths.txt" ]; then
  echo "no files found under $target -- refusing to pass a check that inspected nothing" >&2
  exit 1
fi

report="$work/report.json"
"$GITLEAKS" dir "$work/paths.txt" \
  --config .gitleaks.toml \
  --no-banner \
  --report-format json \
  --report-path "$report" \
  --exit-code 0 >/dev/null 2>&1

count="$(grep -c '"RuleID"' "$report" 2>/dev/null || true)"
if [ "${count:-0}" -eq 0 ]; then
  echo "paths: ok ($(wc -l < "$work/paths.txt" | tr -d ' ') path(s) checked against the disclosure rules)"
  exit 0
fi

echo "paths: $count disclosure(s) in file names" >&2
echo >&2
# Each line of paths.txt is one path, so the finding's line number is its index.
python3 - "$report" "$work/paths.txt" >&2 <<'PY'
import json, sys
findings = json.load(open(sys.argv[1]))
paths = open(sys.argv[2]).read().splitlines()
for f in sorted(findings, key=lambda x: (x.get("StartLine", 0), x["RuleID"])):
    line = f.get("StartLine", 0)
    path = paths[line - 1] if 0 < line <= len(paths) else "(unknown)"
    print(f"  {path}\n      matched {f['RuleID']}\n")
PY
cat >&2 <<'EOF'
A file name is published as surely as a line inside it. Rename the file. If the
name is legitimate, allowlist it in .gitleaks.toml deliberately -- the same
allowlist governs content, so widening it is visible in review.
EOF
exit 1
