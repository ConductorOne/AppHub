#!/usr/bin/env bash
# Copyright 2026 ConductorOne, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Proves the disclosure rules in .gitleaks.toml still fire.
#
# "no leaks found" is the output of a working scanner and of a broken one, and
# review demonstrated the difference: the scan passed while the repository's
# known landmine -- a twelve-digit AWS account ID -- sat in the tree, because no
# rule was looking for it. A scanner nobody has tried to defeat is a scanner
# with an unknown detection rate.
#
# So each disclosure class gets a synthetic example planted in a temporary
# directory, and this script fails if the corresponding rule does not fire.
#
# Every fixture value is assembled at run time from fragments. If the finished
# strings appeared as literals here, this file would itself be a disclosure, and
# `make secrets` would flag the very script that tests it -- which is a fair
# indication the rules work, and an entirely useless way to run CI.
set -euo pipefail

cd "$(dirname "$0")/.."

GITLEAKS="${GITLEAKS:-.tools/gitleaks}"
if [ ! -x "$GITLEAKS" ]; then
  echo "gitleaks not found at $GITLEAKS; run 'make tools'" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- fixtures, assembled so this file contains no matching literal -----------
acct="$(printf '%s%s%s' 1234 5678 9012)"
sg="sg-$(printf '%s' 0a1b2c3d)"
host="deploy.$(printf '%s' svcs).$(printf '%s' corp)"
# An unlisted top-level domain. The first version of the hostname rule
# enumerated suffixes, so a URL under one it had not thought of walked through.
odd_tld="internal-thing.$(printf '%s' co)"
# A plain two-label hostname assigned to a value. Not a URL, not a filename
# trick -- the most ordinary configuration shape there is, and the general rule
# needed three labels, so it went straight through.
plain_host="internal-host.$(printf '%s' io)"
# A private-use suffix IANA does not delegate. Requiring a registrable suffix
# must not lose these: they are what internal hosts actually end in.
private_host="db.$(printf '%s' internal)"
# A URL under a suffix nobody has registered. The context-anchored rules stay
# fail-closed whatever the suffix, which is the round-3 property; only the
# shape-only rules require a known one.
odd_suffix_url="weird-thing.$(printf '%s' zzz)"
# The reserved documentation TLDs (RFC 2606) include the bare ".example"
# suffix, not just the second-level "example.com" form already allowlisted.
# USOSS-64: a host ending in the bare suffix must not be flagged -- it is
# reserved, and by construction never a real host.
example_host="docs.$(printf '%s' example)"
# ...and the allowlist addition must not widen past the reserved suffix: a
# host that merely contains the label "example" under an ordinary suffix is
# not reserved and must stay a finding.
example_lookalike="internal-example.$(printf '%s' corp)"
# A deployment-specific AWS endpoint. A blanket amazonaws.com exception used to
# wave this through, which is the opposite of what the rule is for.
rds_host="prod-db.$(printf '%s' abc123).us-east-1.$(printf '%s' rds).$(printf '%s' amazonaws).$(printf '%s' com)"
# Kubernetes API group names and the bare cluster-internal DNS suffix, which
# must NOT be flagged: an API group is an identifier in the Kubernetes type
# system, not a host, and a provider that could not name one could not write an
# object (USOSS-27).
k8s_group="networking.$(printf '%s' k8s).$(printf '%s' io)"
k8s_label="app.$(printf '%s' kubernetes).$(printf '%s' io)"
k8s_suffix="svc.$(printf '%s' cluster).$(printf '%s' local)"
# ...and the case the suffix exemption must NOT drag in with it. A full
# in-cluster DNS name discloses a service and a namespace, which is exactly what
# the rule is for, so the allowlist entry is anchored to the bare suffix.
k8s_internal="payments-prod.finance.$(printf '%s' svc).$(printf '%s' cluster).$(printf '%s' local)"
# Genuine public AWS service endpoints, which must NOT be flagged, or the rule
# becomes noise and gets deleted.
svc_global="s3.$(printf '%s' amazonaws).$(printf '%s' com)"
svc_regional="dynamodb.us-east-1.$(printf '%s' amazonaws).$(printf '%s' com)"
# Not the canonical AWS documentation key: gitleaks allowlists that one by
# design, so using it would test nothing.
akid="AKIA$(printf '%s' Q7ZC3XV2LM4RTB9W)"
# Go selector chains whose last label is a registrable suffix. `store` and
# `name` are gTLDs, `mu` is Mauritius, `now` is a gTLD -- so a mutex reached
# through a field named `store` is shaped exactly like a three-label host. This
# is the class that put 218 findings on the first large port, and requiring a
# registrable suffix is what caused it rather than what prevented it: the
# discriminator was never the suffix, it is whether the token is data or code.
chain_mu="h.p.$(printf '%s' store).$(printf '%s' mu)"
chain_now="p.$(printf '%s' store).$(printf '%s' now)"
chain_name="r.p.$(printf '%s' name)"
# A structured-data key whose last label is a registrable suffix. `host` is a
# gTLD, so a map key labelling a hostname field is character-for-character a
# two-label host in the one position the Go value rule keys on: alone inside a
# string literal. Its siblings `endpoint.port` and `endpoint.database` set the
# convention and neither is a registrable suffix, so only this one fires.
# Renaming the key to dodge the scanner would make the code worse to satisfy a
# tool, so the key stays and the allowlist carries one exact-anchored entry.
key_host="endpoint.$(printf '%s' host)"
key_port="endpoint.$(printf '%s' port)"
key_db="endpoint.$(printf '%s' database)"
# A Kubernetes API group. Domain-shaped by design, and a Kubernetes provider
# cannot avoid naming one. Covered here in prose, which is where most of them
# appear; the same group inside a string literal is NOT covered and cannot be,
# because there it is character-for-character a hardcoded host in the same
# position. See the pull request that added the Go rules.
api_group="networking.$(printf '%s' k8s).$(printf '%s' io)"

{
  printf 'role = "arn:aws:iam::%s:role/Example"\n' "$acct"
  printf 'aws_account_id = "%s"\n' "$acct"
  printf 'registry = "%s%sus-east-1%s"\n' "$acct" "$(printf '%s' .dkr.ecr.)" "$(printf '%s' .amazonaws.com)"
  printf 'security_group = "%s"\n' "$sg"
  printf 'endpoint = "https://%s/health"\n' "$host"
  printf 'other = "https://%s/health"\n' "$odd_tld"
  printf 'plain = "%s"\n' "$plain_host"
  printf 'in_yaml: %s\n' "$plain_host"
  printf 'private = "%s"\n' "$private_host"
  printf 'odd = "https://%s/health"\n' "$odd_suffix_url"
  printf 'database = "%s"\n' "$rds_host"
  printf '{"aws_account_id": "%s"}\n' "$acct"
  printf '// deployed into %s by hand\n' "$acct"
  printf 'aws_access_key_id = "%s"\n' "$akid"
} > "$work/planted.tf"

# Go source that DOES disclose, in the three positions a Go file can hold one.
# The source repository this project ports from has its internal domain inside a
# format string in the deploy path, so a Go rule that stops reading string
# literals stops catching the one disclosure known to exist. The manifest below
# is the plain-scalar half of the embedded-YAML bypass: a key and a value on one
# line, which no block indicator introduces.
{
  printf 'package z\n\n'
  printf 'func hostRule(name, env string) string {\n'
  printf '\treturn fmt.Sprintf("Host(%%s.%%s.%s)", name, env)\n' "$host"
  printf '}\n\n'
  printf 'const apex = "%s"\n' "$plain_host"
  printf '\nconst manifest = `\nspec:\n  server: %s\n`\n' "$private_host"
} > "$work/planted.go"

# Go source that looks like a block scalar but is not: an indented dotted
# identifier inside a raw string, with no block indicator introducing it. Metric
# names and subtest names are shaped exactly like two-label hostnames, and a
# rule that reports them is a rule somebody switches off.
{
  printf 'package x\n\n'
  # An import path. The domain is followed by a slash, which is what keeps the
  # whole-string value rule off every import block in the repository.
  printf 'import "%s/apimachinery/pkg/runtime/schema"\n\n' "$(printf '%s.%s' k8s io)"
  printf 'const doc = `\nsubtests:\n'
  printf '  case.name\n'
  printf '  request.failed\n'
  printf '  pkg.method\n'
  printf '`\n'
  # Selector chains, which is what a dotted lowercase token in Go source almost
  # always is. Every one of these ends in a registrable suffix, so no suffix
  # list can separate them from a host; what separates them is that they are
  # expressions rather than data. This is the class that produced the 218.
  printf '\nfunc (h *handle) lock() Status {\n'
  printf '\t%s.Lock()\n' "$chain_mu"
  printf '\tdefer %s.Unlock()\n' "$chain_mu"
  printf '\t_ = %s()\n' "$chain_now"
  printf '\t_ = %s\n' "$chain_name"
  # A composite literal spread over lines. gofmt's trailing comma is what stops
  # the YAML-mapping rule reading a struct field as a plain scalar: without it,
  # `Host: <chain>` is a YAML key and value, character for character.
  printf '\treturn Status{\n\t\tHost: %s,\n\t}\n' "$chain_name"
  printf '}\n'
  # A Kubernetes API group in a doc comment. Prose, not an expression, and not a
  # host either -- the second of the two false-positive classes. Only the prose
  # form is covered; see the note on api_group above.
  printf '\n// A %s Ingress cannot serve a caller-chosen port.\n' "$api_group"
  # Map keys labelling the parts of an endpoint. The first is a whole string
  # literal whose second label is a gTLD, which is the shape the Go value rule
  # exists to catch; what makes it not a host is that it names a field rather
  # than addressing anything. Its two siblings are here because they are the
  # reason the key is spelled this way.
  printf '\nfunc observed(st Status) map[string]string {\n'
  printf '\treturn map[string]string{\n'
  printf '\t\t"%s":     st.Endpoint.Host,\n' "$key_host"
  printf '\t\t"%s":     st.Endpoint.Port,\n' "$key_port"
  printf '\t\t"%s": st.Endpoint.DatabaseName,\n' "$key_db"
  printf '\t}\n}\n'
} > "$work/allowed.go"

# ...and the case that must NOT be waved through with it: a real YAML document
# embedded in a Go raw string. The indicator line is what tells them apart, so
# both live in .go files and only one is a finding. The host is on a later line
# of the block, because the first line is the easy case.
{
  printf 'package y\n\nconst manifest = `\nhost: |\n  %s\n`\n' "$plain_host"
  printf '\nconst nested = `\nspec: >-\n  some: value\n  %s\n`\n' "$plain_host"
} > "$work/embedded_yaml.go"

# YAML block scalars put the value on a following line, so the position rule
# that keys on adjacency to the colon cannot see it. Both indicator forms.
{
  printf 'literal_block: |\n  %s\n' "$plain_host"
  printf 'folded_block: >-\n  %s\n' "$plain_host"
} > "$work/block.yml"

# A generic high-entropy token in its own file, so the assertion that the
# default rule set is still loaded does not depend on any rule added here.
generic="$(printf '%s%s' hK7pQ2vX9mZ4tR6y B1nL8wC3dF5gJ0sA)"
printf 'api_key = "%s"\n' "$generic" > "$work/generic.env"

# Hosts that must NOT be flagged. A gate that fires on a legitimate AWS service
# endpoint is a gate somebody switches off.
{
  printf 'a = "https://%s/bucket"\n' "$svc_global"
  printf 'b = "https://%s/"\n' "$svc_regional"
  printf 'c = "%s"\n' "$svc_global"
  # Source file names are shaped exactly like two-label hostnames. If the
  # extension exception ever stops working, every Go file in the repository
  # becomes a finding and the gate gets switched off within the hour.
  printf 'd = "boundary.%s"\n' "$(printf '%s' go)"
  printf 'e = "ci.%s"\n' "$(printf '%s' yml)"
  # Go source shapes that are not hostnames.
  printf 'f := x != tc.want\n'
  printf 'g := pkg.field\n'
  # Reported from the first real port (USOSS-7): ordinary Go field chains read
  # as hostnames unless the suffix has to be a registrable one.
  printf 'h := r.reply.body\n'
  printf 'i = tc.value\n'
  printf 'j = "request.failed"\n'
  # Public vendor API roots the credential providers must name in code. If the
  # allowlist ever stops covering these, the first porting pull request drowns
  # in findings -- which is how a gate gets switched off.
  printf 'k = "api.%s"\n' "$(printf '%s' datadoghq.com)"
  printf 'l = "api.%s"\n' "$(printf '%s' github.com)"
  printf 'm = "api.%s"\n' "$(printf '%s' ddog-gov.com)"
  printf 'n = "api.%s"\n' "$(printf '%s' datadoghq.eu)"
  printf 'o = "api.us3.%s"\n' "$(printf '%s' datadoghq.com)"
  printf '    pkg.method()\n'
  printf '    - list.item\n'
  # Kubernetes API group names and the bare cluster DNS suffix (USOSS-27). A
  # Kubernetes provider names these in every object it writes.
  printf 'p = "%s"\n' "$k8s_group"
  printf 'q = "%s"\n' "$k8s_label"
  printf 'r = "%s"\n' "$k8s_suffix"
  printf 's = "%s"\n' "$example_host"
  printf 't = "https://%s/health"\n' "$example_host"
} > "$work/allowed.tf"

# A full in-cluster DNS name, which must STILL be a finding: the allowlist entry
# above is anchored to the bare suffix precisely so that a real service and
# namespace cannot ride in behind it.
printf 'endpoint = "%s"\n' "$k8s_internal" > "$work/planted_cluster_dns.tf"
# The bare-".example" allowlist entry (USOSS-64) must not have widened to
# match a host that merely contains the word "example" under an ordinary
# suffix. Its own file, like the in-cluster DNS case above, so a regression
# here fails on this specific fixture rather than on some other host still
# tripping the same rule.
printf 'lookalike = "%s"\n' "$example_lookalike" > "$work/planted_example_lookalike.tf"

# Frontend exceptions name exact reviewed expressions, not whole source files.
# Keep a real hostname and a secret in that same source tree as negative controls.
portal_chain="app.$(printf '%s' specification).$(printf '%s' name)"
google_issuer="accounts.$(printf '%s' google).$(printf '%s' com)"
mkdir -p "$work/frontend/src"
printf 'const value = %s;\n' "$portal_chain" > "$work/frontend/src/allowed.tsx"
printf 'const endpoint = "%s";\n' "$host" > "$work/frontend/src/planted_portal.tsx"
printf 'const endpoint = "https://%s";\n' "$odd_suffix_url" > "$work/frontend/src/planted_portal_url.ts"
printf 'const aws_access_key_id = "%s";\n' "$akid" > "$work/frontend/src/planted_portal_secret.ts"
printf 'endpoint = "https://private.%s";\n' "$google_issuer" > "$work/planted_google_apex.tf"
printf 'const value = %s;\n' "$portal_chain" > "$work/planted_selector_outside_scope.tsx"

# A file named after an account ID. gitleaks reads contents, not names, so this
# is checked by hack/check-paths.sh rather than by the rules directly.
paths_fixture="$work/paths"
mkdir -p "$paths_fixture"
printf 'nothing sensitive inside\n' > "$paths_fixture/$acct.txt"

report="$work/report.json"
"$GITLEAKS" dir "$work" \
  --config .gitleaks.toml \
  --no-banner \
  --report-format json \
  --report-path "$report" \
  --exit-code 0 >/dev/null 2>&1

# --- assertions ---------------------------------------------------------------
# Each entry is "rule id:what it is supposed to catch".
expected=(
  "apphub-aws-account-id-in-arn:an account ID inside an ARN"
  "apphub-aws-account-id-assignment:an account ID assigned to an account-shaped name"
  "apphub-aws-ecr-registry-host:an ECR registry hostname, which embeds the account ID"
  "apphub-aws-infrastructure-identifier:a security-group identifier"
  "apphub-hostname-multilabel:a three-label internal hostname that is not on the allowlist"
  "apphub-aws-access-key-id:an AWS key under the identifier the default rules skip"
  "generic-api-key:a high-entropy key, proving the default rule set is still loaded"
  "apphub-twelve-digit-identifier:a bare twelve-digit ID in JSON, a comment, and an assignment"
  "apphub-hostname-in-url:a URL under a top-level domain no list enumerated"
  "apphub-hostname-two-label:a plain two-label hostname assigned as a value"
  "apphub-hostname-block-scalar:a hostname in a YAML block scalar, on its own line"
  "apphub-hostname-block-scalar-indicator:a hostname in YAML embedded in a Go raw string"
  "apphub-hostname-go-string:an internal domain inside a Go format string, which is where the source repository has its own"
  "apphub-hostname-go-string-value:a two-label host that is the whole of a Go string literal"
  "apphub-hostname-go-yaml-key:a host as a plain YAML scalar in a Go raw string, the half no block indicator introduces"
)

status=0
for entry in "${expected[@]}"; do
  id="${entry%%:*}"
  what="${entry#*:}"
  if grep -q "\"RuleID\": *\"$id\"" "$report"; then
    printf '  ok    %-42s %s\n' "$id" "$what"
  else
    printf '  FAIL  %-42s %s\n' "$id" "$what" >&2
    status=1
  fi
done

# The other half of a usable gate: things that must NOT fire. A rule that also
# flags every legitimate AWS service endpoint gets switched off within a week.
if grep -qE '"File": *"[^"]*allowed\.(tf|go|tsx?)"' "$report"; then
  printf '  FAIL  %-42s %s\n' "(false positive)" "a legitimate token was flagged: an AWS service endpoint, a Go selector chain, a Kubernetes API group in prose, or an import path" >&2
  status=1
else
  printf '  ok    %-42s %s\n' "(no false positive)" "AWS endpoints, Go selector chains, an API group in prose, an import path"
fi

# Each control stands alone so another finding cannot hide a widened exception.
for fixture in planted_portal.tsx planted_portal_url.ts planted_portal_secret.ts planted_google_apex.tf planted_selector_outside_scope.tsx; do
  if grep -qE "\"File\": *\"[^\"]*/?$fixture\"" "$report"; then
    printf '  ok    %-42s %s\n' "(frontend exception bounded)" "$fixture"
  else
    printf '  FAIL  %-42s %s\n' "(frontend exception widened)" "$fixture was not caught" >&2
    status=1
  fi
done

# The suffix exemption must not have widened the apex: a full in-cluster DNS
# name still discloses a service and a namespace.
if grep -qE '"File": *"[^"]*planted_cluster_dns\.tf"' "$report"; then
  printf '  ok    %-42s %s\n' "(cluster DNS not widened)" "a full in-cluster service DNS name"
else
  printf '  FAIL  %-42s %s\n' "(cluster DNS not widened)" "a full in-cluster service DNS name was not caught" >&2
  status=1
fi

# The .example allowlist entry (USOSS-64) must not have widened to match a
# host that merely contains the word "example" under an ordinary suffix.
if grep -qE '"File": *"[^"]*planted_example_lookalike\.tf"' "$report"; then
  printf '  ok    %-42s %s\n' "(.example not widened)" "a host containing \"example\" under a real suffix"
else
  printf '  FAIL  %-42s %s\n' "(.example not widened)" "a host containing \"example\" under a real suffix was not caught" >&2
  status=1
fi

# And the disclosure gitleaks structurally cannot see: the name of a file.
if ./hack/check-paths.sh "$paths_fixture" >/dev/null 2>&1; then
  printf '  FAIL  %-42s %s\n' "check-paths.sh" "an account ID in a file name was not caught" >&2
  status=1
else
  printf '  ok    %-42s %s\n' "check-paths.sh" "an account ID in a file name"
fi

if [ "$status" -ne 0 ]; then
  echo >&2
  echo "A disclosure rule stopped firing, or started firing on something legitimate." >&2
  echo "Either .gitleaks.toml changed, or the pinned gitleaks version behaves" >&2
  echo "differently. Do not silence this by editing the fixture -- the fixture is" >&2
  echo "the specification." >&2
  exit 1
fi

echo "secret rules: ok (${#expected[@]} disclosure classes detected, no false positives)"
