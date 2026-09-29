// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Client-side mirror of the public-path rules internal/controlplane/input.go
 * enforces server-side (validatePublicPaths): exact match, a wildcard only
 * as a final /*, no bare /*, no duplicates. Messages match the server's so a
 * rejection reads the same whether it is caught here before a save or
 * echoed back from the API afterward.
 *
 * This mirror deliberately omits the server's extra proxy-safety checks
 * (charset, ".." segments, empty "//" segments): those exist to defend
 * against a proxy that normalizes a path differently than this check
 * matches it, not to guide an owner typing a path in the portal. A value
 * that slips past this mirror is still refused server-side and surfaced
 * through the ordinary API error path.
 */
export function validatePublicPath(path: string, existing: string[]): string | undefined {
  const p = path.trim()
  if (!p) return 'Enter a path.'
  if (p[0] !== '/') return 'Paths start with /.'
  if (/\s/.test(p)) return 'Paths cannot contain spaces.'
  if (p.includes('*') && !p.endsWith('/*')) return 'A wildcard is only allowed as a final /*.'
  if (p === '/*') return 'That makes every path public. Turn off sign-in instead.'
  if (existing.includes(p)) return 'This path is already public.'
  return undefined
}
