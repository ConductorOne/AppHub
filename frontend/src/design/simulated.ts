// Preview-only content with no backing API yet (vulnerability scanning,
// system logs on a deployment that cannot read CloudWatch). Deterministically seeded
// per application id so a given app looks stable within a session, never persisted,
// and never presented as live data — see <PreviewNote>/<PreviewChip>.
import type { ChipTone } from './Chip'

function seedFrom(id: string) {
  let n = 0
  for (const ch of id) n = (n * 31 + ch.charCodeAt(0)) >>> 0
  return n
}

function mulberry32(seed: number) {
  let a = seed
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const SEVERITIES: { label: string; tone: ChipTone }[] = [
  { label: 'Critical', tone: 'error' }, { label: 'High', tone: 'error' },
  { label: 'Medium', tone: 'warning' }, { label: 'Low', tone: 'muted' },
]

const PACKAGES = ['axios', 'next', 'cookie', 'lodash', 'zlib1g (base image)', 'golang.org/x/net', 'markdown-it']

export type SimulatedAdvisory = { id: string; severity: string; tone: ChipTone; title: string; cvss: string }
export type SimulatedVulnPackage = { id: string; name: string; current: string; fixed: string; summary: string; advisories: SimulatedAdvisory[] }

/** A stable-looking, seeded set of vulnerability rows for the preview-only Vulnerabilities tab. */
export function simulatedVulnPackages(appId: string): SimulatedVulnPackage[] {
  const rand = mulberry32(seedFrom(appId))
  const count = 1 + Math.floor(rand() * 3)
  const out: SimulatedVulnPackage[] = []
  for (let i = 0; i < count; i++) {
    const name = PACKAGES[Math.floor(rand() * PACKAGES.length)]!
    const severity = SEVERITIES[Math.floor(rand() * SEVERITIES.length)]!
    out.push({
      id: `${appId}-${i}`, name,
      current: `${1 + Math.floor(rand() * 9)}.${Math.floor(rand() * 20)}.${Math.floor(rand() * 10)}`,
      fixed: `${1 + Math.floor(rand() * 9)}.${Math.floor(rand() * 20)}.${Math.floor(rand() * 10)}`,
      summary: 'Illustrative advisory — connect a scanner to replace this preview.',
      advisories: [{ id: `CVE-PREVIEW-${1000 + Math.floor(rand() * 9000)}`, severity: severity.label, tone: severity.tone, title: 'Preview advisory placeholder', cvss: (rand() * 9 + 1).toFixed(1) }],
    })
  }
  return out
}

export function simulatedSeverityCounts(appId: string) {
  const rand = mulberry32(seedFrom(appId) + 1)
  return { critical: Math.floor(rand() * 2), high: Math.floor(rand() * 3), medium: Math.floor(rand() * 6), low: Math.floor(rand() * 5) }
}

/** Display names matching terraform/environments/example's observability_log_groups. */
export const SIMULATED_LOG_GROUPS = ['AppHub API', 'AppHub worker', 'Builds', 'Ingress (Traefik)', 'Ingress auth (oauth2-proxy)'] as const

const SYSTEM_LOG_LINES: Record<string, string[]> = {
  'AppHub API': [
    'INFO listening addr=0.0.0.0:8080',
    'INFO serving publicOrigin=https://apphub.example.com',
    'INFO directory catalog synced groups=34',
    'INFO signed in provider=google subject=106856311199570378101',
    'INFO GET /api/v1/applications status=200',
  ],
  'AppHub worker': [
    'INFO worker started',
    'INFO claimed operation kind=deploy application=checkout-api',
    'INFO build finished image=registry.example.invalid/checkout-api@sha256:e70bd41',
    'INFO deployment completed application=checkout-api replicas=2',
    'INFO directory catalog synced groups=34',
  ],
  'Builds': [
    'INFO cloning https://github.com/example/checkout-api ref=main',
    'INFO detected Dockerfile at ./Dockerfile',
    'INFO building linux/arm64',
    'INFO pushing registry.example.invalid/checkout-api:e70bd41',
    'INFO build complete duration=2m14s',
  ],
  'Ingress (Traefik)': [
    'Configuration loaded from file: /etc/traefik/traefik.yml',
    'Adding TLS certificates for apphub.example.com',
    'Serving checkout-api.apps.example.com -> http://checkout-api:8080',
    'Server returned HTTP status 200 "GET /healthz"',
  ],
  'Ingress auth (oauth2-proxy)': [
    '[oauth2-proxy] 10.0.1.14 - will.bengtson@conductorone.com [17/Sep/2026:20:01:03] apphub.example.com GET /oauth2/auth HTTP/1.1 202',
    '[oauth2-proxy] session refreshed provider=google',
    '[oauth2-proxy] 10.0.1.14 - anonymous [17/Sep/2026:20:04:11] apphub.example.com GET /oauth2/start HTTP/1.1 302',
  ],
}

export type SimulatedLogEvent = { timestamp: string; message: string }

/** Illustrative CloudWatch lines for the Workspace System logs tab when this deployment cannot read them. */
export function simulatedSystemLogs(group: string, now: number): SimulatedLogEvent[] {
  const lines = SYSTEM_LOG_LINES[group] ?? SYSTEM_LOG_LINES['AppHub API']!
  return lines.map((message, i) => ({
    timestamp: new Date(now - (lines.length - i) * 87_000).toISOString(),
    message,
  }))
}
