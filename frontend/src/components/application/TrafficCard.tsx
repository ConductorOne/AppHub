import { useState } from 'react'
import { useUsage } from '../../hooks/useUsage'
import type { Application, Usage, UsageBucket, UsageRange } from '../../services/types'
import { Failure, httpsAddresses, Loading } from '../Feedback'
import { Icon } from '../../design/Icon'
import { NotAvailable } from '../../design/Preview'
import { relativeTime } from '../../design/status'
import { cardStyle, eyebrowStyle, monoCell, SectionHeader } from './parts'

const RANGE_OPTIONS: { key: UsageRange; label: string }[] = [
  { key: '24h', label: '24h' }, { key: '7d', label: '7d' }, { key: '30d', label: '30d' },
]
const RANGE_HOURS: Record<UsageRange, number> = { '24h': 24, '7d': 168, '30d': 720 }
const RANGE_BAR_HOURS: Record<UsageRange, number> = { '24h': 1, '7d': 6, '30d': 24 }
const HOUR_MS = 3_600_000

type Bar = { startMs: number; endMs: number; ok: number; warn: number; err: number; total: number }

/** Builds one bar per (24h) hour, (7d) 6-hour block, or (30d) day, zero-filling hours the API omitted. */
function buildBars(usage: Usage, range: UsageRange): Bar[] {
  const totalHours = RANGE_HOURS[range]
  const barHours = RANGE_BAR_HOURS[range]
  const sinceMs = Date.parse(usage.since)
  const byHour = new Map<number, UsageBucket>(usage.buckets.map(b => [Date.parse(b.hour), b]))
  const bars: Bar[] = []
  for (let barStart = 0; barStart < totalHours; barStart += barHours) {
    let ok = 0, warn = 0, err = 0, total = 0
    for (let h = barStart; h < barStart + barHours; h++) {
      const bucket = byHour.get(sinceMs + h * HOUR_MS)
      if (!bucket) continue
      ok += bucket.status2xx + bucket.status3xx
      warn += bucket.status4xx
      err += bucket.status5xx
      total += bucket.requests
    }
    bars.push({ startMs: sinceMs + barStart * HOUR_MS, endMs: sinceMs + (barStart + barHours) * HOUR_MS, ok, warn, err, total })
  }
  return bars
}

function formatAxisLabel(ms: number, range: UsageRange) {
  const date = new Date(ms)
  if (range === '24h') return date.toLocaleTimeString(undefined, { hour: 'numeric' })
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function formatBarTooltip(bar: Bar, range: UsageRange) {
  const start = new Date(bar.startMs)
  const end = new Date(bar.endMs)
  const span = range === '24h'
    ? `${start.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })} – ${end.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })}`
    : `${start.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric' })} – ${end.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric' })}`
  return `${span}: ${bar.total} requests (${bar.ok} 2xx/3xx, ${bar.warn} 4xx, ${bar.err} 5xx)`
}

function RangeToggle({ range, onChange }: { range: UsageRange; onChange: (range: UsageRange) => void }) {
  return <div style={{ display: 'inline-flex', border: '1px solid var(--line)', borderRadius: 6, padding: 2, background: 'var(--bg-2)' }}>
    {RANGE_OPTIONS.map(o => <button key={o.key} type="button" onClick={() => onChange(o.key)} style={{
      border: 0, borderRadius: 4, padding: '4px 10px', fontSize: 12, fontWeight: 600, fontFamily: 'inherit', cursor: 'pointer',
      background: range === o.key ? 'var(--bg-0)' : 'transparent', color: range === o.key ? 'var(--ink)' : 'var(--ink-2)',
      boxShadow: range === o.key ? '0 1px 2px rgba(0,0,0,.08)' : 'none',
    }}>{o.label}</button>)}
  </div>
}

function Legend() {
  const items = [{ color: 'var(--ok)', label: '2xx/3xx' }, { color: 'var(--warn)', label: '4xx' }, { color: 'var(--err)', label: '5xx' }]
  return <div style={{ display: 'flex', gap: 14, fontSize: 11.5, color: 'var(--ink-2)', marginTop: 10 }}>
    {items.map(i => <span key={i.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
      <span style={{ width: 8, height: 8, borderRadius: 2, background: i.color, flexShrink: 0 }} />{i.label}
    </span>)}
  </div>
}

function TrafficChart({ bars, range }: { bars: Bar[]; range: UsageRange }) {
  const chartPx = 88
  const max = Math.max(1, ...bars.map(b => b.total))
  return <div>
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: chartPx, borderBottom: '1px solid var(--line)' }}>
      {bars.map(bar => {
        const barPx = bar.total > 0 ? Math.max(2, Math.round((bar.total / max) * chartPx)) : 0
        const okPx = bar.total > 0 ? Math.round((bar.ok / bar.total) * barPx) : 0
        const warnPx = bar.total > 0 ? Math.round((bar.warn / bar.total) * barPx) : 0
        const errPx = Math.max(0, barPx - okPx - warnPx)
        return <div key={bar.startMs} title={formatBarTooltip(bar, range)}
          style={{ flex: 1, minWidth: 2, height: chartPx, display: 'flex', flexDirection: 'column-reverse' }}>
          {bar.total === 0
            ? <div style={{ height: 2, background: 'var(--line-emph)', borderRadius: 1 }} />
            : <>
              {okPx > 0 && <div style={{ height: okPx, background: 'var(--ok)' }} />}
              {warnPx > 0 && <div style={{ height: warnPx, background: 'var(--warn)' }} />}
              {errPx > 0 && <div style={{ height: errPx, background: 'var(--err)' }} />}
            </>}
        </div>
      })}
    </div>
    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--ink-3)', marginTop: 4 }}>
      <span>{formatAxisLabel(bars[0].startMs, range)}</span>
      <span>{formatAxisLabel(bars[bars.length - 1].endMs, range)}</span>
    </div>
  </div>
}

function StatRow({ usage }: { usage: Usage }) {
  const errors5xx = usage.buckets.reduce((sum, b) => sum + b.status5xx, 0)
  const errorPct = usage.totalRequests > 0 ? (errors5xx / usage.totalRequests) * 100 : 0
  const stats = [
    { label: 'Requests', value: usage.totalRequests.toLocaleString() },
    { label: 'Errors', value: `${errors5xx.toLocaleString()} (${errorPct.toFixed(errorPct > 0 && errorPct < 1 ? 1 : 0)}%)` },
    { label: 'Last request', value: usage.lastRequestAt ? relativeTime(usage.lastRequestAt) : 'Never' },
    { label: 'First request', value: usage.firstRequestAt ? new Date(usage.firstRequestAt).toLocaleDateString() : '—' },
  ]
  return <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px,1fr))', gap: 14, marginBottom: 14 }}>
    {stats.map(s => <div key={s.label}>
      <div style={eyebrowStyle}>{s.label}</div>
      <div style={{ ...monoCell, fontSize: 13.5, fontWeight: 600, marginTop: 3 }}>{s.value}</div>
    </div>)}
  </div>
}

function EmptyTraffic({ app }: { app: Application }) {
  const [address] = httpsAddresses(app.addresses)
  return <div style={{
    border: '1px dashed var(--line-emph)', borderRadius: 8, padding: '22px 18px', background: 'var(--bg-1)',
    display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: 6,
  }}>
    <Icon name="activity" size={20} color="var(--ink-4)" />
    <span style={{ fontSize: 13, fontWeight: 600 }}>No requests yet</span>
    <span style={{ fontSize: 12.5, color: 'var(--ink-2)', maxWidth: 440 }}>The first request shows up here within a few minutes of arriving.</span>
    {address && <a href={address} target="_blank" rel="noopener noreferrer" style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--teal)' }}>Open {address}</a>}
  </div>
}

function TrafficBody({ app, usage, range }: { app: Application; usage: ReturnType<typeof useUsage>; range: UsageRange }) {
  if (usage.isPending) return <Loading label="Loading traffic…" />
  if (usage.error) return <Failure error={usage.error} retry={() => void usage.refetch()} />
  const data = usage.data
  if (!data.collecting) return <NotAvailable icon="gauge" title="Traffic">Traffic collection isn't configured for this installation.</NotAvailable>
  if (!data.tracked) return <div style={{ fontSize: 12.5, color: 'var(--ink-3)', border: '1px solid var(--line)', borderRadius: 8, padding: '13px 15px' }}>
    This application has no route, so no requests pass through the ingress to count.
  </div>
  if (!data.firstRequestAt) return <EmptyTraffic app={app} />
  return <div style={cardStyle}>
    <div style={{ padding: '14px 15px' }}>
      <StatRow usage={data} />
      <TrafficChart bars={buildBars(data, range)} range={range} />
      <Legend />
      {data.collectedAt && <p style={{ fontSize: 11, color: 'var(--ink-3)', margin: '10px 0 0' }}>Updated {relativeTime(data.collectedAt)}</p>}
    </div>
  </div>
}

export default function TrafficCard({ app }: { app: Application }) {
  const [range, setRange] = useState<UsageRange>('7d')
  const usage = useUsage(app.id, range)
  return <div>
    <SectionHeader title="Traffic" action={<RangeToggle range={range} onChange={setRange} />} />
    <TrafficBody app={app} usage={usage} range={range} />
  </div>
}
