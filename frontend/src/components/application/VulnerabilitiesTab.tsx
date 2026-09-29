import { useState } from 'react'
import { Chip } from '../../design/Chip'
import { Icon } from '../../design/Icon'
import { PreviewChip, PreviewNote } from '../../design/Preview'
import { simulatedSeverityCounts, simulatedVulnPackages } from '../../design/simulated'
import { monoCell } from './parts'

export default function VulnerabilitiesTab({ appId }: { appId: string }) {
  const counts = simulatedSeverityCounts(appId)
  const packages = simulatedVulnPackages(appId)
  const [open, setOpen] = useState<string>()
  const cards = [
    { label: 'Critical', n: counts.critical, fg: 'var(--err-ink)', bg: 'var(--err-tint)', border: 'var(--err-line)' },
    { label: 'High', n: counts.high, fg: 'var(--err-ink)', bg: 'var(--err-tint)', border: 'var(--err-line)' },
    { label: 'Medium', n: counts.medium, fg: 'var(--warn-ink)', bg: 'var(--warn-tint)', border: 'var(--warn-line)' },
    { label: 'Low', n: counts.low, fg: 'var(--ink-2)', bg: 'var(--bg-2)', border: 'var(--line)' },
  ]
  return <div style={{ maxWidth: 1000 }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 3 }}>
      <h3 style={{ fontSize: 15, fontWeight: 600, margin: 0 }}>Vulnerabilities</h3><PreviewChip />
    </div>
    <p style={{ fontSize: 12.5, color: 'var(--ink-2)', margin: '0 0 12px' }}>Grouped by package, so one version bump closes every advisory under it.</p>
    <PreviewNote>Vulnerability scanning isn't connected yet — these rows are illustrative, not a real scan result.</PreviewNote>
    <div style={{ display: 'flex', gap: 10, margin: '14px 0 18px', flexWrap: 'wrap' }}>
      {cards.map(s => <div key={s.label} style={{ flex: '1 1 130px', border: `1px solid ${s.border}`, borderRadius: 8, padding: '12px 14px', background: s.bg }}>
        <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: s.fg }}>{s.label}</div>
        <div style={{ fontFamily: "'Anybody', sans-serif", fontSize: 24, fontWeight: 600, letterSpacing: '-0.015em', color: s.fg, marginTop: 4 }}>{s.n}</div>
      </div>)}
    </div>
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {packages.map(p => <div key={p.id} style={{ border: '1px solid var(--line)', borderRadius: 8, overflowX: 'auto' }}>
        <button type="button" onClick={() => setOpen(open === p.id ? undefined : p.id)} aria-expanded={open === p.id} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 13, padding: '13px 16px', width: '100%', border: 0, background: 'transparent', cursor: 'pointer', fontFamily: 'inherit', color: 'inherit', textAlign: 'left', flexWrap: 'wrap' }}>
          <Icon name={open === p.id ? 'chevron-down' : 'chevron-right'} size={16} color="var(--ink-4)" />
          <div style={{ flex: 1, minWidth: 180 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9, flexWrap: 'wrap' }}>
              <span className="ds-mono" style={{ fontSize: 13, fontWeight: 500 }}>{p.name}</span>
              <span className="ds-mono" style={{ fontSize: 11.5, color: 'var(--ink-3)' }}>{p.current} → {p.fixed}</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--ink-2)', marginTop: 2 }}>{p.summary}</div>
          </div>
          <div style={{ display: 'flex', gap: 5 }}>{p.advisories.map(a => <Chip key={a.id} tone={a.tone} size="extraSmall">{a.severity}</Chip>)}</div>
        </button>
        {open === p.id && <div style={{ borderTop: '1px solid var(--bg-2)', background: 'var(--bg-1)' }}>
          {p.advisories.map(a => <div key={a.id} style={{ display: 'grid', gridTemplateColumns: 'minmax(0,150px) minmax(0,80px) minmax(0,1fr) minmax(0,52px)', gap: 14, alignItems: 'center', padding: '11px 16px 11px 45px', borderBottom: '1px solid var(--bg-2)' }}>
            <span style={{ ...monoCell, fontSize: 12, fontWeight: 500 }}>{a.id}</span>
            <div><Chip tone={a.tone} size="extraSmall">{a.severity}</Chip></div>
            <div style={{ fontSize: 12.5, minWidth: 0 }}>{a.title}</div>
            <div style={{ ...monoCell, fontSize: 12, color: 'var(--ink-2)', textAlign: 'right' }}>{a.cvss}</div>
          </div>)}
        </div>}
      </div>)}
    </div>
  </div>
}
