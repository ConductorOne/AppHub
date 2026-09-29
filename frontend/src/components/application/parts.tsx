import type { ReactNode } from 'react'

export type AppTab = 'overview' | 'settings' | 'authentication' | 'secrets' | 'resources' | 'domains' | 'vulnerabilities' | 'activity'

export const cardStyle: React.CSSProperties = { border: '1px solid var(--line)', borderRadius: 8, overflow: 'hidden' }
export const eyebrowStyle: React.CSSProperties = { fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }
export const monoCell: React.CSSProperties = { fontFamily: "'Geist Mono', monospace", letterSpacing: '-.02em', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }

export function SectionHeader({ title, description, action }: { title: string; description?: ReactNode; action?: ReactNode }) {
  return <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16, marginBottom: 12, flexWrap: 'wrap' }}>
    <div>
      <h3 style={{ fontSize: 15, fontWeight: 600, margin: description ? '0 0 3px' : 0 }}>{title}</h3>
      {description && <p style={{ fontSize: 12.5, color: 'var(--ink-2)', margin: 0 }}>{description}</p>}
    </div>
    {action}
  </div>
}

/** One label/hint → value row inside a bordered settings card. */
export function FieldRow({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <div style={{ display: 'grid', gridTemplateColumns: 'minmax(110px,190px) minmax(0,1fr)', gap: 16, alignItems: 'center', padding: '12px 15px', borderBottom: '1px solid var(--bg-2)' }}>
    <div>
      <div style={{ fontSize: 12.5, fontWeight: 500 }}>{label}</div>
      {hint && <div style={{ fontSize: 11.5, color: 'var(--ink-3)' }}>{hint}</div>}
    </div>
    <div className="break-text" style={{ minWidth: 0, fontFamily: "'Geist Mono', monospace", fontSize: 12.5, letterSpacing: '-.02em' }}>{children}</div>
  </div>
}

export function CardHeader({ title, action }: { title: ReactNode; action?: ReactNode }) {
  return <div style={{ padding: '12px 15px', borderBottom: '1px solid var(--bg-2)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
    <span style={{ fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8 }}>{title}</span>
    {action}
  </div>
}

/** Inline text-style action that switches tabs or triggers a local action (no navigation). */
export function LinkButton({ children, onClick }: { children: ReactNode; onClick: () => void }) {
  return <button type="button" onClick={onClick} style={{ border: 0, background: 'transparent', padding: 0, cursor: 'pointer', fontFamily: 'inherit', fontSize: 12, fontWeight: 500, color: 'var(--teal)' }}>{children}</button>
}
