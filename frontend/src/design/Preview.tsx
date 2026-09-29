import type { ReactNode } from 'react'
import { Icon } from './Icon'

/** Marks UI backed by simulated/local data rather than a real API, so it can't be mistaken for live state. */
export function PreviewNote({ children }: { children: ReactNode }) {
  return <div style={{
    display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--ink-2)',
    background: 'var(--bg-1)', border: '1px solid var(--line)', borderRadius: 6, padding: '7px 11px',
  }}>
    <Icon name="flask-conical" size={14} color="var(--ink-4)" />
    <span>{children}</span>
  </div>
}

export function PreviewChip() {
  return <span style={{
    display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10.5, fontWeight: 600,
    letterSpacing: '.04em', textTransform: 'uppercase', color: 'var(--preview-ink)', background: 'var(--preview-tint)',
    border: '1px solid var(--preview-line)', borderRadius: 4, padding: '1px 6px',
  }}>Preview</span>
}

/**
 * Placeholder for a designed feature with no backend yet. Renders no data —
 * real or simulated. `chip` defaults to "Not available yet"; pass
 * `<PrivateBetaChip />` for a feature whose backend exists but is not yet
 * open to every workspace. `action`, if given, renders below the description
 * (typically a disabled button — this component never wires one up).
 */
export function NotAvailable({ icon, title, chip, action, children }: { icon: string; title: string; chip?: ReactNode; action?: ReactNode; children: ReactNode }) {
  return <div style={{
    border: '1px dashed var(--line-emph)', borderRadius: 8, padding: '22px 18px', background: 'var(--bg-1)',
    display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: 6,
  }}>
    <Icon name={icon} size={20} color="var(--ink-4)" />
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
      <span style={{ fontSize: 13, fontWeight: 600 }}>{title}</span>{chip ?? <NotAvailableChip />}
    </div>
    <div style={{ fontSize: 12.5, color: 'var(--ink-2)', maxWidth: 440 }}>{children}</div>
    {action && <div style={{ marginTop: 4 }}>{action}</div>}
  </div>
}

/** Marks a feature whose backend exists but is not yet open to every workspace. */
export function PrivateBetaChip() {
  return <span style={{
    display: 'inline-flex', alignItems: 'center', fontSize: 10.5, fontWeight: 600, letterSpacing: '.04em',
    textTransform: 'uppercase', color: 'var(--teal-dark)', background: 'var(--teal-tint)', border: '1px solid var(--teal-line)',
    borderRadius: 4, padding: '1px 6px', whiteSpace: 'nowrap',
  }}>Private Beta</span>
}

export function NotAvailableChip() {
  return <span style={{
    display: 'inline-flex', alignItems: 'center', fontSize: 10.5, fontWeight: 600, letterSpacing: '.04em',
    textTransform: 'uppercase', color: 'var(--ink-3)', background: 'var(--bg-2)', border: '1px solid var(--line)',
    borderRadius: 4, padding: '1px 6px', whiteSpace: 'nowrap',
  }}>Not available yet</span>
}
