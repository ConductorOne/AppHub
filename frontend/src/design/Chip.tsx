import type { ReactNode } from 'react'

const TONES = {
  default: { bg: 'var(--bg-3)', color: 'var(--ink)', border: 'var(--line-emph)' },
  teal: { bg: 'var(--teal-tint)', color: 'var(--teal-dark)', border: 'var(--teal-line)' },
  success: { bg: 'var(--ok-tint)', color: 'var(--ok-ink)', border: 'var(--ok-line)' },
  warning: { bg: 'var(--warn-tint)', color: 'var(--warn-ink)', border: 'var(--warn-line)' },
  error: { bg: 'var(--err-tint)', color: 'var(--err-ink)', border: 'var(--err-line)' },
  muted: { bg: 'var(--bg-2)', color: 'var(--ink-2)', border: 'var(--line)' },
  filled: { bg: 'var(--teal)', color: 'var(--on-accent)', border: 'var(--teal-dark)' },
} as const

export type ChipTone = keyof typeof TONES

type Props = { children: ReactNode; tone?: ChipTone; size?: 'extraSmall' | 'small' | 'medium'; dot?: boolean; pulse?: boolean; style?: React.CSSProperties }

/** Compact status/tag chip: tonal fill, one-step-darker border, optional leading dot that can pulse for in-flight work. */
export function Chip({ children, tone = 'default', size = 'small', dot = false, pulse = false, style = {} }: Props) {
  const t = TONES[tone]
  const pad = size === 'extraSmall' ? '2px 6px' : size === 'medium' ? '6px 10px' : '4px 8px'
  const fs = size === 'extraSmall' ? 10.5 : size === 'medium' ? 13 : 12
  return <span style={{
    display: 'inline-flex', alignItems: 'center', gap: 5, background: t.bg, color: t.color,
    border: `1px solid ${t.border}`, fontFamily: "'Inter', system-ui, sans-serif", fontSize: fs,
    fontWeight: 500, lineHeight: 1.2, padding: pad, borderRadius: 6, whiteSpace: 'nowrap', ...style,
  }}>
    {dot && <span className={pulse ? 'ah-pulse' : undefined} style={{ width: 6, height: 6, borderRadius: 3, background: t.color, flexShrink: 0 }} />}
    {children}
  </span>
}
