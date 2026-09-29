import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

const COLORS = {
  primary: { bg: 'var(--teal)', hover: 'var(--teal-dark)', contrast: 'var(--on-accent)' },
  error: { bg: 'var(--err)', hover: 'var(--err-dark)', contrast: 'var(--on-accent)' },
  success: { bg: 'var(--ok)', hover: 'var(--ok-ink)', contrast: 'var(--on-accent)' },
  neutral: { bg: 'var(--ink)', hover: 'var(--ink-strong)', contrast: 'var(--bg-0)' },
} as const

type Props = {
  children: ReactNode
  variant?: 'contained' | 'outlined' | 'text'
  color?: keyof typeof COLORS
  size?: 'sm' | 'md' | 'lg'
  disabled?: boolean
  startIcon?: ReactNode
  endIcon?: ReactNode
  onClick?: (event: React.MouseEvent) => void
  to?: string
  /** External URL, opened in a new tab. */
  href?: string
  style?: React.CSSProperties
  type?: 'button' | 'submit'
}

/** DS button: 6px radius, 13px/600 label, no text-transform. Variants: contained / outlined / text. */
export function Button({ children, variant = 'contained', color = 'primary', size = 'md', disabled = false, startIcon, endIcon, onClick, to, href, style = {}, type = 'button' }: Props) {
  const c = COLORS[color]
  const base: React.CSSProperties = {
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 6,
    fontFamily: "'Inter', system-ui, sans-serif", fontWeight: 600,
    fontSize: size === 'sm' ? 12 : size === 'lg' ? 14 : 13,
    letterSpacing: '0.004em', lineHeight: 1,
    padding: size === 'sm' ? '5px 9px' : size === 'lg' ? '9px 16px' : '7px 12px',
    borderRadius: 6, border: '1px solid transparent', textTransform: 'none',
    cursor: disabled ? 'not-allowed' : 'pointer', transition: 'all 200ms cubic-bezier(0.4,0,0.2,1)',
    whiteSpace: 'nowrap', textDecoration: 'none',
  }
  let variantStyle: React.CSSProperties
  let hoverBg: string
  let hoverBorder: string
  if (disabled) {
    variantStyle = { background: 'var(--bg-3)', color: 'var(--ink-dim)', borderColor: 'transparent' }
    hoverBg = 'var(--bg-3)'; hoverBorder = 'transparent'
  } else if (variant === 'contained') {
    variantStyle = { background: c.bg, color: c.contrast, borderColor: c.bg }
    hoverBg = c.hover; hoverBorder = c.hover
  } else if (variant === 'outlined') {
    variantStyle = { background: 'transparent', color: c.bg, borderColor: 'var(--line)' }
    hoverBg = 'var(--bg-1)'; hoverBorder = 'var(--line-emph)'
  } else {
    variantStyle = { background: 'transparent', color: c.bg, borderColor: 'transparent', padding: size === 'sm' ? '5px 6px' : '7px 8px' }
    hoverBg = 'var(--bg-2)'; hoverBorder = 'transparent'
  }
  const hoverVars = { '--ds-btn-hover-bg': hoverBg, '--ds-btn-hover-border': hoverBorder } as React.CSSProperties
  const content = <>{startIcon}{children}{endIcon}</>
  const combined = { ...base, ...variantStyle, ...hoverVars, ...style }
  if (href && !disabled) return <a href={href} target="_blank" rel="noopener noreferrer" className="ds-btn" style={combined}>{content}</a>
  if (to && !disabled) return <Link to={to} className="ds-btn" style={combined}>{content}</Link>
  return <button type={type} disabled={disabled} onClick={onClick} className="ds-btn" style={combined}>{content}</button>
}
