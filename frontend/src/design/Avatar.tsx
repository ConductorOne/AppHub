const HUES = ['#7353FF', '#A1006B', '#D157A1', '#FD6300', '#FFC62E', '#7A226A', '#8EAC4E', '#7DBE93', '#00343A', '#0070FF', '#381049', '#0D2056']

function hueFor(key: string) {
  let n = 0
  for (const ch of key || '') n = (n * 31 + ch.charCodeAt(0)) >>> 0
  return HUES[n % HUES.length]
}

type Props = { name: string; size?: number; radius?: number; color?: string; style?: React.CSSProperties }

/** Deterministic 12-hue avatar fill seeded from name, with initials. */
export function Avatar({ name = '', size = 32, radius = 8, color, style = {} }: Props) {
  const initials = (name.trim().split(/\s+/).map(w => w[0]).slice(0, 2).join('') || '?').toUpperCase()
  const bg = color || hueFor(name)
  const fg = bg === '#FFC62E' ? '#2A2826' : '#FFFFFF'
  return <div style={{
    width: size, height: size, borderRadius: radius, background: bg, color: fg,
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
    fontFamily: "'Inter', system-ui, sans-serif", fontSize: Math.round(size * 0.38), fontWeight: 600,
    flexShrink: 0, userSelect: 'none', ...style,
  }}>{initials}</div>
}
