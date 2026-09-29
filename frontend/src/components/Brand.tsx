import { Box } from '@mui/material'
import { useColorScheme } from '@mui/material/styles'
import { Link } from 'react-router-dom'
import { Icon } from '../design/Icon'
import logoDark from '../assets/logo-dark.png'
import logoLight from '../assets/logo-light.png'
import wordmarkDark from '../assets/logo-wordmark-dark.png'
import wordmarkLight from '../assets/logo-wordmark-light.png'

const LOCKUP_RATIO = 902 / 858
const WORDMARK_RATIO = 1024 / 202

export function BrandLogo({ height = 36, to, wordmark = false }: { height?: number; to?: string; wordmark?: boolean }) {
  const ratio = wordmark ? WORDMARK_RATIO : LOCKUP_RATIO
  const light = wordmark ? wordmarkLight : logoLight
  const dark = wordmark ? wordmarkDark : logoDark
  const frame = { position: 'relative' as const, display: 'block', height, width: height * ratio, lineHeight: 0 }
  const img = { position: 'absolute' as const, inset: 0, width: '100%', height: '100%', objectFit: 'contain' as const, objectPosition: 'left center' }
  const image = (
    <Box sx={frame}>
      <Box component="img" src={light} alt="AppHub" className="brand-logo brand-logo-light" sx={img} />
      <Box component="img" src={dark} alt="" className="brand-logo brand-logo-dark" sx={{ ...img, display: 'none' }} aria-hidden />
    </Box>
  )
  if (!to) return image
  return <Box component={Link} to={to} aria-label="AppHub home" sx={{ display: 'inline-flex', alignItems: 'center', textDecoration: 'none', lineHeight: 0 }}>{image}</Box>
}

// Layout only. The border and colours live on .theme-toggle in styles.css so the
// :hover rule there can actually win — an inline style would outrank it.
const TOGGLE_BOX: React.CSSProperties = {
  display: 'flex', alignItems: 'center', justifyContent: 'center', width: 26, height: 26,
  borderRadius: 6, background: 'var(--bg-0)', flexShrink: 0,
}

/** 26px icon button that flips light/dark. Shows the mode it switches *to*: moon on light, sun on dark. */
export function ColorModeToggle() {
  const { mode, setMode, systemMode } = useColorScheme()
  // mode is undefined until the provider reads storage; hold the space so the sidebar does not shift.
  if (!mode) return <span style={{ ...TOGGLE_BOX, background: 'none' }} />
  const dark = (mode === 'system' ? systemMode : mode) === 'dark'
  const label = dark ? 'Switch to light mode' : 'Switch to dark mode'
  return (
    <button type="button" className="theme-toggle" onClick={() => setMode(dark ? 'light' : 'dark')}
      title={label} aria-label={label} style={{ ...TOGGLE_BOX, cursor: 'pointer' }}>
      <Icon name={dark ? 'sun' : 'moon'} size={14} />
    </button>
  )
}
