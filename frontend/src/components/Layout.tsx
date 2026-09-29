import { useEffect, useRef } from 'react'
import { Container } from '@mui/material'
import { Navigate, NavLink, Outlet, useLocation } from 'react-router-dom'
import { useAuth, useLogout } from '../hooks/useAuth'
import { ApiError } from '../services/api'
import { Avatar } from '../design/Avatar'
import { Icon } from '../design/Icon'
import { BrandLogo, ColorModeToggle } from './Brand'
import { Failure, Loading } from './Feedback'

export function RequireAuth() {
  const auth = useAuth()
  const location = useLocation()
  if (auth.isPending) return <Container><Loading label="Checking your session…" /></Container>
  if (auth.error instanceof ApiError && auth.error.status === 401) return <Navigate replace to={`/login?return_to=${encodeURIComponent(location.pathname + location.search)}`} />
  if (auth.error) return <Container><Failure error={auth.error} retry={() => void auth.refetch()} /></Container>
  return <Outlet />
}

const NAV = [
  { to: '/', label: 'Home', icon: 'layout-grid', end: true },
  { to: '/applications', label: 'Applications', icon: 'boxes', end: false },
]
const VULNERABILITIES_NAV = { to: '/vulnerabilities', label: 'Vulnerabilities', icon: 'shield-alert', end: false }
const ADMIN_NAV = { to: '/workspace', label: 'Workspace', icon: 'settings', end: false }

export function Layout() {
  const auth = useAuth()
  const logout = useLogout()
  const location = useLocation()
  const main = useRef<HTMLElement>(null)
  useEffect(() => { main.current?.focus(); window.scrollTo(0, 0) }, [location.pathname])

  return <>
    <a href="#main-content" className="skip-link">Skip to content</a>
    <div style={{ display: 'flex', height: '100vh', width: '100%', background: 'var(--bg-0)' }}>
      <nav style={{ width: 210, flex: '0 0 210px', borderRight: '1px solid var(--line)', background: 'var(--bg-1)', display: 'flex', flexDirection: 'column', height: '100%' }}>
        <div style={{ padding: '16px 14px 12px' }}><BrandLogo to="/" wordmark height={32} /></div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 1, padding: '0 8px' }}>
          {NAV.map(item => <NavLink key={item.to} to={item.to} end={item.end}
            style={({ isActive }) => ({ display: 'flex', alignItems: 'center', gap: 9, padding: '7px 8px', borderRadius: 6, textDecoration: 'none', fontSize: 13, fontWeight: 500, color: isActive ? 'var(--teal)' : 'var(--ink-1)', background: isActive ? 'var(--teal-tint)' : 'transparent' })}>
            <Icon name={item.icon} size={16} /><span>{item.label}</span>
          </NavLink>)}
          {auth.data?.enabledFeatures.includes('vulnerabilities') && <NavLink key={VULNERABILITIES_NAV.to} to={VULNERABILITIES_NAV.to} end={VULNERABILITIES_NAV.end}
            style={({ isActive }) => ({ display: 'flex', alignItems: 'center', gap: 9, padding: '7px 8px', borderRadius: 6, textDecoration: 'none', fontSize: 13, fontWeight: 500, color: isActive ? 'var(--teal)' : 'var(--ink-1)', background: isActive ? 'var(--teal-tint)' : 'transparent' })}>
            <Icon name={VULNERABILITIES_NAV.icon} size={16} /><span>{VULNERABILITIES_NAV.label}</span>
          </NavLink>}
          {auth.data?.role === 'admin' && <NavLink key={ADMIN_NAV.to} to={ADMIN_NAV.to} end={ADMIN_NAV.end}
            style={({ isActive }) => ({ display: 'flex', alignItems: 'center', gap: 9, padding: '7px 8px', borderRadius: 6, textDecoration: 'none', fontSize: 13, fontWeight: 500, color: isActive ? 'var(--teal)' : 'var(--ink-1)', background: isActive ? 'var(--teal-tint)' : 'transparent' })}>
            <Icon name={ADMIN_NAV.icon} size={16} /><span>{ADMIN_NAV.label}</span>
          </NavLink>}
        </div>
        <div style={{ flex: 1 }} />
        <div style={{ padding: 12, borderTop: '1px solid var(--line)', display: 'flex', flexDirection: 'column', gap: 10 }}>
          <NavLink to="/settings" className="account-link" title="Settings" style={{ display: 'flex', alignItems: 'center', gap: 9, textDecoration: 'none', fontSize: 12.5, fontWeight: 500 }}>
            <Avatar name={auth.data?.name || auth.data?.email || '?'} size={22} radius={20} />
            <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{auth.data?.name || auth.data?.email}</span>
            {/* Affordance only — the whole row is the link, so keep it out of the accessibility tree. */}
            <span className="account-gear" aria-hidden style={{ display: 'flex', flexShrink: 0 }}>
              <Icon name="settings" size={14} />
            </span>
          </NavLink>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ColorModeToggle />
            <button type="button" disabled={logout.isPending} onClick={() => logout.mutate()} className="ds-btn"
              style={{ flex: 1, fontFamily: 'inherit', fontSize: 12, fontWeight: 600, color: 'var(--ink-2)', background: 'transparent', border: '1px solid var(--line)', borderRadius: 6, padding: '6px 9px', cursor: 'pointer' }}>
              Sign out
            </button>
          </div>
          <NavLink to="/docs" style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, fontWeight: 500, color: 'var(--teal)', textDecoration: 'none' }}>
            <Icon name="book-open" size={13} />Docs
          </NavLink>
        </div>
      </nav>
      <main id="main-content" tabIndex={-1} ref={main} style={{ flex: 1, minWidth: 0, height: '100%', overflowY: 'auto', outline: 'none' }}>
        {logout.error && <Container sx={{ pt: 2 }}><Failure error={logout.error} retry={() => logout.mutate()} /></Container>}
        <Outlet />
      </main>
    </div>
  </>
}
