import { useMemo } from 'react'
import { useColorScheme } from '@mui/material/styles'
import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuth } from '../hooks/useAuth'
import { apiPath, request, segment, setCSRF } from '../services/api'
import type { Sessions as SessionPage } from '../services/types'
import { Failure, Loading, Timestamp } from '../components/Feedback'
import { Button } from '../design/Button'
import { Chip } from '../design/Chip'
import { Icon } from '../design/Icon'

type Session = SessionPage['items'][number]

const THEMES = [
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
  { value: 'system', label: 'System' },
] as const

const GRID = 'minmax(170px,1.6fr) minmax(0,1.2fr) minmax(0,130px) minmax(0,130px) minmax(0,72px)'
const HEAD: React.CSSProperties = {
  display: 'grid', gridTemplateColumns: GRID, gap: 14, padding: '9px 15px',
  background: 'var(--bg-1)', borderBottom: '1px solid var(--line)', fontSize: 11, fontWeight: 500,
  letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)',
}
const ROW: React.CSSProperties = {
  display: 'grid', gridTemplateColumns: GRID, gap: 14, alignItems: 'center',
  padding: '12px 15px', borderBottom: '1px solid var(--bg-2)',
}
const CARD: React.CSSProperties = {
  border: '1px solid var(--line)', borderRadius: 8, overflowX: 'auto', background: 'var(--bg-0)',
}
const MONO: React.CSSProperties = {
  fontSize: 11, color: 'var(--ink-3)', fontFamily: "'Geist Mono', monospace",
  letterSpacing: '-.02em', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
}

function Section({ title, note, children }: { title: string; note: string; children: React.ReactNode }) {
  return <section>
    <h3 style={{ fontSize: 15, fontWeight: 600, margin: '0 0 3px' }}>{title}</h3>
    <p style={{ fontSize: 12.5, color: 'var(--ink-2)', margin: '0 0 12px', maxWidth: '72ch' }}>{note}</p>
    {children}
  </section>
}

/** Light / Dark / System. Persisted by MUI under the apphub-mode key. */
function ThemeSetting() {
  const { mode, setMode } = useColorScheme()
  return <div style={{ ...CARD, display: 'flex', alignItems: 'center', gap: 14, padding: '13px 15px' }}>
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{ fontSize: 12.5, fontWeight: 500 }}>Theme</div>
      <div style={{ fontSize: 11.5, color: 'var(--ink-2)', marginTop: 2 }}>
        System follows your device appearance. This choice is stored in this browser only.
      </div>
    </div>
    <div role="group" aria-label="Theme"
      style={{ display: 'flex', border: '1px solid var(--line)', borderRadius: 6, overflow: 'hidden', flexShrink: 0, marginLeft: 'auto', background: 'var(--bg-0)' }}>
      {THEMES.map((t, i) => {
        const on = mode === t.value
        return <button key={t.value} type="button" aria-pressed={on} onClick={() => setMode(t.value)}
          style={{
            fontFamily: 'inherit', fontSize: 12, fontWeight: 500, padding: '6px 12px', cursor: 'pointer',
            border: 0, borderLeft: i > 0 ? '1px solid var(--line)' : 0,
            background: on ? 'var(--teal)' : 'var(--bg-0)', color: on ? 'var(--on-accent)' : 'var(--ink-2)',
          }}>{t.label}</button>
      })}
    </div>
  </div>
}

function sessionLabel(session: Session) {
  return session.kind === 'browser' ? 'Browser session' : `Delegated access: ${session.clientId || session.kind}`
}

/** Usable right now: the list endpoint returns expired and revoked sessions too. */
function isActive(session: Session) {
  if (session.revoked) return false
  const expires = Date.parse(session.expiresAt)
  return Number.isNaN(expires) || expires > Date.now()
}

/** The list is paginated, so a bulk revoke has to walk every page rather than trust
 *  whatever the table happens to have loaded. */
async function everySession() {
  const out: Session[] = []
  let cursor = ''
  for (let page = 0; page < 50; page++) {
    const result = await request<SessionPage>(apiPath(`/sessions?limit=100&cursor=${segment(cursor)}`))
    out.push(...result.items)
    if (!result.cursor) break
    cursor = result.cursor
  }
  return out
}

export default function Settings() {
  const auth = useAuth()
  const client = useQueryClient()
  const query = useInfiniteQuery({
    queryKey: ['sessions'],
    initialPageParam: '',
    queryFn: ({ signal, pageParam }) =>
      request<SessionPage>(apiPath(`/sessions?limit=50&cursor=${segment(pageParam)}`), { signal }),
    getNextPageParam: page => page.cursor || undefined,
  })

  // Revoking the session authorizing this request invalidates our CSRF token, so drop
  // the cached client state and land on /login rather than letting queries retry as 401s.
  function afterRevoke(hitCurrent: boolean) {
    if (hitCurrent) {
      setCSRF('')
      client.clear()
      window.location.assign('/login')
      return
    }
    void client.invalidateQueries({ queryKey: ['sessions'] })
  }

  const revoke = useMutation({
    mutationFn: (session: Session) =>
      request<void>(apiPath(`/sessions/${segment(session.id)}`), { method: 'DELETE' }).then(() => session),
    onSuccess: session => afterRevoke(!!session.current),
  })

  // There is no bulk endpoint, so fan out one DELETE per session. This one deliberately
  // spares the current session, so it never invalidates the CSRF token mid-run.
  const revokeAll = useMutation({
    mutationFn: async () => {
      for (const session of (await everySession()).filter(s => !s.current && isActive(s))) {
        await request<void>(apiPath(`/sessions/${segment(session.id)}`), { method: 'DELETE' })
      }
      return false
    },
    onSuccess: afterRevoke,
  })

  const pending = revoke.isPending || revokeAll.isPending
  const sessions = useMemo(() => query.data?.pages.flatMap(page => page.items) || [], [query.data])
  const active = useMemo(() => sessions.filter(isActive), [sessions])
  const others = active.filter(session => !session.current)

  return <>
    <div style={{ padding: '24px 32px 0', borderBottom: '1px solid var(--line)', position: 'sticky', top: 0, background: 'var(--bg-0)', zIndex: 5 }}>
      <h1 style={{ fontFamily: "'Anybody', sans-serif", fontSize: 28, fontWeight: 600, letterSpacing: '-.02em', margin: 0 }}>Settings</h1>
      <p style={{ fontSize: 13, color: 'var(--ink-2)', margin: '4px 0 18px' }}>
        {auth.data?.name || auth.data?.email} · {auth.data?.role} · signed in with {auth.data?.identity.providerId}
      </p>
    </div>

    <div style={{ padding: '24px 32px 56px', maxWidth: 1000, display: 'flex', flexDirection: 'column', gap: 26 }}>
      <Section title="Appearance" note="Choose how AppHub looks on this device.">
        <ThemeSetting />
      </Section>

      <Section title="Signed-in identity"
        note="Accounts from different providers are separate, even when their email addresses match.">
        <div style={CARD}>
          {[
            ['Name', auth.data?.name || '—'],
            ['Email', auth.data?.email || '—'],
            ['Role', auth.data?.role || '—'],
            ['Provider', auth.data?.identity.providerId || '—'],
            ['Issuer', auth.data?.identity.issuer || '—'],
            ['Subject', auth.data?.identity.subject || '—'],
            ['AppHub user ID', auth.data?.id || '—'],
          ].map(([label, value]) => <div key={label}
            style={{ display: 'grid', gridTemplateColumns: 'minmax(130px,190px) minmax(0,1fr)', gap: 16, padding: '10px 15px', borderBottom: '1px solid var(--bg-2)' }}>
            <div style={{ fontSize: 12.5, fontWeight: 500 }}>{label}</div>
            <div className="break-text" style={{ fontSize: 12.5, color: 'var(--ink-2)' }}>{value}</div>
          </div>)}
        </div>
      </Section>

      <Section title="Active sessions"
        note="Every session that can currently act as you. Signing out ends only this browser session; CLI and MCP access are separate delegated sessions and are listed here too. Revoking cannot undo a deployment a worker has already accepted.">
        {revoke.error && <div style={{ marginBottom: 12 }}>
          <Failure error={revoke.error} retry={() => revoke.variables && revoke.mutate(revoke.variables)} />
        </div>}
        {revokeAll.error && <div style={{ marginBottom: 12 }}>
          <Failure error={revokeAll.error} retry={() => revokeAll.mutate()} />
        </div>}

        {query.isPending ? <Loading label="Loading sessions…" />
          : query.error ? <Failure error={query.error} retry={() => void query.refetch()} />
          : !active.length ? <div style={{ ...CARD, padding: '22px 15px', textAlign: 'center', color: 'var(--ink-2)', fontSize: 12.5 }}>
              No active sessions.
            </div>
          : <div style={CARD}>
            <div style={HEAD}><div>Session</div><div>Access</div><div>Started</div><div>Expires</div><div /></div>
            {active.map(session => <div key={session.id} style={ROW}>
              <div style={{ minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ display: 'flex', color: 'var(--teal)', flexShrink: 0 }}>
                    <Icon name={session.kind === 'browser' ? 'monitor' : 'terminal'} size={14} />
                  </span>
                  <span style={{ fontSize: 12.5, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {sessionLabel(session)}
                  </span>
                  {session.current && <Chip tone="teal" size="extraSmall" dot>This device</Chip>}
                </div>
                <div style={MONO}>{session.id}</div>
              </div>
              {/* identity.email is never populated on session rows, so lead with what the
                  session can actually do and name the provider underneath. */}
              <div style={{ minWidth: 0, fontSize: 12, color: 'var(--ink-2)' }}>
                <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {session.kind === 'browser' ? 'Full account access'
                    : session.scopes?.length ? session.scopes.join(', ') : 'No scopes granted'}
                </div>
                {session.resource && <div style={MONO}>{session.resource}</div>}
                <div style={MONO}>via {session.identity.providerId}</div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--ink-2)' }}><Timestamp value={session.createdAt} /></div>
              <div style={{ fontSize: 12, color: 'var(--ink-2)' }}><Timestamp value={session.expiresAt} /></div>
              <div style={{ textAlign: 'right' }}>
                <Button variant="text" color="error" size="sm" disabled={pending}
                  onClick={() => {
                    const ask = session.current
                      ? 'Revoke this browser session? You will be signed out.'
                      : `Revoke ${session.clientId || session.kind} access?`
                    if (window.confirm(ask)) revoke.mutate(session)
                  }}>Revoke</Button>
              </div>
            </div>)}
          </div>}

        {query.hasNextPage && <div style={{ marginTop: 12 }}>
          <Button variant="outlined" size="sm" disabled={query.isFetchingNextPage}
            onClick={() => void query.fetchNextPage()}>Load more sessions</Button>
        </div>}
      </Section>

      {others.length > 0 && <div style={{ border: '1px solid var(--err-line)', borderRadius: 8, padding: '15px 17px', background: 'var(--err-tint)', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
        <span style={{ display: 'flex', color: 'var(--err-ink)', flexShrink: 0 }}><Icon name="shield-alert" size={18} /></span>
        <div style={{ flex: 1, minWidth: 220 }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--err-ink)' }}>
            Revoke every other session
          </div>
          <div style={{ fontSize: 11.5, color: 'var(--err-ink)', marginTop: 1 }}>
            Ends {query.hasNextPage ? 'every session' : `the ${others.length} session${others.length === 1 ? '' : 's'}`} other than this one, including CLI and MCP access. This device stays signed in.
          </div>
        </div>
        <Button color="error" size="sm" disabled={pending}
          onClick={() => {
            if (window.confirm('Revoke every other session? This device stays signed in.')) revokeAll.mutate()
          }}>Revoke all others</Button>
      </div>}
    </div>
  </>
}
