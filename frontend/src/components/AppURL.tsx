import { Icon } from '../design/Icon'
import { httpsAddresses } from './Feedback'

/** Either a full Application or an ApplicationSummary: whatever appURL needs to resolve a link. */
export type AppURLSource = { url?: string; urlScope?: string; addresses?: string[]; live?: boolean }

/** The published URL and whether a successful deploy has made it live. */
export function appURL(app: AppURLSource): { url?: string; host?: string; live: boolean; internal: boolean } {
  const addresses = httpsAddresses(app.addresses)
  const url = app.url ?? addresses[0]
  if (!url) return { live: false, internal: false }
  const host = new URL(url).host
  const live = app.live ?? addresses.some(address => new URL(address).host === host)
  return { url, host, live, internal: app.urlScope === 'internal' }
}

function tooltip(live: boolean, internal: boolean) {
  const where = internal ? 'Reachable only inside the company network. ' : ''
  return where + (live ? 'Opens in a new tab.' : 'Not live until the next successful deploy.')
}

function InternalTag() {
  return <span style={{ fontSize: 10.5, fontWeight: 600, color: 'var(--ink-3)', border: '1px solid var(--line)', borderRadius: 4, padding: '0 5px', fontFamily: "'Inter', system-ui, sans-serif", letterSpacing: 0 }}>Internal</span>
}

/** The app's full hostname as a link, for the detail page header. */
export function AppURL({ app, size = 12.5 }: { app: AppURLSource; size?: number }) {
  const { url, host, live, internal } = appURL(app)
  if (!url) return null
  return <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', minWidth: 0, maxWidth: '100%' }}>
    <a className="ds-mono" href={url} target="_blank" rel="noopener noreferrer" title={tooltip(live, internal)}
      style={{ fontSize: size, letterSpacing: '-.02em', display: 'inline-flex', alignItems: 'center', gap: 5, minWidth: 0, maxWidth: '100%' }}>
      <span className="break-text">{host}</span><Icon name="external-link" size={size - 0.5} />
    </a>
    {internal && <InternalTag />}
    {!live && <span style={{ fontSize: size - 1.5, color: 'var(--ink-3)' }}>· after deploy</span>}
  </span>
}

/** The hostname as text with a clickable link icon, for cards whose own click opens the app's details. */
export function AppURLIcon({ app, size = 12 }: { app: AppURLSource; size?: number }) {
  const { url, host, live, internal } = appURL(app)
  if (!url) return null
  return <span style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0, maxWidth: '100%' }}>
    <span className="ds-mono" style={{ fontSize: size, letterSpacing: '-.02em', color: live ? 'var(--ink-2)' : 'var(--ink-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>{host}</span>
    <a href={url} target="_blank" rel="noopener noreferrer" aria-label={`Open ${host}`} title={tooltip(live, internal)} onClick={event => event.stopPropagation()}
      className="row-hover" style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 22, height: 22, borderRadius: 5, border: '1px solid var(--line)', color: 'var(--teal)', flexShrink: 0 }}>
      <Icon name="external-link" size={13} />
    </a>
    {internal && <InternalTag />}
  </span>
}
