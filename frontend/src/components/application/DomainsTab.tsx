import type { Application } from '../../services/types'
import { appURL } from '../AppURL'
import { httpsAddresses } from '../Feedback'
import { Button } from '../../design/Button'
import { Chip } from '../../design/Chip'
import { Icon } from '../../design/Icon'
import { NotAvailable } from '../../design/Preview'
import { cardStyle, FieldRow, LinkButton, SectionHeader, type AppTab } from './parts'

export default function DomainsTab({ app, onTab }: { app: Application; onTab?: (tab: AppTab) => void }) {
  const exposure = app.specification.exposure
  const signInRequired = exposure.signInRequired ?? true
  const reported = httpsAddresses(app.addresses)
  const published = appURL(app)
  const addresses = published.url ? [published.url, ...reported.filter(address => new URL(address).host !== published.host)] : reported
  const isLive = (address: string) => reported.some(r => new URL(r).host === new URL(address).host)
  return <div style={{ maxWidth: 900, display: 'flex', flexDirection: 'column', gap: 26 }}>
    <div>
      <SectionHeader title="Domains and networking" description="The address AppHub publishes this application at. It goes live after a successful deploy." />
      <div style={cardStyle}>
        {addresses.map(address => {
          const internal = published.url === address ? published.internal : exposure.mode === 'private'
          return <div key={address} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '13px 16px', borderBottom: '1px solid var(--bg-2)', flexWrap: 'wrap' }}>
            <Icon name={internal ? 'lock' : 'globe'} size={16} color={internal ? 'var(--ink-3)' : 'var(--ok)'} />
            <div style={{ flex: 1, minWidth: 180 }}>
              <div className="ds-mono break-text" style={{ fontSize: 13, fontWeight: 500 }}>{new URL(address).host}</div>
              <div style={{ fontSize: 11.5, color: 'var(--ink-3)' }}>{internal ? 'Internal network only' : 'AppHub-managed address'}{isLive(address) ? '' : ' · live after the next successful deploy'}</div>
            </div>
            {internal && <Chip tone="muted" size="extraSmall">Internal</Chip>}
            {isLive(address)
              ? <Chip tone="success" size="extraSmall">Active</Chip>
              : <Chip tone="muted" size="extraSmall">Pending deploy</Chip>}
            <a href={address} target="_blank" rel="noopener noreferrer" style={{ fontSize: 12, fontWeight: 500 }}>Open</a>
          </div>
        })}
        {!addresses.length && <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '13px 16px' }}>
          <Icon name={exposure.mode === 'public' ? 'globe' : 'lock'} size={16} color="var(--ink-3)" />
          <div style={{ fontSize: 12.5, color: 'var(--ink-2)' }}>
            {exposure.mode === 'public'
              ? 'The public address appears here after the first successful deploy.'
              : app.specification.execution === 'scheduled'
                ? 'Scheduled jobs have no address.'
                : 'This private application has no address yet. On targets with an internal ingress it gets one after its next successful deploy; otherwise nothing can connect to it.'}
          </div>
        </div>}
      </div>
    </div>

    <div>
      <SectionHeader title="Custom domains" action={<Button variant="outlined" disabled>Add domain</Button>} />
      <NotAvailable icon="globe" title="Custom domains">Bringing your own domain isn't supported yet. Public applications are served under the workspace's managed domain.</NotAvailable>
    </div>

    <div>
      <SectionHeader title="Traffic" description="Change exposure from the Settings tab." />
      <div style={cardStyle}>
        <FieldRow label="Exposure" hint={exposure.mode === 'public' ? 'Reachable from the internet' : 'Internal network only'}>{exposure.mode}</FieldRow>
        {exposure.mode === 'public' && <FieldRow label="Hostname" hint="Label under the managed domain">{exposure.hostname}</FieldRow>}
        {exposure.mode === 'private' && (exposure.hostname || !!addresses.length) && <FieldRow label="Hostname" hint="Label under the internal domain">{exposure.hostname || 'Generated'}</FieldRow>}
        {!!addresses.length && <FieldRow label="Sign-in" hint="Change on the Authentication tab">
          {signInRequired ? 'Organization sign-in required' : published.internal ? 'Off — anyone on the internal network' : 'Off — anyone with the URL'}
          {onTab && <> · <LinkButton onClick={() => onTab('authentication')}>Authentication</LinkButton></>}
        </FieldRow>}
        {exposure.mode === 'public' && <FieldRow label="MCP OAuth" hint="For clients calling /mcp">{exposure.mcpAuthEnabled ? 'Enabled' : 'Disabled'}</FieldRow>}
        <FieldRow label="Container port">{app.specification.port}</FieldRow>
      </div>
    </div>
  </div>
}
