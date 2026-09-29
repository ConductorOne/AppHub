import { Box } from '@mui/material'
import { Link } from 'react-router-dom'
import { useCategories } from '../../hooks/useApplications'
import type { ApplicationSummary } from '../../services/types'
import { AppURL } from '../AppURL'
import { Avatar } from '../../design/Avatar'
import { Button } from '../../design/Button'
import { Chip } from '../../design/Chip'
import { Icon } from '../../design/Icon'
import { relativeTime, STATUS_META } from '../../design/status'
import { categoryIcon, categoryMeta } from '../../design/categories'
import { OwnerAvatar, ownerNames } from '../../design/owners'
import { ActivityTab } from './StubTabs'
import { cardStyle, eyebrowStyle, type AppTab } from './parts'

type ReadOnlyTab = Extract<AppTab, 'overview' | 'activity'>
const TABS: { key: ReadOnlyTab; label: string }[] = [{ key: 'overview', label: 'Overview' }, { key: 'activity', label: 'Activity' }]

type Props = { app: ApplicationSummary; tab: ReadOnlyTab; onTab: (tab: ReadOnlyTab) => void }

/** Read-only view of another member's application: only what the directory summary exposes. */
export default function ReadOnlyApplication({ app, tab, onTab }: Props) {
  return <div style={{ animation: 'ah-rise 200ms cubic-bezier(0,0,.2,1)' }}>
    <style>{'@keyframes ah-rise { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: none; } }'}</style>
    <Header app={app} tab={tab} onTab={onTab} />
    <Box sx={{ p: '24px 32px 56px' }}>
      {tab === 'overview' && <Overview app={app} />}
      {tab === 'activity' && <ActivityTab />}
    </Box>
  </div>
}

function Header({ app, tab, onTab }: Props) {
  const meta = STATUS_META[app.status]
  const category = categoryMeta(useCategories().data, app.category)

  return <Box sx={{ p: '20px 32px 0', borderBottom: '1px solid var(--line)', position: 'sticky', top: 0, background: 'var(--bg-0)', zIndex: 5 }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--ink-3)', marginBottom: 10 }}>
      <Link to="/applications" style={{ fontSize: 12, fontWeight: 500 }}>Applications</Link><span>/</span>
      <span className="ds-mono">{app.name}</span>
    </div>
    <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
      <Avatar name={app.name} size={34} radius={8} />
      <div style={{ flex: 1, minWidth: 160 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <h1 className="break-text" style={{ fontFamily: "'Anybody', sans-serif", fontSize: 24, fontWeight: 600, letterSpacing: '-.015em', margin: 0 }}>{app.name}</h1>
          <Chip tone={meta.tone} dot size="extraSmall">{meta.label}</Chip>
          {category && <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--ink-2)' }}><Icon name={categoryIcon(category.key)} size={13} />{category.label}</span>}
        </div>
        <AppURL app={app} />
      </div>
      <Chip tone="muted" size="extraSmall">Read only</Chip>
      {app.url && <Button variant="outlined" href={app.url} endIcon={<Icon name="external-link" size={14} />}>Open app</Button>}
    </div>
    <div role="tablist" style={{ display: 'flex', gap: 2, marginTop: 14, overflowX: 'auto' }}>
      {TABS.map(t => <button key={t.key} type="button" role="tab" aria-selected={tab === t.key} onClick={() => onTab(t.key)} style={{ border: 0, background: 'transparent', cursor: 'pointer', fontFamily: 'inherit', fontSize: 13, fontWeight: 500, padding: '9px 12px', color: tab === t.key ? 'var(--teal)' : 'var(--ink-2)', borderBottom: `2px solid ${tab === t.key ? 'var(--teal)' : 'transparent'}`, whiteSpace: 'nowrap' }}>{t.label}</button>)}
    </div>
  </Box>
}

function Overview({ app }: { app: ApplicationSummary }) {
  const meta = STATUS_META[app.status]
  return <div className="app-overview-grid">
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, minWidth: 0 }}>
      <div style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '16px 18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <Chip tone={meta.tone} dot>{meta.label}</Chip>
          <span style={{ fontSize: 13.5, fontWeight: 600 }}>{app.lastDeployedAt ? `Last deployed ${relativeTime(app.lastDeployedAt)}` : 'Not deployed yet'}</span>
        </div>
      </div>
      <div style={{ ...cardStyle, padding: '16px 18px', display: 'flex', gap: 12, alignItems: 'flex-start', background: 'var(--bg-1)', border: '1px dashed var(--line-emph)' }}>
        <Icon name="lock" size={18} color="var(--ink-4)" />
        <div style={{ fontSize: 12.5, color: 'var(--ink-2)' }}>
          <div>Details are visible to the app's owners and workspace admins.</div>
          <div style={{ marginTop: 4 }}>Ask {ownerNames(app.owners, 'or')} for access.</div>
        </div>
      </div>
    </div>
    <aside style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
      <div style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '13px 15px' }}>
        <div style={eyebrowStyle}>Ownership</div>
        {app.owners.map(owner => <div key={owner.key} style={{ display: 'flex', alignItems: 'center', gap: 9, marginTop: 8 }}>
          <OwnerAvatar owner={owner} />
          <div style={{ minWidth: 0 }}>
            <div className="break-text" style={{ fontSize: 12.5, fontWeight: 600 }}>{owner.name}</div>
            <div style={{ fontSize: 11.5, color: 'var(--ink-3)' }}>{owner.kind === 'group' ? 'Group owner' : 'Owner'}</div>
          </div>
        </div>)}
      </div>
    </aside>
  </div>
}
