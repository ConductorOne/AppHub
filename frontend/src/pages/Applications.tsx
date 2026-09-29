import { useMemo, useState } from 'react'
import { Alert, Box, Typography } from '@mui/material'
import { useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { type ListNotice, useApplications, useTargets } from '../hooks/useApplications'
import { Failure, Loading } from '../components/Feedback'
import { AppURLIcon } from '../components/AppURL'
import { Avatar } from '../design/Avatar'
import { Button } from '../design/Button'
import { Chip } from '../design/Chip'
import { Icon } from '../design/Icon'
import { needsAttention, STATUS_META } from '../design/status'

type Filter = 'All' | 'Live' | 'Needs attention' | 'Draft'
const FILTERS: Filter[] = ['All', 'Live', 'Needs attention', 'Draft']

export default function Applications() {
  const auth = useAuth()
  const isAdmin = auth.data?.role === 'admin'
  const [all, setAll] = useState(isAdmin)
  const query = useApplications(all)
  const targets = useTargets()
  const navigate = useNavigate()
  const location = useLocation()
  const notice = (location.state as ListNotice | null)?.notice
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<Filter>('All')

  const applications = query.data?.pages.flatMap(page => page.items) || []
  const q = search.trim().toLowerCase()
  const filtered = useMemo(() => applications
    .filter(app => !q || app.specification.name.toLowerCase().includes(q) || app.specification.source.url.toLowerCase().includes(q))
    .filter(app => filter === 'All' || (filter === 'Live' && app.status === 'running') || (filter === 'Needs attention' && needsAttention(app.status)) || (filter === 'Draft' && app.status === 'draft')),
    [applications, q, filter])

  const stats = [
    { label: 'Applications', value: String(applications.length) },
    { label: 'Live', value: String(applications.filter(a => a.status === 'running').length) },
    { label: 'Needs attention', value: String(applications.filter(a => needsAttention(a.status)).length) },
    { label: 'Targets', value: String(targets.data?.length ?? 0) },
  ]

  return <Box sx={{ padding: '24px 32px 56px' }}>
    <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 24, flexWrap: 'wrap', marginBottom: 18 }}>
      <div>
        <Typography sx={{ fontFamily: "'Anybody', sans-serif", fontSize: 28, fontWeight: 600, letterSpacing: '-0.02em' }}>Applications</Typography>
        <Typography sx={{ fontSize: 13, color: 'var(--ink-2)', mt: 0.5 }}>Source, deployments, and runtime state in one place.</Typography>
      </div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        {isAdmin && <span onClick={() => setAll(v => !v)} style={{ fontSize: 12, fontWeight: 500, padding: '5px 10px', borderRadius: 20, cursor: 'pointer', border: `1px solid ${all ? 'var(--teal)' : 'var(--line)'}`, background: all ? 'var(--teal)' : 'var(--bg-0)', color: all ? 'var(--on-accent)' : 'var(--ink-1)' }}>All organization apps</span>}
        {auth.data?.permittedActions.includes('applications:write') && <Button to="/applications/new">New application</Button>}
      </div>
    </div>

    {notice && <Alert severity="success" role="status" sx={{ mb: 2 }} onClose={() => navigate(location.pathname, { replace: true, state: null })}>{notice}</Alert>}

    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 18 }}>
      {stats.map(s => <div key={s.label} style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '13px 15px', background: 'var(--bg-0)' }}>
        <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }}>{s.label}</div>
        <div style={{ fontFamily: "'Anybody', sans-serif", fontSize: 24, fontWeight: 600, letterSpacing: '-0.015em', marginTop: 6 }}>{s.value}</div>
      </div>)}
    </div>

    <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', marginBottom: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, border: '1px solid var(--line)', borderRadius: 6, padding: '6px 9px', background: 'var(--bg-0)', flex: '0 1 260px' }}>
        <Icon name="search" size={15} color="var(--ink-4)" />
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search applications, repositories"
          style={{ border: 0, outline: 'none', flex: 1, minWidth: 0, background: 'transparent', fontSize: 13, fontFamily: 'inherit' }} />
      </div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {FILTERS.map(label => {
          const on = filter === label
          return <span key={label} onClick={() => setFilter(label)} style={{ fontSize: 12, fontWeight: 500, padding: '5px 10px', borderRadius: 20, cursor: 'pointer', border: `1px solid ${on ? 'var(--teal)' : 'var(--line)'}`, background: on ? 'var(--teal)' : 'var(--bg-0)', color: on ? 'var(--on-accent)' : 'var(--ink-1)' }}>{label}</span>
        })}
      </div>
    </div>

    {query.isPending ? <Loading label="Loading applications…" /> : query.error ? <Failure error={query.error} retry={() => void query.refetch()} /> : filtered.length === 0 ? (
      <div style={{ border: '1px dashed var(--line-emph)', borderRadius: 8, padding: 44, textAlign: 'center' }}>
        <div style={{ fontSize: 15, fontWeight: 600 }}>{applications.length === 0 ? 'No applications yet' : 'No applications match'}</div>
        <div style={{ fontSize: 12.5, color: 'var(--ink-2)', marginTop: 3 }}>{applications.length === 0 ? 'Create your first draft from an approved repository.' : 'Try a different search or filter.'}</div>
      </div>
    ) : <div style={{ border: '1px solid var(--line)', borderRadius: 8, overflowX: 'auto', background: 'var(--bg-0)' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(160px,2.2fr) minmax(0,110px) minmax(0,1.2fr) minmax(0,140px) 18px', gap: 14, padding: '9px 16px', background: 'var(--bg-1)', borderBottom: '1px solid var(--line)', fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }}>
        <div>Application</div><div>Status</div><div>Target</div><div>Revision</div><div />
      </div>
      {filtered.map(app => {
        const meta = STATUS_META[app.status]
        const targetLabel = targets.data?.find(t => t.id === app.specification.targetId)?.label || app.specification.targetId
        return <div key={app.id} onClick={() => navigate(`/applications/${app.id}`)} style={{ display: 'grid', gridTemplateColumns: 'minmax(160px,2.2fr) minmax(0,110px) minmax(0,1.2fr) minmax(0,140px) 18px', gap: 14, padding: '13px 16px', borderBottom: '1px solid var(--bg-2)', alignItems: 'center', cursor: 'pointer', opacity: app.status === 'deleting' ? 0.72 : 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 11, minWidth: 0 }}>
            <Avatar name={app.specification.name} size={30} radius={7} />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 13.5, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{app.specification.name}</div>
              <div className="ds-mono" style={{ fontSize: 11.5, color: 'var(--ink-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{app.specification.source.url}</div>
              <AppURLIcon app={app} />
            </div>
          </div>
          <div><Chip tone={meta.tone} dot pulse={meta.pulse}>{meta.label}</Chip></div>
          <div style={{ fontSize: 12.5, color: 'var(--ink-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{targetLabel}</div>
          <div className="ds-mono" style={{ fontSize: 12.5, color: 'var(--ink-2)' }}>rev {app.revision}</div>
          <div style={{ color: 'var(--ink-4)', display: 'flex' }}><Icon name="chevron-right" size={16} /></div>
        </div>
      })}
    </div>}
    {query.hasNextPage && <Box sx={{ mt: 2 }}><Button variant="outlined" disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>Load more applications</Button></Box>}
    {query.isFetchNextPageError && <Alert severity="error" sx={{ mt: 2 }}>Could not load the next page. Retry without discarding the current list.</Alert>}

    <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, color: 'var(--ink-2)', flexWrap: 'wrap' }}>
      <Icon name="terminal" size={14} />
      <span>Same from the CLI:</span>
      <code className="ds-mono" style={{ fontSize: 12, fontWeight: 500, background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 4, padding: '2px 7px', color: 'var(--ink-1)' }}>apphub apps list</code>
    </div>
  </Box>
}
