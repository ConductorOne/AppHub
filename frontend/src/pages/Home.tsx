import { useMemo, useState } from 'react'
import { Box, Typography } from '@mui/material'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { useCategories, useDirectory } from '../hooks/useApplications'
import type { ApplicationSummary } from '../services/types'
import { Failure, Loading } from '../components/Feedback'
import { AppURLIcon } from '../components/AppURL'
import { Avatar } from '../design/Avatar'
import { Button } from '../design/Button'
import { Chip } from '../design/Chip'
import { Icon } from '../design/Icon'
import { needsAttention, STATUS_META } from '../design/status'
import { categoryIcon, categoryMeta } from '../design/categories'
import { ownerNames } from '../design/owners'

type Filter = 'All' | 'Yours' | 'Live' | 'Needs attention'
const FILTERS: Filter[] = ['All', 'Yours', 'Live', 'Needs attention']
const UNCATEGORIZED = ''
const h2Style: React.CSSProperties = { fontFamily: "'Anybody', sans-serif", fontSize: 17, fontWeight: 600, letterSpacing: '-0.015em', margin: 0 }
const gridStyle: React.CSSProperties = { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 12 }

function chipColors(on: boolean) {
  return { border: `1px solid ${on ? 'var(--teal)' : 'var(--line)'}`, background: on ? 'var(--teal)' : 'var(--bg-0)', color: on ? 'var(--on-accent)' : 'var(--ink-1)' }
}

function greetingFor(name?: string) {
  const hour = new Date().getHours()
  const time = hour < 12 ? 'morning' : hour < 18 ? 'afternoon' : 'evening'
  return `Good ${time}${name ? `, ${name.split(' ')[0]}` : ''}`
}

export default function Home() {
  const auth = useAuth()
  const query = useDirectory()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<Filter>('All')
  const [category, setCategory] = useState<string>()
  const categories = useCategories().data

  const apps = query.data?.pages.flatMap(page => page.items) || []
  const q = search.trim().toLowerCase()

  const keyOf = (app: ApplicationSummary) => categories?.some(c => c.key === app.category) ? app.category! : UNCATEGORIZED
  const matches = useMemo(() => apps.filter(app => !q || app.name.toLowerCase().includes(q) || app.owners.some(owner => owner.name.toLowerCase().includes(q))
    || !!categoryMeta(categories, app.category)?.label.toLowerCase().includes(q)), [apps, q, categories])
  const filtered = useMemo(() => matches.filter(app => {
    if (category !== undefined && keyOf(app) !== category) return false
    if (filter === 'Yours') return app.yours
    if (filter === 'Live') return app.status === 'running'
    if (filter === 'Needs attention') return needsAttention(app.status)
    return true
  }), [matches, filter, category, categories])

  const browsing = filter === 'All' && !q && category === undefined
  const countIn = (key: string) => apps.filter(app => keyOf(app) === key).length
  const categoryChips = [
    ...(categories || []).map(c => ({ key: c.key, label: c.label, count: countIn(c.key) })),
    ...(countIn(UNCATEGORIZED) ? [{ key: UNCATEGORIZED, label: 'Uncategorized', count: countIn(UNCATEGORIZED) }] : []),
  ]
  const groups = browsing ? [
    ...(categories || []).map(c => ({ key: c.key, title: c.label, hint: c.description, items: matches.filter(app => keyOf(app) === c.key) })),
    { key: UNCATEGORIZED, title: 'Uncategorized', hint: 'Owners can pick a category in each application’s settings.', items: matches.filter(app => keyOf(app) === UNCATEGORIZED) },
  ].filter(g => g.items.length) : []
  const activeCategory = category === undefined ? undefined : category === UNCATEGORIZED ? { key: UNCATEGORIZED, label: 'Uncategorized', description: '' } : categoryMeta(categories, category)

  const yours = browsing ? matches.filter(app => app.yours) : []
  const recentlyDeployed = browsing ? [...matches].sort((a, b) => (b.lastDeployedAt ?? b.createdAt).localeCompare(a.lastDeployedAt ?? a.createdAt)).slice(0, 3) : []

  function card(app: ApplicationSummary, showCategory = true) {
    const meta = STATUS_META[app.status]
    const cat = categoryMeta(categories, app.category)
    return <div key={app.id} onClick={() => navigate(`/applications/${app.id}`)} style={{
      border: '1px solid var(--line)', borderRadius: 8, padding: 14, background: 'var(--bg-0)', cursor: 'pointer',
      display: 'flex', flexDirection: 'column', gap: 10,
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 11 }}>
        <Avatar name={app.name} size={34} radius={8} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <span style={{ fontSize: 13.5, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{app.name}</span>
            <span className={meta.pulse ? 'ah-pulse' : undefined} style={{ width: 6, height: 6, borderRadius: 6, flexShrink: 0, background: meta.dot }} />
          </div>
          {showCategory && cat && <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--ink-2)', marginTop: 2 }}><Icon name={categoryIcon(cat.key)} size={12} />{cat.label}</div>}
          <div style={{ marginTop: 6, minWidth: 0 }}><AppURLIcon app={app} /></div>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <Chip tone={meta.tone} size="extraSmall">{meta.label}</Chip>
        {app.yours ? <Chip tone="teal" size="extraSmall">You own this</Chip> : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11.5, color: 'var(--ink-2)', minWidth: 0 }}>{app.owners[0]?.kind === 'group' && <Icon name="users" size={12} />}Owned by {ownerNames(app.owners)}</span>}
        <span style={{ flex: 1 }} />
        <Button variant="outlined" size="sm">Open</Button>
      </div>
    </div>
  }

  return <Box sx={{ padding: '32px', maxWidth: 1080, mx: 'auto' }}>
    <Typography sx={{ fontFamily: "'Anybody', sans-serif", fontSize: 28, fontWeight: 600, letterSpacing: '-0.02em' }}>{greetingFor(auth.data?.name)}</Typography>
    <Typography sx={{ fontSize: 13.5, color: 'var(--ink-2)', mt: 0.5, mb: 2.5 }}>
      Every application in your workspace. Open one to see what it is and who owns it.
    </Typography>

    <div style={{ display: 'flex', alignItems: 'center', gap: 9, border: '1px solid var(--line)', borderRadius: 8, padding: '10px 13px', background: 'var(--bg-0)', maxWidth: 520 }}>
      <Icon name="search" size={17} color="var(--ink-4)" />
      <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search applications by name, owner, or category"
        style={{ border: 0, outline: 'none', flex: 1, minWidth: 0, background: 'transparent', fontSize: 13.5, fontFamily: 'inherit' }} />
      {search && <span onClick={() => setSearch('')} style={{ color: 'var(--ink-4)', display: 'flex', cursor: 'pointer' }}><Icon name="x" size={15} /></span>}
    </div>

    <div style={{ display: 'flex', gap: 6, marginTop: 12, flexWrap: 'wrap', alignItems: 'center' }}>
      {FILTERS.map(label => <span key={label} onClick={() => setFilter(label)} style={{ fontSize: 12, fontWeight: 500, padding: '5px 11px', borderRadius: 20, cursor: 'pointer', ...chipColors(filter === label) }}>{label}</span>)}
      {categoryChips.length > 0 && <span style={{ width: 1, height: 18, background: 'var(--line)', margin: '0 4px' }} />}
      {categoryChips.map(c => {
        const on = category === c.key
        return <span key={c.key || 'uncategorized'} onClick={() => setCategory(on ? undefined : c.key)} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 500, padding: '5px 10px 5px 9px', borderRadius: 20, cursor: 'pointer', ...chipColors(on) }}>
          <Icon name={categoryIcon(c.key)} size={13} />{c.label}<span style={{ fontSize: 11, color: on ? 'var(--on-accent)' : 'var(--ink-3)' }}>{c.count}</span>
        </span>
      })}
    </div>

    <div style={{ paddingTop: 26, display: 'flex', flexDirection: 'column', gap: 28 }}>
      {query.isPending ? <Loading label="Loading applications…" /> : query.error ? <Failure error={query.error} retry={() => void query.refetch()} /> : <>
        {yours.length > 0 && <section>
          <h2 style={{ ...h2Style, marginBottom: 12 }}>Your applications</h2>
          <div style={gridStyle}>{yours.map(app => card(app))}</div>
        </section>}
        {recentlyDeployed.length > 0 && <section>
          <h2 style={{ ...h2Style, marginBottom: 12 }}>Recently deployed</h2>
          <div style={gridStyle}>{recentlyDeployed.map(app => card(app))}</div>
        </section>}
        {groups.map(g => <section key={g.key || 'uncategorized'}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
            <span style={{ display: 'flex', alignSelf: 'center', color: 'var(--teal)' }}><Icon name={categoryIcon(g.key)} size={16} /></span>
            <h2 style={h2Style}>{g.title}</h2>
            <span style={{ fontSize: 12.5, color: 'var(--ink-3)' }}>{g.hint}</span>
          </div>
          <div style={gridStyle}>{g.items.map(app => card(app, false))}</div>
        </section>)}
        {!browsing && <section>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
            {activeCategory && filter === 'All' && !q && <span style={{ display: 'flex', alignSelf: 'center', color: 'var(--teal)' }}><Icon name={categoryIcon(activeCategory.key)} size={16} /></span>}
            <h2 style={h2Style}>{activeCategory && filter === 'All' && !q ? activeCategory.label : `${filtered.length} ${filtered.length === 1 ? 'application' : 'applications'}${activeCategory ? ` in ${activeCategory.label}` : ''}`}</h2>
            {activeCategory?.description && filter === 'All' && !q && <span style={{ fontSize: 12.5, color: 'var(--ink-3)' }}>{activeCategory.description}</span>}
          </div>
          {filtered.length === 0
            ? <div style={{ border: '1px dashed var(--line-emph)', borderRadius: 8, padding: 44, textAlign: 'center' }}>
                <Icon name="search-x" size={24} color="var(--ink-4)" />
                <div style={{ fontSize: 13.5, fontWeight: 600, marginTop: 10 }}>{q ? `No applications match "${search}"` : 'No applications match this filter'}</div>
                <div style={{ fontSize: 12.5, color: 'var(--ink-2)', marginTop: 3 }}>Try another search, or deploy something new.</div>
              </div>
            : <div style={gridStyle}>{filtered.map(app => card(app, !activeCategory))}</div>}
        </section>}
        {browsing && !apps.length && <div style={{ border: '1px dashed var(--line-emph)', borderRadius: 8, padding: 44, textAlign: 'center', fontSize: 13.5, color: 'var(--ink-2)' }}>No applications yet.</div>}

        {auth.data?.permittedActions.includes('applications:write') && <div style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '16px 18px', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap', background: 'var(--bg-1)' }}>
          <span style={{ width: 32, height: 32, borderRadius: 7, background: 'var(--teal-tint)', color: 'var(--teal-dark)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}><Icon name="rocket" size={17} /></span>
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontSize: 13.5, fontWeight: 600 }}>Deploy your own</div>
            <div style={{ fontSize: 12.5, color: 'var(--ink-2)', marginTop: 1 }}>Point AppHub at an approved repository and review the plan before it deploys.</div>
          </div>
          <Button to="/applications/new">New application</Button>
        </div>}
      </>}
    </div>
  </Box>
}
