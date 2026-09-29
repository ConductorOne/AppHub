import { Fragment } from 'react'
import type { Application } from '../../services/types'
import { Button } from '../../design/Button'
import { Icon } from '../../design/Icon'
import { bucketLabel, databaseLabel } from '../../design/status'
import { type AppTab, cardStyle, monoCell, SectionHeader } from './parts'

type EnvVar = { name: string; holds: string }
type Resource = { key: string; icon: string; name: string; spec: string; stats: { label: string; value: string }[]; env: EnvVar[] }

const RELATIONAL_ENV: EnvVar[] = [
  { name: 'DATABASE_HOST', holds: 'endpoint host' },
  { name: 'DATABASE_PORT', holds: 'endpoint port' },
  { name: 'DATABASE_NAME', holds: 'logical database name' },
  { name: 'DATABASE_USER', holds: 'administrator username' },
  { name: 'DATABASE_PASSWORD', holds: 'administrator password (secret)' },
]
const KEY_VALUE_ENV: EnvVar[] = [{ name: 'TABLE_NAME', holds: 'table name' }]
const BUCKET_ENV: EnvVar[] = [{ name: 'BUCKET_NAME', holds: 'bucket name' }, { name: 'BUCKET_URI', holds: 'bucket URI' }]

function resourcesOf(app: Application): Resource[] {
  const { database, bucket } = app.specification
  const out: Resource[] = []
  if (database?.kind === 'relational') out.push({
    key: 'database', icon: 'database', name: databaseLabel(database.kind),
    spec: [database.engine, database.engineVersion].filter(Boolean).join(' '),
    stats: [{ label: 'Database', value: database.databaseName || '—' }, { label: 'Admin user', value: database.adminUsername || '—' }, ...(database.capacity ? [{ label: 'Capacity', value: `${database.capacity.minUnits}–${database.capacity.maxUnits} units` }] : [])],
    env: RELATIONAL_ENV,
  })
  if (database?.kind === 'key-value') out.push({
    key: 'database', icon: 'database', name: databaseLabel(database.kind), spec: 'key-value table',
    stats: [{ label: 'Partition key', value: database.partitionKey || '—' }, { label: 'Sort key', value: database.sortKey || '—' }],
    env: KEY_VALUE_ENV,
  })
  if (bucket?.kind) out.push({
    key: 'bucket', icon: 'hard-drive', name: bucketLabel(bucket.kind), spec: bucket.kind === 'zonal' && bucket.zone ? `zone ${bucket.zone}` : bucket.kind,
    stats: [{ label: 'Access', value: bucket.access || 'read' }],
    env: BUCKET_ENV,
  })
  return out
}

export default function ResourcesTab({ app, onTab }: { app: Application; onTab: (tab: AppTab) => void }) {
  const resources = resourcesOf(app)
  const canWrite = app.permittedActions.includes('applications:write')
  return <div style={{ maxWidth: 960 }}>
    <SectionHeader title="Resources" description="Attached infrastructure. AppHub sets the environment variables below on every deploy, so your application can find each resource without hard-coding its name."
      action={canWrite && <Button variant="outlined" onClick={() => onTab('settings')}>Change in settings</Button>} />
    {!resources.length && <div style={{ ...cardStyle, padding: '14px 16px', fontSize: 12.5, color: 'var(--ink-2)' }}>No database or object storage is attached to this application.</div>}
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {resources.map(r => <div key={r.key} style={cardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 13, padding: '14px 16px', flexWrap: 'wrap' }}>
          <span style={{ width: 32, height: 32, borderRadius: 7, background: 'var(--teal-tint)', color: 'var(--teal-dark)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}><Icon name={r.icon} size={17} /></span>
          <div style={{ flex: 1, minWidth: 160 }}>
            <div style={{ fontSize: 13.5, fontWeight: 600 }}>{r.name}</div>
            <div style={{ ...monoCell, fontSize: 12, color: 'var(--ink-3)', marginTop: 2 }}>{r.spec}</div>
          </div>
          <div style={{ display: 'flex', gap: 22, flexWrap: 'wrap' }}>
            {r.stats.map(st => <div key={st.label}>
              <div style={{ fontSize: 10.5, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }}>{st.label}</div>
              <div style={{ ...monoCell, fontSize: 12.5, marginTop: 2 }}>{st.value}</div>
            </div>)}
          </div>
        </div>
        <div style={{ borderTop: '1px solid var(--line)', padding: '10px 16px 12px' }}>
          <div style={{ fontSize: 10.5, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)', marginBottom: 6 }}>Environment variables</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', columnGap: 16, rowGap: 4 }}>
            {r.env.map(e => <Fragment key={e.name}>
              <code style={{ ...monoCell, fontSize: 12.5 }}>{e.name}</code>
              <span style={{ fontSize: 12.5, color: 'var(--ink-3)' }}>{e.holds}</span>
            </Fragment>)}
          </div>
        </div>
      </div>)}
    </div>
  </div>
}
