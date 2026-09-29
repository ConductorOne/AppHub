import { Link } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth'
import { useDeployments } from '../../hooks/useDeployments'
import type { Application, Deployment, OwnerView } from '../../services/types'
import { Failure, Loading } from '../Feedback'
import { Avatar } from '../../design/Avatar'
import { Chip } from '../../design/Chip'
import { Icon } from '../../design/Icon'
import { OwnerAvatar } from '../../design/owners'
import { PreviewChip } from '../../design/Preview'
import { simulatedSeverityCounts } from '../../design/simulated'
import { bucketLabel, databaseLabel, deploymentStateLabel, DEPLOYMENT_STATE_META, duration, executionLabel, operationLabel, relativeTime, STATUS_META } from '../../design/status'
import { type AppTab, CardHeader, cardStyle, eyebrowStyle, LinkButton, monoCell, SectionHeader } from './parts'
import TrafficCard from './TrafficCard'

type Props = { app: Application; targetLabel: string; vulnEnabled: boolean; onTab: (tab: AppTab) => void }

function newestFirst(items: Deployment[]) {
  return [...items].sort((a, b) => {
    const latest = Date.parse(b.createdAt || '')
    const earlier = Date.parse(a.createdAt || '')
    if (Number.isNaN(latest) || Number.isNaN(earlier)) return 0
    return latest - earlier
  })
}

function headline(latest?: Deployment) {
  if (!latest) return 'Not deployed yet'
  if (latest.operation === 'teardown') return `${operationLabel(latest.operation)} ${latest.terminal ? latest.state : 'started'} ${relativeTime(latest.finishedAt || latest.startedAt || latest.createdAt)}`
  if (latest.state === 'queued' || latest.state === 'running') return `Deploy started ${relativeTime(latest.startedAt || latest.createdAt)}`
  if (latest.state === 'succeeded') return `${latest.execution === 'scheduled' ? 'Schedule installed' : 'Deployed'} ${relativeTime(latest.finishedAt || latest.createdAt)}`
  return `Last deploy ${latest.state} ${relativeTime(latest.finishedAt || latest.createdAt)}`
}

export default function OverviewTab({ app, targetLabel, vulnEnabled, onTab }: Props) {
  const deployments = useDeployments(app.id)
  const items = newestFirst(deployments.data?.items || [])
  const lastSuccess = items.find(d => d.id === app.lastSuccessfulDeploymentId)
  const meta = STATUS_META[app.status]
  const facts = [
    { label: 'Target', value: targetLabel },
    { label: 'Execution', value: executionLabel(app.specification.execution) },
    { label: 'Revision', value: String(app.revision) },
    { label: 'Live commit', value: lastSuccess?.resolvedCommit?.slice(0, 7) || '—' },
    ...(app.lastDeployedAt ? [{ label: 'Last deployed', value: relativeTime(app.lastDeployedAt) }] : []),
  ]

  return <div className="app-overview-grid">
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, minWidth: 0 }}>
      <div style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '16px 18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <Chip tone={meta.tone} dot pulse={meta.pulse}>{meta.label}</Chip>
          <span style={{ fontSize: 13.5, fontWeight: 600 }}>{deployments.isPending ? '…' : headline(items[0])}</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px,1fr))', gap: 14, marginTop: 14 }}>
          {facts.map(f => <div key={f.label}><div style={eyebrowStyle}>{f.label}</div><div style={{ ...monoCell, fontSize: 12.5, marginTop: 3 }}>{f.value}</div></div>)}
        </div>
        {app.specification.execution === 'scheduled' && app.lastSuccessfulDeploymentId && <p style={{ fontSize: 12, color: 'var(--ink-3)', margin: '12px 0 0' }}>The last successful deployment installed the schedule; it does not report the result of each run.</p>}
      </div>

      <TrafficCard app={app} />

      <div>
        <SectionHeader title="Recent activity" />
        <RecentDeploys appId={app.id} items={items} query={deployments} />
      </div>
    </div>

    <aside style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
      {vulnEnabled && <SecurityCard appId={app.id} onReview={() => onTab('vulnerabilities')} />}
      <ResourcesCard app={app} onManage={() => onTab('resources')} />
      <OwnershipCard owners={app.owners} createdAt={app.createdAt} />
    </aside>
  </div>
}

function RecentDeploys({ appId, items, query }: { appId: string; items: Deployment[]; query: ReturnType<typeof useDeployments> }) {
  if (query.isPending) return <Loading label="Loading activity…" />
  if (query.error) return <Failure error={query.error} retry={() => void query.refetch()} />
  if (!items.length) return <div style={{ ...cardStyle, padding: '14px 15px', fontSize: 12.5, color: 'var(--ink-2)' }}>No deployments have been submitted yet.</div>
  return <>
    <div style={cardStyle}>
      {items.map(d => <Link key={d.id} to={`/applications/${appId}/deployments/${d.id}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(0,118px) minmax(0,1fr) minmax(0,80px) minmax(0,64px)', gap: 14, alignItems: 'center', padding: '11px 15px', borderBottom: '1px solid var(--bg-2)', color: 'inherit', fontWeight: 400 }} className="row-hover">
        <div><Chip tone={DEPLOYMENT_STATE_META[d.state].tone} size="extraSmall">{deploymentStateLabel(d)}</Chip></div>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 12.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.message || '—'}</div>
          <div style={{ ...monoCell, fontSize: 11.5, color: 'var(--ink-3)' }}>{d.operation === 'teardown' ? `Deletion · ${d.plannedSteps.length} steps` : `${d.resolvedCommit?.slice(0, 7) || d.requestedSourceRef || 'default branch'} · rev ${d.applicationRevision}`}</div>
        </div>
        <div style={{ fontSize: 12, color: 'var(--ink-2)' }}>{relativeTime(d.createdAt)}</div>
        <div style={{ ...monoCell, fontSize: 12, color: 'var(--ink-2)', textAlign: 'right' }}>{duration(d.startedAt, d.finishedAt)}</div>
      </Link>)}
    </div>
    {!!query.data?.cursor && <p style={{ fontSize: 12, color: 'var(--ink-3)', margin: '8px 0 0' }}>Showing the {items.length} most recent operations.</p>}
  </>
}

function SecurityCard({ appId, onReview }: { appId: string; onReview: () => void }) {
  const counts = simulatedSeverityCounts(appId)
  const rows = [
    { label: 'Critical', count: counts.critical, color: 'var(--err)' }, { label: 'High', count: counts.high, color: 'var(--err)' },
    { label: 'Medium', count: counts.medium, color: 'var(--warn)' }, { label: 'Low', count: counts.low, color: 'var(--ink-dim)' },
  ]
  return <div style={cardStyle}>
    <CardHeader title={<>Security <PreviewChip /></>} action={<LinkButton onClick={onReview}>Review</LinkButton>} />
    <div style={{ padding: '13px 15px', display: 'flex', flexDirection: 'column', gap: 9 }}>
      {rows.map(v => <div key={v.label} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ width: 8, height: 8, borderRadius: 8, background: v.color, flexShrink: 0 }} />
        <span style={{ flex: 1, fontSize: 12.5, color: 'var(--ink-2)' }}>{v.label}</span>
        <span className="ds-mono" style={{ fontSize: 13, fontWeight: 600 }}>{v.count}</span>
      </div>)}
      <p style={{ fontSize: 11.5, color: 'var(--ink-3)', margin: '2px 0 0' }}>Illustrative counts — vulnerability scanning isn't connected yet.</p>
    </div>
  </div>
}

function ResourcesCard({ app, onManage }: { app: Application; onManage: () => void }) {
  const { database, bucket } = app.specification
  const rows = [
    ...(database?.kind ? [{ icon: 'database', name: databaseLabel(database.kind), plan: database.kind === 'relational' ? [database.engine, database.engineVersion].filter(Boolean).join(' ') : database.partitionKey || 'key-value' }] : []),
    ...(bucket?.kind ? [{ icon: 'hard-drive', name: bucketLabel(bucket.kind), plan: bucket.access || 'read' }] : []),
  ]
  return <div style={cardStyle}>
    <CardHeader title="Attached resources" action={<LinkButton onClick={onManage}>View</LinkButton>} />
    <div style={{ padding: '6px 0' }}>
      {!rows.length && <div style={{ padding: '9px 15px', fontSize: 12.5, color: 'var(--ink-3)' }}>No resources attached.</div>}
      {rows.map(r => <div key={r.icon} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 15px' }}>
        <Icon name={r.icon} size={16} color="var(--teal)" />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12.5, fontWeight: 500 }}>{r.name}</div>
          <div style={{ ...monoCell, fontSize: 11, color: 'var(--ink-3)' }}>{r.plan}</div>
        </div>
      </div>)}
    </div>
  </div>
}

function OwnershipCard({ owners, createdAt }: { owners: OwnerView[]; createdAt: string }) {
  const me = useAuth().data?.id
  return <div style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '13px 15px' }}>
    <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>Ownership</div>
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {owners.map(owner => <div key={owner.key} style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
        <OwnerAvatar owner={owner} />
        <div style={{ minWidth: 0 }}>
          <div className="break-text" style={{ fontSize: 12.5, fontWeight: 500 }}>{owner.name}{owner.kind === 'user' && owner.id === me && <span style={{ color: 'var(--ink-3)', fontWeight: 400 }}> (you)</span>}</div>
          <div style={{ fontSize: 11, color: 'var(--ink-3)' }}>{owner.kind === 'group' ? 'Directory group' : 'Owner'}</div>
        </div>
      </div>)}
    </div>
    <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 10 }}>Created {relativeTime(createdAt)}</div>
  </div>
}
