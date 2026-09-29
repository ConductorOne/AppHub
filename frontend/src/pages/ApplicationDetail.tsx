import { useEffect } from 'react'
import { Alert, Box } from '@mui/material'
import { Link, useLocation, useParams, useSearchParams } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { useApplication, useCategories, useDirectoryEntry, useFinishDeletion, useTargets } from '../hooks/useApplications'
import type { Application } from '../services/types'
import { isNotFound } from '../services/api'
import { SubmitDeploymentNotices, useSubmitDeployment } from '../components/SubmitDeployment'
import { Failure, Loading } from '../components/Feedback'
import { AppURL, appURL } from '../components/AppURL'
import AuthenticationTab from '../components/application/AuthenticationTab'
import DeletionProgress from '../components/application/DeletionProgress'
import DomainsTab from '../components/application/DomainsTab'
import OverviewTab from '../components/application/OverviewTab'
import ReadOnlyApplication from '../components/application/ReadOnlyApplication'
import ResourcesTab from '../components/application/ResourcesTab'
import SecretsTab from '../components/application/SecretsTab'
import SettingsTab from '../components/application/SettingsTab'
import { ActivityTab } from '../components/application/StubTabs'
import VulnerabilitiesTab from '../components/application/VulnerabilitiesTab'
import type { AppTab } from '../components/application/parts'
import { Avatar } from '../design/Avatar'
import { Button } from '../design/Button'
import { Chip } from '../design/Chip'
import { Icon } from '../design/Icon'
import { isDeletion, STATUS_META } from '../design/status'
import { categoryIcon, categoryMeta } from '../design/categories'

const TABS: { key: AppTab; label: string }[] = [
  { key: 'overview', label: 'Overview' }, { key: 'settings', label: 'Settings' }, { key: 'authentication', label: 'Authentication' }, { key: 'secrets', label: 'Secrets' },
  { key: 'resources', label: 'Resources' }, { key: 'domains', label: 'Domains' },
  { key: 'vulnerabilities', label: 'Vulnerabilities' }, { key: 'activity', label: 'Activity' },
]

export default function ApplicationDetail() {
  const { id = '' } = useParams()
  const auth = useAuth()
  const vulnEnabled = !!auth.data?.enabledFeatures.includes('vulnerabilities')
  const tabs = TABS.filter(t => t.key !== 'vulnerabilities' || vulnEnabled)
  const [params, setParams] = useSearchParams()
  const tab = tabs.find(t => t.key === params.get('tab'))?.key ?? 'overview'
  const setTab = (next: AppTab) => setParams(next === 'overview' ? {} : { tab: next }, { replace: true })
  const query = useApplication(id)
  const targets = useTargets()

  const notFound = isNotFound(query.error)
  // The last good response survives a failed refetch, so a 404 after watching a deletion means it finished.
  const deleted = notFound && !!query.data && isDeletion(query.data.status)
  const directory = useDirectoryEntry(id, notFound && !deleted)
  const finishDeletion = useFinishDeletion()
  const deletedName = deleted ? query.data?.specification.name ?? '' : ''
  useEffect(() => { if (deletedName) finishDeletion(deletedName) }, [deletedName, finishDeletion])

  if (query.isPending) return <Box sx={{ p: 4 }}><Loading label="Loading application…" /></Box>
  if (deleted) return <Box sx={{ p: 4 }}><Loading label="Finishing deletion…" /></Box>
  if (notFound) {
    if (directory.isPending) return <Box sx={{ p: 4 }}><Loading label="Loading application…" /></Box>
    if (directory.data) {
      const readOnlyTab = tab === 'activity' ? 'activity' : 'overview'
      return <ReadOnlyApplication app={directory.data} tab={readOnlyTab} onTab={setTab} />
    }
    return <Box sx={{ p: 4 }}><Failure error={query.error} retry={() => void query.refetch()} /></Box>
  }
  if (query.error) return <Box sx={{ p: 4 }}><Failure error={query.error} retry={() => void query.refetch()} /></Box>
  const app = query.data!
  return <Loaded app={app} targetLabel={targets.data?.find(t => t.id === app.specification.targetId)?.label || app.specification.targetId} tabs={tabs} tab={tab} onTab={setTab} vulnEnabled={vulnEnabled} />
}

type LoadedProps = { app: Application; targetLabel: string; tabs: typeof TABS; tab: AppTab; onTab: (tab: AppTab) => void; vulnEnabled: boolean }

function Loaded({ app, targetLabel, tabs, tab, onTab: setTab, vulnEnabled }: LoadedProps) {
  const location = useLocation()
  const submit = useSubmitDeployment(app)
  const id = app.id
  const notice = location.state as { draftCreated?: boolean; submissionMessage?: string } | null
  const deleting = isDeletion(app.status)

  return <div style={{ animation: 'ah-rise 200ms cubic-bezier(0,0,.2,1)' }}>
    <style>{'@keyframes ah-rise { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: none; } }'}</style>
    <Header app={app} submit={submit} targetLabel={targetLabel} tabs={tabs} tab={tab} onTab={setTab} />

    <Box sx={{ p: '24px 32px 56px' }}>
      {deleting && <DeletionProgress app={app} />}
      {!deleting && <Box sx={{ mb: submit.mutation.error || submit.pending ? 2 : 0 }}><SubmitDeploymentNotices application={app} submit={submit} /></Box>}
      {!deleting && notice?.draftCreated && <Alert severity="warning" sx={{ mb: 2 }}>Draft saved successfully as {app.id}. Deployment was not confirmed: {notice.submissionMessage} Use Deploy above to submit it; do not recreate this application.</Alert>}
      {!deleting && app.activeDeploymentId && <Alert severity={app.status === 'interrupted' ? 'warning' : 'info'} sx={{ mb: 2 }}>{app.status === 'interrupted' ? 'The previous worker’s outcome is uncertain. Editing and new deployments are locked until an administrator confirms the old worker/build container is stopped and resolves the operation.' : 'A deployment is active. Editing and new submissions are locked until it settles.'}<Button to={`/applications/${id}/deployments/${app.activeDeploymentId}`} style={{ marginTop: 8 }}>View operation</Button></Alert>}

      {tab === 'overview' && <OverviewTab app={app} targetLabel={targetLabel} vulnEnabled={vulnEnabled} onTab={setTab} />}
      {tab === 'settings' && <SettingsTab app={app} />}
      {tab === 'authentication' && <AuthenticationTab app={app} />}
      {tab === 'secrets' && <SecretsTab app={app} />}
      {tab === 'resources' && <ResourcesTab app={app} onTab={setTab} />}
      {tab === 'domains' && <DomainsTab app={app} onTab={setTab} />}
      {tab === 'vulnerabilities' && <VulnerabilitiesTab appId={app.id} />}
      {tab === 'activity' && <ActivityTab />}
    </Box>
  </div>
}

type HeaderProps = { app: Application; submit: ReturnType<typeof useSubmitDeployment>; targetLabel: string; tabs: typeof TABS; tab: AppTab; onTab: (tab: AppTab) => void }

function Header({ app, submit, targetLabel, tabs, tab, onTab }: HeaderProps) {
  const meta = STATUS_META[app.status]
  const category = categoryMeta(useCategories().data, app.specification.category)
  const published = appURL(app)
  const canDeploy = app.permittedActions.includes('deployments:write')
  const readOnly = !canDeploy && !app.permittedActions.includes('applications:write')
  const deleting = isDeletion(app.status)
  const deployLabel = submit.mutation.isPending || submit.pending ? submit.label : app.lastSuccessfulDeploymentId ? 'Redeploy' : 'Deploy'

  return <Box sx={{ p: '20px 32px 0', borderBottom: '1px solid var(--line)', position: 'sticky', top: 0, background: 'var(--bg-0)', zIndex: 5 }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--ink-3)', marginBottom: 10 }}>
      <Link to="/applications" style={{ fontSize: 12, fontWeight: 500 }}>Applications</Link><span>/</span>
      <span className="ds-mono">{app.specification.name}</span>
    </div>
    <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
      <Avatar name={app.specification.name} size={34} radius={8} />
      <div style={{ flex: 1, minWidth: 160 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <h1 className="break-text" style={{ fontFamily: "'Anybody', sans-serif", fontSize: 24, fontWeight: 600, letterSpacing: '-.015em', margin: 0 }}>{app.specification.name}</h1>
          <Chip tone={meta.tone} dot pulse={meta.pulse} size="extraSmall">{meta.label}</Chip>
          {category && <button type="button" onClick={() => onTab('settings')} title="Change in Settings" style={{ display: 'inline-flex', alignItems: 'center', gap: 5, border: 0, background: 'transparent', padding: 0, cursor: 'pointer', fontFamily: 'inherit', fontSize: 12, color: 'var(--ink-2)' }}><Icon name={categoryIcon(category.key)} size={13} />{category.label}</button>}
        </div>
        <AppURL app={app} />
      </div>
      <div title="Deployment target" style={{ display: 'flex', alignItems: 'center', gap: 6, border: '1px solid var(--line)', borderRadius: 6, padding: '5px 9px' }}>
        <span style={{ width: 6, height: 6, borderRadius: 6, background: meta.dot }} />
        <span style={{ fontSize: 12.5, fontWeight: 500 }}>{targetLabel}</span>
      </div>
      {readOnly && <Chip tone="muted" size="extraSmall">Read only</Chip>}
      {!deleting && <Button variant="outlined" to={app.latestDeploymentId ? `/applications/${app.id}/deployments/${app.latestDeploymentId}` : undefined} disabled={!app.latestDeploymentId}>Latest deploy</Button>}
      {!deleting && published.url && <Button variant="outlined" href={published.url} endIcon={<Icon name="external-link" size={14} />}>Open app</Button>}
      {!deleting && canDeploy && <Button disabled={submit.disabled} onClick={() => submit.mutation.mutate()}>{deployLabel}</Button>}
    </div>
    <div role="tablist" style={{ display: 'flex', gap: 2, marginTop: 14, overflowX: 'auto' }}>
      {tabs.map(t => <button key={t.key} type="button" role="tab" aria-selected={tab === t.key} onClick={() => onTab(t.key)} style={{ border: 0, background: 'transparent', cursor: 'pointer', fontFamily: 'inherit', fontSize: 13, fontWeight: 500, padding: '9px 12px', color: tab === t.key ? 'var(--teal)' : 'var(--ink-2)', borderBottom: `2px solid ${tab === t.key ? 'var(--teal)' : 'transparent'}`, whiteSpace: 'nowrap' }}>{t.label}</button>)}
    </div>
  </Box>
}
