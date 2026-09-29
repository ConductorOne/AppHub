import { useState } from 'react'
import { Alert, Box, Stack, Typography } from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useCategories, useTargets } from '../../hooks/useApplications'
import { ApiError, apiPath, request, segment } from '../../services/api'
import type { Application, ApplicationInput } from '../../services/types'
import ApplicationForm from '../ApplicationForm'
import { Failure, Loading } from '../Feedback'
import { Button } from '../../design/Button'
import { Icon } from '../../design/Icon'
import { NotAvailable } from '../../design/Preview'
import { CategoryPicker } from '../../design/categories'
import { executionLabel, isDeletion } from '../../design/status'
import { cardStyle, FieldRow, SectionHeader } from './parts'
import { DeleteApplicationDialog, DeletedResourceList } from './deletion'
import { OwnersSection } from './OwnersSection'

export default function SettingsTab({ app }: { app: Application }) {
  const targets = useTargets()
  const client = useQueryClient()
  const [edit, setEdit] = useState<{ specification: ApplicationInput; revision: number }>()
  const mutation = useMutation({ mutationFn: (input: ApplicationInput) => request<Application>(apiPath(`/applications/${segment(app.id)}`), { method: 'PUT', body: input, headers: { 'If-Match': `"${edit!.revision}"` } }), onSuccess: updated => { client.setQueryData(['application', app.id], updated); void client.invalidateQueries({ queryKey: ['applications'] }); setEdit(undefined) } })
  const locked = !!app.activeDeploymentId
  const stale = mutation.error instanceof ApiError && mutation.error.status === 409
  async function reload() { setEdit(undefined); mutation.reset(); await client.refetchQueries({ queryKey: ['application', app.id] }); await targets.refetch() }

  if (edit) return <Box sx={{ maxWidth: 840 }}>
    <SectionHeader title={`Edit revision ${edit.revision}`} description="Saving creates a new revision. Changes apply on the next deploy." action={<Button variant="outlined" disabled={mutation.isPending} onClick={() => { setEdit(undefined); mutation.reset() }}>Cancel editing</Button>} />
    {stale && <Alert severity="warning" sx={{ mb: 2 }}>This revision is stale or a deployment has started. Reload the current specification before editing; your changes will not overwrite it.<Button variant="outlined" onClick={() => void reload()}>Discard edits and reload</Button></Alert>}
    {targets.isPending ? <Loading /> : targets.error ? <Failure error={targets.error} retry={() => void targets.refetch()} /> : <ApplicationForm targets={targets.data || []} initial={edit.specification} immutableTarget busy={mutation.isPending} locked={locked || stale} error={mutation.error} submitLabel="Save new revision" onSubmit={input => mutation.mutate(input)} />}
  </Box>

  const spec = app.specification
  const canWrite = app.permittedActions.includes('applications:write')
  return <div style={{ maxWidth: 840, display: 'flex', flexDirection: 'column', gap: 26 }}>
    <ListingSection app={app} canWrite={canWrite} locked={locked} />

    <OwnersSection app={app} />

    <div>
      <SectionHeader title="Build and run" description="Changes apply on the next deploy." action={canWrite && <Button variant="outlined" disabled={locked} onClick={() => setEdit({ specification: app.specification, revision: app.revision })}>Edit configuration</Button>} />
      <div style={cardStyle}>
        <FieldRow label="Repository" hint="Cloned at deploy time">{spec.source.url}</FieldRow>
        <FieldRow label="Ref" hint="Branch, tag, or commit">{spec.source.ref || 'Default branch'}</FieldRow>
        <FieldRow label="Dockerfile" hint="Relative to the repository root">{spec.source.dockerfile}</FieldRow>
        <FieldRow label="Execution">{executionLabel(spec.execution)}</FieldRow>
        {spec.schedule && <FieldRow label="Schedule" hint={spec.schedule.timezone}>{spec.schedule.expression} · {spec.schedule.paused ? 'Paused' : 'Enabled'}</FieldRow>}
        <FieldRow label="Port" hint="The container listens here">{spec.port}</FieldRow>
      </div>
    </div>

    <div>
      <SectionHeader title="Scaling" description="Each replica gets the same CPU and memory." />
      <div style={cardStyle}>
        <FieldRow label="Replicas">{spec.replicas}</FieldRow>
        <FieldRow label="CPU">{spec.resources.cpu} millicores</FieldRow>
        <FieldRow label="Memory">{spec.resources.memory} MiB</FieldRow>
      </div>
    </div>

    <div>
      <SectionHeader title="Environment variables" description="Values from attached resources are managed by AppHub." action={<Button variant="outlined" size="sm" disabled>Add variable</Button>} />
      <NotAvailable icon="terminal" title="Environment variables">Setting custom environment variables isn't supported yet. Credentials for attached resources are still injected automatically.</NotAvailable>
    </div>

    <Box component="details" sx={{ fontSize: 12.5 }}>
      <Box component="summary" sx={{ cursor: 'pointer', color: 'var(--ink-2)' }}>Complete saved specification</Box>
      <Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12, background: 'var(--bg-1)', border: '1px solid var(--line)', borderRadius: '8px', p: 1.5 }}>{JSON.stringify(app.specification, null, 2)}</Box>
    </Box>

    <DangerZone app={app} />
  </div>
}

/** Category saves immediately as a new revision, so it never waits for an edit session. */
function ListingSection({ app, canWrite, locked }: { app: Application; canWrite: boolean; locked: boolean }) {
  const categories = useCategories()
  const client = useQueryClient()
  const mutation = useMutation({
    mutationFn: (category: string) => request<Application>(apiPath(`/applications/${segment(app.id)}`), { method: 'PUT', body: { ...app.specification, category: category || undefined }, headers: { 'If-Match': `"${app.revision}"` } }),
    onSuccess: updated => { client.setQueryData(['application', app.id], updated); void client.invalidateQueries({ queryKey: ['applications'] }) },
  })
  const stale = mutation.error instanceof ApiError && mutation.error.status === 409
  return <div>
    <SectionHeader title="Listing" description="How this application is grouped on the Home launcher." />
    <div style={{ ...cardStyle, padding: '12px 15px' }}>
      {categories.isPending ? <Loading label="Loading categories…" /> : categories.error ? <Failure error={categories.error} retry={() => void categories.refetch()} /> : <>
        <CategoryPicker categories={categories.data} value={app.specification.category} disabled={!canWrite || locked || mutation.isPending} onChange={category => mutation.mutate(category)} />
        <div style={{ fontSize: 11.5, color: 'var(--ink-3)', marginTop: 8 }}>
          {app.deletionRequestedAt ? 'Read-only while the application is being deleted.' : !canWrite ? 'Only owners and admins can change the category.' : locked ? 'Category changes are locked while a deployment is active.' : mutation.isPending ? 'Saving…' : 'Saved as a new revision. No redeploy needed.'}
        </div>
      </>}
      {stale && <Alert severity="warning" sx={{ mt: 1.5 }}>This application changed since the page loaded. Reload it and pick the category again.<Button variant="outlined" onClick={() => { mutation.reset(); void client.refetchQueries({ queryKey: ['application', app.id] }) }}>Reload</Button></Alert>}
      {mutation.error && !stale && <Failure error={mutation.error} />}
    </div>
  </div>
}

function deleteBlockedReason(app: Application) {
  if (app.permittedActions.includes('applications:delete')) return undefined
  if (app.activeDeploymentId && app.status !== 'interrupted') return 'A deployment is in progress. You can delete this application once it finishes.'
  return 'Only the owner or an administrator can delete this application.'
}

function DangerZone({ app }: { app: Application }) {
  const [confirming, setConfirming] = useState(false)
  const blocked = deleteBlockedReason(app)
  if (isDeletion(app.status)) return <div style={{ border: '1px solid var(--err-line)', borderRadius: 8, padding: '15px 17px', background: 'var(--err-tint)', fontSize: 12.5, color: 'var(--err-ink)' }}>
    {app.status === 'deleting' ? 'Deletion is in progress. Follow it at the top of this page.' : 'Deletion failed. Retry it from the top of this page.'}
  </div>
  return <div>
    <SectionHeader title="Danger zone" />
    <div style={{ border: '1px solid var(--err-line)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '15px 17px', background: 'var(--err-tint)', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
        <Stack sx={{ flex: 1, minWidth: 220 }}>
          <Typography component="div" sx={{ fontSize: 13, fontWeight: 600, color: 'var(--err-ink)' }}>Delete application</Typography>
          <Typography component="div" sx={{ fontSize: 12.5, color: 'var(--err-ink)', mt: 0.25 }}>Permanently removes {app.specification.name} and all of its infrastructure. Data is destroyed without a snapshot; this cannot be undone.</Typography>
        </Stack>
        <Button color="error" disabled={!!blocked} onClick={() => setConfirming(true)}>Delete application</Button>
      </div>
      <div style={{ padding: '13px 17px', display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }}>What gets deleted</div>
        <DeletedResourceList app={app} compact />
        {blocked && <div style={{ fontSize: 12, color: 'var(--ink-2)', display: 'flex', alignItems: 'center', gap: 6 }}><Icon name="lock" size={13} />{blocked}</div>}
      </div>
    </div>
    <DeleteApplicationDialog app={app} open={confirming} onClose={() => setConfirming(false)} />
  </div>
}
