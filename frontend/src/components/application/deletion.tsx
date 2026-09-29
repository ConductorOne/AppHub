import { Alert } from '@mui/material'
import { useDeleteApplication } from '../../hooks/useApplications'
import { ApiError } from '../../services/api'
import type { Application, TeardownStep } from '../../services/types'
import { appURL } from '../AppURL'
import { Failure } from '../Feedback'
import { ConfirmDialog } from '../../design/ConfirmDialog'
import { Chip } from '../../design/Chip'
import { Icon } from '../../design/Icon'

export const TEARDOWN_STEP_LABEL: Record<TeardownStep, string> = {
  'delete-workload': 'Stopping the service',
  'delete-database': 'Deleting the database',
  'delete-key-value': 'Deleting the key-value table',
  'delete-bucket': 'Emptying and deleting the bucket',
  'delete-secrets': 'Removing secrets',
  'delete-identity': 'Removing the workload identity',
  'delete-image-repository': 'Removing container images',
  'delete-records': 'Removing AppHub records',
}

type DeletedResource = { key: string; icon: string; label: string; detail?: string; dataLoss?: boolean }

/** What a teardown destroys, derived from the saved specification. */
export function deletedResources(app: Application): DeletedResource[] {
  const { execution, database, bucket } = app.specification
  const url = appURL(app).url
  const out: DeletedResource[] = [execution === 'scheduled'
    ? { key: 'workload', icon: 'server', label: 'The scheduled job', detail: 'Its schedule stops and no further runs start.' }
    : { key: 'workload', icon: 'server', label: 'The running service', detail: 'Every replica stops and requests stop being served.' }]
  if (database?.kind === 'relational') out.push({ key: 'database', icon: 'database', label: `The ${database.engine === 'mysql' ? 'MySQL' : 'Postgres'} database${database.databaseName ? ` ${database.databaseName}` : ''}`, detail: 'Every table and row is deleted.', dataLoss: true })
  if (database?.kind === 'key-value') out.push({ key: 'database', icon: 'database', label: 'The key-value table', detail: 'Every item is deleted.', dataLoss: true })
  if (bucket?.kind) out.push({ key: 'bucket', icon: 'hard-drive', label: 'The object storage bucket', detail: 'It is emptied first; every object in it is deleted.', dataLoss: true })
  out.push({ key: 'secrets', icon: 'key-round', label: 'Secrets', detail: 'Stored values cannot be recovered.' })
  out.push({ key: 'images', icon: 'boxes', label: 'Container images', detail: 'Every image built for this application.' })
  out.push(url
    ? { key: 'routes', icon: 'globe', label: 'Routes and URLs', detail: `${url} stops resolving and its hostname is released.` }
    : { key: 'routes', icon: 'globe', label: 'Hostname reservations', detail: 'Any reserved hostname is released.' })
  out.push({ key: 'records', icon: 'scroll-text', label: 'Deployment history', detail: 'The application and its records are removed from AppHub.' })
  return out
}

export function DeletedResourceList({ app, compact = false }: { app: Application; compact?: boolean }) {
  return <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: compact ? 6 : 8 }}>
    {deletedResources(app).map(r => <li key={r.key} style={{ display: 'flex', alignItems: 'flex-start', gap: 9 }}>
      <span style={{ display: 'flex', marginTop: 1, color: r.dataLoss ? 'var(--err)' : 'var(--ink-3)' }}><Icon name={r.icon} size={15} /></span>
      <span style={{ minWidth: 0, fontSize: 12.5, lineHeight: 1.45 }}>
        <span style={{ fontWeight: r.dataLoss ? 600 : 500, color: r.dataLoss ? 'var(--err-ink)' : 'var(--ink)' }}>{r.label}</span>
        {r.dataLoss && <Chip tone="error" size="extraSmall" style={{ marginLeft: 7, verticalAlign: 1 }}>Data loss</Chip>}
        {!compact && r.detail && <span className="break-text" style={{ display: 'block', color: 'var(--ink-2)' }}>{r.detail}</span>}
      </span>
    </li>)}
  </ul>
}

const DELETION_CONFLICTS: Record<string, string> = {
  deployment_running: 'A deployment is running. Delete the application once it finishes.',
  application_deleting: 'This application is being deleted.',
  conflict: 'The application changed; reload and try again.',
  deployment_active: 'The application changed; reload and try again.',
}

/** The name mismatch the server reports against the typed confirmation, shown on the field itself. */
export function confirmNameError(error: unknown) {
  return error instanceof ApiError && error.code === 'confirmation_mismatch' ? error.fieldErrors['confirmName'] || error.message : undefined
}

/** Known deletion conflicts get plain guidance; anything else shows the server's safe message. */
export function DeletionError({ error }: { error: unknown }) {
  if (confirmNameError(error)) return null
  const conflict = error instanceof ApiError && error.status === 409 ? DELETION_CONFLICTS[error.code] : undefined
  if (conflict) return <Alert severity="warning">{conflict} Nothing has been deleted.</Alert>
  return <Failure error={error} />
}

type DialogProps = { app: Application; open: boolean; onClose: () => void }

/** Type-the-name confirmation. On acceptance the dialog closes and the page switches to its deleting state. */
export function DeleteApplicationDialog({ app, open, onClose }: DialogProps) {
  const { mutation, pending } = useDeleteApplication(app)
  const name = app.specification.name
  const cancelsQueued = !!app.activeDeploymentId && app.status === 'deploying'
  function close() { mutation.reset(); onClose() }
  return <ConfirmDialog open={open} title={`Delete ${name}?`} color="error" confirmPhrase={name} confirmLabel="Delete application" busyLabel="Deleting…"
    busy={mutation.isPending} error={mutation.error && <DeletionError error={mutation.error} />} fieldError={confirmNameError(mutation.error)} onClose={close}
    onConfirm={() => mutation.mutate(undefined, { onSuccess: close })}>
    <p style={{ margin: '0 0 12px' }}>This permanently deletes the application and everything AppHub created for it:</p>
    <div style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '12px 14px', background: 'var(--bg-1)' }}><DeletedResourceList app={app} /></div>
    <p style={{ margin: '12px 0 0', fontWeight: 600, color: 'var(--err-ink)' }}>Data is destroyed without a snapshot. This cannot be undone.</p>
    {cancelsQueued && <p style={{ margin: '8px 0 0', color: 'var(--ink-2)' }}>The queued deployment is cancelled.</p>}
    {pending && <p style={{ margin: '8px 0 0', color: 'var(--ink-2)' }}>A previous deletion request may already have been accepted. Confirming resends it with the same key, so it cannot run twice.</p>}
  </ConfirmDialog>
}
