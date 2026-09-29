import { useEffect, useState } from 'react'
import { Alert, AlertTitle, Typography } from '@mui/material'
import { useQueryClient } from '@tanstack/react-query'
import { useDeleteApplication } from '../../hooks/useApplications'
import { useDeployment } from '../../hooks/useDeployments'
import { isNotFound } from '../../services/api'
import type { Application, Deployment, TeardownStep } from '../../services/types'
import { Failure, Loading } from '../Feedback'
import { Button } from '../../design/Button'
import { Chip } from '../../design/Chip'
import { Icon } from '../../design/Icon'
import { duration } from '../../design/status'
import { DeletionError, TEARDOWN_STEP_LABEL } from './deletion'

const MINUTE = 60_000
const SLOW_STEP_MS = 15 * MINUTE
const SLOW_DATABASE_STEP_MS = 25 * MINUTE
const SLOW_QUEUE_MS = 2 * MINUTE

const STEP_HINT: Partial<Record<TeardownStep, string>> = {
  'delete-database': 'Deleting a database usually takes 5–10 minutes. You can leave this page; deletion continues in the background.',
  'delete-bucket': 'Buckets with many objects take longer to empty.',
}

type StepState = 'done' | 'current' | 'waiting' | 'failed' | 'pending'

function useNow(active: boolean) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [active])
  return now
}

/** When the operation entered the queue. A requeue after a worker stopped has no timestamp, so it is timed from when this page saw it. */
function useQueuedSince(op?: Deployment) {
  const queued = op?.state === 'queued'
  const [seen, setSeen] = useState<number>()
  useEffect(() => { setSeen(queued ? Date.now() : undefined) }, [queued, op?.attempt])
  if (!op || !queued) return undefined
  if (!op.startedAt && op.attempt <= 1) return Date.parse(op.createdAt)
  return seen ?? Date.now()
}

function since(iso: string | undefined, now: number) {
  return iso ? duration(iso, new Date(Math.max(now, Date.parse(iso))).toISOString()) : '—'
}

function stepStates(op: Deployment): StepState[] {
  const index = op.step ? op.plannedSteps.indexOf(op.step as TeardownStep) : -1
  return op.plannedSteps.map((_, i) => {
    if (op.state === 'succeeded' || i < index) return 'done'
    if (i !== index) return 'pending'
    if (op.state === 'failed' || op.state === 'interrupted') return 'failed'
    return op.state === 'queued' ? 'waiting' : 'current'
  })
}

const STEP_ICON: Record<StepState, { name: string; color: string; spin?: boolean }> = {
  done: { name: 'circle-check', color: 'var(--ok)' },
  current: { name: 'loader', color: 'var(--teal)', spin: true },
  waiting: { name: 'clock', color: 'var(--warn)' },
  failed: { name: 'circle-x', color: 'var(--err)' },
  pending: { name: 'circle', color: 'var(--ink-4)' },
}

function StepRow({ step, state, elapsed }: { step: TeardownStep; state: StepState; elapsed?: string }) {
  const icon = STEP_ICON[state]
  const active = state === 'current' || state === 'waiting'
  return <li aria-current={active ? 'step' : undefined} style={{ display: 'flex', gap: 11, padding: '9px 17px', background: active ? 'var(--bg-1)' : undefined }}>
    <span style={{ display: 'flex', marginTop: 1, color: icon.color }}><Icon name={icon.name} size={16} className={icon.spin ? 'ah-spin' : undefined} /></span>
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <span style={{ flex: 1, fontSize: 13, fontWeight: active || state === 'failed' ? 600 : 450, color: state === 'pending' ? 'var(--ink-3)' : state === 'failed' ? 'var(--err-ink)' : 'var(--ink)' }}>{TEARDOWN_STEP_LABEL[step] ?? step}</span>
        {state === 'waiting' && <span style={{ fontSize: 12, color: 'var(--warn-ink)' }}>Waiting for a worker</span>}
        {state === 'failed' && <span style={{ fontSize: 12, color: 'var(--err-ink)' }}>Failed</span>}
        {elapsed && <span className="ds-mono" style={{ fontSize: 12, color: 'var(--ink-2)' }}>{elapsed}</span>}
      </div>
      {state === 'current' && STEP_HINT[step] && <div style={{ fontSize: 12, color: 'var(--ink-2)', marginTop: 3 }}>{STEP_HINT[step]}</div>}
    </div>
  </li>
}

type Timing = { now: number; queuedSince?: number }

function isSlow(op: Deployment, { now, queuedSince }: Timing) {
  if (op.terminal) return false
  if (queuedSince !== undefined) return now - queuedSince > SLOW_QUEUE_MS
  const limit = op.step === 'delete-database' ? SLOW_DATABASE_STEP_MS : SLOW_STEP_MS
  return !!op.stepStartedAt && now - Date.parse(op.stepStartedAt) > limit
}

/** Reassurance only: resending the request for a queued or running teardown returns the same operation and changes nothing. */
function SlowNotice({ op }: { op: Deployment }) {
  return <Alert severity="info" icon={<Icon name="clock" size={18} />}>
    <AlertTitle sx={{ fontSize: 13, fontWeight: 600 }}>Taking longer than usual</AlertTitle>
    {op.state === 'queued'
      ? 'No worker has picked this up yet. AppHub will start it automatically once a worker is available. If this persists, contact your platform operator.'
      : 'This step is running longer than it normally does. AppHub keeps retrying automatically, so there is nothing you need to do.'}
  </Alert>
}

function FailureNotice({ op, completed }: { op: Deployment; completed: number }) {
  const failedStep = op.plannedSteps.find(step => step === op.step)
  return <Alert severity="error">
    <AlertTitle sx={{ fontSize: 13, fontWeight: 600 }}>{failedStep ? `${TEARDOWN_STEP_LABEL[failedStep]} failed` : 'Deletion failed'}</AlertTitle>
    {op.message || 'The teardown stopped before every resource was removed.'}
    <Typography component="div" sx={{ fontSize: 12, mt: 0.75 }}>{completed} of {op.plannedSteps.length} steps completed. Resources from the completed steps are already gone.</Typography>
    {op.errorCode && <Typography variant="caption" component="div">Error code: {op.errorCode}</Typography>}
  </Alert>
}

function RetryAction({ app }: { app: Application }) {
  const { mutation } = useDeleteApplication(app)
  return <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
      <Button color="error" disabled={mutation.isPending} onClick={() => mutation.mutate()}
        startIcon={mutation.isPending ? <Icon name="loader" size={14} className="ah-spin" /> : undefined}>{mutation.isPending ? 'Retrying…' : 'Retry deletion'}</Button>
      <span style={{ fontSize: 12, color: 'var(--ink-2)', flex: 1, minWidth: 200 }}>Retrying is safe: resources that are already deleted are skipped.</span>
    </div>
    {mutation.error && <DeletionError error={mutation.error} />}
  </div>
}

function CardHeading({ app, op, now }: { app: Application; op?: Deployment; now: number }) {
  const failed = app.status === 'deletion_failed'
  const start = op?.startedAt ?? op?.createdAt
  const elapsed = op?.terminal ? duration(start, op.finishedAt) : since(start, now)
  return <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 17px', background: failed ? 'var(--err-tint)' : 'var(--warn-tint)', borderBottom: `1px solid ${failed ? 'var(--err-line)' : 'var(--warn-line)'}`, flexWrap: 'wrap' }}>
    <span style={{ width: 32, height: 32, borderRadius: 7, background: 'var(--bg-0)', color: failed ? 'var(--err)' : 'var(--warn)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}><Icon name={failed ? 'triangle-alert' : 'trash-2'} size={17} /></span>
    <div style={{ flex: 1, minWidth: 180 }}>
      <div className="break-text" style={{ fontSize: 14, fontWeight: 600, color: failed ? 'var(--err-ink)' : 'var(--warn-ink)' }}>{failed ? `Deleting ${app.specification.name} failed` : `Deleting ${app.specification.name}`}</div>
      <div style={{ fontSize: 12.5, color: failed ? 'var(--err-ink)' : 'var(--warn-ink)', marginTop: 1 }}>{failed ? 'The application is read-only. Retry to finish removing its resources.' : 'The application is read-only while its resources are removed.'}</div>
    </div>
    {op && op.attempt > 1 && !op.terminal && <Chip tone="muted" size="extraSmall">Retrying automatically (attempt {op.attempt})</Chip>}
    {op && <span title="Total elapsed" style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12.5, color: failed ? 'var(--err-ink)' : 'var(--warn-ink)' }}><Icon name="clock" size={13} /><span className="ds-mono">{elapsed}</span></span>}
  </div>
}

function OperationBody({ app, op, timing }: { app: Application; op: Deployment; timing: Timing }) {
  const states = stepStates(op)
  const slow = isSlow(op, timing)
  const completed = states.filter(state => state === 'done').length
  const failed = app.status === 'deletion_failed'
  const stopped = failed || op.state === 'failed' || op.state === 'interrupted'
  return <>
    {op.plannedSteps.length > 0 && <ol aria-label="Deletion steps" style={{ listStyle: 'none', margin: 0, padding: '6px 0' }}>
      {op.plannedSteps.map((step, i) => <StepRow key={step} step={step} state={states[i]!} elapsed={states[i] === 'current' ? since(op.stepStartedAt, timing.now) : undefined} />)}
    </ol>}
    <div style={{ padding: '12px 17px 15px', borderTop: '1px solid var(--bg-2)', display: 'flex', flexDirection: 'column', gap: 12 }}>
      {op.state === 'queued' && !slow && <span style={{ fontSize: 12.5, color: 'var(--ink-2)' }}>Queued. A worker will pick this up shortly.</span>}
      {slow && <SlowNotice op={op} />}
      {stopped && <FailureNotice op={op} completed={completed} />}
      {failed && <RetryAction app={app} />}
      {!failed && op.state !== 'failed' && <span style={{ fontSize: 12, color: 'var(--ink-3)' }}>Updates every two seconds. You can leave this page; deletion continues in the background.</span>}
    </div>
  </>
}

/** Live teardown progress, shown above the tabs while deletion is requested. */
export default function DeletionProgress({ app }: { app: Application }) {
  const operationId = app.activeDeploymentId ?? app.latestDeploymentId ?? ''
  const query = useDeployment(operationId)
  const client = useQueryClient()
  const op = query.data?.operation === 'teardown' ? query.data : undefined
  const now = useNow(!!op && !op.terminal)
  const queuedSince = useQueuedSince(op)
  const gone = isNotFound(query.error)
  useEffect(() => {
    if (gone || op?.terminal) void client.invalidateQueries({ queryKey: ['application', app.id] })
  }, [gone, op?.terminal, app.id, client])

  return <section aria-label="Deletion progress" aria-live="polite" style={{ border: `1px solid ${app.status === 'deletion_failed' ? 'var(--err-line)' : 'var(--warn-line)'}`, borderRadius: 8, overflow: 'hidden', marginBottom: 20, background: 'var(--bg-0)' }}>
    <CardHeading app={app} op={op} now={now} />
    {op ? <OperationBody app={app} op={op} timing={{ now, queuedSince }} />
      : gone ? <div style={{ padding: '4px 17px' }}><Loading label="Finishing deletion…" /></div>
      : query.error ? <div style={{ padding: '0 17px' }}><Failure error={query.error} retry={() => void query.refetch()} /></div>
      : <div style={{ padding: '4px 17px' }}><Loading label="Loading deletion progress…" /></div>}
  </section>
}
