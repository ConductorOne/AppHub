import type { ChipTone } from './Chip'
import type { Application, Deployment } from '../services/types'

export const STATUS_META: Record<Application['status'], { label: string; tone: ChipTone; dot: string; pulse?: boolean }> = {
  draft: { label: 'Draft', tone: 'muted', dot: 'var(--ink-dim)' },
  deploying: { label: 'Deploying', tone: 'teal', dot: 'var(--teal)', pulse: true },
  running: { label: 'Live', tone: 'success', dot: 'var(--ok)' },
  failed: { label: 'Failed', tone: 'error', dot: 'var(--err)' },
  interrupted: { label: 'Interrupted', tone: 'warning', dot: 'var(--warn)' },
  deleting: { label: 'Deleting', tone: 'warning', dot: 'var(--warn)', pulse: true },
  deletion_failed: { label: 'Deletion failed', tone: 'error', dot: 'var(--err)' },
}

/** Deletion has been requested: the application is read-only until it is gone or the teardown is retried. */
export function isDeletion(status: Application['status']) {
  return status === 'deleting' || status === 'deletion_failed'
}

export function needsAttention(status: Application['status']) {
  return status === 'failed' || status === 'interrupted' || status === 'deletion_failed'
}

export function executionLabel(execution: Application['specification']['execution']) {
  return execution === 'service' ? 'Container service' : 'Scheduled container'
}

export function databaseLabel(kind: string | undefined) {
  return kind === 'relational' ? 'Relational SQL' : kind === 'key-value' ? 'Key-value' : 'None'
}

export function bucketLabel(kind: string | undefined) {
  return kind === 'standard' ? 'Object storage' : kind === 'zonal' ? 'Zonal object storage' : 'None'
}

export function relativeTime(iso?: string) {
  if (!iso || iso.startsWith('0001-')) return '—'
  const ms = Date.now() - new Date(iso).getTime()
  const minutes = Math.round(ms / 60_000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.round(hours / 24)
  return `${days}d ago`
}

export const DEPLOYMENT_STATE_META: Record<Deployment['state'], { label: string; tone: ChipTone }> = {
  queued: { label: 'Queued', tone: 'muted' },
  running: { label: 'Running', tone: 'teal' },
  succeeded: { label: 'Succeeded', tone: 'success' },
  failed: { label: 'Failed', tone: 'error' },
  interrupted: { label: 'Interrupted', tone: 'warning' },
}

export function deploymentStateLabel(deployment: Pick<Deployment, 'state' | 'execution' | 'operation'>) {
  if (deployment.operation === 'teardown') return deployment.state === 'succeeded' ? 'Deleted' : DEPLOYMENT_STATE_META[deployment.state].label
  return deployment.state === 'succeeded' && deployment.execution === 'scheduled' ? 'Schedule installed' : DEPLOYMENT_STATE_META[deployment.state].label
}

export function operationLabel(operation: Deployment['operation']) {
  return operation === 'teardown' ? 'Deletion' : 'Deploy'
}

export function duration(start?: string, end?: string) {
  if (!start || !end || start.startsWith('0001-') || end.startsWith('0001-')) return '—'
  const seconds = Math.max(0, Math.round((new Date(end).getTime() - new Date(start).getTime()) / 1000))
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`
}
