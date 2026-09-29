import { Box } from '@mui/material'
import { Failure, Loading, Timestamp } from '../components/Feedback'
import { Avatar } from '../design/Avatar'
import { Button } from '../design/Button'
import { useAuditLogs, useMembers } from '../hooks/useWorkspace'

const AUDIT_GRID = 'minmax(140px,1.4fr) minmax(0,2fr) minmax(0,1.4fr) minmax(0,110px)'

const ACTION_LABELS: Record<string, string> = {
  'deployments.create': 'Submitted deployment',
  'applications.delete': 'Requested application deletion',
  'secrets.deploy': 'Submitted secret changes',
  'directory.sync': 'Synced directory groups',
}

const ACTION_VERBS: Record<string, string> = {
  add: 'Added', complete: 'Completed', create: 'Created', delete: 'Deleted',
  forget: 'Forgot', remove: 'Removed', replace: 'Replaced', request: 'Requested',
  resolveInterrupted: 'Resolved interrupted', set: 'Set', update: 'Updated',
}

function actionLabel(action: string) {
  if (ACTION_LABELS[action]) return ACTION_LABELS[action]
  const parts = action.split('.')
  const verb = ACTION_VERBS[parts.pop() ?? '']
  if (!verb || !parts.length) return action
  return `${verb} ${parts.join(' ').replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase()}`
}

export function AuditLogTab() {
  const logs = useAuditLogs()
  const members = useMembers()
  const actorNames = new Map<string, string>(members.data?.map(member => [member.id, member.name || member.email]) ?? [])
  const rows = logs.data?.pages.flatMap(page => page.items) ?? []

  return <Box sx={{ maxWidth: 900 }}>
    <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>Audit log</div>
    {logs.isPending && !logs.error ? <Loading label="Loading audit log…" /> : <>
      {logs.error && <Failure error={logs.error} retry={() => { if (logs.isFetchNextPageError) void logs.fetchNextPage(); else void logs.refetch() }} />}
      {!logs.error && rows.length === 0 && <div style={{ color: 'var(--ink-2)', fontSize: 12.5 }}>No audit entries have been recorded yet.</div>}
      {rows.length > 0 && <div style={{ border: '1px solid var(--line)', borderRadius: 8, overflowX: 'auto' }}>
        <div style={{ minWidth: 620 }}>
          <div style={{ display: 'grid', gridTemplateColumns: AUDIT_GRID, gap: 14, padding: '9px 16px', background: 'var(--bg-1)', borderBottom: '1px solid var(--line)', fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }}>
            <div>Actor</div><div>Action</div><div>Target</div><div>When</div>
          </div>
          {rows.map((row, i) => <div key={row.id} style={{ display: 'grid', gridTemplateColumns: AUDIT_GRID, gap: 14, padding: '11px 16px', borderBottom: i < rows.length - 1 ? '1px solid var(--bg-2)' : 0, alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}><Avatar name={actorNames.get(row.actor) ?? row.actor} size={22} radius={20} /><span style={{ fontSize: 12.5, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.actor}>{actorNames.get(row.actor) ?? row.actor}</span></div>
            <div style={{ minWidth: 0, fontSize: 12.5, overflowWrap: 'anywhere' }}>
              <span title={row.action}>{actionLabel(row.action)}</span>
              {row.details && Object.keys(row.details).length > 0 && <details style={{ marginTop: 4, color: 'var(--ink-2)', fontSize: 11.5 }}>
                <summary style={{ cursor: 'pointer' }}>Details</summary>
                <dl style={{ margin: '4px 0 0', overflowWrap: 'anywhere' }}>{Object.entries(row.details).map(([key, value]) => <div key={key}><dt style={{ display: 'inline', fontWeight: 600 }}>{key}: </dt><dd style={{ display: 'inline', margin: 0 }}>{value}</dd></div>)}</dl>
              </details>}
            </div>
            <div className="ds-mono" style={{ fontSize: 12, color: 'var(--ink-2)', overflowWrap: 'anywhere' }}>{row.target}</div>
            <div style={{ fontSize: 12, color: 'var(--ink-3)' }}><Timestamp value={row.occurredAt} /></div>
          </div>)}
        </div>
      </div>}
      {logs.hasNextPage && !logs.isFetchNextPageError && <div style={{ marginTop: 14 }}><Button variant="outlined" size="sm" disabled={logs.isFetchingNextPage} onClick={() => void logs.fetchNextPage()}>{logs.isFetchingNextPage ? 'Loading more…' : 'Load more'}</Button></div>}
    </>}
  </Box>
}
