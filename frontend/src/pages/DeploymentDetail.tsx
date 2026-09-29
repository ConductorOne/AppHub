import { useEffect, useRef, useState } from 'react'
import { Alert, Box, Stack, Typography } from '@mui/material'
import { useParams } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { useDeployment } from '../hooks/useDeployments'
import { useApplication, useFinishDeletion } from '../hooks/useApplications'
import { isNotFound } from '../services/api'
import DeploymentStatus from '../components/DeploymentStatus'
import SubmitDeployment from '../components/SubmitDeployment'
import { AppBrowseLinks, Failure, Loading } from '../components/Feedback'
import { Avatar } from '../design/Avatar'
import { Button } from '../design/Button'
import { Chip } from '../design/Chip'

type LogLine = { t: string; text: string; color: string }

function stamp() {
  const d = new Date()
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

/** Builds a real-time log from actual step/progress/message transitions — never scripted or fabricated. */
function useDerivedLog(deployment?: { step?: string; progress?: string; message?: string; state?: string; terminal?: boolean }) {
  const [lines, setLines] = useState<LogLine[]>([])
  const last = useRef<string>('')
  useEffect(() => {
    if (!deployment) return
    const marker = [deployment.step, deployment.progress, deployment.terminal ? deployment.message : ''].join('|')
    if (marker === last.current) return
    last.current = marker
    const color = deployment.state === 'failed' ? '#FF9985' : deployment.state === 'interrupted' ? 'var(--warn-soft)' : '#F0F1F2'
    const text = deployment.terminal ? (deployment.message || deployment.state) : (deployment.progress || deployment.step || 'Working…')
    if (text) setLines(current => [...current, { t: stamp(), text: String(text), color }])
  }, [deployment])
  return lines
}

export default function DeploymentDetail() {
  const { id = '', deploymentId = '' } = useParams()
  const query = useDeployment(deploymentId)
  const app = useApplication(id)
  const client = useQueryClient()
  const log = useDerivedLog(query.data)
  const teardown = query.data?.operation === 'teardown'
  const finishDeletion = useFinishDeletion()
  const deletedName = teardown && isNotFound(query.error) ? app.data?.specification.name ?? 'The application' : ''
  useEffect(() => { if (deletedName) finishDeletion(deletedName) }, [deletedName, finishDeletion])
  useEffect(() => { if (query.data?.terminal) { void client.invalidateQueries({ queryKey: ['application', id] }); void client.invalidateQueries({ queryKey: ['applications'] }); void client.invalidateQueries({ queryKey: ['deployments', id] }) } }, [query.data?.terminal, id, client])

  return <Box sx={{ p: '28px 32px 56px', maxWidth: 1000, mx: 'auto' }}>
    <Button variant="text" to={`/applications/${id}`} style={{ marginBottom: 14 }}>← Application</Button>
    <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
      <Avatar name={app.data?.specification.name || id} size={36} radius={8} />
      <div style={{ flex: 1, minWidth: 180 }}>
        <Typography sx={{ fontFamily: "'Anybody', sans-serif", fontSize: 24, fontWeight: 600, letterSpacing: '-0.015em' }}>{app.data?.specification.name || 'Deployment'}</Typography>
        <div className="ds-mono break-text" style={{ fontSize: 12.5, color: 'var(--ink-3)' }}>{teardown && <Chip tone="warning" size="extraSmall" style={{ marginRight: 8 }}>Deletion</Chip>}{deploymentId}</div>
      </div>
      {query.data && <Chip tone={query.data.state === 'succeeded' ? 'success' : query.data.state === 'failed' ? 'error' : query.data.state === 'interrupted' ? 'warning' : 'teal'} dot size="medium">{query.data.state}</Chip>}
    </div>

    {query.isPending ? <Loading label="Loading durable deployment state…" /> : deletedName ? <Loading label="Finishing deletion…" /> : query.error ? <Failure error={query.error} retry={() => void query.refetch()} /> : query.data?.applicationId !== id ? <Alert severity="error" sx={{ mt: 3 }}>This operation does not belong to the application in this URL.</Alert> : <Stack spacing={2.5} sx={{ mt: 3 }}>
      {log.length > 0 && <div style={{ border: '1px solid var(--line)', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 14px', background: 'var(--bg-1)', borderBottom: '1px solid var(--line)' }}>
          <span style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)', flex: 1 }}>Operation log</span>
        </div>
        <div className="ds-mono" style={{ background: '#231F20', padding: '14px 16px', maxHeight: 300, overflowY: 'auto', fontSize: 12, lineHeight: 1.75 }}>
          {log.map((l, i) => <div key={i} style={{ display: 'flex', gap: 14 }}><span style={{ color: 'var(--ink-3)', flexShrink: 0 }}>{l.t}</span><span style={{ color: l.color, wordBreak: 'break-word' }}>{l.text}</span></div>)}
          {!query.data.terminal && <div style={{ display: 'flex', gap: 14 }}><span style={{ color: 'var(--ink-3)' }}>&nbsp;</span><span style={{ color: '#5DC05D', animation: 'ah-blink 1s infinite' }}>▊</span></div>}
        </div>
        <style>{'@keyframes ah-blink { 0%, 100% { opacity: .3; } 50% { opacity: 1; } }'}</style>
      </div>}

      <DeploymentStatus deployment={query.data} />

      {query.data.state === 'succeeded' && !teardown && app.data && <div style={{ border: '1px solid var(--ok-line)', background: 'var(--ok-tint)', borderRadius: 8, padding: '16px 18px', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 180 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--ok-ink)' }}>Deployed</div>
          <AppBrowseLinks addresses={query.data.addresses} />
        </div>
        <Button to={`/applications/${id}`}>Open application</Button>
      </div>}

      {query.data.state === 'failed' && teardown && <Alert severity="info">Retry the deletion from the application page. Retrying is safe: resources that are already deleted are skipped.<Button to={`/applications/${id}`} style={{ marginTop: 8 }}>Open application</Button></Alert>}
      {query.data.state === 'failed' && !teardown && app.data && !app.error && <><Alert severity="info">Review the failure and edit the application if needed. A new deployment is a new operation, not a resume from the failed step.</Alert><SubmitDeployment application={app.data} /></>}
      {query.data.state === 'interrupted' && <Button variant="outlined" onClick={() => void query.refetch()}>Refresh operator resolution</Button>}
    </Stack>}
  </Box>
}
