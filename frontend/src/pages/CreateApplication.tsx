import { useState } from 'react'
import { Alert, Box, Typography } from '@mui/material'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { useTargets } from '../hooks/useApplications'
import { useAuth } from '../hooks/useAuth'
import { request, uncertain } from '../services/api'
import { detectRepository } from '../services/detect'
import { clearOperation, loadOperation, retainOperation } from '../services/operations'
import type { Application, ApplicationInput, Detection, Target } from '../services/types'
import ApplicationForm, { initialInput } from '../components/ApplicationForm'
import RepositoryField, { repositoryHelper, repositoryOptions } from '../components/RepositoryField'
import { submitDeployment } from '../components/SubmitDeployment'
import { Failure, Loading } from '../components/Feedback'
import { Button } from '../design/Button'
import { Icon } from '../design/Icon'
import { PreviewNote } from '../design/Preview'

type Step = 'repo' | 'preparing' | 'configure'

const STEP_LABELS: { key: Step; label: string }[] = [
  { key: 'repo', label: 'Repository' },
  { key: 'preparing', label: 'Prepare' },
  { key: 'configure', label: 'Review and deploy' },
]

function StepHeader({ step, onCancel }: { step: Step; onCancel: () => void }) {
  const index = STEP_LABELS.findIndex(s => s.key === step)
  return <div style={{ padding: '16px 32px', borderBottom: '1px solid var(--line)', display: 'flex', alignItems: 'center', gap: 20 }}>
    <Button variant="text" onClick={onCancel}>Cancel</Button>
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'center', flexWrap: 'wrap' }}>
      {STEP_LABELS.map((s, i) => <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{
          width: 20, height: 20, borderRadius: 20, display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 11, fontWeight: 600, border: `1px solid ${i <= index ? 'var(--teal)' : 'var(--line)'}`,
          background: i < index ? 'var(--teal)' : i === index ? 'var(--teal-tint)' : 'var(--bg-0)',
          color: i < index ? 'var(--on-accent)' : i === index ? 'var(--teal-dark)' : 'var(--ink-4)',
        }}>{i + 1}</span>
        <span style={{ fontSize: 12.5, fontWeight: 500, color: i === index ? 'var(--ink)' : 'var(--ink-3)' }}>{s.label}</span>
      </div>)}
    </div>
    <div style={{ width: 60 }} />
  </div>
}

function RepoStep({ targets, onPick }: { targets: Target[]; onPick: (target: Target, repo: string) => void }) {
  const [targetId, setTargetId] = useState(targets.find(t => t.ready)?.id || targets[0]?.id || '')
  const [typedURL, setTypedURL] = useState('')
  const target = targets.find(t => t.id === targetId)
  const options = repositoryOptions(target)
  return <div style={{ maxWidth: 720, margin: '0 auto', padding: '40px 32px 64px' }}>
    <Typography sx={{ fontFamily: "'Anybody', sans-serif", fontSize: 24, fontWeight: 600, letterSpacing: '-0.015em' }}>Point AppHub at a repository</Typography>
    <Typography sx={{ fontSize: 13.5, color: 'var(--ink-2)', mt: 0.75, mb: 3, maxWidth: '54ch' }}>
      {repositoryHelper(target)}
    </Typography>

    <div style={{ display: 'flex', gap: 6, marginBottom: 14, flexWrap: 'wrap' }}>
      {targets.map(t => {
        const on = t.id === targetId
        return <span key={t.id} onClick={() => { setTargetId(t.id); setTypedURL('') }} style={{ fontSize: 12.5, fontWeight: 500, padding: '6px 11px', borderRadius: 6, cursor: 'pointer', border: `1px solid ${on ? 'var(--teal-line)' : 'var(--line)'}`, background: on ? 'var(--teal-tint)' : 'var(--bg-0)', color: on ? 'var(--teal-dark)' : 'var(--ink-1)' }}>
          {t.label}{!t.ready ? ' — unavailable' : ''}
        </span>
      })}
    </div>

    <RepositoryField label="Source repository" value={typedURL} options={options} onChange={setTypedURL} />
    {!target?.ready && <Alert severity="warning" sx={{ mt: 2 }}>This target has no ready worker. Choose another target.</Alert>}
    <div style={{ marginTop: 12 }}>
      <Button variant="outlined" disabled={!target?.ready || !typedURL.trim()} onClick={() => target && onPick(target, typedURL.trim())}>Set up</Button>
    </div>

    <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, color: 'var(--ink-2)', flexWrap: 'wrap' }}>
      <Icon name="terminal" size={14} />
      <code className="ds-mono" style={{ fontSize: 12, fontWeight: 500, background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 4, padding: '2px 7px', color: 'var(--ink-1)' }}>apphub apps create --file spec.json</code>
    </div>
  </div>
}

function PreparingStep({ repo }: { repo: string }) {
  return <div style={{ maxWidth: 560, margin: '0 auto', padding: '96px 32px', textAlign: 'center' }}>
    <div style={{ width: 38, height: 38, margin: '0 auto 20px', borderRadius: 20, border: '2px solid var(--teal-line-soft)', borderTopColor: 'var(--teal)', animation: 'ah-spin 800ms linear infinite' }} />
    <div style={{ fontSize: 15, fontWeight: 600 }}>Preparing {repo}</div>
    <Typography sx={{ fontSize: 12.5, color: 'var(--ink-2)', mt: 1 }}>Looking for a Dockerfile and reading configuration hints from the repository.</Typography>
  </div>
}

// applyDetection prefills only the low-risk fields a Dockerfile scan can name
// with confidence -- the Dockerfile path and its EXPOSE port. Database and
// bucket choices carry capacity/engine decisions a heuristic scan cannot make
// safely, so a suggestion there is surfaced to the requester as a note, never
// applied automatically; see DetectionNote below.
function applyDetection(base: ApplicationInput, repo: string, detection?: Detection): ApplicationInput {
  const result = detection?.state === 'succeeded' ? detection.result : undefined
  return { ...base, source: { ...base.source, url: repo, dockerfile: result?.dockerfilePath || base.source.dockerfile }, port: result?.suggestedPort || base.port }
}

function DetectionNote({ detection }: { detection?: Detection }) {
  if (!detection) return null
  if (detection.state === 'failed') return <Alert severity="info" sx={{ mb: 2 }}>Automatic repository detection did not complete. Defaults are shown below — review them before deploying.</Alert>
  const result = detection.result
  if (!result) return null
  const hints: string[] = []
  if (result.dockerfilePath) hints.push(`Found ${result.dockerfilePath}${result.suggestedPort ? ` (EXPOSE ${result.suggestedPort})` : ''}.`)
  if (result.dockerfileCandidates && result.dockerfileCandidates.length > 1) hints.push(`${result.dockerfileCandidates.length} Dockerfiles were found; the shallowest was used. Change the path below if this repository needs a different one.`)
  if (result.composePreview) hints.push(`${result.composePreview.path} declares ${result.composePreview.services.length} service(s); only this application's own Dockerfile was used to prefill the form.`)
  if (result.suggestedDatabase) hints.push(`This repository looks like it uses a ${result.suggestedDatabase === 'postgres' ? 'relational (PostgreSQL)' : 'DynamoDB-style key-value'} database${result.databaseReason ? ` (${result.databaseReason})` : ''}. Add it below if this application needs one — it is not selected automatically.`)
  if (!hints.length) return <Alert severity="info" sx={{ mb: 2 }}>No Dockerfile or configuration hints were found in this repository. Defaults are shown below.</Alert>
  return <Alert severity="success" sx={{ mb: 2 }}>{hints.join(' ')}</Alert>
}

export default function CreateApplication() {
  const auth = useAuth()
  const targets = useTargets()
  const client = useQueryClient()
  const navigate = useNavigate()
  const [step, setStep] = useState<Step>('repo')
  const [seed, setSeed] = useState<{ target: Target; repo: string }>()
  const [detection, setDetection] = useState<Detection>()
  const [pending, setPending] = useState(() => loadOperation<ApplicationInput>('create'))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>()

  function pick(target: Target, repo: string) {
    setSeed({ target, repo })
    setDetection(undefined)
    setStep('preparing')
    detectRepository(target.id, repo)
      .then(setDetection)
      .catch(() => undefined) // Advisory only: an undetected repository just keeps platform defaults.
      .finally(() => setStep('configure'))
  }

  async function create(input: ApplicationInput) {
    setBusy(true); setError(undefined)
    let application: Application
    try {
      const operation = retainOperation('create', input)
      setPending(operation)
      application = await request<Application>('/api/v1/applications', { method: 'POST', body: operation.input, headers: { 'Idempotency-Key': operation.key } })
      clearOperation('create'); setPending(undefined)
      client.setQueryData(['application', application.id], application)
      void client.invalidateQueries({ queryKey: ['applications'] })
    } catch (failure) { setError(failure); if (!uncertain(failure)) { clearOperation('create'); setPending(undefined) }; setBusy(false); return }
    try {
      const accepted = await submitDeployment(application)
      void client.invalidateQueries({ queryKey: ['application', application.id] })
      navigate(`/applications/${application.id}/deployments/${accepted.deploymentId}`)
    } catch (failure) {
      navigate(`/applications/${application.id}`, { state: { draftCreated: true, submissionMessage: failure instanceof Error ? failure.message : 'Deployment submission failed.' } })
    }
    setBusy(false)
  }

  if (!auth.data?.permittedActions.includes('applications:write')) return <Box sx={{ p: 4 }}><Alert severity="warning">Your current identity cannot create applications.</Alert></Box>
  if (targets.isPending) return <Box sx={{ p: 4 }}><Loading label="Loading target policy…" /></Box>
  if (targets.error) return <Box sx={{ p: 4 }}><Failure error={targets.error} retry={() => void targets.refetch()} /></Box>
  if (!targets.data?.length) return <Box sx={{ p: 4 }}><Alert severity="warning">No deployment targets are enabled. Contact your administrator.</Alert></Box>

  return <div style={{ animation: 'ah-rise 200ms cubic-bezier(0,0,.2,1)' }}>
    <style>{'@keyframes ah-spin { to { transform: rotate(360deg); } } @keyframes ah-rise { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: none; } }'}</style>
    <StepHeader step={step} onCancel={() => navigate('/applications')} />
    {step === 'repo' && <RepoStep targets={targets.data} onPick={pick} />}
    {step === 'preparing' && seed && <PreparingStep repo={seed.repo} />}
    {step === 'configure' && seed && <Box sx={{ maxWidth: 900, mx: 'auto', p: '28px 32px 56px' }}>
      <PreviewNote>The plan below is your editable configuration — nothing has been created yet.</PreviewNote>
      <Box sx={{ mt: 2 }}>
        <DetectionNote detection={detection} />
        {pending && <Alert severity="warning" sx={{ mb: 2 }}>The previous creation may have succeeded. Retry uses the same request, never a new one.
          <Typography variant="caption" component="div" className="break-text">Creation key: {pending.key}</Typography>
          <Button disabled={busy} onClick={() => void create(pending.input)}>Retry exact creation and deploy</Button>
        </Alert>}
        <ApplicationForm targets={targets.data} initial={applyDetection(initialInput(seed.target), seed.repo, detection)}
          busy={busy} locked={!!pending} error={error} submitLabel="Deploy application" onSubmit={input => void create(input)} />
      </Box>
    </Box>}
  </div>
}
