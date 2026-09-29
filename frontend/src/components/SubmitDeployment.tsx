import { Alert, Button, Stack, Typography } from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { apiPath, request, segment, uncertain } from '../services/api'
import { clearOperation, loadOperation, retainOperation } from '../services/operations'
import type { Accepted, Application } from '../services/types'
import { Failure } from './Feedback'
export async function submitDeployment(application: Application) {
  const slot = `deploy.${application.id}`
  const operation = retainOperation(slot, { applicationRevision: application.revision })
  try {
    const accepted = await request<Accepted>(apiPath(`/applications/${segment(application.id)}/deployments`), { method: 'POST', body: operation.input, headers: { 'Idempotency-Key': operation.key } })
    clearOperation(slot)
    return accepted
  } catch (error) { if (!uncertain(error)) clearOperation(slot); throw error }
}
/** Submission state shared by the full SubmitDeployment block and compact triggers such as a header button. */
export function useSubmitDeployment(application: Application) {
  const client = useQueryClient()
  const navigate = useNavigate()
  const mutation = useMutation({ mutationFn: () => submitDeployment(application), onSuccess: accepted => {
    void client.invalidateQueries({ queryKey: ['application', application.id] }); void client.invalidateQueries({ queryKey: ['applications'] }); void client.invalidateQueries({ queryKey: ['deployments', application.id] })
    navigate(`/applications/${application.id}/deployments/${accepted.deploymentId}`)
  } })
  const pending = loadOperation<{ applicationRevision: number }>(`deploy.${application.id}`)
  const disabled = !!application.activeDeploymentId || mutation.isPending || !application.permittedActions.includes('deployments:write')
  const label = mutation.isPending ? 'Submitting…' : pending ? 'Retry original submission' : 'Start new deployment'
  return { mutation, pending, disabled, label }
}
/** Error and uncertain-retry notices for a submission; render next to any compact trigger. */
export function SubmitDeploymentNotices({ application, submit }: { application: Application; submit: ReturnType<typeof useSubmitDeployment> }) {
  if (!submit.mutation.error && !submit.pending) return null
  return <Stack spacing={2}>{submit.mutation.error && <Failure error={submit.mutation.error} />}{submit.pending && <Alert severity="warning">A previous submission may have been accepted. Retry uses the same revision and key, never a new operation.<Typography className="break-text" variant="caption" component="div">Application: {application.id}<br />Idempotency key: {submit.pending.key}</Typography></Alert>}</Stack>
}
export default function SubmitDeployment({ application }: { application: Application }) {
  const submit = useSubmitDeployment(application)
  return <Stack spacing={2}><SubmitDeploymentNotices application={application} submit={submit} /><Button variant="contained" disabled={submit.disabled} onClick={() => submit.mutation.mutate()}>{submit.label}</Button></Stack>
}
