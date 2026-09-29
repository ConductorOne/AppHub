import { useState } from 'react'
import { Alert, Box, Button, Paper, Stack, Typography } from '@mui/material'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { apiPath, request, segment } from '../services/api'
import type { Consent } from '../services/types'
import type { components } from '../generated/api'
import { Failure, Loading, Timestamp } from '../components/Feedback'
const scopeLabels: Record<string, string> = { 'applications:read': 'Read applications and deployment target options', 'applications:write': 'Create and change your applications', 'deployments:read': 'Read deployment history and status', 'deployments:write': 'Submit deployments for your applications', 'app:access': 'Access this application’s MCP endpoint as your signed-in identity' }
export default function Authorize() {
  const [params] = useSearchParams()
  const id = params.get('transactionId') || ''
  const [redirecting, setRedirecting] = useState(false)
  const query = useQuery({ queryKey: ['consent', id], enabled: !!id, queryFn: ({ signal }) => request<Consent>(apiPath(`/oauth/consents/${segment(id)}`), { signal }), staleTime: 0 })
  const decision = useMutation({ mutationFn: (action: 'approve' | 'deny') => request<components['schemas']['ConsentDecisionResponse']>('/oauth/authorize', { method: 'POST', body: { transactionId: id, action } }), onSuccess: result => { setRedirecting(true); window.location.assign(result.redirectUrl) } })
  if (!id) return <Alert severity="error">No authorization transaction was supplied. Restart authorization from your CLI or MCP client.</Alert>
  if (query.isPending) return <Loading label="Loading authorization request…" />
  if (query.error) return <Failure error={query.error} retry={() => void query.refetch()} />
  const consent = query.data!
  const expired = Date.parse(consent.expiresAt) <= Date.now()
  return <Stack spacing={3} sx={{ maxWidth: 720, mx: 'auto' }}><Typography variant="h1">Authorize a client</Typography><Paper variant="outlined" sx={{ p: 3 }}><Stack spacing={3}><Typography>Grant this client access to AppHub as your signed-in identity. Ownership and organization policy still apply.</Typography><Box className="break-text"><Typography><strong>Client:</strong> {consent.clientId}</Typography><Typography><strong>Redirect:</strong> {consent.redirectUri}</Typography><Typography><strong>Resource:</strong> {consent.resource}</Typography><Typography><strong>Identity:</strong> {consent.identity.email} via {consent.identity.providerId}</Typography><Typography variant="body2">Subject: {consent.identity.subject}</Typography></Box><Box><Typography variant="h2">Requested access</Typography><ul>{consent.scopes.map(scope => <li key={scope}>{scopeLabels[scope] || scope}</li>)}</ul></Box><Typography variant="body2">Expires: <Timestamp value={consent.expiresAt} /></Typography>{expired && <Alert severity="warning">This authorization request has expired. Restart from your client.</Alert>}{decision.error && <Failure error={decision.error} />}{decision.error && <Alert severity="info">If the response was lost, the one-time transaction may already be consumed. Restart authorization from the client rather than changing this request.</Alert>}<Stack direction="row" spacing={2}><Button variant="contained" disabled={expired || decision.isPending || redirecting} onClick={() => decision.mutate('approve')}>Approve access</Button><Button variant="outlined" disabled={expired || decision.isPending || redirecting} onClick={() => decision.mutate('deny')}>Deny</Button></Stack></Stack></Paper></Stack>
}
