import { Alert, AlertTitle, Box, Button, CircularProgress, Stack, Typography } from '@mui/material'
import { Link, useLocation } from 'react-router-dom'
import { ApiError } from '../services/api'
export function Loading({ label = 'Loading…' }: { label?: string }) { return <Stack direction="row" spacing={2} role="status" sx={{ py: 4, alignItems: 'center' }}><CircularProgress size={22} /><span>{label}</span></Stack> }
export function Failure({ error, retry }: { error: unknown; retry?: () => void }) {
  const location = useLocation()
  const problem = error instanceof ApiError ? error : undefined
  return <Alert severity="error" role="alert" sx={{ my: 2 }}>
    <AlertTitle>{problem?.status === 401 ? 'Session expired' : problem?.status === 503 ? 'Service unavailable' : problem?.status === 0 ? 'Connection problem' : 'Request unsuccessful'}</AlertTitle>
    <Typography component="p">{problem?.message || 'Something went wrong. Retry the request.'}</Typography>
    {problem?.requestId && <Typography variant="caption">Request ID: {problem.requestId}</Typography>}
    {Object.entries(problem?.fieldErrors || {}).length > 0 && <Box component="ul">{Object.entries(problem!.fieldErrors).map(([field, message]) => <li key={field}><a href={`#field-${field}`}>{field}: {message}</a></li>)}</Box>}
    {problem?.status === 401 ? <Button component={Link} to={`/login?error=session_expired&return_to=${encodeURIComponent(location.pathname + location.search)}`}>Sign in again</Button> : retry && <Button onClick={retry}>Retry</Button>}
  </Alert>
}
export function httpsAddresses(addresses?: string[]) {
  return (addresses || []).filter(address => { try { const url = new URL(address); return url.protocol === 'https:' && url.hostname !== '' && !url.username && !url.password } catch { return false } })
}
export function AppBrowseLinks({ addresses, stopPropagation = false }: { addresses?: string[]; stopPropagation?: boolean }) {
  const links = httpsAddresses(addresses)
  if (!links.length) return null
  return <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>{links.map(address => <a className="break-text" key={address} href={address} target="_blank" rel="noopener noreferrer" onClick={stopPropagation ? event => event.stopPropagation() : undefined} style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--teal)' }}>Open {address}</a>)}</span>
}
export function TLSAddresses({ addresses }: { addresses: string[] }) {
  if (!httpsAddresses(addresses).length) return null
  return <Stack spacing={0.5}><Typography variant="body2" color="text.secondary">Browse</Typography><AppBrowseLinks addresses={addresses} /></Stack>
}
export function Timestamp({ value }: { value?: string }) { return <>{value && !value.startsWith('0001-') ? new Date(value).toLocaleString() : '—'}</> }
