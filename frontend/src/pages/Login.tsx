import { Alert, Box, Button, Container, Paper, Stack, Typography } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { Navigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { ApiError, request } from '../services/api'
import type { Providers } from '../services/types'
import { BrandLogo, ColorModeToggle } from '../components/Brand'
import { Failure, Loading } from '../components/Feedback'
function safeReturn(value: string | null) {
  if (!value) return '/applications'
  try {
    const decoded = decodeURIComponent(value)
    if (!decoded.startsWith('/') || decoded.startsWith('//') || /[\\\u0000-\u001f\u007f]/.test(decoded)) return '/applications'
    const url = new URL(value, window.location.origin)
    return url.origin === window.location.origin && !url.pathname.startsWith('/login') ? url.pathname + url.search : '/applications'
  } catch { return '/applications' }
}
const errors: Record<string, string> = { admission_denied: 'This verified account is not admitted by your organization. Choose an approved identity or contact your administrator.', invalid_callback: 'The sign-in response was invalid, expired, or already used. Start a new sign-in.', session_expired: 'Your session has expired. Sign in to continue where you left off.', provider_unavailable: 'Your sign-in provider is temporarily unavailable. Retry later; your account has not been treated as anonymous.' }
export default function Login() {
  const [params] = useSearchParams()
  const auth = useAuth()
  const providers = useQuery({ queryKey: ['providers'], queryFn: ({ signal }) => request<Providers>('/api/v1/auth/providers', { signal }) })
  const returnTo = safeReturn(params.get('return_to'))
  if (auth.data && !auth.error && !params.get('error')) return <Navigate replace to={returnTo} />
  const authOutage = auth.error && !(auth.error instanceof ApiError && auth.error.status === 401)
  return <Container maxWidth="sm" sx={{ py: { xs: 5, md: 12 } }}><Stack direction="row" sx={{ justifyContent: 'flex-end', mb: 2 }}><ColorModeToggle /></Stack><Paper variant="outlined" sx={{ p: { xs: 3, md: 5 } }}><Stack spacing={3}><Box><Box sx={{ mb: 3, display: 'flex', justifyContent: 'center' }}><BrandLogo wordmark height={56} /></Box><Typography variant="h1">Your applications.<br />One place to deploy.</Typography><Typography color="text.secondary" sx={{ mt: 2 }}>Sign in with your organization’s approved identity provider.</Typography></Box>{params.get('error') && <Alert severity={params.get('error') === 'session_expired' ? 'info' : 'error'}>{errors[params.get('error')!] || 'Sign-in could not be completed. Start a new attempt.'}</Alert>}{authOutage && <Failure error={auth.error} retry={() => void auth.refetch()} />}{providers.isPending ? <Loading label="Loading sign-in providers…" /> : providers.error ? <Failure error={providers.error} retry={() => void providers.refetch()} /> : !providers.data?.providers.length ? <Alert severity="warning">No sign-in providers are available. Contact your AppHub administrator.</Alert> : providers.data.providers.map(provider => { const url = new URL(provider.loginUrl, window.location.origin); if (url.origin !== window.location.origin) return null; url.searchParams.set('return_to', returnTo); return <Button key={provider.id} variant="outlined" size="large" href={url.pathname + url.search} disabled={!!authOutage}>{provider.kind === 'google' ? 'Continue with Google' : `Continue with ${provider.label}`}</Button> })}<Typography variant="caption" color="text.secondary">Different provider identities are separate accounts, even when their email addresses match.</Typography></Stack></Paper></Container>
}
