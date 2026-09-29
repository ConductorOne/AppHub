import { Alert, Box, Typography } from '@mui/material'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { useApplications } from '../hooks/useApplications'
import { Failure, Loading } from '../components/Feedback'
import { Avatar } from '../design/Avatar'
import { Chip } from '../design/Chip'
import { PreviewChip, PreviewNote } from '../design/Preview'
import { simulatedVulnPackages } from '../design/simulated'

export default function Vulnerabilities() {
  const auth = useAuth()
  // Cross-application visibility: a Workspace admin already sees everything
  // else, and a vuln admin sees this one surface across every application
  // without needing the broader role. Neither implies the other's scope.
  const seesEverything = auth.data?.role === 'admin' || !!auth.data?.vulnAdmin
  const query = useApplications(seesEverything)
  const navigate = useNavigate()

  if (auth.isPending) return <Box sx={{ p: 4 }}><Loading label="Loading…" /></Box>
  if (!auth.data?.enabledFeatures.includes('vulnerabilities')) {
    return <Box sx={{ p: 4 }}><Alert severity="warning">Vulnerability scanning is not enabled for your identity.</Alert></Box>
  }

  const apps = query.data?.pages.flatMap(page => page.items) || []

  const rows = apps.flatMap(app => simulatedVulnPackages(app.id).flatMap(p => p.advisories.map(a => ({
    appId: app.id, appName: app.specification.name, pkg: `${p.name} ${p.current}`, severity: a.severity, tone: a.tone, title: a.title,
  }))))
  rows.sort((a, b) => (a.tone === 'error' ? 0 : 1) - (b.tone === 'error' ? 0 : 1))

  return <Box sx={{ p: '24px 32px 56px' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
      <Typography sx={{ fontFamily: "'Anybody', sans-serif", fontSize: 28, fontWeight: 600, letterSpacing: '-0.02em' }}>Vulnerabilities</Typography>
      <PreviewChip />
    </div>
    <Typography sx={{ fontSize: 13, color: 'var(--ink-2)', mb: 2 }}>{seesEverything ? 'Across every application in this workspace.' : 'Across the applications you own.'}</Typography>
    <Box sx={{ maxWidth: 900, mb: 2 }}><PreviewNote>Vulnerability scanning isn't connected yet — this list is illustrative, seeded per application, not a real scan result.</PreviewNote></Box>

    {query.isPending ? <Loading label="Loading applications…" /> : query.error ? <Failure error={query.error} retry={() => void query.refetch()} /> : rows.length === 0 ? (
      <div style={{ border: '1px dashed var(--line-emph)', borderRadius: 8, padding: 44, textAlign: 'center', maxWidth: 900 }}>
        <div style={{ fontSize: 14, fontWeight: 600 }}>Nothing to show</div>
        <div style={{ fontSize: 12.5, color: 'var(--ink-2)', marginTop: 3 }}>{seesEverything ? 'No applications yet.' : 'You do not own any applications yet.'}</div>
      </div>
    ) : <div style={{ border: '1px solid var(--line)', borderRadius: 8, overflow: 'hidden', maxWidth: 900 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(110px,1fr) minmax(120px,1.2fr) minmax(0,88px) minmax(0,1.4fr)', gap: 14, padding: '9px 16px', background: 'var(--bg-1)', borderBottom: '1px solid var(--line)', fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }}>
        <div>Application</div><div>Package</div><div>Severity</div><div>Advisory</div>
      </div>
      {rows.map((r, i) => <div key={i} onClick={() => navigate(`/applications/${r.appId}`)} style={{ display: 'grid', gridTemplateColumns: 'minmax(110px,1fr) minmax(120px,1.2fr) minmax(0,88px) minmax(0,1.4fr)', gap: 14, padding: '12px 16px', borderBottom: '1px solid var(--bg-2)', alignItems: 'center', cursor: 'pointer' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, minWidth: 0 }}>
          <Avatar name={r.appName} size={22} radius={6} />
          <span style={{ fontSize: 12.5, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.appName}</span>
        </div>
        <div className="ds-mono" style={{ fontSize: 12.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.pkg}</div>
        <div><Chip tone={r.tone} size="extraSmall">{r.severity}</Chip></div>
        <div style={{ fontSize: 12.5, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.title}</div>
      </div>)}
    </div>}
  </Box>
}
