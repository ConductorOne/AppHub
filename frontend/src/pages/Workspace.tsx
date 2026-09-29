import { useEffect, useMemo, useState } from 'react'
import { Alert, Autocomplete, Box, Chip as MuiChip, MenuItem, Stack, TextField, ToggleButton, ToggleButtonGroup, Typography } from '@mui/material'
import { Link, useSearchParams } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { useApplications, useTargets } from '../hooks/useApplications'
import { useDeleteRoleMapping, useDirectoryEntitlements, useForgetInstallation, useFeatureFlags, useGitHubAppStatus, useLogGroups, useLogs, useMembers, useRoleMappings, useSetFeatureFlag, useSetGitHubAppConfig, useSetRoleMapping, useStartGitHubAppManifest } from '../hooks/useWorkspace'
import { ApiError } from '../services/api'
import type { DirectoryEntitlement, FeatureFlagMode, GitHubAppConfigInput, Member, Role, Target } from '../services/types'
import { Failure, Loading, Timestamp } from '../components/Feedback'
import { Avatar } from '../design/Avatar'
import { Button } from '../design/Button'
import { Chip } from '../design/Chip'
import { Icon } from '../design/Icon'
import { PreviewChip, PreviewNote } from '../design/Preview'
import { SIMULATED_LOG_GROUPS, simulatedSystemLogs } from '../design/simulated'
import { needsAttention, relativeTime, STATUS_META } from '../design/status'
import { AuditLogTab } from './AuditLogTab'

const MASKED = 'MASKED:****'

type Tab = 'overview' | 'members' | 'roles' | 'flags' | 'github-app' | 'infrastructure' | 'logs' | 'audit'
const TABS: { key: Tab; label: string }[] = [
  { key: 'overview', label: 'Overview' }, { key: 'members', label: 'Members' }, { key: 'roles', label: 'Role assignment' },
  { key: 'flags', label: 'Feature flags' }, { key: 'github-app', label: 'GitHub' }, { key: 'infrastructure', label: 'Infrastructure' },
  { key: 'logs', label: 'System logs' }, { key: 'audit', label: 'Audit log' },
]

function StatCard({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return <div style={{ border: `1px solid ${warn ? 'var(--warn-line)' : 'var(--line)'}`, background: warn ? 'var(--warn-tint)' : 'var(--bg-0)', borderRadius: 8, padding: '13px 15px' }}>
    <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: warn ? 'var(--warn-ink)' : 'var(--ink-2)' }}>{label}</div>
    <div style={{ fontFamily: "'Anybody', sans-serif", fontSize: 24, fontWeight: 600, letterSpacing: '-0.015em', marginTop: 6, color: warn ? 'var(--warn-ink)' : 'var(--ink)' }}>{value}</div>
  </div>
}

function OverviewTab() {
  const applications = useApplications(true)
  const targets = useTargets()
  if (applications.isPending || targets.isPending) return <Loading label="Loading workspace overview…" />
  if (applications.error) return <Failure error={applications.error} retry={() => void applications.refetch()} />
  const apps = applications.data?.pages.flatMap(page => page.items) || []
  const attention = apps.filter(a => needsAttention(a.status))

  return <Box sx={{ maxWidth: 900 }}>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px,1fr))', gap: 12, marginBottom: 24 }}>
      <StatCard label="Applications" value={String(apps.length)} />
      <StatCard label="Live" value={String(apps.filter(a => a.status === 'running').length)} />
      <StatCard label="Needs attention" value={String(attention.length)} warn={attention.length > 0} />
      <StatCard label="Deploy targets" value={String(targets.data?.length ?? 0)} />
    </div>
    <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 10 }}>Needs attention</div>
    {attention.length === 0 ? <div style={{ fontSize: 12.5, color: 'var(--ink-2)' }}>Nothing needs attention right now.</div> : <Stack spacing={1}>
      {attention.map(app => {
        const meta = STATUS_META[app.status]
        return <Link key={app.id} to={`/applications/${app.id}`} style={{ display: 'flex', alignItems: 'center', gap: 12, border: '1px solid var(--line)', borderRadius: 8, padding: '11px 14px', textDecoration: 'none', color: 'inherit' }}>
          <Avatar name={app.specification.name} size={26} radius={7} />
          <span style={{ flex: 1, fontSize: 13, fontWeight: 600 }}>{app.specification.name}</span>
          <Chip tone={meta.tone} dot>{meta.label}</Chip>
          <Icon name="chevron-right" size={14} color="var(--ink-4)" />
        </Link>
      })}
    </Stack>}
  </Box>
}

const MEMBER_GRID = 'minmax(180px,2fr) minmax(0,170px) minmax(0,100px) minmax(0,120px)'
const MEMBER_ROLE_LABEL: Record<Member['role'], string> = { admin: 'Workspace admin', 'app-owner': 'App owner', member: 'Member' }
const MEMBER_ROLE_TONE: Record<Member['role'], 'teal' | 'default' | 'muted'> = { admin: 'teal', 'app-owner': 'default', member: 'muted' }

const MEMBER_ROLE_CARDS: { role: string; can: string[]; cannot: string[] }[] = [
  { role: 'Member', can: ['View applications and their status', 'View their own activity'],
    cannot: ['Create or edit applications', 'See vulnerability findings', 'Change workspace settings'] },
  { role: 'Application owner', can: ['Everything a member can', 'Edit and redeploy applications they own', 'See findings for applications they own'],
    cannot: ['See findings for applications they don’t own', 'Change workspace settings'] },
  { role: 'Workspace admin', can: ['Everything an application owner can, for every application', 'Manage the GitHub App and deploy targets', 'View platform logs'], cannot: [] },
]

function MembersTab() {
  const members = useMembers()
  if (members.isPending) return <Loading label="Loading members…" />
  if (members.error) return <Failure error={members.error} retry={() => void members.refetch()} />
  const rows = members.data || []

  return <Box sx={{ maxWidth: 900 }}>
    <Typography sx={{ fontSize: 15, fontWeight: 600, mb: 0.5 }}>Members</Typography>
    <Typography sx={{ fontSize: 12.5, color: 'var(--ink-2)', mb: 2 }}>
      {rows.length} {rows.length === 1 ? 'person has' : 'people have'} signed in. There is no invite flow — an account
      is created the first time an admitted identity signs in. Map a role to a directory group on the Role assignment tab.
    </Typography>
    {!rows.length
      ? <Alert severity="info">No one has signed in yet.</Alert>
      : <div style={{ border: '1px solid var(--line)', borderRadius: 8, overflow: 'hidden', marginBottom: 24 }}>
          <div style={{ display: 'grid', gridTemplateColumns: MEMBER_GRID, gap: 14, padding: '9px 16px', background: 'var(--bg-1)', borderBottom: '1px solid var(--line)', fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }}>
            <div>Member</div><div>Role</div><div>Status</div><div>Last active</div>
          </div>
          {rows.map((m, i) => <div key={m.id} style={{ display: 'grid', gridTemplateColumns: MEMBER_GRID, gap: 14, padding: '11px 16px', borderBottom: i < rows.length - 1 ? '1px solid var(--bg-2)' : 0, alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9, minWidth: 0 }}>
              <Avatar name={m.name || m.email} size={26} radius={20} />
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 12.5, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.name || m.email}</div>
                <div style={{ fontSize: 11, color: 'var(--ink-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.email}</div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
              <Chip tone={MEMBER_ROLE_TONE[m.role]} size="extraSmall">{MEMBER_ROLE_LABEL[m.role]}</Chip>
              {m.vulnAdmin && <Chip tone="warning" size="extraSmall">Vuln admin</Chip>}
            </div>
            <div><Chip tone={m.disabled ? 'error' : 'success'} size="extraSmall" dot>{m.disabled ? 'Disabled' : 'Active'}</Chip></div>
            <div style={{ fontSize: 12, color: 'var(--ink-3)' }}>{relativeTime(m.lastSeenAt)}</div>
          </div>)}
        </div>}

    <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 10 }}>What each role can do</div>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px,1fr))', gap: 12 }}>
      {MEMBER_ROLE_CARDS.map(c => <div key={c.role} style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '13px 15px' }}>
        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>{c.role}</div>
        <Stack spacing={0.75}>
          {c.can.map(item => <div key={item} style={{ display: 'flex', alignItems: 'flex-start', gap: 7, fontSize: 12, color: 'var(--ink-1)' }}><Icon name="check" size={13} color="var(--ok)" style={{ marginTop: 2, flexShrink: 0 }} />{item}</div>)}
          {c.cannot.map(item => <div key={item} style={{ display: 'flex', alignItems: 'flex-start', gap: 7, fontSize: 12, color: 'var(--ink-4)' }}><Icon name="x" size={13} color="var(--line-emph)" style={{ marginTop: 2, flexShrink: 0 }} />{item}</div>)}
        </Stack>
      </div>)}
    </div>
  </Box>
}

const ASSIGNABLE_ROLES: { value: Role; label: string; hint: string }[] = [
  { value: 'member', label: 'Member', hint: 'Least privilege. Everyone admitted to AppHub starts here.' },
  { value: 'app-owner', label: 'App owner', hint: 'Create and manage applications they own.' },
  { value: 'admin', label: 'Workspace admin', hint: 'Manage the workspace, GitHub App, and deploy targets.' },
  { value: 'vuln-admin', label: 'Vulnerability admin', hint: 'See vulnerability findings across applications, alongside their member / app-owner / admin role.' },
]

const GROUP_SELECT_SX = {
  '& .MuiInputBase-root': { fontSize: 13 },
  '& .MuiInputLabel-root': { fontSize: 13 },
  '& .MuiFormHelperText-root': { fontSize: 11.5 },
  '& .MuiChip-root': { height: 22 },
  '& .MuiChip-label': { fontSize: 12, px: 0.75 },
}

const GROUP_SELECT_SLOTS = {
  paper: { sx: { fontSize: 13 } },
  listbox: { sx: { py: 0.5, '& .MuiAutocomplete-option': { fontSize: 13, minHeight: 32, py: 0.5 } } },
} as const

function RoleAssignmentTab() {
  const entitlements = useDirectoryEntitlements()
  const mappings = useRoleMappings()
  const setMapping = useSetRoleMapping()
  const deleteMapping = useDeleteRoleMapping()
  const [savingRole, setSavingRole] = useState<Role | null>(null)

  if (entitlements.isPending || mappings.isPending) return <Loading label="Loading ConductorOne groups…" />
  if (entitlements.error) return <Failure error={entitlements.error} retry={() => void entitlements.refetch()} />
  if (mappings.error) return <Failure error={mappings.error} retry={() => void mappings.refetch()} />

  const groups = entitlements.data || []
  const assigned = mappings.data || []
  const groupById = new Map(groups.map(g => [g.id, g]))
  const roleByGroup = new Map(assigned.map(m => [m.entitlementId, m.role]))
  const pending = savingRole !== null || setMapping.isPending || deleteMapping.isPending

  function groupOption(id: string, fallbackName?: string): DirectoryEntitlement {
    return groupById.get(id) || { id, displayName: fallbackName || id, bindable: true, syncedAt: '' }
  }

  function selectedFor(role: Role): DirectoryEntitlement[] {
    return assigned.filter(m => m.role === role).map(m => groupOption(m.entitlementId, m.displayName))
  }

  async function setGroups(role: Role, next: DirectoryEntitlement[]) {
    const nextIds = new Set(next.map(g => g.id))
    const currentIds = new Set(assigned.filter(m => m.role === role).map(m => m.entitlementId))
    setSavingRole(role)
    try {
      for (const id of currentIds) {
        if (!nextIds.has(id)) await deleteMapping.mutateAsync(id)
      }
      for (const id of nextIds) {
        if (!currentIds.has(id)) await setMapping.mutateAsync({ entitlementId: id, input: { role } })
      }
    } finally {
      setSavingRole(null)
    }
  }

  return <Box sx={{ maxWidth: 980 }}>
    <Typography sx={{ fontSize: 15, fontWeight: 600, mb: 0.5 }}>Role assignment</Typography>
    <Typography sx={{ fontSize: 12.5, color: 'var(--ink-2)', mb: 2 }}>
      Assign ConductorOne groups to each AppHub role. A group maps to one role; assigning it here moves it if it was
      on another. Membership is fetched at sign-in and cached for a few minutes. AppHub does not grant or request
      access in ConductorOne itself.
    </Typography>
    {!groups.length && <Alert severity="info" sx={{ mb: 2 }}>No ConductorOne groups have been synced yet. <code className="ds-mono">APPHUB_C1_DIRECTORY_*</code> enables login-time group lookup; on loopback, <code className="ds-mono">serve</code> runs that loop — restart it after setting the variables, wait a few seconds, then refresh.</Alert>}
    {setMapping.error && <Failure error={setMapping.error} />}
    {deleteMapping.error && <Failure error={deleteMapping.error} />}
    <div style={{ border: '1px solid var(--line)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(180px,220px) minmax(0,1fr)', gap: 14, padding: '9px 16px', background: 'var(--bg-1)', borderBottom: '1px solid var(--line)', fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }}>
        <div>Role</div><div>Groups</div>
      </div>
      {ASSIGNABLE_ROLES.map((r, i) => (
        <div key={r.value} style={{ display: 'grid', gridTemplateColumns: 'minmax(180px,220px) minmax(0,1fr)', gap: 14, padding: '14px 16px', borderBottom: i < ASSIGNABLE_ROLES.length - 1 ? '1px solid var(--bg-2)' : 0, alignItems: 'start' }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600 }}>{r.label}</div>
            <div style={{ fontSize: 11.5, color: 'var(--ink-3)', marginTop: 4, lineHeight: 1.4 }}>{r.hint}</div>
          </div>
          <Autocomplete
            multiple
            disableCloseOnSelect
            disabled={pending || !groups.length}
            options={groups}
            value={selectedFor(r.value)}
            isOptionEqualToValue={(a, b) => a.id === b.id}
            getOptionLabel={g => {
              const mapped = roleByGroup.get(g.id)
              if (mapped && mapped !== r.value) {
                const other = ASSIGNABLE_ROLES.find(x => x.value === mapped)
                return `${g.displayName} (${other?.label || mapped})`
              }
              return g.displayName
            }}
            onChange={(_, value) => { void setGroups(r.value, value) }}
            sx={GROUP_SELECT_SX}
            slotProps={GROUP_SELECT_SLOTS}
            renderValue={(value, getItemProps) => value.map((g, index) => {
              const { key, ...itemProps } = getItemProps({ index })
              return <MuiChip {...itemProps} key={key} size="small" label={g.displayName} />
            })}
            renderInput={params => <TextField {...params} size="small" placeholder={groups.length ? 'Select groups' : 'No groups synced'} />}
          />
        </div>
      ))}
    </div>
  </Box>
}

// FEATURE_FLAG_INFO supplies display copy and supported modes for known flag
// keys. A key with no entry here falls back to its raw API key and every mode
// the API supports.
type FeatureFlagInfo = {
  label: string
  desc: string
  offDesc?: string
  modes?: readonly FeatureFlagMode[]
  privateBeta?: boolean
}

const FEATURE_FLAG_INFO: Record<string, FeatureFlagInfo> = {
  vulnerabilities: { label: 'Vulnerabilities', desc: 'The Vulnerabilities page and nav link, and everything vulnerability-related.' },
  'provision-application-catalog': {
    label: 'C1 application creation',
    desc: 'Opt in to create or reconcile a C1 application after a successful deployment. Requires a configured C1 integration.',
    offDesc: 'No C1 application is created after a successful deployment.',
    modes: ['off', 'on'],
  },
  'provision-shortlink': {
    label: 'ShortLink creation',
    desc: 'Opt in to create or reconcile a ShortLink after a successful deployment. Uses the exact application name as its alias, which must be a lowercase route without spaces. Requires a configured C1 integration and published HTTPS URL.',
    offDesc: 'No ShortLink is created after a successful deployment.',
    modes: ['off', 'on'],
    privateBeta: true,
  },
}

const FLAG_MODE_OPTIONS: { value: FeatureFlagMode; label: string }[] = [
  { value: 'off', label: 'Off' },
  { value: 'group', label: 'Groups' },
  { value: 'on', label: 'On' },
]

function FeatureFlagsTab() {
  const flags = useFeatureFlags()
  const entitlements = useDirectoryEntitlements()
  const setFlag = useSetFeatureFlag()
  const [picking, setPicking] = useState<string | null>(null)

  if (flags.isPending || entitlements.isPending) return <Loading label="Loading feature flags…" />
  if (flags.error) return <Failure error={flags.error} retry={() => void flags.refetch()} />
  if (entitlements.error) return <Failure error={entitlements.error} retry={() => void entitlements.refetch()} />
  const groups = (entitlements.data || []).filter(e => e.bindable)
  const rows = flags.data || []
  const on = rows.filter(f => f.mode === 'on').length
  const grouped = rows.filter(f => f.mode === 'group').length

  function setMode(key: string, mode: FeatureFlagMode) {
    if (mode === 'group') { setPicking(key); return }
    setPicking(null)
    setFlag.mutate({ key, input: { mode } })
  }
  function setGroups(key: string, next: DirectoryEntitlement[]) {
    if (next.length === 0) {
      setPicking(null)
      setFlag.mutate({ key, input: { mode: 'off' } })
      return
    }
    setPicking(null)
    setFlag.mutate({ key, input: { mode: 'group', groupEntitlementIds: next.map(g => g.id) } })
  }

  return <Box sx={{ maxWidth: 860 }}>
    <Typography sx={{ fontSize: 15, fontWeight: 600, mb: 0.5 }}>Feature flags</Typography>
    <Typography sx={{ fontSize: 12.5, color: 'var(--ink-2)', mb: 2 }}>{on} on · {grouped} group-limited · {rows.length - on - grouped} off</Typography>
    {setFlag.error && <Failure error={setFlag.error} />}
    <Stack spacing={1.25}>
      {rows.map(f => {
        const info: FeatureFlagInfo = FEATURE_FLAG_INFO[f.key] || { label: f.key, desc: '' }
        const modeOptions = info.modes ? FLAG_MODE_OPTIONS.filter(m => info.modes!.includes(m.value)) : FLAG_MODE_OPTIONS
        const supportsGroups = modeOptions.some(m => m.value === 'group')
        const activeMode = supportsGroups || f.mode !== 'group' ? f.mode : 'off'
        const showPicker = supportsGroups && (picking === f.key || f.mode === 'group')
        const selected = (f.groups || []).map(g => groups.find(x => x.id === g.id) || { id: g.id, displayName: g.displayName || g.id, bindable: true, syncedAt: '' })
        const groupOptions = [...selected.filter(g => !groups.some(x => x.id === g.id)), ...groups]
        return <div key={f.key} style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '13px 15px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 13, fontWeight: 600 }}>{info.label}</span>
                {info.privateBeta && <Chip tone="muted" size="extraSmall">Private Beta</Chip>}
              </div>
              {info.desc && <div style={{ fontSize: 12, color: 'var(--ink-2)', marginTop: 2 }}>{info.desc}</div>}
            </div>
            <div role="group" aria-label={`${info.label} setting`} style={{ display: 'flex', border: '1px solid var(--line)', borderRadius: 6, overflow: 'hidden', flexShrink: 0, marginLeft: 'auto' }}>
              {modeOptions.map(m => {
                const groupUnavailable = m.value === 'group' && groups.length === 0
                const selectedMode = activeMode === m.value
                return <button key={m.value} type="button" aria-label={`${info.label}: ${m.label}`} aria-pressed={selectedMode} disabled={setFlag.isPending || groupUnavailable} onClick={() => setMode(f.key, m.value)}
                  title={groupUnavailable ? 'No synced ConductorOne directory groups are available. Configure APPHUB_C1_DIRECTORY_* and sync at least one group first.' : undefined}
                  style={{
                    border: 0, borderLeft: m.value !== 'off' ? '1px solid var(--line)' : 0, background: selectedMode ? 'var(--teal)' : 'var(--bg-0)',
                    color: selectedMode ? 'var(--on-accent)' : groupUnavailable ? 'var(--line-emph)' : 'var(--ink-2)', fontSize: 11.5, fontWeight: 600, padding: '5px 10px',
                    cursor: groupUnavailable ? 'not-allowed' : 'pointer',
                  }}>{m.label}</button>
              })}
            </div>
          </div>
          {showPicker && <Autocomplete
            multiple
            disableCloseOnSelect
            sx={{ mt: 1.5, ...GROUP_SELECT_SX }}
            slotProps={GROUP_SELECT_SLOTS}
            disabled={setFlag.isPending || groups.length === 0}
            options={groupOptions}
            value={selected}
            isOptionEqualToValue={(a, b) => a.id === b.id}
            getOptionLabel={g => g.displayName}
            onChange={(_, value) => setGroups(f.key, value)}
            renderValue={(value, getItemProps) => value.map((g, index) => {
              const { key, ...itemProps } = getItemProps({ index })
              return <MuiChip {...itemProps} key={key} size="small" label={g.displayName} />
            })}
            renderInput={params => <TextField {...params} size="small" label="Limited to groups" placeholder={groups.length ? 'Select groups' : 'No groups synced'} helperText={groups.length === 0 ? 'Configure APPHUB_C1_DIRECTORY_* and sync at least one group first.' : 'Members of any selected ConductorOne group see the feature.'} />}
          />}
          {activeMode === 'off' && <div style={{ fontSize: 11, color: 'var(--ink-4)', marginTop: 8 }}>{info.offDesc || 'Hidden for everyone, including admins.'}</div>}
        </div>
      })}
    </Stack>
  </Box>
}

// submitManifestForm hands off to GitHub's own App Manifest page: a real
// form POST, not a fetch — GitHub answers with an HTML confirmation page,
// not JSON, and the browser must carry the navigation all the way to
// GitHub and back through the callback.
function submitManifestForm(createURL: string, state: string, manifestJSON: string) {
  const form = document.createElement('form')
  form.method = 'POST'
  form.action = `${createURL}?state=${encodeURIComponent(state)}`
  form.style.display = 'none'
  const manifest = document.createElement('input')
  manifest.type = 'hidden'
  manifest.name = 'manifest'
  manifest.value = manifestJSON
  form.appendChild(manifest)
  document.body.appendChild(form)
  form.submit()
}

function CreateGitHubAppCard() {
  const start = useStartGitHubAppManifest()
  const [organization, setOrganization] = useState('')
  function create() {
    start.mutate({ organization: organization.trim() || undefined }, {
      onSuccess: data => submitManifestForm(data.createUrl, data.state, data.manifestJson),
    })
  }
  return <Box>
    <Typography sx={{ fontSize: 15, fontWeight: 600, mb: 0.5 }}>Create via GitHub</Typography>
    <Typography sx={{ fontSize: 12.5, color: 'var(--ink-2)', mb: 2, maxWidth: '72ch' }}>
      Creates the App on GitHub and connects it here automatically — no App ID or private key to copy by hand.
      You'll review and confirm the App on GitHub, then land back on this page.
    </Typography>
    {start.error && <Failure error={start.error} />}
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ alignItems: { sm: 'center' } }}>
      <TextField size="small" label="Organization (optional)" placeholder="your-org" value={organization} onChange={e => setOrganization(e.target.value)} sx={{ minWidth: 200, maxWidth: 280 }} />
      <Button disabled={start.isPending} onClick={create}>{start.isPending ? 'Preparing…' : 'Create GitHub App'}</Button>
    </Stack>
  </Box>
}

function GitHubAppTab() {
  const status = useGitHubAppStatus()
  const setConfig = useSetGitHubAppConfig()
  const forget = useForgetInstallation()
  const [form, setForm] = useState<GitHubAppConfigInput>()

  if (status.isPending) return <Loading label="Loading GitHub App status…" />
  if (status.error) return <Failure error={status.error} retry={() => void status.refetch()} />
  const data = status.data!
  if (!data.available) return <Alert severity="error">The admin-managed GitHub App surface is unavailable on this deployment. This should not happen — contact your operator.</Alert>

  const input = form || { appId: data.appId || 0, apiBaseUrl: data.apiBaseUrl || '', privateKey: data.privateKeyConfigured ? MASKED : '' }
  function patch(value: Partial<GitHubAppConfigInput>) { setForm({ ...input, ...value }) }
  function submit() { setConfig.mutate(input, { onSuccess: () => setForm(undefined) }) }
  const fields = setConfig.error instanceof ApiError ? setConfig.error.fieldErrors : {}

  return <Stack spacing={3.5} sx={{ maxWidth: 900 }}>
    <CreateGitHubAppCard />
    <Box>
      <Typography sx={{ fontSize: 15, fontWeight: 600, mb: 0.5 }}>GitHub App identity</Typography>
      <Typography sx={{ fontSize: 12.5, color: 'var(--ink-2)', mb: 2, maxWidth: '72ch' }}>
        For an already-created App, or a GitHub Enterprise Server instance. The private key is written to durable
        storage and never returned by this page. Leaving the key field showing <code className="ds-mono">{MASKED}</code> keeps the currently stored key.
      </Typography>
      {setConfig.error && <Failure error={setConfig.error} />}
      <div style={{ border: '1px solid var(--line)', borderRadius: 8, padding: 16 }}>
        <Stack spacing={2}>
          <Box className="form-grid">
            <TextField label="App ID" type="number" required value={input.appId || ''} onChange={e => patch({ appId: e.target.value === '' ? 0 : Number(e.target.value) })} error={!!fields.appId} helperText={fields.appId} />
            <TextField label="API base URL" placeholder="https://github.example.com/api/v3" value={input.apiBaseUrl || ''} onChange={e => patch({ apiBaseUrl: e.target.value })} error={!!fields.apiBaseUrl} helperText={fields.apiBaseUrl || 'Leave empty for github.com.'} />
          </Box>
          <TextField label="Private key (PEM)" multiline minRows={4} value={input.privateKey} onChange={e => patch({ privateKey: e.target.value })}
            error={!!fields.privateKey} helperText={fields.privateKey || (data.privateKeyConfigured ? 'A key is stored. Clear this field and save to remove it, or paste a new key to replace it.' : 'Paste the PEM downloaded from the GitHub App settings page.')}
            slotProps={{ htmlInput: { className: 'ds-mono' } }} />
          <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
            <Button disabled={setConfig.isPending || !input.appId} onClick={submit}>{setConfig.isPending ? 'Saving…' : 'Save'}</Button>
            {data.updatedAt && <Typography sx={{ fontSize: 12, color: 'var(--ink-3)' }}>Last updated <Timestamp value={data.updatedAt} />{data.updatedBy ? ` by ${data.updatedBy}` : ''}</Typography>}
          </Stack>
        </Stack>
      </div>
    </Box>

    <Box>
      <Typography sx={{ fontSize: 15, fontWeight: 600, mb: 0.5 }}>Installations</Typography>
      <Typography sx={{ fontSize: 12.5, color: 'var(--ink-2)', mb: 2, maxWidth: '72ch' }}>Synced periodically by the worker. Forgetting an installation only removes the local record — it does not uninstall the app from GitHub, and a still-installed account reappears on the next sync.</Typography>
      {forget.error && <Failure error={forget.error} />}
      {!data.installations.length && <Alert severity="info">No installations have been synced yet.</Alert>}
      <Stack spacing={1.25}>
        {data.installations.map(install => <div key={install.id} style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '14px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
              <Icon name="github" size={18} />
              <div>
                <div style={{ fontSize: 13.5, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8 }}>{install.accountLogin}<Chip size="extraSmall" tone="muted">{install.accountType}</Chip></div>
                <div style={{ fontSize: 12, color: 'var(--ink-2)', marginTop: 2 }}>Repository selection: {install.repositorySelection} · Synced <Timestamp value={install.syncedAt} />{install.suspendedAt && !install.suspendedAt.startsWith('0001-') && ' · Suspended'}</div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
              {install.htmlUrl && <Button variant="outlined" size="sm" onClick={() => window.open(install.htmlUrl, '_blank', 'noopener,noreferrer')}>Configure on GitHub</Button>}
              <Button variant="outlined" color="error" size="sm" disabled={forget.isPending} onClick={() => { if (window.confirm(`Forget installation ${install.accountLogin}?`)) forget.mutate(install.id) }}>Forget</Button>
            </div>
          </div>
          {!!Object.keys(install.permissions).length && <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 10 }}>
            {Object.entries(install.permissions).map(([scope, level]) => <Chip key={scope} size="extraSmall">{scope}: {level}</Chip>)}
          </div>}
        </div>)}
      </Stack>
    </Box>
  </Stack>
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div><div style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }}>{label}</div><div style={{ fontSize: 12.5, marginTop: 3 }}>{value}</div></div>
}

function TargetCard({ target }: { target: Target }) {
  return <div style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '15px 17px' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
      <span style={{ width: 32, height: 32, borderRadius: 7, background: 'var(--teal-tint)', color: 'var(--teal-dark)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}><Icon name="server" size={17} /></span>
      <div style={{ flex: 1, minWidth: 160 }}>
        <div style={{ fontSize: 13.5, fontWeight: 600 }}>{target.label}</div>
        <div className="ds-mono" style={{ fontSize: 11.5, color: 'var(--ink-3)' }}>{target.id}</div>
      </div>
      <Chip tone={target.ready ? 'success' : 'muted'} dot>{target.ready ? 'Ready' : 'Not ready'}</Chip>
    </div>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px,1fr))', gap: 12, marginTop: 14 }}>
      <Fact label="Execution modes" value={target.executionModes.join(', ') || '—'} />
      <Fact label="Resource sizes" value={target.resourceSizes.map(r => `${r.cpu}m/${r.memory}MiB`).join(', ') || '—'} />
      <Fact label="Max replicas" value={String(target.maxReplicas)} />
      <Fact label="Public exposure" value={target.publicExposure ? 'Allowed' : 'Not allowed'} />
      <Fact label="Databases" value={target.databaseKinds.length ? target.databaseKinds.join(', ') : 'None'} />
      <Fact label="Object storage" value={target.bucketKinds.length ? target.bucketKinds.join(', ') : 'None'} />
    </div>
    <div style={{ marginTop: 12 }}>
      <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)', marginBottom: 4 }}>Approved repositories</div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
        {target.repositories.length ? target.repositories.map(r => <span key={r} className="ds-mono" style={{ fontSize: 11.5, background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 4, padding: '2px 7px', color: 'var(--ink-1)' }}>{r}</span>) : <span style={{ fontSize: 12, color: 'var(--ink-4)' }}>GitHub App installations</span>}
      </div>
    </div>
  </div>
}

function InfrastructureTab() {
  const targets = useTargets()
  if (targets.isPending) return <Loading label="Loading deployment targets…" />
  if (targets.error) return <Failure error={targets.error} retry={() => void targets.refetch()} />
  if (!targets.data?.length) return <Alert severity="warning">No deployment targets are enabled. Contact your administrator.</Alert>
  return <Box sx={{ maxWidth: 900 }}>
    <Typography sx={{ fontSize: 15, fontWeight: 600, mb: 0.5 }}>Deploy targets</Typography>
    <Typography sx={{ fontSize: 12.5, color: 'var(--ink-2)', mb: 2 }}>Every application is deployed to exactly one of these operator-configured targets.</Typography>
    <Stack spacing={1.5}>{targets.data.map(t => <TargetCard key={t.id} target={t} />)}</Stack>
  </Box>
}

const RANGES: { label: string; ms: number }[] = [
  { label: '15m', ms: 15 * 60_000 }, { label: '1h', ms: 60 * 60_000 }, { label: '6h', ms: 6 * 60 * 60_000 }, { label: '24h', ms: 24 * 60 * 60_000 },
]

function SystemLogsTab() {
  const groups = useLogGroups()
  const [name, setName] = useState('')
  const [rangeMs, setRangeMs] = useState(RANGES[1]!.ms)
  const [filter, setFilter] = useState('')
  const [applied, setApplied] = useState('')
  const [now, setNow] = useState(() => Date.now())
  const window_ = useMemo(() => ({ start: new Date(now - rangeMs).toISOString(), end: new Date(now).toISOString(), filter: applied }), [now, rangeMs, applied])
  const live = (groups.data?.length ?? 0) > 0
  const groupNames = live ? groups.data! : [...SIMULATED_LOG_GROUPS]
  const active = groupNames.includes(name) ? name : (groupNames[0] || '')
  const logs = useLogs(active, window_, live && !!active)
  const previewEvents = useMemo(() => simulatedSystemLogs(active, now), [active, now])
  const events = live ? (logs.data?.events ?? []) : previewEvents

  if (groups.isPending) return <Loading label="Loading log groups…" />
  if (groups.error) return <Failure error={groups.error} retry={() => void groups.refetch()} />

  return <Stack spacing={2} sx={{ maxWidth: 900 }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <Typography sx={{ fontSize: 15, fontWeight: 600 }}>System logs</Typography>
      {!live && <PreviewChip />}
    </div>
    <Typography sx={{ fontSize: 12.5, color: 'var(--ink-2)' }}>AppHub's own containers, not the apps people deploy. ECS reads these from CloudWatch.</Typography>
    {!live && <PreviewNote>CloudWatch logs aren't available on this deployment — typical of local serve. An ECS deploy tails AppHub's own containers from CloudWatch. These lines are illustrative.</PreviewNote>}
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ alignItems: { sm: 'center' }, opacity: live ? 1 : 0.55 }}>
      <TextField select label="Log group" size="small" fullWidth={false} value={active} onChange={e => setName(e.target.value)} sx={{ minWidth: 180, ...GROUP_SELECT_SX }}>
        {groupNames.map(g => <MenuItem key={g} value={g}>{g}</MenuItem>)}
      </TextField>
      <ToggleButtonGroup size="small" exclusive value={rangeMs} disabled={!live} onChange={(_, value) => { if (value) { setRangeMs(value); setNow(Date.now()) } }}>
        {RANGES.map(r => <ToggleButton key={r.label} value={r.ms}>{r.label}</ToggleButton>)}
      </ToggleButtonGroup>
      <TextField size="small" label="Filter pattern" value={filter} disabled={!live} onChange={e => setFilter(e.target.value)} sx={{ flex: 1, minWidth: 200, ...GROUP_SELECT_SX }}
        onKeyDown={e => { if (live && e.key === 'Enter') { setApplied(filter); setNow(Date.now()) } }} />
      <Button variant="outlined" size="sm" disabled={!live} onClick={() => { setApplied(filter); setNow(Date.now()) }}>Apply</Button>
      <Button variant="text" size="sm" disabled={!live} onClick={() => setNow(Date.now())}>Refresh</Button>
    </Stack>
    {live && logs.error && <Failure error={logs.error} retry={() => void logs.refetch()} />}
    {live && logs.isPending ? <Loading label="Loading logs…" /> : <div style={{ border: '1px solid var(--line)', borderRadius: 8, background: '#231F20', color: '#F0F1F2', padding: 16, maxHeight: 560, overflowY: 'auto', fontFamily: "'Geist Mono', monospace", fontSize: 12.5, opacity: live ? 1 : 0.5 }}>
      {!events.length && <span style={{ color: 'var(--ink-3)' }}>No log events in this window.</span>}
      {events.map((event, i) => <div key={i} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', padding: '2px 0' }}>
        <span style={{ color: 'var(--ink-3)' }}>{event.timestamp ? new Date(event.timestamp).toISOString() : ''}</span>{'  '}{event.message}
      </div>)}
      {live && logs.data?.nextToken && <div style={{ color: 'var(--ink-4)', fontSize: 11.5, marginTop: 6 }}>More events are available — narrow the time range or filter to see them.</div>}
    </div>}
  </Stack>
}

export default function Workspace() {
  const auth = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const [tab, setTab] = useState<Tab>(() => {
    const requested = searchParams.get('tab')
    return TABS.some(t => t.key === requested) ? (requested as Tab) : 'overview'
  })
  // Captured once at mount: the GitHub App Manifest callback lands here with
  // ?manifest=success|error (and ?reason= on error) after a full-page
  // redirect. Read once rather than from searchParams directly, so clearing
  // the query string below doesn't also erase the banner it's meant to show.
  const [manifestBanner] = useState(() => {
    const result = searchParams.get('manifest')
    return result ? { result, reason: searchParams.get('reason') } : null
  })
  useEffect(() => {
    if (manifestBanner) setSearchParams(new URLSearchParams(), { replace: true })
    // Only ever needs to run once, on the redirect landing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (auth.isPending) return <Box sx={{ p: 4 }}><Loading label="Loading…" /></Box>
  if (auth.data?.role !== 'admin') return <Box sx={{ p: 4 }}><Alert severity="warning">Administrator access is required to view the Workspace.</Alert></Box>

  return <Box sx={{ p: '28px 32px 56px' }}>
    <Typography variant="h1" sx={{ mb: 0.5 }}>Workspace</Typography>
    <Typography color="text.secondary" sx={{ mb: 2 }}>Administrator configuration and platform observability. Changes here apply to everyone.</Typography>
    <div style={{ display: 'flex', gap: 2, marginBottom: 24, overflowX: 'auto', borderBottom: '1px solid var(--line)' }}>
      {TABS.map(t => <button key={t.key} type="button" onClick={() => setTab(t.key)} style={{ border: 0, background: 'transparent', cursor: 'pointer', fontFamily: 'inherit', fontSize: 13, fontWeight: 500, padding: '9px 12px', color: tab === t.key ? 'var(--teal)' : 'var(--ink-2)', borderBottom: `2px solid ${tab === t.key ? 'var(--teal)' : 'transparent'}`, whiteSpace: 'nowrap' }}>{t.label}</button>)}
    </div>
    {manifestBanner?.result === 'success' && <Alert severity="success" sx={{ mb: 2 }}>GitHub App created and connected.</Alert>}
    {manifestBanner?.result === 'error' && <Alert severity="error" sx={{ mb: 2 }}>Could not finish creating the GitHub App{manifestBanner.reason ? ` (${manifestBanner.reason})` : ''}. Try again below.</Alert>}
    {tab === 'overview' && <OverviewTab />}
    {tab === 'members' && <MembersTab />}
    {tab === 'roles' && <RoleAssignmentTab />}
    {tab === 'flags' && <FeatureFlagsTab />}
    {tab === 'github-app' && <GitHubAppTab />}
    {tab === 'infrastructure' && <InfrastructureTab />}
    {tab === 'logs' && <SystemLogsTab />}
    {tab === 'audit' && <AuditLogTab />}
  </Box>
}
