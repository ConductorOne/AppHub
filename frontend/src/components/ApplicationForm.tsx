import { useState, type FormEvent } from 'react'
import { Alert, Box, Button, Checkbox, FormControlLabel, MenuItem, Paper, Stack, TextField, Typography } from '@mui/material'
import type { ApplicationInput, Target } from '../services/types'
import { ApiError } from '../services/api'
import { Failure } from './Feedback'
import { useCategories } from '../hooks/useApplications'
import { CategoryPicker } from '../design/categories'
import RepositoryField, { repositoryHelper, repositoryOptions } from './RepositoryField'
// Keep this set in sync with postgres.AllowedExtensions and DatabaseInput in OpenAPI.
const POSTGRES_EXTENSIONS = ['btree_gin', 'btree_gist', 'citext', 'fuzzystrmatch', 'hstore', 'pg_trgm', 'pgcrypto', 'unaccent', 'uuid-ossp', 'vector'] as const
// Relational defaults, prefilled per engine so a user does not have to know
// what to type. Modeled on the source system's own fixed choices for its
// Aurora Serverless v2 cluster (an "appuser" master account and a 0.5-4 ACU
// range) and mirrored by the backend's own defaulting in
// internal/controlplane/input.go (withRelationalDefaults), so a value left at
// its prefill here and one a caller omits entirely land on the same thing.
// Kept in one place so the database-type and engine pickers below stay in sync.
const RELATIONAL_ENGINE_DEFAULTS: Record<'postgres' | 'mysql', { engineVersion: string; adminUsername: string }> = { postgres: { engineVersion: '18', adminUsername: 'appuser' }, mysql: { engineVersion: '8.0', adminUsername: 'appuser' } }
const DEFAULT_CAPACITY = { minUnits: 0.25, maxUnits: 2 }
// Identifiers RDS refuses as a Postgres cluster's initial database name: two
// reserved for RDS's own internal use and two of PostgreSQL's built-in
// template databases. Kept in sync with reservedDatabaseNames in
// internal/controlplane/input.go.
const RESERVED_DATABASE_NAMES = new Set(['rdsadmin', 'postgres', 'template0', 'template1'])
// defaultDatabaseName mirrors the backend's sanitizeDatabaseName: lowercase
// letters, digits and single underscores, starting with a letter, at most 63
// characters, and never a reserved word. Falls back to "app" when nothing
// survives.
function defaultDatabaseName(appName: string): string {
  let name = appName.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').replace(/^[^a-z]+/, '')
  if (name.length > 63) name = name.slice(0, 63).replace(/_+$/, '')
  return name && !RESERVED_DATABASE_NAMES.has(name) ? name : 'app'
}
function relationalDefaults(engine: 'postgres' | 'mysql', appName: string) { return { ...RELATIONAL_ENGINE_DEFAULTS[engine], databaseName: defaultDatabaseName(appName), capacity: { ...DEFAULT_CAPACITY } } }
type Props = { targets: Target[]; initial?: ApplicationInput; immutableTarget?: boolean; busy?: boolean; locked?: boolean; error?: unknown; submitLabel: string; onSubmit: (input: ApplicationInput) => void }
export function initialInput(target?: Target): ApplicationInput {
  const execution = target?.executionModes[0] || 'service'
  const exposure: ApplicationInput['exposure'] = execution === 'service' && target?.publicExposure ? { mode: 'public', hostname: '' } : { mode: 'private' }
  return { name: '', targetId: target?.id || '', source: { url: target?.repositories[0] || '', ref: '', dockerfile: 'Dockerfile' }, execution, port: 8080, resources: target?.resourceSizes[0] || { cpu: 0, memory: 0 }, replicas: 1, exposure }
}
export default function ApplicationForm({ targets, initial, immutableTarget, busy, locked, error, submitLabel, onSubmit }: Props) {
  const [input, setInput] = useState<ApplicationInput>(() => initial || initialInput(targets.find(target => target.ready) || targets[0]))
  const [acknowledged, setAcknowledged] = useState(false)
  const [localError, setLocalError] = useState('')
  const categories = useCategories()
  const target = targets.find(item => item.id === input.targetId)
  const fields = error instanceof ApiError ? error.fieldErrors : {}
  function patch(value: Partial<ApplicationInput>) { setInput(current => ({ ...current, ...value })) }
  function field(name: string, helper?: string) { return { id: `field-${name}`, error: !!fields[name], helperText: fields[name] || helper } }
  function selectTarget(id: string) {
    const next = targets.find(item => item.id === id)
    const defaults = initialInput(next)
    setInput(current => ({ ...defaults, name: current.name, source: { ...defaults.source, ref: current.source.ref, dockerfile: current.source.dockerfile }, port: current.port }))
    setAcknowledged(false)
  }
  // selectEngine re-defaults engineVersion and adminUsername for the newly picked
  // engine, but only for a field still holding the previous engine's default (or
  // left empty) — a value the user typed over its prefill is never overwritten.
  function selectEngine(engine: 'postgres' | 'mysql') {
    const current = input.database!
    const previous = RELATIONAL_ENGINE_DEFAULTS[current.engine as 'postgres' | 'mysql']
    const next = relationalDefaults(engine, input.name)
    const engineVersion = !current.engineVersion || current.engineVersion === previous?.engineVersion ? next.engineVersion : current.engineVersion
    const adminUsername = !current.adminUsername || current.adminUsername === previous?.adminUsername ? next.adminUsername : current.adminUsername
    const databaseName = current.databaseName || next.databaseName
    const capacity = Number.isFinite(current.capacity?.minUnits) && Number.isFinite(current.capacity?.maxUnits) ? current.capacity : next.capacity
    patch({ database: { ...current, engine, engineVersion, adminUsername, databaseName, capacity, extensions: engine === 'postgres' ? current.extensions : undefined } })
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setLocalError('')
    if (!event.currentTarget.reportValidity()) return
    const numbers = [input.port, input.replicas, input.resources.cpu, input.resources.memory]
    if (input.database?.kind === 'relational') numbers.push(input.database.capacity?.minUnits ?? Number.NaN, input.database.capacity?.maxUnits ?? Number.NaN)
    if (!numbers.every(Number.isFinite)) { setLocalError('Complete all required numeric values before saving.'); return }
    if (!target || !target.ready) { setLocalError('This target has no ready worker. Refresh target options and retry.'); return }
    if (input.exposure.mode === 'public' && !acknowledged) { setLocalError('Acknowledge that this application will be publicly accessible.'); return }
    onSubmit(input)
  }
  const available = !!target && target.ready && target.resourceSizes.length > 0 && target.executionModes.length > 0
  return <Box component="form" onSubmit={submit}><Stack spacing={3}>{!!error && <Failure error={error} />}{localError && <Alert severity="error">{localError}</Alert>}{!available && <Alert severity="warning">The selected target is unavailable or has no approved deployment options. No substitute target will be used.</Alert>}<fieldset disabled={busy || locked} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}><Stack spacing={3}>
    <Paper variant="outlined" sx={{ p: 3 }}><Stack spacing={3}><Typography variant="h2">Application & source</Typography><Box className="form-grid"><TextField label="Application name" required value={input.name} onChange={event => patch({ name: event.target.value })} {...field('name')} slotProps={{ htmlInput: { maxLength: 100 } }} /><TextField select label="Deployment target" required disabled={immutableTarget} value={input.targetId} onChange={event => selectTarget(event.target.value)} {...field('targetId', immutableTarget ? 'Target is fixed for this application.' : 'Infrastructure managed by your organization.')} >{targets.map(item => <MenuItem key={item.id} value={item.id}>{item.label}{!item.ready ? ' — worker unavailable' : ''}</MenuItem>)}</TextField></Box>{!!categories.data?.length && <Box id="field-category"><Typography sx={{ fontSize: 13, fontWeight: 500, mb: 1 }}>Category</Typography><CategoryPicker categories={categories.data} value={input.category || ''} onChange={category => patch({ category: category || undefined })} /><Typography variant="caption" color={fields.category ? 'error' : 'text.secondary'} component="div" sx={{ mt: 0.75 }}>{fields.category || 'Groups this application on the Home launcher. Optional.'}</Typography></Box>}<RepositoryField label="Source repository" value={input.source.url} options={repositoryOptions(target)} onChange={url => patch({ source: { ...input.source, url } })} error={!!fields['source.url']} helperText={fields['source.url'] || repositoryHelper(target)} /><Box className="form-grid"><TextField label="Branch, tag, or ref" value={input.source.ref} onChange={event => patch({ source: { ...input.source, ref: event.target.value } })} {...field('source.ref', 'Leave empty to resolve the default branch when deployment starts.')} /><TextField label="Dockerfile path" required value={input.source.dockerfile} onChange={event => patch({ source: { ...input.source, dockerfile: event.target.value } })} {...field('source.dockerfile', 'Relative to the repository root.')} /></Box></Stack></Paper>
    <Paper variant="outlined" sx={{ p: 3 }}><Stack spacing={3}><Typography variant="h2">Container execution</Typography><Box className="form-grid"><TextField select label="Execution mode" value={input.execution} onChange={event => { const execution = event.target.value as ApplicationInput['execution']; patch({ execution, schedule: execution === 'scheduled' ? { expression: '', timezone: 'UTC', paused: false } : undefined, exposure: { mode: 'private' } }); setAcknowledged(false) }} {...field('execution')}>{(target?.executionModes || []).map(mode => <MenuItem key={mode} value={mode}>{mode === 'service' ? 'Continuous service' : 'Scheduled container'}</MenuItem>)}</TextField><TextField label="Container port" type="number" required value={Number.isFinite(input.port) ? input.port : ''} onChange={event => patch({ port: event.target.value === '' ? Number.NaN : Number(event.target.value) })} slotProps={{ htmlInput: { min: 1, max: 65535 } }} {...field('port')} /><TextField select label="CPU / memory" value={`${input.resources.cpu}:${input.resources.memory}`} onChange={event => { const size = target?.resourceSizes.find(item => `${item.cpu}:${item.memory}` === event.target.value); if (size) patch({ resources: size }) }} {...field('resources', 'CPU in millicores; memory in MiB.')} >{(target?.resourceSizes || []).map(size => <MenuItem key={`${size.cpu}:${size.memory}`} value={`${size.cpu}:${size.memory}`}>{size.cpu} millicores / {size.memory} MiB</MenuItem>)}</TextField><TextField label="Replicas" type="number" required value={Number.isFinite(input.replicas) ? input.replicas : ''} onChange={event => patch({ replicas: event.target.value === '' ? Number.NaN : Number(event.target.value) })} slotProps={{ htmlInput: { min: 1, max: target?.maxReplicas || 1 } }} {...field('replicas', `Target limit: ${target?.maxReplicas || 'unavailable'}`)} /></Box>{input.execution === 'scheduled' && <><Box className="form-grid"><TextField label="Schedule expression" required value={input.schedule?.expression || ''} onChange={event => patch({ schedule: { expression: event.target.value, timezone: input.schedule?.timezone || 'UTC', paused: input.schedule?.paused || false } })} {...field('schedule.expression', 'Use an expression supported by your configured target.')} /><TextField label="Schedule timezone" required value={input.schedule?.timezone || 'UTC'} onChange={event => patch({ schedule: { expression: input.schedule?.expression || '', timezone: event.target.value, paused: input.schedule?.paused || false } })} {...field('schedule.timezone')} /></Box><FormControlLabel control={<Checkbox checked={input.schedule?.paused || false} onChange={event => patch({ schedule: { expression: input.schedule?.expression || '', timezone: input.schedule?.timezone || 'UTC', paused: event.target.checked } })} />} label="Install schedule paused" /><Alert severity="info">A successful deployment installs the schedule; it does not confirm that a scheduled execution succeeded.</Alert></>}</Stack></Paper>
    {!!target?.databaseKinds.filter(Boolean).length && <Paper variant="outlined" sx={{ p: 3 }}><Stack spacing={3}><Typography variant="h2">Database</Typography><TextField select label="Database type" value={input.database?.kind || ''} onChange={event => { const kind = event.target.value as NonNullable<ApplicationInput['database']>['kind']; patch({ database: kind === 'key-value' ? { kind, partitionKey: 'pk', sortKey: 'sk' } : kind === 'relational' ? { kind, engine: 'postgres', ...relationalDefaults('postgres', input.name) } : kind ? { kind } : undefined }) }} {...field('database.kind')}><MenuItem value="">No database</MenuItem>{target.databaseKinds.filter(Boolean).map(kind => <MenuItem key={kind} value={kind}>{kind === 'relational' ? 'Relational SQL' : 'Key-value'}</MenuItem>)}</TextField>
      {input.database?.kind === 'relational' && <Box className="form-grid"><TextField select required label="SQL engine" value={input.database.engine || ''} onChange={event => selectEngine(event.target.value as 'postgres' | 'mysql')} {...field('database.engine', 'The backend validates provider-supported engines.')}><MenuItem value="postgres">PostgreSQL</MenuItem><MenuItem value="mysql">MySQL</MenuItem></TextField>{(['engineVersion', 'databaseName', 'adminUsername'] as const).map((key, index) => <TextField key={key} label={['Engine version', 'Logical database name', 'Administrator username'][index]} value={input.database?.[key] || ''} onChange={event => patch({ database: { ...input.database!, [key]: event.target.value } })} {...field(`database.${key}`, ['Prefilled for the selected engine; the default works for most apps.', 'Prefilled from the application name; the default works for most apps.', 'Prefilled; appuser works for most apps.'][index])} />)}{(['minUnits', 'maxUnits'] as const).map((key, index) => <TextField key={key} label={index === 0 ? 'Minimum capacity units' : 'Maximum capacity units'} type="number" value={Number.isFinite(input.database?.capacity?.[key]) ? input.database?.capacity?.[key] : ''} slotProps={{ htmlInput: { min: 0, step: 'any' } }} onChange={event => patch({ database: { ...input.database!, capacity: { minUnits: input.database?.capacity?.minUnits ?? Number.NaN, maxUnits: input.database?.capacity?.maxUnits ?? Number.NaN, [key]: event.target.value === '' ? Number.NaN : Number(event.target.value) } } })} {...field(`database.capacity.${key}`, 'Prefilled to match Aurora Serverless v2’s default range (0.5–4 ACU); raise it for a heavier workload.')} />)}</Box>}
      {input.database?.kind === 'relational' && input.database.engine === 'postgres' && <TextField select label="PostgreSQL extensions" value={input.database.extensions || []} onChange={event => { const selected = typeof event.target.value === 'string' ? event.target.value.split(',') : event.target.value as string[]; patch({ database: { ...input.database!, extensions: POSTGRES_EXTENSIONS.filter(name => selected.includes(name)) } }) }} {...field('database.extensions', 'Optional extensions installed in the application database.')} slotProps={{ select: { multiple: true, renderValue: selected => (selected as string[]).join(', ') } }}>{POSTGRES_EXTENSIONS.map(name => <MenuItem key={name} value={name}>{name}</MenuItem>)}</TextField>}
      {input.database?.kind === 'key-value' && <Box className="form-grid">{(['partitionKey', 'sortKey'] as const).map((key, index) => <TextField key={key} label={index === 0 ? 'Partition key' : 'Sort key (optional)'} value={input.database?.[key] || ''} onChange={event => patch({ database: { ...input.database!, [key]: event.target.value } })} {...field(`database.${key}`, index === 0 ? 'Leave both empty to use pk and sk.' : 'Clear to create a table with no sort key.')} />)}</Box>}</Stack></Paper>}
    {!!target?.bucketKinds.filter(Boolean).length && <Paper variant="outlined" sx={{ p: 3 }}><Stack spacing={3}><Typography variant="h2">Object storage</Typography><TextField select label="Bucket type" value={input.bucket?.kind || ''} onChange={event => { const kind = event.target.value as NonNullable<ApplicationInput['bucket']>['kind']; patch({ bucket: kind ? { kind, access: 'read-write' } : undefined }) }} {...field('bucket.kind')}><MenuItem value="">No bucket</MenuItem>{target.bucketKinds.filter(Boolean).map(kind => <MenuItem key={kind} value={kind}>{kind}</MenuItem>)}</TextField>{input.bucket && <Box className="form-grid"><TextField select label="Workload bucket access" value={input.bucket.access || 'read-write'} onChange={event => patch({ bucket: { ...input.bucket!, access: event.target.value as 'read' | 'read-write' } })} {...field('bucket.access')}><MenuItem value="read">Read only</MenuItem><MenuItem value="read-write">Read and write</MenuItem></TextField>{input.bucket.kind === 'zonal' && <TextField label="Bucket zone" required value={input.bucket.zone || ''} onChange={event => patch({ bucket: { ...input.bucket!, zone: event.target.value } })} {...field('bucket.zone', 'Must match the operator-approved placement.')} />}</Box>}<Typography variant="body2" color="text.secondary">Resource names and credentials are managed by AppHub, not supplied by users.</Typography></Stack></Paper>}
    <Paper variant="outlined" sx={{ p: 3 }}>
      <Stack spacing={3}>
        <Typography variant="h2">Network exposure</Typography>
        <TextField select label="Exposure" value={input.exposure.mode} onChange={event => {
          // Sign-in and public-path rules apply to the route, not to the mode
          // that publishes it, so switching modes carries them across rather
          // than silently discarding what the Authentication tab set. A
          // target that cannot honor them in the new mode (no internal
          // ingress for a private route) reports that at submit time instead.
          const { signInRequired, publicPaths } = input.exposure
          patch({ exposure: event.target.value === 'public' ? { mode: 'public', hostname: '', mcpAuthEnabled: false, signInRequired, publicPaths } : { mode: 'private', signInRequired, publicPaths } })
          setAcknowledged(false)
        }} {...field('exposure.mode')}>
          <MenuItem value="private">{target?.internalExposure ? 'Private (internal network only)' : 'Private network only'}</MenuItem>
          {target?.publicExposure && input.execution === 'service' && <MenuItem value="public">Public HTTPS</MenuItem>}
        </TextField>
        {input.exposure.mode === 'public' ? <>
          <TextField label="Public hostname label" required value={input.exposure.hostname} onChange={event => patch({ exposure: { mode: 'public', hostname: event.target.value, mcpAuthEnabled: input.exposure.mode === 'public' ? input.exposure.mcpAuthEnabled : false, signInRequired: input.exposure.signInRequired, publicPaths: input.exposure.publicPaths } })} slotProps={{ htmlInput: { pattern: '[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?', maxLength: 63 } }} {...field('exposure.hostname', 'One DNS label under the target’s operator-managed domain, not a full domain.')} />
          <FormControlLabel control={<Checkbox checked={input.exposure.mcpAuthEnabled || false} onChange={event => patch({ exposure: { mode: 'public', hostname: input.exposure.mode === 'public' ? input.exposure.hostname : '', mcpAuthEnabled: event.target.checked, signInRequired: input.exposure.signInRequired, publicPaths: input.exposure.publicPaths } })} />} label="Require AppHub OAuth for /mcp" />
          {input.exposure.mcpAuthEnabled
            ? <Alert severity="info">AppHub will publish MCP OAuth discovery and authenticate /mcp, injecting verified identity headers and removing the bearer token before forwarding. Other paths still require platform sign-in.</Alert>
            : <Alert severity="info">Visitors sign in through the platform identity provider before a request reaches this application. The application can assume the caller is already signed in.</Alert>}
          <FormControlLabel control={<Checkbox required checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />} label="I acknowledge that anyone the identity provider admits can open this address." />
        </> : input.execution === 'scheduled' ? <Typography variant="body2">Scheduled jobs have no address.</Typography>
          : target?.internalExposure ? <>
            <Typography variant="body2">Reachable only inside the company network at an internal address, behind organization sign-in. Not reachable from the internet.</Typography>
            <TextField label="Internal hostname label" value={input.exposure.hostname || ''} onChange={event => patch({ exposure: { mode: 'private', hostname: event.target.value || undefined, signInRequired: input.exposure.signInRequired, publicPaths: input.exposure.publicPaths } })} slotProps={{ htmlInput: { pattern: '[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?', maxLength: 63 } }} {...field('exposure.hostname', 'Leave empty to use a generated name. One DNS label under the internal domain.')} />
          </> : <Typography variant="body2">No route is published and nothing can connect to it. Use this for workers that only make outbound calls.</Typography>}
      </Stack>
    </Paper>
    <Button type="submit" variant="contained" size="large" disabled={!available || busy || locked}>{busy ? 'Saving…' : submitLabel}</Button>
  </Stack></fieldset></Stack></Box>
}
