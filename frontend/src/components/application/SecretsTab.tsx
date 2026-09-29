import { useState } from 'react'
import { Alert, Typography } from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { useSecrets } from '../../hooks/useSecrets'
import { ApiError, apiPath, request, segment, uncertain } from '../../services/api'
import { clearOperation, loadOperation, retainOperation } from '../../services/operations'
import type { Accepted, Application, SecretChange, SecretChangesInput, SecretList, SecretView } from '../../services/types'
import { Failure, Loading, Timestamp } from '../Feedback'
import { Button } from '../../design/Button'
import { Chip } from '../../design/Chip'
import { NotAvailable } from '../../design/Preview'
import { cardStyle, eyebrowStyle, LinkButton, monoCell, SectionHeader } from './parts'

const NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/
const RESERVED_PREFIXES = ['DATABASE_', 'APPHUB_', 'AWS_', 'ECS_']
const RESERVED_NAMES = ['PORT', 'TABLE_NAME', 'BUCKET_NAME', 'BUCKET_URI']
const MAX_SECRETS = 50
const MAX_VALUE_BYTES = 4096
const MAX_BATCH_BYTES = 48 * 1024
const encoder = new TextEncoder()
function byteLength(value: string) { return encoder.encode(value).length }
const COLUMNS = 'minmax(140px,220px) minmax(180px,1fr) minmax(96px,140px) minmax(150px,190px)'

type Replacement = { value: string; show: boolean }
type NewRow = { id: string; name: string; value: string; show: boolean }
type RowErrors = { name?: string; value?: string }
type ChangeEntry = { rowKey: string; change: SecretChange }

function isReserved(name: string) { return RESERVED_NAMES.includes(name) || RESERVED_PREFIXES.some(p => name.startsWith(p)) }
function nameFormatError(name: string): string | undefined {
  if (!name) return 'Name is required.'
  if (name.length > 100) return 'Name must be 100 characters or fewer.'
  if (!NAME_PATTERN.test(name)) return 'Use A-Z, 0-9, and _; must start with a letter or underscore.'
  if (isReserved(name)) return 'This name is reserved by the platform.'
  return undefined
}
function valueLengthError(value: string): string | undefined {
  if (!value) return 'Value is required.'
  if (byteLength(value) > MAX_VALUE_BYTES) return `Value must be ${MAX_VALUE_BYTES} bytes or fewer.`
  return undefined
}

function computeNewRowErrors(newRows: NewRow[], existingNames: Set<string>): Record<string, RowErrors> {
  const errors: Record<string, RowErrors> = {}
  const seen = new Set<string>()
  for (const row of newRows) {
    let nameError = nameFormatError(row.name)
    if (!nameError && existingNames.has(row.name)) nameError = 'A secret with this name already exists.'
    if (!nameError && seen.has(row.name)) nameError = 'Duplicate name.'
    if (!nameError && row.name) seen.add(row.name)
    const valueError = valueLengthError(row.value)
    if (nameError || valueError) errors[row.id] = { name: nameError, value: valueError }
  }
  return errors
}

function buildChangeEntries(deletions: Set<string>, replacements: Record<string, Replacement>, newRows: NewRow[]): ChangeEntry[] {
  const entries: ChangeEntry[] = []
  for (const name of deletions) entries.push({ rowKey: name, change: { name, action: 'delete' } })
  for (const [name, replacement] of Object.entries(replacements)) entries.push({ rowKey: name, change: { name, action: 'set', value: replacement.value } })
  for (const row of newRows) entries.push({ rowKey: row.id, change: { name: row.name, action: 'set', value: row.value } })
  return entries
}

function mapServerFieldErrors(error: ApiError, entries: ChangeEntry[]): Record<string, string> {
  const rowErrors: Record<string, string> = {}
  for (const [field, message] of Object.entries(error.fieldErrors)) {
    const match = /^changes\.(\d+)\.(?:name|value)$/.exec(field)
    const entry = match ? entries[Number(match[1])] : undefined
    if (entry) rowErrors[entry.rowKey] = message
  }
  return rowErrors
}

/** Retains only names/actions/revision for uncertain-retry recovery — never a secret value. */
async function submitSecretChanges(app: Application, changes: SecretChange[]) {
  const slot = `secrets.${app.id}`
  const meta = changes.map(({ name, action }) => ({ name, action }))
  const operation = retainOperation(slot, { applicationRevision: app.revision, changes: meta })
  try {
    const body: SecretChangesInput = { applicationRevision: app.revision, changes }
    const accepted = await request<Accepted>(apiPath(`/applications/${segment(app.id)}/secrets/deployments`), { method: 'POST', body, headers: { 'Idempotency-Key': operation.key } })
    clearOperation(slot)
    return accepted
  } catch (error) { if (!uncertain(error)) clearOperation(slot); throw error }
}

function fieldStyle(hasError: boolean): React.CSSProperties {
  return {
    width: '100%', minWidth: 0, fontFamily: "'Geist Mono', monospace", fontSize: 12.5, letterSpacing: '-.02em',
    padding: '6px 8px', border: `1px solid ${hasError ? 'var(--err-line)' : 'var(--line)'}`, borderRadius: 6,
    background: 'var(--bg-0)', color: 'var(--ink)',
  }
}

function SecretValueInput({ value, show, onChange, onToggleShow, error, placeholder }: {
  value: string; show: boolean; onChange: (value: string) => void; onToggleShow: () => void; error?: string; placeholder?: string
}) {
  return <div style={{ minWidth: 0 }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <input type={show ? 'text' : 'password'} value={value} placeholder={placeholder} autoComplete="new-password"
        onChange={event => onChange(event.target.value)} style={fieldStyle(!!error)} />
      <Button variant="text" size="sm" onClick={onToggleShow}>{show ? 'Hide' : 'Show'}</Button>
    </div>
    {error && <div style={{ fontSize: 11, color: 'var(--err-ink)', marginTop: 3 }}>{error}</div>}
  </div>
}

type ExistingRowProps = {
  item: SecretView; editable: boolean; deleting: boolean; replacement?: Replacement; error?: string
  onDelete: (name: string) => void; onUndo: (name: string) => void; onStartReplace: (name: string) => void
  onCancelReplace: (name: string) => void; onChangeValue: (name: string, value: string) => void; onToggleShow: (name: string) => void
}

function ExistingSecretRow({ item, editable, deleting, replacement, error, onDelete, onUndo, onStartReplace, onCancelReplace, onChangeValue, onToggleShow }: ExistingRowProps) {
  const struck: React.CSSProperties = deleting ? { textDecoration: 'line-through', color: 'var(--ink-3)' } : {}
  return <div style={{ display: 'grid', gridTemplateColumns: COLUMNS, gap: 12, alignItems: 'center', padding: '10px 16px', borderBottom: '1px solid var(--bg-2)' }}>
    <span style={{ ...monoCell, fontSize: 12.5, fontWeight: 500, ...struck }}>{item.name}</span>
    {replacement
      ? <SecretValueInput value={replacement.value} show={replacement.show} error={error} onChange={value => onChangeValue(item.name, value)} onToggleShow={() => onToggleShow(item.name)} />
      : <span style={{ ...monoCell, fontSize: 12.5, color: 'var(--ink-3)', ...struck }}>••••••••</span>}
    <span style={{ fontSize: 12, color: 'var(--ink-3)' }}><Timestamp value={item.updatedAt} /></span>
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
      {deleting && <><Chip tone="error" size="extraSmall">Will delete</Chip><LinkButton onClick={() => onUndo(item.name)}>Undo</LinkButton></>}
      {!deleting && replacement && <><Chip tone="warning" size="extraSmall">Changed</Chip><LinkButton onClick={() => onCancelReplace(item.name)}>Cancel</LinkButton></>}
      {!deleting && !replacement && editable && <><LinkButton onClick={() => onStartReplace(item.name)}>Replace value</LinkButton><LinkButton onClick={() => onDelete(item.name)}>Delete</LinkButton></>}
    </div>
  </div>
}

type NewRowProps = {
  row: NewRow; errors?: RowErrors; serverError?: string
  onChangeName: (id: string, name: string) => void; onChangeValue: (id: string, value: string) => void
  onToggleShow: (id: string) => void; onRemove: (id: string) => void
}

function NewSecretRow({ row, errors, serverError, onChangeName, onChangeValue, onToggleShow, onRemove }: NewRowProps) {
  return <div style={{ display: 'grid', gridTemplateColumns: COLUMNS, gap: 12, alignItems: 'start', padding: '10px 16px', borderBottom: '1px solid var(--bg-2)', background: 'var(--teal-tint)' }}>
    <div style={{ minWidth: 0 }}>
      <input value={row.name} placeholder="SECRET_NAME" style={fieldStyle(!!errors?.name)} onChange={event => onChangeName(row.id, event.target.value.toUpperCase())} />
      {errors?.name && <div style={{ fontSize: 11, color: 'var(--err-ink)', marginTop: 3 }}>{errors.name}</div>}
    </div>
    <SecretValueInput value={row.value} show={row.show} placeholder="Value" error={errors?.value ?? serverError} onChange={value => onChangeValue(row.id, value)} onToggleShow={() => onToggleShow(row.id)} />
    <span style={{ fontSize: 12, color: 'var(--ink-3)' }}>—</span>
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <Chip tone="teal" size="extraSmall">New</Chip>
      <LinkButton onClick={() => onRemove(row.id)}>Remove</LinkButton>
    </div>
  </div>
}

export default function SecretsTab({ app }: { app: Application }) {
  const query = useSecrets(app.id)
  if (query.isPending) return <div style={{ maxWidth: 900 }}><Loading label="Loading secrets…" /></div>
  if (query.error) return <div style={{ maxWidth: 900 }}><Failure error={query.error} retry={() => void query.refetch()} /></div>
  return <SecretsEditor app={app} secrets={query.data} />
}

function unavailableView(secrets: SecretList) {
  return <div style={{ maxWidth: 900 }}>
    <SectionHeader title="Secrets" description="Encrypted at rest, decrypted only inside the running app." />
    <NotAvailable icon="key-round" title="Secrets">The operator hasn't configured the secret handoff key, so secrets can't be changed yet.</NotAvailable>
    {secrets.items.length > 0 && <div style={{ ...cardStyle, marginTop: 16 }}>
      {secrets.items.map(item => <div key={item.name} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 16px', borderBottom: '1px solid var(--bg-2)' }}>
        <span style={{ ...monoCell, fontSize: 12.5 }}>{item.name}</span>
        <span style={{ fontSize: 12, color: 'var(--ink-3)' }}><Timestamp value={item.updatedAt} /></span>
      </div>)}
    </div>}
  </div>
}

function SecretsEditor({ app, secrets }: { app: Application; secrets: SecretList }) {
  const client = useQueryClient()
  const navigate = useNavigate()
  const [deletions, setDeletions] = useState<Set<string>>(new Set())
  const [replacements, setReplacements] = useState<Record<string, Replacement>>({})
  const [newRows, setNewRows] = useState<NewRow[]>([])

  const editable = app.permittedActions.includes('applications:write') && app.permittedActions.includes('deployments:write') && !app.activeDeploymentId
  const mutation = useMutation({
    mutationFn: (changes: SecretChange[]) => submitSecretChanges(app, changes),
    onSuccess: accepted => {
      setDeletions(new Set()); setReplacements({}); setNewRows([])
      void client.invalidateQueries({ queryKey: ['application', app.id] })
      void client.invalidateQueries({ queryKey: ['applications'] })
      void client.invalidateQueries({ queryKey: ['deployments', app.id] })
      void client.invalidateQueries({ queryKey: ['secrets', app.id] })
      navigate(`/applications/${app.id}/deployments/${accepted.deploymentId}`)
    },
  })

  if (!secrets.available) return unavailableView(secrets)

  const existingNames = new Set(secrets.items.map(item => item.name))
  const entries = buildChangeEntries(deletions, replacements, newRows)
  const newRowErrors = computeNewRowErrors(newRows, existingNames)
  const totalAfter = secrets.items.length - deletions.size + newRows.length
  const overLimit = totalAfter > MAX_SECRETS
  const batchBytes = entries.reduce((sum, entry) => sum + byteLength(entry.change.value ?? ''), 0)
  const overBatch = batchBytes > MAX_BATCH_BYTES
  const hasReplacementErrors = Object.values(replacements).some(r => !!valueLengthError(r.value))
  const hasErrors = Object.keys(newRowErrors).length > 0 || hasReplacementErrors || overLimit || overBatch
  const changeCount = entries.length
  const canSave = editable && !mutation.isPending && changeCount > 0 && !hasErrors

  const stale = mutation.error instanceof ApiError && mutation.error.status === 409
  const serverRowErrors = mutation.error instanceof ApiError && mutation.error.status === 422 ? mapServerFieldErrors(mutation.error, entries) : {}
  const pendingOp = loadOperation<{ applicationRevision: number; changes: { name: string; action: string }[] }>(`secrets.${app.id}`)
  const lockReason = app.deletionRequestedAt ? 'This application is being deleted, so its secrets are read-only.'
    : app.activeDeploymentId ? 'A deployment is active. Editing is locked until it settles.'
    : !editable ? 'You need application and deployment write access to change secrets.' : undefined

  function reload() { mutation.reset(); void client.refetchQueries({ queryKey: ['application', app.id] }); void client.refetchQueries({ queryKey: ['secrets', app.id] }) }
  function discard() { setDeletions(new Set()); setReplacements({}); setNewRows([]); mutation.reset() }
  function markDelete(name: string) { setReplacements(r => { const next = { ...r }; delete next[name]; return next }); setDeletions(d => new Set(d).add(name)) }
  function undoDelete(name: string) { setDeletions(d => { const next = new Set(d); next.delete(name); return next }) }
  function startReplace(name: string) { setDeletions(d => { const next = new Set(d); next.delete(name); return next }); setReplacements(r => ({ ...r, [name]: { value: '', show: false } })) }
  function cancelReplace(name: string) { setReplacements(r => { const next = { ...r }; delete next[name]; return next }) }
  function changeReplacement(name: string, value: string) { setReplacements(r => ({ ...r, [name]: { value, show: r[name]?.show ?? false } })) }
  function toggleReplacementShow(name: string) { setReplacements(r => ({ ...r, [name]: { value: r[name]?.value ?? '', show: !r[name]?.show } })) }
  function addRow() { setNewRows(rows => [...rows, { id: crypto.randomUUID(), name: '', value: '', show: false }]) }
  function removeRow(id: string) { setNewRows(rows => rows.filter(row => row.id !== id)) }
  function updateRowName(id: string, name: string) { setNewRows(rows => rows.map(row => row.id === id ? { ...row, name } : row)) }
  function updateRowValue(id: string, value: string) { setNewRows(rows => rows.map(row => row.id === id ? { ...row, value } : row)) }
  function toggleRowShow(id: string) { setNewRows(rows => rows.map(row => row.id === id ? { ...row, show: !row.show } : row)) }

  return <div style={{ maxWidth: 980 }}>
    <SectionHeader title="Secrets" description="Encrypted at rest, decrypted only inside the running app."
      action={editable && <Button variant="outlined" size="sm" onClick={addRow}>Add secret</Button>} />

    {lockReason && <Alert severity="info" sx={{ mb: 2 }}>{lockReason}</Alert>}
    {pendingOp && <Alert severity="warning" sx={{ mb: 2 }}>A previous save may have been accepted. Check the latest deployment before retrying; values must be re-entered if you reloaded this page.
      <Typography variant="caption" component="div">Idempotency key: {pendingOp.key}</Typography></Alert>}
    {stale && <Alert severity="warning" sx={{ mb: 2 }}>This application changed since the page loaded, or a deployment already started. Reload before retrying.
      <div><Button variant="outlined" onClick={reload} style={{ marginTop: 8 }}>Reload</Button></div></Alert>}
    {mutation.error && !stale && <Failure error={mutation.error} />}

    {!secrets.items.length && !newRows.length
      ? <div style={{ ...cardStyle, padding: '22px 18px', textAlign: 'center', color: 'var(--ink-2)', fontSize: 12.5 }}>
        {editable ? 'No secrets yet. Add one to inject it as an environment variable on the next deploy.' : 'No secrets have been configured for this application.'}
        {editable && <div style={{ marginTop: 10 }}><Button size="sm" onClick={addRow}>Add secret</Button></div>}
      </div>
      : <div style={cardStyle}>
        <div style={{ display: 'grid', gridTemplateColumns: COLUMNS, gap: 12, padding: '9px 16px', background: 'var(--bg-1)', borderBottom: '1px solid var(--line)' }}>
          <span style={eyebrowStyle}>Name</span><span style={eyebrowStyle}>Value</span><span style={eyebrowStyle}>Last changed</span><span style={eyebrowStyle}>Actions</span>
        </div>
        {secrets.items.map(item => <ExistingSecretRow key={item.name} item={item} editable={editable} deleting={deletions.has(item.name)} replacement={replacements[item.name]}
          error={(replacements[item.name] && valueLengthError(replacements[item.name].value)) || serverRowErrors[item.name]}
          onDelete={markDelete} onUndo={undoDelete} onStartReplace={startReplace} onCancelReplace={cancelReplace} onChangeValue={changeReplacement} onToggleShow={toggleReplacementShow} />)}
        {newRows.map(row => <NewSecretRow key={row.id} row={row} errors={newRowErrors[row.id]} serverError={serverRowErrors[row.id]}
          onChangeName={updateRowName} onChangeValue={updateRowValue} onToggleShow={toggleRowShow} onRemove={removeRow} />)}
      </div>}

    <div style={{ fontSize: 11.5, color: 'var(--ink-3)', margin: '10px 0 16px' }}>Saving rolls out a new task definition with these secrets, reusing the image from the last successful deploy — no rebuild. If the current revision hasn't deployed successfully yet, it's built first. Values can't be viewed after saving.</div>

    {editable && <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
      <Button disabled={!canSave} onClick={() => mutation.mutate(entries.map(entry => entry.change))}>{mutation.isPending ? 'Saving…' : 'Save and redeploy'}</Button>
      <Button variant="outlined" disabled={changeCount === 0 || mutation.isPending} onClick={discard}>Discard changes</Button>
      {changeCount > 0 && <span style={{ fontSize: 12, color: 'var(--ink-2)' }}>{changeCount} unsaved change{changeCount === 1 ? '' : 's'}</span>}
      {overLimit && <span style={{ fontSize: 12, color: 'var(--err-ink)' }}>An application can hold at most {MAX_SECRETS} secrets.</span>}
      {overBatch && <span style={{ fontSize: 12, color: 'var(--err-ink)' }}>Values in one save total at most 48 KiB. Save the rest in another deployment.</span>}
    </div>}
  </div>
}
