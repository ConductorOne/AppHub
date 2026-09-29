import { useEffect, useState } from 'react'
import { Alert, Autocomplete, TextField, Tooltip } from '@mui/material'
import { useAuth } from '../../hooks/useAuth'
import { useAddOwner, useOwners, usePrincipalSearch, useRemoveOwner } from '../../hooks/useOwners'
import { ApiError } from '../../services/api'
import type { Application, OwnerView } from '../../services/types'
import { Failure, Loading } from '../Feedback'
import { Button } from '../../design/Button'
import { Chip } from '../../design/Chip'
import { ConfirmDialog } from '../../design/ConfirmDialog'
import { Icon } from '../../design/Icon'
import { OwnerAvatar } from '../../design/owners'
import { cardStyle, SectionHeader } from './parts'

const DEPLOYMENT_ACTIVE = 'Owners can be changed once the current deployment finishes.'
const LAST_OWNER = 'An application needs at least one owner.'
const SEARCH_DEBOUNCE_MS = 250
const ERROR_MESSAGES: Record<string, string> = {
  last_owner: LAST_OWNER,
  deployment_active: DEPLOYMENT_ACTIVE,
  application_deleting: 'Owners cannot be changed while the application is being deleted.',
  unknown_owner: 'That user or group no longer exists in the directory.',
  too_many_owners: 'An application can have at most 20 owners. Remove one before adding another.',
}

function ownerErrorMessage(error: unknown) {
  if (!(error instanceof ApiError)) return 'The owners could not be changed. Retry the request.'
  return ERROR_MESSAGES[error.code] ?? error.message
}

function readOnlyReason(app: Application) {
  if (app.deletionRequestedAt) return 'Read-only while the application is being deleted.'
  if (app.activeDeploymentId) return DEPLOYMENT_ACTIVE
  return 'Only owners and admins can change owners.'
}

/** Everyone listed, directly or through a directory group, can open, deploy, and delete this application. */
export function OwnersSection({ app }: { app: Application }) {
  const owners = useOwners(app.id)
  const remove = useRemoveOwner(app.id)
  const me = useAuth().data?.id
  const [confirming, setConfirming] = useState<OwnerView>()
  const canWrite = app.permittedActions.includes('owners:write')
  const blocked = !canWrite && !!app.activeDeploymentId && !app.deletionRequestedAt
  const showControls = canWrite || blocked
  const items = owners.data?.items ?? []
  const isMe = (owner: OwnerView) => owner.kind === 'user' && owner.id === me

  function requestRemoval(owner: OwnerView) {
    remove.reset()
    if (isMe(owner)) { setConfirming(owner); return }
    remove.mutate({ key: owner.key, self: false, appName: app.specification.name })
  }
  function confirmRemoval() {
    if (confirming) remove.mutate({ key: confirming.key, self: true, appName: app.specification.name }, { onSuccess: () => setConfirming(undefined) })
  }

  return <div>
    <SectionHeader title="Owners" description="Owners can open, deploy, and delete this application, and manage who else owns it." />
    <div style={cardStyle}>
      {owners.isPending ? <div style={{ padding: '0 15px' }}><Loading label="Loading owners…" /></div>
        : owners.error ? <div style={{ padding: '0 15px' }}><Failure error={owners.error} retry={() => void owners.refetch()} /></div>
        : !items.length ? <div style={{ padding: '14px 15px', fontSize: 12.5, color: 'var(--ink-2)' }}>No owners are listed. An administrator can add one.</div>
        : items.map(owner => <OwnerRow key={owner.key} owner={owner} you={isMe(owner)} showRemove={showControls} disabled={!canWrite || remove.isPending}
            last={items.length === 1} removing={remove.isPending && remove.variables?.key === owner.key} onRemove={() => requestRemoval(owner)} />)}
      {showControls && <AddOwnerPicker app={app} existing={items} disabled={!canWrite || owners.isPending} />}
    </div>
    {!canWrite && <div style={{ fontSize: 11.5, color: 'var(--ink-3)', marginTop: 8, display: 'flex', alignItems: 'center', gap: 6 }}><Icon name="lock" size={12} />{readOnlyReason(app)}</div>}
    {remove.error && !confirming && <Alert severity="error" sx={{ mt: 1.5 }}>{ownerErrorMessage(remove.error)}</Alert>}
    <ConfirmDialog open={!!confirming} title="Remove yourself as an owner?" confirmLabel="Remove me" busyLabel="Removing…" color="error" busy={remove.isPending}
      error={remove.error && <Alert severity="error">{ownerErrorMessage(remove.error)}</Alert>} onConfirm={confirmRemoval} onClose={() => { setConfirming(undefined); remove.reset() }}>
      You will lose access to this application unless you're an owner through a group or an admin.
    </ConfirmDialog>
  </div>
}

type RowProps = { owner: OwnerView; you: boolean; showRemove: boolean; disabled: boolean; last: boolean; removing: boolean; onRemove: () => void }

function OwnerRow({ owner, you, showRemove, disabled, last, removing, onRemove }: RowProps) {
  const group = owner.kind === 'group'
  const detail = group ? 'Everyone in this directory group is an owner.' : owner.email
  return <div style={{ display: 'flex', alignItems: 'center', gap: 11, padding: '11px 15px', borderBottom: '1px solid var(--bg-2)' }}>
    <OwnerAvatar owner={owner} size={28} />
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
        <span className="break-text" style={{ fontSize: 13, fontWeight: 500 }}>{owner.name}</span>
        {you && <Chip tone="teal" size="extraSmall">You</Chip>}
        {group && <Chip tone="muted" size="extraSmall">Group</Chip>}
      </div>
      {detail && <div className="break-text" style={{ fontSize: 11.5, color: 'var(--ink-3)', marginTop: 2 }}>{detail}</div>}
    </div>
    {showRemove && <Tooltip title={last ? LAST_OWNER : ''}>
      <span><Button variant="outlined" color="error" size="sm" disabled={disabled || last} onClick={onRemove}
        startIcon={removing ? <Icon name="loader" size={13} className="ah-spin" /> : undefined}>{removing ? 'Removing…' : 'Remove'}</Button></span>
    </Tooltip>}
  </div>
}

function useDebounced(value: string, ms: number) {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => { const timer = setTimeout(() => setDebounced(value), ms); return () => clearTimeout(timer) }, [value, ms])
  return debounced
}

const PICKER_SLOTS = {
  paper: { sx: { fontSize: 13 } },
  listbox: { sx: { py: 0.5, '& .MuiAutocomplete-option': { fontSize: 13, minHeight: 36, py: 0.75 } } },
} as const

function AddOwnerPicker({ app, existing, disabled }: { app: Application; existing: OwnerView[]; disabled: boolean }) {
  const add = useAddOwner(app.id)
  const [input, setInput] = useState('')
  const q = useDebounced(input, SEARCH_DEBOUNCE_MS)
  const search = usePrincipalSearch(q)
  const added = new Set(existing.map(owner => owner.key))
  const options = input.trim() ? [...(search.data?.users ?? []), ...(search.data?.groups ?? [])] : []
  const noOptions = !input.trim() ? 'Type a name, email, or group' : search.error ? `Search failed: ${search.error.message}` : search.isFetching || input !== q ? 'Searching…' : 'No people or groups match'

  function select(owner: OwnerView | null) {
    if (!owner || added.has(owner.key)) return
    add.mutate({ kind: owner.kind, id: owner.id }, { onSuccess: () => setInput('') })
  }

  return <div style={{ padding: '12px 15px', background: 'var(--bg-1)' }}>
    <Autocomplete<OwnerView>
      value={null} inputValue={input} onInputChange={(_, value, reason) => { if (reason !== 'reset') setInput(value) }} onChange={(_, owner) => select(owner)}
      options={options} filterOptions={all => all} groupBy={owner => owner.kind === 'user' ? 'People' : 'Groups'}
      getOptionLabel={owner => owner.name} getOptionKey={owner => owner.key} isOptionEqualToValue={(a, b) => a.key === b.key} getOptionDisabled={owner => added.has(owner.key)}
      loading={search.isFetching} noOptionsText={noOptions} loadingText="Searching…" disabled={disabled || add.isPending} slotProps={PICKER_SLOTS}
      renderOption={({ key, ...props }, owner) => <li key={key} {...props}><PrincipalOption owner={owner} added={added.has(owner.key)} /></li>}
      renderInput={params => <TextField {...params} size="small" placeholder={add.isPending ? 'Adding…' : 'Add owner: search people and groups'} sx={{ '& .MuiInputBase-root': { fontSize: 13, background: 'var(--bg-0)' } }} />} />
    {add.error && <Alert severity="error" sx={{ mt: 1.5 }} onClose={() => add.reset()}>{ownerErrorMessage(add.error)}</Alert>}
  </div>
}

function PrincipalOption({ owner, added }: { owner: OwnerView; added: boolean }) {
  return <div style={{ display: 'flex', alignItems: 'center', gap: 9, minWidth: 0, width: '100%' }}>
    <OwnerAvatar owner={owner} size={22} />
    <div style={{ flex: 1, minWidth: 0 }}>
      <div className="break-text">{owner.name}</div>
      {owner.email && <div className="break-text" style={{ fontSize: 11.5, color: 'var(--ink-3)' }}>{owner.email}</div>}
    </div>
    {added && <Chip tone="muted" size="extraSmall">Already added</Chip>}
  </div>
}
