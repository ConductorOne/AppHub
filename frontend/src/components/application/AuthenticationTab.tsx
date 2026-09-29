// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useState } from 'react'
import { Alert } from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { ApiError, apiPath, request, segment } from '../../services/api'
import type { Application, ApplicationInput, PublicPathInput } from '../../services/types'
import { appURL } from '../AppURL'
import { Failure } from '../Feedback'
import { Button } from '../../design/Button'
import { ConfirmDialog } from '../../design/ConfirmDialog'
import { Icon } from '../../design/Icon'
import { NotAvailable, PrivateBetaChip } from '../../design/Preview'
import { cardStyle, SectionHeader } from './parts'
import { validatePublicPath } from './publicPathValidation'

/** Omitted means required -- see ExposureInput.signInRequired in api/openapi.yaml. */
function signInRequired(exposure: ApplicationInput['exposure']) {
  return exposure.signInRequired ?? true
}

export default function AuthenticationTab({ app }: { app: Application }) {
  const client = useQueryClient()
  const canWrite = app.permittedActions.includes('applications:write')
  const locked = !!app.activeDeploymentId
  const disabled = !canWrite || locked

  const mutation = useMutation({
    mutationFn: (input: ApplicationInput) => request<Application>(apiPath(`/applications/${segment(app.id)}`), { method: 'PUT', body: input, headers: { 'If-Match': `"${app.revision}"` } }),
    onSuccess: updated => { client.setQueryData(['application', app.id], updated); void client.invalidateQueries({ queryKey: ['applications'] }) },
  })
  const stale = mutation.error instanceof ApiError && mutation.error.status === 409

  const [confirmingOff, setConfirmingOff] = useState(false)
  const [pathDraft, setPathDraft] = useState('')
  const [noteDraft, setNoteDraft] = useState('')
  const [pathError, setPathError] = useState('')

  const published = appURL(app)
  if (!published.url) {
    return <div style={{ maxWidth: 840 }}>
      <SectionHeader title="Authentication" description="AppHub signs people in through ConductorOne before a request reaches your app." />
      <NotAvailable icon="lock" title="No route to protect">
        {app.specification.execution === 'scheduled'
          ? 'Scheduled jobs have no address, so there is nothing here for sign-in to gate.'
          : 'This private application has no route yet. On a target with an internal ingress it gets one after its next successful deploy; until then nothing can open a connection to it.'}
      </NotAvailable>
    </div>
  }

  const exposure = app.specification.exposure
  const required = signInRequired(exposure)
  const publicPaths = exposure.publicPaths ?? []

  function save(next: ApplicationInput['exposure']) {
    mutation.mutate({ ...app.specification, exposure: next })
  }

  function requestToggle() {
    if (disabled) return
    if (required) { setConfirmingOff(true); return }
    save({ ...exposure, signInRequired: true })
  }

  function confirmSignInOff() {
    save({ ...exposure, signInRequired: false })
    setConfirmingOff(false)
  }

  function addPath() {
    const path = pathDraft.trim()
    const error = validatePublicPath(path, publicPaths.map(p => p.path))
    if (error) { setPathError(error); return }
    const entry: PublicPathInput = { path, note: noteDraft.trim() || undefined }
    save({ ...exposure, publicPaths: [...publicPaths, entry] })
    setPathDraft('')
    setNoteDraft('')
    setPathError('')
  }

  function removePath(index: number) {
    save({ ...exposure, publicPaths: publicPaths.filter((_, i) => i !== index) })
  }

  const statusMessage = app.deletionRequestedAt
    ? 'Read-only while the application is being deleted.'
    : !canWrite
      ? 'Only owners and admins can change authentication settings.'
      : locked
        ? 'Authentication changes are locked while a deployment is active.'
        : mutation.isPending
          ? 'Saving…'
          : undefined

  return <div style={{ maxWidth: 840, display: 'flex', flexDirection: 'column', gap: 26 }}>
    <div>
      <div>
        <h3 style={{ fontSize: 15, fontWeight: 600, margin: '0 0 3px' }}>Authentication</h3>
        <p style={{ fontSize: 12.5, color: 'var(--ink-2)', margin: '0 0 12px' }}>AppHub signs people in through ConductorOne before a request reaches your app.</p>
        <div role="button" tabIndex={disabled ? -1 : 0} aria-disabled={disabled} onClick={requestToggle}
          onKeyDown={event => { if ((event.key === 'Enter' || event.key === ' ') && !disabled) { event.preventDefault(); requestToggle() } }}
          style={{ border: '1px solid var(--line)', borderRadius: 8, padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 14, cursor: disabled ? 'not-allowed' : 'pointer', opacity: disabled ? 0.6 : 1 }}>
          <span style={{ width: 32, height: 32, borderRadius: 7, background: required ? 'var(--teal-tint)' : 'var(--warn-tint)', color: required ? 'var(--teal-dark)' : 'var(--warn-ink)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Icon name={required ? 'lock' : 'lock-open'} size={17} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 13.5, fontWeight: 600 }}>Require sign-in</div>
            <div style={{ fontSize: 12, color: 'var(--ink-2)', marginTop: 1 }}>
              {required
                ? 'On. Visitors sign in with ConductorOne. Your app receives their identity in the X-Auth-Request-User and X-Auth-Request-Email headers.'
                : published.internal
                  ? 'Off. Anyone on the internal network can reach every path.'
                  : 'Off. Anyone with the URL can reach every path.'}
            </div>
          </div>
          <span aria-hidden style={{ width: 34, height: 20, borderRadius: 20, flexShrink: 0, background: required ? 'var(--teal)' : 'var(--bg-3)', border: `1px solid ${required ? 'var(--teal-dark)' : 'var(--line-emph)'}`, display: 'flex', alignItems: 'center', padding: 2, transition: 'background 200ms cubic-bezier(.4,0,.2,1)' }}>
            <span style={{ width: 14, height: 14, borderRadius: 14, background: 'var(--bg-0)', marginLeft: required ? 14 : 0, transition: 'margin-left 200ms cubic-bezier(.4,0,.2,1)', boxShadow: '0px 3px 6px -2px #1018281A' }} />
          </span>
        </div>
        {!required && <div style={{ marginTop: 10, border: '1px solid var(--warn-line)', background: 'var(--warn-tint)', borderRadius: 8, padding: '12px 15px', display: 'flex', gap: 11, alignItems: 'flex-start' }}>
          <span style={{ color: 'var(--warn-ink)', display: 'flex', marginTop: 1 }}><Icon name="triangle-alert" size={16} /></span>
          <div style={{ fontSize: 12.5, color: 'var(--warn-ink)' }}>
            https://{published.host} is {published.internal ? 'reachable to anyone on the internal network' : 'public'}. Your {publicPaths.length} public path {publicPaths.length === 1 ? 'rule is kept and applies' : 'rules are kept and apply'} again when sign-in is turned back on.
          </div>
        </div>}
      </div>

      {required && <div style={{ marginTop: 24 }}>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
          <div>
            <h3 style={{ fontSize: 15, fontWeight: 600, margin: '0 0 3px' }}>Public paths</h3>
            <p style={{ fontSize: 12.5, color: 'var(--ink-2)', margin: 0 }}>
              Requests to these paths skip sign-in. Use them for health checks, webhooks, and static assets.{' '}
              <Link to="/docs/access-and-exposure#sign-in-and-public-paths" style={{ fontSize: 12.5, fontWeight: 500 }}>How matching works</Link>
            </p>
          </div>
          <span style={{ fontSize: 12, color: 'var(--ink-3)' }}>{publicPaths.length} public {publicPaths.length === 1 ? 'path' : 'paths'}</span>
        </div>

        <div style={cardStyle}>
          {publicPaths.map((p, i) => <div key={p.path} style={{ display: 'grid', gridTemplateColumns: 'minmax(150px,1.2fr) minmax(0,1fr) 72px', gap: 14, alignItems: 'center', padding: '11px 15px', borderBottom: '1px solid var(--bg-2)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
              <span style={{ display: 'flex', color: 'var(--warn)' }}><Icon name="lock-open" size={14} /></span>
              <code className="break-text" style={{ fontFamily: "'Geist Mono', monospace", fontSize: 12.5, fontWeight: 500, letterSpacing: '-.02em', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.path}</code>
            </div>
            <div className="break-text" style={{ fontSize: 12, color: 'var(--ink-2)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.note || '—'}</div>
            <div style={{ textAlign: 'right' }}><Button variant="text" size="sm" disabled={disabled || mutation.isPending} onClick={() => removePath(i)}>Remove</Button></div>
          </div>)}
          {publicPaths.length === 0 && <div style={{ padding: '18px 15px', fontSize: 12.5, color: 'var(--ink-3)', textAlign: 'center' }}>Every path requires sign-in.</div>}
          <div style={{ padding: '12px 15px', background: 'var(--bg-1)', display: 'grid', gridTemplateColumns: 'minmax(150px,1.2fr) minmax(0,1fr) auto', gap: 10, alignItems: 'start' }}>
            <div>
              <input value={pathDraft} disabled={disabled} onChange={event => { setPathDraft(event.target.value); setPathError('') }} placeholder="/api/webhooks/*"
                style={{ width: '100%', border: `1px solid ${pathError ? 'var(--err)' : 'var(--line)'}`, borderRadius: 6, padding: '7px 9px', fontFamily: "'Geist Mono', monospace", fontSize: 12.5, letterSpacing: '-.02em', background: 'var(--bg-0)' }} />
              {pathError && <div style={{ fontSize: 11.5, color: 'var(--err)', marginTop: 5 }}>{pathError}</div>}
            </div>
            <input value={noteDraft} disabled={disabled} onChange={event => setNoteDraft(event.target.value)} placeholder="What calls this path"
              style={{ width: '100%', border: '1px solid var(--line)', borderRadius: 6, padding: '7px 9px', fontSize: 12.5, background: 'var(--bg-0)' }} />
            <Button variant="outlined" disabled={disabled || mutation.isPending} onClick={addPath}>Add path</Button>
          </div>
        </div>
        <p style={{ fontSize: 11.5, color: 'var(--ink-3)', margin: '8px 0 0' }}>Paths match exactly. End with <code style={{ fontFamily: "'Geist Mono', monospace", letterSpacing: '-.02em' }}>/*</code> to include everything below. Changes apply on the next deploy.</p>
      </div>}

      {statusMessage && <div style={{ fontSize: 11.5, color: 'var(--ink-3)', marginTop: 10 }}>{statusMessage}</div>}
      {stale && <Alert severity="warning" sx={{ mt: 1.5 }}>This application changed since the page loaded.<Button variant="outlined" onClick={() => { mutation.reset(); void client.refetchQueries({ queryKey: ['application', app.id] }) }}>Reload</Button></Alert>}
      {mutation.error && !stale && <Failure error={mutation.error} />}
    </div>

    <div>
      <SectionHeader title="Authorization" description="Fine-grained access decisions for actions inside your app." />
      <NotAvailable icon="shield-check" title="AuthZen" chip={<PrivateBetaChip />} action={<Button variant="outlined" disabled>Request access</Button>}>
        Ask ConductorOne, in real time, whether a signed-in subject may take a specific action on a specific resource -- an AuthZen-compatible Access Evaluation API backed by C1&apos;s own policies and grants. Your app calls it instead of hardcoding its own authorization rules.
      </NotAvailable>
    </div>

    <ConfirmDialog open={confirmingOff} title="Turn off sign-in?" confirmLabel="Turn off sign-in" busyLabel="Turning off…" color="error"
      busy={mutation.isPending} error={mutation.error && !stale ? <Failure error={mutation.error} /> : undefined}
      onConfirm={confirmSignInOff} onClose={() => setConfirmingOff(false)}>
      https://{published.host} will be reachable by {published.internal ? 'anyone on the internal network' : 'anyone with the URL'}, signed in or not. Your public path rules stay recorded and apply again if you turn sign-in back on.
    </ConfirmDialog>
  </div>
}
