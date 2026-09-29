import { useId, useState, type ReactNode } from 'react'
import { Dialog, TextField } from '@mui/material'
import { Button } from './Button'
import { Icon } from './Icon'

type Props = {
  open: boolean
  title: string
  children: ReactNode
  confirmLabel: string
  /** Label while `busy`, e.g. "Deleting…". */
  busyLabel?: string
  /** When set, the confirm button stays disabled until this exact text is typed. */
  confirmPhrase?: string
  color?: 'primary' | 'error'
  busy?: boolean
  /** Inline failure shown above the actions; the dialog stays open so the user can retry or cancel. */
  error?: ReactNode
  /** Server-side rejection of the typed phrase, shown on the text field. */
  fieldError?: string
  onConfirm: () => void
  onClose: () => void
}

const PAPER_SX = { background: 'var(--bg-0)', backgroundImage: 'none', border: '1px solid var(--line)', borderRadius: '10px', boxShadow: '0 18px 50px rgba(0,0,0,.28)', m: 2, width: 'calc(100% - 32px)' }

/** Modal confirmation for consequential actions. Cannot be dismissed while `busy`. */
export function ConfirmDialog({ open, title, children, confirmLabel, busyLabel, confirmPhrase, color = 'primary', busy = false, error, fieldError, onConfirm, onClose }: Props) {
  const [typed, setTyped] = useState('')
  const titleId = useId()
  const matches = confirmPhrase === undefined || typed === confirmPhrase
  const tone = color === 'error' ? { tint: 'var(--err-tint)', ink: 'var(--err)' } : { tint: 'var(--teal-tint)', ink: 'var(--teal)' }

  function close() { if (!busy) onClose() }
  function submit(event: React.FormEvent) { event.preventDefault(); if (matches && !busy) onConfirm() }

  return <Dialog open={open} onClose={close} maxWidth="sm" fullWidth aria-labelledby={titleId}
    slotProps={{ paper: { sx: PAPER_SX }, transition: { onExited: () => setTyped('') } }}>
    <form onSubmit={submit} style={{ padding: '20px 22px 18px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
        <span style={{ width: 32, height: 32, borderRadius: 7, background: tone.tint, color: tone.ink, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}><Icon name={color === 'error' ? 'triangle-alert' : 'check'} size={17} /></span>
        <h2 id={titleId} className="break-text" style={{ fontFamily: "'Anybody', sans-serif", fontSize: 18, fontWeight: 600, letterSpacing: '-.015em', margin: 0, flex: 1 }}>{title}</h2>
        <button type="button" aria-label="Close" onClick={close} disabled={busy} style={{ border: 0, background: 'transparent', padding: 4, display: 'flex', cursor: busy ? 'not-allowed' : 'pointer', color: 'var(--ink-3)' }}><Icon name="x" size={16} /></button>
      </div>
      <div style={{ fontSize: 13, color: 'var(--ink-1)', lineHeight: 1.5 }}>{children}</div>
      {confirmPhrase !== undefined && <label style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12.5, color: 'var(--ink-2)' }}>
        <span>Type <span className="ds-mono break-text" style={{ fontWeight: 600, color: 'var(--ink)', background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 4, padding: '1px 5px' }}>{confirmPhrase}</span> to confirm</span>
        <TextField autoFocus value={typed} onChange={event => setTyped(event.target.value)} disabled={busy} placeholder={confirmPhrase} error={!!fieldError} helperText={fieldError}
          slotProps={{ htmlInput: { autoComplete: 'off', autoCapitalize: 'off', spellCheck: false, className: 'ds-mono', 'aria-label': `Type ${confirmPhrase} to confirm` } }} />
      </label>}
      {error && <div role="alert">{error}</div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, flexWrap: 'wrap', marginTop: 2 }}>
        <Button variant="outlined" color="neutral" disabled={busy} onClick={close}>Cancel</Button>
        <Button type="submit" color={color} disabled={!matches || busy} startIcon={busy ? <Icon name="loader" size={14} className="ah-spin" /> : undefined}>{busy ? busyLabel || confirmLabel : confirmLabel}</Button>
      </div>
    </form>
  </Dialog>
}
