import { Autocomplete, TextField } from '@mui/material'
import type { Target } from '../services/types'

// repositoryOptions is the dropdown contents. An operator allowlist wins,
// because those are the only URLs that target will accept. Otherwise the
// list is what the worker last synced from the GitHub App. Either way the
// field stays editable: a typed or pasted URL is submitted as written.
export function repositoryOptions(target?: Target): string[] {
  if (!target) return []
  if (target.repositories.length > 0) return target.repositories
  return target.repositorySuggestions ?? []
}

export function repositoryHelper(target?: Target): string {
  if (target && target.repositories.length > 0) return 'Choose an approved repository, or paste its URL.'
  if ((target?.repositorySuggestions ?? []).length > 0) return 'Choose a synced repository, or paste a GitHub URL.'
  return 'Paste a GitHub repository URL. Repositories from the GitHub App appear here after the next sync.'
}

export default function RepositoryField({ label, value, options, onChange, error, helperText, disabled }: {
  label: string
  value: string
  options: string[]
  onChange: (url: string) => void
  error?: boolean
  helperText?: string
  disabled?: boolean
}) {
  return <Autocomplete
    freeSolo
    forcePopupIcon
    openOnFocus
    disabled={disabled}
    options={options}
    inputValue={value}
    onInputChange={(_, next, reason) => {
      if (reason === 'input' || reason === 'clear') onChange(next)
    }}
    onChange={(_, next) => {
      if (typeof next === 'string') onChange(next)
    }}
    filterOptions={(opts, state) => {
      const query = state.inputValue.trim().toLowerCase()
      if (!query) return opts
      return opts.filter(option => option.toLowerCase().includes(query))
    }}
    renderInput={params => <TextField {...params} label={label} required error={error} helperText={helperText} placeholder="https://github.com/org/repo" />}
  />
}
