import type { Category } from '../services/types'
import { Icon } from './Icon'

// Presentation only: the category list itself comes from GET /api/v1/categories.
// A key the server adds later without an entry here falls back to 'tag'.
const ICONS: Record<string, string> = {
  'customer-facing': 'globe', 'internal-tools': 'wrench', 'data-jobs': 'workflow', 'developer-tools': 'terminal',
  'ai-agents': 'bot', 'security': 'shield-check', 'observability': 'activity', 'docs': 'book-open',
}

export function categoryIcon(key?: string) { return (key && ICONS[key]) || 'tag' }

/** Resolves an application's category key; unknown or retired keys still show their raw key. */
export function categoryMeta(categories: Category[] | undefined, key?: string) {
  if (!key) return undefined
  return categories?.find(c => c.key === key) || { key, label: key, description: '' }
}

type PickerProps = { categories: Category[]; value?: string; onChange: (key: string) => void; disabled?: boolean }

/** One-of chip picker with an explicit "None" option (uncategorized). */
export function CategoryPicker({ categories, value = '', onChange, disabled = false }: PickerProps) {
  const options = [{ key: '', label: 'None', description: 'Listed under Uncategorized.' }, ...categories]
  return <div role="radiogroup" aria-label="Category" style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
    {options.map(o => {
      const on = value === o.key
      return <button key={o.key || 'none'} type="button" role="radio" aria-checked={on} title={o.description} disabled={disabled} onClick={() => onChange(o.key)} style={{
        display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: 'inherit', fontSize: 12, fontWeight: 500, padding: '6px 10px', borderRadius: 6,
        cursor: disabled ? 'not-allowed' : 'pointer', opacity: disabled && !on ? 0.6 : 1,
        border: `1px solid ${on ? 'var(--teal-line)' : 'var(--line)'}`, background: on ? 'var(--teal-tint)' : 'var(--bg-0)', color: on ? 'var(--teal-dark)' : 'var(--ink-1)',
      }}>
        {o.key && <Icon name={categoryIcon(o.key)} size={13} />}{o.label}
      </button>
    })}
  </div>
}
