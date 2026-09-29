import type { OwnerView } from '../services/types'
import { Avatar } from './Avatar'
import { Icon } from './Icon'

/** A user owner's initials avatar, or a group glyph in the same footprint. */
export function OwnerAvatar({ owner, size = 24 }: { owner: OwnerView; size?: number }) {
  if (owner.kind === 'user') return <Avatar name={owner.name} size={size} radius={size / 2} />
  return <span aria-label="Group" style={{ width: size, height: size, borderRadius: size / 2, background: 'var(--bg-2)', border: '1px solid var(--line)', color: 'var(--ink-2)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, boxSizing: 'border-box' }}>
    <Icon name="users" size={Math.round(size * 0.55)} />
  </span>
}

/** "A", "A and B", or "A, B +N" — pass `or` for "A or B". */
export function ownerNames(owners: OwnerView[], conjunction: 'and' | 'or' = 'and') {
  const [first, second] = owners
  if (!first) return 'an owner'
  if (!second) return first.name
  if (owners.length === 2) return `${first.name} ${conjunction} ${second.name}`
  return `${first.name}, ${second.name} +${owners.length - 2}`
}
