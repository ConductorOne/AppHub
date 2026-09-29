import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import type { Guide } from '../content'
import { pageMatchesSearch } from '../content'
import { Icon } from '../../design/Icon'

interface Props {
  guide: Guide
  activeSlug?: string
}

/** Sticky left nav: section list with a live title/text search filter. */
export function Sidebar({ guide, activeSlug }: Props) {
  const [query, setQuery] = useState('')

  const sections = useMemo(() => guide.sections
    .map(section => ({
      ...section,
      pages: section.pages.filter(navPage => {
        const page = guide.pages.get(navPage.slug)
        return page && pageMatchesSearch(page, query)
      }),
    }))
    .filter(section => section.pages.length > 0),
    [guide, query])

  const hasAnyPages = guide.sections.some(section => section.pages.length > 0)

  return <nav aria-label="Docs" className="docs-sidebar">
    <div style={{ fontFamily: "'Anybody', sans-serif", fontSize: 16, fontWeight: 600 }}>Docs</div>
    <div style={{ position: 'relative' }}>
      <Icon name="search" size={14} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'var(--ink-3)' }} />
      <input
        type="search"
        value={query}
        onChange={e => setQuery(e.target.value)}
        placeholder="Search docs"
        aria-label="Search docs"
        style={{
          width: '100%', boxSizing: 'border-box', padding: '6px 8px 6px 28px', fontSize: 12.5,
          fontFamily: 'inherit', border: '1px solid var(--line)', borderRadius: 6, background: 'var(--bg-0)',
          color: 'var(--ink)',
        }}
      />
    </div>
    {hasAnyPages && sections.length === 0 && <div style={{ fontSize: 12.5, color: 'var(--ink-3)' }}>No pages match &ldquo;{query}&rdquo;.</div>}
    {sections.map(section => <div key={section.title}>
      <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-2)', margin: '0 0 6px', padding: '0 8px' }}>
        {section.title}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
        {section.pages.map(navPage => {
          const active = navPage.slug === activeSlug
          // Background is only set inline when active: an inline style always beats a CSS
          // :hover rule, so the inactive/hover background must come from the class instead.
          return <Link key={navPage.slug} to={`/docs/${navPage.slug}`} className={active ? undefined : 'docs-nav-link'} style={{
            padding: '6px 8px', borderRadius: 6, fontSize: 12.5, textDecoration: 'none',
            color: active ? 'var(--teal-dark)' : 'var(--ink-1)', fontWeight: active ? 500 : 450,
            ...(active ? { background: 'var(--teal-tint)' } : {}),
          }}>{navPage.title}</Link>
        })}
      </div>
    </div>)}
  </nav>
}
