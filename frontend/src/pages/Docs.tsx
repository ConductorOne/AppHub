import { useEffect } from 'react'
import { Alert, Stack, Typography } from '@mui/material'
import { Link, Navigate, useLocation, useParams } from 'react-router-dom'
import { buildGuide, type Page, type TocEntry } from '../docs/content'
import { loadGuideAssets, loadGuideFiles } from '../docs/loader'
import { Sidebar } from '../docs/components/Sidebar'
import { renderInline } from '../docs/components/Inline'
import { renderBlocks } from '../docs/components/Blocks'
import { Button } from '../design/Button'
import { Icon } from '../design/Icon'

// Parsed once for the app's lifetime — docs/guide is embedded at build time, it never changes
// while the app is running.
const GUIDE = buildGuide(loadGuideFiles(), loadGuideAssets())
const EDIT_BASE = 'https://github.com/conductorone/apphub/edit/main/docs/guide'
const ISSUE_BASE = 'https://github.com/conductorone/apphub/issues/new'

const asideLinkStyle: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--ink-2)', textDecoration: 'none',
}

function Toc({ toc }: { toc: TocEntry[] }) {
  return <div>
    <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.06em', textTransform: 'uppercase', color: 'var(--ink-3)', marginBottom: 8 }}>
      On this page
    </div>
    <ul style={{ margin: 0, padding: 0, listStyle: 'none', borderLeft: '1px solid var(--line)', display: 'flex', flexDirection: 'column', gap: 6 }}>
      {toc.map(entry => <li key={entry.id} style={{ paddingLeft: 10 }}>
        <a href={`#${entry.id}`} style={{ fontSize: 12.5, color: 'var(--ink-2)', textDecoration: 'none' }}>{entry.text}</a>
      </li>)}
    </ul>
  </div>
}

function PrevNextCard({ direction, navPage }: { direction: 'Previous' | 'Next'; navPage: { slug: string; title: string } }) {
  return <Link to={`/docs/${navPage.slug}`} className="docs-card" style={{
    flex: '1 1 200px', border: '1px solid var(--line)', borderRadius: 8, padding: '10px 14px',
    textDecoration: 'none', display: 'flex', flexDirection: 'column', gap: 3,
    textAlign: direction === 'Next' ? 'right' : 'left',
  }}>
    <span style={{ fontSize: 11.5, color: 'var(--ink-3)' }}>{direction}</span>
    <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--teal)' }}>{navPage.title}</span>
  </Link>
}

function PrevNext({ page }: { page: Page }) {
  if (!page.prev && !page.next) return null
  return <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, paddingTop: 14, borderTop: '1px solid var(--line)' }}>
    {page.prev && <PrevNextCard direction="Previous" navPage={page.prev} />}
    {page.next && <PrevNextCard direction="Next" navPage={page.next} />}
  </div>
}

function EmptyState() {
  return <Stack spacing={2} sx={{ p: 4 }}>
    <Typography variant="h1" sx={{ fontFamily: "'Anybody', sans-serif", fontSize: 28, fontWeight: 600 }}>Docs</Typography>
    <Alert severity="info">No documentation found.</Alert>
  </Stack>
}

function NotFound({ slug }: { slug: string }) {
  return <Stack spacing={2} sx={{ p: 4 }}>
    <Typography variant="h1" sx={{ fontFamily: "'Anybody', sans-serif", fontSize: 28, fontWeight: 600 }}>Page not found</Typography>
    <Alert severity="info">There's no docs page at &ldquo;{slug}&rdquo;.</Alert>
    <Button to="/docs">Go to docs home</Button>
  </Stack>
}

/** Scrolls the app's scrollable main region to top on page change, or to the URL's #anchor. */
function useScrollOnNavigate(slug: string | undefined, hash: string) {
  useEffect(() => {
    if (hash) {
      const target = document.getElementById(hash.slice(1))
      if (target) { target.scrollIntoView(); return }
    }
    document.getElementById('main-content')?.scrollTo(0, 0)
  }, [slug, hash])
}

export default function Docs() {
  const { slug } = useParams()
  const location = useLocation()
  useScrollOnNavigate(slug, location.hash)

  if (GUIDE.sections.length === 0) return <EmptyState />

  if (!slug) {
    const first = GUIDE.sections.flatMap(section => section.pages)[0]
    return first ? <Navigate replace to={`/docs/${first.slug}`} /> : <EmptyState />
  }

  const page = GUIDE.pages.get(slug)
  if (!page) return <NotFound slug={slug} />

  return <div className="docs-layout">
    <Sidebar guide={GUIDE} activeSlug={slug} />
    <div style={{ padding: '28px clamp(20px,3vw,36px) 64px', maxWidth: 1040, display: 'flex', flexWrap: 'wrap-reverse', gap: '24px 32px' }}>
      <article style={{ flex: '999 1 420px', maxWidth: 680, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--ink-3)' }}>
          <span>{page.section}</span><Icon name="chevron-right" size={12} /><span>{page.title}</span>
        </div>
        <h1 style={{ fontFamily: "'Anybody', sans-serif", fontSize: 28, fontWeight: 600, letterSpacing: '-0.02em', margin: '4px 0 0' }}>
          {page.title}
        </h1>
        <p style={{ fontSize: 15, color: 'var(--ink-2)', lineHeight: 1.55, margin: '8px 0 26px' }}>{renderInline(page.lede)}</p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {renderBlocks(page.blocks)}
          <PrevNext page={page} />
        </div>
      </article>
      <aside style={{ flex: '1 1 160px', maxWidth: 200, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 18 }}>
        {page.toc.length > 0 && <Toc toc={page.toc} />}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <a href={`${EDIT_BASE}/${slug}.md`} target="_blank" rel="noreferrer" style={asideLinkStyle}>
            <Icon name="pencil" size={13} />Edit on GitHub
          </a>
          <a href={`${ISSUE_BASE}?title=${encodeURIComponent(`Docs: ${page.title}`)}`} target="_blank" rel="noreferrer" style={asideLinkStyle}>
            <Icon name="message-square" size={13} />Report an issue
          </a>
        </div>
      </aside>
    </div>
  </div>
}
