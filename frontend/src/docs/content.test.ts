import { existsSync, readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Token, Tokens } from 'marked'
import { describe, expect, it } from 'vitest'
import {
  type Block,
  buildGuide,
  listItemInline,
  listItemSublists,
  pageMatchesSearch,
  parseNav,
  resolveImage,
  resolveLink,
} from './content'

function collectLinkHrefs(tokens: Token[] | undefined, out: string[]) {
  if (!tokens) return
  for (const token of tokens) {
    if (token.type === 'link' && typeof token.href === 'string') out.push(token.href)
    if ('tokens' in token && token.tokens) collectLinkHrefs(token.tokens, out)
  }
}

function collectListLinkHrefs(items: Tokens.ListItem[], out: string[]) {
  for (const item of items) {
    collectLinkHrefs(listItemInline(item), out)
    for (const sublist of listItemSublists(item)) collectListLinkHrefs(sublist.items, out)
  }
}

function collectBlockLinkHrefs(blocks: Block[], out: string[]) {
  for (const block of blocks) {
    switch (block.kind) {
      case 'heading':
      case 'paragraph':
        collectLinkHrefs(block.tokens, out)
        break
      case 'list':
        collectListLinkHrefs(block.items, out)
        break
      case 'table':
        for (const cell of [...block.header, ...block.rows.flat()]) collectLinkHrefs(cell.tokens, out)
        break
      case 'callout':
        collectBlockLinkHrefs(block.blocks, out)
        break
      default:
        break
    }
  }
}

const here = path.dirname(fileURLToPath(import.meta.url))
const fixturesDir = path.join(here, '__fixtures__')

function loadFixtures(): Record<string, string> {
  const files: Record<string, string> = {}
  for (const name of readdirSync(fixturesDir)) {
    if (name.endsWith('.md')) files[name] = readFileSync(path.join(fixturesDir, name), 'utf8')
  }
  return files
}

describe('parseNav', () => {
  it('parses README sections and pages in document order', () => {
    const sections = parseNav(readFileSync(path.join(fixturesDir, 'README.md'), 'utf8'))
    expect(sections).toEqual([
      { title: 'Guide', pages: [{ slug: 'getting-started', title: 'Getting Started' }, { slug: 'configuration', title: 'Configuration' }] },
      { title: 'Reference', pages: [{ slug: 'cli-reference', title: 'CLI Reference' }] },
    ])
  })
})

describe('buildGuide', () => {
  const guide = buildGuide(loadFixtures())

  it('reports missing-readme when README.md is absent', () => {
    const result = buildGuide({ 'getting-started.md': '# Getting Started\n\nIntro.\n' })
    expect(result.error).toBe('missing-readme')
    expect(result.sections).toEqual([])
    expect(result.pages.size).toBe(0)
  })

  it('reports empty for an empty file set', () => {
    const result = buildGuide({})
    expect(result.error).toBe('empty')
  })

  it('extracts page title and lede, separate from the body blocks', () => {
    const page = guide.pages.get('getting-started')!
    expect(page.title).toBe('Getting Started')
    expect(page.lede.map(t => ('text' in t ? t.text : '')).join('')).toContain('installing the CLI')
  })

  it('assigns GitHub-style heading ids and dedupes repeats', () => {
    const page = guide.pages.get('getting-started')!
    const headingIds = page.blocks.filter(b => b.kind === 'heading').map(b => b.id)
    expect(headingIds).toEqual(
      expect.arrayContaining(['installation', 'prerequisites', 'deploying-your-first-app', 'installation-1', 'reference-table']),
    )
  })

  it('only collects h2s into the page TOC', () => {
    const page = guide.pages.get('getting-started')!
    expect(page.toc.map(t => t.id)).toEqual(['installation', 'deploying-your-first-app', 'installation-1', 'reference-table'])
  })

  it('parses GitHub alerts into callouts, with and without a custom title', () => {
    const page = guide.pages.get('getting-started')!
    const callouts = page.blocks.filter(b => b.kind === 'callout')
    expect(callouts).toEqual([
      expect.objectContaining({ tone: 'info', title: 'Note' }),
      expect.objectContaining({ tone: 'muted', title: 'Skip the wait' }),
      expect.objectContaining({ tone: 'info', title: 'Important' }),
      expect.objectContaining({ tone: 'warning', title: 'Warning' }),
      expect.objectContaining({ tone: 'warning', title: 'Danger zone' }),
    ])
  })

  it('renders ordered lists as steps, keeping rewritten inline links', () => {
    const page = guide.pages.get('getting-started')!
    const steps = page.blocks.find(b => b.kind === 'list' && b.ordered)
    expect(steps?.kind).toBe('list')
    if (steps?.kind !== 'list') throw new Error('expected a list block')
    expect(steps.ordered).toBe(true)
    expect(steps.items).toHaveLength(3)
  })

  it('keeps a list nested in a step, with its links rewritten', () => {
    const nested = buildGuide({
      'README.md': '# Docs\n\n## Start\n\n- [One](one.md)\n',
      'one.md': '# One\n\nLede.\n\n1. Fill in:\n   - The [name](one.md#name).\n   - The port.\n',
    })
    expect(nested.error).toBeUndefined()
    const steps = nested.pages.get('one')!.blocks[0]
    if (steps?.kind !== 'list') throw new Error('expected a list block')
    const sublists = listItemSublists(steps.items[0]!)
    expect(sublists).toHaveLength(1)
    expect(sublists[0]!.items).toHaveLength(2)
    const hrefs: string[] = []
    collectListLinkHrefs(steps.items, hrefs)
    expect(hrefs).toEqual(['/docs/one#name'])
  })

  it('computes prev/next in README order', () => {
    const gettingStarted = guide.pages.get('getting-started')!
    const configuration = guide.pages.get('configuration')!
    const cliReference = guide.pages.get('cli-reference')!
    expect(gettingStarted.prev).toBeUndefined()
    expect(gettingStarted.next).toEqual({ slug: 'configuration', title: 'Configuration' })
    expect(configuration.prev).toEqual({ slug: 'getting-started', title: 'Getting Started' })
    expect(configuration.next).toEqual({ slug: 'cli-reference', title: 'CLI Reference' })
    expect(cliReference.next).toBeUndefined()
  })

  it('matches pages by title or body text, case-insensitively', () => {
    const gettingStarted = guide.pages.get('getting-started')!
    const cliReference = guide.pages.get('cli-reference')!
    expect(pageMatchesSearch(gettingStarted, 'DOCKER')).toBe(true)
    expect(pageMatchesSearch(cliReference, 'docker')).toBe(false)
    expect(pageMatchesSearch(cliReference, '')).toBe(true)
  })
})

describe('resolveLink', () => {
  it('rewrites a same-guide page link to an in-app route', () => {
    expect(resolveLink('getting-started.md', 'x')).toEqual({ href: '/docs/getting-started', external: false })
  })

  it('rewrites a same-guide page link with an anchor', () => {
    expect(resolveLink('configuration.md#build-settings', 'x')).toEqual({ href: '/docs/configuration#build-settings', external: false })
  })

  it('rewrites a repo-relative path to a GitHub blob link', () => {
    expect(resolveLink('../../terraform/README.md', 'getting-started')).toEqual({
      href: 'https://github.com/conductorone/apphub/blob/main/terraform/README.md',
      external: true,
    })
  })

  it('leaves an absolute URL untouched and marks it external', () => {
    expect(resolveLink('https://github.com/conductorone/apphub', 'x')).toEqual({
      href: 'https://github.com/conductorone/apphub',
      external: true,
    })
  })
})

describe('resolveImage', () => {
  const assets = { 'images/architecture.svg': '/assets/architecture.abc123.svg' }

  it('resolves a bundled image to its asset URL', () => {
    expect(resolveImage('images/architecture.svg', assets)).toEqual({
      href: '/assets/architecture.abc123.svg',
      external: false,
    })
  })

  it('resolves a bundled image referenced with a leading ./', () => {
    expect(resolveImage('./images/architecture.svg', assets)).toEqual({
      href: '/assets/architecture.abc123.svg',
      external: false,
    })
  })

  it('falls back to a raw-content URL for an image not in the asset map', () => {
    expect(resolveImage('images/missing.png', assets)).toEqual({
      href: 'https://raw.githubusercontent.com/conductorone/apphub/main/docs/guide/images/missing.png',
      external: true,
    })
  })

  it('leaves an absolute URL untouched and marks it external', () => {
    expect(resolveImage('https://example.com/a.png', assets)).toEqual({
      href: 'https://example.com/a.png',
      external: true,
    })
  })
})

describe('buildGuide image assets', () => {
  const assets = { 'images/architecture.svg': '/assets/architecture.abc123.svg' }

  it('rewrites an in-map image to its bundled asset URL, without touching a link to the same path', () => {
    const guide = buildGuide(
      {
        'README.md': '# Docs\n\n## Start\n\n- [One](one.md)\n',
        'one.md':
          '# One\n\nLede.\n\n![Architecture](./images/architecture.svg)\n\nSee the [diagram source](images/architecture.svg).\n',
      },
      assets,
    )
    const page = guide.pages.get('one')!
    const paragraphs = page.blocks.filter((b): b is Extract<Block, { kind: 'paragraph' }> => b.kind === 'paragraph')
    const image = paragraphs[0]!.tokens.find(t => t.type === 'image') as Tokens.Image
    const link = paragraphs[1]!.tokens.find(t => t.type === 'link') as Tokens.Link
    expect(image.href).toBe('/assets/architecture.abc123.svg')
    expect(link.href).toBe('https://github.com/conductorone/apphub/blob/main/docs/guide/images/architecture.svg')
  })

  it('keeps an image not in the asset map pointed at raw content, not the /blob/ page', () => {
    const guide = buildGuide(
      {
        'README.md': '# Docs\n\n## Start\n\n- [One](one.md)\n',
        'one.md': '# One\n\nLede.\n\n![Missing](images/missing.png)\n',
      },
      assets,
    )
    const page = guide.pages.get('one')!
    const paragraph = page.blocks.find((b): b is Extract<Block, { kind: 'paragraph' }> => b.kind === 'paragraph')!
    const image = paragraph.tokens.find(t => t.type === 'image') as Tokens.Image
    expect(image.href).toBe('https://raw.githubusercontent.com/conductorone/apphub/main/docs/guide/images/missing.png')
  })
})

describe('real docs/guide directory (guardrail for doc authors)', () => {
  const guideDir = path.resolve(here, '../../../docs/guide')
  const guideExists = existsSync(guideDir)

  it.skipIf(!guideExists)('lists every page exactly once and resolves every in-guide link', () => {
    const files: Record<string, string> = {}
    for (const name of readdirSync(guideDir)) {
      if (name.endsWith('.md')) files[name] = readFileSync(path.join(guideDir, name), 'utf8')
    }
    const guide = buildGuide(files)
    expect(guide.error).toBeUndefined()

    const navSlugs = guide.sections.flatMap(section => section.pages.map(p => p.slug))
    const seen = new Set<string>()
    for (const slug of navSlugs) {
      expect(seen.has(slug)).toBe(false)
      seen.add(slug)
    }

    const pageFileSlugs = Object.keys(files)
      .filter(name => name !== 'README.md')
      .map(name => name.slice(0, -'.md'.length))
    expect(new Set(navSlugs)).toEqual(new Set(pageFileSlugs))

    for (const slug of navSlugs) {
      const page = guide.pages.get(slug)
      expect(page, `README links to "${slug}" but docs/guide/${slug}.md was not parsed`).toBeDefined()
    }

    for (const page of guide.pages.values()) {
      const hrefs: string[] = []
      collectLinkHrefs(page.lede, hrefs)
      collectBlockLinkHrefs(page.blocks, hrefs)
      for (const href of hrefs.filter(h => h.startsWith('/docs/'))) {
        const linkedSlug = href.slice('/docs/'.length).split('#')[0]
        expect(guide.pages.has(linkedSlug), `${page.slug}.md links to missing page "${linkedSlug}"`).toBe(true)
      }
    }
  })
})
