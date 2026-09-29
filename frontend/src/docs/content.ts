import { Lexer } from 'marked'
import type { MarkedToken, Token, Tokens } from 'marked'

/** Repository the docs live in, used to build GitHub links for out-of-guide files. */
const REPO = 'conductorone/apphub'
const GUIDE_REPO_DIR = 'docs/guide'

export type CalloutTone = 'info' | 'muted' | 'warning'

export interface TocEntry {
  id: string
  text: string
}

export type Block =
  | { kind: 'heading'; depth: 2 | 3; id: string; tokens: Token[] }
  | { kind: 'paragraph'; tokens: Token[] }
  | { kind: 'list'; ordered: boolean; items: Tokens.ListItem[] }
  | { kind: 'code'; lang: string; code: string }
  | { kind: 'table'; header: Tokens.TableCell[]; rows: Tokens.TableCell[][] }
  | { kind: 'callout'; tone: CalloutTone; title: string; blocks: Block[] }
  | { kind: 'hr' }

export interface NavPage {
  slug: string
  title: string
}

export interface NavSection {
  title: string
  pages: NavPage[]
}

export interface Page {
  slug: string
  section: string
  title: string
  lede: Token[]
  blocks: Block[]
  toc: TocEntry[]
  searchText: string
  prev?: NavPage
  next?: NavPage
}

export interface Guide {
  sections: NavSection[]
  pages: Map<string, Page>
  /** Set when the guide directory is missing or has no README nav. */
  error?: 'missing-readme' | 'empty'
}

/** Renders a marked inline-token tree back to plain text, for titles, ledes, and search. */
export function plainText(tokens: Token[] | undefined): string {
  if (!tokens) return ''
  let out = ''
  for (const token of tokens) {
    if ('tokens' in token && token.tokens && token.tokens.length > 0) out += plainText(token.tokens)
    else if ('text' in token && typeof token.text === 'string') out += token.text
  }
  return out
}

function baseSlug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\p{L}\p{N} -]/gu, '')
    .trim()
    .replace(/\s+/g, '-')
}

/** GitHub-style heading id: lowercase, punctuation stripped, spaces to hyphens, deduped. */
export function slugifyHeading(text: string, counts: Map<string, number>): string {
  const base = baseSlug(text) || 'section'
  const seen = counts.get(base) ?? 0
  counts.set(base, seen + 1)
  return seen === 0 ? base : `${base}-${seen}`
}

function splitAnchor(href: string): [string, string | undefined] {
  const hashIndex = href.indexOf('#')
  if (hashIndex === -1) return [href, undefined]
  return [href.slice(0, hashIndex), href.slice(hashIndex + 1)]
}

/** Resolves a relative path from docs/guide/ against the repo root, handling `..` segments. */
function resolveRepoPath(relative: string): string {
  const parts = GUIDE_REPO_DIR.split('/')
  for (const part of relative.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') parts.pop()
    else parts.push(part)
  }
  return parts.join('/')
}

export interface ResolvedLink {
  href: string
  external: boolean
}

/**
 * Rewrites a markdown link per the docs format contract: same-guide `slug.md`(#anchor) links
 * become in-app `/docs/slug` routes, other relative paths become GitHub blob links, and absolute
 * URLs pass through unchanged for a new tab.
 */
export function resolveLink(href: string, currentSlug: string): ResolvedLink {
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('//')) return { href, external: true }
  if (href.startsWith('#')) return { href: `/docs/${currentSlug}${href}`, external: false }
  const [path, anchor] = splitAnchor(href)
  const suffix = anchor ? `#${anchor}` : ''
  if (path.endsWith('.md') && !path.includes('/')) {
    const slug = path.slice(0, -'.md'.length)
    return { href: `/docs/${slug}${suffix}`, external: false }
  }
  const repoPath = resolveRepoPath(path)
  return { href: `https://github.com/${REPO}/blob/main/${repoPath}${suffix}`, external: true }
}

/**
 * Resolves an image src: a relative path that lands on a bundled guide asset (see
 * `loader.ts#loadGuideAssets`) uses its Vite-built URL, so the in-app viewer can render it. A
 * relative path outside the asset map falls back to a raw-content URL rather than `resolveLink`'s
 * `/blob/` page, since a `/blob/` page is HTML and can't be used as an `<img src>`.
 */
export function resolveImage(href: string, assets: Record<string, string>): ResolvedLink {
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('//')) return { href, external: true }
  const [path] = splitAnchor(href)
  const repoPath = resolveRepoPath(path)
  const assetKey = repoPath.startsWith(`${GUIDE_REPO_DIR}/`) ? repoPath.slice(GUIDE_REPO_DIR.length + 1) : undefined
  if (assetKey && assets[assetKey]) return { href: assets[assetKey], external: false }
  return { href: `https://raw.githubusercontent.com/${REPO}/main/${repoPath}`, external: true }
}

/** Recursively rewrites every link/image href inside an inline-token tree in place. */
function rewriteLinks(tokens: Token[] | undefined, currentSlug: string, assets: Record<string, string>): void {
  if (!tokens) return
  for (const token of tokens) {
    if (token.type === 'link') token.href = resolveLink(token.href, currentSlug).href
    else if (token.type === 'image') token.href = resolveImage(token.href, assets).href
    if ('tokens' in token && token.tokens) rewriteLinks(token.tokens, currentSlug, assets)
    if (token.type === 'list') for (const item of (token as Tokens.List).items) rewriteLinks(item.tokens, currentSlug, assets)
  }
}

const ALERT_TAGS = ['NOTE', 'TIP', 'IMPORTANT', 'WARNING', 'CAUTION'] as const
type AlertTag = (typeof ALERT_TAGS)[number]

const ALERT_TONE: Record<AlertTag, CalloutTone> = {
  NOTE: 'info',
  TIP: 'muted',
  IMPORTANT: 'info',
  WARNING: 'warning',
  CAUTION: 'warning',
}

const ALERT_RE = /^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*\r?\n?/i
const TITLE_LINE_RE = /^\*\*(.+?)\*\*\s*\r?\n?/

function parseAlert(raw: string): { tone: CalloutTone; title: string; body: string } | null {
  const match = ALERT_RE.exec(raw)
  if (!match) return null
  const tag = match[1]!.toUpperCase() as AlertTag
  let rest = raw.slice(match[0].length)
  let title = tag.charAt(0) + tag.slice(1).toLowerCase()
  const titleMatch = TITLE_LINE_RE.exec(rest)
  if (titleMatch) {
    title = titleMatch[1]!
    rest = rest.slice(titleMatch[0].length)
  }
  return { tone: ALERT_TONE[tag], title, body: rest }
}

interface BlockCtx {
  slug: string
  headingCounts: Map<string, number>
  toc: TocEntry[]
  assets: Record<string, string>
}

function tableCellsWithLinks(cells: Tokens.TableCell[], slug: string, assets: Record<string, string>): Tokens.TableCell[] {
  for (const cell of cells) rewriteLinks(cell.tokens, slug, assets)
  return cells
}

/** Converts marked block tokens into the page's renderable Block model. */
function tokensToBlocks(tokens: Token[], ctx: BlockCtx): Block[] {
  const blocks: Block[] = []
  for (const raw of tokens) {
    // Cast away the `Tokens.Generic` arm: it exists for custom tokenizer extensions, which this
    // module never registers, and its `[index: string]: any` index signature would otherwise
    // collapse every property access below to `any`.
    const token = raw as MarkedToken
    switch (token.type) {
      case 'space':
      case 'def':
      case 'html':
        break
      case 'heading': {
        const depth = token.depth <= 2 ? 2 : 3
        rewriteLinks(token.tokens, ctx.slug, ctx.assets)
        const id = slugifyHeading(plainText(token.tokens), ctx.headingCounts)
        if (depth === 2) ctx.toc.push({ id, text: plainText(token.tokens) })
        blocks.push({ kind: 'heading', depth, id, tokens: token.tokens })
        break
      }
      case 'paragraph':
        rewriteLinks(token.tokens, ctx.slug, ctx.assets)
        blocks.push({ kind: 'paragraph', tokens: token.tokens })
        break
      case 'list':
        for (const item of token.items) rewriteLinks(item.tokens, ctx.slug, ctx.assets)
        blocks.push({ kind: 'list', ordered: token.ordered, items: token.items })
        break
      case 'code':
        blocks.push({ kind: 'code', lang: token.lang || 'text', code: token.text })
        break
      case 'table':
        blocks.push({
          kind: 'table',
          header: tableCellsWithLinks(token.header, ctx.slug, ctx.assets),
          rows: token.rows.map(row => tableCellsWithLinks(row, ctx.slug, ctx.assets)),
        })
        break
      case 'hr':
        blocks.push({ kind: 'hr' })
        break
      case 'blockquote': {
        const alert = parseAlert(token.text)
        if (alert) {
          const bodyTokens = new Lexer({ gfm: true }).lex(alert.body)
          blocks.push({ kind: 'callout', tone: alert.tone, title: alert.title, blocks: tokensToBlocks(bodyTokens, ctx) })
        } else {
          blocks.push(...tokensToBlocks(token.tokens, ctx))
        }
        break
      }
      default:
        break
    }
  }
  return blocks
}

/** Parses README.md into the sidebar's section/page nav, in document order. */
export function parseNav(readmeRaw: string): NavSection[] {
  const tokens = new Lexer({ gfm: true }).lex(readmeRaw)
  const sections: NavSection[] = []
  let current: NavSection | null = null
  for (const raw of tokens) {
    const token = raw as MarkedToken
    if (token.type === 'heading' && token.depth === 2) {
      current = { title: plainText(token.tokens), pages: [] }
      sections.push(current)
    } else if (token.type === 'list' && current) {
      for (const item of token.items) {
        const link = findFirstLink(item.tokens)
        if (link && link.href.toLowerCase().endsWith('.md')) {
          current.pages.push({ slug: link.href.slice(0, -'.md'.length), title: plainText(link.tokens) })
        }
      }
    }
  }
  return sections
}

function findFirstLink(tokens: Token[]): Tokens.Link | undefined {
  for (const raw of tokens) {
    const token = raw as MarkedToken
    if (token.type === 'link') return token
    if ('tokens' in token && token.tokens) {
      const found = findFirstLink(token.tokens)
      if (found) return found
    }
  }
  return undefined
}

/** Flattens a list item's tight/loose wrapper tokens down to its renderable inline content. */
export function listItemInline(item: Tokens.ListItem): Token[] {
  const out: Token[] = []
  for (const token of item.tokens) {
    if ((token.type === 'text' || token.type === 'paragraph') && 'tokens' in token && token.tokens) {
      out.push(...token.tokens)
    }
  }
  return out
}

/** Returns the lists nested inside a list item, which render below its text. */
export function listItemSublists(item: Tokens.ListItem): Tokens.List[] {
  return item.tokens.filter((token): token is Tokens.List => token.type === 'list')
}

function titleCase(slug: string): string {
  return slug.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')
}

function buildPage(
  slug: string,
  section: string,
  raw: string,
  order: NavPage[],
  index: number,
  assets: Record<string, string>,
): Page {
  const tokens = new Lexer({ gfm: true }).lex(raw)
  let title = titleCase(slug)
  let bodyTokens: Token[] = tokens
  const firstToken = tokens[0] as MarkedToken | undefined
  if (firstToken?.type === 'heading' && firstToken.depth === 1) {
    title = plainText(firstToken.tokens)
    bodyTokens = tokens.slice(1)
  }
  let lede: Token[] = []
  const nonSpace = bodyTokens.findIndex(token => token.type !== 'space')
  if (nonSpace !== -1 && bodyTokens[nonSpace]!.type === 'paragraph') {
    const paragraph = bodyTokens[nonSpace] as Tokens.Paragraph
    rewriteLinks(paragraph.tokens, slug, assets)
    lede = paragraph.tokens
    bodyTokens = bodyTokens.slice(nonSpace + 1)
  }
  const toc: TocEntry[] = []
  const blocks = tokensToBlocks(bodyTokens, { slug, headingCounts: new Map(), toc, assets })
  const searchText = `${title} ${plainText(lede)} ${blocksSearchText(blocks)}`.toLowerCase()
  return {
    slug,
    section,
    title,
    lede,
    blocks,
    toc,
    searchText,
    prev: order[index - 1],
    next: order[index + 1],
  }
}

function blocksSearchText(blocks: Block[]): string {
  let out = ''
  for (const block of blocks) {
    switch (block.kind) {
      case 'heading':
      case 'paragraph':
        out += ` ${plainText(block.tokens)}`
        break
      case 'list':
        for (const item of block.items) out += ` ${plainText(item.tokens)}`
        break
      case 'code':
        out += ` ${block.code}`
        break
      case 'table':
        for (const cell of [...block.header, ...block.rows.flat()]) out += ` ${plainText(cell.tokens)}`
        break
      case 'callout':
        out += ` ${block.title} ${blocksSearchText(block.blocks)}`
        break
      case 'hr':
        break
    }
  }
  return out
}

/**
 * Builds the full guide (nav + pages) from a map of filename (e.g. "README.md",
 * "getting-started.md") to raw markdown source, plus a map of bundled image assets keyed by
 * guide-relative path (e.g. "images/architecture.svg", see `loader.ts#loadGuideAssets`). Missing
 * README or an empty file set is reported via `error` rather than thrown, so the Docs page can
 * show a friendly empty state.
 */
export function buildGuide(files: Record<string, string>, assets: Record<string, string> = {}): Guide {
  const readme = files['README.md']
  if (Object.keys(files).length === 0) return { sections: [], pages: new Map(), error: 'empty' }
  if (!readme) return { sections: [], pages: new Map(), error: 'missing-readme' }

  const sections = parseNav(readme)
  const order = sections.flatMap(section => section.pages)
  const pages = new Map<string, Page>()
  sections.forEach(section => {
    section.pages.forEach(navPage => {
      const raw = files[`${navPage.slug}.md`]
      if (raw === undefined) return
      const index = order.findIndex(p => p.slug === navPage.slug)
      pages.set(navPage.slug, buildPage(navPage.slug, section.title, raw, order, index, assets))
    })
  })
  return { sections, pages }
}

/** True when a page's title or searchable text contains the (case-insensitive) query. */
export function pageMatchesSearch(page: Page, query: string): boolean {
  const q = query.trim().toLowerCase()
  if (!q) return true
  return page.searchText.includes(q)
}
