import type { ReactNode } from 'react'
import type { Tokens } from 'marked'
import type { Block, CalloutTone } from '../content'
import { listItemInline, listItemSublists } from '../content'
import { Icon } from '../../design/Icon'
import { renderInline } from './Inline'
import { CodeBlock } from './CodeBlock'

const CALLOUT_STYLE: Record<CalloutTone, { border: string; bg: string; fg: string; icon: string }> = {
  info: { border: 'var(--teal-line)', bg: 'var(--teal-tint)', fg: 'var(--teal-dark)', icon: 'info' },
  muted: { border: 'var(--line)', bg: 'var(--bg-1)', fg: 'var(--ink-1)', icon: 'lightbulb' },
  warning: { border: 'var(--warn-line)', bg: 'var(--warn-tint)', fg: 'var(--warn-ink)', icon: 'triangle-alert' },
}

function Callout({ tone, title, blocks }: { tone: CalloutTone; title: string; blocks: Block[] }) {
  const style = CALLOUT_STYLE[tone]
  return <div style={{
    display: 'flex', gap: 10, border: `1px solid ${style.border}`, background: style.bg, color: style.fg,
    borderRadius: 8, padding: '12px 15px',
  }}>
    <Icon name={style.icon} size={16} style={{ flexShrink: 0, marginTop: 1 }} />
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
      <div style={{ fontSize: 13, fontWeight: 700 }}>{title}</div>
      <div style={{ fontSize: 13, lineHeight: 1.55 }}>{renderBlocks(blocks)}</div>
    </div>
  </div>
}

function Steps({ items }: { items: Tokens.ListItem[] }) {
  return <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
    {items.map((item, i) => <li key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
      <span style={{
        flexShrink: 0, width: 22, height: 22, borderRadius: '50%', background: 'var(--teal-tint)',
        border: '1px solid var(--teal-line)', color: 'var(--teal-dark)', fontSize: 11.5, fontWeight: 600,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>{i + 1}</span>
      <div style={{ fontSize: 14, lineHeight: 1.65, color: 'var(--ink-1)', paddingTop: 2, minWidth: 0 }}>{renderInline(listItemInline(item))}<Sublists item={item} /></div>
    </li>)}
  </ol>
}

function Sublists({ item }: { item: Tokens.ListItem }) {
  return <>{listItemSublists(item).map((list, i) => <div key={i} style={{ marginTop: 6 }}>{list.ordered ? <Steps items={list.items} /> : <BulletList items={list.items} />}</div>)}</>
}

function BulletList({ items }: { items: Tokens.ListItem[] }) {
  return <ul style={{ margin: 0, paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 6 }}>
    {items.map((item, i) => <li key={i} style={{ fontSize: 14, lineHeight: 1.65, color: 'var(--ink-1)' }}>
      {renderInline(listItemInline(item))}<Sublists item={item} />
    </li>)}
  </ul>
}

function DocTable({ header, rows }: { header: Tokens.TableCell[]; rows: Tokens.TableCell[][] }) {
  return <div style={{ border: '1px solid var(--line)', borderRadius: 8, overflowX: 'auto' }}>
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
      <thead>
        <tr style={{ background: 'var(--bg-1)' }}>
          {header.map((cell, i) => <th key={i} style={{
            textAlign: 'left', padding: '10px 14px', fontSize: 11, fontWeight: 500,
            textTransform: 'uppercase', letterSpacing: '.06em', color: 'var(--ink-2)',
          }}>{renderInline(cell.tokens)}</th>)}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, ri) => <tr key={ri}>
          {row.map((cell, ci) => <td key={ci} style={{ padding: '10px 14px', borderBottom: '1px solid var(--bg-2)', color: 'var(--ink-1)' }}>
            {renderInline(cell.tokens)}
          </td>)}
        </tr>)}
      </tbody>
    </table>
  </div>
}

/** Renders a page's (or a callout's) content blocks in order. */
export function renderBlocks(blocks: Block[]): ReactNode {
  return <>{blocks.map((block, i) => {
    switch (block.kind) {
      case 'heading': {
        const Tag = block.depth === 2 ? 'h2' : 'h3'
        const size = block.depth === 2 ? 19 : 15
        return <Tag key={i} id={block.id} style={{ fontFamily: "'Anybody', sans-serif", fontSize: size, fontWeight: 600, margin: '14px 0 0' }}>
          {renderInline(block.tokens)}
        </Tag>
      }
      case 'paragraph':
        return <p key={i} style={{ fontSize: 14, lineHeight: 1.65, color: 'var(--ink-1)', margin: 0 }}>{renderInline(block.tokens)}</p>
      case 'list':
        return <div key={i}>{block.ordered ? <Steps items={block.items} /> : <BulletList items={block.items} />}</div>
      case 'code':
        return <div key={i}><CodeBlock lang={block.lang} code={block.code} /></div>
      case 'table':
        return <div key={i}><DocTable header={block.header} rows={block.rows} /></div>
      case 'callout':
        return <div key={i}><Callout tone={block.tone} title={block.title} blocks={block.blocks} /></div>
      case 'hr':
        return <hr key={i} style={{ border: 'none', borderTop: '1px solid var(--line)', margin: 0 }} />
      default:
        return null
    }
  })}</>
}
