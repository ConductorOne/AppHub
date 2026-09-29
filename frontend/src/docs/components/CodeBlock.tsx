import { useState } from 'react'
import { Icon } from '../../design/Icon'

interface Props {
  lang: string
  code: string
}

/** Fenced code block: language header with a copy-to-clipboard button, dark mono body. */
export function CodeBlock({ lang, code }: Props) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard access can be denied by the browser; the button simply stays "Copy".
    }
  }

  return <div style={{ border: '1px solid var(--line)', borderRadius: 8, overflow: 'hidden' }}>
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px',
      background: 'var(--bg-1)', borderBottom: '1px solid var(--line)',
    }}>
      <span style={{ fontFamily: "'Geist Mono', monospace", fontSize: 11, color: 'var(--ink-3)' }}>{lang}</span>
      <button type="button" onClick={() => void copy()} style={{
        display: 'flex', alignItems: 'center', gap: 5, fontFamily: 'inherit', fontSize: 11, fontWeight: 500,
        color: 'var(--ink-2)', background: 'transparent', border: 'none', cursor: 'pointer', padding: '2px 4px',
      }}>
        <Icon name={copied ? 'check' : 'copy'} size={13} />
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
    <pre style={{
      margin: 0, padding: '12px 14px', background: '#231F20', color: '#F0F1F2',
      fontFamily: "'Geist Mono', monospace", fontSize: 12.5, lineHeight: 1.7, overflowX: 'auto',
    }}><code>{code}</code></pre>
  </div>
}
