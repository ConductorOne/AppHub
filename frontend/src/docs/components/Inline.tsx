import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { Token } from 'marked'

export const inlineCodeStyle: React.CSSProperties = {
  fontFamily: "'Geist Mono', monospace", fontSize: '0.92em', background: 'var(--bg-2)',
  padding: '1px 5px', borderRadius: 4,
}

/** Renders a docs page's already link-rewritten inline marked tokens to React nodes. */
export function renderInline(tokens: Token[] | undefined, keyPrefix = ''): ReactNode[] {
  if (!tokens) return []
  return tokens.map((token, i) => {
    const key = `${keyPrefix}${i}`
    switch (token.type) {
      case 'text':
      case 'escape':
        return 'tokens' in token && token.tokens ? <span key={key}>{renderInline(token.tokens, `${key}.`)}</span> : <span key={key}>{token.text}</span>
      case 'strong':
        return <strong key={key}>{renderInline(token.tokens, `${key}.`)}</strong>
      case 'em':
        return <em key={key}>{renderInline(token.tokens, `${key}.`)}</em>
      case 'del':
        return <del key={key}>{renderInline(token.tokens, `${key}.`)}</del>
      case 'codespan':
        return <code key={key} style={inlineCodeStyle}>{token.text}</code>
      case 'br':
        return <br key={key} />
      case 'image':
        return <img key={key} src={token.href} alt={token.text} style={{ maxWidth: '100%' }} />
      case 'link': {
        const internal = token.href.startsWith('/docs/')
        const label = renderInline(token.tokens, `${key}.`)
        if (internal) return <Link key={key} to={token.href}>{label}</Link>
        return <a key={key} href={token.href} target="_blank" rel="noreferrer">{label}</a>
      }
      default:
        return null
    }
  })
}
