import {
  Activity, BookOpen, Bot, Boxes, Check, ChevronDown, ChevronRight, Circle, CircleCheck, CircleX, Clock, Copy, Database, ExternalLink, FlaskConical, Gauge, GitBranch, Globe, HardDrive,
  Info, KeyRound, LayoutGrid, Lightbulb, LoaderCircle, Lock, LockOpen, MessageSquare, Monitor, Moon, Pencil, Rocket, ScrollText, Search, SearchX, Server, Settings, ShieldAlert,
  ShieldCheck, SlidersHorizontal, Sun, Tag, Terminal, Trash2, TriangleAlert, User, UserPlus, Users, Workflow, Wrench, X,
  type LucideProps,
} from 'lucide-react'

const SIZES = { small: 16, medium: 20, large: 24 } as const

// Explicit, tree-shakeable registry — add an import above when a new icon name is used.
// lucide-react dropped brand/logo glyphs, so 'github' maps to the generic GitBranch icon.
const REGISTRY: Record<string, React.ComponentType<LucideProps>> = {
  'activity': Activity, 'book-open': BookOpen, 'bot': Bot, 'boxes': Boxes, 'check': Check, 'chevron-down': ChevronDown, 'chevron-right': ChevronRight,
  'circle': Circle, 'circle-check': CircleCheck, 'circle-x': CircleX, 'clock': Clock, 'copy': Copy,
  'database': Database, 'external-link': ExternalLink, 'flask-conical': FlaskConical, 'gauge': Gauge, 'github': GitBranch, 'globe': Globe,
  'hard-drive': HardDrive, 'info': Info, 'key-round': KeyRound, 'layout-grid': LayoutGrid, 'lightbulb': Lightbulb, 'loader': LoaderCircle, 'lock': Lock, 'lock-open': LockOpen,
  'message-square': MessageSquare, 'monitor': Monitor, 'moon': Moon, 'pencil': Pencil, 'rocket': Rocket, 'scroll-text': ScrollText, 'search': Search, 'search-x': SearchX,
  'server': Server, 'settings': Settings, 'shield-alert': ShieldAlert, 'shield-check': ShieldCheck,
  'sliders-horizontal': SlidersHorizontal, 'sun': Sun, 'tag': Tag, 'terminal': Terminal, 'trash-2': Trash2,
  'triangle-alert': TriangleAlert, 'user': User, 'user-plus': UserPlus, 'users': Users, 'workflow': Workflow, 'wrench': Wrench, 'x': X,
}

type Props = Omit<LucideProps, 'size'> & { name: string; size?: number | keyof typeof SIZES }

export function Icon({ name, size = 'medium', strokeWidth = 2, ...rest }: Props) {
  const Glyph = REGISTRY[name]
  const px = typeof size === 'number' ? size : SIZES[size]
  if (!Glyph) return <span style={{ display: 'inline-block', width: px, height: px }} />
  return <Glyph size={px} strokeWidth={strokeWidth} {...rest} />
}
