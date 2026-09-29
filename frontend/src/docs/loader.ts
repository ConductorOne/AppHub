// Loaded at build time — see the `@guide` alias in vite.config.ts, which points at the repo's
// docs/guide/ directory (one level above this package). Vite inlines the raw markdown source of
// every matched file into the bundle; if docs/guide is empty or missing this glob simply matches
// nothing, so buildGuide() reports an empty guide instead of throwing.
const modules = import.meta.glob('@guide/*.md', { query: '?raw', import: 'default', eager: true }) as Record<
  string,
  string
>

// Image assets referenced from guide markdown (e.g. `images/architecture.svg`). Vite emits each
// as a bundled, hashed asset and resolves this glob to its final URL, so the in-app docs viewer
// can render them without reaching out to GitHub.
const imageModules = import.meta.glob('@guide/images/*.{svg,png,jpg,jpeg,gif,webp}', {
  query: '?url',
  import: 'default',
  eager: true,
}) as Record<string, string>

/** Raw markdown source for every docs/guide/*.md file, keyed by filename (e.g. "README.md"). */
export function loadGuideFiles(): Record<string, string> {
  const files: Record<string, string> = {}
  for (const [path, content] of Object.entries(modules)) {
    const name = path.split('/').pop()
    if (name) files[name] = content
  }
  return files
}

/** Bundled asset URL for every guide image, keyed by its guide-relative path (e.g. "images/architecture.svg"). */
export function loadGuideAssets(): Record<string, string> {
  const assets: Record<string, string> = {}
  for (const [path, url] of Object.entries(imageModules)) {
    const key = path.split('/').slice(-2).join('/')
    if (key) assets[key] = url
  }
  return assets
}
