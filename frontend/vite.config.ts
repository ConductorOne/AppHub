import path from 'node:path'
// Imported from 'vitest/config' (not 'vite') so this file's `test` field type-checks; it has no
// effect on `vite`/`vite build`, which simply ignore the extra key.
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

const target = process.env.APPHUB_API_TARGET || 'http://127.0.0.1:8081'
// docs/guide/*.md lives one level above this package, in the repo's docs/ tree.
const guideDir = path.resolve(import.meta.dirname, '../docs/guide')

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@guide': guideDir },
  },
  server: {
    host: '127.0.0.1', port: 5173, strictPort: true,
    allowedHosts: ['localhost', '127.0.0.1'],
    fs: { allow: ['.', guideDir] },
    proxy: {
      '^/(?:api|auth|oauth|mcp|\\.well-known|healthz|readyz)(?:/|$)': { target, changeOrigin: false },
    },
  },
  test: {
    environment: 'node',
  },
})
