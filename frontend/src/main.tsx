import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { CssBaseline, ThemeProvider } from '@mui/material'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import { theme } from './theme'
import './styles.css'
const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 10_000 }, mutations: { retry: false } } })
createRoot(document.getElementById('root')!).render(<StrictMode><QueryClientProvider client={client}><ThemeProvider theme={theme} defaultMode="system" modeStorageKey="apphub-mode" disableTransitionOnChange><CssBaseline enableColorScheme /><BrowserRouter><App /></BrowserRouter></ThemeProvider></QueryClientProvider></StrictMode>)
