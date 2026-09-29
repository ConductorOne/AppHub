import type { ErrorResponse } from './types'

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string,
    public fieldErrors: Record<string, string> = {}, public requestId?: string) {
    super(message)
    this.name = 'ApiError'
  }
}
let csrfToken = ''
export function setCSRF(token: string) { csrfToken = token }
export async function request<T>(path: string, options: {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'; body?: unknown;
  signal?: AbortSignal; headers?: Record<string, string>
} = {}): Promise<T> {
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Same-origin API path required')
  const method = options.method || 'GET'
  let response: Response
  try {
    response = await fetch(path, {
      method, signal: options.signal, credentials: 'same-origin', redirect: 'error',
      headers: { Accept: 'application/json', ...(options.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(method !== 'GET' ? { 'X-CSRF-Token': csrfToken } : {}), ...options.headers },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    })
  } catch (error) {
    if (options.signal?.aborted) throw error
    throw new ApiError(0, 'network_error', 'Cannot reach AppHub. Check your connection and retry. A submitted operation may already have been accepted.')
  }
  if (!response.ok) {
    let body: Partial<ErrorResponse> = {}
    try { body = await response.json() } catch { /* Never display raw proxy/provider responses. */ }
    throw new ApiError(response.status, body.error?.code || 'request_failed',
      body.error?.message || (response.status === 503 ? 'AppHub is temporarily unavailable. Retry without signing out.' : 'The request could not be completed.'),
      body.error?.fieldErrors, body.requestId)
  }
  if (response.status === 204) return undefined as T
  try { return await response.json() as T } catch (error) {
    if (options.signal?.aborted) throw error
    throw new ApiError(0, 'response_incomplete', 'The server response was incomplete. The operation may have succeeded; retry with the retained original key.')
  }
}
export const apiPath = (path: string) => `/api/v1${path}`
export const segment = encodeURIComponent
export const uncertain = (error: unknown) => error instanceof ApiError && (error.status === 0 || error.status >= 500)
export const isNotFound = (error: unknown) => error instanceof ApiError && error.status === 404
/** Query retry policy for resources that can disappear: a 404 is definitive, so surface it at once. */
export const retryUnlessNotFound = (failureCount: number, error: unknown) => !isNotFound(error) && failureCount < 3
