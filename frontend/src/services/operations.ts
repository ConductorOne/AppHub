// Only recovery identifiers and submitted specifications go in session storage, never credentials.
// Keeping these per tab allows a reload after an uncertain response to reuse the exact request.
export interface PendingOperation<T> { key: string; input: T }
let owner = ''
export function setOperationOwner(userId: string) { owner = userId }
export function loadOperation<T>(slot: string): PendingOperation<T> | undefined {
  try { const raw = sessionStorage.getItem(`apphub.operation.${owner}.${slot}`); return raw ? JSON.parse(raw) : undefined } catch { return undefined }
}
export function retainOperation<T>(slot: string, input: T): PendingOperation<T> {
  const previous = loadOperation<T>(slot)
  if (previous) return previous
  const operation = { key: crypto.randomUUID(), input }
  sessionStorage.setItem(`apphub.operation.${owner}.${slot}`, JSON.stringify(operation))
  return operation
}
export function clearOperation(slot: string) { sessionStorage.removeItem(`apphub.operation.${owner}.${slot}`) }
