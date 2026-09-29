import { apiPath, request, segment } from './api'
import type { Detection, DetectionAccepted } from './types'

const POLL_TIMEOUT_MS = 20_000

// Queue and poll an advisory repository scan for the "simple deploy" flow.
// Entirely best-effort: a caller must treat a rejected promise, or a
// terminal 'failed' state, as "nothing detected" and fall back to its own
// defaults, never as a hard error that blocks application creation.
export async function detectRepository(targetId: string, url: string, ref = ''): Promise<Detection> {
  const accepted = await request<DetectionAccepted>(apiPath(`/targets/${segment(targetId)}/detect`), { method: 'POST', body: { url, ref } })
  const deadline = Date.now() + POLL_TIMEOUT_MS
  let view = await request<Detection>(apiPath(`/detections/${segment(accepted.detectionId)}`))
  while (!view.terminal && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, view.pollAfterMs || 1000))
    view = await request<Detection>(apiPath(`/detections/${segment(accepted.detectionId)}`))
  }
  return view
}
