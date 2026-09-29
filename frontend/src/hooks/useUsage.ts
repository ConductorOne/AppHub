import { useQuery } from '@tanstack/react-query'
import { apiPath, request, segment } from '../services/api'
import type { Usage, UsageRange } from '../services/types'

const USAGE_REFETCH_MS = 60_000

export function useUsage(id: string, range: UsageRange) {
  return useQuery({
    queryKey: ['usage', id, range],
    queryFn: ({ signal }) => request<Usage>(apiPath(`/applications/${segment(id)}/usage?range=${range}`), { signal }),
    refetchInterval: USAGE_REFETCH_MS,
  })
}
