import { useQuery } from '@tanstack/react-query'
import { apiPath, request, segment } from '../services/api'
import type { SecretList } from '../services/types'

/** Secret names and metadata for an application. Values are never returned by the API. */
export function useSecrets(id: string) {
  return useQuery({ queryKey: ['secrets', id], queryFn: ({ signal }) => request<SecretList>(apiPath(`/applications/${segment(id)}/secrets`), { signal }) })
}
