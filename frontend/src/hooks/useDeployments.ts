import { useQuery } from '@tanstack/react-query'
import { apiPath, isNotFound, request, retryUnlessNotFound, segment } from '../services/api'
import type { Deployment, Deployments } from '../services/types'

const DEPLOYMENT_HISTORY_LIMIT = 10

export function useDeployment(id: string) {
  return useQuery({ queryKey: ['deployment', id], enabled: !!id, queryFn: ({ signal }) => request<Deployment>(apiPath(`/deployments/${segment(id)}`), { signal }),
    retry: retryUnlessNotFound, refetchInterval: query => !isNotFound(query.state.error) && ['queued', 'running'].includes(query.state.data?.state || '') ? 2000 : false })
}
export function useDeployments(id: string) {
  return useQuery({ queryKey: ['deployments', id],
    queryFn: ({ signal }) => request<Deployments>(apiPath(`/applications/${segment(id)}/deployments?limit=${DEPLOYMENT_HISTORY_LIMIT}`), { signal }) })
}
