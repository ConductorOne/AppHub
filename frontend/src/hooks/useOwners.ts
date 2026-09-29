import { keepPreviousData, type QueryClient, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiPath, isNotFound, request, segment } from '../services/api'
import type { Application, OwnerInput, OwnerList, PrincipalSearchResult } from '../services/types'
import { useLeaveApplication } from './useApplications'

const ownersPath = (appId: string) => apiPath(`/applications/${segment(appId)}/owners`)

export function useOwners(appId: string) {
  return useQuery({ queryKey: ['owners', appId], queryFn: ({ signal }) => request<OwnerList>(ownersPath(appId), { signal }) })
}

/** Users and directory groups matching `q`, at most 25 of each. An empty query is not sent. */
export function usePrincipalSearch(q: string) {
  const term = q.trim()
  return useQuery({ queryKey: ['principals', term], enabled: term !== '', staleTime: 30_000, placeholderData: keepPreviousData,
    queryFn: ({ signal }) => request<PrincipalSearchResult>(apiPath(`/directory/principals?q=${segment(term)}`), { signal }) })
}

function refreshOwners(client: QueryClient, appId: string, owners: OwnerList) {
  client.setQueryData(['owners', appId], owners)
  void client.invalidateQueries({ queryKey: ['owners', appId] }); void client.invalidateQueries({ queryKey: ['application', appId] })
  void client.invalidateQueries({ queryKey: ['applications'] }); void client.invalidateQueries({ queryKey: ['directory'] })
  void client.invalidateQueries({ queryKey: ['directoryEntry', appId] })
}

/** Adding an existing owner is a no-op. Owner changes do not create a revision. */
export function useAddOwner(appId: string) {
  const client = useQueryClient()
  return useMutation({ mutationFn: (owner: OwnerInput) => request<OwnerList>(ownersPath(appId), { method: 'POST', body: owner }),
    onSuccess: owners => refreshOwners(client, appId, owners) })
}

/** Whether the caller can still open the application in full. Any failure but a 404 leaves them on the page to find out. */
async function stillOpens(appId: string) {
  try { await request<Application>(apiPath(`/applications/${segment(appId)}`)); return true } catch (error) { return !isNotFound(error) }
}

export type OwnerRemoval = { key: string; self: boolean; appName: string }

/** The server refuses to remove the last owner. Removing yourself without another route to access leaves for the list. */
export function useRemoveOwner(appId: string) {
  const client = useQueryClient()
  const leave = useLeaveApplication()
  return useMutation({
    mutationFn: async ({ key, self }: OwnerRemoval) => {
      const owners = await request<OwnerList>(`${ownersPath(appId)}/${segment(key)}`, { method: 'DELETE' })
      return { owners, lostAccess: self && !(await stillOpens(appId)) }
    },
    onSuccess: ({ owners, lostAccess }, { appName }) => {
      if (!lostAccess) { refreshOwners(client, appId, owners); return }
      leave(`You are no longer an owner of ${appName}.`)
      client.removeQueries({ queryKey: ['application', appId] }); client.removeQueries({ queryKey: ['owners', appId] })
      void client.invalidateQueries({ queryKey: ['directoryEntry', appId] })
    },
  })
}
