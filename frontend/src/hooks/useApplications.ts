import { useCallback } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { apiPath, isNotFound, request, retryUnlessNotFound, segment, uncertain } from '../services/api'
import { clearOperation, loadOperation, retainOperation } from '../services/operations'
import type { Accepted, Application, ApplicationSummary, ApplicationSummaryPage, Applications, Category, Target } from '../services/types'

const LIST_POLL_WHILE_DELETING_MS = 5000
const READ_ONLY_ACTIONS = ['applications:write', 'deployments:write', 'applications:delete']

export function useTargets() {
  return useQuery({ queryKey: ['targets'], queryFn: ({ signal }) => request<Target[]>(apiPath('/targets'), { signal }), staleTime: 10_000 })
}
export function useCategories() {
  return useQuery({ queryKey: ['categories'], queryFn: ({ signal }) => request<Category[]>(apiPath('/categories'), { signal }), staleTime: 5 * 60_000 })
}
function anyDeleting(pages?: { items: { status: Application['status'] }[] }[]) {
  return pages?.some(page => page.items.some(item => item.status === 'deleting')) ? LIST_POLL_WHILE_DELETING_MS : false
}
export function useApplications(all: boolean) {
  return useInfiniteQuery({ queryKey: ['applications', { all }], initialPageParam: '',
    queryFn: ({ signal, pageParam }) => request<Applications>(apiPath(`/applications?limit=50&all=${all}&cursor=${segment(pageParam)}`), { signal }),
    getNextPageParam: page => page.cursor || undefined, refetchInterval: query => anyDeleting(query.state.data?.pages) })
}
/** Poll while work is in flight. A failed teardown keeps its operation active but is settled, so it stops polling. */
function applicationPollInterval(app: Application | undefined, error: unknown) {
  if (!app || isNotFound(error)) return false
  if (app.status === 'deleting') return 2000
  return app.activeDeploymentId && app.status !== 'interrupted' && app.status !== 'deletion_failed' ? 2000 : false
}
export function useApplication(id: string) {
  return useQuery({ queryKey: ['application', id], queryFn: ({ signal }) => request<Application>(apiPath(`/applications/${segment(id)}`), { signal }),
    retry: retryUnlessNotFound, refetchInterval: query => applicationPollInterval(query.state.data, query.state.error) })
}
export function useDirectory() {
  return useInfiniteQuery({ queryKey: ['directory'], initialPageParam: '',
    queryFn: ({ signal, pageParam }) => request<ApplicationSummaryPage>(apiPath(`/directory/applications?limit=50&cursor=${segment(pageParam)}`), { signal }),
    getNextPageParam: page => page.cursor || undefined, refetchInterval: query => anyDeleting(query.state.data?.pages) })
}
export function useDirectoryEntry(id: string, enabled: boolean) {
  return useQuery({ queryKey: ['directoryEntry', id], enabled,
    queryFn: ({ signal }) => request<ApplicationSummary>(apiPath(`/directory/applications/${segment(id)}`), { signal }) })
}

/** Router state the applications list reads to confirm why the user landed there, e.g. a finished deletion. */
export type ListNotice = { notice: string }

/** Leave an application's pages for the list, which shows `notice` as a confirmation. */
export function useLeaveApplication() {
  const client = useQueryClient()
  const navigate = useNavigate()
  return useCallback((notice: string) => {
    void client.invalidateQueries({ queryKey: ['applications'] }); void client.invalidateQueries({ queryKey: ['directory'] })
    const state: ListNotice = { notice }
    navigate('/applications', { replace: true, state })
  }, [client, navigate])
}

/** Leave a deleted application's pages for the list, which confirms the deletion. */
export function useFinishDeletion() {
  const leave = useLeaveApplication()
  return useCallback((name: string) => leave(`${name} and its resources were deleted.`), [leave])
}

/** 202 queues a teardown; 204 (a never-deployed draft) means the application is already gone. */
export async function deleteApplication(application: Application) {
  const slot = `delete.${application.id}`
  const operation = retainOperation(slot, { confirmName: application.specification.name })
  try {
    const accepted = await request<Accepted | undefined>(apiPath(`/applications/${segment(application.id)}/deletion`), { method: 'POST', body: operation.input, headers: { 'Idempotency-Key': operation.key } })
    clearOperation(slot)
    return accepted
  } catch (error) { if (!uncertain(error)) clearOperation(slot); throw error }
}

function markDeleting(app: Application, accepted: Accepted): Application {
  return { ...app, status: 'deleting', activeDeploymentId: accepted.deploymentId, latestDeploymentId: accepted.deploymentId,
    deletionRequestedAt: app.deletionRequestedAt ?? new Date().toISOString(),
    permittedActions: app.permittedActions.filter(action => !READ_ONLY_ACTIONS.includes(action)) }
}

/** Request (or retry) deletion. The page switches to its deleting state as soon as the teardown is accepted. */
export function useDeleteApplication(application: Application) {
  const client = useQueryClient()
  const finish = useFinishDeletion()
  const mutation = useMutation({ mutationFn: () => deleteApplication(application), onSuccess: accepted => {
    if (!accepted) { finish(application.specification.name); return }
    client.setQueryData<Application>(['application', application.id], current => current && markDeleting(current, accepted))
    void client.invalidateQueries({ queryKey: ['application', application.id] }); void client.invalidateQueries({ queryKey: ['applications'] })
    void client.invalidateQueries({ queryKey: ['directory'] }); void client.invalidateQueries({ queryKey: ['deployments', application.id] })
    void client.invalidateQueries({ queryKey: ['deployment', accepted.deploymentId] })
  } })
  const pending = loadOperation<{ confirmName: string }>(`delete.${application.id}`)
  return { mutation, pending }
}
