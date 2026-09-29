import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiPath, request, segment } from '../services/api'
import type { AuditPage, DirectoryEntitlement, FeatureFlag, FeatureFlagInput, GitHubAppConfigInput, GitHubAppManifestInput, GitHubAppManifestStart, GitHubAppStatus, LogQueryParams, LogResult, Member, RoleMapping, RoleMappingInput } from '../services/types'

export function useMembers() {
  return useQuery({ queryKey: ['workspace', 'members'], queryFn: ({ signal }) => request<Member[]>(apiPath('/admin/members'), { signal }) })
}

export function useGitHubAppStatus() {
  return useQuery({ queryKey: ['workspace', 'github-app'], queryFn: ({ signal }) => request<GitHubAppStatus>(apiPath('/admin/github-app'), { signal }) })
}

export function useSetGitHubAppConfig() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input: GitHubAppConfigInput) => request<GitHubAppStatus>(apiPath('/admin/github-app'), { method: 'PUT', body: input }),
    onSuccess: status => client.setQueryData(['workspace', 'github-app'], status),
  })
}

export function useStartGitHubAppManifest() {
  return useMutation({
    mutationFn: (input: GitHubAppManifestInput) => request<GitHubAppManifestStart>(apiPath('/admin/github-app/manifest'), { method: 'POST', body: input }),
  })
}

export function useForgetInstallation() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => request<void>(apiPath(`/admin/github-app/installations/${segment(id)}`), { method: 'DELETE' }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['workspace', 'github-app'] }),
  })
}

export function useDirectoryEntitlements() {
  return useQuery({ queryKey: ['workspace', 'directory-entitlements'], queryFn: ({ signal }) => request<DirectoryEntitlement[]>(apiPath('/admin/directory/entitlements'), { signal }) })
}

export function useRoleMappings() {
  return useQuery({ queryKey: ['workspace', 'role-mappings'], queryFn: ({ signal }) => request<RoleMapping[]>(apiPath('/admin/role-mappings'), { signal }) })
}

export function useSetRoleMapping() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ entitlementId, input }: { entitlementId: string; input: RoleMappingInput }) =>
      request<RoleMapping>(apiPath(`/admin/role-mappings/${segment(entitlementId)}`), { method: 'PUT', body: input }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['workspace', 'role-mappings'] })
      void client.invalidateQueries({ queryKey: ['currentUser'] })
    },
  })
}

export function useDeleteRoleMapping() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (entitlementId: string) => request<void>(apiPath(`/admin/role-mappings/${segment(entitlementId)}`), { method: 'DELETE' }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['workspace', 'role-mappings'] })
      void client.invalidateQueries({ queryKey: ['currentUser'] })
    },
  })
}

export function useFeatureFlags() {
  return useQuery({ queryKey: ['workspace', 'feature-flags'], queryFn: ({ signal }) => request<FeatureFlag[]>(apiPath('/admin/feature-flags'), { signal }) })
}

export function useSetFeatureFlag() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ key, input }: { key: string; input: FeatureFlagInput }) =>
      request<FeatureFlag>(apiPath(`/admin/feature-flags/${segment(key)}`), { method: 'PUT', body: input }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['workspace', 'feature-flags'] })
      void client.invalidateQueries({ queryKey: ['currentUser'] })
    },
  })
}

export function useAuditLogs() {
  return useInfiniteQuery({
    queryKey: ['workspace', 'audit-logs'],
    initialPageParam: '',
    queryFn: ({ signal, pageParam }) => request<AuditPage>(apiPath(`/admin/audit-logs?limit=50${pageParam ? `&cursor=${segment(pageParam)}` : ''}`), { signal }),
    getNextPageParam: page => page.cursor || undefined,
  })
}

export function useLogGroups() {
  return useQuery({ queryKey: ['workspace', 'log-groups'], queryFn: ({ signal }) => request<string[]>(apiPath('/admin/log-groups'), { signal }) })
}

export function useLogs(name: string, params: LogQueryParams, enabled: boolean) {
  const query = new URLSearchParams()
  if (params.start) query.set('start', params.start)
  if (params.end) query.set('end', params.end)
  if (params.filter) query.set('filter', params.filter)
  return useQuery({
    queryKey: ['workspace', 'logs', name, params.start, params.end, params.filter],
    queryFn: ({ signal }) => request<LogResult>(apiPath(`/admin/logs/${segment(name)}?${query.toString()}`), { signal }),
    enabled: enabled && !!name,
    refetchInterval: query_ => (query_.state.data ? 10_000 : false),
  })
}
