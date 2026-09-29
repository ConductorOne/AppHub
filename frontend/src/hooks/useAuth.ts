import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request, setCSRF } from '../services/api'
import type { User } from '../services/types'
import { setOperationOwner } from '../services/operations'
export function useAuth() {
  return useQuery({ queryKey: ['currentUser'], queryFn: async ({ signal }) => {
    const user = await request<User>('/api/v1/users/me', { signal })
    setCSRF(user.csrfToken || '')
    setOperationOwner(user.id)
    return user
  }, retry: false, staleTime: 30_000, refetchOnWindowFocus: 'always' })
}
export function useLogout() {
  const client = useQueryClient()
  return useMutation({ mutationFn: () => request<void>('/auth/logout', { method: 'POST' }),
    onSuccess: () => { setCSRF(''); client.clear(); window.location.assign('/login') } })
}
