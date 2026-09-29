// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest'
import { validatePublicPath } from './publicPathValidation'

describe('validatePublicPath', () => {
  it('requires a path', () => {
    expect(validatePublicPath('', [])).toBe('Enter a path.')
    expect(validatePublicPath('   ', [])).toBe('Enter a path.')
  })

  it('requires a leading slash', () => {
    expect(validatePublicPath('healthz', [])).toBe('Paths start with /.')
  })

  it('rejects whitespace inside the path', () => {
    expect(validatePublicPath('/health check', [])).toBe('Paths cannot contain spaces.')
  })

  it('allows a trailing /* wildcard', () => {
    expect(validatePublicPath('/api/webhooks/*', [])).toBeUndefined()
  })

  it('rejects a wildcard that is not a trailing /*', () => {
    expect(validatePublicPath('/api/*/webhooks', [])).toBe('A wildcard is only allowed as a final /*.')
    expect(validatePublicPath('/api*', [])).toBe('A wildcard is only allowed as a final /*.')
  })

  it('rejects a bare /* as exempting everything', () => {
    expect(validatePublicPath('/*', [])).toBe('That makes every path public. Turn off sign-in instead.')
  })

  it('rejects a path already in the list', () => {
    expect(validatePublicPath('/healthz', ['/healthz'])).toBe('This path is already public.')
  })

  it('trims surrounding whitespace before checking', () => {
    expect(validatePublicPath('  /healthz  ', [])).toBeUndefined()
  })

  it('accepts a plain exact path', () => {
    expect(validatePublicPath('/healthz', [])).toBeUndefined()
    expect(validatePublicPath('/robots.txt', ['/healthz'])).toBeUndefined()
  })
})
