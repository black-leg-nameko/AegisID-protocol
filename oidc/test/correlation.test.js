import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createProviderServer } from '../src/provider.js'

let server
const port = 4016
const issuer = `http://127.0.0.1:${port}`

function getSetCookies(headers) {
  const raw = typeof headers.raw === 'function' ? headers.raw() : null
  if (raw && raw['set-cookie'] && Array.isArray(raw['set-cookie'])) return raw['set-cookie']
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie()
  const single = headers.get('set-cookie')
  return single ? [single] : []
}
function mergeCookieHeader(existingHeader, newSetCookies) {
  const map = new Map()
  if (existingHeader) {
    existingHeader.split(';').forEach((seg) => {
      const [name, value] = seg.split('=')
      if (name && typeof value !== 'undefined') map.set(name.trim(), value.trim())
    })
  }
  for (const c of newSetCookies || []) {
    const [pair] = String(c).split(';')
    const [name, value] = pair.split('=')
    if (name && typeof value !== 'undefined') map.set(name.trim(), value.trim())
  }
  return Array.from(map.entries()).map(([k, v]) => `${k}=${v}`).join('; ')
}

beforeAll(async () => {
  globalThis.__AegisOidcAudit = []
  const created = await createProviderServer({ issuer, port })
  server = created.server
})

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve))
})

describe('Correlation ID propagation', () => {
  it('propagates X-Correlation-ID through audit and state/redirect', async () => {
    const client_id = 'mvp-client'
    const redirect_uri = 'http://127.0.0.1:3000/callback'
    const correlationId = 'cid-e2e-' + Math.random().toString(36).slice(2, 8)
    const state = correlationId
    const nonce = 'n-' + Math.random().toString(36).slice(2)
    const code_verifier = 'v-' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2)
    const challengeBytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code_verifier))
    const code_challenge = Buffer.from(new Uint8Array(challengeBytes)).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')

    const authUrl = `${issuer}/auth?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code&scope=openid&state=${encodeURIComponent(state)}&nonce=${encodeURIComponent(nonce)}&code_challenge=${encodeURIComponent(code_challenge)}&code_challenge_method=S256`
    const res1 = await fetch(authUrl, { redirect: 'manual', headers: { 'x-correlation-id': correlationId } })
    expect([302, 303]).toContain(res1.status)
    let nextLoc = res1.headers.get('location')
    let cookies = mergeCookieHeader('', getSetCookies(res1.headers))

    // GET login
    let res = await fetch(new URL(nextLoc, issuer), { headers: { cookie: cookies, 'x-correlation-id': correlationId } })
    expect(res.status).toBe(200)
    cookies = mergeCookieHeader(cookies, getSetCookies(res.headers))
    let uid = new URL(nextLoc, issuer).pathname.split('/').pop()
    // POST login
    let form = new URLSearchParams()
    form.set('uid', uid)
    res = await fetch(new URL(nextLoc, issuer), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookies, 'x-correlation-id': correlationId },
      body: form.toString(),
      redirect: 'manual'
    })
    expect([302, 303]).toContain(res.status)
    nextLoc = res.headers.get('location')
    cookies = mergeCookieHeader(cookies, getSetCookies(res.headers))

    // follow redirects to final redirect_uri
    for (let i = 0; i < 10; i++) {
      const url = new URL(nextLoc, issuer)
      const path = url.pathname
      if (path.startsWith('/interaction/') || path.startsWith('/auth/')) {
        const resN = await fetch(url, { redirect: 'manual', headers: { cookie: cookies, 'x-correlation-id': correlationId } })
        expect([302, 303]).toContain(resN.status)
        nextLoc = resN.headers.get('location')
        cookies = mergeCookieHeader(cookies, getSetCookies(resN.headers))
      } else {
        break
      }
    }
    const cb = new URL(nextLoc)
    expect(cb.origin + cb.pathname).toBe(redirect_uri)
    expect(cb.searchParams.get('state')).toBe(correlationId)

    const events = globalThis.__AegisOidcAudit || []
    expect(events.find((e) => e.correlationId === correlationId && e.event === 'interaction_start')).toBeTruthy()
    expect(events.find((e) => e.correlationId === correlationId && e.event === 'interaction_login_completed')).toBeTruthy()
  })
})


