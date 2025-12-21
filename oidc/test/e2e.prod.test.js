import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createProviderServer } from '../src/provider.js'

let server
const port = 4013
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
  const prev = process.env.NODE_ENV
  process.env.NODE_ENV = 'production'
  const created = await createProviderServer({ issuer, port })
  server = created.server
  process.env.NODE_ENV = prev
})

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve))
})

describe('Production resume redirects to client redirect_uri', () => {
  it('completes login+consent and reaches redirect_uri', async () => {
    const client_id = 'mvp-client'
    const redirect_uri = 'http://127.0.0.1:3000/callback'
    const state = 'st-' + Math.random().toString(36).slice(2)
    const nonce = 'n-' + Math.random().toString(36).slice(2)
    const code_verifier = 'v-' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2)
    const challengeBytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code_verifier))
    const code_challenge = Buffer.from(new Uint8Array(challengeBytes)).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')

    const authUrl = `${issuer}/auth?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code&scope=openid&state=${encodeURIComponent(state)}&nonce=${encodeURIComponent(nonce)}&code_challenge=${encodeURIComponent(code_challenge)}&code_challenge_method=S256`
    const res1 = await fetch(authUrl, { redirect: 'manual' })
    expect([302, 303]).toContain(res1.status)
    let nextLoc = res1.headers.get('location')
    let cookies = mergeCookieHeader('', getSetCookies(res1.headers))

    // interaction GET
    const resGet = await fetch(new URL(nextLoc, issuer), { headers: { cookie: cookies } })
    expect(resGet.status).toBe(200)
    cookies = mergeCookieHeader(cookies, getSetCookies(resGet.headers))

    // interaction POST (no payload required; provider auto-continues)
    const uid = new URL(nextLoc, issuer).pathname.split('/').pop()
    const form = new URLSearchParams()
    form.set('uid', uid)
    const resPost = await fetch(new URL(nextLoc, issuer), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookies },
      body: form.toString(),
      redirect: 'manual'
    })
    expect([302, 303]).toContain(resPost.status)
    nextLoc = resPost.headers.get('location')
    cookies = mergeCookieHeader(cookies, getSetCookies(resPost.headers))

    // follow /interaction and /auth until final redirect_uri
    for (let i = 0; i < 20; i++) {
      const url = new URL(nextLoc, issuer)
      const path = url.pathname
      if (path.startsWith('/interaction/') || path.startsWith('/auth/')) {
        const resN = await fetch(url, { redirect: 'manual', headers: { cookie: cookies } })
        expect([302, 303]).toContain(resN.status)
        nextLoc = resN.headers.get('location')
        cookies = mergeCookieHeader(cookies, getSetCookies(resN.headers))
      } else {
        break
      }
    }
    expect(nextLoc).toContain(redirect_uri)
    const cb = new URL(nextLoc)
    expect(cb.searchParams.get('code')).toBeTruthy()
    expect(cb.searchParams.get('state')).toBe(state)
  })
})


