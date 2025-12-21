import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createProviderServer } from '../src/provider.js'

let server
const port = 4012
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
  const created = await createProviderServer({ issuer, port })
  server = created.server
})

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve))
})

describe('Authorization Code + PKCE token exchange', () => {
  it('issues code and exchanges for tokens', async () => {
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

    // open interaction
    const resGet = await fetch(new URL(nextLoc, issuer), { headers: { cookie: cookies } })
    expect(resGet.status).toBe(200)
    cookies = mergeCookieHeader(cookies, getSetCookies(resGet.headers))

    // post interaction (auto-continue)
    const form = new URLSearchParams()
    const uid = String(new URL(nextLoc, issuer).pathname.split('/').pop())
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

    // follow redirects until final redirect_uri with code
    for (let i = 0; i < 10; i++) {
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
    const code = cb.searchParams.get('code')
    expect(code).toBeTruthy()
    expect(cb.searchParams.get('state')).toBe(state)

    // token exchange
    const tokenBody = new URLSearchParams()
    tokenBody.set('grant_type', 'authorization_code')
    tokenBody.set('code', code)
    tokenBody.set('redirect_uri', redirect_uri)
    tokenBody.set('code_verifier', code_verifier)
    const basic = Buffer.from(`${client_id}:mvp-secret`, 'utf-8').toString('base64')
    const resToken = await fetch(`${issuer}/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'authorization': `Basic ${basic}`
      },
      body: tokenBody.toString()
    })
    expect(resToken.status).toBe(200)
    const tokens = await resToken.json()
    expect(tokens.id_token).toBeTypeOf('string')
    expect(tokens.access_token).toBeTypeOf('string')
    expect(tokens.token_type).toBe('Bearer')
  })
})


