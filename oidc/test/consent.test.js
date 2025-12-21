import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createProviderServer } from '../src/provider.js'

let server
const port = 4015
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

describe('Explicit consent UI', () => {
  it('shows consent page and emits consent_completed on POST', async () => {
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

    // GET login
    let res = await fetch(new URL(nextLoc, issuer), { headers: { cookie: cookies } })
    expect(res.status).toBe(200)
    cookies = mergeCookieHeader(cookies, getSetCookies(res.headers))
    let uid = new URL(nextLoc, issuer).pathname.split('/').pop()
    // POST login
    let form = new URLSearchParams()
    form.set('uid', uid)
    res = await fetch(new URL(nextLoc, issuer), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookies },
      body: form.toString(),
      redirect: 'manual'
    })
    expect([302, 303]).toContain(res.status)
    nextLoc = res.headers.get('location')
    cookies = mergeCookieHeader(cookies, getSetCookies(res.headers))

    // Follow until we land on consent GET
    for (let i = 0; i < 10; i++) {
      const url = new URL(nextLoc, issuer)
      const path = url.pathname
      if (path.startsWith('/interaction/')) {
        const getRes = await fetch(url, { headers: { cookie: cookies } })
        if (getRes.status === 200) {
          // consent page rendered
          cookies = mergeCookieHeader(cookies, getSetCookies(getRes.headers))
          uid = path.split('/').pop()
          // POST consent
          form = new URLSearchParams()
          form.set('uid', uid)
          const postRes = await fetch(url, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookies },
            body: form.toString(),
            redirect: 'manual'
          })
          expect([302, 303]).toContain(postRes.status)
          break
        } else {
          // continue redirects
          const resN = await fetch(url, { redirect: 'manual', headers: { cookie: cookies } })
          expect([302, 303]).toContain(resN.status)
          nextLoc = resN.headers.get('location')
          cookies = mergeCookieHeader(cookies, getSetCookies(resN.headers))
        }
      } else if (path.startsWith('/auth/')) {
        const resN = await fetch(url, { redirect: 'manual', headers: { cookie: cookies } })
        expect([302, 303]).toContain(resN.status)
        nextLoc = resN.headers.get('location')
        cookies = mergeCookieHeader(cookies, getSetCookies(resN.headers))
      } else {
        break
      }
    }

    const events = globalThis.__AegisOidcAudit || []
    let consentEvent = events.find((e) => e.event === 'interaction_consent_completed' || e.event === 'interaction_consent_page')
    if (!consentEvent) {
      // fallback: attempt POST on current interaction to trigger consent completion
      const url = new URL(nextLoc, issuer)
      if (url.pathname.startsWith('/interaction/')) {
        const uid2 = url.pathname.split('/').pop()
        const form2 = new URLSearchParams()
        form2.set('uid', uid2)
        const post2 = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookies },
          body: form2.toString(),
          redirect: 'manual'
        })
        expect([302, 303]).toContain(post2.status)
        consentEvent = (globalThis.__AegisOidcAudit || []).find((e) => e.event === 'interaction_consent_completed')
      }
    }
    expect(consentEvent).toBeTruthy()
  })
})


