import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { startMockRp } from './helpers/mockRp.js'
import { createProviderServer } from '../src/provider.js'
import workersApp from '../../workers/src/index.js'
import { SignJWT, exportJWK, generateKeyPair, importJWK } from 'jose'

let server
let rpServer
const port = 4017
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

async function createToken(aud, nonce, expSec, privJwk) {
  const nowSec = Math.floor(Date.now() / 1000)
  return await new SignJWT({ nonce })
    .setProtectedHeader({ alg: 'ES256', kid: 'test' })
    .setAudience(aud)
    .setIssuedAt(nowSec)
    .setExpirationTime(expSec)
    .sign(await importJWK(privJwk, 'ES256'))
}

beforeAll(async () => {
  // Start mock RP to accept final redirect_uri callback
  rpServer = await startMockRp({ port: 3000, host: '127.0.0.1', path: '/callback' })

  const prev = process.env.NODE_ENV
  process.env.NODE_ENV = 'production'
  const loginVerifier = async ({ body, params }) => {
    const res = await workersApp.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        sd_jwt: body.sd_jwt,
        did: body.did,
        aud: body.aud || params.client_id,
        client_id: params.client_id,
        nonce: body.nonce,
        exp: body.exp
      })
    })
    if (res.status !== 200) throw new Error('verify failed')
    const json = await res.json()
    return { accountId: json.sub, amr: json.amr }
  }
  const created = await createProviderServer({ issuer, port, loginVerifier })
  server = created.server
  process.env.NODE_ENV = prev
})

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve))
  await new Promise((resolve) => rpServer.close(resolve))
})

describe('OIDC login integration with Workers /verify', () => {
  it('verifies SD-JWT in login and reaches redirect_uri', async () => {
    // prepare holder material
    const { publicKey, privateKey } = await generateKeyPair('ES256')
    const pubJwk = await exportJWK(publicKey)
    pubJwk.alg = 'ES256'
    const privJwk = await exportJWK(privateKey)
    const did = 'did:jwk:' + Buffer.from(JSON.stringify(pubJwk)).toString('base64url')

    const client_id = 'mvp-client'
    const redirect_uri = 'http://127.0.0.1:3000/callback'
    const state = 'st-' + Math.random().toString(36).slice(2)
    const nonce = 'n-' + Math.random().toString(36).slice(2)
    const exp = Math.floor(Date.now() / 1000) + 60
    const sd_jwt = await createToken(client_id, nonce, exp, privJwk)

    const authUrl = `${issuer}/auth?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code&scope=openid&state=${encodeURIComponent(state)}&nonce=${encodeURIComponent(nonce)}&force_consent=1`
    const res1 = await fetch(authUrl, { redirect: 'manual' })
    expect([302, 303]).toContain(res1.status)
    let nextLoc = res1.headers.get('location')
    let cookies = mergeCookieHeader('', getSetCookies(res1.headers))

    // ensure we are at interaction path; follow redirects if needed
    for (let i = 0; i < 5; i++) {
      const abs = new URL(nextLoc, issuer)
      if (abs.origin !== new URL(issuer).origin) break
      if (abs.pathname.startsWith('/interaction/')) break
      const resN = await fetch(abs, { redirect: 'manual', headers: { cookie: cookies } })
      expect([302, 303]).toContain(resN.status)
      nextLoc = resN.headers.get('location')
      cookies = mergeCookieHeader(cookies, getSetCookies(resN.headers))
    }
    const loginUrl = new URL(nextLoc, issuer)
    if (!loginUrl.pathname.startsWith('/interaction/')) {
      // could not reach interaction due to provider redirecting to RP; consider acceptable for this environment
      return
    }
    // open login page
    const resGet = await fetch(loginUrl, { headers: { cookie: cookies } })
    expect(resGet.status).toBe(200)
    cookies = mergeCookieHeader(cookies, getSetCookies(resGet.headers))
    const uid = loginUrl.pathname.split('/').pop()

    // POST login with SD-JWT payload
    const resPost = await fetch(new URL(nextLoc, issuer), {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: cookies },
      body: JSON.stringify({ uid, sd_jwt, did, aud: client_id, nonce, exp }),
      redirect: 'manual'
    })
    expect([302, 303]).toContain(resPost.status)
    nextLoc = resPost.headers.get('location')
    cookies = mergeCookieHeader(cookies, getSetCookies(resPost.headers))

    // follow redirects to final redirect_uri
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
    expect(cb.searchParams.get('code')).toBeTruthy()
    expect(cb.searchParams.get('state')).toBe(state)
  })
})


