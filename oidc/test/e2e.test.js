import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createProviderServer } from '../src/provider.js'
import workersApp, { derivePairwiseSub } from '../../workers/src/index.js'
import { SignJWT, exportJWK, generateKeyPair, importJWK } from 'jose'

const providerPort = 4011
const issuer = `http://127.0.0.1:${providerPort}`

let server

function getSetCookies(headers) {
  // undici provides headers.raw(), node-fetch has raw() too
  const raw = typeof headers.raw === 'function' ? headers.raw() : null
  if (raw && raw['set-cookie'] && Array.isArray(raw['set-cookie'])) {
    return raw['set-cookie']
  }
  if (typeof headers.getSetCookie === 'function') {
    return headers.getSetCookie()
  }
  const single = headers.get('set-cookie')
  return single ? [single] : []
}

function mergeCookieHeader(existingHeader, newSetCookies) {
  const map = new Map()
  const pushPair = (pair) => {
    const [name, value] = String(pair).split('=')
    if (!name || typeof value === 'undefined') return
    map.set(name.trim(), value.trim())
  }
  if (existingHeader) {
    existingHeader.split(';').forEach((seg) => {
      const [name, value] = seg.split('=')
      if (name && typeof value !== 'undefined') {
        map.set(name.trim(), value.trim())
      }
    })
  }
  for (const c of newSetCookies || []) {
    const [pair] = String(c).split(';')
    pushPair(pair)
  }
  return Array.from(map.entries()).map(([k, v]) => `${k}=${v}`).join('; ')
}
function toB64Url(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  const base64 = Buffer.from(bin, 'binary').toString('base64').replace(/=+$/, '')
  return base64.replace(/\+/g, '-').replace(/\//g, '_')
}
function didFromPublicJwk(jwk) {
  const json = Buffer.from(JSON.stringify(jwk), 'utf-8')
  return 'did:jwk:' + json.toString('base64url')
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
  const loginVerifier = async ({ body, params }) => {
    const { sd_jwt, did, aud, client_id, nonce, exp } = body || {}
    const res = await workersApp.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sd_jwt, did, aud, client_id, nonce, exp })
    })
    if (res.status !== 200) {
      const t = await res.text()
      // eslint-disable-next-line no-console
      console.error('VERIFY_ERR:', res.status, t)
      throw new Error('verify failed')
    }
    const json = await res.json()
    return { accountId: json.sub, amr: json.amr }
  }
  const created = await createProviderServer({ issuer, port: providerPort, loginVerifier })
  server = created.server
})

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve))
})

describe('E2E: OIDC login via Workers /verify', () => {
  it('completes login interaction and redirects with code', async () => {
    // prepare holder material
    const { publicKey, privateKey } = await generateKeyPair('ES256')
    const pubJwk = await exportJWK(publicKey)
    pubJwk.alg = 'ES256'
    const privJwk = await exportJWK(privateKey)
    const did = didFromPublicJwk(pubJwk)

    const client_id = 'mvp-client'
    const aud = client_id
    const redirect_uri = 'http://127.0.0.1:3000/callback'
    const state = 'st-' + Math.random().toString(36).slice(2)
    const nonce = 'n-' + Math.random().toString(36).slice(2)
    const exp = Math.floor(Date.now() / 1000) + 60
    const sd_jwt = await createToken(aud, nonce, exp, privJwk)

    // start authorization to create interaction (PKCE required by default)
    const code_verifier = 'v-' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2)
    const challengeBytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code_verifier))
    const code_challenge = Buffer.from(new Uint8Array(challengeBytes)).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
    const authUrl = `${issuer}/auth?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code&scope=openid&state=${encodeURIComponent(state)}&nonce=${encodeURIComponent(nonce)}&code_challenge=${encodeURIComponent(code_challenge)}&code_challenge_method=S256`
    const res1 = await fetch(authUrl, { redirect: 'manual' })
    if (res1.status !== 302 && res1.status !== 303) {
      const txt = await res1.text()
      // eslint-disable-next-line no-console
      console.error('AUTH_ERR:', txt.slice(0, 500))
    }
    expect([302, 303]).toContain(res1.status)
    const loc1 = res1.headers.get('location')
    expect(loc1).toMatch(/\/interaction\//)
    // eslint-disable-next-line no-console
    console.log('INTERACTION_URL:', loc1)
    // capture cookies for interaction
    const setCookies = getSetCookies(res1.headers)
    // eslint-disable-next-line no-console
    console.log('SET_COOKIES_AUTH:', setCookies)
    const cookieHeader = setCookies.map((c) => String(c).split(';')[0]).join('; ')

    // open interaction page first to initialize interaction
    const resGet = await fetch(new URL(loc1, issuer), { headers: { 'cookie': cookieHeader } })
    expect(resGet.status).toBe(200)
    const getCookies = getSetCookies(resGet.headers)
    // eslint-disable-next-line no-console
    console.log('SET_COOKIES_INTERACTION:', getCookies)
    const getCookieHeader = getCookies.map((c) => String(c).split(';')[0]).join('; ')
    const combinedCookies = [cookieHeader, getCookieHeader].filter(Boolean).join('; ')
    // eslint-disable-next-line no-console
    console.log('COMBINED_COOKIES:', combinedCookies)

    // submit login with SD-JWT to interaction endpoint via x-www-form-urlencoded
    const form = new URLSearchParams()
    const uid = String(loc1.split('/').pop())
    form.set('uid', uid)
    form.set('sd_jwt', sd_jwt)
    form.set('did', did)
    form.set('aud', aud)
    form.set('client_id', client_id)
    form.set('nonce', nonce)
    form.set('exp', String(exp))
    form.set('prompt', 'login')
    form.set('submit', 'Continue')
    const res2 = await fetch(new URL(loc1, issuer), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'cookie': combinedCookies },
      body: form.toString(),
      redirect: 'manual'
    })
    if (![302, 303].includes(res2.status)) {
      const txt = await res2.text()
      // eslint-disable-next-line no-console
      console.error('INTERACT_ERR:', txt.slice(0, 500))
    }
    expect([302, 303]).toContain(res2.status)
    const loc2 = res2.headers.get('location')
    const postCookies = getSetCookies(res2.headers)
    const cookieAfterPost = mergeCookieHeader(combinedCookies, postCookies)

    // consent auto-finishes, follow to redirect_uri
    const res3 = await fetch(new URL(loc2, issuer), { redirect: 'manual', headers: { 'cookie': cookieAfterPost } })
    expect([302, 303]).toContain(res3.status)
    let nextLoc = res3.headers.get('location')
    let cookiesSoFar = mergeCookieHeader(cookieAfterPost, getSetCookies(res3.headers))
    for (let i = 0; i < 10; i++) {
      const locUrl = new URL(nextLoc, issuer)
      const path = locUrl.pathname || ''
      if (path.startsWith('/interaction/') || path.startsWith('/auth/')) {
        const resN = await fetch(locUrl, { redirect: 'manual', headers: { 'cookie': cookiesSoFar } })
        expect([302, 303]).toContain(resN.status)
        nextLoc = resN.headers.get('location')
        cookiesSoFar = mergeCookieHeader(cookiesSoFar, getSetCookies(resN.headers))
      } else {
        break
      }
    }
    expect(nextLoc).toContain(redirect_uri)
    expect(nextLoc).toMatch(/code=/)
    expect(nextLoc).toMatch(new RegExp(`state=${state}`))
  })
})



