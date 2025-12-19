import { describe, it, expect } from 'vitest'
import app from '../src/index.js'
import { SignJWT, exportJWK, generateKeyPair, importJWK } from 'jose'

function toB64Url(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  const base64 = btoa(bin).replace(/=+$/, '')
  return base64.replace(/\+/g, '-').replace(/\//g, '_')
}

function didFromPublicJwk(jwk) {
  const json = new TextEncoder().encode(JSON.stringify(jwk))
  return 'did:jwk:' + toB64Url(json)
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

describe('/verify', () => {
  it('400 when required fields are missing', async () => {
    const res = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({})
    })
    expect(res.status).toBe(400)
  })

  it('422 when nonce mismatches request', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256')
    const pubJwk = await exportJWK(publicKey)
    pubJwk.alg = 'ES256'
    const privJwk = await exportJWK(privateKey)
    const did = didFromPublicJwk(pubJwk)
    const aud = 'mvp-client'
    const nonceInJwt = 'nonce-in-jwt'
    const exp = Math.floor(Date.now() / 1000) + 60
    const sd_jwt = await createToken(aud, nonceInJwt, exp, privJwk)

    const res = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sd_jwt, did, aud, nonce: 'different', exp })
    })
    expect(res.status).toBe(422)
  })

  it('verifies a valid SD-JWT with did:jwk', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256')
    const pubJwk = await exportJWK(publicKey)
    pubJwk.alg = 'ES256'
    const privJwk = await exportJWK(privateKey)
    const did = didFromPublicJwk(pubJwk)
    const aud = 'mvp-client'
    const nonce = 'n-' + Math.random().toString(36).slice(2)
    const exp = Math.floor(Date.now() / 1000) + 60
    const sd_jwt = await createToken(aud, nonce, exp, privJwk)

    const res = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sd_jwt, did, aud, nonce, exp })
    })
    expect(res.status).toBe(200)
    const json = await res.json()
    expect(json.ok).toBe(true)
    expect(typeof json.sub).toBe('string')
    expect(json.amr).toContain('passkey')
  })

  it('422 when exp is out of acceptable range', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256')
    const pubJwk = await exportJWK(publicKey)
    pubJwk.alg = 'ES256'
    const privJwk = await exportJWK(privateKey)
    const did = didFromPublicJwk(pubJwk)
    const aud = 'mvp-client'
    const nonce = 'n-' + Math.random().toString(36).slice(2)
    const expPast = Math.floor(Date.now() / 1000) - 600
    const sd_jwt = await createToken(aud, nonce, Math.floor(Date.now() / 1000) + 60, privJwk)

    const res = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sd_jwt, did, aud, nonce, exp: expPast })
    })
    expect(res.status).toBe(422)
  })

  it('401 when audience mismatches', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256')
    const pubJwk = await exportJWK(publicKey)
    pubJwk.alg = 'ES256'
    const privJwk = await exportJWK(privateKey)
    const did = didFromPublicJwk(pubJwk)
    const aud = 'mvp-client'
    const nonce = 'n-' + Math.random().toString(36).slice(2)
    const exp = Math.floor(Date.now() / 1000) + 60
    const sd_jwt = await createToken(aud, nonce, exp, privJwk)

    const res = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sd_jwt, did, aud: 'wrong-aud', nonce, exp })
    })
    expect(res.status).toBe(401)
  })
})


