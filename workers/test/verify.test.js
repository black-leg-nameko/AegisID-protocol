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
  it('400 when required fields are missing with uniform error body', async () => {
    const res = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({})
    })
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.ok).toBe(false)
    expect(body.error).toBe('invalid_request')
    expect(Array.isArray(body.errors)).toBe(true)
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
      body: JSON.stringify({ sd_jwt, did, aud, client_id: 'mvp-client', nonce: 'different', exp })
    })
    expect(res.status).toBe(422)
    const body = await res.json()
    expect(body.error).toBe('invalid_claims')
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
      body: JSON.stringify({ sd_jwt, did, aud, client_id: 'mvp-client', nonce, exp })
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
      body: JSON.stringify({ sd_jwt, did, aud, client_id: 'mvp-client', nonce, exp: expPast })
    })
    expect(res.status).toBe(422)
    const body = await res.json()
    expect(body.error).toBe('invalid_claims')
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
      body: JSON.stringify({ sd_jwt, did, aud: 'wrong-aud', client_id: 'mvp-client', nonce, exp })
    })
    expect(res.status).toBe(401)
    const body = await res.json()
    expect(body.error).toBe('invalid_signature')
  })

  it('400 when wrong types are provided', async () => {
    const res = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sd_jwt: 123, did: true, aud: {}, client_id: [], nonce: null, exp: "bad" })
    })
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe('invalid_request')
    expect(Array.isArray(body.errors)).toBe(true)
  })

  it('derives pairwise sub via HKDF with client_id', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256')
    const pubJwk = await exportJWK(publicKey)
    pubJwk.alg = 'ES256'
    const privJwk = await exportJWK(privateKey)
    const did = didFromPublicJwk(pubJwk)
    const client_id = 'pairwise-client'
    const aud = client_id
    const nonce = 'n-' + Math.random().toString(36).slice(2)
    const exp = Math.floor(Date.now() / 1000) + 60
    const sd_jwt = await createToken(aud, nonce, exp, privJwk)

    const res = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sd_jwt, did, aud, client_id, nonce, exp })
    })
    expect(res.status).toBe(200)
    const json = await res.json()
    expect(json.ok).toBe(true)
    const res2 = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sd_jwt, did, aud, client_id, nonce, exp })
    })
    const json2 = await res2.json()
    expect(json.sub).toBe(json2.sub)
  })
})


