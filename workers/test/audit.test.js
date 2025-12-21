import { describe, it, expect } from 'vitest'
import app from '../src/index.js'
import { SignJWT, exportJWK, generateKeyPair, importJWK } from 'jose'

async function createToken(aud, nonce, expSec, privJwk) {
  const nowSec = Math.floor(Date.now() / 1000)
  return await new SignJWT({ nonce })
    .setProtectedHeader({ alg: 'ES256', kid: 'test' })
    .setAudience(aud)
    .setIssuedAt(nowSec)
    .setExpirationTime(expSec)
    .sign(await importJWK(privJwk, 'ES256'))
}

describe('Audit events', () => {
  it('emits verify_success and error reasons', async () => {
    globalThis.__AegisAudit = []
    const { publicKey, privateKey } = await generateKeyPair('ES256')
    const pubJwk = await exportJWK(publicKey)
    pubJwk.alg = 'ES256'
    const privJwk = await exportJWK(privateKey)
    const did = 'did:jwk:' + Buffer.from(JSON.stringify(pubJwk)).toString('base64url')
    const client_id = 'mvp-client'
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
    const okEvent = globalThis.__AegisAudit.find((e) => e.event === 'verify_success')
    expect(okEvent).toBeTruthy()
    expect(okEvent.client_id).toBe(client_id)

    // trigger error: nonce mismatch
    globalThis.__AegisAudit = []
    const res2 = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sd_jwt, did, aud, client_id, nonce: 'bad-bad-bad', exp })
    })
    expect(res2.status).toBe(422)
    const errEvent = globalThis.__AegisAudit.find((e) => e.reason === 'nonce_mismatch')
    expect(errEvent).toBeTruthy()
  })
})


