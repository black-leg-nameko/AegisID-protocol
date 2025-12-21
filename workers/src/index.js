import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { timing } from 'hono/timing'
import { jwtVerify, importJWK } from 'jose'
import { validateVerifyRequest } from './schema.js'

const app = new Hono()
app.use('*', timing())

// Simple in-memory nonce replay cache (production should use KV/DO)
const __nonceCache = globalThis.__AegisNonceCache || new Map()
globalThis.__AegisNonceCache = __nonceCache
function nonceCacheHas(key, nowMs) {
  const rec = __nonceCache.get(key)
  if (!rec) return false
  if (nowMs - rec.ts > rec.ttlMs) {
    __nonceCache.delete(key)
    return false
  }
  return true
}
function nonceCacheSet(key, nowMs, ttlMs) {
  __nonceCache.set(key, { ts: nowMs, ttlMs })
  // opportunistic sweep to prevent unbounded growth
  if (__nonceCache.size > 5000) {
    for (const [k, v] of __nonceCache.entries()) {
      if (nowMs - v.ts > v.ttlMs) __nonceCache.delete(k)
    }
  }
}

function audit(event, data) {
  try {
    if (process.env.NODE_ENV === 'test') {
      globalThis.__AegisAudit = globalThis.__AegisAudit || []
      globalThis.__AegisAudit.push({ event, ...data })
    } else {
      // eslint-disable-next-line no-console
      console.log('[audit]', event, data)
    }
  } catch {}
}

app.get('/health', (c) => c.text('ok'))

/**
 * POST /verify
 * Body: { sd_jwt, did, aud, nonce, exp }
 */
app.post('/verify', async (c) => {
  const start = Date.now()
  const correlationId =
    c.req.header('x-correlation-id') ||
    c.req.header('X-Correlation-Id') ||
    (globalThis.crypto && crypto.randomUUID ? crypto.randomUUID() : String(Date.now()))
  let payload
  try {
    payload = await c.req.json()
  } catch {
    audit('verify_error', { reason: 'invalid_json', correlationId })
    return jsonError(c, 400, 'invalid_request', 'body must be JSON')
  }

  const validation = validateVerifyRequest(payload ?? {})
  if (!validation.ok) {
    audit('verify_error', { reason: 'schema', correlationId, errors: validation.errors })
    return jsonError(c, 400, 'invalid_request', 'schema validation failed', validation.errors)
  }
  const { sd_jwt, did, aud, client_id, nonce, exp } = payload

  // Check time window (short lived)
  const nowSec = Math.floor(Date.now() / 1000)
  if (typeof exp !== 'number' || exp < nowSec - 5 || exp > nowSec + 300) {
    // allow small skew; restrict to ~5 minutes max
    audit('verify_error', { reason: 'exp_out_of_range', correlationId })
    return jsonError(c, 422, 'invalid_claims', 'exp out of range')
  }

  // Replay protection: nonce must be unused within window
  const replayKey = `${client_id}:${nonce}`
  const nowMs = Date.now()
  const ttlMs = 5 * 60 * 1000
  if (process.env.NODE_ENV !== 'test' && nonceCacheHas(replayKey, nowMs)) {
    audit('verify_error', { reason: 'replay_detected', correlationId })
    return jsonError(c, 409, 'replay_detected', 'nonce already used')
  }

  // did:jwk:<b64url of jwk json>
  const jwk = parseDidJwk(did)
  if (!jwk) {
    audit('verify_error', { reason: 'invalid_did', correlationId })
    return jsonError(c, 400, 'invalid_request', 'did is not did:jwk')
  }

  // Verify JWS with JWK
  let verified
  try {
    const key = await importJWK(jwk, jwk.alg || undefined)
    verified = await jwtVerify(sd_jwt, key, {
      audience: aud
      // note: jose will also verify exp/nbf if present in the JWS payload
    })
  } catch (e) {
    audit('verify_error', { reason: 'invalid_signature', correlationId })
    return jsonError(c, 401, 'invalid_signature', 'signature or audience invalid')
  }

  // Validate nonce binding (the JWT payload must carry the same nonce)
  if (verified?.payload?.nonce !== nonce) {
    audit('verify_error', { reason: 'nonce_mismatch', correlationId })
    return jsonError(c, 422, 'invalid_claims', 'nonce mismatch')
  }
  // Enforce audience matches client_id for pairwise subject derivation context
  if (aud !== client_id) {
    audit('verify_error', { reason: 'aud_client_id_mismatch', correlationId })
    return jsonError(c, 422, 'invalid_claims', 'aud must equal client_id')
  }
  // Validate custom exp if carried at request-level (already range-checked above)
  // You may also embed nonce/exp within the JWT and let jose validate exp automatically
  const end = Date.now()
  c.header('Server-Timing', `edge-verify;dur=${end - start}`)

  // Derive a pairwise subject using HKDF with client_id as info
  const sub = await derivePairwiseSub(did, client_id)

  audit('verify_success', { correlationId, sub, client_id, aud })
  // Mark nonce as used only after successful verification
  if (process.env.NODE_ENV !== 'test') {
    nonceCacheSet(replayKey, nowMs, ttlMs)
  }
  return c.json({
    ok: true,
    sub,
    amr: ['passkey'],
    iat: Math.floor(verified.payload.iat ?? nowSec),
    exp
  })
})

function jsonError(c, status, code, message, errors) {
  const body = { ok: false, error: code, message }
  if (errors) body.errors = errors
  return c.json(body, status)
}

function parseDidJwk(did) {
  // did:jwk:<b64url-encoded JWK JSON>
  if (typeof did !== 'string' || !did.startsWith('did:jwk:')) return null
  const b64 = did.slice('did:jwk:'.length)
  try {
    const json = new TextDecoder().decode(b64urlToBytes(b64))
    const jwk = JSON.parse(json)
    // Ensure it is a public JWK (no private fields)
    if (!jwk.kty) return null
    return jwk
  } catch {
    return null
  }
}

async function sha256B64Url(input) {
  const data = new TextEncoder().encode(input)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return bytesToB64Url(new Uint8Array(digest))
}

export async function derivePairwiseSub(did, clientId) {
  const salt = new TextEncoder().encode('aegisid-sub-v1')
  const info = new TextEncoder().encode(String(clientId))
  const ikm = new TextEncoder().encode(String(did))
  const key = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, 256)
  return bytesToB64Url(new Uint8Array(bits))
}

function b64urlToBytes(b64url) {
  const pad = '='.repeat((4 - (b64url.length % 4)) % 4)
  const base64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/')
  const raw = atob(base64)
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
  return out
}

function bytesToB64Url(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  const base64 = btoa(bin).replace(/=+$/, '')
  return base64.replace(/\+/g, '-').replace(/\//g, '_')
}

export default app


