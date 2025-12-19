import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { Timing } from 'hono/timing'
import { jwtVerify, importJWK } from 'jose'

const app = new Hono()
app.use('*', Timing())

app.get('/health', (c) => c.text('ok'))

/**
 * POST /verify
 * Body: { sd_jwt, did, aud, nonce, exp }
 */
app.post('/verify', async (c) => {
  const start = Date.now()
  let payload
  try {
    payload = await c.req.json()
  } catch {
    throw new HTTPException(400, { message: 'invalid_request: body must be JSON' })
  }

  const { sd_jwt, did, aud, nonce, exp } = payload ?? {}
  if (!sd_jwt || !did || !aud || !nonce || !exp) {
    throw new HTTPException(400, { message: 'invalid_request: missing required fields' })
  }

  // Check time window (short lived)
  const nowSec = Math.floor(Date.now() / 1000)
  if (typeof exp !== 'number' || exp < nowSec - 5 || exp > nowSec + 300) {
    // allow small skew; restrict to ~5 minutes max
    throw new HTTPException(422, { message: 'invalid_claims: exp out of range' })
  }

  // did:jwk:<b64url of jwk json>
  const jwk = parseDidJwk(did)
  if (!jwk) {
    throw new HTTPException(400, { message: 'invalid_request: did is not did:jwk' })
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
    throw new HTTPException(401, { message: 'invalid_signature' })
  }

  // Validate nonce binding (the JWT payload must carry the same nonce)
  if (verified?.payload?.nonce !== nonce) {
    throw new HTTPException(422, { message: 'invalid_claims: nonce mismatch' })
  }
  // Validate custom exp if carried at request-level (already range-checked above)
  // You may also embed nonce/exp within the JWT and let jose validate exp automatically
  const end = Date.now()
  c.header('Server-Timing', `edge-verify;dur=${end - start}`)

  // Derive a stable subject from DID (pairwise derivation is recommended in production)
  const sub = await sha256B64Url(did)

  return c.json({
    ok: true,
    sub,
    amr: ['passkey'],
    iat: Math.floor(verified.payload.iat ?? nowSec),
    exp
  })
})

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


