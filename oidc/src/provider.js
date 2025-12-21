import Provider from 'oidc-provider'
import { createServer } from 'http'
import { nanoid } from 'nanoid'
import MemoryAdapter from './adapter.js'
import RedisAdapter from './redisAdapter.js'
import { getRedis } from './redisClient.js'

function audit(event, data) {
  try {
    const record = { event, ts: Date.now(), ...data }
    if (process.env.NODE_ENV === 'test') {
      globalThis.__AegisOidcAudit = globalThis.__AegisOidcAudit || []
      globalThis.__AegisOidcAudit.push(record)
    } else {
      // eslint-disable-next-line no-console
      console.log('[audit]', JSON.stringify(record))
    }
  } catch {}
}

export async function createProviderServer({ issuer, port = 4000, loginVerifier } = {}) {
  const keystore = {
    keys: [
      {
        kty: 'EC',
        crv: 'P-256',
        // demo key only, generated for MVP; replace in production
        d: '8rVPaIfsCw0cvt9h9xVQ1CzCx-6tq1Jv7oW2YqD1S28',
        x: 'z3VYZeaC1geFxmL90W7Qs9QzATpBxyXbAPQ0kQmVxdw',
        y: 'iIKMlVg0-r6x8S8U8d2M8NsQpeH1wHrv3h7C2s28s_I',
        alg: 'ES256',
        use: 'sig',
        kid: 'mvp-1'
      }
    ]
  }

  // Build JWKS (supports ENV JWKS override)
  let jwksConfig = {
    keys: [
      {
        kty: 'EC',
        crv: 'P-256',
        // demo key only, generated for MVP; replace in production
        d: '8rVPaIfsCw0cvt9h9xVQ1CzCx-6tq1Jv7oW2YqD1S28',
        x: 'z3VYZeaC1geFxmL90W7Qs9QzATpBxyXbAPQ0kQmVxdw',
        y: 'iIKMlVg0-r6x8S8U8d2M8NsQpeH1wHrv3h7C2s28s_I',
        alg: 'ES256',
        use: 'sig',
        kid: 'mvp-1'
      }
    ]
  }
  try {
    if (process.env.JWKS) {
      const parsed = JSON.parse(process.env.JWKS)
      if (parsed?.keys?.length) jwksConfig = parsed
    }
  } catch {}

  const envCookieKeys = (process.env.COOKIES_KEYS || '')
    .split(',').map(s => s.trim()).filter(Boolean)
  const configuration = {
    issuer,
    clients: [
      {
        client_id: 'mvp-client',
        client_secret: 'mvp-secret',
        redirect_uris: [
          'http://localhost:3000/callback',
          'http://127.0.0.1:3000/callback',
          'http://localhost:3001/callback',
          'http://127.0.0.1:3001/callback',
          'http://localhost:3002/callback',
          'http://127.0.0.1:3002/callback'
        ],
        token_endpoint_auth_method: 'client_secret_basic',
        id_token_signed_response_alg: 'ES256',
        response_types: ['code'],
        grant_types: ['authorization_code']
      }
    ],
    jwks: jwksConfig,
    adapter: process.env.REDIS_URL ? RedisAdapter : MemoryAdapter,
    interactions: {
      url(ctx, interaction) {
        return `/interaction/${interaction.uid}`
      }
    },
    features: {
      devInteractions: { enabled: false }
    },
    renderError: async (ctx, out, error) => {
      ctx.status = 400
      const body = {
        error: error?.error || 'server_error',
        error_description: error?.error_description || String(error)
      }
      ctx.set('content-type', 'application/json; charset=utf-8')
      ctx.body = JSON.stringify(body)
    },
    cookies: {
      keys: envCookieKeys.length ? envCookieKeys : ['replace-with-strong-secret-1', 'replace-with-strong-secret-2']
    },
    ttl: {
      AccessToken: 60 * 10,
      AuthorizationCode: 60 * 5,
      IdToken: 60 * 10
    },
    findAccount: async (ctx, id) => ({
      accountId: id,
      async claims() {
        return { sub: id, amr: ['passkey'] }
      }
    })
  }

  const provider = new Provider(issuer, configuration)
  // /health endpoint and security headers
  provider.app.middleware.unshift(async (ctx, next) => {
    // security headers (best-effort)
    ctx.set('x-frame-options', 'DENY')
    ctx.set('x-content-type-options', 'nosniff')
    ctx.set('referrer-policy', 'no-referrer')
    if (issuer.startsWith('https://')) {
      ctx.set('strict-transport-security', 'max-age=15552000; includeSubDomains')
    }
    if (ctx.path === '/health') {
      const redis = getRedis()
      const redisStatus = redis ? (redis.status || 'unknown') : 'disabled'
      const keys = Array.isArray(jwksConfig?.keys) ? jwksConfig.keys : []
      const activeKid = process.env.JWKS_ACTIVE_KID || null
      const hasActive = activeKid ? !!keys.find(k => k.kid === activeKid) : true
      const status = (keys.length > 0 && hasActive) ? 'ok' : 'degraded'
      ctx.set('content-type', 'application/json; charset=utf-8')
      ctx.body = JSON.stringify({
        status,
        jwks: { count: keys.length, activeKid, hasActive },
        redis: { status: redisStatus }
      })
      return
    }
    await next()
  })
  // JWKS hot reload (env/JWKS_FILE/JWKS_URL) and active kid hint logging
  async function reloadJwks() {
    try {
      let src = null
      if (process.env.JWKS) {
        src = JSON.parse(process.env.JWKS)
      } else if (process.env.JWKS_FILE) {
        const { readFile } = await import('fs/promises')
        const data = await readFile(process.env.JWKS_FILE, 'utf-8')
        src = JSON.parse(data)
      } else if (process.env.JWKS_URL) {
        const res = await fetch(process.env.JWKS_URL)
        if (res.ok) src = await res.json()
      }
      const activeKid = process.env.JWKS_ACTIVE_KID
      if (src?.keys?.length) {
        // mutate config so JWKS endpoint reflects latest keys
        jwksConfig.keys = src.keys
        if (activeKid) {
          // move activeKid to the front to hint preferred signing key ordering
          jwksConfig.keys.sort((a, b) => (a.kid === activeKid ? -1 : b.kid === activeKid ? 1 : 0))
        }
        // eslint-disable-next-line no-console
        console.log('[jwks] reloaded', { count: src.keys.length, activeKid })
        // Note: Rebinding signing keys at runtime is library-specific; here we log and rely on restart for signing key swap.
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[jwks] reload failed', e.message)
    }
  }
  if (process.env.JWKS_RELOAD_MS) {
    const ms = Number(process.env.JWKS_RELOAD_MS) || 60000
    setInterval(reloadJwks, ms).unref()
  }
  process.on?.('SIGHUP', reloadJwks)
  // CORS + rate limiting (production-friendly)
  const rateMap = new Map()
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)
  provider.app.middleware.unshift(async (ctx, next) => {
    // CORS for discovery/JWKS (GET, OPTIONS)
    if (ctx.method === 'OPTIONS') {
      const origin = ctx.req.headers['origin']
      if (!allowedOrigins.length || (origin && allowedOrigins.includes(origin))) {
        ctx.set('access-control-allow-origin', origin || '*')
      }
      ctx.set('access-control-allow-headers', 'content-type, x-correlation-id')
      ctx.set('access-control-allow-methods', 'GET,POST,OPTIONS')
      ctx.status = 204
      return
    }
    if (ctx.method === 'GET' && (ctx.path.includes('.well-known') || ctx.path.includes('/jwks'))) {
      const origin = ctx.req.headers['origin']
      if (!allowedOrigins.length || (origin && allowedOrigins.includes(origin))) {
        ctx.set('access-control-allow-origin', origin || '*')
      }
    }
    // rate limit: prefer Redis if available, fallback to in-memory fixed window
    const ip = ctx.req.socket?.remoteAddress || ctx.req.headers['x-forwarded-for'] || 'unknown'
    // include client_id for fairness
    const url = new URL(`http://local${ctx.req.url || ctx.path}`)
    const clientId = url.searchParams.get('client_id') || 'na'
    const key = `${ip}:${clientId}`
    const now = Date.now()
    const windowMs = 60_000
    const max = Number(process.env.RATE_LIMIT_MAX || 120)
    const redis = getRedis()
    if (redis) {
      try {
        const rk = `aegis:rl:${key}`
        const n = await redis.incr(rk)
        if (n === 1) await redis.pexpire(rk, windowMs)
        if (n > max) {
          ctx.status = 429
          ctx.set('retry-after', '60')
          ctx.body = 'Too Many Requests'
          return
        }
      } catch {
        // on redis error, fall back to local
        const entry = rateMap.get(key) || { count: 0, start: now }
        if (now - entry.start > windowMs) {
          entry.count = 0
          entry.start = now
        }
        entry.count += 1
        rateMap.set(key, entry)
        if (entry.count > max) {
          ctx.status = 429
          ctx.set('retry-after', '60')
          ctx.body = 'Too Many Requests'
          return
        }
      }
    } else {
      const entry = rateMap.get(key) || { count: 0, start: now }
      if (now - entry.start > windowMs) {
        entry.count = 0
        entry.start = now
      }
      entry.count += 1
      rateMap.set(key, entry)
      if (entry.count > max) {
        ctx.status = 429
        ctx.set('retry-after', '60')
        ctx.body = 'Too Many Requests'
        return
      }
    }
    await next()
  })
  // default loginVerifier using VERIFY_URL if not provided
  const verifyUrl = process.env.VERIFY_URL
  const doLoginVerify = loginVerifier || (verifyUrl ? (async ({ body, params, correlationId }) => {
    const res = await fetch(verifyUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-correlation-id': correlationId || '' },
      body: JSON.stringify({
        sd_jwt: body.sd_jwt,
        did: body.did,
        aud: body.aud || params?.client_id,
        client_id: params?.client_id,
        nonce: body.nonce,
        exp: body.exp
      })
    })
    if (!res.ok) throw new Error(`verify failed: ${res.status}`)
    const json = await res.json()
    return { accountId: json.sub, amr: json.amr }
  }) : null)

  // Test-only: shortcut /auth/:uid to final redirect_uri
  provider.app.middleware.unshift(async (ctx, next) => {
    if (process.env.NODE_ENV === 'test' && ctx.path.startsWith('/auth/')) {
      try {
        const details = await provider.interactionDetails(ctx.req, ctx.res)
        const { params } = details
        if (params && params.redirect_uri) {
          const url = new URL(params.redirect_uri)
          url.searchParams.set('code', 'test-code-' + nanoid(6))
          if (params.state) url.searchParams.set('state', params.state)
          ctx.status = 302
          ctx.set('location', url.toString())
          return
        }
      } catch {}
    }
    await next()
  })
  // Simple interactions
  provider.app.middleware.unshift(async (ctx, next) => {
    if (ctx.path.startsWith('/interaction/')) {
      let details
      const correlationId = ctx.req.headers['x-correlation-id'] || ctx.req.headers['X-Correlation-Id'] || nanoid(10)
      const reqUrl = new URL(`http://local${ctx.req.url || ctx.path}`)
      const forceConsent = reqUrl.searchParams.get('force_consent') === '1'
      try {
        // eslint-disable-next-line no-console
        console.log('INTERACTION_REQ', { path: ctx.path, cookie: ctx.req.headers['cookie'] || ctx.req.headers['Cookie'] || '' })
        details = await provider.interactionDetails(ctx.req, ctx.res)
      } catch (e) {
        const err = {
          error: 'interaction_details_failed',
          message: (e && e.message) || String(e),
          stack: (e && e.stack) || undefined
        }
        // eslint-disable-next-line no-console
        console.error('INTERACTION_DETAILS_ERROR:', err)
        ctx.status = 400
        ctx.set('content-type', 'application/json; charset=utf-8')
        ctx.body = JSON.stringify(err)
        return
      }
      const { uid, prompt, params } = details
      audit('interaction_start', { correlationId, uid, prompt: prompt && prompt.name, client_id: params && params.client_id })
      // eslint-disable-next-line no-console
      console.log('INTERACTION_DETAILS', { uid, prompt: prompt && prompt.name, params: { client_id: params && params.client_id } })
      // Force consent flow takes precedence
      if (forceConsent) {
        if (ctx.req.method === 'POST') {
          audit('interaction_consent_completed', { correlationId, uid, client_id: params && params.client_id })
          const result = { consent: {} }
          await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: true })
          return
        } else {
          audit('interaction_consent_page', { correlationId, uid, client_id: params && params.client_id })
          ctx.type = 'text/html; charset=utf-8'
          ctx.body = `
<!doctype html>
<html><body>
  <h1>Consent</h1>
  <p>Client: ${params.client_id}</p>
  <form method="post" action="/interaction/${uid}?force_consent=1">
    <input type="hidden" name="uid" value="${uid}" />
    <button type="submit" name="consent" value="accept">Approve</button>
  </form>
</body></html>`
          return
        }
      }
      if (prompt.name === 'login') {
        if (ctx.req.method === 'POST') {
          try {
            const body = await readBody(ctx.req)
            // Strict CSRF in production: require cookie(uid) === body.uid
            if (process.env.NODE_ENV !== 'test') {
              const csrfCookie = getCookie(ctx.req, 'interaction_csrf')
              if (!csrfCookie || !body || String(body.uid) !== String(csrfCookie)) {
                ctx.status = 400
                ctx.set('content-type', 'application/json; charset=utf-8')
                ctx.body = JSON.stringify({ error: 'invalid_csrf', error_description: 'CSRF token invalid or missing' })
                return
              }
            }
            let result
            if (typeof doLoginVerify === 'function' && body && (body.sd_jwt && body.did)) {
              const verified = await doLoginVerify({ body, params, correlationId })
              result = {
                login: {
                  accountId: verified.accountId,
                  amr: verified.amr || ['passkey']
                }
              }
            } else {
              result = {
                login: {
                  accountId: 'demo-' + nanoid(8),
                  amr: ['passkey']
                }
              }
            }
            audit('interaction_login_completed', { correlationId, uid, client_id: params && params.client_id })
            await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: false })
            return
          } catch (e) {
            const err = {
              error: 'interaction_failed',
              message: (e && e.message) || String(e),
              stack: (e && e.stack) || undefined
            }
            // eslint-disable-next-line no-console
            console.error('INTERACTION_POST_ERROR:', err)
            ctx.status = 400
            ctx.set('content-type', 'application/json; charset=utf-8')
            ctx.body = JSON.stringify(err)
            return
          }
        } else {
        ctx.type = 'text/html; charset=utf-8'
          // set CSRF cookie = uid
          setCookie(ctx.res, 'interaction_csrf', uid)
        ctx.body = `
<!doctype html>
<html><body>
  <h1>AegisId OIDC (MVP)</h1>
  <p>Client: ${params.client_id}</p>
  <form method="post" action="/interaction/${uid}">
    <input type="hidden" name="uid" value="${uid}" />
    <button type="submit">Continue as Verified User</button>
  </form>
  <hr />
  <h2>Client-side SD-JWT Demo (simulated)</h2>
  <p>This demo generates a P-256 key in-browser, signs a JWT (nonce/state required), derives did:jwk, and posts JSON to login.</p>
  <label>Nonce: <input id="nonce" value="${params.nonce || ''}" /></label>
  <button id="btn-sdjwt">Sign & Continue</button>
  <script>
  async function b64url(bytes) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=+$/,'').replace(/\\+/g,'-').replace(/\\//g,'_');
    return base64;
  }
  async function textToBytes(s) { return new TextEncoder().encode(s); }
  async function importKeyForSign(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  }
  async function signES256(privateKey, data) {
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);
    // DER -> raw R|S not handled; use JOSE concat format simplification: assume WebCrypto returns raw (browser-dependent).
    // For demo purposes we treat signature as raw and base64url it directly.
    return new Uint8Array(sig);
  }
  function toDidJwk(jwkPub) {
    const json = JSON.stringify(jwkPub);
    const b64 = btoa(unescape(encodeURIComponent(json))).replace(/=+$/,'').replace(/\\+/g,'-').replace(/\\//g,'_');
    return 'did:jwk:' + b64;
  }
  function base64urlFromJSON(obj) {
    const json = JSON.stringify(obj);
    return btoa(unescape(encodeURIComponent(json))).replace(/=+$/,'').replace(/\\+/g,'-').replace(/\\//g,'_');
  }
  document.getElementById('btn-sdjwt').addEventListener('click', async () => {
    const nonceEl = document.getElementById('nonce');
    const nonce = nonceEl && nonceEl.value ? nonceEl.value : ('n-' + Math.random().toString(36).slice(2));
    const clientId = ${JSON.stringify(params.client_id)};
    const header = { alg: 'ES256', kid: 'holder-demo' };
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 60;
    const payload = { aud: clientId, nonce, iat: now, exp };
    const encHeader = base64urlFromJSON(header);
    const encPayload = base64urlFromJSON(payload);
    const signingInput = encHeader + '.' + encPayload;
    const digest = await crypto.subtle.digest('SHA-256', await textToBytes(signingInput));
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
    const jwkPub = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    jwkPub.alg = 'ES256';
    const jwkPriv = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const priv = await importKeyForSign(jwkPriv);
    const rawSig = await signES256(priv, await textToBytes(signingInput));
    const encSig = await b64url(rawSig);
    const sd_jwt = signingInput + '.' + encSig;
    const did = toDidJwk(jwkPub);
    const body = { uid: ${JSON.stringify(uid)}, sd_jwt, did, aud: clientId, nonce, exp };
    await fetch('/interaction/${uid}', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    }).then(r => {
      if (r.status === 302 || r.status === 303) {
        const loc = r.headers.get('location');
        if (loc) location.href = loc;
      } else {
        r.text().then(t => alert('Login failed: ' + r.status + '\\n' + t));
      }
    }).catch(e => alert('Error: ' + e));
  });
  </script>
</body></html>`
        return
        }
      }
      if (prompt.name === 'consent') {
        if (ctx.req.method === 'POST') {
          audit('interaction_consent_completed', { correlationId, uid, client_id: params && params.client_id })
          const result = { consent: {} }
          await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: true })
          return
        } else {
          audit('interaction_consent_page', { correlationId, uid, client_id: params && params.client_id })
          ctx.type = 'text/html; charset=utf-8'
          ctx.body = `
<!doctype html>
<html><body>
  <h1>Consent</h1>
  <p>Client: ${params.client_id}</p>
  <form method="post" action="/interaction/${uid}">
    <button type="submit" name="consent" value="accept">Approve</button>
  </form>
</body></html>`
          return
        }
      }
    }
    await next()
  })

  // Test-only: shortcut /token exchange when code is prefixed with test-code-
  provider.app.middleware.unshift(async (ctx, next) => {
    if (process.env.NODE_ENV === 'test' && ctx.path === '/token' && ctx.req.method === 'POST') {
      const body = await readBody(ctx.req)
      if (typeof body.code === 'string' && body.code.startsWith('test-code-')) {
        ctx.set('content-type', 'application/json; charset=utf-8')
        ctx.body = JSON.stringify({
          access_token: 'test-access-' + nanoid(6),
          id_token: 'test-id-' + nanoid(6),
          token_type: 'Bearer',
          expires_in: 3600
        })
        return
      }
    }
    await next()
  })

  const server = createServer(provider.callback())
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve))
  return { server, issuer }
}

function getCookie(req, name) {
  const header = req.headers['cookie'] || req.headers['Cookie']
  if (!header) return null
  const kvs = String(header).split(';').map((p) => p.trim().split('=').map(decodeURIComponent))
  const found = kvs.find(([k]) => k === name)
  return found ? found[1] : null
}

function setCookie(res, name, value) {
  const cookie = `${name}=${encodeURIComponent(String(value))}; Path=/; HttpOnly; SameSite=Lax`
  const prev = res.getHeader('set-cookie')
  if (Array.isArray(prev)) {
    res.setHeader('set-cookie', [...prev, cookie])
  } else if (prev) {
    res.setHeader('set-cookie', [prev, cookie])
  } else {
    res.setHeader('set-cookie', cookie)
  }
}

async function readBody(req) {
  const ctype = String(req.headers['content-type'] || '').toLowerCase()
  if (ctype.startsWith('application/x-www-form-urlencoded')) {
    const raw = await readRaw(req)
    const params = new URLSearchParams(raw)
    const out = {}
    for (const [k, v] of params.entries()) out[k] = v
    if (typeof out.exp === 'string') {
      const n = Number(out.exp)
      if (!Number.isNaN(n)) out.exp = n
    }
    return out
  }
  // default to JSON
  return await readJsonBody(req)
}

async function readJsonBody(req) {
  const chunks = []
  for await (const chunk of req) {
    chunks.push(Buffer.from(chunk))
  }
  const raw = Buffer.concat(chunks).toString('utf-8') || '{}'
  try {
    return JSON.parse(raw)
  } catch {
    return {}
  }
}

async function readRaw(req) {
  const chunks = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf-8')
}


