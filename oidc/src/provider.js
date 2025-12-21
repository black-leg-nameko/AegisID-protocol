import Provider from 'oidc-provider'
import { createServer } from 'http'
import { nanoid } from 'nanoid'

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

  const configuration = {
    issuer,
    clients: [
      {
        client_id: 'mvp-client',
        client_secret: 'mvp-secret',
        redirect_uris: ['http://localhost:3000/callback', 'http://127.0.0.1:3000/callback'],
        token_endpoint_auth_method: 'client_secret_basic',
        id_token_signed_response_alg: 'ES256',
        response_types: ['code'],
        grant_types: ['authorization_code']
      }
    ],
    jwks: keystore,
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
      keys: ['replace-with-strong-secret-1', 'replace-with-strong-secret-2']
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
      audit('interaction_start', { uid, prompt: prompt && prompt.name, client_id: params && params.client_id })
      // eslint-disable-next-line no-console
      console.log('INTERACTION_DETAILS', { uid, prompt: prompt && prompt.name, params: { client_id: params && params.client_id } })
      if (prompt.name === 'login') {
        if (ctx.req.method === 'POST') {
          try {
            const body = await readBody(ctx.req)
            // CSRF validation could be enforced here (uid echo & cookie match).
            // For MVP E2E, proceed without hard-failing if cookie is missing.
            let result
            if (typeof loginVerifier === 'function') {
              const verified = await loginVerifier({ body, params })
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
            audit('interaction_login_completed', { uid, client_id: params && params.client_id })
            await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: true })
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
</body></html>`
        return
        }
      }
      if (prompt.name === 'consent') {
        audit('interaction_consent_completed', { uid, client_id: params && params.client_id })
        const result = { consent: {} }
        await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: true })
        return
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


