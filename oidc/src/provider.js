import Provider from 'oidc-provider'
import { createServer } from 'http'
import { nanoid } from 'nanoid'

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

  // Simple interactions
  provider.app.middleware.unshift(async (ctx, next) => {
    if (ctx.path.startsWith('/interaction/')) {
      if (ctx.req.method === 'POST') {
        try {
          // Directly finish interaction using UID from path
          const uid = ctx.path.split('/').pop()
          let result
          if (typeof loginVerifier === 'function') {
            const body = await readJsonBody(ctx.req)
            const verified = await loginVerifier({ body, params: {} })
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
          await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: false })
          return
        } catch (e) {
          ctx.status = 400
          ctx.type = 'text/plain; charset=utf-8'
          ctx.body = String(e && e.message || e)
          return
        }
      } else {
        const { uid, prompt, params } = await provider.interactionDetails(ctx.req, ctx.res)
        if (prompt.name === 'login') {
        ctx.type = 'text/html; charset=utf-8'
        ctx.body = `
<!doctype html>
<html><body>
  <h1>AegisId OIDC (MVP)</h1>
  <p>Client: ${params.client_id}</p>
  <form method="post" action="/interaction/${uid}">
    <button type="submit">Continue as Verified User</button>
  </form>
</body></html>`
        return
        }
      }
      if (prompt.name === 'consent') {
        const result = { consent: {} }
        await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: true })
        return
      }
    }
    await next()
  })

  const server = createServer(provider.callback())
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve))
  return { server, issuer }
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


