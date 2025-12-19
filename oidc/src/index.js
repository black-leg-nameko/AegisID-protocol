import { nanoid } from 'nanoid'
import { createServer } from 'http'
import Provider from 'oidc-provider'

const ISSUER = 'http://127.0.0.1:4000'

// In-memory JWKS (ephemeral)
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
  issuer: ISSUER,
  clients: [
    {
      client_id: 'mvp-client',
      client_secret: 'mvp-secret',
      redirect_uris: ['http://localhost:3000/callback', 'http://127.0.0.1:3000/callback'],
      token_endpoint_auth_method: 'client_secret_basic',
      response_types: ['code'],
      grant_types: ['authorization_code']
    }
  ],
  jwks: keystore,
  interactions: {
    // Simplified default interactions
    url(ctx, interaction) {
      return `/interaction/${interaction.uid}`
    }
  },
  features: {
    devInteractions: { enabled: false },
    pkce: { required: () => true }
  },
  cookies: {
    keys: ['replace-with-strong-secret-1', 'replace-with-strong-secret-2']
  },
  ttl: {
    AccessToken: 60 * 10, // 10m
    AuthorizationCode: 60 * 5, // 5m
    IdToken: 60 * 10 // 10m
  },
  // Minimal subject generation (pairwise recommended in production)
  findAccount: async (ctx, id) => ({
    accountId: id,
    async claims() {
      return { sub: id, amr: ['passkey'] }
    }
  })
}

const provider = new Provider(ISSUER, configuration)

// Simple HTML interactions (no templating for MVP)
provider.app.middleware.unshift(async (ctx, next) => {
  if (ctx.path.startsWith('/interaction/')) {
    const { uid, prompt, params } = await provider.interactionDetails(ctx.req, ctx.res)
    if (prompt.name === 'login') {
      if (ctx.req.method === 'POST') {
        // for MVP: auto-login as a stable demo user (would integrate Workers /verify here)
        const result = {
          login: {
            accountId: 'demo-' + nanoid(8),
            amr: ['passkey']
          }
        }
        await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: false })
        return
      }
      ctx.res.setHeader('content-type', 'text/html; charset=utf-8')
      ctx.res.end(`
<!doctype html>
<html><body>
  <h1>AegisId OIDC (MVP)</h1>
  <p>Client: ${params.client_id}</p>
  <form method="post" action="/interaction/${uid}">
    <button type="submit">Continue as Verified User</button>
  </form>
</body></html>`)
      return
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
server.listen(4000, '127.0.0.1', () => {
  // eslint-disable-next-line no-console
  console.log('OIDC Provider listening at', ISSUER)
})


