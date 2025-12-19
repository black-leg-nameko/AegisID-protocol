import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createProviderServer } from '../src/provider.js'

let server
const port = 4010
const issuer = `http://127.0.0.1:${port}`

beforeAll(async () => {
  const created = await createProviderServer({ issuer, port })
  server = created.server
})

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve))
})

describe('OIDC Provider (MVP)', () => {
  it('exposes discovery document', async () => {
    const res = await fetch(`${issuer}/.well-known/openid-configuration`)
    expect(res.status).toBe(200)
    const json = await res.json()
    expect(json.issuer).toBe(issuer)
    expect(json.authorization_endpoint).toBeTypeOf('string')
    expect(json.token_endpoint).toBeTypeOf('string')
    expect(json.jwks_uri).toBeTypeOf('string')
  })
})


