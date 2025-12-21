import Ajv from 'ajv'

const ajv = new Ajv({ allErrors: true, removeAdditional: true })

export const verifyRequestSchema = {
  type: 'object',
  required: ['sd_jwt', 'did', 'aud', 'client_id', 'nonce', 'exp'],
  additionalProperties: false,
  properties: {
    sd_jwt: { type: 'string', minLength: 1 },
    did: { type: 'string', pattern: '^did:jwk:' },
    aud: { type: 'string', minLength: 3, maxLength: 128, pattern: '^[A-Za-z0-9._-]+$' },
    client_id: { type: 'string', minLength: 3, maxLength: 128, pattern: '^[A-Za-z0-9._-]+$' },
    nonce: { type: 'string', minLength: 8, maxLength: 256 },
    exp: { type: 'number' }
  }
}

const validateVerify = ajv.compile(verifyRequestSchema)

export function validateVerifyRequest(payload) {
  const ok = validateVerify(payload)
  if (ok) return { ok: true, value: payload }
  const errors = (validateVerify.errors || []).map((e) => ({
    path: e.instancePath || '',
    message: e.message || 'invalid'
  }))
  return { ok: false, errors }
}



