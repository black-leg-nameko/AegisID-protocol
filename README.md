## AegisId MVP: Workers/Hono + Node OIDC Provider

### Overview
- Workers (Hono) exposes a low-latency `/verify` endpoint that verifies an SD-JWT presentation using a `did:jwk` public key and returns normalized claims for downstream use.
- A minimal Node OIDC Provider issues standard OIDC tokens (Authorization Code Flow). For MVP, it runs separately and can be integrated later to consume the Workers `/verify` result inside the interaction or a custom login path.

---

## Endpoint Specifications (MVP)

### 1) Workers (Edge) API
Base: `https://<your-workers-domain>/`

- `GET /health`
  - Purpose: Liveness check.
  - Response: `200 OK`, body: `"ok"`

- `POST /verify`
  - Purpose: Verify SD-JWT using `did:jwk` public key. Enforce audience/nonce/exp and return normalized subject and auth context.
  - Request (application/json):
    ```json
    {
      "sd_jwt": "<compact JWS string>",
      "did": "did:jwk:<base64url-encoded-jwk>",
      "aud": "<string, required>",
      "nonce": "<string, required>",
      "exp": 1700000000
    }
    ```
    - `sd_jwt`: Compact JWS presentation produced locally on the Holder device.
    - `did`: DID containing the JWK for verification (`did:jwk` method; public key only).
    - `aud`, `nonce`, `exp`: Bound to the presentation to prevent replay. `exp` should be short-lived (e.g. 30–60s).
  - Response (application/json):
    ```json
    {
      "ok": true,
      "sub": "<stable DID-derived subject>",
      "amr": ["passkey"],
      "iat": 1700000000,
      "exp": 1700000030
    }
    ```
    - `sub`: Derived from `did` and intended client (pairwise recommended in production).
    - `amr`: Authentication methods, includes `"passkey"` when WebAuthn user verification was used.
  - Error responses:
    - `400` with `{ "ok": false, "error": "invalid_request", "detail": "..." }`
    - `401` with `{ "ok": false, "error": "invalid_signature" }`
    - `422` with `{ "ok": false, "error": "invalid_claims", "detail": "..." }`

Notes:
- For MVP, the implementation verifies the JWS signature against the JWK embedded in `did:jwk`. Audience/nonce/exp checks are enforced.
- Production should add:
  - Pairwise `sub` derivation (e.g., HKDF over `(did, client_id)`).
  - Replay defenses and strict clock skew handling.
  - Rate limiting and structured logging.

---

### 2) Node OIDC Provider (Minimal)
Base (local): `http://127.0.0.1:4000`

Implements a minimal Authorization Code Flow using `oidc-provider` with in-memory store and a sample static client. For the MVP:
- Discovery: `GET /.well-known/openid-configuration`
- Authorization: `GET /auth`
- Token: `POST /token`
- JWKS: `GET /jwks`

Login is a very simple built-in interaction. Integration with Workers `/verify` can be done in a follow-up by:
- Accepting a `login_hint_token` that carries an SD-JWT presentation and calling the Workers `/verify` from the provider’s interaction, OR
- Running the `/authorize` fronted by Workers, verifying first, then continuing the OIDC flow on the provider.

---

## Local Development

### Prerequisites
- Node.js 18+
- pnpm or npm
- Cloudflare Wrangler (optional for local dev; otherwise `wrangler dev` will prompt to install)

### Workers (Hono) - Dev
```bash
cd workers
pnpm install   # or: npm install
pnpm dev       # or: npm run dev
```

### Node OIDC Provider - Dev
```bash
cd oidc
pnpm install   # or: npm install
pnpm start     # starts on http://127.0.0.1:4000
```

---

## Files
- `workers/` Cloudflare Workers (Hono) service with `/health` and `/verify`.
- `oidc/` Minimal `oidc-provider` server with one sample client and ephemeral keys.


