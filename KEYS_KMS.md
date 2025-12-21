### Production Key Management: KMS/HSM and Secrets Injection

Goal: Keep private signing keys out of the codebase and local env files; load them securely at runtime.

Recommended patterns:

1) Store private keys in a managed KMS/HSM
- AWS: KMS asymmetric keys (ECC P-256) + AWS Secrets Manager for JWKS JSON if needed.
- GCP: Cloud KMS (Elliptic Curve) + Secret Manager for JWKS JSON.
- Cloudflare: Workers Secrets for encrypted values (public JWKS can be static; private material never leaves KMS if using remote signing).

2) Injection strategies
- Provide signing keys to the OIDC provider via one of:
  - `SIGNING_JWKS` (inline JSON)
  - `SIGNING_JWKS_FILE` (path to a decrypted temp file)
  - `SIGNING_JWKS_URL` (service endpoint returning JWKS over mTLS/VPC)
- Public JWKS for discovery can be served via `JWKS`, `JWKS_FILE`, or `JWKS_URL` (already supported).

3) Example: decrypt-to-file on startup (Linux)
```bash
# fetch and decrypt with your KMS client; write minimal-permission temp file
umask 077
aws secretsmanager get-secret-value --secret-id OIDC_SIGNING_JWKS \
  --query SecretString --output text > /tmp/signing.jwks.json
export SIGNING_JWKS_FILE=/tmp/signing.jwks.json
node oidc/src/index.js
```

4) Active key switching
- Publish both old/new public keys in JWKS during grace period.
- Set `JWKS_ACTIVE_KID=<new-kid>` and send `SIGHUP` or rely on `JWKS_RELOAD_MS` to reorder keys.
- Restart provider if library requires for signing key swap.

5) Rotation policy
- Rotate at a fixed interval (e.g., 90 days) or on compromise.
- Monitor `/health` for `jwks.hasActive: true` and audit logs for key events.

6) Remote signing (optional)
- Instead of embedding private keys, provide a signing service that holds the HSM-bound key and returns JWS/JWT.
- The provider calls it over mTLS; JWKS still reflects the public key.


