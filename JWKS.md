### JWKS and Key Rotation (Plan)

1) Source of Truth
- In production, manage signing keys in a secure KMS/HSM. The service should load JWKS at startup via environment (`JWKS` JSON) or secrets manager.
- Current implementation: `oidc/src/provider.js` reads `process.env.JWKS` when provided; otherwise uses an embedded demo ES256 key (replace ASAP).

2) Rotation Strategy
- Maintain at least two signing keys in JWKS: one active, one retiring.
- Advertise both in `/jwks` until all relying parties have cached the new key.
- Switch active `kid` for signing (via configuration/env) and keep old key published for a grace period (e.g., 7–14 days).

3) Operational Steps
- Generate new ES256 key pair, append to JWKS with unique `kid`.
- Deploy JWKS with both keys. After caches warm, update the signer to use the new `kid`.
- After the grace period, remove the old private key (keep public key for as long as tokens signed by it may remain valid).

4) Future Enhancements
- Implement dynamic keystore reload (hot-reload JWKS on SIGHUP or periodic refresh).
- Add an admin endpoint guarded behind auth to trigger rotation (disabled by default).
- Use a dedicated keystore library and persistent storage to avoid embedding private keys in config.


