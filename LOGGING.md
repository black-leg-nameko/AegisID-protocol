### Logging and Audit Policy (Draft)

1) Structured JSON
- All audit logs are emitted as structured JSON objects with fields:
  - event: string (e.g., verify_success, verify_error, interaction_start, interaction_login_completed, interaction_consent_completed)
  - ts: epoch millis
  - correlationId: optional (planned)
  - client_id: when applicable
  - sub: when applicable (not PII-revealing; pairwise pseudonymous)
  - reason/message: on failures

2) PII Minimization
- Do not log raw JWTs, SD-JWT contents, private keys, or biometric indicators.
- For DIDs, avoid logging full key material. Use derived identifiers (e.g., pairwise sub) where possible.
- Truncate long values and hash sensitive tokens if visibility is absolutely needed (prefer not to log).

3) Correlation IDs
- Each request should carry or generate a correlationId (e.g., HTTP header X-Correlation-ID or generated at ingress).
- The correlationId should be added to every audit record for end-to-end tracing.
- In development/tests, correlationId may be omitted or synthetic.

4) Retention
- Default retention: 30 days for audit logs (configurable).
- Access controls: production logs must be access-controlled; PII data should be redacted at source.
- Export: logs should be exportable to SIEM (e.g., Cloudflare Logs, Datadog, CloudWatch).

5) Error Taxonomy
- verify_error reasons: invalid_json, schema, exp_out_of_range, invalid_did, invalid_signature, nonce_mismatch, aud_client_id_mismatch.
- interaction errors: interaction_details_failed, interaction_failed.

6) Privacy/Security
- Any user-identifying data (email, phone) must not be logged.
- For debugging, enable verbose logs only in non-production.

7) Future Enhancements
- Persist correlationId across Workers and OIDC services.
- Add request sampling and rate-limit related audit events.


