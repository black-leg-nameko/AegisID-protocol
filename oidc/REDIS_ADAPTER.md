# Redis Adapter Schema (Aegis ID OIDC)

Runtime: ioredis (enabled when `REDIS_URL` is present).

Key namespace: `aegis:oidc`

- Item: `aegis:oidc:<model>:<id>` → JSON payload
  - TTL: set per upsert call via `expiresIn` provided by oidc-provider for each model.
  - Fields persisted transparently; `consumed` is added on `consume()`.
- UID index: `aegis:oidc:uid:<uid>` → `<model>:<id>`
- UserCode index: `aegis:oidc:userCode:<code>` → `<model>:<id>`
- Grant set: `aegis:oidc:grant:<grantId>` → Set of `<model>:<id>` (for `revokeByGrantId`)

Models (examples, managed by oidc-provider):
- `Session`, `Interaction`, `AuthorizationCode`, `DeviceCode`, `AccessToken`, `RefreshToken`, `ClientCredentials`, etc.

Operations:
- `upsert(id, payload, expiresIn)`
  - Writes item + indexes; applies `EXPIRE item expiresIn` when provided.
- `find(id)` / `findByUid(uid)` / `findByUserCode(code)`
- `destroy(id)`
  - Deletes item, indexes, and removes from grant set.
- `revokeByGrantId(grantId)`
  - Reads the set, destroys all members, deletes the set.
- `consume(id)`
  - Sets `consumed = now()` on the item.

Notes:
- Index keys do not have TTL; they are removed with the item or via grant revocation.
- Use Redis eviction policy suitable for your deployment; items are TTL’d, indexes are short-lived due to lifecycle operations.


