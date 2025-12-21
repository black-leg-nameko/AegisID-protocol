// Minimal in-memory adapter compatible with oidc-provider v8
// In production, replace with Redis/Postgres-backed implementation.
const nameStore = new Map() // name -> Map(id -> record)
const grantStore = new Map() // grantId -> Set of ids

function getNameMap(name) {
  if (!nameStore.has(name)) nameStore.set(name, new Map())
  return nameStore.get(name)
}

export default class MemoryAdapter {
  constructor(name) {
    this.name = name
    this.store = getNameMap(name)
  }

  async upsert(id, payload, expiresIn) {
    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : undefined
    const rec = { payload, ...(expiresAt ? { expiresAt } : {}) }
    this.store.set(id, rec)
    // track by grantId for revoke
    if (payload && payload.grantId) {
      const key = payload.grantId
      if (!grantStore.has(key)) grantStore.set(key, new Set())
      grantStore.get(key).add(`${this.name}:${id}`)
    }
  }

  async find(id) {
    const rec = this.store.get(id)
    if (!rec) return undefined
    if (rec.expiresAt && rec.expiresAt <= new Date()) {
      this.store.delete(id)
      return undefined
    }
    return rec.payload
  }

  async findByUid(uid) {
    for (const [id, rec] of this.store.entries()) {
      if (rec?.payload?.uid === uid) {
        return this.find(id)
      }
    }
    return undefined
  }

  async findByUserCode(userCode) {
    for (const [id, rec] of this.store.entries()) {
      if (rec?.payload?.userCode === userCode) {
        return this.find(id)
      }
    }
    return undefined
  }

  async destroy(id) {
    const rec = this.store.get(id)
    if (rec?.payload?.grantId) {
      const key = rec.payload.grantId
      const set = grantStore.get(key)
      if (set) set.delete(`${this.name}:${id}`)
    }
    this.store.delete(id)
  }

  async revokeByGrantId(grantId) {
    const set = grantStore.get(grantId)
    if (!set) return
    for (const entry of Array.from(set)) {
      const [name, id] = entry.split(':')
      const map = getNameMap(name)
      map.delete(id)
    }
    grantStore.delete(grantId)
  }

  async consume(id) {
    const rec = this.store.get(id)
    if (!rec) return
    rec.payload.consumed = Math.floor(Date.now() / 1000)
    this.store.set(id, rec)
  }
}


