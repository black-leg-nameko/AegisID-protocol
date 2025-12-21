import { getRedis } from './redisClient.js'

// Key schema:
// base: aegis:oidc
// item: aegis:oidc:<name>:<id> -> JSON(payload, consumed, exp)
// uid index: aegis:oidc:uid:<uid> -> <name>:<id>
// userCode index: aegis:oidc:userCode:<code> -> <name>:<id>
// grant set: aegis:oidc:grant:<grantId> -> Set of <name>:<id>
const BASE = 'aegis:oidc'

function keyItem(name, id) { return `${BASE}:${name}:${id}` }
function keyUid(uid) { return `${BASE}:uid:${uid}` }
function keyUserCode(code) { return `${BASE}:userCode:${code}` }
function keyGrant(grantId) { return `${BASE}:grant:${grantId}` }

export default class RedisAdapter {
  constructor(name) {
    this.name = name
    this.redis = getRedis()
  }

  async upsert(id, payload, expiresIn) {
    const r = this.redis
    const itemKey = keyItem(this.name, id)
    const data = JSON.stringify(payload)
    const p = []
    p.push(r.set(itemKey, data))
    if (expiresIn) p.push(r.expire(itemKey, expiresIn))
    if (payload?.uid) p.push(r.set(keyUid(payload.uid), `${this.name}:${id}`))
    if (payload?.userCode) p.push(r.set(keyUserCode(payload.userCode), `${this.name}:${id}`))
    if (payload?.grantId) p.push(r.sadd(keyGrant(payload.grantId), `${this.name}:${id}`))
    await Promise.all(p)
  }

  async find(id) {
    const v = await this.redis.get(keyItem(this.name, id))
    return v ? JSON.parse(v) : undefined
  }

  async findByUid(uid) {
    const ref = await this.redis.get(keyUid(uid))
    if (!ref) return undefined
    const [name, id] = ref.split(':')
    return await new RedisAdapter(name).find(id)
  }

  async findByUserCode(code) {
    const ref = await this.redis.get(keyUserCode(code))
    if (!ref) return undefined
    const [name, id] = ref.split(':')
    return await new RedisAdapter(name).find(id)
  }

  async destroy(id) {
    const itemKey = keyItem(this.name, id)
    const payload = await this.find(id)
    const p = [this.redis.del(itemKey)]
    if (payload?.uid) p.push(this.redis.del(keyUid(payload.uid)))
    if (payload?.userCode) p.push(this.redis.del(keyUserCode(payload.userCode)))
    if (payload?.grantId) p.push(this.redis.srem(keyGrant(payload.grantId), `${this.name}:${id}`))
    await Promise.all(p)
  }

  async revokeByGrantId(grantId) {
    const setKey = keyGrant(grantId)
    const members = await this.redis.smembers(setKey)
    if (members?.length) {
      const p = members.map((ref) => {
        const [name, id] = ref.split(':')
        return new RedisAdapter(name).destroy(id)
      })
      await Promise.all(p)
    }
    await this.redis.del(setKey)
  }

  async consume(id) {
    const itemKey = keyItem(this.name, id)
    const v = await this.redis.get(itemKey)
    if (!v) return
    const payload = JSON.parse(v)
    payload.consumed = Math.floor(Date.now() / 1000)
    await this.redis.set(itemKey, JSON.stringify(payload))
  }
}


