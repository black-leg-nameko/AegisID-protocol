import { describe, it, expect } from 'vitest'
import MemoryAdapter from '../src/adapter.js'

describe('MemoryAdapter basics', () => {
  it('upsert/find/consume/destroy', async () => {
    const a = new MemoryAdapter('Session')
    await a.upsert('id1', { foo: 'bar', uid: 'u1' }, 1)
    const found = await a.find('id1')
    expect(found.foo).toBe('bar')
    const foundByUid = await a.findByUid('u1')
    expect(foundByUid.foo).toBe('bar')
    await a.consume('id1')
    const consumed = await a.find('id1')
    expect(consumed.consumed).toBeTypeOf('number')
    await a.destroy('id1')
    const gone = await a.find('id1')
    expect(gone).toBeUndefined()
  })

  it('revoke by grantId', async () => {
    const a1 = new MemoryAdapter('AccessToken')
    const a2 = new MemoryAdapter('RefreshToken')
    const grantId = 'g-1'
    await a1.upsert('ax1', { grantId }, 60)
    await a2.upsert('rf1', { grantId }, 60)
    await a1.revokeByGrantId(grantId)
    expect(await a1.find('ax1')).toBeUndefined()
    expect(await a2.find('rf1')).toBeUndefined()
  })
})


