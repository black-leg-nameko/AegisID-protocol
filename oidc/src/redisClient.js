import Redis from 'ioredis'

let client = null

export function getRedis() {
  if (client) return client
  const url = process.env.REDIS_URL
  if (!url) return null
  client = new Redis(url, {
    enableOfflineQueue: false,
    lazyConnect: true,
    maxRetriesPerRequest: 1
  })
  client.on('error', (e) => {
    // eslint-disable-next-line no-console
    console.error('[redis] error', e.message)
  })
  client.connect().catch(() => {})
  return client
}


