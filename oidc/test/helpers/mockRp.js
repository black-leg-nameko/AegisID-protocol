import { createServer } from 'node:http'

export async function startMockRp({ port = 3000, host = '127.0.0.1', path = '/callback' } = {}) {
  const server = createServer((req, res) => {
    if (req.method === 'GET' && req.url && req.url.startsWith(path)) {
      res.statusCode = 200
      res.setHeader('content-type', 'text/plain')
      res.end('OK')
      return
    }
    res.statusCode = 404
    res.end('not found')
  })
  await new Promise((resolve) => server.listen(port, host, resolve))
  return server
}


