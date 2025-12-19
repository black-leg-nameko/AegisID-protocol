// Polyfills for Node test environment
if (typeof globalThis.crypto === 'undefined') {
  // Node 18+ has webcrypto, but ensure availability
  const { webcrypto } = await import('node:crypto')
  // eslint-disable-next-line no-global-assign
  globalThis.crypto = webcrypto
}

if (typeof globalThis.atob === 'undefined') {
  globalThis.atob = (b64) => Buffer.from(b64, 'base64').toString('binary')
}
if (typeof globalThis.btoa === 'undefined') {
  globalThis.btoa = (bin) => Buffer.from(bin, 'binary').toString('base64')
}


