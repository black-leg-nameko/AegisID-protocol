import { createProviderServer } from './provider.js'

const port = 4000
const issuer = `http://127.0.0.1:${port}`
createProviderServer({ issuer, port }).then(() => {
  // eslint-disable-next-line no-console
  console.log('OIDC Provider listening at', issuer)
})


