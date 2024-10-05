#!/usr/bin/env node

import fs from 'fs/promises'
import Autocert from 'autocert'
import MultiRoot from 'multiroot'
import Splicer from '../index.js'

// config
var env = JSON.parse(await fs.readFile('./env.json', 'utf8'))
if (!env.credentials) {
  env.credentials = {}
}

// set up a proxy and some debug logging
var proxy = new Splicer()
proxy.apps = env.apps
proxy.names = env.names
proxy.machines = env.machines
proxy.credentials = env.credentials

proxy.on('tcpbind', port => {
  console.log(`started listening on ${port}`)
})

proxy.on('tcpunbind', port => {
  console.log(`stopped listening on ${port}`)
})

/*
proxy.on('connection', socket => {
  console.log(`tcp connection on ${socket.localPort} from ${socket.remoteAddress}`)
})

proxy._tlsServer.on('tlsClientError', err => {
  console.error('tlsClientError:', err)
})
*/

proxy.on('request', (socket, name, app) => {
  console.log(`[${new Date().toISOString()}] request for ${name} on ${socket.localPort} from ${socket.remoteAddress}`)
})

// ACME integration
var autocert = new Autocert({
  // url: 'https://acme-staging-v02.api.letsencrypt.org/directory'
  email: 'info@example.com',
  challenges: proxy.challenges,
  credentials: proxy.credentials
})

autocert.setCredential = async function (name, credential, cb) {
  this.credentials[name] = credential
  console.log('received credential, persisting', env)
  try {
    await fs.writeFile('./env.json', JSON.stringify(env, null, 2))
  } catch (err) {
    console.error('failed to persist credential', err)
  }
  cb()
}

proxy.SNICallback = autocert.certify.bind(autocert)

proxy.setAcmeChallenge = (name, value, cb) => {
  if (!cb) cb = () => {}
  autocert.setChallenge(name, value, cb)
}

proxy.isAcmeHttpChallenge = pathname => {
  return /^\/\.well-known\/acme-challenge/.test(pathname)
}

proxy.apps = env.apps

// make sure 80 is open for http challenges
/*
proxy.apps.acme = {
  ports: {
    80: true
  }
}
*/

proxy.reload()

// static files
var fileserver = new MultiRoot({ port: 8000 })
fileserver.names = proxy.names
fileserver.apps = proxy.apps
fileserver.reload()

fileserver.on('serve', path => {
  console.log(`started serving ${path}`)
})

fileserver.on('unserve', path => {
  console.log(`stopped serving ${path}`)
})
