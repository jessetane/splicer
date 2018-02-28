#!/usr/bin/env node

var fs = require('fs')
var Autocert = require('autocert')
var MultiRoot = require('multiroot')
var Splicer = require('../../')

// config
var env = require('./env.json')
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

proxy.on('connection', socket => {
  console.log(`tcp connection on ${socket.localPort} from ${socket.remoteAddress}`)
})

// ACME integration
var autocert = new Autocert({
  // url: 'https://acme-staging.api.letsencrypt.org',
  email: 'info@example.com',
  challenges: proxy.challenges,
  credentials: proxy.credentials
})

autocert.setCredential = function (name, credential, cb) {
  this.credentials[name] = credential
  console.log('writing filez', env)
  fs.writeFileSync(__dirname + '/env.json', JSON.stringify(env, null, 2))
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
proxy.apps.acme = {
  ports: {
    80: true
  }
}

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
