#!/usr/bin/env node

var Autocert = require('autocert')
var firebase = require('firebase')
var Collection = require('realtime-collection')
var Terminus = require('../../')

// config
var env = require('./env.json')

// set up a proxy and some debug logging
var proxy = new Terminus({
  acmeValidationPort: 8080,
  shouldTerminateTls: true,
})

proxy.isDomainValidationRequest = req => {
  return /^\.well-known\/acme-challenge/.test(req.url)
}

proxy.on('tcpbind', port => {
  console.log(`started listening on ${port}`)
})

proxy.on('tcpunbind', port => {
  console.log(`stopped listening on ${port}`)
})

proxy._ontcpConnection = socket => {
  console.log(`tcp connection accepted on ${socket.localPort} from ${socket.remoteAddress}`)
  Terminus.prototype._ontcpConnection.call(proxy, socket)
}

// ACME CA and storage integration
var autocert = new Autocert({
  url: 'https://acme-staging.api.letsencrypt.org',
  email: 'info@simple-machines.io',
  challenges: proxy.challenges,
  credentials: proxy.credentials,
})

proxy.SNICallback = (name, cb) => {
  autocert.certify(name, (err, credential) => {
    if (err) console.error(`failed to certify ${name}`, err)
    console.log(`certified ${name}`, credential)
    cb(err, credential)
  })
}

autocert.setChallenge = (key, value, cb) => {
  key = Buffer(key).toString('base64')
  toRef(`challenges/${key}`).update(value, cb)
}

autocert.setCredential = (name, credential, cb) => {
  name = Buffer(name).toString('base64')
  toRef(`credentials/${name}`).update(credential, cb)
}

// storage
var storage = firebase.initializeApp({
  databaseURL: `https://${env.firebaseAppId}.firebaseio.com`,
  serviceAccount: env.googleServiceAccount,
})

var toRef = path => storage.database().ref(path)

var apps = new Collection({
  storage: toRef('apps'),
  items: proxy.apps,
})
apps.on('change', proxy.onappchange)

new Collection({
  storage: toRef('names'),
  items: proxy.names,
  parseKey: key => Buffer(key, 'base64').toString()
})

new Collection({
  storage: toRef('challenges'),
  items: proxy.challenges,
  parseKey: key => Buffer(key, 'base64').toString()
})

new Collection({
  storage: toRef('credentials'),
  items: proxy.credentials,
  parseKey: key => Buffer(key, 'base64').toString()
})

new Collection({
  storage: toRef('machines'),
  items: proxy.backends,
})