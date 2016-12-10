#!/usr/bin/env node

var Autocert = require('autocert')
var Firebase = require('firebase-admin')
var Collection = require('realtime-collection')
var MultiRoot = require('multiroot')
var Splicer = require('splicer')

// config
var env = require('./env.json')

// set up a proxy and some debug logging
var proxy = new Splicer()

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

autocert.setChallenge = (key, value, cb) => {
  key = Buffer(key).toString('base64')
  toRef(`challenges/${key}`).set(value, cb)
}

autocert.setCredential = (name, credential, cb) => {
  name = name.replace(/\./g, '%')
  toRef(`credentials/${name}`).set(credential, cb)
}

proxy.SNICallback = autocert.certify.bind(autocert)

proxy.setAcmeChallenge = autocert.setChallenge

proxy.isAcmeHttpChallenge = pathname => {
  return /^\/\.well-known\/acme-challenge/.test(pathname)
}

proxy.apps.acme = {
  ports: {
    80: true
  }
}

// storage intergration
var storage = Firebase.initializeApp({
  databaseURL: `https://${env.firebaseAppId}.firebaseio.com`,
  credential: Firebase.credential.cert(env.googleServiceAccount)
})

var toRef = path => storage.database().ref('proxy/' + path)

var apps = new Collection({
  storage: toRef('apps'),
  items: proxy.apps
})
apps.on('change', proxy.onappchange)

new Collection({
  storage: toRef('names'),
  items: proxy.names,
  parseKey: key => key.replace(/%/g, '.')
})

new Collection({
  storage: toRef('challenges'),
  items: proxy.challenges,
  parseKey: key => Buffer(key, 'base64').toString()
})

new Collection({
  storage: toRef('credentials'),
  items: proxy.credentials,
  parseKey: key => key.replace(/%/g, '.')
})

new Collection({
  storage: toRef('machines'),
  items: proxy.machines
})

// static files
var fileserver = new MultiRoot({ port: 8000 })
fileserver.names = proxy.names
fileserver.apps = proxy.apps

apps.on('change', fileserver.reload.bind(fileserver))

fileserver.on('serve', path => {
  console.log(`started serving ${path}`)
})

fileserver.on('unserve', path => {
  console.log(`stopped serving ${path}`)
})
