#!/usr/bin/env node

var Terminus = require('./')

var server = new Terminus({
  hostsPath: process.env.HOSTS
    ? (__dirname + '/' + process.env.HOSTS)
    : __dirname + '/hosts'
})

server.on('error', err => {
  console.error(err)
})

server.on('listen', address => {
  console.log(`started listening on ${address}`)
})

server.on('unlisten', server => {
  console.log(`stopped listening on ${address}`)
})

process.on('SIGHUP', () => {
  console.log('got SIGHUP, reloading')
  server.reload()
})
