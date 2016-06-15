#!/usr/bin/env node

var Terminus = require('./')

var server = new Terminus({
  hostsPath: process.env.HOSTS_PATH || __dirname + '/hosts'
})

process.on('SIGHUP', () => {
  console.log('got SIGHUP, reloading')
  server.reload()
})
