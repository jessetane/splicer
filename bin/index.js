#!/usr/bin/env node

import fs from 'fs/promises'
import Autocert from 'autocert'
import MultiRoot from 'multiroot'
import Splicer from '../index.js'

// set up a proxy and some debug logging
var proxy = new Splicer()

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
*/

proxy._tlsServer.on('tlsClientError', err => {
  console.error('tlsClientError:', err)
})

proxy.on('request', (socket, name, app) => {
  console.log(`[${new Date().toISOString()}] request for ${name} on ${socket.localPort} from ${socket.remoteAddress}`)
})

// ACME integration
var autocert = new Autocert({
  // url: 'https://acme-staging-v02.api.letsencrypt.org/directory'
  challenges: proxy.challenges,
})

autocert.setCredential = async function (name, credential, cb) {
  this.credentials[name] = credential
  console.log('received credential, persisting', config)
  try {
    await fs.writeFile(configFile, JSON.stringify(config, null, 2))
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

// static file server
var fileServer = null

// get config file name and start
var args = process.argv.slice(2)
var configFile = args[0] || './config.json'
var config = null
reloadConfig()

// reload on SIGHUP
if (process.platform !== 'win32') {
	process.on('SIGHUP', reloadConfig)
}

async function reloadConfig () {
	if (config) {
		console.log('got SIGHUP, reloading config')
	}
	config = JSON.parse(await fs.readFile(configFile, 'utf8'))
	const oldApps = proxy.apps
	const allApps = Object.assign({}, proxy.apps, config.apps)
	proxy.apps = config.apps
	proxy.names = config.names
	proxy.machines = config.machines
	proxy.credentials = config.credentials = config.credentials || {}
	autocert.credentials = proxy.credentials
  autocert.email = config.acmeUserEmail || 'acme@letsencrypt.org'
	for (let id in allApps) {
		delete proxy.hooks[id]
		proxy.onappchange({
			oldData: oldApps[id],
			newData: proxy.apps[id]
		})
	}
	reloadFileServer()
}

function reloadFileServer () {
	if (!config.fileServerPort) {
		config.fileServerPort = 8000
	}
	if (fileServer) {
		if (fileServer.port !== config.fileServerPort) {
			console.log(`stopped listening on ${fileServer.port}`)
			fileServer.close()
		} else {
			return
		}
	}
	fileServer = new MultiRoot({ port: config.fileServerPort })
	fileServer.names = proxy.names
	fileServer.apps = proxy.apps
	fileServer.on('listen', () => {
		console.log(`started listening on ${fileServer.port}`)
	})
	fileServer.on('serve', path => {
		console.log(`started serving ${path}`)
	})
	fileServer.on('unserve', path => {
		console.log(`stopped serving ${path}`)
	})
	fileServer.reload()
}
