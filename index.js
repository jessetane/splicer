'use strict'

var fs = require('fs')
var net = require('net')
var isTLSClientHello = require('is-tls-client-hello')
var sni = require('sni')

module.exports = class Terminus {
  constructor (opts) {
    this.hostsPath = opts.hostsPath
    this.hosts = {}
    this.servers = {}
    this.reload = this.reload.bind(this)
    this.onconnect = this.onconnect.bind(this)
    this.onserverError = this.onserverError.bind(this)
    this.reload()
  }

  reload () {
    fs.readdir(this.hostsPath, (err, hostPaths) => {
      if (err) return this.emit('error', err)
      var hosts = {}
      var servers = {}
      var hostPath, hostFullPath, pkg, version, main, host, server, address, port, addr, sep
      hostPaths.forEach(hostPath => {
        hostFullPath = this.hostsPath + '/' + hostPath
        try {
          pkg = JSON.parse(fs.readFileSync(hostFullPath + '/package.json', 'utf8')).terminus
          version = pkg.version
          main = pkg.main
        } catch (err) {}
        version = version || '0'
        main = main || 'index.js'
        hostFullPath += '/' + main
        hostPath += '@' + version
        host = this.hosts[hostPath]
        if (host) {
          hosts[hostPath] = host
          delete this.hosts[hostPath]
        } else {
          try {
            delete require.cache[hostFullPath]
            host = hosts[hostPath] = require(hostFullPath)
            host.moduleId = hostFullPath
          } catch (err) {
            console.error('failed to load host at ' + hostPath)
            return
          }
        }
        for (address in host.listen) {
          addr = '::'
          port = null
          sep = address.lastIndexOf(':')
          if (sep === -1) {
            port = address
          } else {
            addr = address.slice(0, sep) || '::'
            port = address.slice(sep)
          }
          server = this.servers[addr] && this.servers[addr][port]
          if (server) {
            delete this.servers[addr][port]
          } else {
            server = servers[addr] && servers[addr][port]
            if (!server) {
              server = net.createServer(this.onconnect)
              server.on('error', this.onserverError)
              server.listen(port, addr)
              console.log(`started listening on ${addr}:${port}`)
            }
          }
          servers[addr] = servers[addr] || {}
          servers[addr][port] = server
        }
      })
      for (addr in this.servers) {
        for (port in this.servers[addr]) {
          server = this.servers[addr][port]
          server.removeListener('error', this.onserverError)
          server.close() // destroy?
          console.log(`stopped listening on ${addr}:${port}`)
        }
      }
      this.servers = servers
      for (hostPath in this.hosts) {
        delete require.cache[host.moduleId]
        host = this.hosts[hostPath]
        host.close()
      }
      this.hosts = hosts
    })
  }

  onconnect (socket) {
    socket.once('readable', () => {
      var data = socket.read()
      if (!data || data.length === 0) return
      var host, string, name = null
      if (isTLSClientHello(data)) {
        name = sni(data)
      } else {
        string = data.toString('ascii')
        name = string.match(/host: ([^:]*)/i)
        if (name) name = name[1]
      }
      host = this.lookupHostByName(name)
      if (host) {
        socket.unshift(data)
        host.listen[socket.localPort](socket, name)
      } else {
        socket.destroy()
      }
    })
  }

  lookupHostByName (name) {
    var defaultHost = null
    var host = null
    for (var hostPath in this.hosts) {
      var _host = this.hosts[hostPath]
      if (_host.default === true) defaultHost = _host
      if (name) {
        if (_host.names.find(_name => {
          if (typeof _name === 'string') {
            return _name === name
          } else {
            return _name.test(name)
          }
        })) {
          host = _host
          break
        }
      }
    }
    return host || defaultHost
  }

  onserverError (err) {
    console.error('external server got error', err)
  }
}
