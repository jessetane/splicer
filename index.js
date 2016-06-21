'use strict'

var EventEmitter = require('events')
var fs = require('fs')
var net = require('net')
var isTLSClientHello = require('is-tls-client-hello')
var extractSNI = require('sni')

var isHTTPRegex = /[^\r\n]*HTTP\/1\.1[\r\n]/
var extractHTTPHost = /[\r\n]host: ([^:\r\n ]+)/i

module.exports = class Terminus extends EventEmitter {
  constructor (opts) {
    super()
    this.hostsPath = opts.hostsPath
    this.hosts = {}
    this.servers = {}
    this.reload = this.reload.bind(this)
    this.onconnect = this.onconnect.bind(this)
    this.onserverError = this.onserverError.bind(this)
    this.reload()
  }

  reload () {
    this.loadHostConfigurations((err, configurations) => {
      if (err) return this.emit(err)
      var activeHosts = {}
      var activeServers = {}
      configurations.forEach(configuration => {
        var host = this.lookupOrLoadHost(configuration, activeHosts)
        if (host) {
          this.lookupOrStartServer(host, activeServers)
        }
      })
      this.stopInactiveServers(activeServers)
      this.unloadInactiveHosts(activeHosts)
    })
  }

  loadHostConfigurations (cb) {
    fs.readdir(this.hostsPath, (err, hostIds) => {
      if (err) return cb(err)
      var n = hostIds.length
      var configurations = []
      hostIds.forEach(id => {
        var fullPath = this.hostsPath + '/' + id
        fs.stat(fullPath, (err, stat) => {
          if (!cb) return
          if (err) return done(err)
          if (stat.isDirectory()) {
            fs.readFile(fullPath + '/package.json', 'utf8', (err, data) => {
              if (!cb) return
              if (err && err.code !== 'ENOENT') return done(err)
              var pkg = {}
              try {
                pkg = JSON.parse(data)
              } catch (err) {}
              pkg = pkg.terminus || {}
              configurations.push({
                id: id + '@' + (pkg.version || '0'),
                main: fullPath + '/' + (pkg.main || 'index.js'),
              })
              done()
            })
          } else {
            configurations.push({
              id: id + '@0',
              main: fullPath,
            })
            done()
          }
        })
      })
      function done (err) {
        if (!cb) return
        if (err) {
          var _cb = cb
          cb = null
          _cb(err)
          return
        }
        if (--n > 0) return
        cb(null, configurations)
      }
    })
  }

  lookupOrLoadHost (configuration, actives) {
    var id = configuration.id
    var main = configuration.main
    var host = this.hosts[id]
    if (host) {
      delete this.hosts[id]
    } else {
      delete require.cache[main]
      try {
        host = require(main)
      } catch (err) {
        // this.emit('error', err)
        return
      }
      host.cacheKey = main
      if (!host.listen) {
        this.emit('error', Error('host has no listeners'))
        return
      }
    }
    return actives[id] = host
  }

  lookupOrStartServer (host, actives) {
    for (var address in host.listen) {
      var addr = '::'
      var port = null
      var sep = address.lastIndexOf(':')
      if (sep === -1) {
        port = address
      } else {
        addr = address.slice(0, sep) || '::'
        port = address.slice(sep)
      }
      var server = this.servers[addr] && this.servers[addr][port]
      if (server) {
        delete this.servers[addr][port]
      } else {
        server = actives[addr] && actives[addr][port]
        if (!server) {
          server = net.createServer(this.onconnect)
          server.address = addr + ':' + port
          server.on('error', this.onserverError)
          server.listen(port, addr, err => {
            if (err) {
              this.emit('error', err)
            } else {
              this.emit('listen', server.address)
            }
          })
        }
      }
      actives[addr] = actives[addr] || {}
      actives[addr][port] = server
    }
  }

  stopInactiveServers (actives) {
    for (var addr in this.servers) {
      for (var port in this.servers[addr]) {
        var server = this.servers[addr][port]
        server.removeListener('error', this.onserverError)
        server.close() // do we need to destroy sockets here?
        this.emit('unlisten', server.address)
      }
    }
    this.servers = actives
  }

  unloadInactiveHosts (actives) {
    for (var id in this.hosts) {
      var host = this.hosts[id]
      host.close && host.close()
      delete require.cache[host.cacheKey]
    }
    this.hosts = actives
  }

  onconnect (socket) {
    // console.log(socket.localPort)
    // var socketId = socket.remoteAddress + socket.remotePort
    // this.sockets[socketId] = socket
    // socket.once('close', () => {
    //   delete this.sockets[socketId]
    // })
    socket.once('readable', () => {
      var data = socket.read()
      if (!data || data.length === 0) return
      var host, string, name = null
      var id = null
      if (isTLSClientHello(data)) {
        name = extractSNI(data)
      } else {
        var first1024 = data.toString('ascii', 0, 1024)
        if (isHTTPRegex.test(first1024)) {
          name = first1024.match(extractHTTPHost)
          name = name && name[1]
        } else {
          id = first1024.split('\n')[0].slice(0,255)
        }
      }
      host = this.lookupHostByName(name, id)
      if (host) {
        socket.unshift(data)
        var handler = host.listen[socket.localPort]
        if (handler) {
          handler(socket, name)
        } else {
          socket.destroy()
        }
      } else {
        socket.destroy()
      }
    })
  }

  lookupHostByName (name, id) {
    var isName = !!name
    var host = null
    for (var id in this.hosts) {
      var _host = this.hosts[id]
      var names = isName ? _host.names : _host.ids
      if (names) {
        if (names.find(_name => {
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
    return host
  }

  close () {
    this.stopInactiveServers()
    this.unloadInactiveHosts()
  }

  onserverError (err) {
    this.emit('error', err)
  }
}
